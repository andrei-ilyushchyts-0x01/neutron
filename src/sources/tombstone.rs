//! Watcher for `/data/tombstones/`.
//!
//! Android's `tombstoned` writes a per-crash record into `/data/tombstones/`
//! when a native process dies on a fatal signal. The header carries the pid,
//! signal, fault address, and the process comm. Userspace formats vary
//! slightly across Android releases but the pid/signal lines are stable
//! enough for a regex grab.
//!
//! ## Production path
//!
//! - Watch a directory (default `/data/tombstones/`) for new files.
//! - When a new file appears, parse the first 60 lines for the header.
//! - Emit a [`ProcessExitEvent`] with `source = ExitSource::Tombstone`.
//!
//! Polling-based for portability — `inotify(7)` would shave latency but adds
//! a kernel dependency that breaks on hosts. The poll interval (default 1 s)
//! is configurable.
//!
//! ## Test path
//!
//! [`MockTombstoneWatcher`] lets unit tests feed pre-baked file lists +
//! contents without touching the filesystem.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use neutron_common::ExitSource;

use super::ProcessExitEvent;

const DEFAULT_TOMBSTONE_DIR: &str = "/data/tombstones";
const HEADER_LINE_LIMIT: usize = 60;
const MAX_TOMBSTONE_LINE_BYTES: usize = 16 * 1024;
const MAX_TOMBSTONE_HEADER_BYTES: usize = 256 * 1024;
const MAX_TOMBSTONE_DIRECTORY_ENTRIES: usize = 4096;
const MAX_TOMBSTONE_COMM_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TombstoneSourceStats {
    pub baseline_primes: u64,
    pub baseline_errors: u64,
    pub baseline_files: u64,
    pub unprimed_polls: u64,
    pub polls: u64,
    pub directory_errors: u64,
    pub directory_entry_errors: u64,
    pub directory_overflows: u64,
    pub files_read: u64,
    pub file_read_errors: u64,
    pub oversized_files: u64,
    pub file_identity_races: u64,
    pub malformed_files: u64,
    pub emitted: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TombstoneSourceError {
    pub operation: &'static str,
    pub path: String,
    pub kind: io::ErrorKind,
    pub message: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TombstoneRuntimeState {
    pub primed: bool,
    pub available: bool,
    pub last_error: Option<TombstoneSourceError>,
}

/// Behaviour shared by the production watcher and test mocks.
pub trait TombstoneWatcher {
    /// Return any new tombstone files observed since the last call. Caller
    /// (the main loop) calls this periodically; the watcher tracks which
    /// files it has already reported.
    fn poll(&mut self, now_ns: u64) -> Vec<ProcessExitEvent>;
}

/// Production watcher backed by `std::fs::read_dir`.
pub struct RealTombstoneWatcher {
    dir: PathBuf,
    seen: HashMap<PathBuf, TombstoneFileIdentity>,
    /// Baseline priming is explicit so callers can establish it before the
    /// evidence boundary instead of dropping files created before the first
    /// event-loop poll.
    primed: bool,
    stats: TombstoneSourceStats,
    runtime_state: TombstoneRuntimeState,
}

impl RealTombstoneWatcher {
    pub fn new() -> Self {
        Self::with_dir(DEFAULT_TOMBSTONE_DIR)
    }

    pub fn with_dir(path: impl AsRef<Path>) -> Self {
        Self {
            dir: path.as_ref().to_path_buf(),
            seen: HashMap::new(),
            primed: false,
            stats: TombstoneSourceStats::default(),
            runtime_state: TombstoneRuntimeState::default(),
        }
    }

    /// Returns `true` if the watch directory exists and is readable. The
    /// loader uses this to decide whether to spawn the watcher at all
    /// (avoid silent no-op on hosts without `/data/tombstones/`).
    pub fn dir_available(&self) -> bool {
        match fs::metadata(&self.dir) {
            Ok(m) => m.is_dir(),
            Err(_) => false,
        }
    }

    pub fn stats(&self) -> TombstoneSourceStats {
        self.stats
    }

    pub fn runtime_state(&self) -> &TombstoneRuntimeState {
        &self.runtime_state
    }

    /// Record every current tombstone version as pre-existing. Call this
    /// immediately before the capture evidence boundary. The update is
    /// atomic: any directory or file error leaves the watcher unprimed.
    pub fn prime(&mut self) -> io::Result<()> {
        self.stats.baseline_primes = self.stats.baseline_primes.saturating_add(1);
        self.primed = false;
        self.runtime_state.primed = false;
        let paths = match self.candidate_paths() {
            Ok(paths) => paths,
            Err(error) => {
                self.stats.baseline_errors = self.stats.baseline_errors.saturating_add(1);
                return Err(error);
            }
        };
        let mut baseline = HashMap::with_capacity(paths.len());
        for path in paths {
            match open_tombstone(&path) {
                Ok(opened) => {
                    baseline.insert(path, opened.identity);
                }
                Err(error) => {
                    self.stats.baseline_errors = self.stats.baseline_errors.saturating_add(1);
                    self.runtime_state.available = false;
                    self.record_error("prime_file", &path, &error);
                    return Err(error);
                }
            }
        }
        self.stats.baseline_files = self
            .stats
            .baseline_files
            .saturating_add(baseline.len() as u64);
        self.seen = baseline;
        self.primed = true;
        self.runtime_state.primed = true;
        self.runtime_state.available = true;
        self.runtime_state.last_error = None;
        Ok(())
    }

    fn record_error(&mut self, operation: &'static str, path: &Path, error: &io::Error) {
        self.runtime_state.last_error = Some(TombstoneSourceError {
            operation,
            path: path.to_string_lossy().into_owned(),
            kind: error.kind(),
            message: error.to_string(),
        });
    }

    fn candidate_paths(&mut self) -> io::Result<Vec<PathBuf>> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => {
                self.runtime_state.available = true;
                entries
            }
            Err(error) => {
                self.stats.directory_errors = self.stats.directory_errors.saturating_add(1);
                self.runtime_state.available = false;
                let directory = self.dir.clone();
                self.record_error("read_dir", &directory, &error);
                return Err(error);
            }
        };
        let mut current = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    self.stats.directory_entry_errors =
                        self.stats.directory_entry_errors.saturating_add(1);
                    let directory = self.dir.clone();
                    self.record_error("read_dir_entry", &directory, &error);
                    return Err(error);
                }
            };
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if !name.starts_with("tombstone_") {
                continue;
            }
            if current.len() == MAX_TOMBSTONE_DIRECTORY_ENTRIES {
                self.stats.directory_overflows = self.stats.directory_overflows.saturating_add(1);
                let error = io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "tombstone directory exceeds {MAX_TOMBSTONE_DIRECTORY_ENTRIES} entries"
                    ),
                );
                let directory = self.dir.clone();
                self.record_error("read_dir", &directory, &error);
                return Err(error);
            }
            current.push(path);
        }
        current.sort();
        Ok(current)
    }
}

impl Default for RealTombstoneWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl TombstoneWatcher for RealTombstoneWatcher {
    fn poll(&mut self, now_ns: u64) -> Vec<ProcessExitEvent> {
        let mut out = Vec::new();
        self.stats.polls = self.stats.polls.saturating_add(1);
        if !self.primed {
            self.stats.unprimed_polls = self.stats.unprimed_polls.saturating_add(1);
            self.runtime_state.available = false;
            let error = io::Error::new(
                io::ErrorKind::InvalidInput,
                "tombstone watcher must be primed before polling",
            );
            let directory = self.dir.clone();
            self.record_error("poll_unprimed", &directory, &error);
            return out;
        }
        self.runtime_state.last_error = None;
        let current = match self.candidate_paths() {
            Ok(current) => current,
            Err(_) => return out,
        };
        let current_paths: HashSet<_> = current.iter().cloned().collect();
        self.seen.retain(|path, _| current_paths.contains(path));
        for path in current {
            let opened = match open_tombstone(&path) {
                Ok(opened) => opened,
                Err(error) => {
                    self.stats.file_read_errors = self.stats.file_read_errors.saturating_add(1);
                    self.record_error("open_file", &path, &error);
                    continue;
                }
            };
            if self.seen.get(&path) == Some(&opened.identity) {
                continue;
            }
            let identity = opened.identity;
            let content = match read_tombstone_header(opened) {
                Ok(content) => content,
                Err(error) => {
                    self.stats.file_read_errors = self.stats.file_read_errors.saturating_add(1);
                    if error.to_string().contains("exceeds size limit") {
                        self.stats.oversized_files = self.stats.oversized_files.saturating_add(1);
                    }
                    if error.kind() == io::ErrorKind::InvalidData {
                        self.stats.malformed_files = self.stats.malformed_files.saturating_add(1);
                    }
                    if error.kind() == io::ErrorKind::Interrupted {
                        self.stats.file_identity_races =
                            self.stats.file_identity_races.saturating_add(1);
                    }
                    self.record_error("read_file", &path, &error);
                    continue;
                }
            };
            self.stats.files_read = self.stats.files_read.saturating_add(1);
            self.seen.insert(path, identity);
            if let Some(ev) = parse_tombstone_header(&content, now_ns) {
                self.stats.emitted = self.stats.emitted.saturating_add(1);
                out.push(ev);
            } else {
                self.stats.malformed_files = self.stats.malformed_files.saturating_add(1);
            }
        }
        out
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TombstoneFileIdentity {
    device: u64,
    inode: u64,
    mtime_seconds: i64,
    mtime_nanoseconds: i64,
    size: u64,
}

impl TombstoneFileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mtime_seconds: metadata.mtime(),
            mtime_nanoseconds: metadata.mtime_nsec(),
            size: metadata.len(),
        }
    }
}

struct OpenTombstone {
    file: File,
    identity: TombstoneFileIdentity,
}

fn open_tombstone(path: &Path) -> io::Result<OpenTombstone> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tombstone must be a single-link regular file",
        ));
    }
    Ok(OpenTombstone {
        file,
        identity: TombstoneFileIdentity::from_metadata(&metadata),
    })
}

fn read_tombstone_header(opened: OpenTombstone) -> io::Result<String> {
    let mut reader = BufReader::new(opened.file);
    let mut line = Vec::new();
    let mut header = Vec::new();
    for _ in 0..HEADER_LINE_LIMIT {
        if !read_bounded_line(&mut reader, &mut line, MAX_TOMBSTONE_LINE_BYTES)? {
            break;
        }
        let next_len = header.len().saturating_add(line.len()).saturating_add(1);
        if next_len > MAX_TOMBSTONE_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tombstone header exceeds size limit",
            ));
        }
        header.extend_from_slice(&line);
        header.push(b'\n');
    }
    let after = TombstoneFileIdentity::from_metadata(&reader.get_ref().metadata()?);
    if after != opened.identity {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "tombstone identity changed while reading",
        ));
    }
    String::from_utf8(header).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    out: &mut Vec<u8>,
    limit: usize,
) -> io::Result<bool> {
    out.clear();
    let mut exceeded = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if exceeded {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tombstone line exceeds size limit",
                ));
            }
            return Ok(!out.is_empty());
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consume = newline.map_or(available.len(), |index| index + 1);
        let content = newline.map_or(available, |index| &available[..index]);
        if out.len() < limit + 1 {
            let remaining = limit + 1 - out.len();
            out.extend_from_slice(&content[..content.len().min(remaining)]);
        }
        exceeded |= out.len() > limit;
        reader.consume(consume);
        if newline.is_some() {
            if exceeded {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tombstone line exceeds size limit",
                ));
            }
            return Ok(true);
        }
    }
}

/// Parses the header of a tombstone file. Returns `None` if the file does
/// not carry the canonical pid/signal lines.
///
/// Expected header shape (Android 11+):
///
/// ```text
/// Build fingerprint: '...'
/// Revision: '0'
/// ABI: 'arm64'
/// Timestamp: 2026-05-05 ...
/// pid: 12345, tid: 12345, name: app  >>> com.example <<<
/// signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0
/// ```
pub fn parse_tombstone_header(content: &str, ts_ns: u64) -> Option<ProcessExitEvent> {
    let mut pid: Option<u32> = None;
    let mut uid: Option<u32> = None;
    let mut signal: Option<u32> = None;
    let mut comm: Option<String> = None;

    for line in content.lines().take(HEADER_LINE_LIMIT) {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("pid: ") {
            // "pid: 12345, tid: 12345, name: foo  >>> com.example <<<"
            let mut parts = rest.split(',').map(str::trim);
            if let Some(pid_str) = parts.next() {
                pid = pid_str.parse().ok();
            }
            // Parse "name: <comm>" segment. The comm value is followed by a
            // ">>> <package> <<<" suffix that we strip — the bare comm is what
            // /proc/<pid>/comm and BPF agree on.
            if let Some(name_seg) = parts.find(|s| s.starts_with("name: ")) {
                let raw = name_seg.trim_start_matches("name: ");
                let cut = raw.find(">>>").map(|i| &raw[..i]).unwrap_or(raw);
                comm = Some(cut.trim().to_string());
            }
        } else if let Some(rest) = trimmed.strip_prefix("uid:") {
            uid = rest.trim().parse().ok();
        } else if let Some(rest) = trimmed.strip_prefix("signal ") {
            // "signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0"
            let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            signal = num_str.parse().ok();
        }
    }

    let pid = pid.filter(|pid| *pid != 0)?;
    let signal = signal.filter(|signal| *signal != 0)?;
    let comm = comm.filter(|comm| !comm.is_empty() && comm.len() <= MAX_TOMBSTONE_COMM_BYTES)?;
    Some(ProcessExitEvent {
        ts_ns,
        pid,
        uid,
        comm,
        exit_code: 0,
        exit_signal: signal,
        source: ExitSource::Tombstone,
    })
}

/// In-memory mock for unit tests. Each call to `feed` queues a virtual file
/// that will be returned on the next `poll`. Useful for engine integration
/// tests that need the watcher to be deterministic.
#[cfg(test)]
#[derive(Default)]
pub struct MockTombstoneWatcher {
    queued: Vec<String>,
}

#[cfg(test)]
impl MockTombstoneWatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, content: impl Into<String>) {
        self.queued.push(content.into());
    }
}

#[cfg(test)]
impl TombstoneWatcher for MockTombstoneWatcher {
    fn poll(&mut self, now_ns: u64) -> Vec<ProcessExitEvent> {
        self.queued
            .drain(..)
            .filter_map(|c| parse_tombstone_header(&c, now_ns))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutron_common::SIGSEGV;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "neutron-tombstone-{label}-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ))
    }

    const SAMPLE_HEADER: &str = "\
Build fingerprint: 'google/raven/raven:14/UQ1A.240105.004/11206848:user/release-keys'
Revision: '0'
ABI: 'arm64'
Timestamp: 2026-05-05 12:34:56.789+0000
pid: 12345, tid: 12345, name: example.app  >>> com.example.app <<<
uid: 10123
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0
Cause: null pointer dereference
";

    #[test]
    fn parses_canonical_header() {
        let ev = parse_tombstone_header(SAMPLE_HEADER, 999).expect("parses");
        assert_eq!(ev.pid, 12345);
        assert_eq!(ev.exit_signal, SIGSEGV);
        assert_eq!(ev.comm, "example.app");
        assert_eq!(ev.uid, Some(10123));
        assert_eq!(ev.source, ExitSource::Tombstone);
        assert_eq!(ev.ts_ns, 999);
    }

    #[test]
    fn missing_uid_remains_unknown() {
        let header = "pid: 7, tid: 7, name: foo  >>> foo <<<\n\
signal 11 (SIGSEGV), code 1, fault addr 0x0\n";
        let ev = parse_tombstone_header(header, 1).expect("valid header");
        assert_eq!(ev.uid, None);
    }

    #[test]
    fn missing_pid_returns_none() {
        let header = "signal 11 (SIGSEGV), code 1, fault addr 0x0\n";
        assert!(parse_tombstone_header(header, 0).is_none());
    }

    #[test]
    fn missing_signal_is_malformed() {
        let header = "pid: 7, tid: 7, name: foo  >>> foo <<<\n";
        assert!(parse_tombstone_header(header, 0).is_none());
    }

    #[test]
    fn zero_pid_signal_and_empty_or_oversized_comm_are_malformed() {
        assert!(parse_tombstone_header("pid: 0, tid: 0, name: foo\nsignal 11\n", 0).is_none());
        assert!(parse_tombstone_header("pid: 7, tid: 7, name: foo\nsignal 0\n", 0).is_none());
        assert!(parse_tombstone_header("pid: 7, tid: 7, name:   \nsignal 11\n", 0).is_none());
        let comm = "x".repeat(MAX_TOMBSTONE_COMM_BYTES + 1);
        assert!(
            parse_tombstone_header(&format!("pid: 7, tid: 7, name: {comm}\nsignal 11\n"), 0,)
                .is_none()
        );
    }

    #[test]
    fn signal_parser_handles_trailing_text() {
        let header = "pid: 1, tid: 1, name: x\nsignal 6 (SIGABRT), code -1\n";
        let ev = parse_tombstone_header(header, 0).expect("parses");
        assert_eq!(ev.exit_signal, 6);
    }

    #[test]
    fn header_line_limit_caps_scan() {
        // pid is on the very last line beyond the cap — must NOT be picked up.
        let mut lines: Vec<String> = (0..HEADER_LINE_LIMIT + 5)
            .map(|i| format!("filler line {i}"))
            .collect();
        lines.push("pid: 99, tid: 99, name: late  >>> late <<<".into());
        lines.push("signal 11 (SIGSEGV), code 1, fault addr 0x0".into());
        let blob = lines.join("\n");
        assert!(parse_tombstone_header(&blob, 0).is_none());
    }

    #[test]
    fn mock_watcher_emits_queued_events_then_drains() {
        let mut w = MockTombstoneWatcher::new();
        w.feed(SAMPLE_HEADER);
        let first = w.poll(123);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].pid, 12345);
        let second = w.poll(456);
        assert!(second.is_empty(), "subsequent poll must be empty");
    }

    #[test]
    fn missing_directory_error_is_observable() {
        let directory = temp_dir("missing");
        let mut watcher = RealTombstoneWatcher::with_dir(&directory);

        assert!(watcher.prime().is_err());

        assert_eq!(watcher.stats().directory_errors, 1);
        assert_eq!(watcher.stats().baseline_errors, 1);
        assert!(!watcher.runtime_state().primed);
        assert!(!watcher.runtime_state().available);
        let error = watcher
            .runtime_state()
            .last_error
            .as_ref()
            .expect("directory failure must be retained");
        assert_eq!(error.operation, "read_dir");
        assert_eq!(error.kind, std::io::ErrorKind::NotFound);
    }

    #[test]
    fn per_file_error_is_counted_and_retried() {
        let directory = temp_dir("file-error");
        fs::create_dir(&directory).unwrap();
        let mut watcher = RealTombstoneWatcher::with_dir(&directory);
        watcher.prime().unwrap();
        let tombstone = directory.join("tombstone_00");
        symlink(directory.join("missing-target"), &tombstone).unwrap();

        assert!(watcher.poll(2).is_empty());

        assert_eq!(watcher.stats().file_read_errors, 1);
        assert!(watcher.runtime_state().available);
        assert_eq!(
            watcher
                .runtime_state()
                .last_error
                .as_ref()
                .unwrap()
                .operation,
            "open_file"
        );
        assert!(!watcher.seen.contains_key(&tombstone));
        assert!(watcher.poll(3).is_empty());
        assert_eq!(
            watcher.stats().file_read_errors,
            2,
            "failed reads are retried"
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn oversized_tombstone_is_rejected_without_unbounded_read() {
        let directory = temp_dir("oversize");
        fs::create_dir(&directory).unwrap();
        let mut watcher = RealTombstoneWatcher::with_dir(&directory);
        watcher.prime().unwrap();
        fs::write(
            directory.join("tombstone_01"),
            vec![b'x'; MAX_TOMBSTONE_HEADER_BYTES + 1],
        )
        .unwrap();

        assert!(watcher.poll(2).is_empty());

        assert_eq!(watcher.stats().oversized_files, 1);
        assert_eq!(watcher.stats().file_read_errors, 1);
        assert_eq!(
            watcher.runtime_state().last_error.as_ref().unwrap().kind,
            std::io::ErrorKind::InvalidData
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn real_watcher_counts_successful_bounded_emission() {
        let directory = temp_dir("success");
        fs::create_dir(&directory).unwrap();
        let mut watcher = RealTombstoneWatcher::with_dir(&directory);
        watcher.prime().unwrap();
        fs::write(directory.join("tombstone_02"), SAMPLE_HEADER).unwrap();

        let events = watcher.poll(2);

        assert_eq!(events.len(), 1);
        assert_eq!(watcher.stats().files_read, 1);
        assert_eq!(watcher.stats().emitted, 1);
        assert!(watcher.runtime_state().available);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn explicit_baseline_is_ignored_and_new_version_is_emitted() {
        let directory = temp_dir("baseline");
        fs::create_dir(&directory).unwrap();
        let tombstone = directory.join("tombstone_03");
        fs::write(&tombstone, SAMPLE_HEADER).unwrap();
        let mut watcher = RealTombstoneWatcher::with_dir(&directory);

        watcher.prime().unwrap();
        assert!(watcher.poll(1).is_empty());
        assert_eq!(watcher.stats().baseline_files, 1);
        assert!(watcher.runtime_state().primed);

        let replacement = SAMPLE_HEADER.replace("pid: 12345", "pid: 54321");
        fs::write(&tombstone, format!("{replacement}extra\n")).unwrap();
        let events = watcher.poll(2);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].pid, 54321);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn unprimed_poll_is_observable_and_never_establishes_a_baseline() {
        let directory = temp_dir("unprimed");
        fs::create_dir(&directory).unwrap();
        let mut watcher = RealTombstoneWatcher::with_dir(&directory);

        assert!(watcher.poll(1).is_empty());
        assert_eq!(watcher.stats().unprimed_polls, 1);
        assert!(!watcher.runtime_state().primed);
        assert_eq!(
            watcher
                .runtime_state()
                .last_error
                .as_ref()
                .unwrap()
                .operation,
            "poll_unprimed"
        );

        fs::remove_dir_all(directory).unwrap();
    }
}
