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

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use neutron_common::ExitSource;

use super::ProcessExitEvent;

const DEFAULT_TOMBSTONE_DIR: &str = "/data/tombstones";
const HEADER_LINE_LIMIT: usize = 60;

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
    seen: HashSet<PathBuf>,
    /// `false` until we have observed the directory at least once. Files
    /// present on first observation are added to `seen` without emission —
    /// they pre-date this neutron session.
    primed: bool,
}

impl RealTombstoneWatcher {
    pub fn new() -> Self {
        Self::with_dir(DEFAULT_TOMBSTONE_DIR)
    }

    pub fn with_dir(path: impl AsRef<Path>) -> Self {
        Self {
            dir: path.as_ref().to_path_buf(),
            seen: HashSet::new(),
            primed: false,
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
}

impl Default for RealTombstoneWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl TombstoneWatcher for RealTombstoneWatcher {
    fn poll(&mut self, now_ns: u64) -> Vec<ProcessExitEvent> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(&self.dir) {
            Ok(it) => it,
            Err(_) => return out,
        };
        let mut current: Vec<PathBuf> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            // Tombstones are named "tombstone_NN" (decimal). Skip subdirs and
            // anything that doesn't look like one.
            let name = match path.file_name().and_then(|s| s.to_str()) {
                Some(s) => s,
                None => continue,
            };
            if !name.starts_with("tombstone_") {
                continue;
            }
            current.push(path);
        }
        if !self.primed {
            self.primed = true;
            for p in current {
                self.seen.insert(p);
            }
            return out;
        }
        for path in current {
            if self.seen.contains(&path) {
                continue;
            }
            self.seen.insert(path.clone());
            // Read the first ~60 lines — the header is always at the top.
            let content = match fs::read_to_string(&path) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if let Some(ev) = parse_tombstone_header(&content, now_ns) {
                out.push(ev);
            }
        }
        out
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
        } else if let Some(rest) = trimmed.strip_prefix("signal ") {
            // "signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0"
            let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            signal = num_str.parse().ok();
        }
        // Bail early once both critical fields are present.
        if pid.is_some() && signal.is_some() && comm.is_some() {
            break;
        }
    }

    let pid = pid?;
    let signal = signal.unwrap_or(0);
    let comm = comm.unwrap_or_default();
    Some(ProcessExitEvent {
        ts_ns,
        pid,
        uid: 0, // tombstones don't carry uid in the header
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
        assert_eq!(ev.source, ExitSource::Tombstone);
        assert_eq!(ev.ts_ns, 999);
    }

    #[test]
    fn missing_pid_returns_none() {
        let header = "signal 11 (SIGSEGV), code 1, fault addr 0x0\n";
        assert!(parse_tombstone_header(header, 0).is_none());
    }

    #[test]
    fn missing_signal_defaults_to_zero() {
        let header = "pid: 7, tid: 7, name: foo  >>> foo <<<\n";
        let ev = parse_tombstone_header(header, 0).expect("parses");
        assert_eq!(ev.exit_signal, 0);
        assert_eq!(ev.pid, 7);
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
}
