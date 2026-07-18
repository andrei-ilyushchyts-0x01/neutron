//! Periodic `/proc/<pid>/fd` and `/proc/<pid>/limits` sampler.
//!
//! Sprint-1 PR 3 introduces a first-class FD-count signal so rules can match
//! on `fd_count_pct_of_rlimit_gt` and `fd_count_gt` predicates. Without this,
//! "HAL process fd table grew to 32768/32768" cases were invisible to the
//! engine — the FD graph only updated on observed open/close syscalls and
//! had no notion of an absolute count or rlimit.
//!
//! ## Architecture
//!
//! ```text
//!   main loop ── active_pids snapshot ──▶ FdPoller (thread)
//!                                          │
//!                                          │  every `interval`:
//!                                          │    for pid in scope:
//!                                          │      reader.fd_count(pid)
//!                                          │      reader.rlimit_nofile(pid)
//!                                          │      reader.top_fd_paths(pid, n)
//!                                          ▼
//!   main loop ◀─── FdSampleEvent ────────  mpsc::sync_channel
//!         │
//!         ├─► FdGraph::record_sample (HWM, growth rate)
//!         └─► format_fd_snapshot_json → rule engine + output
//! ```
//!
//! The hot loop is split for testability: [`collect_samples`] is a pure
//! function over a [`ProcReader`] trait that tests substitute with canned
//! data — no real `/proc` access in unit tests. The thread harness in
//! [`FdPoller::spawn`] is a thin wrapper over it.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MAX_PROC_STATUS_BYTES: usize = 256 * 1024;
const MAX_PROC_STAT_BYTES: usize = 64 * 1024;
const MAX_PROC_LIMITS_BYTES: usize = 256 * 1024;
const MAX_PROC_FD_ENTRIES: usize = 1_048_576;
const MAX_PROC_PIDS: usize = 131_072;

/// One sample emitted per in-scope PID per poller tick. Crosses the
/// `mpsc::sync_channel` from the poller thread back to the main loop.
#[derive(Debug, Clone)]
pub struct FdSampleEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub fd_count: u32,
    /// Soft `RLIMIT_NOFILE` from `/proc/<pid>/limits`. A sample is suppressed
    /// if this value cannot be read and parsed.
    pub rlimit_nofile: u32,
    /// Top-N most-frequently-targeted fd paths. Empty when the poller's
    /// `top_paths_n` is `0` (default in CLI). Sorted descending by count
    /// with ties broken alphabetically for deterministic output.
    pub top_paths: Vec<(String, u32)>,
    /// Monotonic-equivalent timestamp the poller stamped, in nanoseconds.
    /// Aligned with the same `Instant`-derived clock so deltas with
    /// previous samples are meaningful.
    pub ts_ns: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FdPollerStats {
    pub samples_sent: u64,
    pub samples_dropped_full: u64,
    pub sample_receiver_disconnected: u64,
    pub active_updates_sent: u64,
    pub active_updates_dropped_full: u64,
    pub active_receiver_disconnected: u64,
    pub active_updates_applied: u64,
    pub proc_disappeared: u64,
    pub proc_permission_errors: u64,
    pub proc_io_errors: u64,
    pub proc_parse_errors: u64,
    pub proc_truncations: u64,
    pub proc_races: u64,
    pub pid_reuse: u64,
    pub samples_suppressed_read_errors: u64,
    pub target_unreadable_polls: u64,
    pub scope_read_errors: u64,
    pub running: bool,
}

#[derive(Default)]
struct AtomicPollerStats {
    samples_sent: AtomicU64,
    samples_dropped_full: AtomicU64,
    sample_receiver_disconnected: AtomicU64,
    active_updates_sent: AtomicU64,
    active_updates_dropped_full: AtomicU64,
    active_receiver_disconnected: AtomicU64,
    active_updates_applied: AtomicU64,
    proc_disappeared: AtomicU64,
    proc_permission_errors: AtomicU64,
    proc_io_errors: AtomicU64,
    proc_parse_errors: AtomicU64,
    proc_truncations: AtomicU64,
    proc_races: AtomicU64,
    pid_reuse: AtomicU64,
    samples_suppressed_read_errors: AtomicU64,
    target_unreadable_polls: AtomicU64,
    scope_read_errors: AtomicU64,
    running: AtomicBool,
}

impl AtomicPollerStats {
    fn snapshot(&self) -> FdPollerStats {
        FdPollerStats {
            samples_sent: self.samples_sent.load(Ordering::Relaxed),
            samples_dropped_full: self.samples_dropped_full.load(Ordering::Relaxed),
            sample_receiver_disconnected: self.sample_receiver_disconnected.load(Ordering::Relaxed),
            active_updates_sent: self.active_updates_sent.load(Ordering::Relaxed),
            active_updates_dropped_full: self.active_updates_dropped_full.load(Ordering::Relaxed),
            active_receiver_disconnected: self.active_receiver_disconnected.load(Ordering::Relaxed),
            active_updates_applied: self.active_updates_applied.load(Ordering::Relaxed),
            proc_disappeared: self.proc_disappeared.load(Ordering::Relaxed),
            proc_permission_errors: self.proc_permission_errors.load(Ordering::Relaxed),
            proc_io_errors: self.proc_io_errors.load(Ordering::Relaxed),
            proc_parse_errors: self.proc_parse_errors.load(Ordering::Relaxed),
            proc_truncations: self.proc_truncations.load(Ordering::Relaxed),
            proc_races: self.proc_races.load(Ordering::Relaxed),
            pid_reuse: self.pid_reuse.load(Ordering::Relaxed),
            samples_suppressed_read_errors: self
                .samples_suppressed_read_errors
                .load(Ordering::Relaxed),
            target_unreadable_polls: self.target_unreadable_polls.load(Ordering::Relaxed),
            scope_read_errors: self.scope_read_errors.load(Ordering::Relaxed),
            running: self.running.load(Ordering::Acquire),
        }
    }
}

fn increment_saturating(counter: &AtomicU64) {
    add_saturating(counter, 1);
}

fn add_saturating(counter: &AtomicU64, amount: u64) {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_add(amount);
        if next == current {
            return;
        }
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcReadErrorKind {
    Disappeared,
    PermissionDenied,
    Io,
    Parse,
    Truncated,
    Race,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcReadError {
    pub kind: ProcReadErrorKind,
    pub operation: &'static str,
    pub message: String,
}

impl ProcReadError {
    pub fn new(
        kind: ProcReadErrorKind,
        operation: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            operation,
            message: message.into(),
        }
    }

    fn from_io(operation: &'static str, error: io::Error, not_found: ProcReadErrorKind) -> Self {
        let kind = match error.kind() {
            io::ErrorKind::NotFound => not_found,
            io::ErrorKind::PermissionDenied => ProcReadErrorKind::PermissionDenied,
            io::ErrorKind::InvalidData if error.to_string().contains("exceeds size limit") => {
                ProcReadErrorKind::Truncated
            }
            _ => ProcReadErrorKind::Io,
        };
        Self::new(kind, operation, error.to_string())
    }
}

impl fmt::Display for ProcReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.operation, self.message)
    }
}

impl std::error::Error for ProcReadError {}

pub type ProcReadResult<T> = std::result::Result<T, ProcReadError>;

#[derive(Clone)]
pub struct ActiveSetSender {
    sender: SyncSender<HashSet<u32>>,
    stats: Arc<AtomicPollerStats>,
}

impl ActiveSetSender {
    fn new(sender: SyncSender<HashSet<u32>>, stats: Arc<AtomicPollerStats>) -> Self {
        Self { sender, stats }
    }

    pub fn try_send(&self, active: HashSet<u32>) -> Result<(), mpsc::TrySendError<HashSet<u32>>> {
        match self.sender.try_send(active) {
            Ok(()) => {
                increment_saturating(&self.stats.active_updates_sent);
                Ok(())
            }
            Err(mpsc::TrySendError::Full(active)) => {
                increment_saturating(&self.stats.active_updates_dropped_full);
                Err(mpsc::TrySendError::Full(active))
            }
            Err(mpsc::TrySendError::Disconnected(active)) => {
                increment_saturating(&self.stats.active_receiver_disconnected);
                Err(mpsc::TrySendError::Disconnected(active))
            }
        }
    }

    pub fn stats(&self) -> FdPollerStats {
        self.stats.snapshot()
    }
}

/// Which PIDs the poller should sample on each tick.
///
/// CLI exposes this as `--fdgraph-pids traced|active|uid|all` with `Active`
/// as the default. `UidClass` remains an enum value for wire/source
/// compatibility but is rejected until its semantics are implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopePolicy {
    /// `--pid <N>` target plus followed-children PIDs (the BPF
    /// `PID_WHITELIST` set, surfaced by main.rs into the active set).
    /// Equivalent to `Active` in practice today; the distinction matters
    /// when UID-class polling lands.
    Traced,
    /// Default scope. PIDs that have produced at least one fd-bearing
    /// event since startup, plus the explicit `--pid` target if non-zero.
    /// Avoids broad `/proc` scans under `--pid 0` (the prior session's
    /// most expensive footgun).
    Active,
    /// Reserved for a future all-PIDs-sharing-UID implementation.
    UidClass,
    /// All PIDs visible in `/proc`. Heavy; use only for one-off audits.
    All,
}

impl std::str::FromStr for ScopePolicy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "traced" => Ok(Self::Traced),
            "active" => Ok(Self::Active),
            "uid" | "uidclass" => {
                Err("--fdgraph-pids=uid is unsupported in 1.5 (use traced|active|all)".into())
            }
            "all" => Ok(Self::All),
            other => Err(format!(
                "unknown --fdgraph-pids value '{other}' (expected: traced|active|all)"
            )),
        }
    }
}

/// Abstraction over `/proc` reads — production uses [`RealProcReader`];
/// tests substitute a canned-data implementation so unit tests never
/// touch the host filesystem and stay deterministic.
pub trait ProcReader: Send + Sync + 'static {
    fn process_starttime(&self, pid: u32) -> ProcReadResult<u64>;
    fn pid_meta(&self, pid: u32) -> ProcReadResult<(u32, String)>;
    fn fd_count(&self, pid: u32) -> ProcReadResult<u32>;
    fn rlimit_nofile(&self, pid: u32) -> ProcReadResult<u32>;
    fn top_fd_paths(&self, pid: u32, n: usize) -> ProcReadResult<Vec<(String, u32)>>;
    fn all_pids(&self) -> ProcReadResult<Vec<u32>>;
}

/// Real `/proc` reader. Production wiring.
pub struct RealProcReader;

impl ProcReader for RealProcReader {
    fn process_starttime(&self, pid: u32) -> ProcReadResult<u64> {
        let stat =
            read_bounded_proc_file(Path::new(&format!("/proc/{pid}/stat")), MAX_PROC_STAT_BYTES)
                .map_err(|error| {
                    ProcReadError::from_io("read_stat", error, ProcReadErrorKind::Disappeared)
                })?;
        let stat = String::from_utf8(stat).map_err(|error| {
            ProcReadError::new(ProcReadErrorKind::Parse, "parse_stat", error.to_string())
        })?;
        parse_process_starttime(&stat).ok_or_else(|| {
            ProcReadError::new(
                ProcReadErrorKind::Parse,
                "parse_stat",
                "missing or invalid process starttime",
            )
        })
    }

    fn pid_meta(&self, pid: u32) -> ProcReadResult<(u32, String)> {
        let status = read_bounded_proc_file(
            Path::new(&format!("/proc/{pid}/status")),
            MAX_PROC_STATUS_BYTES,
        )
        .map_err(|error| {
            ProcReadError::from_io("read_status", error, ProcReadErrorKind::Disappeared)
        })?;
        let status = String::from_utf8(status).map_err(|error| {
            ProcReadError::new(ProcReadErrorKind::Parse, "parse_status", error.to_string())
        })?;
        let mut uid: Option<u32> = None;
        let mut name: Option<String> = None;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Name:") {
                name = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("Uid:") {
                uid = rest
                    .split_whitespace()
                    .next()
                    .and_then(|value| value.parse().ok());
            }
            if uid.is_some() && name.is_some() {
                break;
            }
        }
        let uid = uid.ok_or_else(|| {
            ProcReadError::new(
                ProcReadErrorKind::Parse,
                "parse_status",
                "missing or invalid Uid field",
            )
        })?;
        let name = name.filter(|name| !name.is_empty()).ok_or_else(|| {
            ProcReadError::new(
                ProcReadErrorKind::Parse,
                "parse_status",
                "missing Name field",
            )
        })?;
        Ok((uid, name))
    }

    fn fd_count(&self, pid: u32) -> ProcReadResult<u32> {
        let entries = std::fs::read_dir(format!("/proc/{pid}/fd")).map_err(|error| {
            ProcReadError::from_io("read_fd_dir", error, ProcReadErrorKind::Disappeared)
        })?;
        let mut count: u32 = 0;
        for entry in entries {
            entry.map_err(|error| {
                ProcReadError::from_io("read_fd_entry", error, ProcReadErrorKind::Race)
            })?;
            if count as usize == MAX_PROC_FD_ENTRIES {
                return Err(ProcReadError::new(
                    ProcReadErrorKind::Truncated,
                    "read_fd_dir",
                    format!("fd directory exceeds {MAX_PROC_FD_ENTRIES} entries"),
                ));
            }
            count = count.saturating_add(1);
        }
        Ok(count)
    }

    fn rlimit_nofile(&self, pid: u32) -> ProcReadResult<u32> {
        let text = read_bounded_proc_file(
            Path::new(&format!("/proc/{pid}/limits")),
            MAX_PROC_LIMITS_BYTES,
        )
        .map_err(|error| {
            ProcReadError::from_io("read_limits", error, ProcReadErrorKind::Disappeared)
        })?;
        let text = String::from_utf8(text).map_err(|error| {
            ProcReadError::new(ProcReadErrorKind::Parse, "parse_limits", error.to_string())
        })?;
        parse_rlimit_nofile(&text).ok_or_else(|| {
            ProcReadError::new(
                ProcReadErrorKind::Parse,
                "parse_limits",
                "missing or invalid Max open files soft limit",
            )
        })
    }

    fn top_fd_paths(&self, pid: u32, n: usize) -> ProcReadResult<Vec<(String, u32)>> {
        if n == 0 {
            return Ok(Vec::new());
        }
        let entries = std::fs::read_dir(format!("/proc/{pid}/fd")).map_err(|error| {
            ProcReadError::from_io("read_fd_dir", error, ProcReadErrorKind::Disappeared)
        })?;
        let mut counts: HashMap<String, u32> = HashMap::new();
        for (observed, entry) in entries.enumerate() {
            let entry = entry.map_err(|error| {
                ProcReadError::from_io("read_fd_entry", error, ProcReadErrorKind::Race)
            })?;
            if observed == MAX_PROC_FD_ENTRIES {
                return Err(ProcReadError::new(
                    ProcReadErrorKind::Truncated,
                    "read_fd_paths",
                    format!("fd directory exceeds {MAX_PROC_FD_ENTRIES} entries"),
                ));
            }
            let target = std::fs::read_link(entry.path()).map_err(|error| {
                ProcReadError::from_io("read_fd_link", error, ProcReadErrorKind::Race)
            })?;
            *counts
                .entry(target.to_string_lossy().into_owned())
                .or_insert(0) += 1;
        }
        Ok(rank(counts, n))
    }

    fn all_pids(&self) -> ProcReadResult<Vec<u32>> {
        let entries = std::fs::read_dir("/proc")
            .map_err(|error| ProcReadError::from_io("read_proc", error, ProcReadErrorKind::Io))?;
        let mut pids = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| {
                ProcReadError::from_io("read_proc_entry", error, ProcReadErrorKind::Race)
            })?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Ok(pid) = name.parse() else {
                continue;
            };
            if pids.len() == MAX_PROC_PIDS {
                return Err(ProcReadError::new(
                    ProcReadErrorKind::Truncated,
                    "read_proc",
                    format!("proc directory exceeds {MAX_PROC_PIDS} PIDs"),
                ));
            }
            pids.push(pid);
        }
        Ok(pids)
    }
}

fn parse_process_starttime(stat: &str) -> Option<u64> {
    let after_comm = stat.rsplit_once(')')?.1;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

fn read_bounded_proc_file(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proc input must be a single-link regular file",
        ));
    }
    if metadata.len() > limit as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proc input exceeds size limit",
        ));
    }
    let mut bytes = Vec::with_capacity(limit.min(4096));
    file.take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proc input exceeds size limit",
        ));
    }
    Ok(bytes)
}

/// Sort/truncate a count map into a deterministic top-N. Descending count,
/// ascending path on tie. Pure helper — also used by tests.
fn rank(counts: HashMap<String, u32>, n: usize) -> Vec<(String, u32)> {
    let mut pairs: Vec<(String, u32)> = counts.into_iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    pairs.truncate(n);
    pairs
}

/// Parse the soft `RLIMIT_NOFILE` from a `/proc/<pid>/limits` body.
/// Format: a fixed-width column line starting with `Max open files`.
/// Returns `0` when the limit cannot be located (defensive — every
/// kernel since 2.6 emits this line, but the parser must not panic on
/// truncated reads or future formatting changes).
pub(crate) fn parse_rlimit_nofile(text: &str) -> Option<u32> {
    for line in text.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("Max open files") {
            continue;
        }
        // Format: "Max open files            <soft>     <hard>     files"
        // Columns split on whitespace yield ["Max", "open", "files", soft, hard, "files"].
        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        if let Some(soft_str) = cols.get(3) {
            if let Ok(soft) = soft_str.parse::<u32>() {
                return Some(soft);
            }
        }
    }
    None
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcReadStats {
    pub disappeared: u64,
    pub permission_errors: u64,
    pub io_errors: u64,
    pub parse_errors: u64,
    pub truncations: u64,
    pub races: u64,
    pub pid_reuse: u64,
    pub samples_suppressed_read_errors: u64,
    pub target_unreadable_polls: u64,
    pub scope_read_errors: u64,
}

impl ProcReadStats {
    fn record(&mut self, error: &ProcReadError) {
        let counter = match error.kind {
            ProcReadErrorKind::Disappeared => &mut self.disappeared,
            ProcReadErrorKind::PermissionDenied => &mut self.permission_errors,
            ProcReadErrorKind::Io => &mut self.io_errors,
            ProcReadErrorKind::Parse => &mut self.parse_errors,
            ProcReadErrorKind::Truncated => &mut self.truncations,
            ProcReadErrorKind::Race => &mut self.races,
        };
        *counter = counter.saturating_add(1);
    }
}

/// Collect samples and explicit read-health statistics. A failed fd-directory
/// read suppresses that PID's sample. No missing identity, rlimit, or path
/// value is replaced with a valid-looking zero/empty fallback.
pub fn collect_samples(
    reader: &dyn ProcReader,
    pids: &[u32],
    ts_ns: u64,
    top_paths_n: usize,
    target_pid: u32,
    identities: &mut HashMap<u32, u64>,
) -> (Vec<FdSampleEvent>, ProcReadStats) {
    let mut out = Vec::with_capacity(pids.len());
    let mut stats = ProcReadStats::default();
    let mut target_unreadable = false;
    for &pid in pids {
        let starttime = match reader.process_starttime(pid) {
            Ok(starttime) => starttime,
            Err(error) => {
                stats.record(&error);
                stats.samples_suppressed_read_errors =
                    stats.samples_suppressed_read_errors.saturating_add(1);
                target_unreadable |= pid == target_pid;
                continue;
            }
        };
        if identities
            .get(&pid)
            .is_some_and(|known| *known != starttime)
        {
            stats.pid_reuse = stats.pid_reuse.saturating_add(1);
            target_unreadable |= pid == target_pid;
            continue;
        }
        identities.entry(pid).or_insert(starttime);
        let fd_count = match reader.fd_count(pid) {
            Ok(fd_count) => fd_count,
            Err(error) => {
                stats.record(&error);
                stats.samples_suppressed_read_errors =
                    stats.samples_suppressed_read_errors.saturating_add(1);
                target_unreadable |= pid == target_pid;
                continue;
            }
        };
        let (uid, comm) = match reader.pid_meta(pid) {
            Ok(meta) => meta,
            Err(error) => {
                stats.record(&error);
                stats.samples_suppressed_read_errors =
                    stats.samples_suppressed_read_errors.saturating_add(1);
                target_unreadable |= pid == target_pid;
                continue;
            }
        };
        let rlimit = match reader.rlimit_nofile(pid) {
            Ok(rlimit) => rlimit,
            Err(error) => {
                stats.record(&error);
                stats.samples_suppressed_read_errors =
                    stats.samples_suppressed_read_errors.saturating_add(1);
                target_unreadable |= pid == target_pid;
                continue;
            }
        };
        let top = match reader.top_fd_paths(pid, top_paths_n) {
            Ok(top) => top,
            Err(error) => {
                stats.record(&error);
                stats.samples_suppressed_read_errors =
                    stats.samples_suppressed_read_errors.saturating_add(1);
                target_unreadable |= pid == target_pid;
                continue;
            }
        };
        match reader.process_starttime(pid) {
            Ok(after) if after == starttime => {}
            Ok(_) => {
                stats.pid_reuse = stats.pid_reuse.saturating_add(1);
                target_unreadable |= pid == target_pid;
                continue;
            }
            Err(error) => {
                stats.record(&error);
                stats.samples_suppressed_read_errors =
                    stats.samples_suppressed_read_errors.saturating_add(1);
                target_unreadable |= pid == target_pid;
                continue;
            }
        }
        out.push(FdSampleEvent {
            pid,
            uid,
            comm,
            fd_count,
            rlimit_nofile: rlimit,
            top_paths: top,
            ts_ns,
        });
    }
    stats.target_unreadable_polls = u64::from(target_unreadable);
    (out, stats)
}

/// Static configuration for an [`FdPoller`] thread.
#[derive(Clone, Debug)]
pub struct PollerConfig {
    pub interval: Duration,
    pub scope: ScopePolicy,
    /// Target PID from `--pid`. `0` ⇒ all-processes mode.
    pub target_pid: u32,
    /// Top-N path aggregation per sample. `0` disables (cheaper).
    pub top_paths_n: usize,
}

impl Default for PollerConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            scope: ScopePolicy::Active,
            target_pid: 0,
            top_paths_n: 0,
        }
    }
}

impl PollerConfig {
    fn validate(&self) -> io::Result<()> {
        if self.interval < Duration::from_millis(10) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fd poller interval must be at least 10ms",
            ));
        }
        if self.interval > Duration::from_secs(300) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fd poller interval must not exceed 300s",
            ));
        }
        Ok(())
    }
}

/// Resolve the in-scope PID set under `policy`. Pure — exported so the
/// CLI can dry-run a scope decision and tests can assert behaviour without
/// spawning a thread.
pub fn resolve_scope(
    policy: ScopePolicy,
    target_pid: u32,
    active: &HashSet<u32>,
    reader: &dyn ProcReader,
) -> ProcReadResult<Vec<u32>> {
    match policy {
        ScopePolicy::Traced => {
            // Sprint-1 simplification: Traced ≡ Active ∪ {target_pid}.
            // Followed-children PIDs are surfaced into the active set by
            // the main loop's clone-exit handler so we don't need a separate
            // PID_WHITELIST snapshot here.
            let mut set: HashSet<u32> = active.clone();
            if target_pid != 0 {
                set.insert(target_pid);
            }
            Ok(set.into_iter().collect())
        }
        ScopePolicy::Active => {
            let mut set: HashSet<u32> = active.clone();
            if target_pid != 0 {
                // Always include the explicit target so a brand-new traced
                // process gets sampled before its first fd-bearing syscall.
                set.insert(target_pid);
            }
            Ok(set.into_iter().collect())
        }
        ScopePolicy::UidClass => Err(ProcReadError::new(
            ProcReadErrorKind::Io,
            "resolve_scope",
            "uid-class scope is unsupported in 1.5",
        )),
        ScopePolicy::All => reader.all_pids(),
    }
}

fn merge_proc_read_stats(stats: &AtomicPollerStats, reads: ProcReadStats) {
    add_saturating(&stats.proc_disappeared, reads.disappeared);
    add_saturating(&stats.proc_permission_errors, reads.permission_errors);
    add_saturating(&stats.proc_io_errors, reads.io_errors);
    add_saturating(&stats.proc_parse_errors, reads.parse_errors);
    add_saturating(&stats.proc_truncations, reads.truncations);
    add_saturating(&stats.proc_races, reads.races);
    add_saturating(&stats.pid_reuse, reads.pid_reuse);
    add_saturating(
        &stats.samples_suppressed_read_errors,
        reads.samples_suppressed_read_errors,
    );
    add_saturating(
        &stats.target_unreadable_polls,
        reads.target_unreadable_polls,
    );
    add_saturating(&stats.scope_read_errors, reads.scope_read_errors);
}

/// Spawn the poller thread. Returns `(samples_rx, active_tx, stop_tx,
/// JoinHandle)`. The main loop:
/// - reads new samples via `samples_rx.try_recv()` each iteration;
/// - sends a fresh active-PID set via `active_tx.try_send(...)` whenever
///   it observes a new fd-bearing event for an unfamiliar PID;
/// - sends `()` on `stop_tx` to signal shutdown (or simply drops the
///   sender — the thread exits when the next try_recv returns
///   `Disconnected`).
pub type SpawnedPoller = (
    Receiver<FdSampleEvent>,
    ActiveSetSender,
    SyncSender<()>,
    JoinHandle<()>,
);

pub fn spawn(cfg: PollerConfig, reader: Box<dyn ProcReader>) -> io::Result<SpawnedPoller> {
    cfg.validate()?;
    let (samples_tx, samples_rx) = mpsc::sync_channel::<FdSampleEvent>(1024);
    let (active_tx, active_rx) = mpsc::sync_channel::<HashSet<u32>>(8);
    let (stop_tx, stop_rx) = mpsc::sync_channel::<()>(1);
    let stats = Arc::new(AtomicPollerStats::default());
    stats.running.store(true, Ordering::Release);
    let active_tx = ActiveSetSender::new(active_tx, Arc::clone(&stats));

    let handle = thread::spawn(move || {
        struct RunningGuard(Arc<AtomicPollerStats>);
        impl Drop for RunningGuard {
            fn drop(&mut self) {
                self.0.running.store(false, Ordering::Release);
            }
        }
        let _running = RunningGuard(Arc::clone(&stats));
        let mut current_active: HashSet<u32> = HashSet::new();
        let mut process_identities = HashMap::new();
        loop {
            // Shutdown signal: explicit message OR sender dropped.
            match stop_rx.try_recv() {
                Ok(()) | Err(mpsc::TryRecvError::Disconnected) => return,
                Err(mpsc::TryRecvError::Empty) => {}
            }
            // Drain any active-set updates non-blockingly. The main loop
            // sends the full set each time — we never accumulate diffs.
            while let Ok(set) = active_rx.try_recv() {
                current_active = set;
                increment_saturating(&stats.active_updates_applied);
            }
            let pids =
                match resolve_scope(cfg.scope, cfg.target_pid, &current_active, reader.as_ref()) {
                    Ok(pids) => pids,
                    Err(error) => {
                        let mut reads = ProcReadStats {
                            scope_read_errors: 1,
                            ..ProcReadStats::default()
                        };
                        reads.record(&error);
                        merge_proc_read_stats(&stats, reads);
                        if wait_for_stop(&stop_rx, cfg.interval) {
                            return;
                        }
                        continue;
                    }
                };
            let ts_ns = crate::causal::monotonic_timestamp_ns();
            let in_scope: HashSet<u32> = pids.iter().copied().collect();
            process_identities.retain(|pid, _| in_scope.contains(pid));
            let (samples, reads) = collect_samples(
                reader.as_ref(),
                &pids,
                ts_ns,
                cfg.top_paths_n,
                cfg.target_pid,
                &mut process_identities,
            );
            merge_proc_read_stats(&stats, reads);
            for sample in samples {
                if try_send_sample(&samples_tx, sample, &stats) == SampleSendResult::Disconnected {
                    return;
                }
            }
            if wait_for_stop(&stop_rx, cfg.interval) {
                return;
            }
        }
    });

    Ok((samples_rx, active_tx, stop_tx, handle))
}

fn wait_for_stop(receiver: &Receiver<()>, interval: Duration) -> bool {
    !matches!(
        receiver.recv_timeout(interval),
        Err(mpsc::RecvTimeoutError::Timeout)
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SampleSendResult {
    Sent,
    DroppedFull,
    Disconnected,
}

fn try_send_sample(
    sender: &SyncSender<FdSampleEvent>,
    sample: FdSampleEvent,
    stats: &AtomicPollerStats,
) -> SampleSendResult {
    match sender.try_send(sample) {
        Ok(()) => {
            increment_saturating(&stats.samples_sent);
            SampleSendResult::Sent
        }
        Err(mpsc::TrySendError::Full(_)) => {
            increment_saturating(&stats.samples_dropped_full);
            SampleSendResult::DroppedFull
        }
        Err(mpsc::TrySendError::Disconnected(_)) => {
            increment_saturating(&stats.sample_receiver_disconnected);
            SampleSendResult::Disconnected
        }
    }
}

#[allow(dead_code)]
fn ensure_path_is_proc(p: &Path) -> bool {
    // Tiny helper kept for forward-compat with sprint-2 sandboxing work
    // (UID-class scope will need to confirm a path is under /proc before
    // following symlinks). Unused in sprint-1.
    p.starts_with("/proc")
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "neutron-fd-poller-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ))
    }

    /// Mock `ProcReader` driven by canned per-PID data.
    struct MockReader {
        pids: Mutex<HashMap<u32, MockPid>>,
        all: Mutex<Vec<u32>>,
    }

    struct MockPid {
        uid: u32,
        comm: String,
        fd_count: Option<u32>,
        rlimit: u32,
        top_paths: Vec<(String, u32)>,
    }

    impl MockReader {
        fn new() -> Self {
            Self {
                pids: Mutex::new(HashMap::new()),
                all: Mutex::new(Vec::new()),
            }
        }
        fn set(&self, pid: u32, p: MockPid) {
            self.pids.lock().unwrap().insert(pid, p);
        }
        fn set_all(&self, all: Vec<u32>) {
            *self.all.lock().unwrap() = all;
        }
    }

    impl ProcReader for MockReader {
        fn process_starttime(&self, pid: u32) -> ProcReadResult<u64> {
            if self.pids.lock().unwrap().contains_key(&pid) {
                Ok(u64::from(pid) * 100)
            } else {
                Err(ProcReadError::new(
                    ProcReadErrorKind::Disappeared,
                    "starttime",
                    "process disappeared",
                ))
            }
        }

        fn pid_meta(&self, pid: u32) -> ProcReadResult<(u32, String)> {
            self.pids
                .lock()
                .unwrap()
                .get(&pid)
                .map(|p| (p.uid, p.comm.clone()))
                .ok_or_else(|| {
                    ProcReadError::new(
                        ProcReadErrorKind::Disappeared,
                        "pid_meta",
                        "process disappeared",
                    )
                })
        }
        fn fd_count(&self, pid: u32) -> ProcReadResult<u32> {
            self.pids
                .lock()
                .unwrap()
                .get(&pid)
                .and_then(|p| p.fd_count)
                .ok_or_else(|| {
                    ProcReadError::new(
                        ProcReadErrorKind::Disappeared,
                        "fd_count",
                        "process disappeared",
                    )
                })
        }
        fn rlimit_nofile(&self, pid: u32) -> ProcReadResult<u32> {
            self.pids
                .lock()
                .unwrap()
                .get(&pid)
                .map(|p| p.rlimit)
                .ok_or_else(|| {
                    ProcReadError::new(
                        ProcReadErrorKind::Disappeared,
                        "rlimit",
                        "process disappeared",
                    )
                })
        }
        fn top_fd_paths(&self, pid: u32, n: usize) -> ProcReadResult<Vec<(String, u32)>> {
            let mut v = self
                .pids
                .lock()
                .unwrap()
                .get(&pid)
                .map(|p| p.top_paths.clone())
                .ok_or_else(|| {
                    ProcReadError::new(
                        ProcReadErrorKind::Disappeared,
                        "top_paths",
                        "process disappeared",
                    )
                })?;
            v.truncate(n);
            Ok(v)
        }
        fn all_pids(&self) -> ProcReadResult<Vec<u32>> {
            Ok(self.all.lock().unwrap().clone())
        }
    }

    struct FailingReader(ProcReadErrorKind);

    impl ProcReader for FailingReader {
        fn process_starttime(&self, _pid: u32) -> ProcReadResult<u64> {
            Ok(1)
        }

        fn pid_meta(&self, _pid: u32) -> ProcReadResult<(u32, String)> {
            Ok((1000, "target".into()))
        }

        fn fd_count(&self, _pid: u32) -> ProcReadResult<u32> {
            Err(ProcReadError::new(self.0, "fd_count", "injected"))
        }

        fn rlimit_nofile(&self, _pid: u32) -> ProcReadResult<u32> {
            Ok(1024)
        }

        fn top_fd_paths(&self, _pid: u32, _n: usize) -> ProcReadResult<Vec<(String, u32)>> {
            Ok(Vec::new())
        }

        fn all_pids(&self) -> ProcReadResult<Vec<u32>> {
            Err(ProcReadError::new(self.0, "all_pids", "injected"))
        }
    }

    struct ReuseReader(AtomicU64);

    impl ProcReader for ReuseReader {
        fn process_starttime(&self, _pid: u32) -> ProcReadResult<u64> {
            Ok(self.0.fetch_add(1, Ordering::Relaxed) + 1)
        }

        fn pid_meta(&self, _pid: u32) -> ProcReadResult<(u32, String)> {
            Ok((1000, "target".into()))
        }

        fn fd_count(&self, _pid: u32) -> ProcReadResult<u32> {
            Ok(1)
        }

        fn rlimit_nofile(&self, _pid: u32) -> ProcReadResult<u32> {
            Ok(1024)
        }

        fn top_fd_paths(&self, _pid: u32, _n: usize) -> ProcReadResult<Vec<(String, u32)>> {
            Ok(Vec::new())
        }

        fn all_pids(&self) -> ProcReadResult<Vec<u32>> {
            Ok(vec![42])
        }
    }

    struct ComponentFailReader(&'static str);

    impl ProcReader for ComponentFailReader {
        fn process_starttime(&self, _pid: u32) -> ProcReadResult<u64> {
            Ok(1)
        }

        fn pid_meta(&self, _pid: u32) -> ProcReadResult<(u32, String)> {
            if self.0 == "meta" {
                Err(ProcReadError::new(
                    ProcReadErrorKind::Parse,
                    "meta",
                    "injected",
                ))
            } else {
                Ok((1000, "target".into()))
            }
        }

        fn fd_count(&self, _pid: u32) -> ProcReadResult<u32> {
            Ok(1)
        }

        fn rlimit_nofile(&self, _pid: u32) -> ProcReadResult<u32> {
            if self.0 == "rlimit" {
                Err(ProcReadError::new(
                    ProcReadErrorKind::PermissionDenied,
                    "rlimit",
                    "injected",
                ))
            } else {
                Ok(1024)
            }
        }

        fn top_fd_paths(&self, _pid: u32, _n: usize) -> ProcReadResult<Vec<(String, u32)>> {
            if self.0 == "paths" {
                Err(ProcReadError::new(
                    ProcReadErrorKind::Race,
                    "paths",
                    "injected",
                ))
            } else {
                Ok(Vec::new())
            }
        }

        fn all_pids(&self) -> ProcReadResult<Vec<u32>> {
            Ok(vec![42])
        }
    }

    fn pid(
        uid: u32,
        comm: &str,
        fd_count: Option<u32>,
        rlimit: u32,
        top: Vec<(&str, u32)>,
    ) -> MockPid {
        MockPid {
            uid,
            comm: comm.into(),
            fd_count,
            rlimit,
            top_paths: top.into_iter().map(|(s, c)| (s.to_string(), c)).collect(),
        }
    }

    #[test]
    fn scope_policy_parses_known_aliases() {
        use std::str::FromStr;
        assert_eq!(
            ScopePolicy::from_str("traced").unwrap(),
            ScopePolicy::Traced
        );
        assert_eq!(
            ScopePolicy::from_str("ACTIVE").unwrap(),
            ScopePolicy::Active
        );
        assert!(ScopePolicy::from_str("uid").is_err());
        assert!(ScopePolicy::from_str("uidclass").is_err());
        assert_eq!(ScopePolicy::from_str("all").unwrap(), ScopePolicy::All);
    }

    #[test]
    fn scope_policy_rejects_unknown_value() {
        use std::str::FromStr;
        let err = ScopePolicy::from_str("everything").unwrap_err();
        assert!(err.contains("unknown"), "{err}");
        assert!(err.contains("traced|active|all"), "{err}");
    }

    #[test]
    fn parse_rlimit_nofile_extracts_soft_limit_from_proc_format() {
        // Real Pixel /proc/<pid>/limits format (sample header trimmed).
        let text = "\
Limit                     Soft Limit           Hard Limit           Units
Max cpu time              unlimited            unlimited            seconds
Max file size             unlimited            unlimited            bytes
Max data size             unlimited            unlimited            bytes
Max stack size            8388608              unlimited            bytes
Max processes             3902                 3902                 processes
Max open files            32768                32768                files
Max locked memory         67108864             67108864             bytes
";
        assert_eq!(parse_rlimit_nofile(text), Some(32768));
    }

    #[test]
    fn parse_rlimit_nofile_rejects_missing_line() {
        // Truncated read or malformed file — defensive default.
        assert_eq!(parse_rlimit_nofile(""), None);
        assert_eq!(
            parse_rlimit_nofile("Max cpu time unlimited unlimited seconds"),
            None
        );
    }

    #[test]
    fn parses_starttime_after_parenthesized_comm() {
        let mut fields = vec!["S".to_string()];
        fields.extend((4..=21).map(|field| field.to_string()));
        fields.push("987654".into());
        let stat = format!("42 (worker ) name) {}", fields.join(" "));
        assert_eq!(parse_process_starttime(&stat), Some(987654));
        assert_eq!(parse_process_starttime("malformed"), None);
    }

    #[test]
    fn collect_samples_drops_pids_with_no_fd_count() {
        let r = MockReader::new();
        r.set(42, pid(1000, "alive", Some(120), 1024, vec![]));
        r.set(43, pid(1000, "gone", None, 0, vec![]));
        let (samples, stats) =
            collect_samples(&r, &[42, 43], 1_000_000_000, 0, 43, &mut HashMap::new());
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].pid, 42);
        assert_eq!(samples[0].fd_count, 120);
        assert_eq!(stats.disappeared, 1);
        assert_eq!(stats.target_unreadable_polls, 1);
    }

    #[test]
    fn collect_samples_includes_top_paths_when_n_positive() {
        let r = MockReader::new();
        r.set(
            42,
            pid(
                1000,
                "hal",
                Some(3),
                1024,
                vec![("/dev/dma_heap/system", 2), ("/dev/binder", 1)],
            ),
        );
        let (samples, stats) =
            collect_samples(&r, &[42], 1_000_000_000, 5, 42, &mut HashMap::new());
        assert_eq!(samples[0].top_paths.len(), 2);
        assert_eq!(samples[0].top_paths[0].0, "/dev/dma_heap/system");
        assert_eq!(stats, ProcReadStats::default());
    }

    #[test]
    fn collect_samples_skips_top_paths_when_n_zero() {
        let r = MockReader::new();
        r.set(
            42,
            pid(1000, "hal", Some(3), 1024, vec![("/dev/binder", 1)]),
        );
        let (samples, stats) =
            collect_samples(&r, &[42], 1_000_000_000, 0, 42, &mut HashMap::new());
        assert!(samples[0].top_paths.is_empty());
        assert_eq!(stats, ProcReadStats::default());
    }

    #[test]
    fn proc_failures_are_classified_and_explicit_target_loss_is_observable() {
        let cases = [
            (ProcReadErrorKind::Disappeared, [1, 0, 0, 0, 0, 0]),
            (ProcReadErrorKind::PermissionDenied, [0, 1, 0, 0, 0, 0]),
            (ProcReadErrorKind::Io, [0, 0, 1, 0, 0, 0]),
            (ProcReadErrorKind::Parse, [0, 0, 0, 1, 0, 0]),
            (ProcReadErrorKind::Truncated, [0, 0, 0, 0, 1, 0]),
            (ProcReadErrorKind::Race, [0, 0, 0, 0, 0, 1]),
        ];
        for (kind, expected) in cases {
            let (samples, stats) =
                collect_samples(&FailingReader(kind), &[42], 1, 0, 42, &mut HashMap::new());
            assert!(samples.is_empty());
            assert_eq!(
                [
                    stats.disappeared,
                    stats.permission_errors,
                    stats.io_errors,
                    stats.parse_errors,
                    stats.truncations,
                    stats.races,
                ],
                expected
            );
            assert_eq!(stats.target_unreadable_polls, 1);
        }
    }

    #[test]
    fn pid_reuse_during_sample_suppresses_the_record() {
        let (samples, stats) = collect_samples(
            &ReuseReader(AtomicU64::new(0)),
            &[42],
            1,
            0,
            42,
            &mut HashMap::new(),
        );
        assert!(samples.is_empty());
        assert_eq!(stats.pid_reuse, 1);
        assert_eq!(stats.target_unreadable_polls, 1);
    }

    #[test]
    fn missing_identity_rlimit_or_requested_paths_never_fabricates_a_sample() {
        for component in ["meta", "rlimit", "paths"] {
            let (samples, stats) = collect_samples(
                &ComponentFailReader(component),
                &[42],
                1,
                1,
                42,
                &mut HashMap::new(),
            );
            assert!(samples.is_empty(), "{component}");
            assert_eq!(stats.samples_suppressed_read_errors, 1, "{component}");
            assert_eq!(stats.target_unreadable_polls, 1, "{component}");
        }
    }

    #[test]
    fn spawned_samples_use_the_capture_monotonic_clock() {
        let reader = MockReader::new();
        reader.set(42, pid(1000, "target", Some(1), 1024, vec![]));
        let before = crate::causal::monotonic_timestamp_ns();
        let (samples, _active, stop, handle) = spawn(
            PollerConfig {
                interval: Duration::from_millis(10),
                target_pid: 42,
                ..PollerConfig::default()
            },
            Box::new(reader),
        )
        .unwrap();
        let sample = samples.recv_timeout(Duration::from_secs(1)).unwrap();
        let after = crate::causal::monotonic_timestamp_ns();
        stop.send(()).unwrap();
        handle.join().unwrap();

        assert!(sample.ts_ns >= before && sample.ts_ns <= after);
    }

    #[test]
    fn poller_rejects_busy_spin_and_unreasonable_intervals() {
        for interval in [Duration::ZERO, Duration::from_secs(301)] {
            let result = spawn(
                PollerConfig {
                    interval,
                    ..PollerConfig::default()
                },
                Box::new(MockReader::new()),
            );
            assert!(result.is_err());
        }
    }

    #[test]
    fn stop_interrupts_a_long_poll_interval() {
        let (samples, active, stop, handle) = spawn(
            PollerConfig {
                interval: Duration::from_secs(300),
                ..PollerConfig::default()
            },
            Box::new(MockReader::new()),
        )
        .unwrap();
        drop(samples);
        drop(active);
        stop.send(()).unwrap();
        let started = std::time::Instant::now();
        handle.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn resolve_scope_active_always_includes_explicit_target_pid() {
        let r = MockReader::new();
        let active = HashSet::new();
        let pids = resolve_scope(ScopePolicy::Active, 540, &active, &r).unwrap();
        assert_eq!(pids, vec![540]);
    }

    #[test]
    fn resolve_scope_active_unions_explicit_target_with_active_set() {
        let r = MockReader::new();
        let mut active = HashSet::new();
        active.insert(7);
        active.insert(540);
        let mut pids = resolve_scope(ScopePolicy::Active, 540, &active, &r).unwrap();
        pids.sort();
        assert_eq!(pids, vec![7, 540]);
    }

    #[test]
    fn resolve_scope_traced_with_pid_zero_uses_active_set() {
        let r = MockReader::new();
        let mut active = HashSet::new();
        active.insert(99);
        let pids = resolve_scope(ScopePolicy::Traced, 0, &active, &r).unwrap();
        assert_eq!(pids, vec![99]);
    }

    #[test]
    fn resolve_scope_all_consults_reader_all_pids() {
        let r = MockReader::new();
        r.set_all(vec![1, 2, 3]);
        let active = HashSet::new();
        let mut pids = resolve_scope(ScopePolicy::All, 0, &active, &r).unwrap();
        pids.sort();
        assert_eq!(pids, vec![1, 2, 3]);
    }

    #[test]
    fn resolve_scope_uidclass_is_never_fail_open() {
        let r = MockReader::new();
        let mut active = HashSet::new();
        active.insert(540);
        let error = resolve_scope(ScopePolicy::UidClass, 0, &active, &r).unwrap_err();
        assert!(error.to_string().contains("unsupported"));
    }

    #[test]
    fn rank_descending_with_alphabetical_tiebreak() {
        let mut counts: HashMap<String, u32> = HashMap::new();
        counts.insert("b".into(), 5);
        counts.insert("a".into(), 5); // tie with b
        counts.insert("c".into(), 10);
        let top = rank(counts, 3);
        assert_eq!(
            top,
            vec![
                ("c".to_string(), 10),
                ("a".to_string(), 5),
                ("b".to_string(), 5),
            ]
        );
    }

    #[test]
    fn active_update_channel_saturation_is_counted() {
        let stats = Arc::new(AtomicPollerStats::default());
        let (tx, rx) = mpsc::sync_channel(1);
        let sender = ActiveSetSender::new(tx, Arc::clone(&stats));

        assert!(sender.try_send(HashSet::from([1])).is_ok());
        assert!(matches!(
            sender.try_send(HashSet::from([1, 2])),
            Err(mpsc::TrySendError::Full(_))
        ));
        let snapshot = sender.stats();
        assert_eq!(snapshot.active_updates_sent, 1);
        assert_eq!(snapshot.active_updates_dropped_full, 1);

        drop(rx);
        assert!(matches!(
            sender.try_send(HashSet::from([3])),
            Err(mpsc::TrySendError::Disconnected(_))
        ));
        assert_eq!(sender.stats().active_receiver_disconnected, 1);
    }

    #[test]
    fn sample_channel_saturation_and_disconnect_are_counted() {
        let stats = AtomicPollerStats::default();
        let (tx, rx) = mpsc::sync_channel(1);
        let sample = FdSampleEvent {
            pid: 1,
            uid: 2,
            comm: "sample".into(),
            fd_count: 3,
            rlimit_nofile: 4,
            top_paths: Vec::new(),
            ts_ns: 5,
        };

        assert_eq!(
            try_send_sample(&tx, sample.clone(), &stats),
            SampleSendResult::Sent
        );
        assert_eq!(
            try_send_sample(&tx, sample.clone(), &stats),
            SampleSendResult::DroppedFull
        );
        drop(rx);
        assert_eq!(
            try_send_sample(&tx, sample, &stats),
            SampleSendResult::Disconnected
        );
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.samples_sent, 1);
        assert_eq!(snapshot.samples_dropped_full, 1);
        assert_eq!(snapshot.sample_receiver_disconnected, 1);
    }

    #[test]
    fn poller_counters_saturate_instead_of_wrapping() {
        let counter = AtomicU64::new(u64::MAX);
        increment_saturating(&counter);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn proc_file_reader_rejects_oversize_and_symlink_inputs() {
        let directory = temp_dir();
        fs::create_dir(&directory).unwrap();
        let input = directory.join("status");
        let link = directory.join("status-link");
        fs::write(&input, b"12345").unwrap();
        symlink(&input, &link).unwrap();

        assert_eq!(read_bounded_proc_file(&input, 5).unwrap(), b"12345");
        assert_eq!(
            read_bounded_proc_file(&input, 4).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(read_bounded_proc_file(&link, 5).is_err());

        fs::remove_dir_all(directory).unwrap();
    }
}
