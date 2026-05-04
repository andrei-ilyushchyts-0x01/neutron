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
use std::path::Path;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// One sample emitted per in-scope PID per poller tick. Crosses the
/// `mpsc::sync_channel` from the poller thread back to the main loop.
#[derive(Debug, Clone)]
pub struct FdSampleEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub fd_count: u32,
    /// Soft `RLIMIT_NOFILE` from `/proc/<pid>/limits`. `0` when unknown
    /// (process gone, permission denied) — downstream consumers must treat
    /// `0` as "no signal", not "0 percent".
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

/// Which PIDs the poller should sample on each tick.
///
/// CLI exposes this as `--fdgraph-pids traced|active|uid|all` with `Active`
/// as the default. `UidClass` is parseable today but degrades to `Active`
/// at runtime (full UID-class support is on the sprint-2 list).
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
    /// All PIDs sharing a UID class with the target. Sprint-2 feature —
    /// today this falls back to `Active` with a stderr warning.
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
            "uid" | "uidclass" => Ok(Self::UidClass),
            "all" => Ok(Self::All),
            other => Err(format!(
                "unknown --fdgraph-pids value '{other}' (expected: traced|active|uid|all)"
            )),
        }
    }
}

/// Abstraction over `/proc` reads — production uses [`RealProcReader`];
/// tests substitute a canned-data implementation so unit tests never
/// touch the host filesystem and stay deterministic.
pub trait ProcReader: Send + Sync + 'static {
    /// `(uid, comm)` for `pid`. `None` when the process is gone or
    /// `/proc/<pid>/status` is unreadable.
    fn pid_meta(&self, pid: u32) -> Option<(u32, String)>;
    /// Count of fd entries under `/proc/<pid>/fd/`. `None` on read error.
    fn fd_count(&self, pid: u32) -> Option<u32>;
    /// Soft `RLIMIT_NOFILE` from `/proc/<pid>/limits`. `0` on read error
    /// so callers can still emit a partial sample.
    fn rlimit_nofile(&self, pid: u32) -> u32;
    /// Top-N targets of `/proc/<pid>/fd/<fd>` readlinks, sorted by
    /// occurrence. Empty when `n == 0` or on read error.
    fn top_fd_paths(&self, pid: u32, n: usize) -> Vec<(String, u32)>;
    /// All numeric entries in `/proc/`. Used only by `ScopePolicy::All`.
    /// Default impl returns empty so `ScopePolicy::All` requires explicit
    /// reader support.
    fn all_pids(&self) -> Vec<u32> {
        Vec::new()
    }
}

/// Real `/proc` reader. Production wiring.
pub struct RealProcReader;

impl ProcReader for RealProcReader {
    fn pid_meta(&self, pid: u32) -> Option<(u32, String)> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let mut uid: Option<u32> = None;
        let mut name: Option<String> = None;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Name:") {
                name = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("Uid:") {
                uid = rest.split_whitespace().next().and_then(|s| s.parse().ok());
            }
            if uid.is_some() && name.is_some() {
                break;
            }
        }
        Some((uid.unwrap_or(0), name.unwrap_or_default()))
    }

    fn fd_count(&self, pid: u32) -> Option<u32> {
        let entries = std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
        let mut count: u32 = 0;
        for _ in entries {
            count = count.saturating_add(1);
        }
        Some(count)
    }

    fn rlimit_nofile(&self, pid: u32) -> u32 {
        let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/limits")) else {
            return 0;
        };
        parse_rlimit_nofile(&text)
    }

    fn top_fd_paths(&self, pid: u32, n: usize) -> Vec<(String, u32)> {
        if n == 0 {
            return Vec::new();
        }
        let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            return Vec::new();
        };
        let mut counts: HashMap<String, u32> = HashMap::new();
        for entry in entries.flatten() {
            if let Ok(target) = std::fs::read_link(entry.path()) {
                *counts
                    .entry(target.to_string_lossy().into_owned())
                    .or_insert(0) += 1;
            }
        }
        rank(counts, n)
    }

    fn all_pids(&self) -> Vec<u32> {
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name();
                let s = name.to_str()?;
                s.parse().ok()
            })
            .collect()
    }
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
pub(crate) fn parse_rlimit_nofile(text: &str) -> u32 {
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
                return soft;
            }
        }
    }
    0
}

/// Pure sample collection: given a [`ProcReader`] and a set of in-scope
/// PIDs, return one [`FdSampleEvent`] per PID the reader recognises.
/// Skips PIDs whose `fd_count` read fails (process gone). `top_paths_n`
/// of `0` skips per-sample readlink work.
pub fn collect_samples(
    reader: &dyn ProcReader,
    pids: &[u32],
    ts_ns: u64,
    top_paths_n: usize,
) -> Vec<FdSampleEvent> {
    let mut out = Vec::with_capacity(pids.len());
    for &pid in pids {
        let Some(fd_count) = reader.fd_count(pid) else {
            continue;
        };
        let (uid, comm) = reader.pid_meta(pid).unwrap_or((0, String::new()));
        let rlimit = reader.rlimit_nofile(pid);
        let top = reader.top_fd_paths(pid, top_paths_n);
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
    out
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

/// Resolve the in-scope PID set under `policy`. Pure — exported so the
/// CLI can dry-run a scope decision and tests can assert behaviour without
/// spawning a thread.
pub fn resolve_scope(
    policy: ScopePolicy,
    target_pid: u32,
    active: &HashSet<u32>,
    reader: &dyn ProcReader,
) -> Vec<u32> {
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
            set.into_iter().collect()
        }
        ScopePolicy::Active => {
            let mut set: HashSet<u32> = active.clone();
            if target_pid != 0 {
                // Always include the explicit target so a brand-new traced
                // process gets sampled before its first fd-bearing syscall.
                set.insert(target_pid);
            }
            set.into_iter().collect()
        }
        ScopePolicy::UidClass => {
            eprintln!(
                "neutron: --fdgraph-pids=uid is not implemented in sprint-1; \
                 falling back to active scope"
            );
            let mut set: HashSet<u32> = active.clone();
            if target_pid != 0 {
                set.insert(target_pid);
            }
            set.into_iter().collect()
        }
        ScopePolicy::All => reader.all_pids(),
    }
}

/// Spawn the poller thread. Returns `(samples_rx, active_tx, stop_tx,
/// JoinHandle)`. The main loop:
/// - reads new samples via `samples_rx.try_recv()` each iteration;
/// - sends a fresh active-PID set via `active_tx.try_send(...)` whenever
///   it observes a new fd-bearing event for an unfamiliar PID;
/// - sends `()` on `stop_tx` to signal shutdown (or simply drops the
///   sender — the thread exits when the next try_recv returns
///   `Disconnected`).
pub fn spawn(
    cfg: PollerConfig,
    reader: Box<dyn ProcReader>,
) -> (
    Receiver<FdSampleEvent>,
    SyncSender<HashSet<u32>>,
    SyncSender<()>,
    JoinHandle<()>,
) {
    let (samples_tx, samples_rx) = mpsc::sync_channel::<FdSampleEvent>(1024);
    let (active_tx, active_rx) = mpsc::sync_channel::<HashSet<u32>>(8);
    let (stop_tx, stop_rx) = mpsc::sync_channel::<()>(1);

    let handle = thread::spawn(move || {
        let mut current_active: HashSet<u32> = HashSet::new();
        let start = Instant::now();
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
            }
            let pids = resolve_scope(cfg.scope, cfg.target_pid, &current_active, reader.as_ref());
            let ts_ns = start.elapsed().as_nanos() as u64;
            for sample in collect_samples(reader.as_ref(), &pids, ts_ns, cfg.top_paths_n) {
                if samples_tx.try_send(sample).is_err() {
                    // Channel full or main loop dropped its receiver. Drop
                    // this sample. Sustained drops indicate the consumer is
                    // backed up; sprint-2 surfaces this in capture summary.
                    break;
                }
            }
            thread::sleep(cfg.interval);
        }
    });

    (samples_rx, active_tx, stop_tx, handle)
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
    use std::sync::Mutex;

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
        fn pid_meta(&self, pid: u32) -> Option<(u32, String)> {
            self.pids
                .lock()
                .unwrap()
                .get(&pid)
                .map(|p| (p.uid, p.comm.clone()))
        }
        fn fd_count(&self, pid: u32) -> Option<u32> {
            self.pids.lock().unwrap().get(&pid).and_then(|p| p.fd_count)
        }
        fn rlimit_nofile(&self, pid: u32) -> u32 {
            self.pids
                .lock()
                .unwrap()
                .get(&pid)
                .map(|p| p.rlimit)
                .unwrap_or(0)
        }
        fn top_fd_paths(&self, pid: u32, n: usize) -> Vec<(String, u32)> {
            let mut v = self
                .pids
                .lock()
                .unwrap()
                .get(&pid)
                .map(|p| p.top_paths.clone())
                .unwrap_or_default();
            v.truncate(n);
            v
        }
        fn all_pids(&self) -> Vec<u32> {
            self.all.lock().unwrap().clone()
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
        assert_eq!(ScopePolicy::from_str("uid").unwrap(), ScopePolicy::UidClass);
        assert_eq!(
            ScopePolicy::from_str("uidclass").unwrap(),
            ScopePolicy::UidClass
        );
        assert_eq!(ScopePolicy::from_str("all").unwrap(), ScopePolicy::All);
    }

    #[test]
    fn scope_policy_rejects_unknown_value() {
        use std::str::FromStr;
        let err = ScopePolicy::from_str("everything").unwrap_err();
        assert!(err.contains("unknown"), "{err}");
        assert!(err.contains("traced|active|uid|all"), "{err}");
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
        assert_eq!(parse_rlimit_nofile(text), 32768);
    }

    #[test]
    fn parse_rlimit_nofile_returns_zero_on_missing_line() {
        // Truncated read or malformed file — defensive default.
        assert_eq!(parse_rlimit_nofile(""), 0);
        assert_eq!(
            parse_rlimit_nofile("Max cpu time unlimited unlimited seconds"),
            0
        );
    }

    #[test]
    fn collect_samples_drops_pids_with_no_fd_count() {
        let r = MockReader::new();
        r.set(42, pid(1000, "alive", Some(120), 1024, vec![]));
        r.set(43, pid(1000, "gone", None, 0, vec![]));
        let samples = collect_samples(&r, &[42, 43], 1_000_000_000, 0);
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].pid, 42);
        assert_eq!(samples[0].fd_count, 120);
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
        let samples = collect_samples(&r, &[42], 1_000_000_000, 5);
        assert_eq!(samples[0].top_paths.len(), 2);
        assert_eq!(samples[0].top_paths[0].0, "/dev/dma_heap/system");
    }

    #[test]
    fn collect_samples_skips_top_paths_when_n_zero() {
        let r = MockReader::new();
        r.set(
            42,
            pid(1000, "hal", Some(3), 1024, vec![("/dev/binder", 1)]),
        );
        let samples = collect_samples(&r, &[42], 1_000_000_000, 0);
        assert!(samples[0].top_paths.is_empty());
    }

    #[test]
    fn resolve_scope_active_always_includes_explicit_target_pid() {
        let r = MockReader::new();
        let active = HashSet::new();
        let pids = resolve_scope(ScopePolicy::Active, 540, &active, &r);
        assert_eq!(pids, vec![540]);
    }

    #[test]
    fn resolve_scope_active_unions_explicit_target_with_active_set() {
        let r = MockReader::new();
        let mut active = HashSet::new();
        active.insert(7);
        active.insert(540);
        let mut pids = resolve_scope(ScopePolicy::Active, 540, &active, &r);
        pids.sort();
        assert_eq!(pids, vec![7, 540]);
    }

    #[test]
    fn resolve_scope_traced_with_pid_zero_uses_active_set() {
        let r = MockReader::new();
        let mut active = HashSet::new();
        active.insert(99);
        let pids = resolve_scope(ScopePolicy::Traced, 0, &active, &r);
        assert_eq!(pids, vec![99]);
    }

    #[test]
    fn resolve_scope_all_consults_reader_all_pids() {
        let r = MockReader::new();
        r.set_all(vec![1, 2, 3]);
        let active = HashSet::new();
        let mut pids = resolve_scope(ScopePolicy::All, 0, &active, &r);
        pids.sort();
        assert_eq!(pids, vec![1, 2, 3]);
    }

    #[test]
    fn resolve_scope_uidclass_logs_and_falls_back_to_active() {
        let r = MockReader::new();
        let mut active = HashSet::new();
        active.insert(540);
        let pids = resolve_scope(ScopePolicy::UidClass, 0, &active, &r);
        assert_eq!(pids, vec![540]);
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
}
