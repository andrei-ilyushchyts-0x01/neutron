//! Userspace file-descriptor graph.
//!
//! Tracks the `(pid, fd) → resource` binding so events that take a bare fd —
//! `ioctl`, `read`, `write`, `mmap`, `ppoll` — can be enriched with the
//! resource's path and kind. Without this binding a line like
//!
//! ```text
//! ioctl(fd=44, cmd=0xc0180921, ...)
//! ```
//!
//! is essentially opaque; with the FD graph it becomes
//!
//! ```text
//! ioctl(fd=44, cmd=0xc0180921, ...) /dev/kgsl-3d0  [device]
//! ```
//!
//! The graph is fully userspace — it does NOT live in BPF maps. The verifier
//! complexity tax of putting fd→path tables in the kernel is not worth the
//! per-event lookup cost we save.
//!
//! ## State transitions
//!
//! | Syscall (aarch64 nr)            | What we do                                  |
//! |----------------------------------|---------------------------------------------|
//! | `openat` (56) exit, `ret >= 0`   | insert `(pid, ret)` with path from `data[]` |
//! | `openat2` (437) exit, `ret >= 0` | same                                        |
//! | `close` (57) enter               | remove `(pid, args[0])`                     |
//! | `dup` (23) exit, `ret >= 0`      | clone `(pid, args[0])` → `(pid, ret)`       |
//! | `dup3` (24) exit, `ret >= 0`     | clone `(pid, args[0])` → `(pid, ret)`       |
//! | `socket` (198) exit, `ret >= 0`  | insert `(pid, ret)` as `Socket`             |
//! | `socketpair` (199) exit          | (pair returned via `args[3]` — best-effort) |
//! | `pipe2` (59) exit                | (pair returned via `args[0]` — best-effort) |
//! | `memfd_create` (279) exit        | insert `(pid, ret)` as `Memfd`              |
//! | `accept` (202) / `accept4` (242) | insert `(pid, ret)` as `Socket`             |
//!
//! ## Misses
//!
//! When `lookup_or_resolve` is called for an `(pid, fd)` we don't know about,
//! we attempt one `/proc/<pid>/fd/<fd>` readlink and backfill the entry. The
//! miss counter increments regardless of whether the fallback succeeded so
//! the capture summary can warn about gaps.

use std::collections::HashMap;

use neutron_common::SyscallEvent;

pub mod poller;

/// Coarse classification of what a fd points at. Driven from the path
/// (or synthetic prefix for socket/pipe/memfd).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdKind {
    File,
    Device,
    Socket,
    Pipe,
    AnonInode,
    Binder,
    Ashmem,
    Memfd,
    Unknown,
}

impl FdKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FdKind::File => "file",
            FdKind::Device => "device",
            FdKind::Socket => "socket",
            FdKind::Pipe => "pipe",
            FdKind::AnonInode => "anon_inode",
            FdKind::Binder => "binder",
            FdKind::Ashmem => "ashmem",
            FdKind::Memfd => "memfd",
            FdKind::Unknown => "unknown",
        }
    }
}

/// Single resource binding kept in the graph.
#[derive(Debug, Clone)]
pub struct FdEntry {
    pub kind: FdKind,
    pub path: String,
    /// Open-time wallclock-equivalent (BPF `bpf_ktime_get_ns()`). 0 for
    /// entries backfilled via `/proc`.
    pub opened_at_ns: u64,
}

impl FdEntry {
    fn new(path: impl Into<String>, ts_ns: u64) -> Self {
        let path = path.into();
        let kind = classify(&path);
        Self {
            kind,
            path,
            opened_at_ns: ts_ns,
        }
    }

    fn synthetic(kind: FdKind, ts_ns: u64) -> Self {
        let path = synthetic_path(kind).to_string();
        Self {
            kind,
            path,
            opened_at_ns: ts_ns,
        }
    }
}

fn synthetic_path(kind: FdKind) -> &'static str {
    match kind {
        FdKind::Socket => "socket:[?]",
        FdKind::Pipe => "pipe:[?]",
        FdKind::AnonInode => "anon_inode:[?]",
        FdKind::Memfd => "anon_inode:memfd:[?]",
        FdKind::Binder => "/dev/binder",
        FdKind::Ashmem => "/dev/ashmem",
        FdKind::Device => "/dev/[?]",
        FdKind::File => "[?]",
        FdKind::Unknown => "[?]",
    }
}

/// Classify a path string into an [`FdKind`].
///
/// Matches in order, most specific first:
/// - `/dev/binder*`, `/dev/hwbinder`, `/dev/vndbinder` → Binder
/// - paths containing `ashmem` → Ashmem
/// - paths containing `memfd:` (in `/proc/<pid>/fd/<fd>` readlinks) → Memfd
/// - `/dev/...` → Device
/// - `socket:[N]` → Socket
/// - `pipe:[N]` → Pipe
/// - `anon_inode:...` → AnonInode
/// - everything else → File
pub fn classify(path: &str) -> FdKind {
    if path.starts_with("/dev/binder") || path == "/dev/hwbinder" || path == "/dev/vndbinder" {
        return FdKind::Binder;
    }
    if path.contains("ashmem") {
        return FdKind::Ashmem;
    }
    if path.contains("memfd:") {
        return FdKind::Memfd;
    }
    if path.starts_with("/dev/") {
        return FdKind::Device;
    }
    if path.starts_with("socket:[") {
        return FdKind::Socket;
    }
    if path.starts_with("pipe:[") {
        return FdKind::Pipe;
    }
    if path.starts_with("anon_inode:") {
        return FdKind::AnonInode;
    }
    if path.is_empty() {
        return FdKind::Unknown;
    }
    FdKind::File
}

/// Per-PID first-class metrics derived from poller samples.
///
/// `current` is computed from the live graph at sample time; the rest are
/// stamped in by [`FdGraph::record_sample`]. Sprint-1 PR 3 adds these so
/// rules like `R001_fd_table_exhaustion` can match `fd_count_pct_of_rlimit_gt`
/// against a single observable predicate.
#[derive(Debug, Clone, Copy, Default)]
pub struct FdStats {
    /// FD count at the last sample. The poller passes the value it read
    /// from `/proc/<pid>/fd` so this is authoritative even when neutron
    /// missed some open/close events earlier in the session.
    pub current: u32,
    /// Maximum [`current`] observed for this PID since the graph was
    /// created. Monotonically non-decreasing — exposed for "fd table grew
    /// to N/M" findings.
    pub high_water_mark: u32,
    /// Average growth rate (fds/second) between the last two samples.
    /// `0.0` until at least two samples have been recorded.
    pub growth_rate_per_sec: f32,
    /// Wallclock-equivalent (`bpf_ktime_get_ns()`-domain) timestamp of the
    /// most recent [`record_sample`] call. `0` when never sampled.
    pub last_sample_ts_ns: u64,
    /// Snapshot of [`current`] at the previous sample. Together with
    /// `last_sample_ts_ns` this is what `growth_rate_per_sec` is computed
    /// from. Reset to zero on `drop_pid`.
    pub last_sample_count: u32,
    /// Per-process open files limit from `/proc/<pid>/limits` (the soft
    /// `RLIMIT_NOFILE`). `0` when unknown — rules guarding on
    /// `fd_count_pct_of_rlimit_gt` skip events with `rlimit == 0`.
    pub rlimit_nofile: u32,
}

impl FdStats {
    /// Percent of `rlimit_nofile` currently consumed, rounded down to the
    /// nearest whole percent. Returns `None` when `rlimit_nofile == 0`
    /// (unknown limit) so rule predicates can distinguish "no signal" from
    /// "0 percent".
    pub fn pct_of_rlimit(&self) -> Option<u8> {
        if self.rlimit_nofile == 0 {
            return None;
        }
        // Use u64 arithmetic to avoid overflow on pathological counts.
        let pct = (self.current as u64 * 100) / self.rlimit_nofile as u64;
        Some(pct.min(100) as u8)
    }
}

/// FD graph keyed by `(pid, fd)`.
///
/// Memory: O(open fds across tracked processes). On Android one app
/// process typically holds 100–500 fds; the cost is negligible.
#[derive(Debug, Default)]
pub struct FdGraph {
    per_pid: HashMap<u32, HashMap<i32, FdEntry>>,
    per_stats: HashMap<u32, FdStats>,
    miss_count: u64,
    backfill_count: u64,
}

impl FdGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of `(pid, fd)` lookups that didn't find a tracked entry.
    /// Includes lookups satisfied by the `/proc/<pid>/fd/<fd>` fallback.
    pub fn miss_count(&self) -> u64 {
        self.miss_count
    }

    /// Number of entries inserted via the `/proc/<pid>/fd/<fd>` fallback
    /// (rather than from a captured open-side syscall).
    pub fn backfill_count(&self) -> u64 {
        self.backfill_count
    }

    /// Drop all state for a pid (e.g. on `exit_group` or process death).
    pub fn drop_pid(&mut self, pid: u32) {
        self.per_pid.remove(&pid);
        self.per_stats.remove(&pid);
    }

    /// First-class metrics for `pid`. `None` when no sample has been
    /// recorded and no fd-bearing event has been observed.
    pub fn stats(&self, pid: u32) -> Option<&FdStats> {
        self.per_stats.get(&pid)
    }

    /// Record a poller sample. Updates `current`, `high_water_mark`, and
    /// (when at least one prior sample is on file) `growth_rate_per_sec`.
    /// `rlimit` is the soft `RLIMIT_NOFILE` from `/proc/<pid>/limits`;
    /// pass `0` when unknown.
    pub fn record_sample(&mut self, pid: u32, count: u32, rlimit: u32, ts_ns: u64) {
        let entry = self.per_stats.entry(pid).or_default();
        // Growth rate over the interval since the last sample. Compare the
        // new `count` against the *previous* sample's count, which is held
        // in `entry.current` until we overwrite it below. Negative deltas
        // (process closed many fds) round to a non-negative rate so rule
        // predicates can use `growth_rate_per_sec > N` without sign quirks.
        let rate = if entry.last_sample_ts_ns != 0 && ts_ns > entry.last_sample_ts_ns {
            let dt_ns = (ts_ns - entry.last_sample_ts_ns) as f64;
            let delta = count as i64 - entry.current as i64;
            ((delta.max(0) as f64) * 1_000_000_000.0 / dt_ns) as f32
        } else {
            0.0
        };
        entry.last_sample_count = entry.current;
        entry.last_sample_ts_ns = ts_ns;
        entry.current = count;
        if count > entry.high_water_mark {
            entry.high_water_mark = count;
        }
        entry.growth_rate_per_sec = rate;
        if rlimit != 0 {
            entry.rlimit_nofile = rlimit;
        }
    }

    /// Top-N most-occurring `path` values across this PID's tracked fds.
    /// Returned in descending count order; ties broken by path string for
    /// stability across runs (test-friendly).
    pub fn top_paths(&self, pid: u32, n: usize) -> Vec<(String, u32)> {
        let Some(map) = self.per_pid.get(&pid) else {
            return Vec::new();
        };
        let mut counts: HashMap<&str, u32> = HashMap::new();
        for entry in map.values() {
            *counts.entry(entry.path.as_str()).or_insert(0) += 1;
        }
        let mut pairs: Vec<(String, u32)> = counts
            .into_iter()
            .map(|(p, c)| (p.to_string(), c))
            .collect();
        // Descending by count, then ascending by path for deterministic
        // ordering — matters for golden-output assertions.
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        pairs.truncate(n);
        pairs
    }

    /// Plain lookup — does NOT touch `/proc`. Returns `None` if the fd is
    /// not in the graph.
    pub fn lookup(&self, pid: u32, fd: i32) -> Option<&FdEntry> {
        self.per_pid.get(&pid)?.get(&fd)
    }

    /// Lookup with a single-shot `/proc/<pid>/fd/<fd>` readlink fallback if
    /// the entry is missing. The backfilled entry is inserted into the
    /// graph for subsequent lookups. The miss counter increments either
    /// way; `backfill_count` increments only on a successful readlink.
    pub fn lookup_or_resolve(&mut self, pid: u32, fd: i32, ts_hint_ns: u64) -> Option<FdEntry> {
        if let Some(entry) = self.per_pid.get(&pid).and_then(|m| m.get(&fd)) {
            return Some(entry.clone());
        }
        self.miss_count = self.miss_count.saturating_add(1);
        let path = crate::decode::resolve_path_from_fd(pid, fd as i64)?;
        let entry = FdEntry::new(path, ts_hint_ns);
        self.backfill_count = self.backfill_count.saturating_add(1);
        self.per_pid
            .entry(pid)
            .or_default()
            .insert(fd, entry.clone());
        Some(entry)
    }

    /// Insert a fully-described entry. Used by direct callers and tests.
    pub fn insert(&mut self, pid: u32, fd: i32, entry: FdEntry) {
        self.per_pid.entry(pid).or_default().insert(fd, entry);
    }

    /// Remove a single fd binding. No-op if absent.
    pub fn remove(&mut self, pid: u32, fd: i32) {
        if let Some(m) = self.per_pid.get_mut(&pid) {
            m.remove(&fd);
        }
    }

    /// Returns the (fd, fd-arg-position) pair that an event references, if
    /// any. Used by the JSON formatter to decide whether to enrich.
    /// `arg_index` is the position of the fd in `ev.args` so callers can
    /// disambiguate (e.g. mmap takes fd at args[4], everyone else at args[0]).
    pub fn fd_arg_for_event(ev: &SyscallEvent) -> Option<(i32, usize)> {
        let nr = { ev.syscall_nr };
        let args = { ev.args };
        match nr {
            // Syscalls with fd at args[0]:
            //   29 = ioctl, 57 = close, 63 = read, 64 = write,
            //   67 = pread64, 68 = pwrite64, 73 = ppoll (first fd if pollfd[0]),
            //   23 = dup, 24 = dup3
            29 | 57 | 63 | 64 | 67 | 68 | 23 | 24 => Some((args[0] as i32, 0)),
            // mmap(222): fd at args[4]. ret is the mapped address; -1 fd
            // means MAP_ANONYMOUS, no resolution.
            222 if (args[4] as i32) >= 0 => Some((args[4] as i32, 4)),
            _ => None,
        }
    }

    /// Drive state transitions from a SyscallEvent. Call once per event
    /// (both enter and exit). `decoded_path` is the path string already
    /// extracted from the event's `data[]` (from `format_data_field`),
    /// passed in to avoid re-decoding here.
    pub fn update(&mut self, ev: &SyscallEvent, decoded_path: Option<&str>) {
        let nr = { ev.syscall_nr };
        let is_enter = { ev.is_enter } != 0;
        let ret = { ev.ret };
        let pid = { ev.pid };
        let args = { ev.args };
        let ts = { ev.timestamp_ns };

        match (nr, is_enter) {
            // openat / openat2 — insert on successful exit
            (56 | 437, false) if ret >= 0 => {
                if let Some(p) = decoded_path {
                    self.insert(pid, ret as i32, FdEntry::new(p, ts));
                }
            }
            // close — remove on enter (regardless of return)
            (57, true) => {
                let fd = args[0] as i32;
                self.remove(pid, fd);
            }
            // dup / dup3 — clone old → new on successful exit
            (23 | 24, false) if ret >= 0 => {
                let old = args[0] as i32;
                let new = ret as i32;
                if let Some(entry) = self.per_pid.get(&pid).and_then(|m| m.get(&old)).cloned() {
                    self.insert(pid, new, entry);
                }
            }
            // socket / accept / accept4 — synthetic socket on success
            (198 | 202 | 242, false) if ret >= 0 => {
                self.insert(pid, ret as i32, FdEntry::synthetic(FdKind::Socket, ts));
            }
            // socketpair (199) / pipe2 (59) — both return TWO fds via a
            // userspace pointer at args[0] / args[3]. The BPF programs do
            // NOT currently fetch that pointer, so we cannot enroll the
            // pair without a userspace `/proc/<pid>/fd/<fd>` follow-up.
            // For MVP, leave the fd pair untracked; `lookup_or_resolve`
            // backfills on first use. TODO(P1): capture the fd pair in
            // `capture_syscall_data` so we don't pay the proc lookup.
            // memfd_create — synthetic memfd on success
            (279, false) if ret >= 0 => {
                self.insert(pid, ret as i32, FdEntry::synthetic(FdKind::Memfd, ts));
            }
            // exit_group — process died; drop all its fds so memory doesn't
            // grow unbounded across long --pid 0 captures.
            (94, true) => {
                self.drop_pid(pid);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev_exit_openat(pid: u32, ret: i64) -> SyscallEvent {
        SyscallEvent {
            pid,
            syscall_nr: 56,
            is_enter: 0,
            ret,
            ..SyscallEvent::default()
        }
    }

    fn ev_enter_close(pid: u32, fd: i32) -> SyscallEvent {
        let mut ev = SyscallEvent {
            pid,
            syscall_nr: 57,
            is_enter: 1,
            ..SyscallEvent::default()
        };
        ev.args[0] = fd as u64;
        ev
    }

    fn ev_exit_dup3(pid: u32, old_fd: i32, new_fd: i32) -> SyscallEvent {
        let mut ev = SyscallEvent {
            pid,
            syscall_nr: 24,
            is_enter: 0,
            ret: new_fd as i64,
            ..SyscallEvent::default()
        };
        ev.args[0] = old_fd as u64;
        ev
    }

    fn ev_exit_socket(pid: u32, fd: i32) -> SyscallEvent {
        SyscallEvent {
            pid,
            syscall_nr: 198,
            is_enter: 0,
            ret: fd as i64,
            ..SyscallEvent::default()
        }
    }

    fn ev_ioctl(pid: u32, fd: i32) -> SyscallEvent {
        let mut ev = SyscallEvent {
            pid,
            syscall_nr: 29,
            is_enter: 1,
            ..SyscallEvent::default()
        };
        ev.args[0] = fd as u64;
        ev
    }

    fn ev_mmap(pid: u32, fd: i32) -> SyscallEvent {
        let mut ev = SyscallEvent {
            pid,
            syscall_nr: 222,
            is_enter: 1,
            ..SyscallEvent::default()
        };
        ev.args[4] = fd as u64;
        ev
    }

    fn ev_exit_memfd(pid: u32, fd: i32) -> SyscallEvent {
        SyscallEvent {
            pid,
            syscall_nr: 279,
            is_enter: 0,
            ret: fd as i64,
            ..SyscallEvent::default()
        }
    }

    #[test]
    fn classify_recognizes_binder_devices() {
        assert_eq!(classify("/dev/binder"), FdKind::Binder);
        assert_eq!(classify("/dev/hwbinder"), FdKind::Binder);
        assert_eq!(classify("/dev/vndbinder"), FdKind::Binder);
        assert_eq!(classify("/dev/binderfs/binder"), FdKind::Binder);
    }

    #[test]
    fn classify_recognizes_ashmem_anywhere_in_path() {
        assert_eq!(classify("/dev/ashmem"), FdKind::Ashmem);
        assert_eq!(classify("/dev/ashmem/something"), FdKind::Ashmem);
    }

    #[test]
    fn classify_distinguishes_memfd_from_anon_inode() {
        assert_eq!(classify("anon_inode:memfd:test"), FdKind::Memfd);
        assert_eq!(classify("anon_inode:[eventfd]"), FdKind::AnonInode);
    }

    #[test]
    fn classify_kgsl_as_device() {
        assert_eq!(classify("/dev/kgsl-3d0"), FdKind::Device);
        assert_eq!(classify("/dev/dma_heap/system"), FdKind::Device);
    }

    #[test]
    fn classify_socket_pipe_prefixes() {
        assert_eq!(classify("socket:[12345]"), FdKind::Socket);
        assert_eq!(classify("pipe:[678]"), FdKind::Pipe);
    }

    #[test]
    fn classify_falls_back_to_file_for_regular_paths() {
        assert_eq!(classify("/data/data/com.example/cache/x"), FdKind::File);
        assert_eq!(classify("/proc/self/maps"), FdKind::File);
    }

    #[test]
    fn classify_empty_is_unknown() {
        assert_eq!(classify(""), FdKind::Unknown);
    }

    #[test]
    fn openat_exit_inserts_entry_with_path_kind() {
        let mut g = FdGraph::new();
        g.update(&ev_exit_openat(42, 7), Some("/dev/kgsl-3d0"));
        let entry = g.lookup(42, 7).expect("entry inserted");
        assert_eq!(entry.path, "/dev/kgsl-3d0");
        assert_eq!(entry.kind, FdKind::Device);
    }

    #[test]
    fn openat_exit_with_negative_ret_does_not_insert() {
        let mut g = FdGraph::new();
        g.update(&ev_exit_openat(42, -2), Some("/nonexistent"));
        assert!(g.lookup(42, -2).is_none());
        assert!(g.per_pid.get(&42).map(|m| m.is_empty()).unwrap_or(true));
    }

    #[test]
    fn close_enter_removes_entry() {
        let mut g = FdGraph::new();
        g.update(&ev_exit_openat(42, 9), Some("/data/x"));
        assert!(g.lookup(42, 9).is_some());
        g.update(&ev_enter_close(42, 9), None);
        assert!(g.lookup(42, 9).is_none());
    }

    #[test]
    fn dup3_clones_entry_to_new_fd() {
        let mut g = FdGraph::new();
        g.update(&ev_exit_openat(42, 5), Some("/dev/binder"));
        g.update(&ev_exit_dup3(42, 5, 17), None);
        let dup = g.lookup(42, 17).expect("dup3 cloned");
        assert_eq!(dup.path, "/dev/binder");
        assert_eq!(dup.kind, FdKind::Binder);
    }

    #[test]
    fn dup3_without_source_does_not_create_orphan() {
        let mut g = FdGraph::new();
        g.update(&ev_exit_dup3(42, 99, 17), None);
        assert!(g.lookup(42, 17).is_none());
    }

    #[test]
    fn socket_inserts_synthetic_entry() {
        let mut g = FdGraph::new();
        g.update(&ev_exit_socket(42, 4), None);
        let s = g.lookup(42, 4).expect("socket inserted");
        assert_eq!(s.kind, FdKind::Socket);
        assert!(s.path.starts_with("socket:"));
    }

    #[test]
    fn memfd_create_inserts_synthetic_entry() {
        let mut g = FdGraph::new();
        g.update(&ev_exit_memfd(42, 11), None);
        let s = g.lookup(42, 11).expect("memfd inserted");
        assert_eq!(s.kind, FdKind::Memfd);
    }

    fn ev_enter_exit_group(pid: u32) -> SyscallEvent {
        SyscallEvent {
            pid,
            syscall_nr: 94,
            is_enter: 1,
            ..SyscallEvent::default()
        }
    }

    #[test]
    fn exit_group_drops_pid_state() {
        let mut g = FdGraph::new();
        g.update(&ev_exit_openat(42, 5), Some("/x"));
        g.update(&ev_exit_openat(42, 6), Some("/y"));
        g.update(&ev_enter_exit_group(42), None);
        assert!(g.lookup(42, 5).is_none());
        assert!(g.lookup(42, 6).is_none());
    }

    #[test]
    fn drop_pid_removes_all_entries_for_pid() {
        let mut g = FdGraph::new();
        g.update(&ev_exit_openat(42, 5), Some("/x"));
        g.update(&ev_exit_openat(42, 6), Some("/y"));
        g.update(&ev_exit_openat(99, 5), Some("/z"));
        g.drop_pid(42);
        assert!(g.lookup(42, 5).is_none());
        assert!(g.lookup(42, 6).is_none());
        assert!(g.lookup(99, 5).is_some());
    }

    #[test]
    fn lookup_or_resolve_increments_miss_when_not_tracked() {
        let mut g = FdGraph::new();
        // /proc/0/fd/99 readlink is guaranteed to fail on a normal host.
        let _ = g.lookup_or_resolve(0, 99, 0);
        assert_eq!(g.miss_count(), 1);
        assert_eq!(g.backfill_count(), 0);
    }

    #[test]
    fn lookup_or_resolve_returns_tracked_entry_without_miss() {
        let mut g = FdGraph::new();
        g.insert(7, 3, FdEntry::new("/dev/null", 0));
        let hit = g.lookup_or_resolve(7, 3, 0).expect("tracked");
        assert_eq!(hit.path, "/dev/null");
        assert_eq!(g.miss_count(), 0);
    }

    #[test]
    fn fd_kind_strings_are_stable() {
        assert_eq!(FdKind::Device.as_str(), "device");
        assert_eq!(FdKind::Binder.as_str(), "binder");
        assert_eq!(FdKind::Memfd.as_str(), "memfd");
    }

    #[test]
    fn fd_arg_for_event_recognizes_ioctl_at_args_zero() {
        let ev = ev_ioctl(7, 12);
        assert_eq!(FdGraph::fd_arg_for_event(&ev), Some((12, 0)));
    }

    #[test]
    fn fd_arg_for_event_recognizes_mmap_at_args_four() {
        let ev = ev_mmap(7, 5);
        assert_eq!(FdGraph::fd_arg_for_event(&ev), Some((5, 4)));
    }

    #[test]
    fn fd_arg_for_event_treats_anonymous_mmap_as_no_fd() {
        let mut ev = ev_mmap(7, -1);
        ev.args[4] = (-1i64) as u64;
        assert_eq!(FdGraph::fd_arg_for_event(&ev), None);
    }

    #[test]
    fn fd_arg_for_event_skips_non_fd_syscalls() {
        let ev = ev_exit_openat(7, 5);
        assert_eq!(FdGraph::fd_arg_for_event(&ev), None);
    }

    // ── FdStats / poller-facing metrics (sprint-1 PR 3) ─────────────────────

    #[test]
    fn record_sample_initialises_high_water_and_zero_growth_rate() {
        let mut g = FdGraph::new();
        g.record_sample(42, 100, 1024, 1_000_000_000);
        let s = g.stats(42).expect("stats present after first sample");
        assert_eq!(s.current, 100);
        assert_eq!(s.high_water_mark, 100);
        assert_eq!(s.rlimit_nofile, 1024);
        // First sample has no prior data point — growth rate stays 0.
        assert_eq!(s.growth_rate_per_sec, 0.0);
    }

    #[test]
    fn record_sample_high_water_mark_is_monotonic() {
        let mut g = FdGraph::new();
        g.record_sample(42, 100, 1024, 1_000_000_000);
        g.record_sample(42, 50, 1024, 2_000_000_000);
        // current shrank but HWM must not regress.
        assert_eq!(g.stats(42).unwrap().current, 50);
        assert_eq!(g.stats(42).unwrap().high_water_mark, 100);
        g.record_sample(42, 150, 1024, 3_000_000_000);
        assert_eq!(g.stats(42).unwrap().high_water_mark, 150);
    }

    #[test]
    fn record_sample_growth_rate_uses_last_two_samples() {
        let mut g = FdGraph::new();
        g.record_sample(42, 100, 1024, 1_000_000_000);
        // 1s later, +50 fds → 50 fds/s.
        g.record_sample(42, 150, 1024, 2_000_000_000);
        let rate = g.stats(42).unwrap().growth_rate_per_sec;
        assert!((rate - 50.0).abs() < 0.5, "expected ~50 fds/s, got {rate}");
    }

    #[test]
    fn record_sample_negative_delta_clamps_growth_rate_to_zero() {
        // Process closed fds between samples. We don't model that as a
        // negative rate (rules use `> N` predicates); growth rate stays >= 0.
        let mut g = FdGraph::new();
        g.record_sample(42, 200, 1024, 1_000_000_000);
        g.record_sample(42, 100, 1024, 2_000_000_000);
        assert_eq!(g.stats(42).unwrap().growth_rate_per_sec, 0.0);
    }

    #[test]
    fn pct_of_rlimit_returns_none_when_limit_unknown() {
        let mut g = FdGraph::new();
        g.record_sample(42, 100, 0, 1_000_000_000);
        assert_eq!(g.stats(42).unwrap().pct_of_rlimit(), None);
    }

    #[test]
    fn pct_of_rlimit_rounds_down_and_caps_at_one_hundred() {
        let mut g = FdGraph::new();
        g.record_sample(42, 950, 1000, 1_000_000_000);
        assert_eq!(g.stats(42).unwrap().pct_of_rlimit(), Some(95));
        // Capping protects against rlimit changing mid-session.
        g.record_sample(42, 2000, 1000, 2_000_000_000);
        assert_eq!(g.stats(42).unwrap().pct_of_rlimit(), Some(100));
    }

    #[test]
    fn top_paths_returns_descending_counts_with_path_tiebreak() {
        let mut g = FdGraph::new();
        // Three fds to /dev/dma_heap/system, two to /dev/binder, one to /tmp/x.
        g.insert(7, 1, FdEntry::new("/dev/dma_heap/system", 0));
        g.insert(7, 2, FdEntry::new("/dev/dma_heap/system", 0));
        g.insert(7, 3, FdEntry::new("/dev/dma_heap/system", 0));
        g.insert(7, 4, FdEntry::new("/dev/binder", 0));
        g.insert(7, 5, FdEntry::new("/dev/binder", 0));
        g.insert(7, 6, FdEntry::new("/tmp/x", 0));
        let top = g.top_paths(7, 2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0], ("/dev/dma_heap/system".into(), 3));
        assert_eq!(top[1], ("/dev/binder".into(), 2));
    }

    #[test]
    fn top_paths_returns_empty_for_unknown_pid() {
        let g = FdGraph::new();
        assert!(g.top_paths(42, 5).is_empty());
    }

    #[test]
    fn drop_pid_clears_per_stats_too() {
        let mut g = FdGraph::new();
        g.record_sample(42, 100, 1024, 1_000_000_000);
        g.drop_pid(42);
        assert!(g.stats(42).is_none());
    }
}
