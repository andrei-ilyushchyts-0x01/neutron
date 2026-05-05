//! In-flight binder transaction tracker (sprint-2 PR 2).
//!
//! The userspace correlator pairs caller-side `binder/binder_transaction`
//! events (BPF nr=-1) with callee-side `binder/binder_transaction_received`
//! events (BPF nr=-4) by `debug_id` carried in `ptr_hint`. When both halves
//! are observed, the tracker emits a synthesised
//! [`BinderCallEvent`] with status [`BinderCallStatus::Completed`].
//!
//! The tracker also serves crash correlation: when a `process_exit` fires
//! with `classification == "crash"`, [`BinderTracker::on_callee_crash`]
//! drains any in-flight transactions whose callee equals the dying PID and
//! emits them as [`BinderCallStatus::CalleeCrashed`]. This is the source of
//! the `R004_binder_callee_crash` finding.
//!
//! # Memory bound
//!
//! Bounded LRU keyed by `debug_id` with a default cap of 1024 in-flight
//! entries. When inserting would exceed the cap, the least-recently-touched
//! entry is silently dropped (its `binder_call` event is lost — see Q4 in
//! the design doc; surfacing evicted entries as `Unmatched` is a follow-up).

use std::collections::HashMap;

use neutron_common::BinderCallStatus;

/// Default in-flight cap. ~256 bytes per entry → ~256 KB worst case.
const DEFAULT_MAX_INFLIGHT: usize = 1024;

/// Synthesised pair-event surfaced by the tracker. Always has a complete
/// caller→callee mapping (`callee_pid` is taken from the caller-side
/// `to_proc` field, which is populated at send time).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinderCallEvent {
    pub debug_id: i32,
    pub caller_pid: u32,
    pub caller_uid: u32,
    pub caller_comm: String,
    pub callee_pid: u32,
    pub code: u32,
    pub flags: u32,
    pub reply: bool,
    pub sent_ts_ns: u64,
    /// `Some(ts)` when matched against a received event; `None` when the
    /// callee crashed before dequeueing the transaction.
    pub received_ts_ns: Option<u64>,
    pub status: BinderCallStatus,
}

impl BinderCallEvent {
    /// Latency in microseconds. `None` until a receive event matches the
    /// caller (i.e. for `CalleeCrashed` entries that never received).
    pub fn latency_us(&self) -> Option<u64> {
        let recv = self.received_ts_ns?;
        Some(recv.saturating_sub(self.sent_ts_ns) / 1_000)
    }
}

/// One in-flight transaction recorded by the caller-side tracepoint.
#[derive(Clone, Debug)]
struct Inflight {
    caller_pid: u32,
    caller_uid: u32,
    caller_comm: String,
    callee_pid: u32,
    code: u32,
    flags: u32,
    reply: bool,
    sent_ts_ns: u64,
    /// LRU tick — bumped on every operation that touches this entry.
    lru: u64,
}

/// Bounded LRU map of in-flight binder transactions.
#[derive(Debug)]
pub struct BinderTracker {
    max_inflight: usize,
    inflight: HashMap<i32, Inflight>,
    tick: u64,
}

impl Default for BinderTracker {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_INFLIGHT)
    }
}

impl BinderTracker {
    pub fn new(max_inflight: usize) -> Self {
        Self {
            max_inflight: max_inflight.max(1),
            inflight: HashMap::new(),
            tick: 0,
        }
    }

    pub fn max_inflight(&self) -> usize {
        self.max_inflight
    }

    pub fn inflight_count(&self) -> usize {
        self.inflight.len()
    }

    /// Record a caller-side `binder_transaction` event. `callee_pid` is the
    /// `to_proc` field from the BPF-decoded args. `debug_id == 0` is treated
    /// as "no usable id" and silently dropped (the kernel has been observed
    /// to emit `0` on early-init paths before the binder driver assigned an
    /// id; we cannot pair those).
    #[allow(clippy::too_many_arguments)]
    pub fn record_caller(
        &mut self,
        debug_id: i32,
        caller_pid: u32,
        caller_uid: u32,
        caller_comm: impl Into<String>,
        callee_pid: u32,
        code: u32,
        flags: u32,
        reply: bool,
        sent_ts_ns: u64,
    ) {
        if debug_id == 0 || caller_pid == 0 {
            return;
        }
        self.tick = self.tick.wrapping_add(1);
        let entry = Inflight {
            caller_pid,
            caller_uid,
            caller_comm: caller_comm.into(),
            callee_pid,
            code,
            flags,
            reply,
            sent_ts_ns,
            lru: self.tick,
        };
        self.inflight.insert(debug_id, entry);
        // Evict LRU until within cap.
        while self.inflight.len() > self.max_inflight {
            if let Some(victim) = self
                .inflight
                .iter()
                .min_by_key(|(_, v)| v.lru)
                .map(|(k, _)| *k)
            {
                self.inflight.remove(&victim);
            } else {
                break;
            }
        }
    }

    /// Record a callee-side `binder_transaction_received` event. Returns the
    /// completed pair as a [`BinderCallEvent`] when the matching caller is
    /// found; returns `None` for an unmatched receive (which happens when
    /// caller-side filtering dropped the originating event).
    pub fn record_received(
        &mut self,
        debug_id: i32,
        received_ts_ns: u64,
    ) -> Option<BinderCallEvent> {
        if debug_id == 0 {
            return None;
        }
        let inflight = self.inflight.remove(&debug_id)?;
        Some(BinderCallEvent {
            debug_id,
            caller_pid: inflight.caller_pid,
            caller_uid: inflight.caller_uid,
            caller_comm: inflight.caller_comm,
            callee_pid: inflight.callee_pid,
            code: inflight.code,
            flags: inflight.flags,
            reply: inflight.reply,
            sent_ts_ns: inflight.sent_ts_ns,
            received_ts_ns: Some(received_ts_ns),
            status: BinderCallStatus::Completed,
        })
    }

    /// Drain in-flight transactions whose callee equals `crashed_pid` and
    /// emit them as [`BinderCallStatus::CalleeCrashed`]. Called by the main
    /// loop on every `process_exit` event with `classification == "crash"`.
    pub fn on_callee_crash(&mut self, crashed_pid: u32) -> Vec<BinderCallEvent> {
        if crashed_pid == 0 {
            return Vec::new();
        }
        let to_drain: Vec<i32> = self
            .inflight
            .iter()
            .filter(|(_, v)| v.callee_pid == crashed_pid)
            .map(|(k, _)| *k)
            .collect();
        let mut out = Vec::with_capacity(to_drain.len());
        for id in to_drain {
            if let Some(entry) = self.inflight.remove(&id) {
                out.push(BinderCallEvent {
                    debug_id: id,
                    caller_pid: entry.caller_pid,
                    caller_uid: entry.caller_uid,
                    caller_comm: entry.caller_comm,
                    callee_pid: entry.callee_pid,
                    code: entry.code,
                    flags: entry.flags,
                    reply: entry.reply,
                    sent_ts_ns: entry.sent_ts_ns,
                    received_ts_ns: None,
                    status: BinderCallStatus::CalleeCrashed,
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_call(t: &mut BinderTracker, debug_id: i32, caller: u32, callee: u32, ts: u64) {
        t.record_caller(debug_id, caller, 1000, "caller", callee, 7, 0, false, ts);
    }

    #[test]
    fn caller_then_received_emits_completed_pair() {
        let mut t = BinderTracker::new(64);
        record_call(&mut t, 42, 100, 200, 1_000_000);
        assert_eq!(t.inflight_count(), 1);
        let pair = t.record_received(42, 1_500_000).expect("pair matches");
        assert_eq!(pair.caller_pid, 100);
        assert_eq!(pair.callee_pid, 200);
        assert_eq!(pair.code, 7);
        assert_eq!(pair.status, BinderCallStatus::Completed);
        assert_eq!(pair.latency_us(), Some(500));
        assert_eq!(t.inflight_count(), 0, "matched entry must be removed");
    }

    #[test]
    fn unmatched_received_returns_none() {
        let mut t = BinderTracker::new(64);
        // Receive without a prior caller record (caller-side was filtered).
        assert!(t.record_received(99, 1_000_000).is_none());
    }

    #[test]
    fn debug_id_zero_is_dropped_on_both_sides() {
        let mut t = BinderTracker::new(64);
        record_call(&mut t, 0, 100, 200, 1_000_000);
        assert_eq!(t.inflight_count(), 0);
        assert!(t.record_received(0, 1_000_000).is_none());
    }

    #[test]
    fn crash_drains_only_matching_callee() {
        let mut t = BinderTracker::new(64);
        record_call(&mut t, 1, 100, 200, 1_000);
        record_call(&mut t, 2, 100, 200, 2_000);
        record_call(&mut t, 3, 100, 999, 3_000); // different callee
        let drained = t.on_callee_crash(200);
        assert_eq!(drained.len(), 2);
        for ev in &drained {
            assert_eq!(ev.callee_pid, 200);
            assert_eq!(ev.status, BinderCallStatus::CalleeCrashed);
            assert!(ev.received_ts_ns.is_none());
            assert!(ev.latency_us().is_none());
        }
        assert_eq!(t.inflight_count(), 1, "PID 999 transaction must remain");
    }

    #[test]
    fn lru_evicts_oldest_when_over_cap() {
        let mut t = BinderTracker::new(2);
        record_call(&mut t, 1, 1, 1, 100);
        record_call(&mut t, 2, 2, 2, 200);
        record_call(&mut t, 3, 3, 3, 300); // forces eviction of id=1
        assert_eq!(t.inflight_count(), 2);
        assert!(
            t.record_received(1, 0).is_none(),
            "id=1 should have been evicted"
        );
        assert!(t.record_received(2, 0).is_some());
        assert!(t.record_received(3, 0).is_some());
    }

    #[test]
    fn on_callee_crash_with_pid_zero_is_noop() {
        let mut t = BinderTracker::new(64);
        record_call(&mut t, 1, 100, 0, 1_000);
        let drained = t.on_callee_crash(0);
        assert!(drained.is_empty());
        assert_eq!(t.inflight_count(), 1, "entries with callee_pid=0 untouched");
    }

    #[test]
    fn crashed_pair_carries_caller_metadata() {
        let mut t = BinderTracker::new(64);
        t.record_caller(7, 100, 1000, "myapp", 200, 13, 1, false, 1_000_000);
        let drained = t.on_callee_crash(200);
        assert_eq!(drained.len(), 1);
        let p = &drained[0];
        assert_eq!(p.caller_comm, "myapp");
        assert_eq!(p.caller_uid, 1000);
        assert_eq!(p.code, 13);
        assert_eq!(p.flags, 1);
        assert!(!p.reply);
    }
}
