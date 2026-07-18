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
//! entries. Evictions, unmatched receive events, and discarded causal
//! metadata are counted so final capture health cannot silently claim a
//! complete causal view.

use std::collections::HashMap;

use neutron_common::BinderCallStatus;

use crate::causal::CausalMetadata;

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
    /// Phase 4b — binder handle (`target_node` field of the kernel
    /// tracepoint). Combined with `callee_pid`, identifies a specific
    /// service/interface in the callee process. `0` when the BPF
    /// captured no value (legacy traces from before Phase 4b).
    pub target_node: i32,
    pub sent_ts_ns: u64,
    /// `Some(ts)` when matched against a received event; `None` when the
    /// callee crashed before dequeueing the transaction.
    pub received_ts_ns: Option<u64>,
    pub status: BinderCallStatus,
    pub causal_metadata: Option<CausalMetadata>,
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
    target_node: i32,
    sent_ts_ns: u64,
    causal_metadata: Option<CausalMetadata>,
    /// LRU tick — bumped on every operation that touches this entry.
    lru: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BinderTrackerStats {
    pub baseline_discarded: u64,
    pub tracker_evictions: u64,
    pub unmatched_receives: u64,
    pub causal_metadata_discarded: u64,
    pub invalid_callers: u64,
}

/// Bounded LRU map of in-flight binder transactions.
#[derive(Debug)]
pub struct BinderTracker {
    max_inflight: usize,
    inflight: HashMap<i32, Inflight>,
    tick: u64,
    stats: BinderTrackerStats,
    scenario_bounded: bool,
    active_generation: Option<u16>,
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
            stats: BinderTrackerStats::default(),
            scenario_bounded: false,
            active_generation: None,
        }
    }

    pub fn max_inflight(&self) -> usize {
        self.max_inflight
    }

    pub fn inflight_count(&self) -> usize {
        self.inflight.len()
    }

    pub fn stats(&self) -> BinderTrackerStats {
        self.stats
    }

    /// Begin a marker-bounded evidence interval. The first boundary discards
    /// whole-run correlation telemetry gathered before the marker, while
    /// retaining the number of pre-boundary caller halves as non-degrading
    /// baseline accounting. Later scenarios accumulate into the same health
    /// totals. Events are admitted only when their BPF-stamped generation
    /// matches the active interval.
    pub fn begin_scenario(&mut self, generation: u16) -> bool {
        if generation == 0 || self.active_generation.is_some() {
            return false;
        }
        let baseline = self.inflight.len() as u64;
        self.inflight.clear();
        if self.scenario_bounded {
            self.stats.baseline_discarded = self.stats.baseline_discarded.saturating_add(baseline);
        } else {
            self.stats = BinderTrackerStats {
                baseline_discarded: baseline,
                ..BinderTrackerStats::default()
            };
            self.scenario_bounded = true;
        }
        self.active_generation = Some(generation);
        true
    }

    /// Freeze correlation telemetry at a completed marker boundary.
    pub fn finish_scenario(&mut self, generation: u16) -> bool {
        if self.active_generation != Some(generation) {
            return false;
        }
        self.discard_inflight();
        self.active_generation = None;
        true
    }

    fn accepts_generation(&self, generation: u16) -> bool {
        !self.scenario_bounded || self.active_generation == Some(generation)
    }

    /// Clear caller halves collected before a scenario evidence boundary.
    /// These records are outside the scenario by definition, so account them
    /// separately without turning them into in-scenario correlation loss.
    pub fn reset_baseline(&mut self) {
        self.stats.baseline_discarded = self
            .stats
            .baseline_discarded
            .saturating_add(self.inflight.len() as u64);
        self.inflight.clear();
    }

    /// Drop every still-unpaired transaction at a scenario or shutdown
    /// boundary and account for the lost pair and any attached metadata.
    pub fn discard_inflight(&mut self) {
        let evictions = self.inflight.len() as u64;
        let causal = self
            .inflight
            .values()
            .filter(|entry| entry.causal_metadata.is_some())
            .count() as u64;
        self.inflight.clear();
        self.stats.tracker_evictions = self.stats.tracker_evictions.saturating_add(evictions);
        self.stats.causal_metadata_discarded =
            self.stats.causal_metadata_discarded.saturating_add(causal);
    }

    fn account_eviction(&mut self, entry: &Inflight) {
        self.stats.tracker_evictions = self.stats.tracker_evictions.saturating_add(1);
        if entry.causal_metadata.is_some() {
            self.stats.causal_metadata_discarded =
                self.stats.causal_metadata_discarded.saturating_add(1);
        }
    }

    /// Record a caller-side `binder_transaction` event. `callee_pid` is the
    /// `to_proc` field from the BPF-decoded args. `debug_id == 0` is treated
    /// as "no usable id" and counted as an invalid caller. A zero caller or
    /// callee PID is likewise unusable because it cannot form a causal edge.
    /// Raw tracepoint records can contain zero identity fields; we preserve
    /// those records but cannot pair them.
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
        target_node: i32,
        sent_ts_ns: u64,
        causal_metadata: Option<CausalMetadata>,
    ) {
        self.record_caller_for_generation(
            0,
            debug_id,
            caller_pid,
            caller_uid,
            caller_comm,
            callee_pid,
            code,
            flags,
            reply,
            target_node,
            sent_ts_ns,
            causal_metadata,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_caller_for_generation(
        &mut self,
        generation: u16,
        debug_id: i32,
        caller_pid: u32,
        caller_uid: u32,
        caller_comm: impl Into<String>,
        callee_pid: u32,
        code: u32,
        flags: u32,
        reply: bool,
        target_node: i32,
        sent_ts_ns: u64,
        causal_metadata: Option<CausalMetadata>,
    ) {
        if !self.accepts_generation(generation) {
            return;
        }
        if debug_id == 0 || caller_pid == 0 || callee_pid == 0 {
            self.stats.invalid_callers = self.stats.invalid_callers.saturating_add(1);
            if causal_metadata.is_some() {
                self.stats.causal_metadata_discarded =
                    self.stats.causal_metadata_discarded.saturating_add(1);
            }
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
            target_node,
            sent_ts_ns,
            causal_metadata,
            lru: self.tick,
        };
        if let Some(replaced) = self.inflight.insert(debug_id, entry) {
            self.account_eviction(&replaced);
        }
        // Evict LRU until within cap.
        while self.inflight.len() > self.max_inflight {
            if let Some(victim) = self
                .inflight
                .iter()
                .min_by_key(|(_, v)| v.lru)
                .map(|(k, _)| *k)
            {
                if let Some(evicted) = self.inflight.remove(&victim) {
                    self.account_eviction(&evicted);
                }
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
        self.record_received_for_generation(0, debug_id, received_ts_ns)
    }

    pub fn record_received_for_generation(
        &mut self,
        generation: u16,
        debug_id: i32,
        received_ts_ns: u64,
    ) -> Option<BinderCallEvent> {
        if !self.accepts_generation(generation) {
            return None;
        }
        if debug_id == 0 {
            self.stats.unmatched_receives = self.stats.unmatched_receives.saturating_add(1);
            return None;
        }
        let Some(inflight) = self.inflight.remove(&debug_id) else {
            self.stats.unmatched_receives = self.stats.unmatched_receives.saturating_add(1);
            return None;
        };
        Some(BinderCallEvent {
            debug_id,
            caller_pid: inflight.caller_pid,
            caller_uid: inflight.caller_uid,
            caller_comm: inflight.caller_comm,
            callee_pid: inflight.callee_pid,
            code: inflight.code,
            flags: inflight.flags,
            reply: inflight.reply,
            target_node: inflight.target_node,
            sent_ts_ns: inflight.sent_ts_ns,
            received_ts_ns: Some(received_ts_ns),
            status: BinderCallStatus::Completed,
            causal_metadata: inflight.causal_metadata,
        })
    }

    /// Drain in-flight transactions whose callee equals `crashed_pid` and
    /// emit them as [`BinderCallStatus::CalleeCrashed`]. Called by the main
    /// loop on every `process_exit` event with `classification == "crash"`.
    pub fn on_callee_crash(&mut self, crashed_pid: u32) -> Vec<BinderCallEvent> {
        self.on_callee_crash_for_generation(0, crashed_pid)
    }

    pub fn on_callee_crash_for_generation(
        &mut self,
        generation: u16,
        crashed_pid: u32,
    ) -> Vec<BinderCallEvent> {
        if !self.accepts_generation(generation) {
            return Vec::new();
        }
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
                    target_node: entry.target_node,
                    sent_ts_ns: entry.sent_ts_ns,
                    received_ts_ns: None,
                    status: BinderCallStatus::CalleeCrashed,
                    causal_metadata: entry.causal_metadata,
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
        t.record_caller(
            debug_id, caller, 1000, "caller", callee, 7, 0, false, 0, ts, None,
        );
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
        assert_eq!(t.stats().unmatched_receives, 1);
    }

    #[test]
    fn invalid_caller_identifiers_and_zero_receive_are_counted() {
        let mut t = BinderTracker::new(64);
        record_call(&mut t, 0, 100, 200, 1_000_000);
        record_call(&mut t, 1, 0, 200, 1_000_001);
        record_call(&mut t, 2, 100, 0, 1_000_002);
        assert_eq!(t.inflight_count(), 0);
        assert!(t.record_received(0, 1_000_000).is_none());
        assert_eq!(t.stats().invalid_callers, 3);
        assert_eq!(t.stats().unmatched_receives, 1);
    }

    #[test]
    fn completed_pair_carries_causal_metadata_without_discard() {
        let metadata = crate::causal::CausalMetadata {
            scenario_id: "scenario".into(),
            trace_id: 1,
            span_id: 2,
            parent_span_id: 0,
            depth: 0,
            relation: crate::causal::CausalRelation::Exact,
            root_package: Some("com.example".into()),
            root_uid: Some(10123),
        };
        let mut t = BinderTracker::new(64);
        t.record_caller(
            7,
            100,
            10123,
            "caller",
            200,
            8,
            0,
            false,
            0,
            1_000,
            Some(metadata.clone()),
        );

        let pair = t.record_received(7, 2_000).expect("pair matches");
        assert_eq!(pair.causal_metadata, Some(metadata));
        assert_eq!(t.stats().causal_metadata_discarded, 0);
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
        assert_eq!(t.stats().tracker_evictions, 1);
    }

    #[test]
    fn evicted_causal_metadata_is_counted_and_tracker_clear_is_bounded() {
        let metadata = crate::causal::CausalMetadata {
            scenario_id: "scenario".into(),
            trace_id: 1,
            span_id: 2,
            parent_span_id: 0,
            depth: 0,
            relation: crate::causal::CausalRelation::Exact,
            root_package: Some("com.example".into()),
            root_uid: Some(10123),
        };
        let mut t = BinderTracker::new(1);
        t.record_caller(
            1,
            100,
            10123,
            "caller",
            200,
            7,
            0,
            false,
            0,
            1_000,
            Some(metadata.clone()),
        );
        t.record_caller(
            2,
            100,
            10123,
            "caller",
            200,
            8,
            0,
            false,
            0,
            2_000,
            Some(metadata),
        );
        assert_eq!(t.inflight_count(), 1);
        assert_eq!(t.stats().tracker_evictions, 1);
        assert_eq!(t.stats().causal_metadata_discarded, 1);

        t.discard_inflight();
        assert_eq!(t.inflight_count(), 0);
        assert_eq!(t.stats().tracker_evictions, 2);
        assert_eq!(t.stats().causal_metadata_discarded, 2);
    }

    #[test]
    fn zero_callee_is_rejected_and_zero_crash_is_noop() {
        let mut t = BinderTracker::new(64);
        record_call(&mut t, 1, 100, 0, 1_000);
        let drained = t.on_callee_crash(0);
        assert!(drained.is_empty());
        assert_eq!(t.inflight_count(), 0);
        assert_eq!(t.stats().invalid_callers, 1);
    }

    #[test]
    fn scenario_boundary_discards_baseline_and_freezes_post_marker_health() {
        let mut t = BinderTracker::new(64);
        record_call(&mut t, 1, 100, 200, 1_000);
        record_call(&mut t, 0, 100, 200, 1_001);
        assert!(t.record_received(99, 1_002).is_none());

        assert!(t.begin_scenario(1));
        assert_eq!(t.inflight_count(), 0);
        assert_eq!(t.stats().baseline_discarded, 1);
        assert_eq!(t.stats().invalid_callers, 0);
        assert_eq!(t.stats().unmatched_receives, 0);

        t.record_caller_for_generation(0, 2, 100, 1000, "caller", 200, 7, 0, false, 0, 2_000, None);
        t.record_caller_for_generation(1, 0, 100, 1000, "caller", 200, 7, 0, false, 0, 2_001, None);
        assert_eq!(t.stats().invalid_callers, 1);
        t.record_caller_for_generation(1, 3, 100, 1000, "caller", 200, 7, 0, false, 0, 2_002, None);
        assert!(t.record_received_for_generation(0, 3, 2_003).is_none());
        assert_eq!(t.inflight_count(), 1);
        assert!(t.record_received_for_generation(1, 3, 2_004).is_some());

        assert!(t.finish_scenario(1));
        let frozen = t.stats();
        t.record_caller_for_generation(0, 0, 100, 1000, "caller", 200, 7, 0, false, 0, 3_000, None);
        assert!(t.record_received_for_generation(1, 77, 3_001).is_none());
        assert_eq!(t.stats(), frozen);
    }

    #[test]
    fn sequential_scenarios_accumulate_only_matching_generation_loss() {
        let mut t = BinderTracker::new(64);
        assert!(t.begin_scenario(1));
        t.record_caller_for_generation(1, 0, 100, 1000, "caller", 200, 7, 0, false, 0, 1_000, None);
        assert!(t.finish_scenario(1));

        assert!(t.begin_scenario(2));
        assert!(t.record_received_for_generation(1, 44, 2_000).is_none());
        assert!(t.record_received_for_generation(2, 45, 2_001).is_none());
        assert!(t.finish_scenario(2));

        assert_eq!(t.stats().invalid_callers, 1);
        assert_eq!(t.stats().unmatched_receives, 1);
    }

    #[test]
    fn wrong_generation_crash_cannot_drain_active_scenario_entry() {
        let mut t = BinderTracker::new(64);
        assert!(t.begin_scenario(7));
        t.record_caller_for_generation(7, 1, 100, 1000, "caller", 200, 7, 0, false, 0, 1_000, None);

        assert!(t.on_callee_crash_for_generation(0, 200).is_empty());
        assert_eq!(t.inflight_count(), 1);
        assert_eq!(t.on_callee_crash_for_generation(7, 200).len(), 1);
        assert_eq!(t.inflight_count(), 0);
    }

    #[test]
    fn crashed_pair_carries_caller_metadata() {
        let mut t = BinderTracker::new(64);
        t.record_caller(7, 100, 1000, "myapp", 200, 13, 1, false, 5, 1_000_000, None);
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
