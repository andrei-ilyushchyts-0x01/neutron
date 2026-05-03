//! Capture-health telemetry.
//!
//! The BPF programs maintain a small `COUNTERS` array map that tracks every
//! degraded path (ring drops, INFLIGHT misses, stack-id failures, ...). The
//! userspace loader reads it at exit and prints a structured "capture
//! summary" block so operators know whether absence-of-finding is conclusive.
//!
//! The slot index → label table is the single source of truth for what
//! counters we surface. Adding a new counter means:
//!   1. Reserve a `COUNTER_*` constant in `neutron-common`.
//!   2. Bump it from BPF (or userspace) at the relevant call site.
//!   3. Add it to `COUNTER_LABELS` below.

use neutron_common::{
    COUNTER_EVENTS_SUBMITTED, COUNTER_FD_LOOKUP_MISSED, COUNTER_INFLIGHT_LOOKUP_MISSED,
    COUNTER_INFLIGHT_UPDATE_FAILED, COUNTER_PATH_READ_FAILED, COUNTER_PATH_TRUNCATED,
    COUNTER_RINGBUF_RESERVE_FAILED, COUNTER_SLOT_COUNT, COUNTER_STACK_KERNEL_FAILED,
    COUNTER_STACK_USER_FAILED, COUNTER_SYMBOLIZATION_FAILED,
};

/// Human-readable labels for each counter slot, in display order.
///
/// Slots not listed here are treated as reserved and ignored by the summary
/// printer. Order is purely cosmetic — it controls the printed layout.
pub const COUNTER_LABELS: &[(u32, &str, CounterKind)] = &[
    (
        COUNTER_EVENTS_SUBMITTED,
        "events submitted",
        CounterKind::Volume,
    ),
    (
        COUNTER_RINGBUF_RESERVE_FAILED,
        "ringbuf reserve failed",
        CounterKind::Drop,
    ),
    (
        COUNTER_INFLIGHT_UPDATE_FAILED,
        "inflight update failed",
        CounterKind::Degradation,
    ),
    (
        COUNTER_INFLIGHT_LOOKUP_MISSED,
        "inflight lookup missed",
        CounterKind::Degradation,
    ),
    (
        COUNTER_STACK_USER_FAILED,
        "user stack failed",
        CounterKind::Degradation,
    ),
    (
        COUNTER_STACK_KERNEL_FAILED,
        "kernel stack failed",
        CounterKind::Degradation,
    ),
    (
        COUNTER_PATH_READ_FAILED,
        "path read failed",
        CounterKind::Degradation,
    ),
    (
        COUNTER_PATH_TRUNCATED,
        "path truncated",
        CounterKind::Degradation,
    ),
    (
        COUNTER_FD_LOOKUP_MISSED,
        "fd lookup missed",
        CounterKind::Degradation,
    ),
    (
        COUNTER_SYMBOLIZATION_FAILED,
        "symbolization failed",
        CounterKind::Degradation,
    ),
];

/// Severity tagging for summary rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterKind {
    /// Plain volume metric. Always shown. Never triggers the warning banner.
    Volume,
    /// Hard data loss (event dropped). Triggers the warning banner if > 0.
    Drop,
    /// Soft degradation (event reached userspace but lacks attribution).
    /// Triggers the warning banner if > 0.
    Degradation,
}

/// In-memory snapshot of the COUNTERS map at a point in time.
#[derive(Debug, Clone, Default)]
pub struct CaptureHealth {
    pub slots: [u64; COUNTER_SLOT_COUNT as usize],
}

impl CaptureHealth {
    /// Read every slot of the BPF `COUNTERS` map into a snapshot. Slots that
    /// fail to read are left as zero — the summary will show those as `0`,
    /// not as missing.
    pub fn read(map: &aya::maps::Array<&aya::maps::MapData, u64>) -> Self {
        let mut out = Self::default();
        for (idx, slot) in out.slots.iter_mut().enumerate() {
            if let Ok(v) = map.get(&(idx as u32), 0) {
                *slot = v;
            }
        }
        out
    }

    /// True if any drop-class or degradation-class counter is non-zero.
    pub fn has_degradation(&self) -> bool {
        for (idx, _, kind) in COUNTER_LABELS {
            if matches!(kind, CounterKind::Drop | CounterKind::Degradation)
                && self.slots[*idx as usize] > 0
            {
                return true;
            }
        }
        false
    }

    /// Counter value at the given slot index. Returns 0 for out-of-range.
    pub fn get(&self, idx: u32) -> u64 {
        self.slots.get(idx as usize).copied().unwrap_or(0)
    }
}

/// Userspace counters not tracked by BPF. Today: FD-graph miss + backfill.
#[derive(Debug, Clone, Default)]
pub struct UserspaceHealth {
    pub fd_graph_miss: u64,
    pub fd_graph_backfilled: u64,
}

/// Render the capture summary as a single block of text, suitable for stderr.
/// Includes the warning banner when any drop or degradation counter is > 0.
pub fn format_summary(health: &CaptureHealth, total_userspace_events: u64) -> String {
    format_summary_with(health, &UserspaceHealth::default(), total_userspace_events)
}

/// Same as [`format_summary`] but also prints the userspace-side counters
/// (FD graph misses, backfills, etc.) under their own subsection.
pub fn format_summary_with(
    health: &CaptureHealth,
    user: &UserspaceHealth,
    total_userspace_events: u64,
) -> String {
    let mut out = String::new();
    out.push_str("\nCapture summary:\n");
    out.push_str(&format!(
        "  events processed (userspace): {total_userspace_events}\n"
    ));
    for (idx, label, _) in COUNTER_LABELS {
        let v = health.get(*idx);
        out.push_str(&format!("  {label}: {v}\n"));
    }
    if user.fd_graph_miss > 0 || user.fd_graph_backfilled > 0 {
        out.push_str(&format!(
            "  fd graph: {} miss(es), {} resolved via /proc/<pid>/fd\n",
            user.fd_graph_miss, user.fd_graph_backfilled
        ));
    }
    if health.has_degradation() {
        out.push_str(
            "\nWARNING: capture had drops or degraded paths. Absence of a finding\n\
             is NOT conclusive — the relevant event may have been dropped, the\n\
             stack may have failed to resolve, or the path may have been truncated.\n\
             Re-run with a smaller scope (--profile, narrower --pid) or compare\n\
             against a clean baseline before drawing conclusions.\n",
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_degradation_false_when_only_volume_counters_set() {
        let mut h = CaptureHealth::default();
        h.slots[COUNTER_EVENTS_SUBMITTED as usize] = 12_345;
        assert!(!h.has_degradation());
    }

    #[test]
    fn has_degradation_true_when_ringbuf_reserve_failed() {
        let mut h = CaptureHealth::default();
        h.slots[COUNTER_RINGBUF_RESERVE_FAILED as usize] = 1;
        assert!(h.has_degradation());
    }

    #[test]
    fn has_degradation_true_when_stack_failed() {
        let mut h = CaptureHealth::default();
        h.slots[COUNTER_STACK_USER_FAILED as usize] = 1;
        assert!(h.has_degradation());
    }

    #[test]
    fn format_summary_contains_warning_when_drops() {
        let mut h = CaptureHealth::default();
        h.slots[COUNTER_EVENTS_SUBMITTED as usize] = 100;
        h.slots[COUNTER_RINGBUF_RESERVE_FAILED as usize] = 7;
        let s = format_summary(&h, 100);
        assert!(s.contains("Capture summary"));
        assert!(s.contains("ringbuf reserve failed: 7"));
        assert!(s.contains("WARNING"));
        assert!(s.contains("NOT conclusive"));
    }

    #[test]
    fn format_summary_omits_warning_when_clean() {
        let mut h = CaptureHealth::default();
        h.slots[COUNTER_EVENTS_SUBMITTED as usize] = 100;
        let s = format_summary(&h, 100);
        assert!(s.contains("Capture summary"));
        assert!(s.contains("events submitted: 100"));
        assert!(!s.contains("WARNING"));
    }

    #[test]
    fn format_summary_includes_userspace_event_count() {
        let h = CaptureHealth::default();
        let s = format_summary(&h, 99_999);
        assert!(s.contains("events processed (userspace): 99999"));
    }

    #[test]
    fn format_summary_with_emits_fd_graph_line_when_nonzero() {
        let h = CaptureHealth::default();
        let user = UserspaceHealth {
            fd_graph_miss: 12,
            fd_graph_backfilled: 9,
        };
        let s = format_summary_with(&h, &user, 100);
        assert!(s.contains("fd graph: 12 miss(es), 9 resolved"));
    }

    #[test]
    fn format_summary_with_omits_fd_graph_line_when_zero() {
        let h = CaptureHealth::default();
        let user = UserspaceHealth::default();
        let s = format_summary_with(&h, &user, 100);
        assert!(!s.contains("fd graph:"));
    }
}
