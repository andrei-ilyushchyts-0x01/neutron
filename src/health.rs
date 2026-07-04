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
    COUNTER_INFLIGHT_UPDATE_FAILED, COUNTER_IOCTL_REFRESH_MISSED, COUNTER_PATH_READ_FAILED,
    COUNTER_PATH_TRUNCATED, COUNTER_RINGBUF_RESERVE_FAILED, COUNTER_SLOT_COUNT,
    COUNTER_STACK_KERNEL_FAILED, COUNTER_STACK_USER_FAILED, COUNTER_SYMBOLIZATION_FAILED,
    COUNTER_UNIX_MSG_CONTROL_NESTED, COUNTER_UNIX_MSG_CONTROL_TRUNCATED,
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
    (
        COUNTER_IOCTL_REFRESH_MISSED,
        "ioctl refresh missed",
        CounterKind::Degradation,
    ),
    (
        COUNTER_UNIX_MSG_CONTROL_TRUNCATED,
        "unix msg control truncated",
        CounterKind::Degradation,
    ),
    (
        COUNTER_UNIX_MSG_CONTROL_NESTED,
        "unix msg control nested",
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

/// Userspace counters not tracked by BPF. Track everything that
/// shapes the userspace stage of the predicate / sampler / capture
/// pipeline so an operator can audit "where did my events go?" from
/// one block instead of three subsystems.
#[derive(Debug, Clone, Default)]
pub struct UserspaceHealth {
    pub fd_graph_miss: u64,
    pub fd_graph_backfilled: u64,
    /// Events that survived the BPF prefilter and the userspace
    /// post-filter (Phase 1a/1b match). Equal to `events_userspace`
    /// when no `--match-*` flag is configured.
    pub events_matched: u64,
    /// Events the Phase 1d sampler dropped (uniform Bernoulli /
    /// rate-limit). State-tracking and sentinel events are exempt by
    /// construction so they're never counted here.
    pub events_sampled_out: u64,
    /// Lines actually written to the output sink. With
    /// `--capture matched+context=<DUR>` this can exceed
    /// `events_matched` because backward+forward ring flushes emit
    /// multiple lines per match.
    pub events_emitted: u64,
}

/// Static capture configuration surfaced in the shutdown health event.
#[derive(Debug, Clone, Default)]
pub struct CaptureMetadata {
    pub driver_packs: Vec<String>,
    pub kprobe_packs: Vec<String>,
    pub attached_programs: Vec<String>,
    pub ioctl_refresh_cmds: Vec<u32>,
    pub ioctl_refresh_types: Vec<u32>,
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
    // Predicate / sampler / context-window pipeline counters. Always
    // shown when the loop ran for at least one event so operators can
    // see how a `--match-*` configuration thinned the trace.
    if total_userspace_events > 0 {
        out.push_str(&format!(
            "  matched: {}  sampled-out: {}  emitted: {}\n",
            user.events_matched, user.events_sampled_out, user.events_emitted
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

/// Phase 5c — render the capture-health snapshot as a single NDJSON
/// line tagged `type:"capture_health"`. Emitted on shutdown when
/// `--json` is on so downstream consumers see the same counters that
/// go to stderr without scraping prose. Field set is stable; new
/// counters are added at the tail.
pub fn format_capture_health_json(
    health: &CaptureHealth,
    user: &UserspaceHealth,
    total_userspace_events: u64,
) -> String {
    format_capture_health_json_with_metadata(
        health,
        user,
        total_userspace_events,
        &CaptureMetadata::default(),
    )
}

pub fn format_capture_health_json_with_metadata(
    health: &CaptureHealth,
    user: &UserspaceHealth,
    total_userspace_events: u64,
    meta: &CaptureMetadata,
) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(256);
    let _ = write!(
        s,
        r#"{{"type":"capture_health","events_userspace":{}"#,
        total_userspace_events,
    );
    for (idx, label, _) in COUNTER_LABELS {
        // Field name = label with spaces → underscores.
        let key: String = label
            .chars()
            .map(|c| if c.is_ascii_whitespace() { '_' } else { c })
            .collect();
        let _ = write!(s, r#","{key}":{}"#, health.get(*idx));
    }
    let _ = write!(
        s,
        r#","fd_graph_miss":{},"fd_graph_backfilled":{},"events_matched":{},"events_sampled_out":{},"events_emitted":{},"degraded":{}"#,
        user.fd_graph_miss,
        user.fd_graph_backfilled,
        user.events_matched,
        user.events_sampled_out,
        user.events_emitted,
        health.has_degradation()
    );
    write_string_array(&mut s, "driver_packs", &meta.driver_packs);
    write_string_array(&mut s, "kprobe_packs", &meta.kprobe_packs);
    write_string_array(&mut s, "attached_programs", &meta.attached_programs);
    write_u32_array_hex(&mut s, "ioctl_refresh_cmds", &meta.ioctl_refresh_cmds);
    write_u32_array_hex(&mut s, "ioctl_refresh_types", &meta.ioctl_refresh_types);
    s.push('}');
    s
}

fn write_string_array(s: &mut String, key: &str, values: &[String]) {
    use std::fmt::Write as _;
    let _ = write!(s, r#","{key}":["#);
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            s.push(',');
        }
        let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
        let _ = write!(s, r#""{escaped}""#);
    }
    s.push(']');
}

fn write_u32_array_hex(s: &mut String, key: &str, values: &[u32]) {
    use std::fmt::Write as _;
    let _ = write!(s, r#","{key}":["#);
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            s.push(',');
        }
        let _ = write!(s, r#""{value:#x}""#);
    }
    s.push(']');
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
            ..UserspaceHealth::default()
        };
        let s = format_summary_with(&h, &user, 100);
        assert!(s.contains("fd graph: 12 miss(es), 9 resolved"));
    }

    #[test]
    fn format_summary_emits_pipeline_counters_when_events_seen() {
        let h = CaptureHealth::default();
        let user = UserspaceHealth {
            events_matched: 50,
            events_sampled_out: 30,
            events_emitted: 70,
            ..UserspaceHealth::default()
        };
        let s = format_summary_with(&h, &user, 100);
        assert!(s.contains("matched: 50"));
        assert!(s.contains("sampled-out: 30"));
        assert!(s.contains("emitted: 70"));
    }

    #[test]
    fn format_summary_with_omits_fd_graph_line_when_zero() {
        let h = CaptureHealth::default();
        let user = UserspaceHealth::default();
        let s = format_summary_with(&h, &user, 100);
        assert!(!s.contains("fd graph:"));
    }

    #[test]
    fn capture_health_json_round_trips_to_known_fields() {
        let mut h = CaptureHealth::default();
        h.slots[COUNTER_EVENTS_SUBMITTED as usize] = 12_345;
        h.slots[COUNTER_RINGBUF_RESERVE_FAILED as usize] = 7;
        let user = UserspaceHealth {
            fd_graph_miss: 3,
            fd_graph_backfilled: 2,
            events_matched: 50,
            events_sampled_out: 5,
            events_emitted: 60,
        };
        let line = format_capture_health_json(&h, &user, 99_999);
        let v: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(v["type"], "capture_health");
        assert_eq!(v["events_userspace"], 99_999u64);
        assert_eq!(v["events_submitted"], 12_345u64);
        assert_eq!(v["ringbuf_reserve_failed"], 7u64);
        assert_eq!(v["fd_graph_miss"], 3u64);
        assert_eq!(v["fd_graph_backfilled"], 2u64);
        assert_eq!(v["events_matched"], 50u64);
        assert_eq!(v["events_sampled_out"], 5u64);
        assert_eq!(v["events_emitted"], 60u64);
        assert_eq!(v["degraded"], true);
    }

    #[test]
    fn capture_health_json_marks_clean_capture_not_degraded() {
        let h = CaptureHealth::default();
        let user = UserspaceHealth::default();
        let line = format_capture_health_json(&h, &user, 0);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["degraded"], false);
    }
}
