//! [`Finding`] — the engine's output type.
//!
//! Findings are deliberately self-contained: each one carries enough context
//! (rule metadata, process identity, evidence, period) for a researcher to act
//! on without consulting the original raw NDJSON.
//!
//! ## Schema v2 — observation framing
//!
//! v2 extends Finding with `behavior`, `interpretation`, `confidence`,
//! `false_positives`, `evidence_quality`, and `capture_health`. The intent is
//! to reframe findings from verdicts ("root_detection: su probe") into
//! evidence with interpretation ("filesystem_probe targeting su path; possible
//! root detection; confidence 0.8"). All v2 fields are additive and default to
//! `None` / empty — rules and consumers can ignore them.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::rule::{Category, Severity};

/// One representative event attached to a [`Finding`]. We keep a small bounded
/// number per finding (see [`crate::rule::MAX_EVIDENCE_PER_FINDING`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventSnapshot {
    pub ts_ns: u64,
    pub name: String,
    pub is_enter: bool,
    pub ret: i64,
    /// Decoded path/data field if present.
    pub data: Option<String>,
    /// Original JSON of the event, retained verbatim. Useful for downstream
    /// tools that want the full record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
}

/// Numerical and counting aggregates computed from the events that
/// contributed to a [`Finding`]. Sprint-2 PR 4. All fields are optional;
/// the engine populates whichever apply for the contributing event kinds
/// (frequency-based fields fill in for any rule with `>=2` events; the
/// fd_* fields fill only when `EventKind::FdSnapshot` events matched;
/// the binder_* fields fill only when `EventKind::BinderCall` events
/// matched). Empty/None fields are omitted from JSON output.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Aggregates {
    /// `event_count / span_secs`. Populated when at least two events
    /// matched within a non-zero span.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_per_sec: Option<f64>,
    /// Tightest gap between consecutive matched events, in milliseconds.
    /// `None` when fewer than two events matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_interval_ms: Option<f64>,
    /// Loosest gap between consecutive matched events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_interval_ms: Option<f64>,
    /// Number of distinct `target` strings observed across contributing
    /// events. `None` when no event carried a usable target (data/comm
    /// fallback inside `match_target`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distinct_targets: Option<u32>,
    /// Highest `fd_count` observed in any contributing FdSnapshot event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_fd_count: Option<u32>,
    /// Highest `fd_pct_of_rlimit` observed in any contributing FdSnapshot
    /// event. `None` when the matching events had unknown rlimit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_fd_pct_of_rlimit: Option<u8>,
    /// Number of distinct `callee_pid` values observed in contributing
    /// BinderCall events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distinct_callee_pids: Option<u32>,
    /// Number of distinct AIDL `code` values observed in contributing
    /// BinderCall events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distinct_binder_codes: Option<u32>,
}

impl Aggregates {
    /// Returns `true` when no field has been populated. Used by the
    /// finding serializer to omit the whole `aggregates` object instead
    /// of emitting `{}`.
    pub fn is_empty(&self) -> bool {
        self.events_per_sec.is_none()
            && self.min_interval_ms.is_none()
            && self.max_interval_ms.is_none()
            && self.distinct_targets.is_none()
            && self.peak_fd_count.is_none()
            && self.peak_fd_pct_of_rlimit.is_none()
            && self.distinct_callee_pids.is_none()
            && self.distinct_binder_codes.is_none()
    }
}

/// Coarse evidence quality bucket. Derived (in future versions) from
/// `capture_health` plus stack-resolution outcome. Today this is left `None`
/// in the engine; users of v2-aware rules can still set it explicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceQuality {
    Low,
    Medium,
    High,
}

/// Per-finding capture-health snapshot. Snapshots tell the reader whether
/// the BPF capture for this specific finding's window was clean or whether
/// drops/truncation/symbolization-misses might have shaped the result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaptureHealthSnapshot {
    /// True if any path captured during the finding's window had to be
    /// truncated to fit into `data[128]`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub path_truncated: bool,
    /// True if user-stack resolution succeeded for at least one event in
    /// this finding's evidence (best-effort; defaults to `true` for rules
    /// that don't depend on stacks).
    #[serde(default = "true_default", skip_serializing_if = "is_true")]
    pub stack_resolved: bool,
    /// True if the BPF ringbuf or any inflight/stack counter was incremented
    /// while this finding's window was open. Operators should treat the
    /// finding as suggestive, not conclusive.
    #[serde(default, skip_serializing_if = "is_false")]
    pub drops_during_window: bool,
}

impl Default for CaptureHealthSnapshot {
    /// "All good" baseline: no truncation, stack resolved, no drops. Matches
    /// the serde defaults so deserialize-from-empty-object round-trips.
    fn default() -> Self {
        Self {
            path_truncated: false,
            stack_resolved: true,
            drops_during_window: false,
        }
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}
fn is_true(b: &bool) -> bool {
    *b
}
fn true_default() -> bool {
    true
}

/// A finalized rule match.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub category: Category,
    pub pid: u32,
    pub comm: String,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub event_count: u32,
    /// Average period between matched events (frequency rules only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period_ms: Option<f64>,
    /// First-matched target (path / data string), for `PerTarget` aggregation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub evidence: Vec<EventSnapshot>,
    /// References from the rule definition.
    #[serde(default)]
    pub references: Vec<String>,

    // ── Schema v2 — observation framing ─────────────────────────────────────
    /// Observable pattern slug (e.g. `proc_self_maps_polling`). Copied from
    /// the rule definition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior: Option<String>,
    /// Possible interpretations for the behavior. Copied from the rule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interpretation: Vec<String>,
    /// Rule's baseline confidence in the interpretation, `0.0..=1.0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    /// Known false-positive scenarios for this rule. Copied from the rule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub false_positives: Vec<String>,
    /// Coarse evidence-quality bucket. `None` until the engine wires
    /// `capture_health` in — preserved here so consumers can adopt the
    /// field today without a second schema bump.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_quality: Option<EvidenceQuality>,
    /// Per-finding capture-health snapshot. Defaults to "all good"; the
    /// engine populates it when the loader threads runtime counters in.
    #[serde(default)]
    pub capture_health: CaptureHealthSnapshot,

    // ── Sprint-2 PR 4 — finding aggregation + raw window ────────────────────
    /// Numerical and counting aggregates computed at flush time. Omitted
    /// from JSON when no field was populated.
    #[serde(default, skip_serializing_if = "Aggregates::is_empty")]
    pub aggregates: Aggregates,
    /// Up to `--finding-raw-window` full NDJSON lines from the events that
    /// contributed to this finding. Order matches the matching order. The
    /// engine clones each line verbatim (byte-exact), so consumers can
    /// re-parse them with the same parser as the live capture.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raw_window: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> Finding {
        Finding {
            rule_id: "T999_x".into(),
            rule_name: "x".into(),
            severity: Severity::Low,
            category: Category::Antitamper,
            pid: 1,
            comm: "x".into(),
            first_seen_ns: 0,
            last_seen_ns: 0,
            event_count: 1,
            period_ms: None,
            target: None,
            evidence: vec![],
            references: vec![],
            behavior: None,
            interpretation: vec![],
            confidence: None,
            false_positives: vec![],
            evidence_quality: None,
            capture_health: CaptureHealthSnapshot::default(),
            aggregates: Aggregates::default(),
            raw_window: Vec::new(),
        }
    }

    #[test]
    fn empty_v2_fields_are_omitted_from_json() {
        let f = minimal();
        let s = serde_json::to_string(&f).unwrap();
        for key in [
            "behavior",
            "interpretation",
            "confidence",
            "false_positives",
            "evidence_quality",
        ] {
            assert!(!s.contains(key), "expected {key} to be omitted, got: {s}");
        }
        // capture_health serializes as `{}` when defaults match the skip rules.
        // Default snapshot has stack_resolved=true (skip_if_true) and the
        // other two false (skip_if_false), so we expect an empty object.
        assert!(s.contains(r#""capture_health":{}"#));
    }

    #[test]
    fn populated_v2_fields_appear_in_json() {
        let mut f = minimal();
        f.behavior = Some("proc_self_maps_polling".into());
        f.interpretation = vec!["possible anti-instrumentation".into()];
        f.confidence = Some(0.85);
        f.false_positives = vec!["crash reporter unwinder".into()];
        f.evidence_quality = Some(EvidenceQuality::High);
        f.capture_health.path_truncated = true;
        f.capture_health.stack_resolved = false;
        f.capture_health.drops_during_window = true;

        let s = serde_json::to_string(&f).unwrap();
        assert!(s.contains(r#""behavior":"proc_self_maps_polling""#));
        assert!(s.contains(r#""interpretation":["possible anti-instrumentation"]"#));
        assert!(s.contains(r#""confidence":0.85"#));
        assert!(s.contains(r#""false_positives":["crash reporter unwinder"]"#));
        assert!(s.contains(r#""evidence_quality":"high""#));
        assert!(s.contains(r#""path_truncated":true"#));
        assert!(s.contains(r#""stack_resolved":false"#));
        assert!(s.contains(r#""drops_during_window":true"#));
    }

    #[test]
    fn finding_round_trips_through_serde() {
        let mut f = minimal();
        f.behavior = Some("test".into());
        f.confidence = Some(0.5);
        f.evidence_quality = Some(EvidenceQuality::Medium);
        let s = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&s).unwrap();
        assert_eq!(back.behavior.as_deref(), Some("test"));
        assert_eq!(back.confidence, Some(0.5));
        assert_eq!(back.evidence_quality, Some(EvidenceQuality::Medium));
    }

    #[test]
    fn empty_aggregates_and_raw_window_omitted_from_json() {
        let f = minimal();
        let s = serde_json::to_string(&f).unwrap();
        assert!(
            !s.contains("aggregates"),
            "empty Aggregates should be omitted: {s}"
        );
        assert!(
            !s.contains("raw_window"),
            "empty raw_window should be omitted: {s}"
        );
    }

    #[test]
    fn populated_aggregates_appear_in_json() {
        let mut f = minimal();
        f.aggregates.events_per_sec = Some(42.0);
        f.aggregates.min_interval_ms = Some(1.5);
        f.aggregates.peak_fd_count = Some(31000);
        let s = serde_json::to_string(&f).unwrap();
        assert!(s.contains(r#""events_per_sec":42.0"#));
        assert!(s.contains(r#""min_interval_ms":1.5"#));
        assert!(s.contains(r#""peak_fd_count":31000"#));
    }

    #[test]
    fn raw_window_lines_round_trip_through_serde() {
        let mut f = minimal();
        f.raw_window = vec![
            r#"{"type":"syscall","nr":56}"#.into(),
            r#"{"type":"binder_call","status":"completed"}"#.into(),
        ];
        let s = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&s).unwrap();
        assert_eq!(back.raw_window.len(), 2);
        assert_eq!(back.raw_window[0], r#"{"type":"syscall","nr":56}"#);
    }
}
