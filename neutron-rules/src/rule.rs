//! Rule type definitions.
//!
//! Rules are deserialized from YAML (see `rules/default.yaml`) and evaluated
//! by [`crate::engine::RuleEngine`].

use serde::{Deserialize, Serialize};

use crate::condition::MatchCondition;

/// Severity levels follow common security tooling conventions (Falco, MITRE).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// Rule category — used for filtering and reporting only.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    RootDetection,
    Antitamper,
    Network,
    NetworkRecon,
    Memory,
    Ipc,
    Recon,
    ResourceExhaustion,
    Crash,
}

/// Sliding-window trigger spec: emit a finding only after at least `min_count`
/// matches occur within `window_ms`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrequencySpec {
    pub window_ms: u64,
    pub min_count: u32,
}

/// How matches are aggregated into findings.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateMode {
    /// Emit one finding per matching event. High-noise — use only for rare
    /// events (e.g. RWX mmap).
    EveryEvent,
    /// Emit once per `(rule, pid)`. Subsequent matches update `last_seen` and
    /// `count` and are folded into the same finding.
    #[default]
    PerProcess,
    /// Emit once per `(rule, pid, target)` where `target` is the first matched
    /// path or data string. Useful for rules that probe many distinct paths.
    PerTarget,
}

/// Number of evidence events kept per finding. Cheap upper bound on memory.
pub const MAX_EVIDENCE_PER_FINDING: usize = 5;

/// A single detection rule.
///
/// Schema v2 (additive) extends each rule with **observation-level** fields
/// — `behavior`, `interpretation`, `confidence`, `false_positives` — so the
/// finding output can be framed as evidence + interpretation rather than as
/// a verdict. Existing rules without these fields still work unchanged: the
/// emitted finding leaves them empty/`None`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub category: Category,
    #[serde(default)]
    pub references: Vec<String>,
    /// AND-joined match conditions. All must hold for a candidate event.
    pub conditions: Vec<MatchCondition>,
    /// Optional frequency trigger. If set, single matches do not emit; the
    /// rule fires only after the window threshold is met.
    #[serde(default)]
    pub frequency: Option<FrequencySpec>,
    /// Aggregation policy for matched events.
    #[serde(default)]
    pub aggregate: AggregateMode,
    /// Optional: if true, the rule is loaded but disabled by default. Useful
    /// for noisy or experimental rules.
    #[serde(default)]
    pub disabled: bool,

    // ── Schema v2 — observation framing ────────────────────────────────────
    /// Short slug describing the *observable* pattern, not the verdict.
    /// Examples: `proc_self_maps_polling`, `mmap_rwx_anonymous`,
    /// `binder_transaction_burst`. Stable; reusable across rule variants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior: Option<String>,
    /// One or more candidate explanations for why this behavior matters.
    /// Listed without ranking — `confidence` quantifies the rule's overall
    /// claim; the interpretations are hypotheses for the reader.
    #[serde(default)]
    pub interpretation: Vec<String>,
    /// Baseline confidence in the interpretation, `0.0..=1.0`. Higher means
    /// the behavior is a strong signal of the listed interpretation. The
    /// engine passes this through verbatim today; future versions may
    /// adjust per-finding based on `capture_health`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    /// Known false-positive scenarios for this rule. Useful guidance for
    /// users triaging findings; reproduced into each emitted finding.
    #[serde(default)]
    pub false_positives: Vec<String>,
}

impl Rule {
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() {
            return Err("rule.id is empty".into());
        }
        if self.conditions.is_empty() {
            return Err(format!("rule {} has no conditions", self.id));
        }
        if let Some(freq) = &self.frequency {
            if freq.window_ms == 0 {
                return Err(format!("rule {}: frequency.window_ms must be > 0", self.id));
            }
            if freq.min_count == 0 {
                return Err(format!("rule {}: frequency.min_count must be > 0", self.id));
            }
        }
        Ok(())
    }
}
