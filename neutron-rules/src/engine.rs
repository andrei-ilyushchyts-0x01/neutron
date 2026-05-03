//! [`RuleEngine`] — feeds events through rules and emits findings.
//!
//! The engine is single-threaded and intentionally simple. It holds:
//! - a vector of compiled [`Rule`]s,
//! - per-rule state keyed by `(rule_idx, pid[, target])`,
//! - a buffer of finalized findings ready for the caller to drain.

use std::collections::HashMap;

use crate::condition::match_target;
use crate::event::Event;
use crate::finding::{EventSnapshot, Finding};
use crate::loader::LoaderError;
use crate::rule::{AggregateMode, Rule, MAX_EVIDENCE_PER_FINDING};
use crate::window::SlidingWindow;

/// Composite key per active finding.
#[derive(Clone, Eq, Hash, PartialEq)]
struct StateKey {
    rule_idx: usize,
    pid: u32,
    target: String, // empty for non-PerTarget rules
}

/// Mutable per-(rule, pid[, target]) state.
struct ActiveState {
    first_ns: u64,
    last_ns: u64,
    count: u32,
    comm: String,
    target: Option<String>,
    evidence: Vec<EventSnapshot>,
    /// Sliding window for frequency rules. `None` if the rule has no
    /// `frequency` spec.
    window: Option<SlidingWindow>,
    /// True after we've already emitted a finding for this state. Subsequent
    /// matches update count/last_ns but don't re-emit (per `PerProcess`/
    /// `PerTarget` semantics).
    emitted: bool,
}

pub struct RuleEngine {
    rules: Vec<Rule>,
    states: HashMap<StateKey, ActiveState>,
    pending: Vec<Finding>,
}

impl RuleEngine {
    /// Build an engine from an explicit list of rules.
    pub fn new(rules: Vec<Rule>) -> Result<Self, LoaderError> {
        for r in &rules {
            r.validate().map_err(LoaderError::Validation)?;
        }
        Ok(Self {
            rules: rules.into_iter().filter(|r| !r.disabled).collect(),
            states: HashMap::new(),
            pending: Vec::new(),
        })
    }

    /// Build an engine pre-loaded with the bundled default ruleset (the 15
    /// detectors documented in `docs/rules/reference.md`).
    pub fn with_default_rules() -> Result<Self, LoaderError> {
        let rules = crate::loader::load_rules_yaml_str(crate::builtin::DEFAULT_RULES_YAML)?;
        Self::new(rules)
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Hot path: evaluate all rules against `ev`. May stage one or more
    /// findings into the pending buffer.
    pub fn feed(&mut self, ev: &Event<'_>) {
        // Iterate rules by index so we can take a stable key without re-borrow.
        for (idx, rule) in self.rules.iter().enumerate() {
            if !rule.conditions.iter().all(|c| c.matches(ev)) {
                continue;
            }

            let target_str = if rule.aggregate == AggregateMode::PerTarget {
                match_target(ev)
            } else {
                String::new()
            };

            let key = StateKey {
                rule_idx: idx,
                pid: ev.pid,
                target: target_str.clone(),
            };

            // Make a snapshot before mutating state (cheap, bounded by max evidence).
            let snap_target = if target_str.is_empty() {
                None
            } else {
                Some(target_str.clone())
            };

            let state = self.states.entry(key).or_insert_with(|| {
                let window = rule
                    .frequency
                    .as_ref()
                    .map(|f| SlidingWindow::new(f.window_ms));
                ActiveState {
                    first_ns: ev.ts_ns,
                    last_ns: ev.ts_ns,
                    count: 0,
                    comm: ev.comm.to_string(),
                    target: snap_target,
                    evidence: Vec::with_capacity(MAX_EVIDENCE_PER_FINDING),
                    window,
                    emitted: false,
                }
            });

            state.last_ns = ev.ts_ns;
            state.count = state.count.saturating_add(1);
            if state.evidence.len() < MAX_EVIDENCE_PER_FINDING {
                state.evidence.push(EventSnapshot {
                    ts_ns: ev.ts_ns,
                    name: ev.name.to_string(),
                    is_enter: ev.is_enter,
                    ret: ev.ret,
                    data: ev.data.map(|s| s.to_string()),
                    raw: Some(ev.raw_json().clone()),
                });
            }
            if let Some(w) = state.window.as_mut() {
                w.record(ev.ts_ns);
            }

            let should_emit = match (&rule.frequency, rule.aggregate) {
                // Frequency rule: fire only when window threshold is reached,
                // and only once per state (subsequent updates fold into the
                // emitted finding).
                (Some(spec), _) => {
                    let count = state.window.as_ref().map(|w| w.len() as u32).unwrap_or(0);
                    !state.emitted && count >= spec.min_count
                }
                // EveryEvent: emit on every match.
                (None, AggregateMode::EveryEvent) => true,
                // PerProcess / PerTarget: emit on first match.
                (None, AggregateMode::PerProcess | AggregateMode::PerTarget) => !state.emitted,
            };

            if should_emit {
                state.emitted = matches!(
                    rule.aggregate,
                    AggregateMode::PerProcess | AggregateMode::PerTarget
                ) || rule.frequency.is_some();
                let finding = build_finding(rule, ev.pid, state);
                self.pending.push(finding);
            }
        }
    }

    /// Return any findings produced since the last call. Does NOT flush
    /// per-process aggregations — those keep updating until [`flush_all`].
    pub fn drain_ready(&mut self) -> Vec<Finding> {
        std::mem::take(&mut self.pending)
    }

    /// Flush all pending findings and produce final-summary updates for any
    /// frequency / aggregated states that have accumulated additional matches
    /// since their first emission. The engine is consumed by this call.
    pub fn flush_all(mut self) -> Vec<Finding> {
        let mut out = std::mem::take(&mut self.pending);

        for (key, state) in &self.states {
            if !state.emitted {
                continue;
            }
            // Re-emit a final summary if the state has accumulated more events
            // than the snapshot taken at first emission. Downstream tools can
            // dedupe by `rule_id + pid`.
            if state.count > 1 {
                let rule = &self.rules[key.rule_idx];
                out.push(build_finding(rule, key.pid, state));
            }
        }

        out
    }
}

fn build_finding(rule: &Rule, pid: u32, state: &ActiveState) -> Finding {
    let period_ms = state.window.as_ref().and_then(|w| w.period_ms());
    Finding {
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        severity: rule.severity,
        category: rule.category,
        pid,
        comm: state.comm.clone(),
        first_seen_ns: state.first_ns,
        last_seen_ns: state.last_ns,
        event_count: state.count,
        period_ms,
        target: state.target.clone(),
        evidence: state.evidence.clone(),
        references: rule.references.clone(),
        // Schema v2 — passed through verbatim from the rule definition.
        // `evidence_quality` and `capture_health` stay at defaults today;
        // wiring them to live BPF counters is a follow-up (see ROADMAP).
        behavior: rule.behavior.clone(),
        interpretation: rule.interpretation.clone(),
        confidence: rule.confidence,
        false_positives: rule.false_positives.clone(),
        evidence_quality: None,
        capture_health: crate::finding::CaptureHealthSnapshot::default(),
    }
}
