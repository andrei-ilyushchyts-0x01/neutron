//! [`RuleEngine`] — feeds events through rules and emits findings.
//!
//! The engine is single-threaded and intentionally simple. It holds:
//! - a vector of compiled [`Rule`]s,
//! - per-rule state keyed by `(rule_idx, pid[, target])`,
//! - a buffer of finalized findings ready for the caller to drain.

use std::collections::{HashMap, HashSet};

use crate::condition::match_target;
use crate::event::Event;
use crate::finding::{Aggregates, EventSnapshot, Finding};
use crate::loader::LoaderError;
use crate::rule::{AggregateMode, Rule, MAX_EVIDENCE_PER_FINDING};
use crate::window::SlidingWindow;

/// Default cap on per-finding `raw_window` length. Configurable via
/// [`RuleEngine::set_raw_window_cap`]. Sized to keep finding lines under
/// ~10 KB even when each contributing event is verbose (~1 KB JSON).
pub const DEFAULT_RAW_WINDOW_CAP: usize = 10;
/// Hard cap on the size of distinct-set trackers per state. Prevents a
/// runaway rule from blowing memory on a long-running session. The tracker
/// stops inserting once the cap is reached; the count reflects "≥ cap".
const MAX_DISTINCT_TRACKED: usize = 1024;

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

    // ── Sprint-2 PR 4 — aggregation + raw window state ──────────────────────
    /// Bounded list of full NDJSON lines, one per contributing event whose
    /// `Event::raw_line` was available.
    raw_lines: Vec<String>,
    /// Previous event's ts_ns — used to compute min/max inter-event interval.
    prev_ts_ns: Option<u64>,
    /// Tightest gap observed (ns).
    min_interval_ns: Option<u64>,
    /// Loosest gap observed (ns).
    max_interval_ns: Option<u64>,
    /// Highest fd_count from contributing FdSnapshot events.
    peak_fd_count: Option<u32>,
    /// Highest fd_pct_of_rlimit from contributing FdSnapshot events.
    peak_fd_pct_of_rlimit: Option<u8>,
    /// Distinct callee_pid values from contributing BinderCall events.
    callee_pids: HashSet<u32>,
    /// Distinct AIDL code values from contributing BinderCall events.
    binder_codes: HashSet<u32>,
    /// Distinct target strings from contributing events (any kind that has
    /// a usable `match_target` — typically the `data` field, falling back
    /// to `comm`).
    targets: HashSet<String>,
    /// True once any of the distinct-set trackers hit `MAX_DISTINCT_TRACKED`.
    /// Prevents memory bloat on runaway rules.
    distinct_tracker_capped: bool,
}

pub struct RuleEngine {
    rules: Vec<Rule>,
    states: HashMap<StateKey, ActiveState>,
    pending: Vec<Finding>,
    /// Cap on `Finding::raw_window` length per state. `0` disables raw-line
    /// capture entirely. Sprint-2 PR 4.
    raw_window_cap: usize,
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
            raw_window_cap: DEFAULT_RAW_WINDOW_CAP,
        })
    }

    /// Set the per-finding raw_window cap. `0` disables raw-line capture.
    /// Sprint-2 PR 4.
    pub fn set_raw_window_cap(&mut self, cap: usize) {
        self.raw_window_cap = cap;
    }

    pub fn raw_window_cap(&self) -> usize {
        self.raw_window_cap
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

            let raw_window_cap = self.raw_window_cap;
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
                    raw_lines: Vec::new(),
                    prev_ts_ns: None,
                    min_interval_ns: None,
                    max_interval_ns: None,
                    peak_fd_count: None,
                    peak_fd_pct_of_rlimit: None,
                    callee_pids: HashSet::new(),
                    binder_codes: HashSet::new(),
                    targets: HashSet::new(),
                    distinct_tracker_capped: false,
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

            // ── Sprint-2 PR 4: aggregate / raw-window collection ──────
            //
            // raw_window: bounded clone of full NDJSON line. Only fills
            // when the caller stamped raw_line on the Event view; offline
            // re-parses (Event::parse_line) populate it, the engine hot
            // path in main.rs does too.
            if state.raw_lines.len() < raw_window_cap {
                if let Some(line) = ev.raw_line() {
                    state.raw_lines.push(line.to_string());
                }
            }
            // Inter-event intervals.
            if let Some(prev) = state.prev_ts_ns {
                let gap = ev.ts_ns.saturating_sub(prev);
                state.min_interval_ns = Some(state.min_interval_ns.map_or(gap, |x| x.min(gap)));
                state.max_interval_ns = Some(state.max_interval_ns.map_or(gap, |x| x.max(gap)));
            }
            state.prev_ts_ns = Some(ev.ts_ns);
            // FdSnapshot peaks.
            if let Some(c) = ev.fd_count {
                state.peak_fd_count = Some(state.peak_fd_count.map_or(c, |x| x.max(c)));
            }
            if let Some(p) = ev.fd_pct_of_rlimit {
                state.peak_fd_pct_of_rlimit =
                    Some(state.peak_fd_pct_of_rlimit.map_or(p, |x| x.max(p)));
            }
            // BinderCall distincts.
            if let Some(callee) = ev.binder_callee_pid {
                if state.callee_pids.len() < MAX_DISTINCT_TRACKED {
                    state.callee_pids.insert(callee);
                } else {
                    state.distinct_tracker_capped = true;
                }
            }
            if let Some(code) = ev.binder_code {
                if state.binder_codes.len() < MAX_DISTINCT_TRACKED {
                    state.binder_codes.insert(code);
                } else {
                    state.distinct_tracker_capped = true;
                }
            }
            // Distinct targets — uses the same logic as PerTarget aggregation.
            let t = match_target(ev);
            if !t.is_empty() {
                if state.targets.len() < MAX_DISTINCT_TRACKED {
                    state.targets.insert(t);
                } else {
                    state.distinct_tracker_capped = true;
                }
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
        aggregates: build_aggregates(state),
        raw_window: state.raw_lines.clone(),
    }
}

/// Compute the [`Aggregates`] block from a state's running tallies.
/// `events_per_sec` is `count / span_secs` when at least two events landed
/// inside a non-zero span. Min/max intervals are drawn from the running
/// trackers populated in `feed`.
fn build_aggregates(state: &ActiveState) -> Aggregates {
    let mut a = Aggregates::default();
    let span_ns = state.last_ns.saturating_sub(state.first_ns);
    if state.count >= 2 && span_ns > 0 {
        let span_s = span_ns as f64 / 1_000_000_000.0;
        if span_s > 0.0 {
            a.events_per_sec = Some(state.count as f64 / span_s);
        }
    }
    a.min_interval_ms = state.min_interval_ns.map(|n| n as f64 / 1_000_000.0);
    a.max_interval_ms = state.max_interval_ns.map(|n| n as f64 / 1_000_000.0);
    if !state.targets.is_empty() {
        a.distinct_targets = Some(state.targets.len() as u32);
    }
    a.peak_fd_count = state.peak_fd_count;
    a.peak_fd_pct_of_rlimit = state.peak_fd_pct_of_rlimit;
    if !state.callee_pids.is_empty() {
        a.distinct_callee_pids = Some(state.callee_pids.len() as u32);
    }
    if !state.binder_codes.is_empty() {
        a.distinct_binder_codes = Some(state.binder_codes.len() as u32);
    }
    a
}
