//! Shared evidence limits and deterministic projections of normalized captures.
use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::{json, Value};

use crate::capture_normalize::{CausalRelation, NormalizedCapture};

#[derive(Clone, Debug, Serialize)]
pub struct CapturePassport {
    pub schema: &'static str,
    pub capture_sha256: String,
    pub bundle_integrity: &'static str,
    pub transport_health: String,
    pub bounded_claims_eligible: bool,
    pub restrictions: Vec<String>,
    pub effective_scope: Option<crate::health::CaptureScope>,
    pub scenarios: Vec<Value>,
}

impl CapturePassport {
    pub fn from_capture(capture: &NormalizedCapture) -> Self {
        let health = capture.health.as_ref();
        let scope = health.and_then(|health| health.capture_scope.clone());
        let mut restrictions = capture.health_warnings.clone();
        if scope.is_none() {
            restrictions.insert("effective capture scope is unknown".into());
        }
        if capture.scenario_contract.is_none() {
            restrictions.insert("no validated bounded scenario lifecycle".into());
        }
        if let Some(scope) = &scope {
            restrictions.extend(scope.claim_scope_reasons.iter().cloned());
        }
        let eligible = health.is_some_and(|health| {
            health.status == "complete" && !health.degraded && !health.output_cap_hit
        }) && scope
            .as_ref()
            .is_some_and(|scope| scope.claim_scope_complete)
            && restrictions.is_empty();
        let scenarios = capture
            .markers
            .iter()
            .map(|marker| {
                json!({
                    "name": marker.name, "phase": marker.phase, "ts_ns": marker.ts_ns,
                    "clock": "capture monotonic nanoseconds", "trace_id": marker.trace_id,
                    "subject": marker.subject, "root_package": marker.root_package,
                    "root_uid": marker.root_uid, "root_pid": marker.root_pid,
                })
            })
            .collect();
        Self {
            schema: "neutron.capture-passport/v1",
            capture_sha256: capture.capture_sha256.clone(),
            bundle_integrity: "not checked by detached capture analysis; use evidence verify",
            transport_health: health
                .map_or("unknown", |health| health.status.as_str())
                .into(),
            bounded_claims_eligible: eligible,
            restrictions: restrictions.into_iter().collect(),
            effective_scope: scope,
            scenarios,
        }
    }

    pub fn render_text(&self) -> String {
        let mut output = format!(
            "Capture SHA-256: {}\nTransport health: {}\nClaims: {}\nBundle integrity: {}\n",
            self.capture_sha256,
            self.transport_health,
            if self.bounded_claims_eligible {
                "bounded observations only; never general unreachability"
            } else {
                "positive observations only; absence is nonconclusive"
            },
            self.bundle_integrity,
        );
        for reason in &self.restrictions {
            output.push_str(&format!(
                "Restriction: {}\n",
                crate::decode::escape_text(reason)
            ));
        }
        output.push_str(&format!(
            "Scenario boundaries: {}\nEffective capture scope: {}\n",
            json!(self.scenarios),
            json!(self.effective_scope)
        ));
        output
    }
}

#[derive(Debug)]
struct Step {
    pid: u32,
    receiver: Option<u32>,
    trace: String,
    span: String,
    parent: Option<String>,
    ts: Option<u64>,
    relation: CausalRelation,
    kind: &'static str,
    label: String,
}

impl Step {
    fn alternatives(&self, steps: &[Self]) -> String {
        let candidates: Vec<_> = steps
            .iter()
            .filter(|candidate| {
                candidate.trace == self.trace
                    && candidate.receiver == Some(self.pid)
                    && candidate.span != self.span
                    && Some(candidate.span.as_str()) != self.parent.as_deref()
                    && candidate
                        .ts
                        .zip(self.ts)
                        .is_some_and(|(delivery, event)| delivery <= event)
            })
            .take(8)
            .map(|candidate| markdown(&candidate.span))
            .collect();
        if candidates.is_empty() {
            "none in this overview".into()
        } else {
            candidates.join(", ")
        }
    }
}

/// A bounded overview of recorded causal spans, with references into the hashed input.
pub(crate) fn narrative(
    capture: &NormalizedCapture,
    subject: Option<&crate::subject::SubjectSelector>,
) -> String {
    let selected: BTreeSet<_> = capture
        .markers
        .iter()
        .filter(|marker| {
            subject.map_or(true, |subject| {
                subject.matches_capture(
                    marker.subject.as_ref(),
                    marker.root_package.as_deref(),
                    marker.root_uid,
                    marker.root_pid,
                )
            })
        })
        .filter_map(|marker| marker.trace_id.as_deref())
        .collect();
    let mut steps = Vec::new();
    for span in &capture.binders {
        if let (Some(trace), Some(id)) = (&span.trace_id, &span.span_id) {
            steps.push(Step { pid: span.caller_pid, receiver: Some(span.callee_pid), trace: trace.clone(), span: id.clone(), parent: span.parent_span_id.clone(),
                ts: span.ts_ns, relation: span.relation, kind: "Binder",
                label: format!("PID {} → PID {}, Binder code {}, delivery={}, service={} (attribution={}); dequeue does not prove method completion",
                    span.caller_pid, span.callee_pid, span.code.map_or("unknown".into(), |v| v.to_string()),
                    span.status.as_deref().unwrap_or("unknown"), span.service.as_deref().unwrap_or("unknown"),
                    span.attribution_confidence.as_deref().unwrap_or("unknown")),
            });
        }
    }
    for span in &capture.syscalls {
        if let (Some(trace), Some(id)) = (&span.trace_id, &span.span_id) {
            steps.push(Step {
                pid: span.pid,
                receiver: None,
                trace: trace.clone(),
                span: id.clone(),
                parent: span.parent_span_id.clone(),
                ts: span.ts_ns,
                relation: span.relation,
                kind: "syscall",
                label: format!(
                    "PID {} TID {}: {} {}, result={}, fd={} ({})",
                    span.pid,
                    span.tid,
                    span.name,
                    span.phase,
                    span.ret
                        .filter(|_| span.is_exit())
                        .map_or("not observed".into(), |v| v.to_string()),
                    span.fd_path.as_deref().unwrap_or("unknown"),
                    span.fd_binding_confidence.as_deref().unwrap_or("unknown")
                ),
            });
        }
    }
    steps.retain(|step| subject.is_none() || selected.contains(step.trace.as_str()));
    steps.sort_by(|a, b| (&a.trace, a.ts, &a.span, a.kind).cmp(&(&b.trace, b.ts, &b.span, b.kind)));
    let mut output = String::from("## Observability overview\n\nObserved Binder and syscall spans are listed below. Return values describe kernel operations; they do not establish application policy outcomes. External probe results are separate artifacts: use `evidence report` on the verified run bundle. In-process decisions and unobserved asynchronous work remain blind spots.\n\n");
    if steps.is_empty() {
        output.push_str("No causally identified Binder/syscall spans are available for this selection. Detailed positive observations may still appear below.\n\n");
        return output;
    }
    // Bound narrative work independently of the full normalized capture.
    let total = steps.len();
    steps.truncate(512);
    let index: BTreeMap<_, _> = steps
        .iter()
        .enumerate()
        .map(|(i, s)| ((s.trace.as_str(), s.span.as_str()), i))
        .collect();
    let mut best = Vec::new();
    let mut best_rank = None;
    for i in 0..steps.len() {
        let mut chain = Vec::new();
        let mut seen = BTreeSet::new();
        let mut current = Some(i);
        let mut incomplete = false;
        while let Some(j) = current {
            if !seen.insert(j) {
                incomplete = true;
                break;
            }
            chain.push(j);
            current = steps[j].parent.as_ref().and_then(|parent| {
                let found = index
                    .get(&(steps[j].trace.as_str(), parent.as_str()))
                    .copied();
                if found.is_none() {
                    incomplete = true;
                }
                found
            });
        }
        let uncertain = chain
            .iter()
            .filter(|&&j| steps[j].parent.is_some() && steps[j].relation != CausalRelation::Exact)
            .count();
        let boundaries: BTreeSet<_> = chain.iter().map(|&j| steps[j].kind).collect();
        let rank = (
            incomplete,
            uncertain,
            std::cmp::Reverse(boundaries.len()),
            std::cmp::Reverse(chain.len()),
        );
        if best_rank.as_ref().map_or(true, |best| &rank < best) {
            best_rank = Some(rank);
            best = chain;
        }
    }
    best.reverse();
    output.push_str("**Best-supported displayed chain** (within the overview limit; edge confidence is preserved):\n\n");
    if best_rank.is_some_and(|rank| rank.0) {
        output.push_str("Ancestry is incomplete: a parent is missing from the overview or a cycle was encountered.\n\n");
    }
    if best.len() > 64 {
        output.push_str(
            "Chain shortened to its first 64 spans; see the raw capture for the remainder.\n\n",
        );
    }
    for &i in best.iter().take(64) {
        let step = &steps[i];
        let boundary = match step.parent.as_deref() {
            Some(parent) if !index.contains_key(&(step.trace.as_str(), parent)) => {
                "; parent outside overview or missing"
            }
            _ => "",
        };
        output.push_str(&format!(
            "- {} — {:?}{}; source trace `{}`, span `{}`.\n",
            markdown(&step.label),
            step.relation,
            boundary,
            markdown(&step.trace),
            markdown(&step.span)
        ));
        if step.relation == CausalRelation::Inferred {
            output.push_str(&format!("  Process/follow context is a candidate only; queue ownership and unrelated work are unresolved. Other observed same-PID delivery spans (up to 8, not established parents): {}.\n", step.alternatives(&steps)));
        }
    }
    output.push_str("\n**Timeline by trace** — capture monotonic nanoseconds; separate traces are not a shared semantic action.\n\n| Timestamp ns | Boundary | Causal evidence | Input records | Other same-PID deliveries (candidates only, max 8) |\n|---|---|---|---|---|\n");
    for step in steps.iter().take(64) {
        let refs = capture
            .source_records
            .get(&(step.trace.clone(), step.span.clone()));
        let broken = step
            .parent
            .as_ref()
            .is_some_and(|parent| !index.contains_key(&(step.trace.as_str(), parent.as_str())));
        output.push_str(&format!(
            "| {} | {} | {:?}{}; trace {}; span {}; parent {} | {} | {} |\n",
            step.ts.map_or("unknown".into(), |v| v.to_string()),
            markdown(&step.label),
            step.relation,
            if broken {
                "; parent outside overview or missing"
            } else {
                ""
            },
            markdown(&step.trace),
            markdown(&step.span),
            markdown(step.parent.as_deref().unwrap_or("none")),
            refs.map_or("unavailable".into(), |v| v
                .iter()
                .take(8)
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(", ")),
            if step.relation == CausalRelation::Inferred {
                step.alternatives(&steps)
            } else {
                "not inferred".into()
            }
        ));
    }
    output.push_str(&format!("\nShowing {} of {total} causal spans; chain selection examines at most 512. Input record numbers refer to the capture SHA-256 in the passport. Other branches and raw events remain in that capture.\n\n", steps.len().min(64)));
    output
}

fn markdown(value: &str) -> String {
    crate::decode::escape_text(value)
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('|', "&#124;")
        .replace('`', "&#96;")
        .replace('[', "&#91;")
        .replace(']', "&#93;")
}
