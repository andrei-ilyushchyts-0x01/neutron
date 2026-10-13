//! Ordered scenario validation shared by bundles and detached consumers.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActiveLiveScenario {
    subject: Option<crate::subject::ResolvedSubject>,
    scenario_id: String,
    trace_id: String,
    generation: u16,
    root_package: Option<String>,
    root_uid: Option<u32>,
    root_pid: Option<u32>,
    start_ts_ns: u64,
    max_event_ts_ns: u64,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct LiveScenarioLifecycle {
    active: Option<ActiveLiveScenario>,
    seen_scenarios: BTreeSet<String>,
    seen_trace_ids: BTreeSet<String>,
    seen_generations: BTreeSet<u16>,
    completed: Vec<crate::capture_normalize::ScenarioIdentity>,
    trace_ids: std::collections::BTreeMap<String, String>,
    last_boundary_ts_ns: u64,
}

impl LiveScenarioLifecycle {
    pub(crate) fn contract(&self) -> Result<crate::capture_normalize::ScenarioContract> {
        self.finish(&Value::Null)?;
        Ok(crate::capture_normalize::ScenarioContract {
            scenarios: self.completed.clone(),
            trace_ids: self.trace_ids.clone(),
        })
    }

    pub(crate) fn observe(
        &mut self,
        kind: &str,
        object: &serde_json::Map<String, Value>,
    ) -> Result<()> {
        if kind == "marker" {
            self.observe_marker(object)
        } else {
            self.observe_event(object)
        }
    }

    fn observe_marker(&mut self, object: &serde_json::Map<String, Value>) -> Result<()> {
        let scenario_id = required_record_text(object, "scenario_id")?;
        validate_scenario_id(scenario_id)?;
        if required_record_text(object, "name")? != scenario_id {
            bail!("scenario marker name and scenario_id differ");
        }
        let trace_id = required_record_text(object, "trace_id")?;
        validate_trace_id(trace_id)?;
        let generation = object
            .get("generation")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .filter(|value| *value > 0)
            .context("scenario marker is missing a valid generation")?;
        let timestamp = object
            .get("ts_ns")
            .and_then(Value::as_u64)
            .filter(|value| *value > 0)
            .context("scenario marker is missing a positive timestamp")?;
        if timestamp < self.last_boundary_ts_ns {
            bail!("scenario boundary timestamps are not monotonic");
        }
        let subject = object
            .get("subject")
            .map(|value| serde_json::from_value::<crate::subject::ResolvedSubject>(value.clone()))
            .transpose()?;
        if let Some(subject) = &subject {
            subject.validate()?;
        }
        let root_package = optional_record_text(object, "root_package")?;
        let root_uid = optional_record_u32(object, "root_uid", false)?;
        let root_pid = optional_record_u32(object, "root_pid", true)?;
        if subject.is_none() && root_package.is_none() && root_uid.is_none() && root_pid.is_none() {
            bail!("scenario marker is missing a package, UID, or PID root selector");
        }

        match required_record_text(object, "phase")? {
            "start" => {
                if self.active.is_some() {
                    bail!("scenario markers overlap or contain duplicate starts");
                }
                if !self.seen_scenarios.insert(scenario_id.to_owned()) {
                    bail!("scenario_id was reused in one capture");
                }
                if !self.seen_trace_ids.insert(trace_id.to_owned()) {
                    bail!("trace_id was reused in one capture");
                }
                if !self.seen_generations.insert(generation) {
                    bail!("scenario generation was reused in one capture");
                }
                self.active = Some(ActiveLiveScenario {
                    subject,
                    scenario_id: scenario_id.to_owned(),
                    trace_id: trace_id.to_owned(),
                    generation,
                    root_package,
                    root_uid,
                    root_pid,
                    start_ts_ns: timestamp,
                    max_event_ts_ns: timestamp,
                });
                self.last_boundary_ts_ns = timestamp;
            }
            "end" => {
                let active = self
                    .active
                    .take()
                    .context("scenario end marker has no matching start")?;
                if active.subject != subject
                    || active.scenario_id != scenario_id
                    || active.trace_id != trace_id
                    || active.generation != generation
                    || active.root_package != root_package
                    || active.root_uid != root_uid
                    || active.root_pid != root_pid
                {
                    bail!("scenario start/end identity does not match");
                }
                if timestamp < active.start_ts_ns || timestamp < active.max_event_ts_ns {
                    bail!("scenario end timestamp precedes its bounded records");
                }
                self.trace_ids
                    .insert(active.scenario_id.clone(), active.trace_id);
                self.completed
                    .push(crate::capture_normalize::ScenarioIdentity {
                        subject: active
                            .subject
                            .as_ref()
                            .map(|subject| subject.selector.clone()),
                        scenario_id: active.scenario_id,
                        root_package: active.root_package,
                        root_uid: active.root_uid,
                        root_pid: active.root_pid,
                    });
                self.last_boundary_ts_ns = timestamp;
            }
            _ => bail!("scenario marker phase must be start or end"),
        }
        Ok(())
    }

    fn observe_event(&mut self, object: &serde_json::Map<String, Value>) -> Result<()> {
        let has_scenario = object.contains_key("scenario_id");
        let has_trace = object.contains_key("trace_id");
        if !has_scenario && !has_trace {
            return Ok(());
        }
        let scenario_id = required_record_text(object, "scenario_id")?;
        let trace_id = required_record_text(object, "trace_id")?;
        validate_scenario_id(scenario_id)?;
        validate_trace_id(trace_id)?;
        let active = self
            .active
            .as_mut()
            .context("causally tagged record is outside a scenario interval")?;
        if active.scenario_id != scenario_id || active.trace_id != trace_id {
            bail!("causal record scenario_id/trace_id does not match the active scenario");
        }
        if let Some(value) = object.get("subject") {
            let subject: crate::subject::ResolvedSubject = serde_json::from_value(value.clone())?;
            active
                .subject
                .as_ref()
                .context("subject admission has no scenario subject")?
                .validate_successor(&subject)?;
        }
        if let Some(generation) = optional_record_u32(object, "generation", true)? {
            if generation != u32::from(active.generation) {
                bail!("causal record generation does not match the active scenario");
            }
        }
        if let Some(root_package) = optional_record_text(object, "root_package")? {
            if active.root_package.as_deref() != Some(root_package.as_str()) {
                bail!("causal record package root does not match the active scenario");
            }
        }
        if let Some(root_uid) = optional_record_u32(object, "root_uid", false)? {
            if active.root_uid != Some(root_uid) {
                bail!("causal record UID root does not match the active scenario");
            }
        }
        if let Some(root_pid) = optional_record_u32(object, "root_pid", true)? {
            if active.root_pid != Some(root_pid) {
                bail!("causal record PID root does not match the active scenario");
            }
        }
        if let Some(timestamp) = object.get("ts_ns").or_else(|| object.get("timestamp_ns")) {
            let timestamp = timestamp
                .as_u64()
                .filter(|value| *value > 0)
                .context("causal record has an invalid timestamp")?;
            if timestamp < active.start_ts_ns {
                bail!("causal record timestamp precedes its scenario start");
            }
            active.max_event_ts_ns = active.max_event_ts_ns.max(timestamp);
        }
        Ok(())
    }

    pub(crate) fn finish(&self, expected_health: &Value) -> Result<()> {
        if let Some(active) = &self.active {
            let status = expected_health.get("status").and_then(Value::as_str);
            let expected_reason = format!(
                "scenario '{}' ended without a closing marker",
                active.scenario_id
            );
            let reason_recorded = expected_health
                .get("incomplete_reasons")
                .and_then(Value::as_array)
                .is_some_and(|reasons| {
                    reasons
                        .iter()
                        .any(|reason| reason.as_str() == Some(expected_reason.as_str()))
                });
            if !matches!(status, Some("incomplete" | "unknown")) || !reason_recorded {
                bail!("scenario start marker has no matching end");
            }
            return Ok(());
        }
        if self.completed.is_empty() {
            bail!("capture has no paired scenario lifecycle markers");
        }
        Ok(())
    }
}

fn required_record_text<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a str> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("record is missing {field}"))?;
    validate_label(field, value)?;
    Ok(value)
}

fn optional_record_text(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<String>> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .filter(|value| !value.is_empty())
        .with_context(|| format!("record contains invalid {field}"))?;
    validate_label(field, value)?;
    Ok(Some(value.to_owned()))
}

fn optional_record_u32(
    object: &serde_json::Map<String, Value>,
    field: &str,
    positive: bool,
) -> Result<Option<u32>> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    let value = value
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| !positive || *value > 0)
        .with_context(|| format!("record contains invalid {field}"))?;
    Ok(Some(value))
}

fn validate_scenario_id(value: &str) -> Result<()> {
    if value.len() > 128 || value.trim().is_empty() || value.chars().any(char::is_control) {
        bail!("scenario_id must be at most 128 printable characters");
    }
    Ok(())
}

fn validate_trace_id(value: &str) -> Result<()> {
    validate_lower_hex("trace_id", value, 16)?;
    if value.bytes().all(|byte| byte == b'0') {
        bail!("trace_id must be non-zero");
    }
    Ok(())
}

pub(crate) fn validate_lower_hex(name: &str, value: &str, length: usize) -> Result<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{name} must contain {length} lowercase hexadecimal digits");
    }
    Ok(())
}

pub(crate) fn validate_label(name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        bail!("{name} must be a bounded printable string");
    }
    Ok(())
}
