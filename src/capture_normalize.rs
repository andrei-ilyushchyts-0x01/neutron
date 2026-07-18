//! Shared, tolerant normalization for causal NDJSON captures.

use std::collections::{BTreeMap, BTreeSet};
use std::io::BufRead;

use anyhow::{Context, Result};
use serde_json::{Map, Value};

use crate::capture_input::{read_capture_record, validate_capture_strings};

const MAX_NORMALIZED_ITEMS: usize = 1_000_000;
const MAX_NORMALIZED_STRING_BYTES: usize = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum CausalRelation {
    #[default]
    Exact,
    Inferred,
}

#[derive(Clone, Debug, Default)]
pub struct BinderSpan {
    pub ts_ns: Option<u64>,
    pub debug_id: i64,
    pub caller_pid: u32,
    pub caller_uid: Option<u32>,
    pub callee_pid: u32,
    pub caller_comm: Option<String>,
    pub callee_comm: Option<String>,
    pub target_node: Option<i64>,
    pub code: Option<u64>,
    pub flags: Option<u64>,
    pub reply: Option<bool>,
    pub service: Option<String>,
    pub service_candidates: Vec<String>,
    pub method: Option<String>,
    pub attribution_confidence: Option<String>,
    pub latency_us: Option<u64>,
    pub status: Option<String>,
    pub trace_id: Option<String>,
    pub scenario_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub depth: Option<u8>,
    pub root_package: Option<String>,
    pub root_uid: Option<u32>,
    pub relation: CausalRelation,
}

#[derive(Clone, Debug, Default)]
pub struct SyscallSpan {
    pub ts_ns: Option<u64>,
    pub pid: u32,
    pub uid: Option<u32>,
    pub tid: u32,
    pub nr: i64,
    pub name: String,
    pub comm: Option<String>,
    pub phase: String,
    pub ret: Option<i64>,
    pub latency_us: Option<u64>,
    pub ioctl_cmd: Option<u32>,
    pub ioctl_name: Option<String>,
    pub ioctl_family: Option<String>,
    pub fd_path: Option<String>,
    pub args: Option<[u64; 6]>,
    pub data_phase: Option<String>,
    pub dma_heap: Option<DmaHeapAllocation>,
    pub trace_id: Option<String>,
    pub scenario_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub depth: Option<u8>,
    pub root_package: Option<String>,
    pub root_uid: Option<u32>,
    pub relation: CausalRelation,
    pub enter_ts_ns: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DmaHeapAllocation {
    pub length: u64,
    pub returned_fd: i32,
    pub fd_flags: u32,
    pub heap_flags: u64,
}

impl SyscallSpan {
    pub fn is_exit(&self) -> bool {
        self.phase == "exit"
    }
}

#[derive(Clone, Debug, Default)]
pub struct ExitSpan {
    pub ts_ns: Option<u64>,
    pub pid: u32,
    pub uid: Option<u32>,
    pub comm: Option<String>,
    pub classification: String,
    pub label: String,
    pub trace_id: Option<String>,
    pub scenario_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub depth: Option<u8>,
    pub root_package: Option<String>,
    pub root_uid: Option<u32>,
    pub relation: CausalRelation,
}

#[derive(Clone, Debug, Default)]
pub struct SelinuxSpan {
    pub ts_ns: Option<u64>,
    pub pid: u32,
    pub tid: u32,
    pub uid: Option<u32>,
    pub comm: Option<String>,
    pub source_domain: String,
    pub target_type: String,
    pub tclass: String,
    pub permissions: Vec<String>,
    pub path: Option<String>,
    pub result: String,
    pub trace_id: Option<String>,
    pub scenario_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub depth: Option<u8>,
    pub root_package: Option<String>,
    pub root_uid: Option<u32>,
    pub relation: CausalRelation,
}

#[derive(Clone, Debug, Default)]
pub struct Marker {
    pub ts_ns: Option<u64>,
    pub name: String,
    pub phase: Option<String>,
    pub scenario_id: Option<String>,
    pub trace_id: Option<String>,
    pub root_package: Option<String>,
    pub root_uid: Option<u32>,
    pub root_pid: Option<u32>,
}

/// Stable scenario identity used to decide whether two captures exercised
/// the same bounded procedure. Trace IDs and timestamps are deliberately not
/// part of the cross-run identity: they prove pairing inside a run, while the
/// scenario name and root selector define what may be compared.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScenarioIdentity {
    pub scenario_id: String,
    pub root_package: Option<String>,
    pub root_uid: Option<u32>,
    pub root_pid: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScenarioContract {
    pub scenarios: Vec<ScenarioIdentity>,
    pub trace_ids: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default)]
pub struct CaptureHealth {
    pub status: String,
    pub degraded: bool,
    pub output_cap_hit: bool,
    pub root_package: Option<String>,
    pub root_uid: Option<u32>,
    pub boot_id: Option<String>,
    pub fingerprint: Option<String>,
    pub traced_process_limit: u64,
    pub binder_depth_limit: u64,
    pub binder_follow_failed: u64,
    pub follow_policy_filtered: u64,
    pub follow_ttl_expired: u64,
    pub binder_tracker_evictions: u64,
    pub binder_unmatched_receives: u64,
    pub binder_causal_metadata_discarded: u64,
    pub binder_invalid_callers: u64,
    pub binder_tracker_enabled: bool,
    pub kprobe_attach_failures: Vec<String>,
    pub capture_scope: Option<crate::health::CaptureScope>,
}

#[derive(Clone, Debug, Default)]
pub struct NormalizedCapture {
    pub binders: Vec<BinderSpan>,
    pub syscalls: Vec<SyscallSpan>,
    pub exits: Vec<ExitSpan>,
    pub denials: Vec<SelinuxSpan>,
    pub markers: Vec<Marker>,
    pub health: Option<CaptureHealth>,
    pub trace_packages: BTreeMap<String, String>,
    pub health_warnings: BTreeSet<String>,
    pub has_causal: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum BinderKey {
    Causal(String, String),
    Legacy(i64),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum SyscallKey {
    Causal(String, String),
    Legacy(Option<String>, u32, u32, u64, i64),
}

pub fn normalize_capture<R: BufRead>(mut reader: R) -> Result<NormalizedCapture> {
    let mut binders = BTreeMap::<BinderKey, BinderSpan>::new();
    let mut syscalls = BTreeMap::<SyscallKey, SyscallSpan>::new();
    let mut capture = NormalizedCapture::default();
    let mut malformed_lines = 0_u64;
    let mut invalid_known_records = 0_u64;
    let mut unknown_records = 0_u64;
    let mut health_records = 0_u64;
    let mut final_record_is_health = false;
    let mut record = Vec::new();
    let mut record_number = 1usize;
    let mut normalized_items = 0usize;
    let mut string_bytes = 0usize;

    while read_capture_record(&mut reader, &mut record, record_number)? {
        let line = std::str::from_utf8(&record)
            .with_context(|| format!("capture record {record_number} is not UTF-8"))?
            .trim();
        if line.is_empty() {
            record_number += 1;
            continue;
        }
        final_record_is_health = false;
        let value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => {
                malformed_lines = malformed_lines.saturating_add(1);
                record_number += 1;
                continue;
            }
        };
        string_bytes = string_bytes
            .checked_add(validate_capture_strings(&value, record_number)?)
            .context("normalized capture string byte count overflow")?;
        if string_bytes > MAX_NORMALIZED_STRING_BYTES {
            anyhow::bail!("normalized capture strings exceed {MAX_NORMALIZED_STRING_BYTES} bytes");
        }
        let Some(object) = value.as_object() else {
            malformed_lines = malformed_lines.saturating_add(1);
            record_number += 1;
            continue;
        };
        let Some(kind) = text(object, "type") else {
            malformed_lines = malformed_lines.saturating_add(1);
            record_number += 1;
            continue;
        };
        let retained_items = match kind {
            "binder" | "binder_call" | "binder_received" => object
                .get("service_candidates")
                .and_then(Value::as_array)
                .map_or(1, |values| values.len().saturating_add(1)),
            "selinux_denial" => object
                .get("permissions")
                .and_then(Value::as_array)
                .map_or(1, |values| values.len().saturating_add(1)),
            "syscall" | "process_exit" | "marker" | "capture_health" => 1,
            _ => 0,
        };
        normalized_items = normalized_items
            .checked_add(retained_items)
            .context("normalized capture item count overflow")?;
        if normalized_items > MAX_NORMALIZED_ITEMS {
            anyhow::bail!("normalized capture exceeds {MAX_NORMALIZED_ITEMS} retained items");
        }
        final_record_is_health = kind == "capture_health";

        if let (Some(trace), Some(package)) =
            (text(object, "trace_id"), text(object, "root_package"))
        {
            capture
                .trace_packages
                .insert(trace.to_string(), package.to_string());
        }

        match kind {
            "binder" | "binder_call" => {
                capture.has_causal |= has_causal(object);
                if !merge_binder(&mut binders, object) {
                    invalid_known_records = invalid_known_records.saturating_add(1);
                }
            }
            "binder_received" => {
                capture.has_causal |= has_causal(object);
                if !merge_binder_received(&mut binders, object) {
                    invalid_known_records = invalid_known_records.saturating_add(1);
                }
            }
            "syscall" => {
                capture.has_causal |= has_causal(object);
                if !merge_syscall(&mut syscalls, object) {
                    invalid_known_records = invalid_known_records.saturating_add(1);
                }
            }
            "process_exit" => {
                capture.has_causal |= has_causal(object);
                if let Some(exit) = parse_exit(object) {
                    capture.exits.push(exit);
                } else {
                    invalid_known_records = invalid_known_records.saturating_add(1);
                }
            }
            "selinux_denial" => {
                capture.has_causal |= has_causal(object);
                if let Some(denial) = parse_selinux_denial(object) {
                    capture.denials.push(denial);
                } else {
                    invalid_known_records = invalid_known_records.saturating_add(1);
                }
            }
            "marker" => capture.markers.push(parse_marker(object)),
            "capture_health" => {
                health_records = health_records.saturating_add(1);
                merge_health(&mut capture, object);
            }
            "fd_snapshot" | "finding" | "process_maps" | "stack_trace" | "follow_guardrail" => {
                if !valid_ignorable_record(kind, object) {
                    invalid_known_records = invalid_known_records.saturating_add(1);
                }
            }
            _ => unknown_records = unknown_records.saturating_add(1),
        }
        record_number += 1;
    }

    for binder in binders.into_values() {
        if binder.caller_pid == 0 || binder.callee_pid == 0 {
            capture
                .health_warnings
                .insert("ignored Binder span with a missing process endpoint".into());
        } else {
            capture.binders.push(binder);
        }
    }
    for syscall in syscalls.into_values() {
        if syscall.pid == 0 {
            capture
                .health_warnings
                .insert("ignored syscall span with a missing process endpoint".into());
        } else {
            capture.syscalls.push(syscall);
        }
    }
    if malformed_lines > 0 {
        capture.health_warnings.insert(format!(
            "ignored {malformed_lines} malformed NDJSON record(s); run health is unknown"
        ));
        if let Some(health) = capture.health.as_mut() {
            health.status = "unknown".into();
            health.degraded = true;
        }
    }
    if invalid_known_records > 0 {
        capture.health_warnings.insert(format!(
            "ignored {invalid_known_records} recognized record(s) with missing or invalid required fields; run health is unknown"
        ));
        if let Some(health) = capture.health.as_mut() {
            health.status = "unknown".into();
            health.degraded = true;
        }
    }
    if unknown_records > 0 {
        capture.health_warnings.insert(format!(
            "ignored {unknown_records} unknown record type(s); run health is unknown"
        ));
        if let Some(health) = capture.health.as_mut() {
            health.status = "unknown".into();
            health.degraded = true;
        }
    }
    if health_records > 1 {
        capture.health_warnings.insert(format!(
            "capture contains {health_records} capture_health records; run health is unknown"
        ));
        if let Some(health) = capture.health.as_mut() {
            health.status = "unknown".into();
            health.degraded = true;
        }
    }
    if capture.health.is_none() || !final_record_is_health {
        capture
            .health_warnings
            .insert("capture has no final capture_health record; run is incomplete".into());
        if let Some(health) = capture.health.as_mut() {
            if health.status != "unknown" {
                health.status = "incomplete".into();
            }
            health.degraded = true;
        }
    }
    Ok(capture)
}

/// Validate that the capture has one or more non-overlapping, exactly paired
/// scenario boundaries and that every causally tagged behavior belongs to a
/// declared scenario. This is an additional gate for negative/diff claims;
/// clean transport health alone cannot prove that the same stimulus ran.
pub fn validated_scenario_contract(capture: &NormalizedCapture) -> Result<ScenarioContract> {
    let contract = validated_marker_contract(&capture.markers)?;
    for (scenario_id, trace_id) in capture
        .binders
        .iter()
        .filter_map(|event| {
            event
                .scenario_id
                .as_deref()
                .map(|id| (id, event.trace_id.as_deref()))
        })
        .chain(capture.syscalls.iter().filter_map(|event| {
            event
                .scenario_id
                .as_deref()
                .map(|id| (id, event.trace_id.as_deref()))
        }))
        .chain(capture.exits.iter().filter_map(|event| {
            event
                .scenario_id
                .as_deref()
                .map(|id| (id, event.trace_id.as_deref()))
        }))
        .chain(capture.denials.iter().filter_map(|event| {
            event
                .scenario_id
                .as_deref()
                .map(|id| (id, event.trace_id.as_deref()))
        }))
    {
        if contract.trace_ids.get(scenario_id).map(String::as_str) != trace_id {
            anyhow::bail!("event scenario_id/trace_id does not match a completed scenario");
        }
    }
    Ok(contract)
}

pub fn validated_marker_contract(markers: &[Marker]) -> Result<ScenarioContract> {
    let mut active: Option<(&Marker, String)> = None;
    let mut scenarios = Vec::new();
    let mut trace_ids = BTreeMap::new();
    let mut seen = BTreeSet::new();

    for marker in markers {
        let phase = marker
            .phase
            .as_deref()
            .context("scenario marker is missing phase")?;
        let scenario_id = marker
            .scenario_id
            .as_deref()
            .filter(|value| !value.is_empty())
            .context("scenario marker is missing scenario_id")?;
        if marker.name != scenario_id {
            anyhow::bail!("scenario marker name and scenario_id differ");
        }
        let trace_id = marker
            .trace_id
            .as_deref()
            .filter(|value| !value.is_empty())
            .context("scenario marker is missing trace_id")?;
        let timestamp = marker
            .ts_ns
            .filter(|value| *value > 0)
            .context("scenario marker is missing a positive timestamp")?;
        if marker.root_package.is_none() && marker.root_uid.is_none() && marker.root_pid.is_none() {
            anyhow::bail!("scenario marker is missing a package, UID, or PID root selector");
        }
        match phase {
            "start" => {
                if active.is_some() {
                    anyhow::bail!("scenario markers overlap or contain duplicate starts");
                }
                if !seen.insert(scenario_id.to_string()) {
                    anyhow::bail!("scenario_id was reused in one capture");
                }
                active = Some((marker, trace_id.to_string()));
            }
            "end" => {
                let (start, start_trace_id) = active
                    .take()
                    .context("scenario end marker has no matching start")?;
                if start.scenario_id.as_deref() != Some(scenario_id)
                    || start_trace_id != trace_id
                    || start.root_package != marker.root_package
                    || start.root_uid != marker.root_uid
                    || start.root_pid != marker.root_pid
                {
                    anyhow::bail!("scenario start/end identity does not match");
                }
                if start.ts_ns.is_some_and(|start_ts| timestamp < start_ts) {
                    anyhow::bail!("scenario end timestamp precedes its start");
                }
                scenarios.push(ScenarioIdentity {
                    scenario_id: scenario_id.to_string(),
                    root_package: marker.root_package.clone(),
                    root_uid: marker.root_uid,
                    root_pid: marker.root_pid,
                });
                trace_ids.insert(scenario_id.to_string(), trace_id.to_string());
            }
            _ => anyhow::bail!("scenario marker phase must be start or end"),
        }
    }
    if active.is_some() {
        anyhow::bail!("scenario start marker has no matching end");
    }
    if scenarios.is_empty() {
        anyhow::bail!("capture has no paired scenario lifecycle markers");
    }
    Ok(ScenarioContract {
        scenarios,
        trace_ids,
    })
}

fn valid_ignorable_record(kind: &str, object: &Map<String, Value>) -> bool {
    let positive = |field| number_u64(object, field).is_some_and(|value| value > 0);
    match kind {
        "fd_snapshot" => positive("pid"),
        "finding" => text(object, "rule_id").is_some_and(|value| !value.is_empty()),
        "process_maps" => positive("pid") && object.get("mappings").is_some_and(Value::is_array),
        "stack_trace" => {
            positive("pid")
                && text(object, "stack_trace_ref").is_some_and(|value| !value.is_empty())
        }
        "follow_guardrail" => {
            positive("caller_pid")
                && positive("callee_pid")
                && text(object, "status").is_some()
                && text(object, "reason").is_some()
        }
        _ => false,
    }
}

fn merge_binder(
    binders: &mut BTreeMap<BinderKey, BinderSpan>,
    object: &Map<String, Value>,
) -> bool {
    let Some(debug_id) = number_i64(object, "debug_id") else {
        return false;
    };
    let causal_key = causal_key(object).map(|(trace, span)| BinderKey::Causal(trace, span));
    let key = if let Some(key) = causal_key {
        key
    } else {
        let matches: Vec<BinderKey> = binders
            .iter()
            .filter(|(_, span)| span.debug_id == debug_id)
            .map(|(key, _)| key.clone())
            .collect();
        if matches.len() == 1 {
            matches[0].clone()
        } else {
            BinderKey::Legacy(debug_id)
        }
    };

    let node = binders.entry(key).or_insert_with(|| BinderSpan {
        debug_id,
        ..BinderSpan::default()
    });
    apply_binder_fields(node, object);
    true
}

fn merge_binder_received(
    binders: &mut BTreeMap<BinderKey, BinderSpan>,
    object: &Map<String, Value>,
) -> bool {
    let Some(debug_id) = number_i64(object, "debug_id") else {
        return false;
    };
    let key = causal_key(object)
        .map(|(trace, span)| BinderKey::Causal(trace, span))
        .unwrap_or_else(|| BinderKey::Legacy(debug_id));
    let node = binders.entry(key).or_insert_with(|| BinderSpan {
        debug_id,
        ..BinderSpan::default()
    });
    node.ts_ns = node.ts_ns.or_else(|| number_u64(object, "ts_ns"));
    node.callee_pid = number_u32(object, "pid").unwrap_or(node.callee_pid);
    replace_text(&mut node.callee_comm, object, "comm");
    replace_text(&mut node.trace_id, object, "trace_id");
    replace_text(&mut node.scenario_id, object, "scenario_id");
    replace_text(&mut node.span_id, object, "span_id");
    replace_text(&mut node.parent_span_id, object, "parent_span_id");
    node.depth = number_u64(object, "depth")
        .and_then(|value| u8::try_from(value).ok())
        .or(node.depth);
    replace_text(&mut node.root_package, object, "root_package");
    node.root_uid = number_u32(object, "root_uid").or(node.root_uid);
    if let Some(relation) = relation(object) {
        node.relation = relation;
    }
    true
}

fn apply_binder_fields(node: &mut BinderSpan, object: &Map<String, Value>) {
    node.ts_ns = number_u64(object, "ts_ns").or(node.ts_ns);
    node.caller_pid = number_u32(object, "caller_pid")
        .or_else(|| number_u32(object, "pid"))
        .unwrap_or(node.caller_pid);
    node.caller_uid = number_u32(object, "caller_uid")
        .or_else(|| number_u32(object, "uid"))
        .or(node.caller_uid);
    node.callee_pid = number_u32(object, "callee_pid")
        .or_else(|| number_u32(object, "to_proc"))
        .unwrap_or(node.callee_pid);
    replace_text(&mut node.caller_comm, object, "caller_comm");
    if text(object, "caller_comm").is_none() {
        replace_text(&mut node.caller_comm, object, "comm");
    }
    replace_text(&mut node.callee_comm, object, "callee_comm");
    node.target_node = number_i64(object, "target_node").or(node.target_node);
    node.code = number_u64(object, "code").or(node.code);
    node.flags = number_u64(object, "flags").or(node.flags);
    node.reply = object.get("reply").and_then(Value::as_bool).or(node.reply);
    replace_text(&mut node.service, object, "service");
    if let Some(candidates) = object.get("service_candidates").and_then(Value::as_array) {
        node.service_candidates = candidates
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
    }
    replace_text(&mut node.method, object, "method");
    replace_text(
        &mut node.attribution_confidence,
        object,
        "attribution_confidence",
    );
    node.latency_us = number_u64(object, "latency_us").or(node.latency_us);
    replace_text(&mut node.status, object, "status");
    replace_text(&mut node.trace_id, object, "trace_id");
    replace_text(&mut node.scenario_id, object, "scenario_id");
    replace_text(&mut node.span_id, object, "span_id");
    replace_text(&mut node.parent_span_id, object, "parent_span_id");
    node.depth = number_u64(object, "depth")
        .and_then(|value| u8::try_from(value).ok())
        .or(node.depth);
    replace_text(&mut node.root_package, object, "root_package");
    node.root_uid = number_u32(object, "root_uid").or(node.root_uid);
    if let Some(relation) = relation(object) {
        node.relation = relation;
    }
}

fn merge_syscall(
    syscalls: &mut BTreeMap<SyscallKey, SyscallSpan>,
    object: &Map<String, Value>,
) -> bool {
    let Some(pid) = number_u32(object, "pid") else {
        return false;
    };
    let tid = number_u32(object, "tid")
        .or_else(|| number_u32(object, "tgid"))
        .unwrap_or(pid);
    let nr = number_i64(object, "nr")
        .or_else(|| number_i64(object, "syscall_nr"))
        .unwrap_or(-1);
    let enter_ts_ns = number_u64(object, "enter_ts_ns")
        .or_else(|| number_u64(object, "ts_ns"))
        .unwrap_or(0);
    let is_exit = text(object, "phase") == Some("exit")
        || object.get("enter").and_then(Value::as_bool) == Some(false);
    let phase = text(object, "phase")
        .map(str::to_string)
        .unwrap_or_else(|| if is_exit { "exit" } else { "enter" }.to_string());
    let key = causal_key(object)
        .map(|(trace, span)| SyscallKey::Causal(trace, span))
        .unwrap_or_else(|| {
            SyscallKey::Legacy(
                text(object, "trace_id").map(str::to_string),
                pid,
                tid,
                enter_ts_ns,
                nr,
            )
        });
    let explicit_name = text(object, "name")
        .or_else(|| text(object, "syscall"))
        .filter(|value| !value.is_empty());
    if explicit_name.is_none() && nr < 0 {
        return false;
    }
    let name = explicit_name
        .map(str::to_string)
        .unwrap_or_else(|| format!("syscall {nr}"));
    let fd_path = text(object, "fd_path").or_else(|| {
        matches!(name.as_str(), "open" | "openat" | "openat2")
            .then(|| text(object, "data"))
            .flatten()
    });
    let candidate = SyscallSpan {
        ts_ns: number_u64(object, "ts_ns"),
        pid,
        uid: number_u32(object, "uid"),
        tid,
        nr,
        name,
        comm: text(object, "comm").map(str::to_string),
        phase,
        ret: number_i64(object, "ret"),
        latency_us: number_u64(object, "latency_us"),
        ioctl_cmd: ioctl_cmd(object),
        ioctl_name: text(object, "ioctl_name").map(str::to_string),
        ioctl_family: text(object, "ioctl_family").map(str::to_string),
        fd_path: fd_path.map(str::to_string),
        args: syscall_args(object),
        data_phase: text(object, "data_phase").map(str::to_string),
        dma_heap: parse_dma_heap(object),
        trace_id: text(object, "trace_id").map(str::to_string),
        scenario_id: text(object, "scenario_id").map(str::to_string),
        span_id: text(object, "span_id").map(str::to_string),
        parent_span_id: text(object, "parent_span_id").map(str::to_string),
        depth: number_u64(object, "depth").and_then(|value| u8::try_from(value).ok()),
        root_package: text(object, "root_package").map(str::to_string),
        root_uid: number_u32(object, "root_uid"),
        relation: relation(object).unwrap_or_default(),
        enter_ts_ns,
    };

    match syscalls.get_mut(&key) {
        Some(existing) if existing.is_exit() && !candidate.is_exit() => {}
        Some(existing) => merge_syscall_fields(existing, candidate, relation(object)),
        None => {
            syscalls.insert(key, candidate);
        }
    }
    true
}

fn merge_syscall_fields(
    existing: &mut SyscallSpan,
    candidate: SyscallSpan,
    candidate_relation: Option<CausalRelation>,
) {
    let previous = std::mem::take(existing);
    *existing = candidate;
    existing.ts_ns = existing.ts_ns.or(previous.ts_ns);
    existing.uid = existing.uid.or(previous.uid);
    existing.comm = existing.comm.take().or(previous.comm);
    existing.ret = existing.ret.or(previous.ret);
    existing.latency_us = existing.latency_us.or(previous.latency_us);
    existing.ioctl_cmd = existing.ioctl_cmd.or(previous.ioctl_cmd);
    existing.ioctl_name = existing.ioctl_name.take().or(previous.ioctl_name);
    existing.ioctl_family = existing.ioctl_family.take().or(previous.ioctl_family);
    existing.fd_path = existing.fd_path.take().or(previous.fd_path);
    existing.args = existing.args.or(previous.args);
    existing.data_phase = existing.data_phase.take().or(previous.data_phase);
    existing.dma_heap = existing.dma_heap.take().or(previous.dma_heap);
    existing.trace_id = existing.trace_id.take().or(previous.trace_id);
    existing.scenario_id = existing.scenario_id.take().or(previous.scenario_id);
    existing.span_id = existing.span_id.take().or(previous.span_id);
    existing.parent_span_id = existing.parent_span_id.take().or(previous.parent_span_id);
    existing.depth = existing.depth.or(previous.depth);
    existing.root_package = existing.root_package.take().or(previous.root_package);
    existing.root_uid = existing.root_uid.or(previous.root_uid);
    if candidate_relation.is_none() {
        existing.relation = previous.relation;
    }
}

fn parse_exit(object: &Map<String, Value>) -> Option<ExitSpan> {
    let pid = number_u32(object, "pid")?;
    Some(ExitSpan {
        ts_ns: number_u64(object, "ts_ns"),
        pid,
        uid: number_u32(object, "uid"),
        comm: text(object, "comm").map(str::to_string),
        classification: text(object, "classification")
            .unwrap_or("unknown")
            .to_string(),
        label: text(object, "signal_name")
            .or_else(|| text(object, "classification"))
            .unwrap_or("process exit")
            .to_string(),
        trace_id: text(object, "trace_id").map(str::to_string),
        scenario_id: text(object, "scenario_id").map(str::to_string),
        span_id: text(object, "span_id").map(str::to_string),
        parent_span_id: text(object, "parent_span_id").map(str::to_string),
        depth: number_u64(object, "depth").and_then(|value| u8::try_from(value).ok()),
        root_package: text(object, "root_package").map(str::to_string),
        root_uid: number_u32(object, "root_uid"),
        relation: relation(object).unwrap_or_default(),
    })
}

fn parse_selinux_denial(object: &Map<String, Value>) -> Option<SelinuxSpan> {
    let pid = number_u32(object, "pid")?;
    if pid == 0 {
        return None;
    }
    Some(SelinuxSpan {
        ts_ns: number_u64(object, "ts_ns"),
        pid,
        tid: number_u32(object, "tid").unwrap_or(pid),
        uid: number_u32(object, "uid"),
        comm: text(object, "comm").map(str::to_string),
        source_domain: text(object, "source_domain")
            .unwrap_or_default()
            .to_string(),
        target_type: text(object, "target_type").unwrap_or_default().to_string(),
        tclass: text(object, "tclass").unwrap_or_default().to_string(),
        permissions: object
            .get("permissions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        path: text(object, "path").map(str::to_string),
        result: text(object, "result").unwrap_or("denied").to_string(),
        trace_id: text(object, "trace_id").map(str::to_string),
        scenario_id: text(object, "scenario_id").map(str::to_string),
        span_id: text(object, "span_id").map(str::to_string),
        parent_span_id: text(object, "parent_span_id").map(str::to_string),
        depth: number_u64(object, "depth").and_then(|value| u8::try_from(value).ok()),
        root_package: text(object, "root_package").map(str::to_string),
        root_uid: number_u32(object, "root_uid"),
        relation: relation(object).unwrap_or_default(),
    })
}

fn parse_marker(object: &Map<String, Value>) -> Marker {
    Marker {
        ts_ns: number_u64(object, "ts_ns"),
        name: text(object, "name").unwrap_or_default().to_string(),
        phase: text(object, "phase").map(str::to_string),
        scenario_id: text(object, "scenario_id").map(str::to_string),
        trace_id: text(object, "trace_id").map(str::to_string),
        root_package: text(object, "root_package").map(str::to_string),
        root_uid: number_u32(object, "root_uid"),
        root_pid: number_u32(object, "root_pid"),
    }
}

fn merge_health(capture: &mut NormalizedCapture, object: &Map<String, Value>) {
    let contract_errors = crate::health::capture_health_contract_errors(object);
    let legacy_degraded_field = object.get("degraded").and_then(Value::as_bool);
    let legacy_degraded = legacy_degraded_field.unwrap_or(false);
    let output_cap_hit = object
        .get("output_cap_hit")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let explicit_status = object.get("status");
    let parsed_status = explicit_status
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "complete" | "degraded" | "incomplete" | "unknown"));
    let mut status = parsed_status.map(str::to_string).unwrap_or_else(|| {
        if explicit_status.is_some() {
            "unknown".into()
        } else {
            if output_cap_hit {
                "incomplete".into()
            } else if legacy_degraded {
                "degraded".into()
            } else {
                "complete".into()
            }
        }
    });
    let contradictory = parsed_status.is_some_and(|value| {
        (value == "complete" && (legacy_degraded || output_cap_hit))
            || (value != "complete" && legacy_degraded_field == Some(false))
            || (output_cap_hit && !matches!(value, "incomplete" | "unknown"))
    });
    if contradictory {
        status = "unknown".into();
        capture
            .health_warnings
            .insert("capture_health fields are contradictory".into());
    } else if explicit_status.is_some() && parsed_status.is_none() {
        capture
            .health_warnings
            .insert("capture_health status is invalid".into());
    }
    let mut health = CaptureHealth {
        degraded: legacy_degraded || status != "complete",
        output_cap_hit,
        status,
        root_package: text(object, "root_package").map(str::to_string),
        root_uid: number_u32(object, "root_uid"),
        boot_id: text(object, "boot_id").map(str::to_string),
        fingerprint: text(object, "fingerprint").map(str::to_string),
        traced_process_limit: number_u64(object, "traced_process_limit").unwrap_or(0),
        binder_depth_limit: number_u64(object, "binder_depth_limit").unwrap_or(0),
        binder_follow_failed: number_u64(object, "binder_follow_failed").unwrap_or(0),
        follow_policy_filtered: number_u64(object, "follow_policy_filtered").unwrap_or(0),
        follow_ttl_expired: number_u64(object, "follow_ttl_expired").unwrap_or(0),
        binder_tracker_evictions: number_u64(object, "binder_tracker_evictions").unwrap_or(0),
        binder_unmatched_receives: number_u64(object, "binder_unmatched_receives").unwrap_or(0),
        binder_causal_metadata_discarded: number_u64(object, "binder_causal_metadata_discarded")
            .unwrap_or(0),
        binder_invalid_callers: number_u64(object, "binder_invalid_callers").unwrap_or(0),
        binder_tracker_enabled: object
            .get("binder_tracker_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        kprobe_attach_failures: object
            .get("kprobe_attach_failures")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        capture_scope: object
            .get("capture_scope")
            .and_then(|value| crate::health::CaptureScope::from_json_value(value).ok()),
    };
    if !contract_errors.is_empty() {
        health.status = "unknown".into();
        health.degraded = true;
        capture.health_warnings.insert(format!(
            "capture_health contract is incomplete or invalid: {}",
            contract_errors.join("; ")
        ));
    }
    for (value, label) in [
        (health.traced_process_limit, "traced process limit"),
        (health.binder_depth_limit, "Binder depth limit"),
        (health.binder_follow_failed, "Binder follow failure"),
        (health.binder_tracker_evictions, "Binder tracker eviction"),
        (health.binder_unmatched_receives, "Binder unmatched receive"),
        (
            health.binder_causal_metadata_discarded,
            "Binder causal metadata discard",
        ),
        (health.binder_invalid_callers, "Binder invalid caller"),
        (
            number_u64(object, "ringbuf_reserve_failed").unwrap_or(0),
            "ring buffer event loss",
        ),
        (
            number_u64(object, "inflight_update_failed").unwrap_or(0),
            "syscall correlation update failure",
        ),
        (
            number_u64(object, "inflight_lookup_missed").unwrap_or(0),
            "syscall correlation lookup miss",
        ),
        (
            number_u64(object, "thread_context_update_failed").unwrap_or(0),
            "Binder thread-context failure",
        ),
    ] {
        if value > 0 {
            capture.health_warnings.insert(label.to_string());
        }
    }
    if !health.binder_tracker_enabled {
        capture
            .health_warnings
            .insert("Binder correlation tracker was disabled".into());
    }
    for failure in &health.kprobe_attach_failures {
        capture.health_warnings.insert(format!(
            "requested kprobe source was not attached: {failure}"
        ));
    }
    if let Some(scope) = &health.capture_scope {
        if !scope.claim_scope_complete {
            capture.health_warnings.insert(format!(
                "capture claim scope is restricted: {}",
                scope.claim_scope_reasons.join(", ")
            ));
        }
    }
    if health.status != "complete" {
        capture
            .health_warnings
            .insert(format!("capture health is {}", health.status));
    }
    if health.output_cap_hit {
        capture
            .health_warnings
            .insert("output cap truncated the capture".into());
    }
    if health.follow_policy_filtered > 0 {
        capture
            .health_warnings
            .insert("Binder branches were policy-filtered".into());
    }
    if health.follow_ttl_expired > 0 {
        capture
            .health_warnings
            .insert("Binder followers expired by TTL".into());
    }
    capture.health = Some(health);
}

fn causal_key(object: &Map<String, Value>) -> Option<(String, String)> {
    Some((
        text(object, "trace_id")?.to_string(),
        text(object, "span_id")?.to_string(),
    ))
}

fn has_causal(object: &Map<String, Value>) -> bool {
    object.contains_key("trace_id") && object.contains_key("span_id")
}

fn ioctl_cmd(object: &Map<String, Value>) -> Option<u32> {
    object
        .get("ioctl_cmd")
        .and_then(|value| {
            value
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .or_else(|| value.as_str().and_then(parse_u32))
        })
        .or_else(|| {
            object
                .get("args")
                .and_then(Value::as_array)
                .and_then(|args| args.get(1))
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
        })
}

fn syscall_args(object: &Map<String, Value>) -> Option<[u64; 6]> {
    let values = object.get("args")?.as_array()?;
    if values.len() != 6 {
        return None;
    }
    let mut args = [0_u64; 6];
    for (target, value) in args.iter_mut().zip(values) {
        *target = value.as_u64()?;
    }
    Some(args)
}

fn parse_dma_heap(object: &Map<String, Value>) -> Option<DmaHeapAllocation> {
    let dma_heap = object.get("dma_heap")?.as_object()?;
    Some(DmaHeapAllocation {
        length: number_u64(dma_heap, "len")?,
        returned_fd: number_i64(dma_heap, "returned_fd")?.try_into().ok()?,
        fd_flags: number_u32(dma_heap, "fd_flags")?,
        heap_flags: number_u64(dma_heap, "heap_flags")?,
    })
}

fn parse_u32(value: &str) -> Option<u32> {
    let value = value.trim();
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || value.parse().ok(),
            |hex| u32::from_str_radix(hex, 16).ok(),
        )
}

fn replace_text(target: &mut Option<String>, object: &Map<String, Value>, key: &str) {
    if let Some(value) = text(object, key) {
        *target = Some(value.to_string());
    }
}

fn relation(object: &Map<String, Value>) -> Option<CausalRelation> {
    match text(object, "causal_relation") {
        Some("exact") => Some(CausalRelation::Exact),
        Some("inferred") => Some(CausalRelation::Inferred),
        _ => None,
    }
}

fn text<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

fn number_u64(object: &Map<String, Value>, key: &str) -> Option<u64> {
    object.get(key).and_then(Value::as_u64)
}

fn number_u32(object: &Map<String, Value>, key: &str) -> Option<u32> {
    number_u64(object, key).and_then(|value| u32::try_from(value).ok())
}

fn number_i64(object: &Map<String, Value>, key: &str) -> Option<i64> {
    object.get(key).and_then(|value| {
        value
            .as_i64()
            .or_else(|| value.as_u64().and_then(|number| i64::try_from(number).ok()))
    })
}
