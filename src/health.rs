//! Capture-health telemetry.
//!
//! The BPF programs maintain a small per-CPU `COUNTERS` array map that tracks every
//! degraded path (ring drops, INFLIGHT misses, stack-id failures, ...). The
//! userspace loader reads it at exit and prints a structured "capture
//! summary" block so operators know whether absence-of-finding is conclusive.
//!
//! The slot index → label table is the single source of truth for what
//! counters we surface. Adding a new counter means:
//!   1. Reserve a `COUNTER_*` constant in `neutron-common`.
//!   2. Bump it from BPF (or userspace) at the relevant call site.
//!   3. Add it to `COUNTER_LABELS` below.

use std::collections::BTreeSet;

use neutron_common::{
    COUNTER_BINDER_DEPTH_LIMIT, COUNTER_BINDER_FOLLOW_FAILED,
    COUNTER_CAUSAL_ADMISSION_BOUNDARY_EXIT, COUNTER_EVENTS_SUBMITTED,
    COUNTER_INFLIGHT_LOOKUP_MISSED, COUNTER_INFLIGHT_UPDATE_FAILED,
    COUNTER_IOCTL_PAYLOAD_TRUNCATED, COUNTER_IOCTL_REFRESH_MISSED, COUNTER_PATH_READ_FAILED,
    COUNTER_PATH_TRUNCATED, COUNTER_PAYLOAD_READ_FAILED, COUNTER_RINGBUF_RESERVE_FAILED,
    COUNTER_SLOT_COUNT, COUNTER_STACK_KERNEL_FAILED, COUNTER_STACK_USER_FAILED,
    COUNTER_THREAD_CONTEXT_UPDATE_FAILED, COUNTER_TRACED_PROCESS_LIMIT,
    COUNTER_TRACEPOINT_READ_FAILED, COUNTER_UNIX_MSG_CONTROL_NESTED,
    COUNTER_UNIX_MSG_CONTROL_TRUNCATED,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

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
    (
        COUNTER_TRACED_PROCESS_LIMIT,
        "traced process limit",
        CounterKind::Drop,
    ),
    (
        COUNTER_BINDER_DEPTH_LIMIT,
        "binder depth limit",
        CounterKind::Drop,
    ),
    (
        COUNTER_BINDER_FOLLOW_FAILED,
        "binder follow failed",
        CounterKind::Degradation,
    ),
    (
        COUNTER_THREAD_CONTEXT_UPDATE_FAILED,
        "thread context update failed",
        CounterKind::Degradation,
    ),
    (
        COUNTER_CAUSAL_ADMISSION_BOUNDARY_EXIT,
        "causal admission boundary exit",
        CounterKind::Volume,
    ),
    (
        COUNTER_PAYLOAD_READ_FAILED,
        "payload read failed",
        CounterKind::Degradation,
    ),
    (
        COUNTER_TRACEPOINT_READ_FAILED,
        "tracepoint read failed",
        CounterKind::Degradation,
    ),
    (
        COUNTER_IOCTL_PAYLOAD_TRUNCATED,
        "ioctl payload truncated",
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
// Mandatory path-loss slots are wired in BPF. FD graph and symbolization
// health are represented by the richer userspace fields below rather than by
// their legacy reserved BPF slots.
pub const UNSUPPORTED_COUNTERS: &[&str] = &[];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Complete,
    Degraded,
    Incomplete,
    Unknown,
}

impl HealthStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Degraded => "degraded",
            Self::Incomplete => "incomplete",
            Self::Unknown => "unknown",
        }
    }
}

/// Validate the evidence-bearing shape of a final capture-health record.
/// This deliberately rejects legacy/minimal objects as conclusive evidence:
/// missing telemetry and unreadable mandatory counters must become `unknown`.
pub fn capture_health_contract_errors(object: &Map<String, Value>) -> Vec<String> {
    const READABLE_COUNTERS: &[&str] = &[
        "events_submitted",
        "ringbuf_reserve_failed",
        "inflight_update_failed",
        "inflight_lookup_missed",
        "user_stack_failed",
        "kernel_stack_failed",
        "path_read_failed",
        "path_truncated",
        "ioctl_refresh_missed",
        "unix_msg_control_truncated",
        "unix_msg_control_nested",
        "traced_process_limit",
        "binder_depth_limit",
        "binder_follow_failed",
        "thread_context_update_failed",
        "causal_admission_boundary_exit",
        "payload_read_failed",
        "tracepoint_read_failed",
        "ioctl_payload_truncated",
    ];
    const COUNTS: &[&str] = &[
        "events_userspace",
        "fd_graph_miss",
        "fd_graph_backfilled",
        "fd_poller_samples_dropped",
        "fd_poller_shutdown_samples_discarded",
        "fd_poller_sample_channel_errors",
        "fd_poller_active_updates_dropped",
        "fd_poller_active_channel_errors",
        "fd_poller_proc_disappeared",
        "fd_poller_proc_permission_errors",
        "fd_poller_proc_io_errors",
        "fd_poller_proc_parse_errors",
        "fd_poller_proc_truncations",
        "fd_poller_proc_races",
        "fd_poller_pid_reuse",
        "fd_poller_samples_suppressed_read_errors",
        "fd_poller_target_unreadable_polls",
        "fd_poller_scope_read_errors",
        "scenario_inflight_discarded",
        "scenario_context_discarded",
        "scenario_context_baseline_discarded",
        "events_matched",
        "events_sampled_out",
        "events_emitted",
        "follow_policy_filtered",
        "follow_ttl_expired",
        "binder_tracker_evictions",
        "binder_unmatched_receives",
        "binder_causal_metadata_discarded",
        "binder_invalid_callers",
        "binder_baseline_discarded",
        "native_maps_truncated",
        "native_stacks_truncated",
        "native_refresh_failed",
        "logcat_baseline_drains",
        "logcat_baseline_lines_discarded",
        "logcat_baseline_events_discarded",
        "logcat_baseline_pending_discarded",
        "logcat_baseline_errors",
        "logcat_unprimed_drains",
        "logcat_lines_read",
        "logcat_oversized_lines",
        "logcat_eof",
        "logcat_read_errors",
        "logcat_incomplete_correlations",
        "logcat_malformed_correlations",
        "logcat_unsupported_java_fatal",
        "logcat_unsupported_anr",
        "logcat_untrusted_native_exits",
        "selinux_baseline_drains",
        "selinux_baseline_records_discarded",
        "selinux_baseline_pending_discarded",
        "selinux_baseline_errors",
        "selinux_unprimed_drains",
        "selinux_parsed",
        "selinux_malformed",
        "selinux_deduplicated",
        "selinux_out_of_scope",
        "selinux_eof",
        "selinux_read_errors",
        "tombstone_baseline_primes",
        "tombstone_baseline_errors",
        "tombstone_baseline_files",
        "tombstone_unprimed_polls",
        "tombstone_directory_errors",
        "tombstone_directory_entry_errors",
        "tombstone_directory_overflows",
        "tombstone_file_read_errors",
        "tombstone_oversized_files",
        "tombstone_file_identity_races",
        "tombstone_malformed_files",
        "tombstone_unmatched_in_scope",
        "tombstone_out_of_scope",
        "shutdown_events_discarded",
        "max_depth",
        "max_processes",
        "bpf_abi_major",
        "bpf_abi_minor",
        "bpf_feature_bits",
        "ring_size_bytes",
    ];
    const STRING_ARRAYS: &[&str] = &[
        "read_errors",
        "incomplete_reasons",
        "unknown_reasons",
        "unsupported_counters",
        "driver_packs",
        "kprobe_packs",
        "attached_programs",
        "ioctl_refresh_cmds",
        "ioctl_refresh_types",
        "match_packages",
        "match_uids",
        "match_pids",
        "kprobe_attach_failures",
    ];

    let mut errors = Vec::new();
    if object.get("type").and_then(Value::as_str) != Some("capture_health") {
        errors.push("type must be capture_health".into());
    }
    for field in READABLE_COUNTERS {
        match object.get(*field) {
            Some(value) if value.as_u64().is_some() => {}
            Some(Value::Null) => errors.push(format!("mandatory counter {field} is unreadable")),
            Some(_) => errors.push(format!("{field} must be an unsigned integer or null")),
            None => errors.push(format!("missing mandatory counter {field}")),
        }
    }
    for field in COUNTS {
        if object.get(*field).and_then(Value::as_u64).is_none() {
            errors.push(format!("missing or invalid unsigned field {field}"));
        }
    }
    for field in ["output_cap_hit", "binder_tracker_enabled", "degraded"] {
        if object.get(field).and_then(Value::as_bool).is_none() {
            errors.push(format!("missing or invalid boolean field {field}"));
        }
    }
    for field in STRING_ARRAYS {
        match object.get(*field).and_then(Value::as_array) {
            Some(values) if values.iter().all(|value| value.as_str().is_some()) => {}
            _ => errors.push(format!("missing or invalid string array {field}")),
        }
    }
    if object
        .get("unsupported_counters")
        .and_then(Value::as_array)
        .is_some_and(|values| !values.is_empty())
    {
        errors.push("unsupported mandatory counters make health unknown".into());
    }
    if !matches!(
        object.get("status").and_then(Value::as_str),
        Some("complete" | "degraded" | "incomplete" | "unknown")
    ) {
        errors.push("missing or invalid health status".into());
    }
    if !matches!(
        object.get("selinux_avc_source").and_then(Value::as_str),
        Some("disabled" | "available" | "unavailable")
    ) {
        errors.push("missing or invalid selinux_avc_source".into());
    }
    for field in ["logcat_source", "tombstone_source"] {
        if !matches!(
            object.get(field).and_then(Value::as_str),
            Some("disabled" | "available" | "unavailable")
        ) {
            errors.push(format!("missing or invalid {field}"));
        }
    }
    let capture_scope = match object.get("capture_scope") {
        Some(value) => match CaptureScope::from_json_value(value) {
            Ok(scope) => Some(scope),
            Err(error) => {
                errors.push(error);
                None
            }
        },
        None => {
            errors.push("missing capture_scope".into());
            None
        }
    };
    if let Some(scope) = &capture_scope {
        let expected: BTreeSet<_> = scope
            .packs
            .kprobe
            .iter()
            .flat_map(|pack| {
                pack.failures
                    .iter()
                    .map(|failure| format!("{}:{failure}", pack.name))
            })
            .collect();
        let recorded: BTreeSet<_> = object
            .get("kprobe_attach_failures")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        if expected != recorded {
            errors.push("capture_scope kprobe failures do not match kprobe_attach_failures".into());
        }
        if !expected.is_empty() && object.get("status").and_then(Value::as_str) == Some("complete")
        {
            errors.push("requested kprobe attachment failure cannot have complete health".into());
        }
        for (field, expected) in [
            (
                "bpf_object_sha256",
                Value::String(scope.producer.bpf_object_sha256.clone()),
            ),
            (
                "bpf_build_id",
                Value::String(scope.producer.bpf_build_id.clone()),
            ),
            (
                "bpf_feature_bits",
                Value::from(scope.producer.bpf_feature_bits),
            ),
            (
                "driver_packs",
                serde_json::to_value(&scope.packs.driver).expect("string vectors serialize"),
            ),
            (
                "kprobe_packs",
                serde_json::to_value(
                    scope
                        .packs
                        .kprobe
                        .iter()
                        .map(|pack| pack.name.as_str())
                        .collect::<Vec<_>>(),
                )
                .expect("string vectors serialize"),
            ),
            (
                "match_packages",
                serde_json::to_value(&scope.filters.match_packages)
                    .expect("string vectors serialize"),
            ),
            ("max_depth", Value::from(scope.instrumentation.max_depth)),
            (
                "max_processes",
                Value::from(scope.instrumentation.max_processes),
            ),
            (
                "logcat_source",
                Value::String(source_status(
                    scope.sources.logcat_requested,
                    scope.sources.logcat_available,
                )),
            ),
            (
                "selinux_avc_source",
                Value::String(source_status(
                    scope.sources.selinux_logcat_requested,
                    scope.sources.selinux_logcat_available,
                )),
            ),
            (
                "tombstone_source",
                Value::String(source_status(
                    scope.sources.tombstone_requested,
                    scope.sources.tombstone_available,
                )),
            ),
        ] {
            if object.get(field) != Some(&expected) {
                errors.push(format!(
                    "capture_scope does not match top-level capture health field {field}"
                ));
            }
        }
        if !optional_string_field_matches(
            object,
            "root_package",
            scope.observation.root_package.as_deref(),
        ) {
            errors.push("capture_scope does not match top-level root_package".into());
        }
        if !optional_u64_field_matches(
            object,
            "root_uid",
            scope.observation.root_uid.map(u64::from),
        ) {
            errors.push("capture_scope does not match top-level root_uid".into());
        }
        match expected_attached_programs(scope) {
            Some(expected)
                if object.get("attached_programs") == Some(&serde_json::json!(expected)) => {}
            _ => errors.push("capture_scope does not match top-level attached_programs".into()),
        }
    }
    validate_hex_field(object, "bpf_object_sha256", 64, &mut errors);
    validate_hex_field(object, "bpf_build_id", 40, &mut errors);
    if !object
        .get("boot_id")
        .and_then(Value::as_str)
        .is_some_and(valid_boot_id)
    {
        errors.push("missing or invalid boot_id".into());
    }
    for field in ["bpf_object_sha256", "bpf_build_id"] {
        if object
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|value| value.bytes().all(|byte| byte == b'0'))
        {
            errors.push(format!("{field} must not be an all-zero placeholder"));
        }
    }
    if object.get("bpf_event_size").and_then(Value::as_u64)
        != Some(core::mem::size_of::<neutron_common::SyscallEvent>() as u64)
    {
        errors.push("missing or incompatible bpf_event_size".into());
    }
    if object.get("bpf_abi_major").and_then(Value::as_u64)
        != Some(neutron_common::BPF_ABI_MAJOR as u64)
    {
        errors.push("missing or incompatible bpf_abi_major".into());
    }
    if object
        .get("ring_size_bytes")
        .and_then(Value::as_u64)
        .is_some_and(|value| value == 0)
    {
        errors.push("ring_size_bytes must be greater than zero".into());
    }
    if object.get("max_processes").and_then(Value::as_u64) == Some(0) {
        errors.push("max_processes must be greater than zero".into());
    }
    let required_features = neutron_common::BPF_FEATURE_SYSCALL_TRACE
        | neutron_common::BPF_FEATURE_PROCESS_EXIT
        | neutron_common::BPF_FEATURE_PER_CPU_HEALTH;
    if object
        .get("bpf_feature_bits")
        .and_then(Value::as_u64)
        .is_some_and(|bits| bits & required_features != required_features)
    {
        errors.push("bpf_feature_bits omit a mandatory capture capability".into());
    }
    let attached: BTreeSet<&str> = object
        .get("attached_programs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    for required in [
        "trace_sys_enter",
        "trace_sys_exit",
        "trace_sched_process_exit",
    ] {
        if !attached.contains(required) {
            errors.push(format!("attached_programs is missing {required}"));
        }
    }
    let status = object.get("status").and_then(Value::as_str);
    let degraded = object.get("degraded").and_then(Value::as_bool);
    if status == Some("complete") && degraded != Some(false) {
        errors.push("complete health requires degraded=false".into());
    }
    if status.is_some_and(|value| value != "complete") && degraded == Some(false) {
        errors.push("non-complete health requires degraded=true".into());
    }
    if status == Some("complete") && health_record_has_loss(object) {
        errors.push("complete health contradicts recorded loss or uncertainty".into());
    }
    if binder_causal_loss(object)
        && !object
            .get("incomplete_reasons")
            .and_then(Value::as_array)
            .is_some_and(|reasons| !reasons.is_empty())
    {
        errors.push("Binder causal loss requires an explicit incomplete reason".into());
    }
    if status == Some("complete") {
        let submitted = object.get("events_submitted").and_then(Value::as_u64);
        let userspace = object.get("events_userspace").and_then(Value::as_u64);
        let discarded = object
            .get("shutdown_events_discarded")
            .and_then(Value::as_u64);
        if !matches!((submitted, userspace, discarded), (Some(a), Some(b), Some(c)) if a == b.saturating_add(c))
        {
            errors.push(
                "complete health requires events_submitted = events_userspace + shutdown_events_discarded"
                    .into(),
            );
        }
    }
    errors
}

pub fn capture_health_is_complete(object: &Map<String, Value>) -> bool {
    capture_health_contract_errors(object).is_empty()
        && object.get("status").and_then(Value::as_str) == Some("complete")
        && object.get("degraded").and_then(Value::as_bool) == Some(false)
        && object
            .get("capture_scope")
            .and_then(|value| CaptureScope::from_json_value(value).ok())
            .is_some_and(|scope| scope.claim_scope_complete)
}

fn health_record_has_loss(object: &Map<String, Value>) -> bool {
    const NONZERO_IS_LOSS: &[&str] = &[
        "ringbuf_reserve_failed",
        "inflight_update_failed",
        "inflight_lookup_missed",
        "user_stack_failed",
        "kernel_stack_failed",
        "path_read_failed",
        "path_truncated",
        "ioctl_refresh_missed",
        "unix_msg_control_truncated",
        "unix_msg_control_nested",
        "traced_process_limit",
        "binder_depth_limit",
        "binder_follow_failed",
        "thread_context_update_failed",
        "payload_read_failed",
        "tracepoint_read_failed",
        "ioctl_payload_truncated",
        "events_sampled_out",
        "follow_policy_filtered",
        "follow_ttl_expired",
        "binder_tracker_evictions",
        "binder_unmatched_receives",
        "binder_causal_metadata_discarded",
        "binder_invalid_callers",
        "native_maps_truncated",
        "native_stacks_truncated",
        "native_refresh_failed",
        "fd_poller_samples_dropped",
        "fd_poller_shutdown_samples_discarded",
        "fd_poller_sample_channel_errors",
        "fd_poller_active_updates_dropped",
        "fd_poller_active_channel_errors",
        "fd_poller_proc_disappeared",
        "fd_poller_proc_permission_errors",
        "fd_poller_proc_io_errors",
        "fd_poller_proc_parse_errors",
        "fd_poller_proc_truncations",
        "fd_poller_proc_races",
        "fd_poller_pid_reuse",
        "fd_poller_samples_suppressed_read_errors",
        "fd_poller_target_unreadable_polls",
        "fd_poller_scope_read_errors",
        "scenario_inflight_discarded",
        "scenario_context_discarded",
        "logcat_baseline_errors",
        "logcat_unprimed_drains",
        "logcat_oversized_lines",
        "logcat_eof",
        "logcat_read_errors",
        "logcat_incomplete_correlations",
        "logcat_malformed_correlations",
        "logcat_unsupported_java_fatal",
        "logcat_unsupported_anr",
        "logcat_untrusted_native_exits",
        "selinux_malformed",
        "selinux_baseline_errors",
        "selinux_unprimed_drains",
        "selinux_eof",
        "selinux_read_errors",
        "tombstone_baseline_errors",
        "tombstone_unprimed_polls",
        "tombstone_directory_errors",
        "tombstone_directory_entry_errors",
        "tombstone_directory_overflows",
        "tombstone_file_read_errors",
        "tombstone_oversized_files",
        "tombstone_file_identity_races",
        "tombstone_malformed_files",
        "tombstone_unmatched_in_scope",
        "shutdown_events_discarded",
    ];
    NONZERO_IS_LOSS
        .iter()
        .any(|field| object.get(*field).and_then(Value::as_u64).unwrap_or(0) > 0)
        || object.get("output_cap_hit").and_then(Value::as_bool) == Some(true)
        || object
            .get("binder_tracker_enabled")
            .and_then(Value::as_bool)
            == Some(false)
        || object.get("selinux_avc_source").and_then(Value::as_str) == Some("unavailable")
        || object.get("logcat_source").and_then(Value::as_str) == Some("unavailable")
        || object.get("tombstone_source").and_then(Value::as_str) == Some("unavailable")
        || object
            .get("fd_graph_miss")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > object
                .get("fd_graph_backfilled")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        || [
            "read_errors",
            "incomplete_reasons",
            "unknown_reasons",
            "kprobe_attach_failures",
        ]
        .iter()
        .any(|field| {
            object
                .get(*field)
                .and_then(Value::as_array)
                .is_some_and(|values| !values.is_empty())
        })
}

fn binder_causal_loss(object: &Map<String, Value>) -> bool {
    [
        "binder_tracker_evictions",
        "binder_unmatched_receives",
        "binder_causal_metadata_discarded",
        "binder_invalid_callers",
    ]
    .iter()
    .any(|field| object.get(*field).and_then(Value::as_u64).unwrap_or(0) > 0)
        || object
            .get("binder_tracker_enabled")
            .and_then(Value::as_bool)
            == Some(false)
}

fn source_status(requested: bool, available: bool) -> String {
    if !requested {
        "disabled"
    } else if available {
        "available"
    } else {
        "unavailable"
    }
    .into()
}

fn optional_string_field_matches(
    object: &Map<String, Value>,
    field: &str,
    expected: Option<&str>,
) -> bool {
    match expected {
        Some(expected) => object.get(field).and_then(Value::as_str) == Some(expected),
        None => !object.contains_key(field),
    }
}

fn optional_u64_field_matches(
    object: &Map<String, Value>,
    field: &str,
    expected: Option<u64>,
) -> bool {
    match expected {
        Some(expected) => object.get(field).and_then(Value::as_u64) == Some(expected),
        None => !object.contains_key(field),
    }
}

fn expected_attached_programs(scope: &CaptureScope) -> Option<Vec<String>> {
    let mut expected = vec![
        "trace_sys_enter".into(),
        "trace_sys_exit".into(),
        "trace_sched_process_exit".into(),
    ];
    if scope.instrumentation.binder_tracepoints {
        expected.push("trace_binder_transaction".into());
        expected.push("trace_binder_transaction_received".into());
    }
    for source in scope
        .packs
        .kprobe
        .iter()
        .flat_map(|pack| &pack.attached_sources)
    {
        let (program, symbol) = source.split_once('@')?;
        if program.is_empty() || symbol.is_empty() {
            return None;
        }
        expected.push(program.into());
    }
    Some(expected)
}

fn validate_hex_field(
    object: &Map<String, Value>,
    field: &str,
    length: usize,
    errors: &mut Vec<String>,
) {
    let valid = object
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|value| {
            value.len() == length
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        });
    if !valid {
        errors.push(format!("missing or invalid {field}"));
    }
}

fn valid_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'),
        })
}

#[derive(Debug, Clone, Default)]
pub struct CaptureHealth {
    pub slots: [u64; COUNTER_SLOT_COUNT as usize],
    pub read_errors: Vec<String>,
    pub unreadable_slots: Vec<u32>,
}

impl CaptureHealth {
    /// Aggregate every per-CPU slot without turning map errors into zeroes.
    pub fn read(map: &aya::maps::PerCpuArray<&aya::maps::MapData, u64>) -> Self {
        let mut out = Self::default();
        for (idx, slot) in out.slots.iter_mut().enumerate() {
            match map.get(&(idx as u32), 0) {
                Ok(values) => {
                    *slot = values.iter().copied().fold(0_u64, u64::saturating_add);
                }
                Err(error) => {
                    out.unreadable_slots.push(idx as u32);
                    let label = COUNTER_LABELS
                        .iter()
                        .find_map(|(slot, label, _)| (*slot == idx as u32).then_some(*label))
                        .unwrap_or("reserved");
                    out.read_errors
                        .push(format!("counter:{}:{error}", label.replace(' ', "_")));
                }
            }
        }
        out
    }

    pub fn unknown(error: impl Into<String>) -> Self {
        Self {
            read_errors: vec![error.into()],
            unreadable_slots: (0..COUNTER_SLOT_COUNT).collect(),
            ..Self::default()
        }
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

    pub fn is_readable(&self, idx: u32) -> bool {
        !self.unreadable_slots.contains(&idx)
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
    pub fd_poller_samples_dropped: u64,
    pub fd_poller_shutdown_samples_discarded: u64,
    pub fd_poller_sample_channel_errors: u64,
    pub fd_poller_active_updates_dropped: u64,
    pub fd_poller_active_channel_errors: u64,
    pub fd_poller_proc_disappeared: u64,
    pub fd_poller_proc_permission_errors: u64,
    pub fd_poller_proc_io_errors: u64,
    pub fd_poller_proc_parse_errors: u64,
    pub fd_poller_proc_truncations: u64,
    pub fd_poller_proc_races: u64,
    pub fd_poller_pid_reuse: u64,
    pub fd_poller_samples_suppressed_read_errors: u64,
    pub fd_poller_target_unreadable_polls: u64,
    pub fd_poller_scope_read_errors: u64,
    /// Syscall enter state deliberately removed at a scenario boundary.
    pub scenario_inflight_discarded: u64,
    /// Buffered context-window records cleared at a scenario boundary.
    pub scenario_context_discarded: u64,
    pub scenario_context_baseline_discarded: u64,
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
    /// True when `--max-output-size` stopped the primary output stream.
    /// Important because the main NDJSON file may be missing the final
    /// `capture_health` line unless `--health-output` was also used.
    pub output_cap_hit: bool,
    /// Binder branches intentionally bounded by userspace follow guardrails.
    pub follow_policy_filtered: u64,
    pub follow_ttl_expired: u64,
    /// Binder pair/causal records lost inside the userspace correlator.
    pub binder_tracker_evictions: u64,
    pub binder_unmatched_receives: u64,
    pub binder_causal_metadata_discarded: u64,
    pub binder_invalid_callers: u64,
    pub binder_baseline_discarded: u64,
    pub binder_tracker_disabled: bool,
    /// Requested kprobe sources that could not be attached.
    pub kprobe_attach_failures: Vec<String>,
    /// Native map/stack records exceeded a bound or could not be refreshed.
    pub native_capture_degraded: bool,
    pub native_maps_truncated: u64,
    pub native_stacks_truncated: u64,
    pub native_refresh_failed: u64,
    pub logcat_source_enabled: bool,
    pub logcat_source_available: bool,
    pub logcat_baseline_drains: u64,
    pub logcat_baseline_lines_discarded: u64,
    pub logcat_baseline_events_discarded: u64,
    pub logcat_baseline_pending_discarded: u64,
    pub logcat_baseline_errors: u64,
    pub logcat_unprimed_drains: u64,
    pub logcat_lines_read: u64,
    pub logcat_oversized_lines: u64,
    pub logcat_eof: u64,
    pub logcat_read_errors: u64,
    pub logcat_incomplete_correlations: u64,
    pub logcat_malformed_correlations: u64,
    pub logcat_unsupported_java_fatal: u64,
    pub logcat_unsupported_anr: u64,
    /// Native-fatal text that lacked a matching BPF sched-exit event and was
    /// therefore not promoted to authoritative process-exit evidence.
    pub logcat_untrusted_native_exits: u64,
    /// AVC logcat source state and bounded ingestion counters.
    pub selinux_source_enabled: bool,
    pub selinux_source_available: bool,
    pub selinux_baseline_drains: u64,
    pub selinux_baseline_records_discarded: u64,
    pub selinux_baseline_pending_discarded: u64,
    pub selinux_baseline_errors: u64,
    pub selinux_unprimed_drains: u64,
    pub selinux_parsed: u64,
    pub selinux_malformed: u64,
    pub selinux_deduplicated: u64,
    pub selinux_out_of_scope: u64,
    pub selinux_eof: u64,
    pub selinux_read_errors: u64,
    pub tombstone_source_enabled: bool,
    pub tombstone_source_available: bool,
    pub tombstone_baseline_primes: u64,
    pub tombstone_baseline_errors: u64,
    pub tombstone_baseline_files: u64,
    pub tombstone_unprimed_polls: u64,
    pub tombstone_directory_errors: u64,
    pub tombstone_directory_entry_errors: u64,
    pub tombstone_directory_overflows: u64,
    pub tombstone_file_read_errors: u64,
    pub tombstone_oversized_files: u64,
    pub tombstone_file_identity_races: u64,
    pub tombstone_malformed_files: u64,
    pub tombstone_unmatched_in_scope: u64,
    pub tombstone_out_of_scope: u64,
    /// Known reasons the run ended without a complete evidence boundary.
    pub incomplete_reasons: Vec<String>,
    /// Runtime sources whose state could not be established.
    pub unknown_reasons: Vec<String>,
    /// Records drained only after producers detached and therefore not emitted.
    pub shutdown_events_discarded: u64,
}

impl UserspaceHealth {
    fn selinux_degraded(&self) -> bool {
        self.selinux_source_enabled && !self.selinux_source_available
    }
}

fn binder_causal_loss_reasons(user: &UserspaceHealth) -> Vec<String> {
    let mut reasons = Vec::new();
    if user.binder_tracker_evictions > 0 {
        reasons.push(format!(
            "Binder tracker evicted {} in-flight transaction(s) before correlation",
            user.binder_tracker_evictions
        ));
    }
    if user.binder_unmatched_receives > 0 {
        reasons.push(format!(
            "Binder tracker observed {} receive event(s) without a matching caller",
            user.binder_unmatched_receives
        ));
    }
    if user.binder_causal_metadata_discarded > 0 {
        reasons.push(format!(
            "Binder tracker discarded causal metadata for {} transaction(s)",
            user.binder_causal_metadata_discarded
        ));
    }
    if user.binder_invalid_callers > 0 {
        reasons.push(format!(
            "Binder tracker rejected {} caller event(s) with unusable identity",
            user.binder_invalid_callers
        ));
    }
    if user.binder_tracker_disabled {
        reasons.push("Binder transaction correlation was disabled for this capture".into());
    }
    reasons
}

fn kprobe_attachment_reasons(user: &UserspaceHealth) -> impl Iterator<Item = String> + '_ {
    user.kprobe_attach_failures
        .iter()
        .map(|failure| format!("requested kprobe source was not attached: {failure}"))
}

pub fn health_status(health: &CaptureHealth, user: &UserspaceHealth) -> HealthStatus {
    if !health.read_errors.is_empty()
        || !user.unknown_reasons.is_empty()
        || user.logcat_eof > 0
        || user.logcat_read_errors > 0
        || user.selinux_eof > 0
        || user.selinux_read_errors > 0
        || user.selinux_baseline_errors > 0
        || user.selinux_unprimed_drains > 0
        || user.fd_poller_proc_permission_errors > 0
        || user.fd_poller_proc_io_errors > 0
        || user.fd_poller_proc_parse_errors > 0
        || user.fd_poller_proc_truncations > 0
        || user.fd_poller_proc_races > 0
        || user.fd_poller_target_unreadable_polls > 0
        || user.fd_poller_scope_read_errors > 0
        || user.logcat_baseline_errors > 0
        || user.tombstone_directory_errors > 0
        || user.tombstone_baseline_errors > 0
        || user.tombstone_unprimed_polls > 0
        || user.tombstone_file_identity_races > 0
    {
        HealthStatus::Unknown
    } else if user.output_cap_hit
        || user.events_sampled_out > 0
        || user.follow_policy_filtered > 0
        || user.follow_ttl_expired > 0
        || user.binder_tracker_evictions > 0
        || user.binder_unmatched_receives > 0
        || user.binder_causal_metadata_discarded > 0
        || user.binder_invalid_callers > 0
        || user.binder_tracker_disabled
        || !user.kprobe_attach_failures.is_empty()
        || !user.incomplete_reasons.is_empty()
        || user.shutdown_events_discarded > 0
        || user.fd_poller_samples_dropped > 0
        || user.fd_poller_shutdown_samples_discarded > 0
        || user.fd_poller_sample_channel_errors > 0
        || user.fd_poller_active_updates_dropped > 0
        || user.fd_poller_active_channel_errors > 0
        || user.fd_poller_proc_disappeared > 0
        || user.fd_poller_pid_reuse > 0
        || user.fd_poller_samples_suppressed_read_errors > 0
        || user.scenario_inflight_discarded > 0
        || user.scenario_context_discarded > 0
        || user.logcat_oversized_lines > 0
        || user.logcat_unprimed_drains > 0
        || user.logcat_incomplete_correlations > 0
        || user.logcat_malformed_correlations > 0
        || user.logcat_unsupported_java_fatal > 0
        || user.logcat_unsupported_anr > 0
        || user.logcat_untrusted_native_exits > 0
        || user.tombstone_directory_entry_errors > 0
        || user.tombstone_directory_overflows > 0
        || user.tombstone_file_read_errors > 0
        || user.tombstone_oversized_files > 0
        || user.tombstone_malformed_files > 0
        || user.tombstone_unmatched_in_scope > 0
        || (user.logcat_source_enabled && !user.logcat_source_available)
        || (user.tombstone_source_enabled && !user.tombstone_source_available)
    {
        HealthStatus::Incomplete
    } else if health.has_degradation()
        || user.native_capture_degraded
        || user.selinux_degraded()
        || user.selinux_malformed > 0
        || user.fd_graph_miss > user.fd_graph_backfilled
    {
        HealthStatus::Degraded
    } else {
        HealthStatus::Complete
    }
}

pub const CAPTURE_SCOPE_SCHEMA: &str = "neutron.capture-scope/v1";

/// Effective observation and output boundary for one capture. Transport
/// health and claim scope are deliberately separate: a filtered capture can
/// be delivered without loss while still being unsuitable for an unfiltered
/// negative claim. `claim_scope_complete` never implies reachability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureScope {
    pub schema: String,
    pub output: CaptureOutputScope,
    pub observation: CaptureObservationScope,
    pub filters: CaptureFilterScope,
    pub sampling: CaptureSamplingScope,
    pub instrumentation: CaptureInstrumentationScope,
    pub packs: CapturePackScope,
    pub sources: CaptureSourceScope,
    pub findings: CaptureFindingScope,
    pub enrichment: CaptureEnrichmentScope,
    pub producer: CaptureProducerScope,
    pub claim_scope_complete: bool,
    pub claim_scope_reasons: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureOutputScope {
    pub event_mode: String,
    pub serialization: String,
    pub capture_mode: String,
    pub context_duration_ns: Option<u64>,
    pub destination: String,
    pub max_output_bytes: Option<u64>,
    pub rotate_output_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureObservationScope {
    pub target_pid: u32,
    pub root_package: Option<String>,
    pub root_uid: Option<u32>,
    pub follow_children: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureFilterScope {
    pub bpf: Vec<String>,
    pub userspace: Vec<String>,
    pub exclude_comm: Vec<String>,
    pub match_expression: Option<String>,
    pub match_packages: Vec<String>,
    pub match_android_providers: Vec<String>,
    pub alert_rwx_only: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureSamplingScope {
    pub probability: f64,
    pub rate_limit_per_second: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureInstrumentationScope {
    pub binder_tracepoints: bool,
    pub binder_correlation: bool,
    pub causal_follow: bool,
    pub follow_services: bool,
    pub follow_hal: bool,
    pub stacks: bool,
    pub capture_reads: bool,
    pub resolve_paths: bool,
    pub max_depth: u8,
    pub max_processes: u32,
    pub follow_ttl_ns: u64,
    pub follow_allow_domains: Vec<String>,
    pub follow_deny_domains: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturePackScope {
    pub driver: Vec<String>,
    pub kprobe: Vec<KprobePackScope>,
    pub schema: Vec<String>,
    pub schema_identities: Vec<CaptureContentIdentity>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureContentIdentity {
    pub name: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureSourceScope {
    pub fdgraph_enabled: bool,
    pub fdgraph_interval: String,
    pub fdgraph_pid_scope: String,
    pub fdgraph_thresholds: String,
    pub fdgraph_top_paths_n: usize,
    pub logcat_requested: bool,
    pub logcat_available: bool,
    pub selinux_logcat_requested: bool,
    pub selinux_logcat_available: bool,
    pub tombstone_requested: bool,
    pub tombstone_available: bool,
    pub tombstone_dir: Option<String>,
    pub lookback_events: usize,
    pub binder_inflight_capacity: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureFindingScope {
    pub enabled: bool,
    pub rules_sha256: Option<String>,
    pub drain_interval: u64,
    pub raw_window: usize,
    pub fd_snapshot_on_finding: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureEnrichmentScope {
    pub binder_services_sha256: Option<String>,
    pub binder_methods_sha256: Option<String>,
    pub aidl_catalog_sha256: Option<String>,
    pub dynamic_service_inventory_sha256: Option<String>,
    pub dynamic_hal_inventory_sha256: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureProducerScope {
    pub bpf_object_sha256: String,
    pub bpf_build_id: String,
    pub bpf_feature_bits: u64,
    pub userspace_binary_sha256: String,
    pub userspace_version: String,
    pub userspace_git_commit: String,
    pub userspace_git_dirty: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KprobePackScope {
    pub name: String,
    pub requested_sources: Vec<String>,
    pub attached_sources: Vec<String>,
    pub failures: Vec<String>,
}

impl CaptureScope {
    /// Minimal complete scope used by producers and contract fixtures.
    pub fn unfiltered_raw_ndjson() -> Self {
        Self {
            schema: CAPTURE_SCOPE_SCHEMA.into(),
            output: CaptureOutputScope {
                event_mode: "raw_only".into(),
                serialization: "ndjson".into(),
                capture_mode: "matched".into(),
                context_duration_ns: None,
                destination: "stdout".into(),
                max_output_bytes: None,
                rotate_output_bytes: None,
            },
            observation: CaptureObservationScope::default(),
            filters: CaptureFilterScope::default(),
            sampling: CaptureSamplingScope {
                probability: 1.0,
                rate_limit_per_second: None,
            },
            instrumentation: CaptureInstrumentationScope {
                max_depth: 4,
                max_processes: 64,
                follow_ttl_ns: 30_000_000_000,
                ..CaptureInstrumentationScope::default()
            },
            packs: CapturePackScope::default(),
            sources: CaptureSourceScope {
                fdgraph_enabled: false,
                fdgraph_interval: "1s".into(),
                fdgraph_pid_scope: "active".into(),
                fdgraph_thresholds: "1024,8192,90%".into(),
                logcat_requested: false,
                logcat_available: false,
                selinux_logcat_requested: false,
                selinux_logcat_available: false,
                tombstone_requested: false,
                tombstone_available: false,
                tombstone_dir: None,
                lookback_events: 100,
                binder_inflight_capacity: 1024,
                ..CaptureSourceScope::default()
            },
            findings: CaptureFindingScope {
                drain_interval: 256,
                ..CaptureFindingScope::default()
            },
            enrichment: CaptureEnrichmentScope::default(),
            producer: CaptureProducerScope {
                bpf_object_sha256: "1".repeat(64),
                bpf_build_id: "2".repeat(40),
                bpf_feature_bits: neutron_common::BPF_FEATURE_SYSCALL_TRACE
                    | neutron_common::BPF_FEATURE_PROCESS_EXIT
                    | neutron_common::BPF_FEATURE_PER_CPU_HEALTH,
                userspace_binary_sha256: "3".repeat(64),
                userspace_version: "1.5.0-rc.1".into(),
                userspace_git_commit: "2".repeat(40),
                userspace_git_dirty: false,
            },
            claim_scope_complete: true,
            claim_scope_reasons: Vec::new(),
        }
    }

    pub fn recompute_claim_scope(mut self) -> Self {
        self.claim_scope_reasons = self.expected_claim_scope_reasons();
        self.claim_scope_complete = self.claim_scope_reasons.is_empty();
        self
    }

    pub fn from_json_value(value: &Value) -> Result<Self, String> {
        validate_capture_scope_shape(value)?;
        let scope: Self = serde_json::from_value(value.clone())
            .map_err(|error| format!("invalid capture_scope: {error}"))?;
        let errors = scope.validation_errors();
        if errors.is_empty() {
            Ok(scope)
        } else {
            Err(errors.join("; "))
        }
    }

    fn validation_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.schema != CAPTURE_SCOPE_SCHEMA {
            errors.push(format!(
                "capture_scope.schema must be {CAPTURE_SCOPE_SCHEMA}"
            ));
        }
        if !matches!(
            self.output.event_mode.as_str(),
            "raw_only" | "raw_and_findings" | "findings_only"
        ) {
            errors.push("capture_scope.output.event_mode is invalid".into());
        }
        if !matches!(self.output.serialization.as_str(), "ndjson" | "text") {
            errors.push("capture_scope.output.serialization is invalid".into());
        }
        if !matches!(self.output.destination.as_str(), "stdout" | "file") {
            errors.push("capture_scope.output.destination is invalid".into());
        }
        match (
            self.output.capture_mode.as_str(),
            self.output.context_duration_ns,
        ) {
            ("matched", None) | ("matched_with_context", Some(1..)) => {}
            _ => errors.push(
                "capture_scope.output capture_mode/context_duration_ns are inconsistent".into(),
            ),
        }
        if self.output.max_output_bytes.is_some_and(|value| value == 0)
            || self
                .output
                .rotate_output_bytes
                .is_some_and(|value| value == 0)
        {
            errors.push("capture_scope output bounds must be greater than zero".into());
        }
        if self.output.max_output_bytes.is_some() && self.output.rotate_output_bytes.is_some() {
            errors.push("capture_scope output cap and rotation are mutually exclusive".into());
        }
        if !self.sampling.probability.is_finite()
            || !(0.0..=1.0).contains(&self.sampling.probability)
        {
            errors.push("capture_scope sampling probability must be within 0..=1".into());
        }
        if self
            .sampling
            .rate_limit_per_second
            .is_some_and(|value| value == 0)
        {
            errors.push("capture_scope rate limit must be greater than zero".into());
        }
        if self.instrumentation.max_processes == 0 {
            errors.push("capture_scope max_processes must be greater than zero".into());
        }
        if self.instrumentation.causal_follow && !self.instrumentation.binder_tracepoints {
            errors.push("capture_scope causal_follow requires Binder tracepoints".into());
        }
        if (self.instrumentation.follow_services || self.instrumentation.follow_hal)
            && !self.instrumentation.causal_follow
        {
            errors.push("capture_scope service/HAL follow requires causal_follow".into());
        }
        for (label, values) in [
            ("filters.bpf", self.filters.bpf.as_slice()),
            ("filters.userspace", self.filters.userspace.as_slice()),
            ("filters.exclude_comm", self.filters.exclude_comm.as_slice()),
            (
                "filters.match_packages",
                self.filters.match_packages.as_slice(),
            ),
            (
                "filters.match_android_providers",
                self.filters.match_android_providers.as_slice(),
            ),
            (
                "instrumentation.follow_allow_domains",
                self.instrumentation.follow_allow_domains.as_slice(),
            ),
            (
                "instrumentation.follow_deny_domains",
                self.instrumentation.follow_deny_domains.as_slice(),
            ),
            ("packs.driver", self.packs.driver.as_slice()),
            ("packs.schema", self.packs.schema.as_slice()),
        ] {
            if values.iter().any(|value| value.trim().is_empty()) {
                errors.push(format!("capture_scope.{label} contains an empty value"));
            }
        }
        for pack in &self.packs.kprobe {
            if pack.name.trim().is_empty()
                || pack.requested_sources.is_empty()
                || pack
                    .requested_sources
                    .iter()
                    .chain(&pack.attached_sources)
                    .chain(&pack.failures)
                    .any(|value| value.trim().is_empty())
            {
                errors.push("capture_scope.packs.kprobe contains invalid source status".into());
            }
            if pack
                .attached_sources
                .iter()
                .any(|source| !pack.requested_sources.contains(source))
            {
                errors.push("capture_scope attached an unrequested kprobe source".into());
            }
        }
        if expected_attached_programs(self).is_none() {
            errors.push("capture_scope has an invalid attached kprobe source".into());
        }
        if self.packs.schema.len() != self.packs.schema_identities.len()
            || self
                .packs
                .schema
                .iter()
                .zip(&self.packs.schema_identities)
                .any(|(name, identity)| name != &identity.name)
        {
            errors.push("capture_scope schema pack names and identities differ".into());
        }
        for identity in &self.packs.schema_identities {
            if identity.name.trim().is_empty() || !valid_lower_hex(&identity.sha256, 64) {
                errors.push("capture_scope schema pack identity is invalid".into());
            }
        }
        if self.sources.fdgraph_interval.trim().is_empty()
            || self.sources.fdgraph_pid_scope.trim().is_empty()
            || self.sources.fdgraph_thresholds.trim().is_empty()
            || self
                .sources
                .tombstone_dir
                .as_deref()
                .is_some_and(str::is_empty)
        {
            errors.push("capture_scope source configuration contains an empty value".into());
        }
        if self.findings.drain_interval == 0
            || self.findings.enabled != self.findings.rules_sha256.is_some()
            || self
                .findings
                .rules_sha256
                .as_deref()
                .is_some_and(|value| !valid_lower_hex(value, 64))
        {
            errors.push("capture_scope findings rules identity is inconsistent".into());
        }
        for (name, value) in [
            (
                "binder_services_sha256",
                self.enrichment.binder_services_sha256.as_deref(),
            ),
            (
                "binder_methods_sha256",
                self.enrichment.binder_methods_sha256.as_deref(),
            ),
            (
                "aidl_catalog_sha256",
                self.enrichment.aidl_catalog_sha256.as_deref(),
            ),
            (
                "dynamic_service_inventory_sha256",
                self.enrichment.dynamic_service_inventory_sha256.as_deref(),
            ),
            (
                "dynamic_hal_inventory_sha256",
                self.enrichment.dynamic_hal_inventory_sha256.as_deref(),
            ),
        ] {
            if value.is_some_and(|value| !valid_lower_hex(value, 64)) {
                errors.push(format!("capture_scope enrichment {name} is invalid"));
            }
        }
        if !valid_lower_hex(&self.producer.bpf_object_sha256, 64)
            || !valid_lower_hex(&self.producer.bpf_build_id, 40)
            || self.producer.bpf_feature_bits == 0
            || !valid_lower_hex(&self.producer.userspace_binary_sha256, 64)
            || self.producer.userspace_version.trim().is_empty()
            || !valid_lower_hex(&self.producer.userspace_git_commit, 40)
        {
            errors.push("capture_scope producer identity is invalid".into());
        }
        if self.producer.bpf_build_id != self.producer.userspace_git_commit {
            errors.push("capture_scope BPF and userspace source commits differ".into());
        }
        if self.instrumentation.binder_tracepoints
            && self.producer.bpf_feature_bits & neutron_common::BPF_FEATURE_BINDER_TRACE == 0
        {
            errors.push("capture_scope Binder tracepoints lack the BPF feature".into());
        }
        if self.instrumentation.stacks
            && self.producer.bpf_feature_bits & neutron_common::BPF_FEATURE_STACKS == 0
        {
            errors.push("capture_scope stacks lack the BPF feature".into());
        }
        if (!self.sources.logcat_requested && self.sources.logcat_available)
            || (!self.sources.selinux_logcat_requested && self.sources.selinux_logcat_available)
            || (!self.sources.tombstone_requested && self.sources.tombstone_available)
        {
            errors.push("capture_scope source is available without being requested".into());
        }
        if self
            .filters
            .match_expression
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            errors.push("capture_scope.filters.match_expression is empty".into());
        }
        let expected = self.expected_claim_scope_reasons();
        if self.claim_scope_reasons != expected || self.claim_scope_complete != expected.is_empty()
        {
            errors.push(
                "capture_scope claim_scope_complete/reasons contradict effective scope".into(),
            );
        }
        errors
    }

    fn expected_claim_scope_reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if self.output.event_mode == "findings_only" {
            reasons.push("findings_only_output".into());
        }
        if self.output.serialization != "ndjson" {
            reasons.push("non_ndjson_event_output".into());
        }
        if !self.filters.bpf.is_empty() {
            reasons.push("bpf_filters".into());
        }
        if !self.filters.userspace.is_empty() {
            reasons.push("userspace_filters".into());
        }
        if !self.filters.exclude_comm.is_empty() {
            reasons.push("excluded_commands".into());
        }
        if self.filters.match_expression.is_some() {
            reasons.push("match_expression".into());
        }
        if self.filters.alert_rwx_only {
            reasons.push("alert_rwx_filter".into());
        }
        if self.instrumentation.capture_reads {
            reasons.push("read_content_capture_unsupported".into());
        }
        if self.observation.follow_children {
            reasons.push("follow_children_clone3_unsupported".into());
        }
        if !self.instrumentation.follow_allow_domains.is_empty()
            || !self.instrumentation.follow_deny_domains.is_empty()
        {
            reasons.push("binder_follow_domain_filter".into());
        }
        if self.sources.logcat_requested {
            reasons.push("logcat_gap_accounting_unavailable".into());
            if !self.sources.logcat_available {
                reasons.push("logcat_source_unavailable".into());
            }
        }
        if self.sources.selinux_logcat_requested {
            reasons.push("selinux_logcat_gap_accounting_unavailable".into());
            if !self.sources.selinux_logcat_available {
                reasons.push("selinux_source_unavailable".into());
            }
        }
        if self.sources.tombstone_requested {
            reasons.push("tombstone_polling_gap_possible".into());
            if !self.sources.tombstone_available {
                reasons.push("tombstone_source_unavailable".into());
            }
        }
        if self.sampling.probability < 1.0 {
            reasons.push("probabilistic_sampling".into());
        }
        if self.sampling.rate_limit_per_second.is_some() {
            reasons.push("rate_limit".into());
        }
        if self.producer.userspace_git_dirty {
            reasons.push("userspace_source_dirty".into());
        }
        if self
            .packs
            .kprobe
            .iter()
            .any(|pack| !pack.failures.is_empty())
        {
            reasons.push("kprobe_attachment_failure".into());
        }
        reasons
    }
}

fn validate_capture_scope_shape(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "capture_scope must be an object".to_string())?;
    require_fields(
        object,
        "capture_scope",
        &[
            "schema",
            "output",
            "observation",
            "filters",
            "sampling",
            "instrumentation",
            "packs",
            "sources",
            "findings",
            "enrichment",
            "producer",
            "claim_scope_complete",
            "claim_scope_reasons",
        ],
    )?;
    for (name, fields) in [
        (
            "output",
            &[
                "event_mode",
                "serialization",
                "capture_mode",
                "context_duration_ns",
                "destination",
                "max_output_bytes",
                "rotate_output_bytes",
            ][..],
        ),
        (
            "observation",
            &["target_pid", "root_package", "root_uid", "follow_children"][..],
        ),
        (
            "filters",
            &[
                "bpf",
                "userspace",
                "exclude_comm",
                "match_expression",
                "match_packages",
                "match_android_providers",
                "alert_rwx_only",
            ][..],
        ),
        ("sampling", &["probability", "rate_limit_per_second"][..]),
        (
            "instrumentation",
            &[
                "binder_tracepoints",
                "binder_correlation",
                "causal_follow",
                "follow_services",
                "follow_hal",
                "stacks",
                "capture_reads",
                "resolve_paths",
                "max_depth",
                "max_processes",
                "follow_ttl_ns",
                "follow_allow_domains",
                "follow_deny_domains",
            ][..],
        ),
        (
            "packs",
            &["driver", "kprobe", "schema", "schema_identities"][..],
        ),
        (
            "sources",
            &[
                "fdgraph_enabled",
                "fdgraph_interval",
                "fdgraph_pid_scope",
                "fdgraph_thresholds",
                "fdgraph_top_paths_n",
                "logcat_requested",
                "logcat_available",
                "selinux_logcat_requested",
                "selinux_logcat_available",
                "tombstone_requested",
                "tombstone_available",
                "tombstone_dir",
                "lookback_events",
                "binder_inflight_capacity",
            ][..],
        ),
        (
            "findings",
            &[
                "enabled",
                "rules_sha256",
                "drain_interval",
                "raw_window",
                "fd_snapshot_on_finding",
            ][..],
        ),
        (
            "enrichment",
            &[
                "binder_services_sha256",
                "binder_methods_sha256",
                "aidl_catalog_sha256",
                "dynamic_service_inventory_sha256",
                "dynamic_hal_inventory_sha256",
            ][..],
        ),
        (
            "producer",
            &[
                "bpf_object_sha256",
                "bpf_build_id",
                "bpf_feature_bits",
                "userspace_binary_sha256",
                "userspace_version",
                "userspace_git_commit",
                "userspace_git_dirty",
            ][..],
        ),
    ] {
        let nested = object
            .get(name)
            .and_then(Value::as_object)
            .ok_or_else(|| format!("capture_scope.{name} must be an object"))?;
        require_fields(nested, &format!("capture_scope.{name}"), fields)?;
    }
    Ok(())
}

fn require_fields(object: &Map<String, Value>, label: &str, fields: &[&str]) -> Result<(), String> {
    let missing: Vec<_> = fields
        .iter()
        .copied()
        .filter(|field| !object.contains_key(*field))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("{label} is missing {}", missing.join(", ")))
    }
}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value.bytes().any(|byte| byte != b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Static capture configuration surfaced in the shutdown health event.
#[derive(Debug, Clone, Default)]
pub struct CaptureMetadata {
    pub capture_scope: Option<CaptureScope>,
    pub driver_packs: Vec<String>,
    pub kprobe_packs: Vec<String>,
    pub attached_programs: Vec<String>,
    pub ioctl_refresh_cmds: Vec<u32>,
    pub ioctl_refresh_types: Vec<u32>,
    pub match_packages: Vec<String>,
    pub match_uids: Vec<String>,
    pub match_pids: Vec<String>,
    pub root_package: Option<String>,
    pub root_uid: Option<u32>,
    pub boot_id: Option<String>,
    pub fingerprint: Option<String>,
    pub max_depth: u8,
    pub max_processes: u32,
    pub bpf_object_sha256: Option<String>,
    pub bpf_build_id: Option<String>,
    pub bpf_abi_major: Option<u16>,
    pub bpf_abi_minor: Option<u16>,
    pub bpf_event_size: Option<u32>,
    pub bpf_feature_bits: Option<u64>,
    pub ring_size_bytes: Option<u64>,
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
    let status = health_status(health, user);
    let mut incomplete_reasons = user.incomplete_reasons.clone();
    incomplete_reasons.extend(binder_causal_loss_reasons(user));
    incomplete_reasons.extend(kprobe_attachment_reasons(user));
    let mut out = String::new();
    out.push_str("\nCapture summary:\n");
    out.push_str(&format!("  status: {}\n", status.as_str()));
    out.push_str(&format!(
        "  events processed (userspace): {total_userspace_events}\n"
    ));
    for (idx, label, _) in COUNTER_LABELS {
        if health.is_readable(*idx) {
            out.push_str(&format!("  {label}: {}\n", health.get(*idx)));
        } else {
            out.push_str(&format!("  {label}: unknown\n"));
        }
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
    if user.output_cap_hit {
        out.push_str("  output cap hit: true\n");
    }
    if user.shutdown_events_discarded > 0 {
        out.push_str(&format!(
            "  shutdown drain discarded: {}\n",
            user.shutdown_events_discarded
        ));
    }
    for error in &health.read_errors {
        out.push_str(&format!("  health read error: {error}\n"));
    }
    for reason in &incomplete_reasons {
        out.push_str(&format!("  incomplete: {reason}\n"));
    }
    for reason in &user.unknown_reasons {
        out.push_str(&format!("  unknown: {reason}\n"));
    }
    if user.follow_policy_filtered > 0 || user.follow_ttl_expired > 0 {
        out.push_str(&format!(
            "  binder follow guardrails: policy-filtered={} ttl-expired={}\n",
            user.follow_policy_filtered, user.follow_ttl_expired
        ));
    }
    if user.binder_tracker_evictions > 0
        || user.binder_unmatched_receives > 0
        || user.binder_causal_metadata_discarded > 0
        || user.binder_invalid_callers > 0
        || user.binder_tracker_disabled
    {
        out.push_str(&format!(
            "  binder correlator: enabled={} evicted={} unmatched-receives={} causal-metadata-discarded={} invalid-callers={}\n",
            !user.binder_tracker_disabled,
            user.binder_tracker_evictions,
            user.binder_unmatched_receives,
            user.binder_causal_metadata_discarded,
            user.binder_invalid_callers,
        ));
    }
    if user.native_capture_degraded {
        out.push_str(&format!(
            "  native capture: {} map/path truncation(s), {} stack truncation(s), {} refresh failure(s)\n",
            user.native_maps_truncated,
            user.native_stacks_truncated,
            user.native_refresh_failed,
        ));
    }
    if user.selinux_source_enabled {
        let status = if user.selinux_source_available {
            "available"
        } else {
            "unavailable"
        };
        out.push_str(&format!(
            "  selinux AVC source: {status}; parsed={} malformed={} deduplicated={} out-of-scope={}\n",
            user.selinux_parsed,
            user.selinux_malformed,
            user.selinux_deduplicated,
            user.selinux_out_of_scope,
        ));
    }
    if status != HealthStatus::Complete {
        out.push_str(
            "\nWARNING: capture health is not complete. Absence of a finding is NOT conclusive.\n\
             Re-run with a smaller scope and require status=complete\n\
             before drawing a negative conclusion.\n",
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
    let mut effective_user = user.clone();
    effective_user
        .incomplete_reasons
        .extend(binder_causal_loss_reasons(user));
    effective_user
        .incomplete_reasons
        .extend(kprobe_attachment_reasons(user));
    effective_user
        .unknown_reasons
        .extend(capture_metadata_errors(meta, user));
    if health.is_readable(COUNTER_EVENTS_SUBMITTED) {
        let submitted = health.get(COUNTER_EVENTS_SUBMITTED);
        let accounted = total_userspace_events.saturating_add(user.shutdown_events_discarded);
        if submitted != accounted {
            effective_user.incomplete_reasons.push(format!(
                "event reconciliation mismatch: submitted={submitted} accounted={accounted}"
            ));
        }
    }
    let status = health_status(health, &effective_user);
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
        if health.is_readable(*idx) {
            let _ = write!(s, r#","{key}":{}"#, health.get(*idx));
        } else {
            let _ = write!(s, r#","{key}":null"#);
        }
    }
    let _ = write!(
        s,
        r#","fd_graph_miss":{},"fd_graph_backfilled":{},"events_matched":{},"events_sampled_out":{},"events_emitted":{},"output_cap_hit":{},"follow_policy_filtered":{},"follow_ttl_expired":{},"binder_tracker_evictions":{},"binder_unmatched_receives":{},"binder_causal_metadata_discarded":{},"binder_invalid_callers":{},"binder_baseline_discarded":{},"binder_tracker_enabled":{},"native_maps_truncated":{},"native_stacks_truncated":{},"native_refresh_failed":{},"selinux_avc_source":"{}","selinux_baseline_drains":{},"selinux_baseline_records_discarded":{},"selinux_baseline_pending_discarded":{},"selinux_baseline_errors":{},"selinux_unprimed_drains":{},"selinux_parsed":{},"selinux_malformed":{},"selinux_deduplicated":{},"selinux_out_of_scope":{},"shutdown_events_discarded":{},"status":"{}","degraded":{}"#,
        user.fd_graph_miss,
        user.fd_graph_backfilled,
        user.events_matched,
        user.events_sampled_out,
        user.events_emitted,
        user.output_cap_hit,
        user.follow_policy_filtered,
        user.follow_ttl_expired,
        user.binder_tracker_evictions,
        user.binder_unmatched_receives,
        user.binder_causal_metadata_discarded,
        user.binder_invalid_callers,
        user.binder_baseline_discarded,
        !user.binder_tracker_disabled,
        user.native_maps_truncated,
        user.native_stacks_truncated,
        user.native_refresh_failed,
        if !user.selinux_source_enabled {
            "disabled"
        } else if user.selinux_source_available {
            "available"
        } else {
            "unavailable"
        },
        user.selinux_baseline_drains,
        user.selinux_baseline_records_discarded,
        user.selinux_baseline_pending_discarded,
        user.selinux_baseline_errors,
        user.selinux_unprimed_drains,
        user.selinux_parsed,
        user.selinux_malformed,
        user.selinux_deduplicated,
        user.selinux_out_of_scope,
        user.shutdown_events_discarded,
        status.as_str(),
        status != HealthStatus::Complete,
    );
    let logcat_source = if !user.logcat_source_enabled {
        "disabled"
    } else if user.logcat_source_available {
        "available"
    } else {
        "unavailable"
    };
    let tombstone_source = if !user.tombstone_source_enabled {
        "disabled"
    } else if user.tombstone_source_available {
        "available"
    } else {
        "unavailable"
    };
    let _ = write!(
        s,
        r#","fd_poller_samples_dropped":{},"fd_poller_shutdown_samples_discarded":{},"fd_poller_sample_channel_errors":{},"fd_poller_active_updates_dropped":{},"fd_poller_active_channel_errors":{},"fd_poller_proc_disappeared":{},"fd_poller_proc_permission_errors":{},"fd_poller_proc_io_errors":{},"fd_poller_proc_parse_errors":{},"fd_poller_proc_truncations":{},"fd_poller_proc_races":{},"fd_poller_pid_reuse":{},"fd_poller_samples_suppressed_read_errors":{},"fd_poller_target_unreadable_polls":{},"fd_poller_scope_read_errors":{},"scenario_inflight_discarded":{},"scenario_context_discarded":{},"scenario_context_baseline_discarded":{},"logcat_source":"{}","logcat_baseline_drains":{},"logcat_baseline_lines_discarded":{},"logcat_baseline_events_discarded":{},"logcat_baseline_pending_discarded":{},"logcat_baseline_errors":{},"logcat_unprimed_drains":{},"logcat_lines_read":{},"logcat_oversized_lines":{},"logcat_eof":{},"logcat_read_errors":{},"logcat_incomplete_correlations":{},"logcat_malformed_correlations":{},"logcat_unsupported_java_fatal":{},"logcat_unsupported_anr":{},"logcat_untrusted_native_exits":{},"selinux_eof":{},"selinux_read_errors":{},"tombstone_source":"{}","tombstone_baseline_primes":{},"tombstone_baseline_errors":{},"tombstone_baseline_files":{},"tombstone_unprimed_polls":{},"tombstone_directory_errors":{},"tombstone_directory_entry_errors":{},"tombstone_directory_overflows":{},"tombstone_file_read_errors":{},"tombstone_oversized_files":{},"tombstone_file_identity_races":{},"tombstone_malformed_files":{},"tombstone_unmatched_in_scope":{},"tombstone_out_of_scope":{}"#,
        user.fd_poller_samples_dropped,
        user.fd_poller_shutdown_samples_discarded,
        user.fd_poller_sample_channel_errors,
        user.fd_poller_active_updates_dropped,
        user.fd_poller_active_channel_errors,
        user.fd_poller_proc_disappeared,
        user.fd_poller_proc_permission_errors,
        user.fd_poller_proc_io_errors,
        user.fd_poller_proc_parse_errors,
        user.fd_poller_proc_truncations,
        user.fd_poller_proc_races,
        user.fd_poller_pid_reuse,
        user.fd_poller_samples_suppressed_read_errors,
        user.fd_poller_target_unreadable_polls,
        user.fd_poller_scope_read_errors,
        user.scenario_inflight_discarded,
        user.scenario_context_discarded,
        user.scenario_context_baseline_discarded,
        logcat_source,
        user.logcat_baseline_drains,
        user.logcat_baseline_lines_discarded,
        user.logcat_baseline_events_discarded,
        user.logcat_baseline_pending_discarded,
        user.logcat_baseline_errors,
        user.logcat_unprimed_drains,
        user.logcat_lines_read,
        user.logcat_oversized_lines,
        user.logcat_eof,
        user.logcat_read_errors,
        user.logcat_incomplete_correlations,
        user.logcat_malformed_correlations,
        user.logcat_unsupported_java_fatal,
        user.logcat_unsupported_anr,
        user.logcat_untrusted_native_exits,
        user.selinux_eof,
        user.selinux_read_errors,
        tombstone_source,
        user.tombstone_baseline_primes,
        user.tombstone_baseline_errors,
        user.tombstone_baseline_files,
        user.tombstone_unprimed_polls,
        user.tombstone_directory_errors,
        user.tombstone_directory_entry_errors,
        user.tombstone_directory_overflows,
        user.tombstone_file_read_errors,
        user.tombstone_oversized_files,
        user.tombstone_file_identity_races,
        user.tombstone_malformed_files,
        user.tombstone_unmatched_in_scope,
        user.tombstone_out_of_scope,
    );
    write_string_array(&mut s, "read_errors", &health.read_errors);
    write_string_array(
        &mut s,
        "incomplete_reasons",
        &effective_user.incomplete_reasons,
    );
    write_string_array(&mut s, "unknown_reasons", &effective_user.unknown_reasons);
    let unsupported: Vec<_> = UNSUPPORTED_COUNTERS
        .iter()
        .map(|value| (*value).to_string())
        .collect();
    write_string_array(&mut s, "unsupported_counters", &unsupported);
    write_string_array(&mut s, "driver_packs", &meta.driver_packs);
    write_string_array(&mut s, "kprobe_packs", &meta.kprobe_packs);
    write_string_array(&mut s, "attached_programs", &meta.attached_programs);
    write_u32_array_hex(&mut s, "ioctl_refresh_cmds", &meta.ioctl_refresh_cmds);
    write_u32_array_hex(&mut s, "ioctl_refresh_types", &meta.ioctl_refresh_types);
    write_string_array(&mut s, "match_packages", &meta.match_packages);
    write_string_array(&mut s, "match_uids", &meta.match_uids);
    write_string_array(&mut s, "match_pids", &meta.match_pids);
    write_string_array(
        &mut s,
        "kprobe_attach_failures",
        &user.kprobe_attach_failures,
    );
    s.push_str(r#","capture_scope":"#);
    match &meta.capture_scope {
        Some(scope) => s.push_str(
            &serde_json::to_string(scope).expect("serializing capture scope cannot fail"),
        ),
        None => s.push_str("null"),
    }
    write_optional_string(&mut s, "root_package", meta.root_package.as_deref());
    if let Some(uid) = meta.root_uid {
        let _ = write!(s, r#","root_uid":{uid}"#);
    }
    write_optional_string(&mut s, "boot_id", meta.boot_id.as_deref());
    write_optional_string(&mut s, "fingerprint", meta.fingerprint.as_deref());
    let _ = write!(
        s,
        r#","max_depth":{},"max_processes":{}"#,
        meta.max_depth, meta.max_processes
    );
    write_optional_string(
        &mut s,
        "bpf_object_sha256",
        meta.bpf_object_sha256.as_deref(),
    );
    write_optional_string(&mut s, "bpf_build_id", meta.bpf_build_id.as_deref());
    if let Some(value) = meta.bpf_abi_major {
        let _ = write!(s, r#","bpf_abi_major":{value}"#);
    }
    if let Some(value) = meta.bpf_abi_minor {
        let _ = write!(s, r#","bpf_abi_minor":{value}"#);
    }
    if let Some(value) = meta.bpf_event_size {
        let _ = write!(s, r#","bpf_event_size":{value}"#);
    }
    if let Some(value) = meta.bpf_feature_bits {
        let _ = write!(s, r#","bpf_feature_bits":{value}"#);
    }
    if let Some(value) = meta.ring_size_bytes {
        let _ = write!(s, r#","ring_size_bytes":{value}"#);
    }
    s.push('}');
    s
}

fn capture_metadata_errors(meta: &CaptureMetadata, user: &UserspaceHealth) -> Vec<String> {
    let mut errors = Vec::new();
    let valid_hex = |value: Option<&str>, len: usize| {
        value.is_some_and(|value| {
            value.len() == len
                && value.bytes().any(|byte| byte != b'0')
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
    };
    if !valid_hex(meta.bpf_object_sha256.as_deref(), 64) {
        errors.push("capture metadata lacks a nonzero BPF object SHA-256".into());
    }
    if !valid_hex(meta.bpf_build_id.as_deref(), 40) {
        errors.push("capture metadata lacks a nonzero BPF build ID".into());
    }
    if !meta.boot_id.as_deref().is_some_and(valid_boot_id) {
        errors.push("capture metadata lacks a canonical boot ID".into());
    }
    if meta.bpf_abi_major != Some(neutron_common::BPF_ABI_MAJOR)
        || meta.bpf_abi_minor != Some(neutron_common::BPF_ABI_MINOR)
        || meta.bpf_event_size != Some(core::mem::size_of::<neutron_common::SyscallEvent>() as u32)
    {
        errors.push("capture metadata has an incompatible BPF ABI".into());
    }
    let required_features = neutron_common::BPF_FEATURE_SYSCALL_TRACE
        | neutron_common::BPF_FEATURE_PROCESS_EXIT
        | neutron_common::BPF_FEATURE_PER_CPU_HEALTH;
    if meta
        .bpf_feature_bits
        .map_or(true, |bits| bits & required_features != required_features)
    {
        errors.push("capture metadata omits mandatory BPF feature bits".into());
    }
    if meta.ring_size_bytes.map_or(true, |value| value == 0) {
        errors.push("capture metadata lacks a ring size".into());
    }
    if meta.max_processes == 0 {
        errors.push("capture metadata max_processes is zero".into());
    }
    match &meta.capture_scope {
        Some(scope) => {
            errors.extend(scope.validation_errors());
            let kprobe_packs: Vec<_> = scope
                .packs
                .kprobe
                .iter()
                .map(|pack| pack.name.clone())
                .collect();
            if meta.bpf_object_sha256.as_deref() != Some(scope.producer.bpf_object_sha256.as_str())
                || meta.bpf_build_id.as_deref() != Some(scope.producer.bpf_build_id.as_str())
                || meta.bpf_feature_bits != Some(scope.producer.bpf_feature_bits)
            {
                errors.push(
                    "capture metadata producer BPF identity differs from capture_scope".into(),
                );
            }
            if meta.driver_packs != scope.packs.driver {
                errors.push("capture metadata driver_packs differ from capture_scope".into());
            }
            if meta.kprobe_packs != kprobe_packs {
                errors.push("capture metadata kprobe_packs differ from capture_scope".into());
            }
            if meta.match_packages != scope.filters.match_packages {
                errors.push("capture metadata match_packages differ from capture_scope".into());
            }
            if meta.root_package != scope.observation.root_package
                || meta.root_uid != scope.observation.root_uid
            {
                errors.push("capture metadata root selector differs from capture_scope".into());
            }
            if meta.max_depth != scope.instrumentation.max_depth {
                errors.push("capture metadata max_depth differs from capture_scope".into());
            }
            if meta.max_processes != scope.instrumentation.max_processes {
                errors.push("capture metadata max_processes differs from capture_scope".into());
            }
            if source_status(user.logcat_source_enabled, user.logcat_source_available)
                != source_status(
                    scope.sources.logcat_requested,
                    scope.sources.logcat_available,
                )
                || source_status(user.selinux_source_enabled, user.selinux_source_available)
                    != source_status(
                        scope.sources.selinux_logcat_requested,
                        scope.sources.selinux_logcat_available,
                    )
                || source_status(
                    user.tombstone_source_enabled,
                    user.tombstone_source_available,
                ) != source_status(
                    scope.sources.tombstone_requested,
                    scope.sources.tombstone_available,
                )
            {
                errors.push("capture source availability differs from capture_scope".into());
            }
            if expected_attached_programs(scope).as_ref() != Some(&meta.attached_programs) {
                errors.push("capture metadata attached_programs differ from capture_scope".into());
            }
        }
        None => errors.push("capture metadata lacks capture_scope".into()),
    }
    let attached: BTreeSet<_> = meta.attached_programs.iter().map(String::as_str).collect();
    for program in [
        "trace_sys_enter",
        "trace_sys_exit",
        "trace_sched_process_exit",
    ] {
        if !attached.contains(program) {
            errors.push(format!("capture metadata did not attach {program}"));
        }
    }
    errors
}

fn write_optional_string(s: &mut String, key: &str, value: Option<&str>) {
    use std::fmt::Write as _;
    if let Some(value) = value {
        let encoded = serde_json::to_string(value).expect("serializing a string cannot fail");
        let _ = write!(s, r#","{key}":{encoded}"#);
    }
}

fn write_string_array(s: &mut String, key: &str, values: &[String]) {
    use std::fmt::Write as _;
    let _ = write!(s, r#","{key}":["#);
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            s.push(',');
        }
        let encoded = serde_json::to_string(value).expect("serializing a string cannot fail");
        let _ = write!(s, "{encoded}");
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

    fn valid_capture_metadata() -> CaptureMetadata {
        CaptureMetadata {
            capture_scope: Some(CaptureScope::unfiltered_raw_ndjson()),
            attached_programs: vec![
                "trace_sys_enter".into(),
                "trace_sys_exit".into(),
                "trace_sched_process_exit".into(),
            ],
            max_depth: 4,
            max_processes: 64,
            boot_id: Some("11111111-2222-3333-4444-555555555555".into()),
            bpf_object_sha256: Some("1".repeat(64)),
            bpf_build_id: Some("2".repeat(40)),
            bpf_abi_major: Some(neutron_common::BPF_ABI_MAJOR),
            bpf_abi_minor: Some(neutron_common::BPF_ABI_MINOR),
            bpf_event_size: Some(core::mem::size_of::<neutron_common::SyscallEvent>() as u32),
            bpf_feature_bits: Some(
                neutron_common::BPF_FEATURE_SYSCALL_TRACE
                    | neutron_common::BPF_FEATURE_PROCESS_EXIT
                    | neutron_common::BPF_FEATURE_PER_CPU_HEALTH,
            ),
            ring_size_bytes: Some(1 << 20),
            ..CaptureMetadata::default()
        }
    }

    #[test]
    fn has_degradation_false_when_only_volume_counters_set() {
        let mut h = CaptureHealth::default();
        h.slots[COUNTER_EVENTS_SUBMITTED as usize] = 12_345;
        assert!(!h.has_degradation());
    }

    #[test]
    fn admission_boundary_exit_is_visible_without_marking_loss() {
        let mut h = CaptureHealth::default();
        h.slots[COUNTER_CAUSAL_ADMISSION_BOUNDARY_EXIT as usize] = 3;

        assert_eq!(h.get(COUNTER_CAUSAL_ADMISSION_BOUNDARY_EXIT), 3);
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
            output_cap_hit: false,
            ..UserspaceHealth::default()
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
        assert_eq!(v["output_cap_hit"], false);
        assert_eq!(v["degraded"], true);
    }

    #[test]
    fn capture_health_rejects_tampered_duplicate_scope_fields() {
        let mut meta = valid_capture_metadata();
        let scope = meta.capture_scope.as_mut().unwrap();
        scope.observation.root_package = Some("com.example.app".into());
        scope.observation.root_uid = Some(10123);
        scope.filters.match_packages = vec!["com.example.peer".into()];
        scope.instrumentation.binder_tracepoints = true;
        scope.packs.driver = vec!["binder".into()];
        scope.packs.kprobe = vec![KprobePackScope {
            name: "binder".into(),
            requested_sources: vec!["kprobe_binder_ioctl@binder_ioctl".into()],
            attached_sources: vec!["kprobe_binder_ioctl@binder_ioctl".into()],
            failures: Vec::new(),
        }];
        scope.sources.logcat_requested = true;
        scope.sources.logcat_available = true;
        scope.sources.selinux_logcat_requested = true;
        scope.sources.selinux_logcat_available = true;
        scope.sources.tombstone_requested = true;
        scope.sources.tombstone_available = true;
        scope.sources.tombstone_dir = Some("/data/tombstones".into());
        scope.producer.bpf_feature_bits |= neutron_common::BPF_FEATURE_BINDER_TRACE;
        *scope = scope.clone().recompute_claim_scope();
        meta.driver_packs = vec!["binder".into()];
        meta.kprobe_packs = vec!["binder".into()];
        meta.attached_programs.extend([
            "trace_binder_transaction".into(),
            "trace_binder_transaction_received".into(),
            "kprobe_binder_ioctl".into(),
        ]);
        meta.match_packages = vec!["com.example.peer".into()];
        meta.root_package = Some("com.example.app".into());
        meta.root_uid = Some(10123);
        meta.bpf_feature_bits =
            Some(meta.bpf_feature_bits.unwrap() | neutron_common::BPF_FEATURE_BINDER_TRACE);
        let user = UserspaceHealth {
            logcat_source_enabled: true,
            logcat_source_available: true,
            selinux_source_enabled: true,
            selinux_source_available: true,
            tombstone_source_enabled: true,
            tombstone_source_available: true,
            ..UserspaceHealth::default()
        };
        let value: Value = serde_json::from_str(&format_capture_health_json_with_metadata(
            &CaptureHealth::default(),
            &user,
            0,
            &meta,
        ))
        .unwrap();
        assert!(capture_health_contract_errors(value.as_object().unwrap()).is_empty());

        let mut variants = Vec::new();
        for (field, replacement) in [
            ("bpf_object_sha256", serde_json::json!("9".repeat(64))),
            ("bpf_build_id", serde_json::json!("8".repeat(40))),
            (
                "bpf_feature_bits",
                serde_json::json!(
                    meta.bpf_feature_bits.unwrap() | neutron_common::BPF_FEATURE_STACKS
                ),
            ),
            ("driver_packs", serde_json::json!(["kgsl"])),
            ("kprobe_packs", serde_json::json!(["kgsl"])),
            ("match_packages", serde_json::json!(["com.example.other"])),
            ("root_package", serde_json::json!("com.example.other")),
            ("root_uid", serde_json::json!(10124)),
            ("max_depth", serde_json::json!(5)),
            ("max_processes", serde_json::json!(65)),
            ("logcat_source", serde_json::json!("unavailable")),
            ("selinux_avc_source", serde_json::json!("unavailable")),
            ("tombstone_source", serde_json::json!("unavailable")),
        ] {
            let mut variant = value.clone();
            variant
                .as_object_mut()
                .unwrap()
                .insert(field.into(), replacement);
            variants.push((field, variant));
        }
        let mut missing_binder_received = value.clone();
        missing_binder_received["attached_programs"] = serde_json::json!([
            "trace_sys_enter",
            "trace_sys_exit",
            "trace_sched_process_exit",
            "trace_binder_transaction",
            "kprobe_binder_ioctl"
        ]);
        variants.push(("attached_programs", missing_binder_received));

        for (field, variant) in variants {
            let errors = capture_health_contract_errors(variant.as_object().unwrap());
            assert!(
                !errors.is_empty(),
                "tampered duplicate {field} was accepted"
            );
        }
    }

    #[test]
    fn generated_duplicate_scope_mismatch_makes_health_unknown() {
        let mut meta = valid_capture_metadata();
        meta.max_depth += 1;

        let value: Value = serde_json::from_str(&format_capture_health_json_with_metadata(
            &CaptureHealth::default(),
            &UserspaceHealth::default(),
            0,
            &meta,
        ))
        .unwrap();

        assert_eq!(value["status"], "unknown");
        assert!(value["unknown_reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reason| reason
                .as_str()
                .is_some_and(|reason| reason.contains("max_depth"))));
    }

    #[test]
    fn capture_health_json_without_provenance_is_unknown() {
        let h = CaptureHealth::default();
        let user = UserspaceHealth::default();
        let line = format_capture_health_json(&h, &user, 0);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["status"], "unknown");
        assert_eq!(v["degraded"], true);
        assert!(!v["unknown_reasons"].as_array().unwrap().is_empty());
        assert!(v.get("root_uid").is_none());
        assert!(v.get("boot_id").is_none());
        assert!(v.get("fingerprint").is_none());
    }

    #[test]
    fn capture_health_json_reports_output_cap_hit() {
        let h = CaptureHealth::default();
        let user = UserspaceHealth {
            output_cap_hit: true,
            ..UserspaceHealth::default()
        };
        let line = format_capture_health_json(&h, &user, 7);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();

        assert_eq!(v["output_cap_hit"], true);
    }

    #[test]
    fn native_capture_bounds_mark_health_degraded() {
        let user = UserspaceHealth {
            native_capture_degraded: true,
            native_maps_truncated: 1,
            ..UserspaceHealth::default()
        };
        let health = CaptureHealth::default();
        let value: serde_json::Value =
            serde_json::from_str(&format_capture_health_json(&health, &user, 1)).unwrap();
        assert_eq!(value["degraded"], true);
        assert!(format_summary_with(&health, &user, 1).contains("native capture"));
    }

    #[test]
    fn unavailable_default_selinux_source_marks_health_degraded() {
        let user = UserspaceHealth {
            selinux_source_enabled: true,
            selinux_source_available: false,
            ..UserspaceHealth::default()
        };
        let health = CaptureHealth::default();
        let value: serde_json::Value =
            serde_json::from_str(&format_capture_health_json(&health, &user, 0)).unwrap();
        assert_eq!(value["selinux_avc_source"], "unavailable");
        assert_eq!(value["degraded"], true);
    }

    #[test]
    fn follow_guardrails_make_causal_negative_evidence_incomplete() {
        let health = CaptureHealth::default();
        let user = UserspaceHealth {
            follow_policy_filtered: 3,
            follow_ttl_expired: 2,
            ..UserspaceHealth::default()
        };
        let value: serde_json::Value = serde_json::from_str(
            &format_capture_health_json_with_metadata(&health, &user, 0, &valid_capture_metadata()),
        )
        .unwrap();
        assert_eq!(value["follow_policy_filtered"], 3);
        assert_eq!(value["follow_ttl_expired"], 2);
        assert_eq!(value["status"], "incomplete");
        assert_eq!(value["degraded"], true);
        let summary = format_summary_with(&health, &user, 0);
        assert!(summary.contains("policy-filtered=3"));
        assert!(summary.contains("ttl-expired=2"));
    }

    #[test]
    fn capture_health_json_includes_additive_root_and_device_metadata() {
        let metadata = CaptureMetadata {
            root_uid: Some(10123),
            boot_id: Some("11111111-2222-3333-4444-555555555555".into()),
            fingerprint: Some("vendor/device:\"build\"".into()),
            ..CaptureMetadata::default()
        };
        let line = format_capture_health_json_with_metadata(
            &CaptureHealth::default(),
            &UserspaceHealth::default(),
            0,
            &metadata,
        );
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["root_uid"], 10123);
        assert_eq!(value["boot_id"], "11111111-2222-3333-4444-555555555555");
        assert_eq!(value["fingerprint"], "vendor/device:\"build\"");
    }

    #[test]
    fn format_summary_reports_output_cap_hit() {
        let h = CaptureHealth::default();
        let user = UserspaceHealth {
            output_cap_hit: true,
            ..UserspaceHealth::default()
        };
        let s = format_summary_with(&h, &user, 7);

        assert!(s.contains("output cap hit: true"));
    }
}
