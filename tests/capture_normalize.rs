use std::io::Cursor;

use neutron::capture_normalize::{normalize_capture, CausalRelation};
use neutron::health::{
    format_capture_health_json_with_metadata, CaptureHealth as RuntimeHealth, CaptureMetadata,
    CaptureScope, UserspaceHealth,
};

#[test]
fn syscall_enter_and_exit_merge_into_one_exit_span() {
    let input = r#"
{"type":"syscall","ts_ns":20,"pid":200,"tid":201,"nr":29,"name":"ioctl","phase":"enter","args":[4,3227014671,0,0,0,0],"trace_id":"trace-a","scenario_id":"camera","span_id":"span-1","parent_span_id":"binder-1","causal_relation":"exact"}
{"type":"syscall","ts_ns":30,"enter_ts_ns":20,"pid":200,"tid":201,"nr":29,"name":"ioctl","phase":"exit","args":[4,3227014671,0,0,0,0],"ret":0,"latency_us":10,"fd_path":"/dev/video0","ioctl_family":"v4l2","ioctl_name":"VIDIOC_QBUF","trace_id":"trace-a","scenario_id":"camera","span_id":"span-1","parent_span_id":"binder-1","depth":2,"causal_relation":"exact"}
"#;

    let capture = normalize_capture(Cursor::new(input)).expect("normalize capture");

    assert_eq!(capture.syscalls.len(), 1);
    let syscall = &capture.syscalls[0];
    assert_eq!(syscall.phase, "exit");
    assert_eq!(syscall.ret, Some(0));
    assert_eq!(syscall.latency_us, Some(10));
    assert_eq!(syscall.ioctl_cmd, Some(3_227_014_671));
    assert_eq!(syscall.fd_path.as_deref(), Some("/dev/video0"));
    assert_eq!(syscall.ioctl_family.as_deref(), Some("v4l2"));
    assert_eq!(syscall.ioctl_name.as_deref(), Some("VIDIOC_QBUF"));
    assert_eq!(syscall.scenario_id.as_deref(), Some("camera"));
    assert_eq!(syscall.parent_span_id.as_deref(), Some("binder-1"));
    assert_eq!(syscall.depth, Some(2));
    assert_eq!(syscall.relation, CausalRelation::Exact);
}

#[test]
fn binder_enrichment_without_relation_does_not_overwrite_inferred_evidence() {
    let input = r#"
{"type":"binder","ts_ns":10,"pid":100,"comm":"app","to_proc":200,"target_node":7,"code":1,"debug_id":11,"trace_id":"trace-a","scenario_id":"camera","span_id":"binder-1","parent_span_id":"root-1","depth":1,"causal_relation":"inferred"}
{"type":"binder_call","ts_ns":10,"debug_id":11,"caller_pid":100,"caller_comm":"app","callee_pid":200,"target_node":7,"code":1,"service":"camera/default","method":"connect","attribution_confidence":"candidate","latency_us":5,"status":"completed","trace_id":"trace-a","scenario_id":"camera","span_id":"binder-1","parent_span_id":"root-1"}
"#;

    let capture = normalize_capture(Cursor::new(input)).expect("normalize capture");

    assert_eq!(capture.binders.len(), 1);
    let binder = &capture.binders[0];
    assert_eq!(binder.caller_pid, 100);
    assert_eq!(binder.callee_pid, 200);
    assert_eq!(binder.service.as_deref(), Some("camera/default"));
    assert_eq!(binder.method.as_deref(), Some("connect"));
    assert_eq!(binder.attribution_confidence.as_deref(), Some("candidate"));
    assert_eq!(binder.scenario_id.as_deref(), Some("camera"));
    assert_eq!(binder.parent_span_id.as_deref(), Some("root-1"));
    assert_eq!(binder.depth, Some(1));
    assert_eq!(binder.relation, CausalRelation::Inferred);
}

#[test]
fn repeated_binder_debug_and_span_ids_stay_separate_across_traces() {
    let input = r#"
{"type":"binder","pid":10,"to_proc":20,"debug_id":7,"code":1,"trace_id":"trace-a","span_id":"same-span","parent_span_id":"root-a","causal_relation":"exact"}
{"type":"binder_call","debug_id":7,"caller_pid":10,"callee_pid":20,"code":1,"service":"svc.one","trace_id":"trace-a","span_id":"same-span","parent_span_id":"root-a","causal_relation":"exact"}
{"type":"binder","pid":30,"to_proc":40,"debug_id":7,"code":2,"trace_id":"trace-b","span_id":"same-span","parent_span_id":"root-b","causal_relation":"exact"}
{"type":"binder_call","debug_id":7,"caller_pid":30,"callee_pid":40,"code":2,"service":"svc.two","trace_id":"trace-b","span_id":"same-span","parent_span_id":"root-b","causal_relation":"exact"}
"#;

    let capture = normalize_capture(Cursor::new(input)).expect("normalize capture");

    assert_eq!(capture.binders.len(), 2);
    let observed: Vec<_> = capture
        .binders
        .iter()
        .map(|binder| {
            (
                binder.trace_id.as_deref(),
                binder.service.as_deref(),
                binder.caller_pid,
                binder.callee_pid,
            )
        })
        .collect();
    assert_eq!(
        observed,
        vec![
            (Some("trace-a"), Some("svc.one"), 10, 20),
            (Some("trace-b"), Some("svc.two"), 30, 40),
        ]
    );
}

#[test]
fn malformed_unknown_and_non_object_lines_taint_health_without_hiding_valid_records() {
    let input = r#"
not-json
42
{"type":"future_event","span_id":"ignored"}
{"unknown":"object-without-type"}
{"type":"syscall","ts_ns":1,"pid":9,"tid":9,"nr":29,"name":"ioctl","phase":"exit","ret":0,"future_field":{"nested":true}}
"#;

    let capture = normalize_capture(Cursor::new(input)).expect("normalize capture");

    assert_eq!(capture.syscalls.len(), 1);
    assert!(capture.binders.is_empty());
    assert!(capture.exits.is_empty());
    assert!(capture
        .health_warnings
        .iter()
        .any(|warning| warning.contains("unknown record type")));
}

#[test]
fn unknown_record_type_overrides_claimed_complete_health() {
    let input = r#"
{"type":"future_event","span_id":"not-understood"}
{"type":"capture_health","status":"complete","degraded":false,"output_cap_hit":false}
"#;
    let capture = normalize_capture(Cursor::new(input)).unwrap();
    let health = capture.health.unwrap();
    assert_eq!(health.status, "unknown");
    assert!(health.degraded);
}

#[test]
fn capture_health_retains_uid_and_device_identity_metadata() {
    let input = r#"
{"type":"capture_health","degraded":true,"output_cap_hit":false,"root_package":"com.example.app","root_uid":10123,"boot_id":"8b2d6c98-20a1-4e7e-944f-53f61b52d5ef","fingerprint":"google/husky/husky:16/test:user/release-keys"}
"#;

    let capture = normalize_capture(Cursor::new(input)).expect("normalize capture");
    let health = capture.health.expect("capture health");

    assert!(health.degraded);
    assert!(!health.output_cap_hit);
    assert_eq!(health.root_package.as_deref(), Some("com.example.app"));
    assert_eq!(health.root_uid, Some(10123));
    assert_eq!(
        health.boot_id.as_deref(),
        Some("8b2d6c98-20a1-4e7e-944f-53f61b52d5ef")
    );
    assert_eq!(
        health.fingerprint.as_deref(),
        Some("google/husky/husky:16/test:user/release-keys")
    );
}

#[test]
fn capture_health_marks_intentionally_incomplete_follow_branches() {
    let input = r#"{"type":"capture_health","degraded":false,"follow_policy_filtered":3,"follow_ttl_expired":2}"#;
    let capture = normalize_capture(Cursor::new(input)).unwrap();
    let health = capture.health.unwrap();

    assert_eq!(health.follow_policy_filtered, 3);
    assert_eq!(health.follow_ttl_expired, 2);
    assert!(capture
        .health_warnings
        .contains("Binder branches were policy-filtered"));
    assert!(capture
        .health_warnings
        .contains("Binder followers expired by TTL"));
}

#[test]
fn markers_retain_scenario_and_root_selector_metadata() {
    let input = r#"
{"type":"marker","ts_ns":99,"name":"surface-observe","phase":"start","scenario_id":"surface-observe","trace_id":"trace-a","root_package":"com.example.app","root_uid":10123}
"#;

    let capture = normalize_capture(Cursor::new(input)).expect("normalize capture");

    assert_eq!(capture.markers.len(), 1);
    let marker = &capture.markers[0];
    assert_eq!(marker.ts_ns, Some(99));
    assert_eq!(marker.name, "surface-observe");
    assert_eq!(marker.phase.as_deref(), Some("start"));
    assert_eq!(marker.scenario_id.as_deref(), Some("surface-observe"));
    assert_eq!(marker.trace_id.as_deref(), Some("trace-a"));
    assert_eq!(marker.root_package.as_deref(), Some("com.example.app"));
    assert_eq!(marker.root_uid, Some(10123));
}

#[test]
fn malformed_binder_endpoints_and_oversized_debug_ids_are_ignored() {
    let input = r#"
{"type":"binder","pid":10,"debug_id":7,"trace_id":"trace-a","span_id":"missing-callee"}
{"type":"binder","pid":10,"to_proc":20,"debug_id":18446744073709551615,"trace_id":"trace-a","span_id":"overflow"}
"#;

    let capture = normalize_capture(Cursor::new(input)).expect("normalize capture");

    assert!(capture.binders.is_empty());
    assert!(capture
        .health_warnings
        .contains("ignored Binder span with a missing process endpoint"));
}

#[test]
fn binder_received_enriches_the_callee_process_identity() {
    let capture = r#"
{"type":"binder","ts_ns":10,"pid":100,"comm":"app","to_proc":200,"debug_id":11,"code":1,"trace_id":"trace-a","span_id":"binder-1","causal_relation":"exact"}
{"type":"binder_received","ts_ns":11,"pid":200,"comm":"camera-hal","debug_id":11,"trace_id":"trace-a","span_id":"binder-1","causal_relation":"exact"}
{"type":"binder_call","debug_id":11,"caller_pid":100,"callee_pid":200,"code":1,"trace_id":"trace-a","span_id":"binder-1","status":"completed","causal_relation":"exact"}
"#;

    let normalized = normalize_capture(Cursor::new(capture)).unwrap();
    assert_eq!(normalized.binders.len(), 1);
    assert_eq!(
        normalized.binders[0].callee_comm.as_deref(),
        Some("camera-hal")
    );
}

#[test]
fn selinux_denials_preserve_policy_and_causal_evidence() {
    let input = r#"{"type":"selinux_denial","ts_ns":90,"pid":42,"tid":43,"uid":1000,"comm":"keymint","source_domain":"hal_keymint_default","target_type":"tee_device","tclass":"chr_file","permissions":["ioctl","read"],"path":"/dev/trusty-ipc-dev0","result":"denied","trace_id":"trace-a","scenario_id":"surface-observe","span_id":"denial-1","parent_span_id":"binder-1","depth":1,"root_package":"com.example.app","root_uid":10123,"causal_relation":"inferred"}"#;
    let capture = normalize_capture(Cursor::new(input)).unwrap();

    assert_eq!(capture.denials.len(), 1);
    let denial = &capture.denials[0];
    assert_eq!(denial.pid, 42);
    assert_eq!(denial.tid, 43);
    assert_eq!(denial.source_domain, "hal_keymint_default");
    assert_eq!(denial.target_type, "tee_device");
    assert_eq!(denial.permissions, ["ioctl", "read"]);
    assert_eq!(denial.path.as_deref(), Some("/dev/trusty-ipc-dev0"));
    assert_eq!(denial.relation, CausalRelation::Inferred);
    assert!(capture.has_causal);
}

#[test]
fn syscall_uid_is_retained_and_pid_zero_is_rejected() {
    let input = r#"
{"type":"syscall","pid":42,"uid":1000,"tid":42,"name":"ioctl","phase":"exit","trace_id":"trace-a","span_id":"valid"}
{"type":"syscall","pid":0,"uid":10123,"tid":0,"name":"ioctl","phase":"exit","trace_id":"trace-a","span_id":"invalid"}
"#;

    let capture = normalize_capture(Cursor::new(input)).unwrap();
    assert_eq!(capture.syscalls.len(), 1);
    assert_eq!(capture.syscalls[0].uid, Some(1000));
    assert!(capture
        .health_warnings
        .contains("ignored syscall span with a missing process endpoint"));
}

#[test]
fn process_exit_unknown_uid_is_not_normalized_as_root() {
    let input =
        r#"{"type":"process_exit","pid":42,"uid":null,"comm":"native","classification":"crash"}"#;

    let capture = normalize_capture(Cursor::new(input)).unwrap();
    assert_eq!(capture.exits.len(), 1);
    assert_eq!(capture.exits[0].uid, None);
}

#[test]
fn recognized_records_missing_required_fields_taint_health_unknown() {
    let input = r#"
{"type":"syscall"}
{"type":"binder","pid":10,"to_proc":20}
{"type":"process_exit"}
{"type":"selinux_denial"}
{"type":"capture_health","status":"complete","degraded":false,"output_cap_hit":false}
"#;

    let capture = normalize_capture(Cursor::new(input)).unwrap();
    let health = capture.health.expect("final health record");
    assert_eq!(health.status, "unknown");
    assert!(health.degraded);
    assert!(capture.health_warnings.iter().any(|warning| warning
        .contains("ignored 4 recognized record(s) with missing or invalid required fields")));
}

#[test]
fn duplicate_health_records_cannot_restore_complete_status() {
    let input = r#"
{"type":"capture_health","status":"unknown","degraded":true,"output_cap_hit":false}
{"type":"capture_health","status":"complete","degraded":false,"output_cap_hit":false}
"#;
    let capture = normalize_capture(Cursor::new(input)).unwrap();
    assert_eq!(capture.health.unwrap().status, "unknown");
    assert!(capture
        .health_warnings
        .iter()
        .any(|warning| warning.contains("2 capture_health records")));
}

#[test]
fn oversized_capture_record_is_rejected_before_json_allocation() {
    let input = format!(
        r#"{{"type":"marker","name":"{}"}}"#,
        "x".repeat(4 * 1024 * 1024 + 1)
    );

    let error = normalize_capture(Cursor::new(input)).unwrap_err();
    assert!(format!("{error:#}").contains("capture record 1 exceeds"));
}

#[test]
fn excessive_nested_cardinality_is_rejected_before_retention() {
    let candidates = vec![r#""""#; 1_000_000].join(",");
    let input = format!(
        r#"{{"type":"binder","pid":10,"to_proc":20,"debug_id":1,"service_candidates":[{candidates}]}}"#
    );

    let error = normalize_capture(Cursor::new(input)).unwrap_err();
    assert!(format!("{error:#}").contains("exceeds 1000000 retained items"));
}

#[test]
fn binder_correlation_loss_survives_normalization_and_taints_health() {
    let input = r#"{"type":"capture_health","binder_tracker_evictions":2,"binder_unmatched_receives":3,"binder_causal_metadata_discarded":1,"binder_invalid_callers":4,"binder_tracker_enabled":false}"#;
    let capture = normalize_capture(Cursor::new(input)).unwrap();
    let health = capture.health.unwrap();

    assert_eq!(health.binder_tracker_evictions, 2);
    assert_eq!(health.binder_unmatched_receives, 3);
    assert_eq!(health.binder_causal_metadata_discarded, 1);
    assert_eq!(health.binder_invalid_callers, 4);
    assert!(!health.binder_tracker_enabled);
    assert_eq!(health.status, "unknown");
    assert!(capture
        .health_warnings
        .iter()
        .any(|warning| warning.contains("Binder tracker eviction")));
    assert!(capture
        .health_warnings
        .iter()
        .any(|warning| warning.contains("Binder correlation tracker was disabled")));
}

#[test]
fn normalized_health_exposes_restricted_claim_scope_without_degrading_transport() {
    let mut scope = CaptureScope::unfiltered_raw_ndjson();
    scope.filters.userspace = vec!["fd_path glob {/dev/kgsl*}".into()];
    let scope = scope.recompute_claim_scope();
    let metadata = CaptureMetadata {
        max_depth: scope.instrumentation.max_depth,
        max_processes: scope.instrumentation.max_processes,
        capture_scope: Some(scope),
        attached_programs: vec![
            "trace_sys_enter".into(),
            "trace_sys_exit".into(),
            "trace_sched_process_exit".into(),
        ],
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
    };
    let line = format_capture_health_json_with_metadata(
        &RuntimeHealth::default(),
        &UserspaceHealth::default(),
        0,
        &metadata,
    );
    let capture = normalize_capture(Cursor::new(line)).unwrap();
    let health = capture.health.unwrap();

    assert_eq!(health.status, "complete");
    assert!(!health.degraded);
    let scope = health.capture_scope.unwrap();
    assert!(!scope.claim_scope_complete);
    assert_eq!(scope.claim_scope_reasons, ["userspace_filters"]);
    assert!(capture
        .health_warnings
        .iter()
        .any(|warning| warning.contains("claim scope is restricted")));
}
