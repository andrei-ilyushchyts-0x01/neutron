use std::io::Cursor;

use neutron::capture_normalize::{normalize_capture, CausalRelation};

#[test]
fn syscall_enter_and_exit_merge_into_one_exit_span() {
    let input = r#"
{"type":"syscall","ts_ns":20,"pid":200,"tid":201,"nr":29,"name":"ioctl","phase":"enter","args":[4,3227014671,0,0,0,0],"trace_id":"trace-a","scenario_id":"camera","span_id":"span-1","parent_span_id":"binder-1","causal_relation":"exact"}
{"type":"syscall","ts_ns":30,"enter_ts_ns":20,"pid":200,"tid":201,"nr":29,"name":"ioctl","phase":"exit","args":[4,3227014671,0,0,0,0],"ret":0,"latency_us":10,"ioctl_name":"VIDIOC_QBUF","trace_id":"trace-a","scenario_id":"camera","span_id":"span-1","parent_span_id":"binder-1","causal_relation":"exact"}
"#;

    let capture = normalize_capture(Cursor::new(input)).expect("normalize capture");

    assert_eq!(capture.syscalls.len(), 1);
    let syscall = &capture.syscalls[0];
    assert_eq!(syscall.phase, "exit");
    assert_eq!(syscall.ret, Some(0));
    assert_eq!(syscall.latency_us, Some(10));
    assert_eq!(syscall.ioctl_name.as_deref(), Some("VIDIOC_QBUF"));
    assert_eq!(syscall.relation, CausalRelation::Exact);
}

#[test]
fn binder_enrichment_without_relation_does_not_overwrite_inferred_evidence() {
    let input = r#"
{"type":"binder","ts_ns":10,"pid":100,"comm":"app","to_proc":200,"target_node":7,"code":1,"debug_id":11,"trace_id":"trace-a","scenario_id":"camera","span_id":"binder-1","parent_span_id":"root-1","causal_relation":"inferred"}
{"type":"binder_call","ts_ns":10,"debug_id":11,"caller_pid":100,"caller_comm":"app","callee_pid":200,"target_node":7,"code":1,"service":"camera/default","method":"connect","latency_us":5,"status":"completed","trace_id":"trace-a","scenario_id":"camera","span_id":"binder-1","parent_span_id":"root-1"}
"#;

    let capture = normalize_capture(Cursor::new(input)).expect("normalize capture");

    assert_eq!(capture.binders.len(), 1);
    let binder = &capture.binders[0];
    assert_eq!(binder.caller_pid, 100);
    assert_eq!(binder.callee_pid, 200);
    assert_eq!(binder.service.as_deref(), Some("camera/default"));
    assert_eq!(binder.method.as_deref(), Some("connect"));
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
fn malformed_unknown_and_non_object_lines_are_ignored() {
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
}

#[test]
fn capture_health_retains_uid_and_device_identity_metadata() {
    let input = r#"
{"type":"capture_health","degraded":true,"output_cap_hit":false,"root_uid":10123,"boot_id":"8b2d6c98-20a1-4e7e-944f-53f61b52d5ef","fingerprint":"google/husky/husky:16/test:user/release-keys"}
"#;

    let capture = normalize_capture(Cursor::new(input)).expect("normalize capture");
    let health = capture.health.expect("capture health");

    assert!(health.degraded);
    assert!(!health.output_cap_hit);
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
