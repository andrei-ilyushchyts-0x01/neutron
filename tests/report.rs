use clap::CommandFactory;
use neutron::cli::Cli;
use neutron::format::format_process_exit_json;
use neutron::health::{
    format_capture_health_json_with_metadata, CaptureHealth, CaptureMetadata, UserspaceHealth,
};
use neutron::report::{
    parse_service_list, render_binder_template_from_reader, render_report_from_reader,
    render_service_catalog_from_reader, run_report, ReportArgs, ReportOptions,
};
use neutron::sources::ProcessExitEvent;
use neutron_common::{ExitSource, SIGSEGV};
use std::io::Cursor;

fn report(input: &str, opts: ReportOptions) -> String {
    render_report_from_reader(Cursor::new(input), opts).expect("render report")
}

fn complete_health() -> String {
    let mut health = CaptureHealth::default();
    health.slots[neutron_common::COUNTER_EVENTS_SUBMITTED as usize] = 4;
    let capture_scope = neutron::health::CaptureScope::unfiltered_raw_ndjson();
    format_capture_health_json_with_metadata(
        &health,
        &UserspaceHealth::default(),
        4,
        &CaptureMetadata {
            max_depth: capture_scope.instrumentation.max_depth,
            max_processes: capture_scope.instrumentation.max_processes,
            capture_scope: Some(capture_scope),
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
        },
    )
}

fn bounded_capture_with_health(
    events: &str,
    scenario: &str,
    trace_id: &str,
    health: impl AsRef<str>,
) -> String {
    let mut lines = vec![serde_json::json!({
        "type": "marker",
        "ts_ns": 1,
        "name": scenario,
        "phase": "start",
        "scenario_id": scenario,
        "trace_id": trace_id,
        "root_pid": 10,
    })
    .to_string()];
    for line in events
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let mut value: serde_json::Value = serde_json::from_str(line).expect("event JSON");
        let object = value.as_object_mut().expect("event object");
        object.insert("scenario_id".into(), scenario.into());
        object.insert("trace_id".into(), trace_id.into());
        lines.push(value.to_string());
    }
    lines.push(
        serde_json::json!({
            "type": "marker",
            "ts_ns": 3,
            "name": scenario,
            "phase": "end",
            "scenario_id": scenario,
            "trace_id": trace_id,
            "root_pid": 10,
        })
        .to_string(),
    );
    lines.push(health.as_ref().to_string());
    format!("{}\n", lines.join("\n"))
}

fn bounded_capture(events: &str, scenario: &str, trace_id: &str) -> String {
    bounded_capture_with_health(events, scenario, trace_id, complete_health())
}

#[test]
fn markdown_report_renders_expected_sections() {
    let capture = r#"
{"type":"syscall","pid":42,"tid":43,"uid":10341,"name":"openat","comm":"wallet","phase":"exit","ret":3,"ok":true,"fd_path":"/proc/self/maps","latency_us":7}
{"type":"syscall","pid":42,"tid":43,"uid":10341,"name":"socket","comm":"wallet","phase":"exit","ret":9,"ok":true,"domain":"AF_UNIX","sock_type":"SOCK_STREAM","protocol":"0","fd_path":"socket:[123]"}
{"type":"syscall","pid":42,"tid":43,"uid":10341,"name":"ioctl","comm":"wallet","phase":"exit","ret":0,"ok":true,"ioctl_family":"binder","ioctl_name":"BINDER_WRITE_READ","fd_path":"/dev/binder"}
{"type":"syscall","pid":42,"tid":43,"uid":10341,"name":"mprotect","comm":"wallet","phase":"exit","ret":0,"ok":true,"prot":"RWX"}
{"type":"finding","rule_id":"R001","severity":"high","category":"memory","process":{"pid":42,"comm":"wallet"}}
{"type":"capture_health","events_userspace":5,"events_emitted":5,"degraded":false,"output_cap_hit":false,"match_packages":["com.example.wallet"],"match_uids":["10341"],"match_pids":["42"]}
"#;

    let md = report(
        capture,
        ReportOptions {
            title: Some("Wallet Boundary".into()),
            package: Some("com.example.wallet".into()),
            ..ReportOptions::default()
        },
    );

    for heading in [
        "# Wallet Boundary",
        "## Capture Health",
        "## Traced Scope",
        "## Top Syscalls",
        "## Sensitive Paths",
        "## Sockets",
        "## Binder Targets",
        "## Ioctl Families",
        "## mmap / RWX",
        "## Crashes / Findings",
    ] {
        assert!(md.contains(heading), "missing heading {heading}:\n{md}");
    }
    assert!(md.contains("com.example.wallet"));
    assert!(md.contains("/proc/self/maps"));
    assert!(md.contains("RWX"));
    assert!(md.contains("R001"));
}

#[test]
fn degraded_health_and_output_cap_emit_warning() {
    let capture = r#"{"type":"capture_health","events_userspace":7,"degraded":true,"output_cap_hit":true,"ringbuf_reserve_failed":2}"#;
    let md = report(capture, ReportOptions::default());

    assert!(md.contains("WARNING"));
    assert!(md.contains("degraded"));
    assert!(md.contains("output cap"));
}

#[test]
fn complete_transport_with_restricted_scope_warns_against_negative_claims() {
    let mut health: serde_json::Value =
        serde_json::from_str(&complete_health()).expect("health JSON");
    health["capture_scope"]["output"]["event_mode"] = "findings_only".into();
    health["capture_scope"]["claim_scope_complete"] = false.into();
    health["capture_scope"]["claim_scope_reasons"] = serde_json::json!(["findings_only_output"]);

    let md = report(&health.to_string(), ReportOptions::default());

    assert!(md.contains("effective capture scope is restricted"));
    assert!(md.contains("unfiltered negative claims are not supported"));
}

#[test]
fn formatter_crash_classification_reaches_the_report() {
    let exit = ProcessExitEvent {
        ts_ns: 42,
        pid: 1234,
        uid: Some(10_341),
        comm: "camera-hal".into(),
        exit_code: 0,
        exit_signal: SIGSEGV,
        source: ExitSource::Tracepoint,
    };
    let capture = format!(
        "{}\n{}\n",
        format_process_exit_json(&exit, &[], Some(7)),
        complete_health()
    );

    let md = report(&capture, ReportOptions::default());

    assert!(md.contains("camera-hal"), "missing crash label:\n{md}");
    assert!(md.contains("SIGSEGV"), "missing crash signal:\n{md}");
    assert!(
        md.contains("Crashes / Findings"),
        "missing crash section:\n{md}"
    );
}

#[test]
fn binder_attribution_prefers_exact_service_then_map_then_catalog_then_raw() {
    let capture = r#"
{"type":"binder_call","debug_id":1,"caller_pid":10,"caller_uid":10341,"caller_comm":"wallet","callee_pid":200,"target_node":1,"code":7,"status":"completed","service":"android.hardware.security.keymint.IKeyMintDevice/default"}
{"type":"binder_call","debug_id":2,"caller_pid":10,"caller_uid":10341,"caller_comm":"wallet","callee_pid":201,"target_node":2,"code":8,"status":"completed"}
{"type":"binder_call","debug_id":3,"caller_pid":10,"caller_uid":10341,"caller_comm":"wallet","callee_pid":202,"target_node":3,"code":9,"status":"completed"}
{"type":"binder_call","debug_id":4,"caller_pid":10,"caller_uid":10341,"caller_comm":"wallet","callee_pid":203,"target_node":4,"code":10,"status":"completed"}
"#;
    let md = report(
        capture,
        ReportOptions {
            binder_services_json: Some(
                r#"{"201":{"2":"android.security.IKeystoreService/default"}}"#.into(),
            ),
            binder_catalog_json: Some(
                r#"{"202":{"services":["activity","package"],"source":"service list -p"}}"#.into(),
            ),
            ..ReportOptions::default()
        },
    );

    assert!(md.contains("android.hardware.security.keymint.IKeyMintDevice/default"));
    assert!(md.contains("android.security.IKeystoreService/default"));
    assert!(md.contains("candidates: activity, package"));
    assert!(md.contains("pid=203 node=4 code=10"));
}

#[test]
fn baseline_diff_reports_new_and_removed_behavior() {
    let base = bounded_capture(
        r#"
{"type":"syscall","pid":10,"name":"openat","fd_path":"/proc/version"}
{"type":"syscall","pid":10,"name":"ioctl","ioctl_family":"binder","fd_path":"/dev/binder"}
{"type":"binder_call","debug_id":1,"caller_pid":10,"callee_pid":200,"target_node":1,"code":7,"status":"completed","service":"activity"}
"#,
        "procedure",
        "trace-base",
    );
    let test = bounded_capture(
        r#"
{"type":"syscall","pid":10,"name":"openat","fd_path":"/proc/self/maps"}
{"type":"syscall","pid":10,"name":"ioctl","ioctl_family":"kgsl","fd_path":"/dev/kgsl-3d0"}
{"type":"binder_call","debug_id":2,"caller_pid":10,"callee_pid":201,"target_node":2,"code":8,"status":"completed","service":"package"}
{"type":"syscall","pid":10,"name":"socket","fd_path":"socket:[1]"}
"#,
        "procedure",
        "trace-test",
    );

    let md = report(
        &test,
        ReportOptions {
            baseline_capture: Some(base),
            ..ReportOptions::default()
        },
    );

    assert!(md.contains("## New Behavior"));
    assert!(md.contains("syscalls"));
    assert!(md.contains("+ socket"));
    assert!(md.contains("- /proc/version"));
    assert!(md.contains("+ /proc/self/maps"));
    assert!(md.contains("+ kgsl"));
    assert!(md.contains("+ package"));
}

#[test]
fn baseline_diff_rejects_different_effective_capture_scopes() {
    let baseline = bounded_capture(
        r#"{"type":"syscall","pid":10,"name":"openat"}"#,
        "procedure",
        "trace-base",
    );
    let mut test_health: serde_json::Value =
        serde_json::from_str(&complete_health()).expect("health JSON");
    test_health["capture_scope"]["observation"]["target_pid"] = 20.into();
    let test = bounded_capture_with_health(
        r#"{"type":"syscall","pid":20,"name":"socket"}"#,
        "procedure",
        "trace-test",
        test_health.to_string(),
    );

    let md = report(
        &test,
        ReportOptions {
            baseline_capture: Some(baseline),
            ..ReportOptions::default()
        },
    );

    assert!(md.contains("identical claim-complete effective capture scope"));
    assert!(
        !md.contains("- + socket"),
        "nonconclusive diff leaked:\n{md}"
    );
}

#[test]
fn baseline_diff_requires_matching_completed_scenario_lifecycles() {
    let event = r#"{"type":"syscall","pid":10,"name":"openat"}"#;
    let bounded = bounded_capture(event, "procedure", "trace-base");
    let unmarked = format!("{event}\n{}\n", complete_health());
    let md = report(
        &unmarked,
        ReportOptions {
            baseline_capture: Some(bounded.clone()),
            ..ReportOptions::default()
        },
    );
    assert!(md.contains("paired scenario lifecycle/root contract"));
    assert!(!md.contains("- - openat"));

    let different = bounded_capture(event, "different", "trace-test");
    let md = report(
        &different,
        ReportOptions {
            baseline_capture: Some(bounded.clone()),
            ..ReportOptions::default()
        },
    );
    assert!(md.contains("behavior diff is nonconclusive"));

    let unfinished = bounded_capture(event, "procedure", "trace-test")
        .lines()
        .filter(|line| !line.contains(r#""phase":"end""#))
        .collect::<Vec<_>>()
        .join("\n");
    let md = report(
        &unfinished,
        ReportOptions {
            baseline_capture: Some(bounded),
            ..ReportOptions::default()
        },
    );
    assert!(md.contains("behavior diff is nonconclusive"));
}

#[test]
fn baseline_diff_ignores_behavior_outside_the_scenario_boundary() {
    let inside = r#"{"type":"syscall","pid":10,"name":"ioctl"}"#;
    let baseline = format!(
        "{}\n{}",
        r#"{"type":"syscall","pid":10,"name":"outside_baseline"}"#,
        bounded_capture(inside, "procedure", "trace-base")
    );
    let test = format!(
        "{}\n{}",
        r#"{"type":"syscall","pid":10,"name":"outside_test"}"#,
        bounded_capture(inside, "procedure", "trace-test")
    );
    let md = report(
        &test,
        ReportOptions {
            baseline_capture: Some(baseline),
            ..ReportOptions::default()
        },
    );
    assert!(md.contains("## New Behavior"));
    assert!(!md.contains("- + outside_test"));
    assert!(!md.contains("- - outside_baseline"));
}

#[test]
fn report_rejects_hard_linked_capture_and_baseline() {
    let directory = std::env::temp_dir().join(format!(
        "neutron-report-hardlink-{}-{}",
        std::process::id(),
        line!()
    ));
    std::fs::create_dir(&directory).unwrap();
    let capture = directory.join("capture.ndjson");
    let baseline = directory.join("baseline.ndjson");
    std::fs::write(&capture, b"capture\n").unwrap();
    std::fs::hard_link(&capture, &baseline).unwrap();

    let error = run_report(ReportArgs {
        capture: capture.to_string_lossy().into_owned(),
        baseline: Some(baseline.to_string_lossy().into_owned()),
        title: None,
        package: None,
        binder_services: None,
        binder_catalog: None,
        aidl_catalog: None,
        top: 10,
        output: None,
    })
    .unwrap_err();
    assert!(format!("{error:#}").contains("same file"));

    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn malformed_and_blank_lines_are_skipped() {
    let md = report(
        "not json\n\n{\"type\":\"syscall\",\"name\":\"openat\",\"fd_path\":\"/proc/self/maps\",\"ioctl_family\":\"binder\"}\n{bad",
        ReportOptions::default(),
    );

    assert!(!md.contains("| openat |"));
    assert!(!md.contains("/proc/self/maps"));
    assert!(!md.contains("| binder |"));
    assert!(md.contains("Parsed events: 1"));
}

#[test]
fn recognized_record_missing_required_fields_makes_report_health_unknown() {
    let capture = r#"
{"type":"syscall"}
{"type":"capture_health","status":"complete","degraded":false,"output_cap_hit":false}
"#;
    let md = report(capture, ReportOptions::default());

    assert!(md.contains("malformed, invalid, or unknown NDJSON"));
    assert!(md.contains("status is `unknown`"));
    assert!(md.contains("Absence of evidence is not conclusive"));
}

#[test]
fn zero_identity_raw_binder_preserves_explicit_incomplete_report_health() {
    let mut health: serde_json::Value = serde_json::from_str(&complete_health()).unwrap();
    let object = health.as_object_mut().unwrap();
    object.insert("binder_invalid_callers".into(), 1.into());
    object.insert("status".into(), "incomplete".into());
    object.insert("degraded".into(), true.into());
    object.insert(
        "incomplete_reasons".into(),
        serde_json::json!(["Binder caller identity was unusable"]),
    );
    let capture = bounded_capture_with_health(
        r#"{"type":"binder","ts_ns":2,"pid":1545,"to_proc":0,"debug_id":0,"code":0,"target_node":0}"#,
        "probe_keystore_lookup",
        "0000000000001234",
        health.to_string(),
    );

    let md = report(&capture, ReportOptions::default());

    assert!(md.contains("status is `incomplete`"));
    assert!(!md.contains("status is `unknown`"));
    assert!(!md.contains("malformed, invalid, or unknown NDJSON"));
    assert!(!md.contains("pid=0 node=0"));
}

#[test]
fn zero_identity_binder_with_complete_health_makes_report_unknown() {
    for event in [
        r#"{"type":"binder","ts_ns":2,"pid":1545,"to_proc":0,"debug_id":0,"code":0,"target_node":0}"#,
        r#"{"type":"binder_received","ts_ns":2,"pid":536,"debug_id":0}"#,
    ] {
        let capture = bounded_capture_with_health(
            event,
            "probe_keystore_lookup",
            "0000000000001234",
            complete_health(),
        );

        let md = report(&capture, ReportOptions::default());

        assert!(md.contains("status is `unknown`"), "{md}");
        assert!(md.contains("unusable Binder identity"), "{md}");
        assert!(md.contains("Absence of evidence is not conclusive"), "{md}");
    }
}

#[test]
fn malformed_synthetic_binder_call_makes_report_health_unknown() {
    for event in [
        r#"{"type":"binder_call","caller_pid":42,"callee_pid":536}"#,
        r#"{"type":"binder_call","caller_pid":42,"callee_pid":536,"debug_id":"7"}"#,
        r#"{"type":"binder_call","caller_pid":42,"callee_pid":536,"debug_id":0}"#,
    ] {
        let capture = bounded_capture(event, "scenario", "0000000000001234");
        let md = report(&capture, ReportOptions::default());

        assert!(md.contains("malformed, invalid, or unknown NDJSON"), "{md}");
        assert!(md.contains("status is `unknown`"), "{md}");
    }
}

#[test]
fn malformed_marker_cannot_hide_unscoped_zero_binder_identity() {
    let capture = [
        r#"{"type":"binder","ts_ns":1,"pid":1545,"to_proc":0,"debug_id":0}"#.to_string(),
        r#"{"type":"marker","name":"not-a-valid-boundary"}"#.to_string(),
        complete_health(),
    ]
    .join("\n")
        + "\n";

    let md = report(&capture, ReportOptions::default());

    assert!(md.contains("status is `unknown`"), "{md}");
    assert!(md.contains("scenario marker lifecycle is invalid"), "{md}");
}

#[test]
fn unscoped_zero_binder_warns_without_tainting_bounded_health() {
    let capture = [
        r#"{"type":"binder","ts_ns":1,"pid":1545,"to_proc":0,"debug_id":0}"#.to_string(),
        r#"{"type":"marker","ts_ns":2,"name":"scenario","phase":"start","scenario_id":"scenario","trace_id":"0000000000001234","root_pid":10}"#.to_string(),
        r#"{"type":"marker","ts_ns":3,"name":"scenario","phase":"end","scenario_id":"scenario","trace_id":"0000000000001234","root_pid":10}"#.to_string(),
        complete_health(),
    ]
    .join("\n")
        + "\n";

    let md = report(&capture, ReportOptions::default());

    assert!(md.contains("unusable Binder identity"));
    assert!(!md.contains("status is `unknown`"));
    assert!(md.contains("- `status`: complete"));
}

#[test]
fn unknown_record_type_makes_report_health_unknown() {
    let capture = r#"
{"type":"future_event","pid":42}
{"type":"capture_health","status":"complete","degraded":false,"output_cap_hit":false}
"#;
    let md = report(capture, ReportOptions::default());

    assert!(md.contains("malformed, invalid, or unknown NDJSON"));
    assert!(md.contains("status is `unknown`"));
}

#[test]
fn hostile_capture_strings_cannot_inject_markdown_structure_or_html() {
    let records = [
        serde_json::json!({
            "type": "syscall",
            "pid": 42,
            "name": "openat`\n## Forged Event Heading",
            "comm": "bad\n- forged-list-item",
            "fd_path": "/proc/self/maps`\n<script>alert(1)</script>"
        })
        .to_string(),
        serde_json::json!({
            "type": "finding",
            "rule_id": "R`\n## Forged Finding Heading",
            "severity": "high",
            "category": "[click](javascript:alert(1))"
        })
        .to_string(),
        complete_health(),
    ];
    let md = report(
        &records.join("\n"),
        ReportOptions {
            title: Some("Trusted\n## Forged Title <script>x</script> [x](javascript:y)".into()),
            ..ReportOptions::default()
        },
    );

    assert!(
        !md.contains("\n## Forged"),
        "forged heading rendered:\n{md}"
    );
    assert!(!md.contains("<script>"), "raw HTML rendered:\n{md}");
    assert!(
        !md.contains("[x](javascript:y)"),
        "active title link rendered:\n{md}"
    );
    assert!(
        md.contains("\\n"),
        "control characters should remain visible"
    );
    assert!(md.contains("\\x60"), "backticks should remain visible");
    assert!(md.contains("&lt;script&gt;"), "HTML should be escaped");
}

#[test]
fn appended_clean_health_cannot_override_an_earlier_unknown_record() {
    let capture = r#"
{"type":"capture_health","status":"unknown","degraded":true,"output_cap_hit":false}
{"type":"capture_health","status":"complete","degraded":false,"output_cap_hit":false}
"#;
    let md = report(capture, ReportOptions::default());

    assert!(md.contains("2 `capture_health` records"));
    assert!(md.contains("status is `unknown`"));
}

#[test]
fn binder_template_groups_unique_pairs_with_codes_and_status_counts() {
    let capture = r#"
{"type":"binder_call","callee_pid":200,"target_node":1,"code":7,"status":"completed"}
{"type":"binder_call","callee_pid":200,"target_node":1,"code":8,"status":"callee_crashed"}
{"type":"binder_call","callee_pid":200,"target_node":1,"code":8,"status":"callee_crashed"}
{"type":"binder_call","callee_pid":201,"target_node":2,"code":9,"status":"completed","service":"already.resolved"}
"#;

    let json = render_binder_template_from_reader(Cursor::new(capture)).expect("template");
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid template json");

    assert_eq!(v["200"]["1"]["service"], "");
    assert_eq!(v["200"]["1"]["observed_codes"]["8"], 2);
    assert_eq!(v["200"]["1"]["status_counts"]["callee_crashed"], 2);
    assert!(
        v.get("201").is_none(),
        "resolved pairs should not need a template"
    );
}

#[test]
fn service_list_parser_accepts_common_android_shapes() {
    let input = r#"
Found 3 services:
0	activity: [android.app.IActivityManager] pid=123
1 package: [android.content.pm.IPackageManager] (pid 123)
2	android.hardware.security.keymint.IKeyMintDevice/default: [android.hardware.security.keymint.IKeyMintDevice] pid=456
"#;

    let catalog = parse_service_list(input).expect("catalog");
    assert_eq!(
        catalog.get(&123).expect("pid 123"),
        &vec!["activity".to_string(), "package".to_string()]
    );
    assert_eq!(
        catalog.get(&456).expect("pid 456"),
        &vec!["android.hardware.security.keymint.IKeyMintDevice/default".to_string()]
    );

    let json = render_service_catalog_from_reader(Cursor::new(input)).expect("catalog json");
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid catalog json");
    assert_eq!(v["123"]["services"][0], "activity");
    assert_eq!(v["123"]["source"], "service list -p");
}

#[test]
fn cli_help_lists_report_and_binder_map() {
    let mut cmd = Cli::command();
    let mut help = Vec::new();
    cmd.write_long_help(&mut help).unwrap();
    let help = String::from_utf8(help).unwrap();

    assert!(
        help.contains("report"),
        "top-level help missing report:\n{help}"
    );
    assert!(
        help.contains("binder-map"),
        "top-level help missing binder-map:\n{help}"
    );
}

#[test]
fn recipes_help_lists_boundary_report_workflows() {
    let mut cmd = Cli::command();
    let recipes = cmd
        .find_subcommand_mut("recipes")
        .expect("recipes subcommand");
    let mut help = Vec::new();
    recipes.write_long_help(&mut help).unwrap();
    let help = String::from_utf8(help).unwrap();

    for name in ["launch-diff", "action-diff", "native-surface-audit"] {
        assert!(help.contains(name), "missing recipe {name}:\n{help}");
    }
}
