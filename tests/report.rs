use clap::CommandFactory;
use neutron::cli::Cli;
use neutron::report::{
    parse_service_list, render_binder_template_from_reader, render_report_from_reader,
    render_service_catalog_from_reader, ReportOptions,
};
use std::io::Cursor;

fn report(input: &str, opts: ReportOptions) -> String {
    render_report_from_reader(Cursor::new(input), opts).expect("render report")
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
fn binder_attribution_prefers_exact_service_then_map_then_catalog_then_raw() {
    let capture = r#"
{"type":"binder_call","caller_pid":10,"caller_uid":10341,"caller_comm":"wallet","callee_pid":200,"target_node":1,"code":7,"status":"completed","service":"android.hardware.security.keymint.IKeyMintDevice/default"}
{"type":"binder_call","caller_pid":10,"caller_uid":10341,"caller_comm":"wallet","callee_pid":201,"target_node":2,"code":8,"status":"completed"}
{"type":"binder_call","caller_pid":10,"caller_uid":10341,"caller_comm":"wallet","callee_pid":202,"target_node":3,"code":9,"status":"completed"}
{"type":"binder_call","caller_pid":10,"caller_uid":10341,"caller_comm":"wallet","callee_pid":203,"target_node":4,"code":10,"status":"completed"}
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
    let base = r#"
{"type":"syscall","name":"openat","fd_path":"/proc/version"}
{"type":"syscall","name":"ioctl","ioctl_family":"binder","fd_path":"/dev/binder"}
{"type":"binder_call","callee_pid":200,"target_node":1,"code":7,"status":"completed","service":"activity"}
"#;
    let test = r#"
{"type":"syscall","name":"openat","fd_path":"/proc/self/maps"}
{"type":"syscall","name":"ioctl","ioctl_family":"kgsl","fd_path":"/dev/kgsl-3d0"}
{"type":"binder_call","callee_pid":201,"target_node":2,"code":8,"status":"completed","service":"package"}
{"type":"syscall","name":"socket","fd_path":"socket:[1]"}
"#;

    let md = report(
        test,
        ReportOptions {
            baseline_capture: Some(base.into()),
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
fn malformed_and_blank_lines_are_skipped() {
    let md = report(
        "not json\n\n{\"type\":\"syscall\",\"name\":\"openat\"}\n{bad",
        ReportOptions::default(),
    );

    assert!(md.contains("openat"));
    assert!(md.contains("Parsed events: 1"));
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
