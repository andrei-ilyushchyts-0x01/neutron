use std::io::Cursor;

use clap::Parser;
use neutron::cli::{Cli, Command};
use neutron::selinux::{
    explain_from_reader, parse_avc_line, render_explanation_text, DenialDeduper,
};

const ENFORCING_AVC: &str = r#"05-05 12:00:00.000  1000  1000 W auditd: type=1400 audit(1714910400.123:9182): avc: denied { ioctl read } for pid=1234 comm="com.example.app" path="/dev/trusty-ipc-dev0" ioctlcmd=0xc0047401 scontext=u:r:untrusted_app:s0:c123,c456 tcontext=u:object_r:tee_device:s0 tclass=chr_file permissive=0"#;

#[test]
fn parses_enforcing_multi_permission_avc() {
    let denial = parse_avc_line(ENFORCING_AVC)
        .expect("valid AVC")
        .expect("AVC record");

    assert_eq!(denial.audit_id.as_deref(), Some("1714910400.123:9182"));
    assert_eq!(denial.pid, 1234);
    assert_eq!(denial.tid, 1234);
    assert_eq!(denial.comm, "com.example.app");
    assert_eq!(denial.source_domain, "untrusted_app");
    assert_eq!(denial.target_type, "tee_device");
    assert_eq!(denial.permissions, ["ioctl", "read"]);
    assert_eq!(denial.permission, None);
    assert_eq!(denial.path.as_deref(), Some("/dev/trusty-ipc-dev0"));
    assert_eq!(denial.ioctlcmd.as_deref(), Some("0xc0047401"));
    assert!(!denial.permissive);
    assert_eq!(denial.result, "denied");
}

#[test]
fn parses_permissive_single_permission_pathless_avc() {
    let line = r#"kernel: audit(1.000:7): avc: denied { getattr } for pid=77 comm="worker thread" name="quoted name" scontext=u:r:vendor_hal:s0 tcontext=u:object_r:sysfs:s0 tclass=file permissive=1"#;
    let denial = parse_avc_line(line).unwrap().unwrap();

    assert_eq!(denial.permissions, ["getattr"]);
    assert_eq!(denial.permission.as_deref(), Some("getattr"));
    assert_eq!(denial.path.as_deref(), Some("quoted name"));
    assert!(denial.permissive);
    assert_eq!(denial.result, "allowed_permissive");
}

#[test]
fn rejects_malformed_contexts_and_bounded_fields() {
    let malformed = ENFORCING_AVC.replace("u:r:untrusted_app:s0:c123,c456", "not-a-context");
    assert!(parse_avc_line(&malformed).is_err());

    let oversized = format!(
        "avc: denied {{ read }} for pid=1 comm=app path=\"{}\" scontext=u:r:a:s0 tcontext=u:object_r:b:s0 tclass=file",
        "x".repeat(20_000)
    );
    assert!(parse_avc_line(&oversized).is_err());

    assert!(parse_avc_line("ActivityManager: harmless line")
        .unwrap()
        .is_none());
}

#[test]
fn deduplicates_audit_copies_and_bounded_fallback_fingerprints() {
    let denial = parse_avc_line(ENFORCING_AVC).unwrap().unwrap();
    let mut deduper = DenialDeduper::new(2);
    assert!(!deduper.is_duplicate(&denial, 1));
    assert!(deduper.is_duplicate(&denial, 2));

    let mut no_id = denial.clone();
    no_id.audit_id = None;
    assert!(!deduper.is_duplicate(&no_id, 3));
    assert!(deduper.is_duplicate(&no_id, 4));

    let mut other = no_id.clone();
    other.pid = 99;
    assert!(!deduper.is_duplicate(&other, 5));
    assert!(deduper.len() <= 2);
}

fn positive_capture() -> String {
    r#"
{"type":"selinux_denial","event_id":9182,"ts_ns":100,"pid":10,"tid":11,"comm":"com.example.app","scontext":"u:r:untrusted_app:s0","source_domain":"untrusted_app","tcontext":"u:object_r:tee_device:s0","target_type":"tee_device","tclass":"chr_file","permissions":["ioctl"],"permission":"ioctl","path":"/dev/trusty-ipc-dev0","permissive":false,"result":"denied","trace_id":"trace-a","scenario_id":"keymint","span_id":"denial-1","parent_span_id":"root-1","depth":0,"causal_relation":"exact"}
{"type":"binder_call","event_id":9183,"ts_ns":110,"caller_pid":10,"callee_pid":200,"status":"completed","service":"android.hardware.security.keymint.IKeyMintDevice/default","attribution_confidence":"exact","trace_id":"trace-a","scenario_id":"keymint","span_id":"binder-1","parent_span_id":"root-1","depth":1,"causal_relation":"exact"}
{"type":"syscall","event_id":9184,"ts_ns":120,"pid":200,"tid":201,"name":"ioctl","phase":"exit","ret":0,"ok":true,"fd_path":"/dev/trusty-ipc-dev0","trace_id":"trace-a","scenario_id":"keymint","span_id":"ioctl-1","parent_span_id":"binder-1","depth":1,"causal_relation":"exact"}
"#
    .into()
}

#[test]
fn explains_observed_exact_delegation_in_json_and_text() {
    let explanation = explain_from_reader(Cursor::new(positive_capture()), 9182).unwrap();
    let value = serde_json::to_value(&explanation).unwrap();

    assert_eq!(value["schema"], "neutron.selinux-explanation/v1");
    assert_eq!(value["policy"]["source_type"], "untrusted_app");
    assert_eq!(value["policy"]["target_type"], "tee_device");
    assert_eq!(value["delegated_paths"].as_array().unwrap().len(), 1);
    assert_eq!(value["delegated_paths"][0]["callee_pid"], 200);
    assert_eq!(
        value["delegated_paths"][0]["service"],
        "android.hardware.security.keymint.IKeyMintDevice/default"
    );
    assert_eq!(value["delegated_paths"][0]["syscall"]["ret"], 0);

    let text = render_explanation_text(&explanation);
    assert!(text.contains("com.example.app (pid 10, tid 11)"));
    assert!(text.contains("was denied"));
    assert!(text.contains("untrusted_app tee_device:chr_file { ioctl }"));
    assert!(text.contains("callee pid 200"));
    assert!(text.contains("successful ioctl"));
}

#[test]
fn permissive_explanation_does_not_claim_operation_was_blocked() {
    let capture = positive_capture()
        .replace(r#""permissive":false"#, r#""permissive":true"#)
        .replace(r#""result":"denied""#, r#""result":"allowed_permissive""#);
    let explanation = explain_from_reader(Cursor::new(capture), 9182).unwrap();
    let text = render_explanation_text(&explanation);

    assert!(text.contains("allowed because the source domain was permissive"));
    assert!(!text.contains("was blocked"));
}

#[test]
fn excludes_non_exact_or_unsuccessful_delegated_evidence_with_warnings() {
    for (needle, replacement, warning) in [
        (
            r#""trace_id":"trace-a""#,
            r#""trace_id":"trace-b""#,
            "different trace",
        ),
        (r#""ret":0"#, r#""ret":-13"#, "failed syscall"),
        (
            r#""causal_relation":"exact""#,
            r#""causal_relation":"inferred""#,
            "inferred",
        ),
        (
            r#""attribution_confidence":"exact""#,
            r#""attribution_confidence":"candidate""#,
            "candidate service attribution",
        ),
        (
            r#""fd_path":"/dev/trusty-ipc-dev0""#,
            r#""fd_path":"/dev/other""#,
            "different path",
        ),
    ] {
        let mut capture = positive_capture();
        let index = capture.rfind(needle).expect("fixture needle");
        capture.replace_range(index..index + needle.len(), replacement);
        let explanation = explain_from_reader(Cursor::new(capture), 9182).unwrap();
        assert!(explanation.delegated_paths.is_empty(), "{warning}");
        assert!(
            explanation
                .warnings
                .iter()
                .any(|item| item.contains(warning)),
            "missing warning {warning}: {:?}",
            explanation.warnings
        );
    }
}

#[test]
fn service_side_denial_is_not_delegated_reachability() {
    let capture = format!(
        "{}{}",
        positive_capture().replace(
            r#""type":"syscall""#,
            r#""type":"selinux_denial","scontext":"u:r:keymint:s0","source_domain":"keymint","tcontext":"u:object_r:tee_device:s0","target_type":"tee_device","tclass":"chr_file","permissions":["ioctl"],"permissive":false,"result":"denied""#,
        ),
        "\n"
    );
    let explanation = explain_from_reader(Cursor::new(capture), 9182).unwrap();
    assert!(explanation.delegated_paths.is_empty());
    assert!(explanation
        .warnings
        .iter()
        .any(|warning| warning.contains("service-side denial")));
}

#[test]
fn pathless_denial_never_claims_delegated_path() {
    let capture = positive_capture()
        .replace(r#","path":"/dev/trusty-ipc-dev0""#, "")
        .replace(r#","fd_path":"/dev/trusty-ipc-dev0""#, "");
    let explanation = explain_from_reader(Cursor::new(capture), 9182).unwrap();
    assert!(explanation.delegated_paths.is_empty());
    assert!(explanation
        .warnings
        .iter()
        .any(|warning| warning.contains("pathless")));
}

#[test]
fn explain_rejects_missing_or_non_denial_event_ids() {
    let error = explain_from_reader(Cursor::new("{\"type\":\"syscall\",\"event_id\":1}\n"), 1)
        .unwrap_err()
        .to_string();
    assert!(error.contains("not a SELinux denial"));

    let error = explain_from_reader(Cursor::new(positive_capture()), 9999)
        .unwrap_err()
        .to_string();
    assert!(error.contains("event 9999 not found"));
}

#[test]
fn selinux_explain_cli_accepts_public_flags() {
    let cli = Cli::try_parse_from([
        "neutron",
        "selinux",
        "explain",
        "capture.ndjson",
        "--event-id",
        "9182",
        "--format",
        "json",
        "--output",
        "report.json",
    ])
    .unwrap();

    assert!(matches!(cli.command, Some(Command::Selinux(_))));
}
