use serde_json::Value;
use std::process::{Command, Output};

fn neutron(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_neutron"))
        .args(args)
        .output()
        .expect("run neutron")
}

fn stdout(output: &Output) -> String {
    assert!(
        output.status.success(),
        "neutron exited with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

fn text_field<'a>(text: &'a str, name: &str) -> &'a str {
    text.lines()
        .find_map(|line| {
            let rest = line.trim().strip_prefix(name)?;
            let value = rest
                .trim_start_matches(|character: char| character == ':' || character == '=')
                .trim();
            (!value.is_empty()).then_some(value)
        })
        .unwrap_or_else(|| panic!("missing or empty {name} field in:\n{text}"))
}

fn assert_git_commit(value: &str) {
    assert_eq!(value.len(), 40, "git_commit must be the full SHA-1");
    assert!(
        value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "git_commit must be hexadecimal: {value}"
    );
}

#[test]
fn version_verbose_reports_release_and_build_identity() {
    let output = stdout(&neutron(&["--version", "--verbose"]));
    assert_eq!(output.lines().next(), Some("neutron 1.5.0-rc.1"));

    assert_git_commit(text_field(&output, "git_commit"));
    assert!(matches!(text_field(&output, "git_dirty"), "true" | "false"));
    assert_ne!(text_field(&output, "build_timestamp"), "unknown");
    assert!(text_field(&output, "rustc_version").starts_with("rustc "));
    assert!(text_field(&output, "target").contains('-'));
    assert_ne!(text_field(&output, "feature_set"), "unknown");
    assert!(
        text_field(&output, "bpf_abi_major").parse::<u16>().is_ok(),
        "bpf_abi_major must be numeric"
    );
    assert_eq!(text_field(&output, "syscall_event_size"), "257");
    assert_ne!(text_field(&output, "bpf_feature_bits"), "unknown");
}

#[test]
fn self_info_json_matches_neutron_self_info_v1() {
    let output = stdout(&neutron(&["self-info", "--json"]));
    let value: Value = serde_json::from_str(&output).expect("self-info emits one JSON document");

    assert_eq!(value["schema"], "neutron.self-info/v1");
    assert_eq!(value["tool"]["version"], "1.5.0-rc.1");
    assert_git_commit(
        value["tool"]["git_commit"]
            .as_str()
            .expect("tool.git_commit is a string"),
    );
    assert!(value["tool"]["git_dirty"].is_boolean());
    assert!(value["tool"]["build_timestamp"]
        .as_str()
        .is_some_and(|timestamp| !timestamp.is_empty() && timestamp != "unknown"));
    assert!(value["tool"]["rustc_version"]
        .as_str()
        .is_some_and(|rustc| rustc.starts_with("rustc ")));
    assert!(value["tool"]["target"]
        .as_str()
        .is_some_and(|target| target.contains('-')));
    assert!(value["tool"]["feature_set"].is_array());
    assert!(value["bpf"]["abi_major"].is_u64());
    assert_eq!(value["bpf"]["event_size"], 257);
    assert!(value["bpf"]["feature_bits"].is_array());
}
