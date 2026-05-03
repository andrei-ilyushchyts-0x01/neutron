//! Integration tests: end-to-end pipeline coverage for the decoder/format/rule
//! wiring. These tests pin the JSON shape that the rules engine consumes so
//! refactors do not break that contract.

use neutron::decode::format_comm;
use neutron::format::{format_event_json, format_event_json_with_stack, format_event_text};
use neutron_common::SyscallEvent;

fn comm_bytes(name: &str) -> [u8; 16] {
    let mut c = [0u8; 16];
    let n = name.len().min(16);
    c[..n].copy_from_slice(&name.as_bytes()[..n]);
    c
}

fn data_path(path: &[u8]) -> [u8; 128] {
    let mut data = [0u8; 128];
    let n = path.len().min(data.len());
    data[..n].copy_from_slice(&path[..n]);
    data
}

#[test]
fn openat_su_event_triggers_su_binary_probe_rule() {
    // Build an exit event for openat("/system/bin/su"). Default rule
    // T004_su_binary_probe matches this with aggregate=PerTarget on syscall
    // 56 / data path equal to one of the listed candidates.
    let ev = SyscallEvent {
        timestamp_ns: 1_000_000,
        pid: 4242,
        tgid: 4242,
        uid: 10001,
        syscall_nr: 56,
        args: [(-100i64) as u64, 0, 0, 0, 0, 0],
        ret: -1,
        is_enter: 0,
        comm: comm_bytes("rootcheck"),
        data: data_path(b"/system/bin/su\0"),
        ..SyscallEvent::default()
    };
    let line = format_event_json(&ev, false);

    let mut engine = neutron_rules::RuleEngine::with_default_rules()
        .expect("default rules load");
    let owned = neutron_rules::Event::parse_line(&line)
        .expect("event parses (this confirms the JSON contract)");
    let view = owned.view().expect("event view");
    engine.feed(&view);

    let findings = engine.flush_all();
    assert!(
        findings.iter().any(|f| f.rule_id == "T004_su_binary_probe"),
        "expected T004_su_binary_probe finding, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn connect_event_text_includes_decoded_sockaddr() {
    let mut data = [0u8; 128];
    // AF_INET 8.8.8.8:80
    data[..8].copy_from_slice(&[0x02, 0x00, 0x00, 0x50, 8, 8, 8, 8]);
    let ev = SyscallEvent {
        timestamp_ns: 0,
        pid: 99,
        tgid: 99,
        syscall_nr: 203, // connect
        is_enter: 1,
        comm: comm_bytes("net"),
        data,
        ..SyscallEvent::default()
    };
    let s = format_event_text(&ev, false);
    assert!(
        s.contains("AF_INET 8.8.8.8:80"),
        "expected decoded sockaddr in text output, got {s}"
    );
}

#[test]
fn binder_event_text_starts_with_binder_header() {
    let ev = SyscallEvent {
        syscall_nr: -1,
        timestamp_ns: 1_000_000,
        pid: 5,
        tgid: 5,
        args: [42, 0x1, 0, 99, 0, 7],
        comm: comm_bytes("svc"),
        ..SyscallEvent::default()
    };
    let s = format_event_text(&ev, false);
    assert!(s.contains("BINDER"), "expected BINDER token in {s}");
    assert!(s.contains("to_proc=42"), "expected to_proc in {s}");
}

#[test]
fn format_event_json_with_stack_feeds_engine_for_stack_contains_rules() {
    // T016 requires syscall=79 + path /system/xbin/su + stack containing "libc".
    // This exercises the production data flow: format_event_json_with_stack →
    // Event::parse_line → MatchCondition::matches.
    let ev = SyscallEvent {
        timestamp_ns: 1_000_000,
        pid: 4242,
        tgid: 4242,
        uid: 10001,
        syscall_nr: 79,
        args: [0, 0, 0, 0, 0, 0],
        ret: -2,
        is_enter: 0,
        comm: comm_bytes("rootcheck"),
        data: data_path(b"/system/xbin/su\0"),
        ..SyscallEvent::default()
    };
    let stack = "vfs_statx+0x10 ;; libc.so:fstatat+0x12 <- libnative-utils.so:check_root+0x40";
    let line = format_event_json_with_stack(&ev, false, Some(stack));

    let mut engine = neutron_rules::RuleEngine::with_default_rules().unwrap();
    let owned = neutron_rules::Event::parse_line(&line)
        .expect("event parses with stack field");
    let view = owned.view().expect("event view");
    // Confirm the parsed view actually carries the stack so the engine can
    // see it — this is the load-bearing contract for stack-aware rules.
    assert_eq!(view.stack, Some(stack));
    engine.feed(&view);

    let findings = engine.flush_all();
    assert!(
        findings.iter().any(|f| f.rule_id == "T016_native_root_check_via_libc"),
        "expected T016 finding via stack-aware rule, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn format_comm_helper_is_reachable_through_lib() {
    // Sanity: confirms the lib re-exports work as documented.
    let mut buf = [0u8; 16];
    buf[..3].copy_from_slice(b"abc");
    assert_eq!(format_comm(&buf), "abc");
}
