//! Integration tests for the rule engine.
//!
//! Each test feeds synthetic NDJSON-style events that mirror the actual
//! `neutron --json` output and asserts on the findings produced.

use neutron_rules::{Event, RuleEngine};
use serde_json::Value;
use std::path::Path;

fn feed_lines(engine: &mut RuleEngine, lines: &[&str]) {
    for line in lines {
        let value: Value = serde_json::from_str(line).expect("test line is valid JSON");
        let ev = Event::from_value(&value, Some(line)).expect("event view");
        engine.feed(&ev);
    }
}

fn load_dexprotector_engine() -> RuleEngine {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("rules")
        .join("dexprotector-rasp.yaml");
    let rules = neutron_rules::load_rules_yaml_file(&path).unwrap_or_else(|err| {
        panic!(
            "DexProtector ruleset should load from {}: {err}",
            path.display()
        )
    });
    RuleEngine::new(rules).expect("DexProtector rules should validate")
}

#[test]
fn default_ruleset_loads() {
    let engine = RuleEngine::with_default_rules().unwrap();
    assert!(
        engine.rule_count() >= 15,
        "expected >=15 default rules, got {}",
        engine.rule_count()
    );
}

#[test]
fn proc_self_maps_polling_fires_after_threshold() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    let lines = [
        r#"{"ts_ns":1000000000,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/proc/self/maps"}"#,
        r#"{"ts_ns":3000000000,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/proc/self/maps"}"#,
    ];
    feed_lines(&mut engine, &lines);
    let findings = engine.drain_ready();
    let hit: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "T001_proc_self_maps_polling")
        .collect();
    assert_eq!(
        hit.len(),
        1,
        "expected exactly one T001 finding, got {}: {findings:?}",
        hit.len()
    );
    assert_eq!(hit[0].pid, 42);
    assert_eq!(hit[0].event_count, 2);
}

#[test]
fn single_proc_self_maps_does_not_fire() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000000000,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/proc/self/maps"}"#,
        ],
    );
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "T001_proc_self_maps_polling");
    assert!(
        hit.is_none(),
        "T001 should NOT fire on a single event: {findings:?}"
    );
}

#[test]
fn su_binary_probe_fires_immediately() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":1000,"nr":48,"name":"faccessat","comm":"app","enter":false,"ret":-2,"args":[0,0,0,0,0,0],"data":"/system/xbin/su"}"#,
        ],
    );
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "T004_su_binary_probe");
    assert!(
        hit.is_some(),
        "T004 should fire on first faccessat to /system/xbin/su: {findings:?}"
    );
}

#[test]
fn su_binary_probe_fires_on_statfs() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":1000,"nr":43,"name":"statfs","comm":"app","enter":false,"ret":-2,"args":[0,0,0,0,0,0],"data":"/system/xbin/su"}"#,
        ],
    );
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "T004_su_binary_probe");
    assert!(
        hit.is_some(),
        "T004 should fire on statfs to /system/xbin/su: {findings:?}"
    );
}

#[test]
fn rwx_mmap_fires_per_event() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":1000,"nr":222,"name":"mmap","comm":"app","enter":false,"ret":1024,"args":[0,4096,7,34,0,0],"rwx_alert":"RWX"}"#,
            r#"{"ts_ns":2000,"pid":42,"tid":42,"uid":1000,"nr":222,"name":"mmap","comm":"app","enter":false,"ret":2048,"args":[0,4096,7,34,0,0],"rwx_alert":"RWX"}"#,
        ],
    );
    let findings = engine.drain_ready();
    let hits: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "T011_rwx_memory_allocation")
        .collect();
    assert_eq!(
        hits.len(),
        2,
        "T011 with every_event should emit twice for two RWX mmaps"
    );
}

#[test]
fn frida_artifact_probe_per_target_only_emits_once_per_path() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":1000,"nr":48,"name":"faccessat","comm":"app","enter":false,"ret":-2,"args":[0,0,0,0,0,0],"data":"/data/local/tmp/frida-server"}"#,
            r#"{"ts_ns":2000,"pid":42,"tid":42,"uid":1000,"nr":48,"name":"faccessat","comm":"app","enter":false,"ret":-2,"args":[0,0,0,0,0,0],"data":"/data/local/tmp/frida-server"}"#,
            r#"{"ts_ns":3000,"pid":42,"tid":42,"uid":1000,"nr":48,"name":"faccessat","comm":"app","enter":false,"ret":-2,"args":[0,0,0,0,0,0],"data":"/data/local/tmp/re.frida.server"}"#,
        ],
    );
    let findings = engine.drain_ready();
    let hits: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "T006_frida_artifact_probe")
        .collect();
    assert_eq!(
        hits.len(),
        2,
        "expected one finding per distinct target, got {hits:?}"
    );
}

#[test]
fn unrelated_events_produce_no_findings() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":1000,"nr":63,"name":"read","comm":"app","enter":false,"ret":1024,"args":[7,0,0,0,0,0]}"#,
            r#"{"ts_ns":2000,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/data/data/app/cache/boring.txt"}"#,
        ],
    );
    assert!(engine.drain_ready().is_empty());
}

#[test]
fn t015_does_not_fire_on_proc_self_maps() {
    // Regression: on-device run of v0.1 fired T015 on /proc/self/maps,
    // duplicating T001. Self-paths must be excluded.
    let mut engine = RuleEngine::with_default_rules().unwrap();
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/proc/self/maps"}"#,
        ],
    );
    let findings = engine.drain_ready();
    let t015 = findings
        .iter()
        .find(|f| f.rule_id == "T015_cross_process_proc_inspection");
    assert!(
        t015.is_none(),
        "T015 must NOT fire on /proc/self/maps: {findings:?}"
    );
}

#[test]
fn t015_fires_on_cross_process_inspection() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/proc/12345/maps"}"#,
        ],
    );
    let findings = engine.drain_ready();
    let t015 = findings
        .iter()
        .find(|f| f.rule_id == "T015_cross_process_proc_inspection");
    assert!(
        t015.is_some(),
        "T015 should fire on /proc/<other_pid>/maps: {findings:?}"
    );
}

#[test]
fn stack_contains_matches_when_substring_present() {
    // T016 needs newfstatat (79) + path /system/xbin/su + stack containing "libc".
    let mut engine = RuleEngine::with_default_rules().unwrap();
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":1000,"nr":79,"name":"newfstatat","comm":"app","enter":false,"ret":-2,"args":[0,0,0,0,0,0],"data":"/system/xbin/su","stack":"vfs_statx+0x10 ;; libc.so:fstatat+0x12 <- libnative-utils.so:check_root+0x40"}"#,
        ],
    );
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "T016_native_root_check_via_libc");
    assert!(
        hit.is_some(),
        "T016 should fire when stack contains 'libc': {findings:?}"
    );
}

#[test]
fn stack_contains_does_not_match_when_stack_absent() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    // No stack field → T016 must NOT fire even though path matches.
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":1000,"nr":79,"name":"newfstatat","comm":"app","enter":false,"ret":-2,"args":[0,0,0,0,0,0],"data":"/system/xbin/su"}"#,
        ],
    );
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "T016_native_root_check_via_libc");
    assert!(
        hit.is_none(),
        "T016 must NOT fire without stack data: {findings:?}"
    );
}

#[test]
fn stack_not_contains_excludes_renderscript() {
    // T019 fires on /system/lib64 openat unless stack mentions RenderScript.
    let mut engine = RuleEngine::with_default_rules().unwrap();
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/system/lib64/libRS.so","stack":"libc.so:open+0x10 <- libRS_internal.so:RenderScript_init+0x40"}"#,
        ],
    );
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "T019_native_lib_path_inspection");
    assert!(
        hit.is_none(),
        "T019 must NOT fire when stack mentions RenderScript: {findings:?}"
    );
}

#[test]
fn stack_not_contains_passes_when_stack_absent() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    // No stack → T019 still fires (forbidden substring trivially absent).
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/system/lib64/libxhook.so"}"#,
        ],
    );
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "T019_native_lib_path_inspection");
    assert!(
        hit.is_some(),
        "T019 should fire on /system/lib64/* with no stack: {findings:?}"
    );
}

#[test]
fn t017_jit_cache_fires_after_threshold() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    let mut lines: Vec<String> = Vec::new();
    for i in 0..6 {
        lines.push(format!(
            r#"{{"ts_ns":{},"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"stack":"<JIT>+0x{:x}"}}"#,
            1_000_000_000u64 + (i as u64) * 500_000_000,
            0x1000 + i * 16,
        ));
    }
    let line_refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
    feed_lines(&mut engine, &line_refs);
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "T017_jit_cache_syscall");
    assert!(
        hit.is_some(),
        "T017 should fire after 5+ JIT-frame syscalls in 10s: {findings:?}"
    );
}

#[test]
fn default_ruleset_has_at_least_22_rules() {
    let engine = RuleEngine::with_default_rules().unwrap();
    assert!(
        engine.rule_count() >= 22,
        "expected >=22 default rules after T020-T022, got {}",
        engine.rule_count()
    );
}

#[test]
fn t020_anon_mapping_origin_fires_for_banking_app_pattern() {
    // Reproduces the V1.0.0 finding stack: /proc/self/maps from an
    // anonymous executable mapping. Should fire HIGH-severity T020 in
    // addition to (or instead of) T001.
    let mut engine = RuleEngine::with_default_rules().unwrap();
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/proc/self/maps","stack":"vfs_open+0x10 ;; [anon:1e80]+0x393d0 <- libc.so:__start_thread+0x48"}"#,
        ],
    );
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "T020_native_check_from_anon_mapping");
    assert!(
        hit.is_some(),
        "T020 should fire on /proc/self/maps from [anon: stack: {findings:?}"
    );
}

#[test]
fn t020_does_not_fire_when_stack_is_libc_only() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/proc/self/maps","stack":"vfs_open+0x10 ;; libc.so:open+0x12"}"#,
        ],
    );
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "T020_native_check_from_anon_mapping");
    assert!(
        hit.is_none(),
        "T020 must NOT fire without [anon: in stack: {findings:?}"
    );
}

#[test]
fn t021_frida_thread_comm_scan_fires_after_threshold() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    let mut lines: Vec<String> = Vec::new();
    for i in 0..5 {
        lines.push(format!(
            r#"{{"ts_ns":{},"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/proc/self/task/{}/comm"}}"#,
            1_000_000_000u64 + (i as u64) * 1_000_000_000,
            19236 + i,
        ));
    }
    let line_refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
    feed_lines(&mut engine, &line_refs);
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "T021_frida_thread_comm_scan");
    assert!(
        hit.is_some(),
        "T021 should fire after 5+ task/<TID>/comm reads: {findings:?}"
    );
}

#[test]
fn t021_does_not_fire_for_unrelated_proc_self_paths() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/proc/self/maps"}"#,
            r#"{"ts_ns":2000,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/proc/self/status"}"#,
        ],
    );
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "T021_frida_thread_comm_scan");
    assert!(
        hit.is_none(),
        "T021 must NOT fire on /proc/self/{{maps,status}}: {findings:?}"
    );
}

#[test]
fn t022_bpf_syscall_from_app_fires() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":10313,"nr":280,"name":"bpf","comm":"example.bankapp","enter":false,"ret":7,"args":[0,0,0,0,0,0]}"#,
        ],
    );
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "T022_unexpected_bpf_syscall");
    assert!(
        hit.is_some(),
        "T022 should fire for bpf() from a regular app: {findings:?}"
    );
}

#[test]
fn t022_does_not_fire_for_netd() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":1000,"nr":280,"name":"bpf","comm":"netd","enter":false,"ret":7,"args":[0,0,0,0,0,0]}"#,
        ],
    );
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "T022_unexpected_bpf_syscall");
    assert!(hit.is_none(), "T022 must NOT fire for netd: {findings:?}");
}

#[test]
fn prctl_pr_get_dumpable_fires() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    // arg0 = 3 = PR_GET_DUMPABLE
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":1000,"nr":167,"name":"prctl","comm":"app","enter":false,"ret":1,"args":[3,0,0,0,0,0]}"#,
        ],
    );
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "T010_prctl_dumpable_check");
    assert!(hit.is_some(), "T010 should fire for prctl(PR_GET_DUMPABLE)");
}

#[test]
fn dexprotector_ruleset_loads_as_full_pack() {
    let engine = load_dexprotector_engine();
    assert!(
        engine.rule_count() >= 30,
        "expected default rules plus DexProtector additions, got {}",
        engine.rule_count()
    );
    let rule_ids: Vec<_> = engine.rules().iter().map(|r| r.id.as_str()).collect();
    assert!(rule_ids.contains(&"T004_su_binary_probe"));
    assert!(rule_ids.contains(&"DP001_dexprotector_boot_libraries"));
    assert!(rule_ids.contains(&"DP008_dexprotector_startup_burst"));
}

#[test]
fn dp001_dexprotector_boot_library_probe_fires() {
    let mut engine = load_dexprotector_engine();
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":10313,"nr":56,"name":"openat","comm":"protected.app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/data/app/~~pkg/lib/arm64/libdexprotector.so"}"#,
        ],
    );
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "DP001_dexprotector_boot_libraries");
    assert!(
        hit.is_some(),
        "DP001 should fire on libdexprotector.so access: {findings:?}"
    );
}

#[test]
fn dp002_dexprotector_asset_blob_probe_fires() {
    let mut engine = load_dexprotector_engine();
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":10313,"nr":56,"name":"openat","comm":"protected.app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/data/app/pkg/base.apk/assets/se.dat"}"#,
        ],
    );
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "DP002_dexprotector_asset_blobs");
    assert!(
        hit.is_some(),
        "DP002 should fire on DexProtector asset blob access: {findings:?}"
    );
}

#[test]
fn dp004_dexprotector_proc_maps_rasp_fires_with_native_stack() {
    let mut engine = load_dexprotector_engine();
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":10313,"nr":56,"name":"openat","comm":"protected.app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/proc/self/maps","stack":"vfs_open+0x10 ;; libdp.so:check_environment+0x40 <- libc.so:open+0x12"}"#,
        ],
    );
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "DP004_dexprotector_proc_maps_rasp");
    assert!(
        hit.is_some(),
        "DP004 should fire on /proc/self/maps from libdp stack: {findings:?}"
    );
}

#[test]
fn t001_finding_carries_schema_v2_fields_through_engine() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    let lines = [
        r#"{"ts_ns":1000000000,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/proc/self/maps"}"#,
        r#"{"ts_ns":3000000000,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/proc/self/maps"}"#,
    ];
    feed_lines(&mut engine, &lines);
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "T001_proc_self_maps_polling")
        .expect("T001 should fire after threshold");

    assert_eq!(hit.behavior.as_deref(), Some("proc_self_maps_polling"));
    assert!(
        hit.interpretation
            .iter()
            .any(|s| s.contains("anti-instrumentation")),
        "expected anti-instrumentation interpretation, got {:?}",
        hit.interpretation
    );
    assert_eq!(hit.confidence, Some(0.85));
    assert!(
        hit.false_positives
            .iter()
            .any(|fp| fp.contains("crash reporters")),
        "expected crash-reporter FP note, got {:?}",
        hit.false_positives
    );
    // capture_health defaults to the "all good" baseline; the engine
    // doesn't wire live BPF counters yet (deferred to a follow-up).
    assert!(!hit.capture_health.path_truncated);
    assert!(hit.capture_health.stack_resolved);
    assert!(!hit.capture_health.drops_during_window);
}

#[test]
fn finding_json_includes_v2_fields_when_set_on_rule() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    let lines = [
        r#"{"ts_ns":1000000000,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/proc/self/maps"}"#,
        r#"{"ts_ns":3000000000,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/proc/self/maps"}"#,
    ];
    feed_lines(&mut engine, &lines);
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "T001_proc_self_maps_polling")
        .unwrap();
    let s = serde_json::to_string(hit).unwrap();
    assert!(s.contains(r#""behavior":"proc_self_maps_polling""#), "{s}");
    assert!(s.contains(r#""interpretation":["#), "{s}");
    assert!(s.contains(r#""confidence":0.85"#), "{s}");
    assert!(s.contains(r#""false_positives":["#), "{s}");
}

#[test]
fn finding_json_omits_v2_fields_when_unset() {
    // T002 has not been migrated to v2 yet; its emitted finding should not
    // include the new fields in JSON output.
    let mut engine = RuleEngine::with_default_rules().unwrap();
    feed_lines(
        &mut engine,
        &[
            r#"{"ts_ns":1000,"pid":7,"tid":7,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":4,"args":[0,0,0,0,0,0],"data":"/proc/self/mountinfo"}"#,
        ],
    );
    let findings = engine.drain_ready();
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "T002_mountinfo_magisk_check")
        .expect("T002 should fire on first mountinfo open");
    let s = serde_json::to_string(hit).unwrap();
    assert!(
        !s.contains(r#""behavior":"#),
        "T002 has no v2 behavior; JSON: {s}"
    );
    assert!(
        !s.contains(r#""confidence":"#),
        "T002 has no v2 confidence; JSON: {s}"
    );
    // false_positives and interpretation default to empty Vec, omitted by skip rule.
    assert!(
        !s.contains(r#""interpretation":["#),
        "expected omitted interpretation; got {s}"
    );
}
