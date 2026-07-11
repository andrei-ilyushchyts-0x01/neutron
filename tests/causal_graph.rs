use std::io::Cursor;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

use clap::Parser;
use neutron::binder_services::{
    parse_lshal, AttributionConfidence, BinderCatalog, BinderMethodMap, BinderServiceMap,
};
use neutron::causal::{
    enrich_json, CausalMetadata, CausalRelation, CausalWire, ControlServer, MarkRequest,
    ScenarioState,
};
use neutron::cli::{Cli, Command};
use neutron::graph::{render_mermaid_from_reader, GraphOptions};
use neutron::SyscallEvent;

#[test]
fn trace_subcommand_and_legacy_trace_flags_are_both_accepted() {
    let legacy = Cli::try_parse_from(["neutron", "--pid", "42"]).expect("legacy trace CLI");
    assert!(legacy.command.is_none());
    assert_eq!(legacy.args.pid, 42);

    let explicit = Cli::try_parse_from([
        "neutron",
        "trace",
        "--package",
        "com.example.app",
        "--follow-services",
        "--follow-hal",
        "--max-depth",
        "4",
        "--max-processes",
        "64",
    ])
    .expect("explicit trace CLI");
    let Command::Trace(args) = explicit.command.expect("trace subcommand") else {
        panic!("wrong subcommand")
    };
    assert_eq!(args.package.as_deref(), Some("com.example.app"));
    assert!(
        args.follow_binder,
        "service/HAL discovery implies Binder follow"
    );
    assert_eq!(args.max_depth, 4);
    assert_eq!(args.max_processes, 64);
}

#[test]
fn max_processes_accepts_documented_bounds_only() {
    for accepted in ["1", "1024"] {
        Cli::try_parse_from(["neutron", "trace", "--max-processes", accepted])
            .unwrap_or_else(|e| panic!("{accepted} should be valid: {e}"));
    }
    for rejected in ["0", "1025"] {
        assert!(
            Cli::try_parse_from(["neutron", "trace", "--max-processes", rejected]).is_err(),
            "{rejected} should be rejected"
        );
    }
}

#[test]
fn syscall_wire_preserves_generation_parent_and_relation_across_enter_exit() {
    let mut enter = SyscallEvent {
        pid: 200,
        tgid: 201,
        syscall_nr: 29,
        enter_timestamp_ns: 123,
        maps_generation: 7,
        ..SyscallEvent::default()
    };
    CausalWire::new(42, CausalRelation::Exact, 2).write_to(&mut enter);

    let mut exit = SyscallEvent {
        pid: enter.pid,
        tgid: enter.tgid,
        syscall_nr: enter.syscall_nr,
        enter_timestamp_ns: enter.enter_timestamp_ns,
        maps_generation: enter.maps_generation,
        ..SyscallEvent::default()
    };
    CausalWire::from_event(&enter).write_to(&mut exit);

    assert_eq!(CausalWire::from_event(&exit).parent_debug_id, 42);
    assert_eq!(
        CausalWire::from_event(&exit).relation,
        CausalRelation::Exact
    );
    assert_eq!(CausalWire::from_event(&exit).depth, 2);
    let generation = { exit.maps_generation };
    assert_eq!(generation, 7);
}

#[test]
fn scenario_lifecycle_rejects_nested_duplicate_and_mismatched_markers() {
    let mut state = ScenarioState::default();
    let started = state.start_with_trace_id("camera", 0x1234).expect("start");
    assert_eq!(started.generation, 1);
    assert_eq!(started.trace_id, 0x1234);
    assert!(state.start_with_trace_id("nested", 2).is_err());
    assert!(state.end("wrong").is_err());
    let ended = state.end("camera").expect("matching end");
    assert_eq!(ended.scenario_id, "camera");
    assert!(state.end("camera").is_err());
}

#[test]
fn causal_json_has_stable_pair_span_and_honest_relation() {
    let meta = CausalMetadata {
        scenario_id: "camera".into(),
        trace_id: 0x1234,
        span_id: 0xabcd,
        parent_span_id: 0x55,
        depth: 2,
        relation: CausalRelation::Inferred,
        root_package: Some("com.example.app".into()),
        root_uid: None,
    };
    let line = enrich_json(r#"{"type":"syscall","phase":"exit"}"#, &meta).unwrap();
    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(value["scenario_id"], "camera");
    assert_eq!(value["trace_id"], "0000000000001234");
    assert_eq!(value["span_id"], "000000000000abcd");
    assert_eq!(value["parent_span_id"], "0000000000000055");
    assert_eq!(value["depth"], 2);
    assert_eq!(value["causal_relation"], "inferred");
    assert!(value.get("root_uid").is_none());
}

#[test]
fn service_and_lshal_catalogs_keep_ambiguous_candidates_honest() {
    let mut catalog = BinderCatalog::default();
    catalog.merge_service_list(
        "0 activity: [android.app.IActivityManager] pid=200\n\
         1 package: [android.content.pm.IPackageManager] pid=200\n",
    );
    catalog.merge_lshal("android.hardware.camera.provider@2.7::ICameraProvider/default 4/4 300\n");
    assert_eq!(
        parse_lshal("android.hardware.camera.provider@2.7::ICameraProvider/default 4/4 300\n")
            .get(&300)
            .unwrap(),
        &vec!["android.hardware.camera.provider@2.7::ICameraProvider/default".to_string()]
    );

    let exact = BinderServiceMap::from_json(r#"{"300":{"7":"verified.camera/default"}}"#).unwrap();
    let methods =
        BinderMethodMap::from_json(r#"{"verified.camera/default":{"1":"connect"}}"#).unwrap();

    let ambiguous = catalog.resolve(&exact, &methods, 200, 1, 9);
    assert_eq!(ambiguous.service, None);
    assert_eq!(ambiguous.candidates, vec!["activity", "package"]);
    assert_eq!(ambiguous.confidence, Some(AttributionConfidence::Candidate));
    assert_eq!(ambiguous.method, None);

    let verified = catalog.resolve(&exact, &methods, 300, 7, 1);
    assert_eq!(verified.service.as_deref(), Some("verified.camera/default"));
    assert_eq!(verified.method.as_deref(), Some("connect"));
    assert_eq!(verified.confidence, Some(AttributionConfidence::Exact));

    let unknown_code = catalog.resolve(&exact, &methods, 300, 7, 99);
    assert_eq!(unknown_code.method_label(), "code=99");
}

#[test]
fn control_socket_round_trips_one_validated_marker_request() {
    let path = std::env::temp_dir().join(format!(
        "neutron-control-{}-{}.sock",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = std::fs::remove_file(&path);
    let server = ControlServer::bind(&path).expect("bind control socket");
    let server_thread = thread::spawn(move || {
        for _ in 0..100 {
            if let Some(pending) = server.try_recv().expect("accept request") {
                assert_eq!(pending.request.name, "camera");
                assert_eq!(pending.request.phase, "start");
                pending.respond_ok(99, 1, 0x1234).expect("response");
                return;
            }
            thread::sleep(Duration::from_millis(2));
        }
        panic!("control request not received")
    });

    let response = neutron::causal::send_mark_request(
        &path,
        &MarkRequest {
            name: "camera".into(),
            phase: "start".into(),
            meta: Default::default(),
        },
    )
    .expect("control response");
    assert!(response.ok);
    assert_eq!(response.ts_ns, Some(99));
    server_thread.join().unwrap();
    let _ = std::fs::remove_file(&path);
}

#[test]
fn stalled_control_client_is_rejected_without_failing_server() {
    let path =
        std::env::temp_dir().join(format!("neutron-control-stall-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let server = ControlServer::bind(&path).expect("bind control socket");
    let _stalled = UnixStream::connect(&path).expect("connect stalled client");
    assert!(
        server
            .try_recv()
            .expect("stalled client is non-fatal")
            .is_none(),
        "an incomplete request must not become a marker"
    );
    drop(server);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn causal_graph_merges_pairs_and_uses_solid_and_dotted_edges() {
    let capture = r#"
{"type":"marker","phase":"start","name":"camera","scenario_id":"camera","trace_id":"0000000000001234","root_package":"com.example.app"}
{"type":"binder","ts_ns":10,"pid":100,"comm":"app","to_proc":200,"target_node":7,"code":1,"debug_id":11,"span_id":"00000000000000b1","parent_span_id":"00000000000000a1","trace_id":"0000000000001234","scenario_id":"camera","depth":1,"causal_relation":"exact"}
{"type":"binder_call","ts_ns":10,"debug_id":11,"caller_pid":100,"caller_comm":"app","callee_pid":200,"target_node":7,"code":1,"service":"camera/default","method":"connect","latency_us":5,"status":"completed"}
{"type":"syscall","ts_ns":20,"enter_ts_ns":20,"pid":200,"tid":201,"comm":"camera-hal","nr":29,"name":"ioctl","phase":"enter","span_id":"00000000000000c1","parent_span_id":"00000000000000b1","trace_id":"0000000000001234","scenario_id":"camera","depth":2,"causal_relation":"exact","ioctl_name":"VIDIOC_QBUF"}
{"type":"syscall","ts_ns":30,"enter_ts_ns":20,"pid":200,"tid":201,"comm":"camera-hal","nr":29,"name":"ioctl","phase":"exit","span_id":"00000000000000c1","parent_span_id":"00000000000000b1","trace_id":"0000000000001234","scenario_id":"camera","depth":2,"causal_relation":"exact","ioctl_name":"VIDIOC_QBUF","ret":0,"latency_us":10}
{"type":"process_exit","ts_ns":40,"pid":200,"comm":"camera-hal","classification":"crash","signal_name":"SIGSEGV","span_id":"00000000000000d1","parent_span_id":"00000000000000b1","trace_id":"0000000000001234","scenario_id":"camera","depth":2,"causal_relation":"inferred"}
{"type":"marker","phase":"end","name":"camera","scenario_id":"camera","trace_id":"0000000000001234"}
"#;
    let mermaid = render_mermaid_from_reader(
        Cursor::new(capture),
        &GraphOptions {
            root_package: Some("com.example.app".into()),
        },
    )
    .expect("render graph");

    assert!(mermaid.starts_with("flowchart TD\n"));
    assert_eq!(
        mermaid.matches("VIDIOC_QBUF").count(),
        1,
        "enter+exit merged"
    );
    assert_eq!(mermaid.matches("camera/default.connect").count(), 1);
    assert!(
        mermaid.contains(" --> "),
        "exact edge should be solid: {mermaid}"
    );
    assert!(
        mermaid.contains(" -. inferred .-> "),
        "inferred edge should be dotted: {mermaid}"
    );
    assert!(!mermaid.contains("Invalid or unsupported diagram"));
}

#[test]
fn old_capture_gets_process_edges_and_causal_warning() {
    let capture = r#"
{"type":"binder","ts_ns":10,"pid":100,"comm":"app","to_proc":200,"target_node":7,"code":1,"debug_id":11}
{"type":"syscall","ts_ns":20,"pid":200,"tid":201,"comm":"hal","nr":29,"name":"ioctl","phase":"exit","ret":0}
"#;
    let mermaid = render_mermaid_from_reader(Cursor::new(capture), &GraphOptions::default())
        .expect("render legacy graph");
    assert!(mermaid.starts_with("flowchart TD\n"));
    assert!(mermaid.contains("%% WARNING:"));
    assert!(mermaid.contains("p_100 --> b_"));
    assert!(mermaid.contains("p_200 --> s_"));
}

#[test]
fn concurrent_binder_calls_remain_separate_spans() {
    let capture = r#"
{"type":"binder","pid":10,"comm":"app","to_proc":20,"debug_id":1,"code":7,"target_node":1,"trace_id":"0000000000000001","span_id":"0000000000000011","parent_span_id":"0000000000000010","depth":1,"causal_relation":"exact"}
{"type":"binder","pid":10,"comm":"app","to_proc":30,"debug_id":2,"code":8,"target_node":2,"trace_id":"0000000000000001","span_id":"0000000000000012","parent_span_id":"0000000000000010","depth":1,"causal_relation":"exact"}
{"type":"binder_call","debug_id":1,"caller_pid":10,"callee_pid":20,"code":7,"target_node":1,"service":"svc.one","status":"completed"}
{"type":"binder_call","debug_id":2,"caller_pid":10,"callee_pid":30,"code":8,"target_node":2,"service":"svc.two","status":"completed"}
"#;
    let graph = render_mermaid_from_reader(Cursor::new(capture), &GraphOptions::default()).unwrap();
    assert_eq!(graph.matches("svc.one code=7").count(), 1);
    assert_eq!(graph.matches("svc.two code=8").count(), 1);
    assert!(graph.contains("b_00000001"));
    assert!(graph.contains("b_00000002"));
}

#[test]
fn one_way_process_context_is_rendered_as_inferred() {
    let capture = r#"
{"type":"syscall","pid":20,"tid":21,"comm":"oneway-hal","nr":29,"name":"ioctl","phase":"exit","ts_ns":2,"enter_ts_ns":1,"trace_id":"0000000000000001","span_id":"0000000000000020","parent_span_id":"0000000000000011","depth":1,"causal_relation":"inferred"}
"#;
    let graph = render_mermaid_from_reader(Cursor::new(capture), &GraphOptions::default()).unwrap();
    assert!(graph.contains("-. inferred .->"));
}

#[test]
fn process_limit_is_preserved_as_mermaid_warning() {
    let capture = r#"
{"type":"capture_health","traced_process_limit":3,"binder_depth_limit":1,"binder_follow_failed":2}
{"type":"syscall","pid":10,"tid":10,"name":"ioctl","phase":"exit","ts_ns":1}
"#;
    let graph = render_mermaid_from_reader(Cursor::new(capture), &GraphOptions::default()).unwrap();
    assert!(graph.contains("traced process limit"));
    assert!(graph.contains("Binder depth limit"));
    assert!(graph.contains("Binder follow failure"));
    assert!(!graph.contains("Invalid or unsupported diagram"));
}

#[test]
fn graph_keeps_callee_identity_device_path_and_generic_loss_warnings() {
    let capture = r#"
{"type":"binder","ts_ns":10,"pid":100,"comm":"app","to_proc":200,"debug_id":11,"code":1,"trace_id":"trace-a","span_id":"binder-1","causal_relation":"exact"}
{"type":"binder_received","ts_ns":11,"pid":200,"comm":"camera-hal","debug_id":11,"trace_id":"trace-a","span_id":"binder-1","causal_relation":"exact"}
{"type":"binder_call","debug_id":11,"caller_pid":100,"callee_pid":200,"code":1,"trace_id":"trace-a","span_id":"binder-1","status":"completed","causal_relation":"exact"}
{"type":"syscall","pid":200,"tid":201,"comm":"camera-hal","name":"ioctl","nr":29,"phase":"exit","ret":0,"fd_path":"/dev/video0","ioctl_name":"VIDIOC_QBUF","trace_id":"trace-a","span_id":"ioctl-1","parent_span_id":"binder-1","causal_relation":"exact"}
{"type":"capture_health","degraded":true,"output_cap_hit":true,"ringbuf_reserve_failed":9}
"#;

    let graph = render_mermaid_from_reader(Cursor::new(capture), &GraphOptions::default()).unwrap();
    assert!(graph.contains("camera-hal (pid 200)"), "{graph}");
    assert!(graph.contains("/dev/video0"), "{graph}");
    assert!(graph.contains("output cap"), "{graph}");
    assert!(graph.contains("ring buffer"), "{graph}");
}
