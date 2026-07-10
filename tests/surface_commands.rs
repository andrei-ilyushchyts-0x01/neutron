use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use neutron::surface::{
    run, CaptureRecord, Device, DeviceIdentity, Evidence, Process, Relation, Service,
    SurfaceCommand, SurfaceExplainArgs, SurfaceHealth, SurfaceInputArgs, SurfaceProcessArgs,
    SurfaceReachableArgs, SurfaceScanArgs, SurfaceSnapshot,
};
use serde_json::Value;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "neutron-{label}-{}-{nonce}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).expect("create test directory");
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn minimal_snapshot() -> SurfaceSnapshot {
    let service_id = "service:binder:example.IExample/default";
    let process_id = "process:boot-test:42:100";
    SurfaceSnapshot {
        schema: "neutron.surface/v1".into(),
        neutron_version: "1.4.0".into(),
        collected_at: "2026-07-10T00:00:00Z".into(),
        device: DeviceIdentity {
            fingerprint: "example/fingerprint".into(),
            boot_id: "boot-test".into(),
        },
        health: SurfaceHealth::default(),
        services: vec![Service {
            id: service_id.into(),
            name: "example.IExample/default".into(),
            transport: "binder".into(),
            pid: Some(42),
            process_id: Some(process_id.into()),
            hal: true,
            confidence: "exact".into(),
            ..Service::default()
        }],
        processes: vec![Process {
            id: process_id.into(),
            pid: 42,
            uid: 10_123,
            gid: 10_123,
            cmdline: vec!["/vendor/bin/example".into()],
            executable: Some("/vendor/bin/example".into()),
            starttime: 100,
            boot_id: "boot-test".into(),
            selinux_domain: "u:r:hal_example_default:s0".into(),
            ..Process::default()
        }],
        devices: vec![Device {
            id: "device:char:10:1".into(),
            path: "/dev/example".into(),
            kind: "char".into(),
            major: 10,
            minor: 1,
            mode: 0o660,
            ..Device::default()
        }],
        modules: Vec::new(),
        relations: vec![Relation {
            id: "relation:package-service".into(),
            relation_type: "binder".into(),
            from: "package:com.example.app".into(),
            to: service_id.into(),
            evidence: Evidence {
                source: "capture".into(),
                detail: None,
            },
            confidence: "exact".into(),
            causal_relation: Some("exact".into()),
            trace_id: Some("0000000000000001".into()),
            scenario_id: Some("surface-observe".into()),
            span_id: Some("0000000000000010".into()),
            ioctl: None,
        }],
        captures: vec![CaptureRecord {
            id: "capture:0000000000000001:surface-observe".into(),
            trace_id: "0000000000000001".into(),
            scenario_id: "surface-observe".into(),
            root_package: Some("com.example.app".into()),
            root_uid: None,
            boot_id: Some("boot-test".into()),
            fingerprint: Some("example/fingerprint".into()),
            health: "complete".into(),
        }],
    }
}

fn input_args(input: &Path, output: &Path) -> SurfaceInputArgs {
    SurfaceInputArgs {
        input: input.to_string_lossy().into_owned(),
        output: Some(output.to_string_lossy().into_owned()),
    }
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("read command output"))
        .expect("command output is valid JSON")
}

fn assert_secure(path: &Path) {
    let mode = fs::metadata(path)
        .expect("output metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "{} must be mode 0600", path.display());
}

#[test]
fn query_command_variants_emit_secure_json_envelopes() {
    let temp = TestDir::new("surface-commands");
    let snapshot_path = temp.path("surface.json");
    fs::write(
        &snapshot_path,
        serde_json::to_vec_pretty(&minimal_snapshot()).unwrap(),
    )
    .expect("write input snapshot");

    let cases = vec![
        (
            "services",
            "services",
            SurfaceCommand::Services(input_args(&snapshot_path, &temp.path("services.json"))),
        ),
        (
            "hals",
            "hals",
            SurfaceCommand::Hals(input_args(&snapshot_path, &temp.path("hals.json"))),
        ),
        (
            "devices",
            "devices",
            SurfaceCommand::Devices(input_args(&snapshot_path, &temp.path("devices.json"))),
        ),
        (
            "process",
            "process",
            SurfaceCommand::Process(SurfaceProcessArgs {
                pid: 42,
                io: input_args(&snapshot_path, &temp.path("process.json")),
            }),
        ),
        (
            "explain",
            "entity",
            SurfaceCommand::Explain(SurfaceExplainArgs {
                selector: "example.IExample/default".into(),
                io: input_args(&snapshot_path, &temp.path("explain.json")),
            }),
        ),
        (
            "reachable",
            "nodes",
            SurfaceCommand::Reachable(SurfaceReachableArgs {
                from_package: Some("com.example.app".into()),
                from_uid: None,
                io: input_args(&snapshot_path, &temp.path("reachable.json")),
            }),
        ),
    ];

    for (name, field, command) in cases {
        let output = temp.path(&format!("{name}.json"));
        run(command).unwrap_or_else(|error| panic!("{name} command failed: {error:#}"));
        let envelope = read_json(&output);
        assert_eq!(envelope["schema"], "neutron.surface/query/v1");
        assert!(envelope.get(field).is_some(), "{name} omitted {field}");
        assert_secure(&output);
    }
}

#[test]
fn static_scan_with_real_reader_writes_a_secure_round_trip_snapshot() {
    let temp = TestDir::new("surface-real-scan");
    let output = temp.path("surface.json");

    run(SurfaceCommand::Scan(SurfaceScanArgs {
        capture: None,
        observe: None,
        from_package: None,
        from_uid: None,
        output: Some(output.to_string_lossy().into_owned()),
    }))
    .expect("static scan on Linux");

    let snapshot: SurfaceSnapshot =
        serde_json::from_slice(&fs::read(&output).expect("read scan output"))
            .expect("scan output is a surface snapshot");
    assert_eq!(snapshot.schema, "neutron.surface/v1");
    let round_trip: SurfaceSnapshot =
        serde_json::from_value(serde_json::to_value(&snapshot).unwrap()).unwrap();
    assert_eq!(round_trip, snapshot);
    assert_secure(&output);
}

#[test]
fn uid_queries_and_selector_errors_are_reported_as_json_command_errors() {
    let temp = TestDir::new("surface-query-edges");
    let snapshot_path = temp.path("surface.json");
    let mut snapshot = minimal_snapshot();
    snapshot.relations[0].from = "uid:10123".into();
    snapshot.captures[0].root_package = None;
    snapshot.captures[0].root_uid = Some(10_123);
    fs::write(&snapshot_path, serde_json::to_vec(&snapshot).unwrap()).unwrap();

    let reachable = temp.path("uid-reachable.json");
    run(SurfaceCommand::Reachable(SurfaceReachableArgs {
        from_package: None,
        from_uid: Some(10_123),
        io: input_args(&snapshot_path, &reachable),
    }))
    .unwrap();
    assert_eq!(read_json(&reachable)["root"], "uid:10123");

    let device = temp.path("device-explain.json");
    run(SurfaceCommand::Explain(SurfaceExplainArgs {
        selector: "/dev/example".into(),
        io: input_args(&snapshot_path, &device),
    }))
    .unwrap();
    assert_eq!(read_json(&device)["entity"]["kind"], "device");

    let missing_process = run(SurfaceCommand::Process(SurfaceProcessArgs {
        pid: 999,
        io: input_args(&snapshot_path, &temp.path("missing.json")),
    }))
    .unwrap_err();
    assert!(format!("{missing_process:#}").contains("not present"));

    let no_selector = run(SurfaceCommand::Reachable(SurfaceReachableArgs {
        from_package: None,
        from_uid: None,
        io: input_args(&snapshot_path, &temp.path("no-selector.json")),
    }))
    .unwrap_err();
    assert!(format!("{no_selector:#}").contains("exactly one"));

    let missing_entity = run(SurfaceCommand::Explain(SurfaceExplainArgs {
        selector: "absent".into(),
        io: input_args(&snapshot_path, &temp.path("absent.json")),
    }))
    .unwrap_err();
    assert!(format!("{missing_entity:#}").contains("did not match"));

    let mut ambiguous = snapshot;
    let mut reused = ambiguous.processes[0].clone();
    reused.id = "process:boot-test:42:101".into();
    reused.starttime = 101;
    ambiguous.processes.push(reused);
    ambiguous.devices[0]
        .aliases
        .push("example.IExample/default".into());
    fs::write(&snapshot_path, serde_json::to_vec(&ambiguous).unwrap()).unwrap();
    assert!(run(SurfaceCommand::Process(SurfaceProcessArgs {
        pid: 42,
        io: input_args(&snapshot_path, &temp.path("ambiguous-process.json")),
    }))
    .is_err());
    assert!(run(SurfaceCommand::Explain(SurfaceExplainArgs {
        selector: "example.IExample/default".into(),
        io: input_args(&snapshot_path, &temp.path("ambiguous-entity.json")),
    }))
    .is_err());
}

#[test]
fn capture_scan_degrades_mismatched_health_and_rejects_output_symlinks() {
    let temp = TestDir::new("surface-capture-command");
    let capture = temp.path("capture.ndjson");
    fs::write(
        &capture,
        concat!(
            "{\"type\":\"marker\",\"phase\":\"start\",\"name\":\"imported\",\"scenario_id\":\"imported\",\"trace_id\":\"trace-uid\",\"root_uid\":10123}\n",
            "{\"type\":\"capture_health\",\"degraded\":true,\"root_uid\":10123,\"boot_id\":\"different-boot\",\"fingerprint\":\"different/fingerprint\"}\n"
        ),
    )
    .unwrap();
    let output = temp.path("surface.json");
    run(SurfaceCommand::Scan(SurfaceScanArgs {
        capture: Some(capture.to_string_lossy().into_owned()),
        observe: None,
        from_package: None,
        from_uid: None,
        output: Some(output.to_string_lossy().into_owned()),
    }))
    .unwrap();
    let snapshot: SurfaceSnapshot = serde_json::from_value(read_json(&output)).unwrap();
    assert_eq!(snapshot.captures[0].health, "degraded");
    assert_eq!(snapshot.health.status, "degraded");

    let target = temp.path("target.json");
    let link = temp.path("output-link.json");
    fs::write(&target, b"untouched").unwrap();
    symlink(&target, &link).unwrap();
    let error = run(SurfaceCommand::Services(input_args(&output, &link))).unwrap_err();
    assert!(format!("{error:#}").contains("secure output"));
    assert_eq!(fs::read(&target).unwrap(), b"untouched");
}
