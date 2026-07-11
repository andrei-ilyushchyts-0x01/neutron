use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use neutron::cli::{Cli, Command, HarnessCommand};
use neutron::harness::{self, ExtractArgs, HARNESS_SCHEMA};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn temp_dir(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "neutron-harness-{name}-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn write_blob(capture: &Path, bytes: &[u8]) -> String {
    let digest = format!("{:x}", Sha256::digest(bytes));
    let blob_dir = PathBuf::from(format!("{}.blobs", capture.display()));
    fs::create_dir_all(&blob_dir).unwrap();
    fs::write(blob_dir.join(&digest), bytes).unwrap();
    digest
}

fn capture_line(event_id: u64, digest: &str, status: &str) -> Value {
    json!({
        "type": "syscall",
        "event_id": event_id,
        "pid": 42,
        "uid": 10123,
        "name": "ioctl",
        "phase": "enter",
        "args": [7, 3222823425u32, 4096, 0, 0, 0],
        "fd_path": "/dev/sample0",
        "trace_id": "trace-a",
        "span_id": "ioctl-a",
        "parent_span_id": "binder-a",
        "harness_ref": {
            "schema": "neutron.harness-ref/v1",
            "kind": "ioctl",
            "status": status,
            "sha256": digest,
            "length": 8,
            "resources": [],
            "identity": {
                "serial": "USB123",
                "fingerprint": "google/husky/test:user/release-keys",
                "boot_id": "boot-a",
                "uid": 10123,
                "domain": "u:r:untrusted_app:s0"
            }
        }
    })
}

#[test]
fn cli_registers_harness_commands_and_capture_guard() {
    let cli = Cli::try_parse_from([
        "neutron",
        "harness",
        "extract",
        "capture.ndjson",
        "--event-id",
        "7",
        "--output",
        "case",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Harness(HarnessCommand::Extract(_)))
    ));

    let cli = Cli::try_parse_from([
        "neutron",
        "--harness-capture",
        "--pid",
        "42",
        "--output",
        "capture.ndjson",
    ])
    .unwrap();
    assert!(cli.args.harness_capture);
}

#[test]
fn extract_writes_portable_artifact_contract() {
    let root = temp_dir("extract");
    let capture = root.join("capture.ndjson");
    let input = b"abcdefgh";
    let digest = write_blob(&capture, input);
    let predecessor = json!({
        "type": "binder",
        "event_id": 6,
        "pid": 20,
        "to_proc": 42,
        "span_id": "binder-a",
        "service": "sample.IService/default"
    });
    let health = json!({
        "type": "capture_health",
        "root_package": "com.example.app",
        "root_uid": 10123,
        "boot_id": "boot-a",
        "fingerprint": "google/husky/test:user/release-keys"
    });
    fs::write(
        &capture,
        format!(
            "{}\n{}\n{}\n",
            predecessor,
            capture_line(7, &digest, "complete"),
            health
        ),
    )
    .unwrap();

    let output = root.join("case");
    harness::extract(ExtractArgs {
        capture,
        event_id: 7,
        output: output.clone(),
    })
    .unwrap();

    for name in [
        "metadata.json",
        "resources.json",
        "input.bin",
        "replay.rs",
        "runner.json",
        "setup.sh",
        "README.md",
    ] {
        assert!(output.join(name).is_file(), "missing {name}");
    }
    assert_eq!(fs::read(output.join("input.bin")).unwrap(), input);
    let metadata: Value =
        serde_json::from_slice(&fs::read(output.join("metadata.json")).unwrap()).unwrap();
    assert_eq!(metadata["schema"], HARNESS_SCHEMA);
    assert_eq!(metadata["selected_event_id"], 7);
    assert_eq!(metadata["replay_status"], "ready");
    assert_eq!(metadata["steps"][0]["event_id"], 6);
    assert_eq!(metadata["steps"][1]["event_id"], 7);
    assert_eq!(metadata["required_identity"]["package"], "com.example.app");
    let runner: Value =
        serde_json::from_slice(&fs::read(output.join("runner.json")).unwrap()).unwrap();
    assert_eq!(runner["transport"], "adb");
    assert_eq!(runner["capabilities"], json!([]));
    assert_eq!(runner["execute"][0], "{artifact}/replay");
    assert_eq!(runner["execute"][1], "{artifact}/input.bin");
    let compiled = std::process::Command::new("rustc")
        .arg("--edition=2021")
        .arg(output.join("replay.rs"))
        .arg("-o")
        .arg(output.join("replay-host-check"))
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "generated replay.rs did not compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
}

#[test]
fn extract_rejects_duplicate_ids_missing_blobs_hash_mismatches_and_unknown_ref_fields() {
    let root = temp_dir("invalid");
    let capture = root.join("capture.ndjson");
    let digest = "00".repeat(32);

    let duplicate = format!(
        "{}\n{}\n",
        capture_line(7, &digest, "complete"),
        capture_line(7, &digest, "complete")
    );
    fs::write(&capture, duplicate).unwrap();
    let error = harness::extract(ExtractArgs {
        capture: capture.clone(),
        event_id: 7,
        output: root.join("duplicate"),
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("duplicate event_id"), "{error}");

    fs::write(
        &capture,
        format!("{}\n", capture_line(7, &digest, "complete")),
    )
    .unwrap();
    let error = harness::extract(ExtractArgs {
        capture: capture.clone(),
        event_id: 7,
        output: root.join("missing"),
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("missing blob"), "{error}");

    write_blob(&capture, b"wrong contents");
    let blob_dir = PathBuf::from(format!("{}.blobs", capture.display()));
    fs::write(blob_dir.join(&digest), b"wrong contents").unwrap();
    let error = harness::extract(ExtractArgs {
        capture: capture.clone(),
        event_id: 7,
        output: root.join("mismatch"),
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("hash mismatch"), "{error}");

    let mut line = capture_line(7, &digest, "complete");
    line["harness_ref"]["future"] = json!(true);
    fs::write(&capture, format!("{line}\n")).unwrap();
    let error = harness::extract(ExtractArgs {
        capture,
        event_id: 7,
        output: root.join("unknown"),
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("unknown field"), "{error}");

    let oversized = root.join("oversized.ndjson");
    fs::write(&oversized, vec![b' '; 4 * 1024 * 1024 + 1]).unwrap();
    let error = harness::extract(ExtractArgs {
        capture: oversized,
        event_id: 7,
        output: root.join("oversized"),
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("exceeds"), "{error}");
}

#[test]
fn truncated_capture_extracts_as_blocked_not_partially_replayable() {
    let root = temp_dir("blocked");
    let capture = root.join("capture.ndjson");
    let digest = write_blob(&capture, b"abcdefgh");
    fs::write(
        &capture,
        format!("{}\n", capture_line(9, &digest, "truncated")),
    )
    .unwrap();
    let output = root.join("case");
    harness::extract(ExtractArgs {
        capture,
        event_id: 9,
        output: output.clone(),
    })
    .unwrap();
    let metadata: Value =
        serde_json::from_slice(&fs::read(output.join("metadata.json")).unwrap()).unwrap();
    assert_eq!(metadata["replay_status"], "blocked");
    assert!(metadata["blocked_reasons"][0]
        .as_str()
        .unwrap()
        .contains("truncated"));
}
