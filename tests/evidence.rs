use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

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

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn neutron() -> Command {
    Command::new(env!("CARGO_BIN_EXE_neutron"))
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn write_minimal_bundle(run: &Path, artifact: &[u8]) {
    fs::write(run.join("targets.json"), artifact).unwrap();
    fs::write(
        run.join("manifest.json"),
        concat!(
            "{\n",
            "  \"schema\": \"neutron.run-manifest/v1\",\n",
            "  \"run_kind\": \"surface_static\",\n",
            "  \"bpf\": {\"used\": false},\n",
            "  \"stimulus_executed\": false,\n",
            "  \"configuration_changed\": false,\n",
            "  \"collection\": {\"minimal\": true, \"full_snapshot_retained\": false}\n",
            "}\n",
        ),
    )
    .unwrap();
    let sums = format!(
        "{}  targets.json\n{}  manifest.json\n",
        digest(artifact),
        digest(&fs::read(run.join("manifest.json")).unwrap()),
    );
    fs::write(run.join("SHA256SUMS"), sums).unwrap();
}

#[test]
fn evidence_verify_detects_artifact_tampering() {
    let run = TestDir::new("evidence-verify");
    write_minimal_bundle(run.path(), b"[]\n");

    let valid = neutron()
        .args(["evidence", "verify"])
        .arg(run.path())
        .output()
        .expect("run evidence verify");
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stderr)
    );

    fs::write(run.path().join("targets.json"), b"tampered\n").unwrap();
    let tampered = neutron()
        .args(["evidence", "verify"])
        .arg(run.path())
        .output()
        .expect("run tampered evidence verify");
    assert!(!tampered.status.success());
    assert!(String::from_utf8_lossy(&tampered.stderr).contains("targets.json"));
}

#[test]
fn evidence_verify_rejects_traversal_paths() {
    let run = TestDir::new("evidence-traversal");
    write_minimal_bundle(run.path(), b"[]\n");
    fs::write(
        run.path().join("SHA256SUMS"),
        format!("{}  ../outside\n", digest(b"outside")),
    )
    .unwrap();

    let output = neutron()
        .args(["evidence", "verify"])
        .arg(run.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsafe artifact path"));
}

#[test]
fn external_probe_import_is_typed_and_content_addressed() {
    let run = TestDir::new("evidence-import");
    let input = run.path().join("probe-result.json");
    fs::write(&input, b"{\"lookup\":\"denied\"}\n").unwrap();

    let output = neutron()
        .args([
            "evidence",
            "import",
            "--run-dir",
            run.path().to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--id",
            "ccc-direct-lookup",
            "--claim",
            "call-denied",
            "--imported-from",
            "authorized-app-probe",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let annotation: serde_json::Value = serde_json::from_slice(
        &fs::read(run.path().join("external-evidence/ccc-direct-lookup.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(annotation["schema"], "neutron.external-evidence/v1");
    assert_eq!(annotation["measured_by"], "external_probe");
    assert_eq!(annotation["claim_type"], "call_denied");
    assert_eq!(annotation["imported_from"], "authorized-app-probe");
    assert_eq!(
        annotation["artifact_sha256"],
        digest(b"{\"lookup\":\"denied\"}\n")
    );
}

#[test]
fn not_observed_clean_requires_complete_health() {
    let run = TestDir::new("evidence-negative-gate");
    let input = run.path().join("probe-result.json");
    fs::write(&input, b"{}\n").unwrap();

    let output = neutron()
        .args([
            "evidence",
            "import",
            "--run-dir",
            run.path().to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--id",
            "negative-observation",
            "--claim",
            "not-observed-clean",
            "--imported-from",
            "authorized-app-probe",
            "--health-status",
            "degraded",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("not_observed_clean requires complete health"));
}
