use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use neutron::run_manifest::{
    finalize_bundle, write_artifact, write_targets, DeviceIdentity, ResearchModel, RunCollection,
    RunHealth, RunHealthStatus, RunManifest, StaticSurfaceManifest, ToolIdentity,
};
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
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("make test directory private");
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

fn write_probe_identity(directory: &Path) -> PathBuf {
    let path = directory.join("probe-runtime.json");
    let identity = serde_json::json!({
        "schema": "neutron.external-probe-runtime/v1",
        "apk_sha256": "a".repeat(64),
        "signing_certificate_sha256": "b".repeat(64),
        "package": "dev.neutron.probe",
        "version_code": 1,
        "version_name": "1.0",
        "target_sdk": 35,
        "device_boot_id": "12345678-1234-1234-1234-123456789abc",
        "uid": 10123,
        "install_state": "installed_enabled",
        "granted_permissions": ["android.permission.DUMP"]
    });
    fs::write(&path, serde_json::to_vec_pretty(&identity).unwrap()).unwrap();
    path
}

fn write_minimal_bundle(run: &Path) {
    let targets = vec![
        "vendor.example.IExample/default".to_string(),
        "vendor.google.bluetooth_ext.IBluetoothCcc/default".to_string(),
    ];
    let target_artifact = write_targets(run, &targets).unwrap();
    let provenance_reasons: Vec<_> = ToolIdentity::current()
        .unwrap()
        .provenance_issues()
        .into_iter()
        .map(|issue| format!("tool provenance unknown: {issue}"))
        .collect();
    let health_status = if provenance_reasons.is_empty() {
        "complete"
    } else {
        "unknown"
    };
    let coverage = serde_json::json!({
        "schema": "neutron.surface-coverage/v1",
        "neutron_version": env!("CARGO_PKG_VERSION"),
        "collected_at": "2026-07-17T00:00:00Z",
        "device": {
            "fingerprint": "",
            "boot_id": "12345678-1234-1234-1234-123456789abc"
        },
        "collection": {
            "target_count": 2,
            "minimal": true,
            "full_snapshot_retained": false
        },
        "repeat": {"count": 1, "semantic_drift": []},
        "health": {"status": health_status, "warnings": provenance_reasons},
        "summary": {"exact": 0, "unresolved": 2, "ambiguous": 0},
        "rows": targets.iter().map(|endpoint| {
            let excerpt = format!("format=aidl transport=binder endpoint={endpoint}");
            serde_json::json!({
                "endpoint": endpoint,
                "declared": true,
                "live": false,
                "transport": "binder",
                "attribution": {
                    "confidence": "unresolved",
                    "sources": [{
                        "measured_by": "neutron",
                        "collector": "vintf",
                        "source": "/vendor/etc/vintf/manifest.xml",
                        "evidence": excerpt,
                        "evidence_sha256": digest(excerpt.as_bytes()),
                        "source_sha256": digest(b"sanitized-vintf-fixture")
                    }]
                }
            })
        }).collect::<Vec<_>>()
    });
    let mut coverage_bytes = serde_json::to_vec_pretty(&coverage).unwrap();
    coverage_bytes.push(b'\n');
    let coverage_artifact = write_artifact(run, "surface.coverage.json", &coverage_bytes).unwrap();
    let manifest = RunManifest::static_surface(StaticSurfaceManifest {
        run_id: "evidence-test".into(),
        started_at: "2026-07-17T00:00:00Z".into(),
        completed_at: "2026-07-17T00:00:01Z".into(),
        device: DeviceIdentity {
            boot_id: Some("12345678-1234-1234-1234-123456789abc".into()),
            ..DeviceIdentity::default()
        },
        research_model: ResearchModel {
            observer_privilege: "test".into(),
            attacker_capability: "ordinary_installed_app".into(),
        },
        collection: RunCollection {
            target_count: 2,
            minimal: true,
            full_snapshot_retained: false,
            repeat: 1,
        },
        health: RunHealth {
            status: if provenance_reasons.is_empty() {
                RunHealthStatus::Complete
            } else {
                RunHealthStatus::Unknown
            },
            reasons: provenance_reasons,
        },
        artifacts: vec![target_artifact, coverage_artifact],
    })
    .unwrap();
    finalize_bundle(run, &manifest).unwrap();
}

#[test]
fn evidence_verify_detects_artifact_tampering() {
    let run = TestDir::new("evidence-verify");
    write_minimal_bundle(run.path());

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
fn evidence_verify_rejects_invalid_manifest_claims_even_when_rehashed() {
    let run = TestDir::new("evidence-manifest-contract");
    write_minimal_bundle(run.path());
    let path = run.path().join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    manifest["bpf_loaded"] = serde_json::Value::Bool(true);
    fs::write(&path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    neutron::evidence::refresh_checksums(run.path()).unwrap();

    let output = neutron()
        .args(["evidence", "verify"])
        .arg(run.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("incompatible runtime side effect"));
}

#[test]
fn evidence_verify_rejects_traversal_paths() {
    let run = TestDir::new("evidence-traversal");
    write_minimal_bundle(run.path());
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
    write_minimal_bundle(run.path());
    let source = TestDir::new("evidence-import-source");
    let input = source.path().join("probe-result.json");
    fs::write(&input, b"{\"lookup\":\"denied\"}\n").unwrap();
    let probe_identity = write_probe_identity(source.path());

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
            "--subject-id",
            "service:binder:vendor.google.bluetooth_ext.IBluetoothCcc/default",
            "--claim-scope",
            r#"{"procedure":"direct_call","caller":"ordinary_installed_app","attempt_count":1}"#,
            "--probe-identity",
            probe_identity.to_str().unwrap(),
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
    assert_eq!(annotation["claim_scope"]["procedure"], "direct_call");
    assert_eq!(
        annotation["claim_scope"]["caller"],
        "ordinary_installed_app"
    );
    assert_eq!(annotation["claim_scope"]["attempt_count"], 1);
    assert_eq!(annotation["probe_identity"]["package"], "dev.neutron.probe");
    assert_eq!(annotation["probe_identity"]["uid"], 10123);
    assert_eq!(
        annotation["probe_identity"]["install_state"],
        "installed_enabled"
    );
    assert_eq!(
        annotation["subject_id"],
        "service:binder:vendor.google.bluetooth_ext.IBluetoothCcc/default"
    );
    assert_eq!(
        annotation["artifact_sha256"],
        digest(b"{\"lookup\":\"denied\"}\n")
    );
}

#[test]
fn duplicate_import_preserves_existing_evidence_and_bundle_integrity() {
    let run = TestDir::new("evidence-duplicate-import");
    write_minimal_bundle(run.path());
    let source = TestDir::new("evidence-duplicate-import-source");
    let first_input = source.path().join("first.json");
    let second_input = source.path().join("second.json");
    fs::write(&first_input, b"{\"result\":\"first\"}\n").unwrap();
    fs::write(&second_input, b"{\"result\":\"second\"}\n").unwrap();
    let probe_identity = write_probe_identity(source.path());

    let import = |input: &Path| {
        neutron()
            .args([
                "evidence",
                "import",
                "--run-dir",
                run.path().to_str().unwrap(),
                "--input",
                input.to_str().unwrap(),
                "--id",
                "stable-result",
                "--claim",
                "call-succeeded",
                "--imported-from",
                "authorized-app-probe",
                "--subject-id",
                "service:binder:vendor.example.IExample/default",
                "--probe-identity",
                probe_identity.to_str().unwrap(),
            ])
            .output()
            .unwrap()
    };
    assert!(import(&first_input).status.success());
    let artifact_path = run.path().join("external-evidence/stable-result.artifact");
    let annotation_path = run.path().join("external-evidence/stable-result.json");
    let original_artifact = fs::read(&artifact_path).unwrap();
    let original_annotation = fs::read(&annotation_path).unwrap();

    let duplicate = import(&second_input);
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already exists"));
    assert_eq!(fs::read(&artifact_path).unwrap(), original_artifact);
    assert_eq!(fs::read(&annotation_path).unwrap(), original_annotation);

    let verified = neutron()
        .args(["evidence", "verify"])
        .arg(run.path())
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
}

#[test]
fn not_observed_clean_requires_complete_health() {
    let run = TestDir::new("evidence-negative-gate");
    write_minimal_bundle(run.path());
    let source = TestDir::new("evidence-negative-source");
    let input = source.path().join("probe-result.json");
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
            "--subject-id",
            "service:binder:vendor.example.IExample/default",
            "--health-status",
            "degraded",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("not_observed_clean requires complete health"));
}

#[test]
fn behavioral_app_claim_requires_runtime_probe_identity() {
    let run = TestDir::new("evidence-probe-identity-gate");
    write_minimal_bundle(run.path());
    let source = TestDir::new("evidence-probe-identity-source");
    let input = source.path().join("probe-result.json");
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
            "call-without-identity",
            "--claim",
            "call-succeeded",
            "--imported-from",
            "authorized-app-probe",
            "--subject-id",
            "service:binder:vendor.example.IExample/default",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("behavioral app evidence requires --probe-identity"));
}

#[test]
fn behavioral_app_claim_rejects_unusable_probe_install_identity() {
    let run = TestDir::new("evidence-invalid-probe-identity");
    write_minimal_bundle(run.path());
    let source = TestDir::new("evidence-invalid-probe-identity-source");
    let input = source.path().join("probe-result.json");
    fs::write(&input, b"{}\n").unwrap();
    let probe_identity = source.path().join("disabled-probe.json");
    fs::write(
        &probe_identity,
        serde_json::to_vec(&serde_json::json!({
            "schema": "neutron.external-probe-runtime/v1",
            "apk_sha256": "a".repeat(64),
            "signing_certificate_sha256": "b".repeat(64),
            "package": "dev.neutron.probe",
            "version_code": 1,
            "version_name": "1.0",
            "target_sdk": 35,
            "device_boot_id": "12345678-1234-1234-1234-123456789abc",
            "uid": 10123,
            "install_state": "installed_disabled",
            "granted_permissions": []
        }))
        .unwrap(),
    )
    .unwrap();

    let output = neutron()
        .args([
            "evidence",
            "import",
            "--run-dir",
            run.path().to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--id",
            "disabled-probe",
            "--claim",
            "call-denied",
            "--imported-from",
            "authorized-app-probe",
            "--subject-id",
            "service:binder:vendor.example.IExample/default",
            "--probe-identity",
            probe_identity.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("install_state=installed_enabled"));
}

#[test]
fn behavioral_app_claim_rejects_probe_identity_from_another_boot() {
    let run = TestDir::new("evidence-cross-boot-probe-identity");
    write_minimal_bundle(run.path());
    let source = TestDir::new("evidence-cross-boot-probe-identity-source");
    let input = source.path().join("probe-result.json");
    fs::write(&input, b"{}\n").unwrap();
    let probe_identity = write_probe_identity(source.path());
    let mut identity: serde_json::Value =
        serde_json::from_slice(&fs::read(&probe_identity).unwrap()).unwrap();
    identity["device_boot_id"] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into();
    fs::write(&probe_identity, serde_json::to_vec(&identity).unwrap()).unwrap();

    let output = neutron()
        .args([
            "evidence",
            "import",
            "--run-dir",
            run.path().to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--id",
            "cross-boot-probe",
            "--claim",
            "call-succeeded",
            "--imported-from",
            "authorized-app-probe",
            "--subject-id",
            "service:binder:vendor.example.IExample/default",
            "--probe-identity",
            probe_identity.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("does not match the run manifest boot_id")
    );
}

#[test]
fn not_observed_clean_requires_a_bounded_claim_scope() {
    let run = TestDir::new("evidence-negative-scope-gate");
    write_minimal_bundle(run.path());
    let source = TestDir::new("evidence-negative-scope-source");
    let input = source.path().join("probe-result.json");
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
            "negative-without-scope",
            "--claim",
            "not-observed-clean",
            "--imported-from",
            "authorized-app-probe",
            "--subject-id",
            "service:binder:vendor.example.IExample/default",
            "--health-status",
            "complete",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("requires an explicit bounded --claim-scope"));
}

#[test]
fn claim_scope_rejects_free_form_or_unbounded_values() {
    let run = TestDir::new("evidence-invalid-scope-gate");
    write_minimal_bundle(run.path());
    let source = TestDir::new("evidence-invalid-scope-source");
    let input = source.path().join("probe-result.json");
    fs::write(&input, b"{}\n").unwrap();

    for scope in [
        "globally_unreachable_forever",
        r#"{"procedure":"lookup","caller":"ordinary_app","attempt_count":0}"#,
        r#"{"procedure":"lookup","caller":"ordinary_app","attempt_count":1000001}"#,
        r#"{"procedure":"lookup","caller":"ordinary_app","attempt_count":1,"global":true}"#,
    ] {
        let output = neutron()
            .args([
                "evidence",
                "import",
                "--run-dir",
                run.path().to_str().unwrap(),
                "--input",
                input.to_str().unwrap(),
                "--id",
                "invalid-scope",
                "--claim",
                "not-observed-clean",
                "--imported-from",
                "authorized-app-probe",
                "--subject-id",
                "service:binder:vendor.example.IExample/default",
                "--health-status",
                "complete",
                "--claim-scope",
                scope,
            ])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "invalid scope unexpectedly accepted: {scope}"
        );
    }
}

#[test]
fn import_refuses_to_reseal_a_tampered_bundle() {
    let run = TestDir::new("evidence-import-tampered");
    write_minimal_bundle(run.path());
    fs::write(run.path().join("targets.json"), b"tampered\n").unwrap();
    let source = TestDir::new("evidence-import-tampered-source");
    let input = source.path().join("probe-result.json");
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
            "must-not-reseal",
            "--claim",
            "call-denied",
            "--imported-from",
            "authorized-app-probe",
            "--subject-id",
            "service:binder:vendor.example.IExample/default",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("hash mismatch"));
    assert!(!run.path().join("external-evidence").exists());
}

#[test]
fn verify_rejects_forged_external_negative_health() {
    let run = TestDir::new("evidence-forged-negative");
    write_minimal_bundle(run.path());
    let external = run.path().join("external-evidence");
    fs::create_dir(&external).unwrap();
    fs::set_permissions(&external, fs::Permissions::from_mode(0o700)).unwrap();
    let artifact = b"{}\n";
    fs::write(external.join("forged.artifact"), artifact).unwrap();
    let annotation = serde_json::json!({
        "schema": "neutron.external-evidence/v1",
        "id": "forged",
        "subject_id": "service:binder:vendor.example.IExample/default",
        "measured_by": "external_probe",
        "claim_type": "not_observed_clean",
        "imported_from": "untrusted-assertion",
        "artifact_path": "external-evidence/forged.artifact",
        "artifact_sha256": digest(artifact),
        "health_status": "degraded"
    });
    fs::write(
        external.join("forged.json"),
        serde_json::to_vec_pretty(&annotation).unwrap(),
    )
    .unwrap();
    neutron::evidence::refresh_checksums(run.path()).unwrap();

    let output = neutron()
        .args(["evidence", "verify"])
        .arg(run.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("not_observed_clean requires complete health"));
}

#[cfg(unix)]
#[test]
fn verify_rejects_symlinked_artifact_parent() {
    use std::os::unix::fs::symlink;

    let run = TestDir::new("evidence-parent-symlink");
    write_minimal_bundle(run.path());
    let outside = TestDir::new("evidence-parent-symlink-outside");
    fs::write(outside.path().join("artifact"), b"outside\n").unwrap();
    symlink(outside.path(), run.path().join("nested")).unwrap();
    fs::write(
        run.path().join("SHA256SUMS"),
        format!("{}  nested/artifact\n", digest(b"outside\n")),
    )
    .unwrap();

    let output = neutron()
        .args(["evidence", "verify"])
        .arg(run.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("symlink"));
}
