use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("neutron-run-bundle-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
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

#[test]
fn surface_coverage_emits_a_self_verifying_static_bundle() {
    let directory = TestDir::new();
    let targets = directory.path().join("targets.txt");
    let json = directory.path().join("coverage.json");
    let tsv = directory.path().join("coverage.tsv");
    let run = directory.path().join("run");
    fs::write(&targets, "vendor.example.IExample/default\n").unwrap();

    let output = neutron()
        .args(["surface", "coverage", "--minimal", "--repeat", "2"])
        .arg("--targets")
        .arg(&targets)
        .arg("--json")
        .arg(&json)
        .arg("--tsv")
        .arg(&tsv)
        .arg("--run-dir")
        .arg(&run)
        .arg("--attacker-capability")
        .arg("ordinary_installed_app")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(run.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["schema"], "neutron.run-manifest/v1");
    assert_eq!(manifest["run_kind"], "surface_static");
    assert_eq!(manifest["bpf_loaded"], false);
    assert_eq!(manifest["stimulus_executed"], false);
    assert_eq!(manifest["configuration_changed"], false);
    assert_eq!(manifest["collection"]["minimal"], true);
    assert_eq!(manifest["collection"]["full_snapshot_retained"], false);
    assert_eq!(
        manifest["research_model"]["attacker_capability"],
        "ordinary_installed_app"
    );

    let verified = neutron()
        .args(["evidence", "verify"])
        .arg(&run)
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
}

#[test]
fn surface_coverage_refuses_to_overwrite_its_target_list() {
    let directory = TestDir::new();
    let targets = directory.path().join("targets.txt");
    let tsv = directory.path().join("coverage.tsv");
    fs::write(&targets, "vendor.example.IExample/default\n").unwrap();
    let original = fs::read(&targets).unwrap();

    let output = neutron()
        .args(["surface", "coverage", "--minimal"])
        .arg("--targets")
        .arg(&targets)
        .arg("--json")
        .arg(directory.path().join(".").join("targets.txt"))
        .arg("--tsv")
        .arg(&tsv)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--targets must be different"));
    assert_eq!(fs::read(&targets).unwrap(), original);
}
