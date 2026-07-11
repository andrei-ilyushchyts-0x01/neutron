use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use neutron::cli::{Cli, Command};
use neutron::research::{compute_pack_hash, load_pack, parse_duration};

const BUILTIN_PACKS: &[&str] = &[
    "keymint",
    "gpu",
    "camera",
    "media-codec",
    "bluetooth",
    "wifi",
    "usb",
];

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "neutron-research-test-{name}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn copy_dir(source: &Path, destination: &Path) {
    fs::create_dir(destination).unwrap();
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        fs::copy(entry.path(), &target).unwrap();
        fs::set_permissions(target, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn reseal(path: &Path) {
    let digest = compute_pack_hash(path).unwrap();
    let manifest_path = path.join("pack.yaml");
    let manifest = fs::read_to_string(&manifest_path).unwrap();
    let mut replaced = false;
    let manifest = manifest
        .lines()
        .map(|line| {
            if line.starts_with("content_hash:") {
                replaced = true;
                format!("content_hash: {digest}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(replaced);
    fs::write(manifest_path, format!("{manifest}\n")).unwrap();
}

#[test]
fn research_cli_exposes_authorization_gate_and_bounded_duration() {
    let cli = Cli::try_parse_from([
        "neutron",
        "research",
        "--pack",
        "camera",
        "--scenario",
        "single-frame",
        "--param",
        "camera_id=0",
        "--duration",
        "2s",
        "--output",
        "/tmp/result",
        "--probe-package",
        "dev.neutron.probe",
        "--authorized-use",
    ])
    .unwrap();
    let Some(Command::Research(args)) = cli.command else {
        panic!("research command was not parsed")
    };
    assert_eq!(args.pack, "camera");
    assert!(args.authorized_use);
    assert_eq!(args.params, ["camera_id=0"]);

    assert!(parse_duration("1s").is_ok());
    assert!(parse_duration("10m").is_ok());
    assert!(parse_duration("999ms").is_err());
    assert!(parse_duration("601s").is_err());
}

#[test]
fn all_builtin_packs_are_strict_and_sealed() {
    for name in BUILTIN_PACKS {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("packs")
            .join(name);
        let loaded = load_pack(&path, false)
            .unwrap_or_else(|error| panic!("built-in pack {name} should load: {error:#}"));
        assert_eq!(loaded.manifest.id, *name);
        assert_eq!(loaded.manifest.schema, "neutron.research-pack/v1");
        assert_eq!(
            loaded.manifest.content_hash,
            compute_pack_hash(&path).unwrap()
        );
        assert!(!loaded.scenarios.scenarios.is_empty());
    }
}

#[test]
fn local_pack_rejects_mutation_traversal_and_symlink_components() {
    let root = temp_dir("trust");
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("packs")
        .join("keymint");

    let mutated = root.join("mutated");
    copy_dir(&source, &mutated);
    fs::write(mutated.join("report.md"), "changed\n").unwrap();
    assert!(load_pack(&mutated, true)
        .unwrap_err()
        .to_string()
        .contains("hash"));

    let traversal = root.join("traversal");
    copy_dir(&source, &traversal);
    let manifest = fs::read_to_string(traversal.join("pack.yaml"))
        .unwrap()
        .replace("services.json", "../services.json");
    fs::write(traversal.join("pack.yaml"), manifest).unwrap();
    assert!(load_pack(&traversal, true)
        .unwrap_err()
        .to_string()
        .contains("component path"));

    let linked = root.join("linked");
    copy_dir(&source, &linked);
    fs::remove_file(linked.join("services.json")).unwrap();
    symlink(source.join("services.json"), linked.join("services.json")).unwrap();
    assert!(load_pack(&linked, true)
        .unwrap_err()
        .to_string()
        .contains("regular non-symlink"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn missing_authorization_writes_private_non_stimulating_artifacts() {
    let parent = temp_dir("authorization");
    let output = parent.join("run");
    let status = ProcessCommand::new(env!("CARGO_BIN_EXE_neutron"))
        .args(["research", "--pack", "keymint", "--output"])
        .arg(&output)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
    let run: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("run.json")).unwrap()).unwrap();
    assert_eq!(run["status"], "authorization_required");
    let stimulus: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("stimulus.json")).unwrap()).unwrap();
    assert_eq!(stimulus["status"], "not_executed");
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for entry in fs::read_dir(&output).unwrap() {
        let metadata = entry.unwrap().metadata().unwrap();
        if metadata.is_file() {
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
    }
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn local_pack_rejects_duplicate_ids_unsupported_schema_and_oversized_files() {
    let root = temp_dir("schema");
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("packs")
        .join("gpu");

    let duplicate = root.join("duplicate");
    copy_dir(&source, &duplicate);
    let mut services: serde_json::Value =
        serde_json::from_slice(&fs::read(duplicate.join("services.json")).unwrap()).unwrap();
    let item = services["services"][0].clone();
    services["services"].as_array_mut().unwrap().push(item);
    fs::write(
        duplicate.join("services.json"),
        serde_json::to_vec(&services).unwrap(),
    )
    .unwrap();
    reseal(&duplicate);
    assert!(load_pack(&duplicate, true)
        .unwrap_err()
        .to_string()
        .contains("duplicate service"));

    let schema = root.join("schema-version");
    copy_dir(&source, &schema);
    let manifest = fs::read_to_string(schema.join("pack.yaml"))
        .unwrap()
        .replace("neutron.research-pack/v1", "neutron.research-pack/v2");
    fs::write(schema.join("pack.yaml"), manifest).unwrap();
    assert!(load_pack(&schema, true)
        .unwrap_err()
        .to_string()
        .contains("unsupported research pack schema"));

    let oversized = root.join("oversized");
    copy_dir(&source, &oversized);
    fs::write(oversized.join("report.md"), vec![b'x'; 1024 * 1024 + 1]).unwrap();
    assert!(load_pack(&oversized, true)
        .unwrap_err()
        .to_string()
        .contains("component exceeds"));

    fs::remove_dir_all(root).unwrap();
}
