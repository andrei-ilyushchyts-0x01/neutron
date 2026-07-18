use std::cell::RefCell;
use std::io;
use std::path::{Path, PathBuf};

use neutron::surface::coverage::{collect_coverage_with_reader, parse_targets, CoverageOptions};
use neutron::surface::{CommandOutput, PlatformMetadata, PlatformReader};
use serde_json::Value;

const TARGET: &str = "vendor.google.bluetooth_ext.IBluetoothCcc/default";
const UNRELATED: &str = "vendor.example.unrelated.IUnrelated/default";

#[derive(Default)]
struct FakeReader {
    operations: RefCell<Vec<String>>,
}

impl FakeReader {
    fn record(&self, kind: &str, value: impl AsRef<str>) {
        self.operations
            .borrow_mut()
            .push(format!("{kind}:{}", value.as_ref()));
    }

    fn operations(&self) -> Vec<String> {
        self.operations.borrow().clone()
    }
}

impl PlatformReader for FakeReader {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.record("read", path.to_string_lossy());
        let value = match path.to_str() {
            Some("/proc/sys/kernel/random/boot_id") => "boot-a\n",
            Some("/system/build.prop") => {
                "ro.build.fingerprint=google/husky/test:user/release-keys\n"
            }
            Some("/proc/42/stat") => {
                "42 (bluetooth-hal) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 19\n"
            }
            Some("/proc/42/status") => {
                "Name:\tbluetooth-hal\nUid:\t1002\t1002\t1002\t1002\nGid:\t1002\t1002\t1002\t1002\n"
            }
            Some("/proc/42/attr/current") => "u:r:hal_bluetooth_btlinux:s0\n",
            Some("/vendor/etc/vintf/manifest.xml") => {
                r#"<manifest version="2.0" type="device">
                  <hal format="aidl">
                    <name>vendor.google.bluetooth_ext</name>
                    <fqname>IBluetoothCcc/default</fqname>
                  </hal>
                </manifest>"#
            }
            _ => return Err(io::Error::from(io::ErrorKind::NotFound)),
        };
        Ok(value.as_bytes().to_vec())
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        self.record("read_dir", path.to_string_lossy());
        match path.to_str() {
            Some(
                "/system/etc/vintf/manifest"
                | "/vendor/etc/vintf/manifest"
                | "/product/etc/vintf/manifest"
                | "/system_ext/etc/vintf/manifest"
                | "/odm/etc/vintf/manifest",
            ) => Ok(Vec::new()),
            _ => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        }
    }

    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        self.record("read_link", path.to_string_lossy());
        match path.to_str() {
            Some("/proc/42/exe") => Ok(PathBuf::from(
                "/vendor/bin/hw/android.hardware.bluetooth-service",
            )),
            _ => Err(io::Error::from(io::ErrorKind::NotFound)),
        }
    }

    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        self.record("canonicalize", path.to_string_lossy());
        Err(io::Error::from(io::ErrorKind::NotFound))
    }

    fn metadata(&self, path: &Path) -> io::Result<PlatformMetadata> {
        self.record("metadata", path.to_string_lossy());
        Err(io::Error::from(io::ErrorKind::NotFound))
    }

    fn selinux_context(&self, path: &Path) -> io::Result<Option<String>> {
        self.record("selinux_context", path.to_string_lossy());
        Err(io::Error::from(io::ErrorKind::NotFound))
    }

    fn command_output(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
        let argv = std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        self.record("command", &argv);
        let stdout = match (program, args) {
            ("service", ["list"]) => format!(
                "Found 2 services:\n0\t{TARGET}: [vendor.google.bluetooth_ext.IBluetoothCcc]\n1\t{UNRELATED}: [vendor.example.unrelated.IUnrelated]\n"
            ),
            ("dumpsys", ["--pid", name]) if *name == TARGET => "42\n".into(),
            ("dumpsys", ["--pid", name]) if *name == UNRELATED => "99\n".into(),
            ("lshal", ["-i", "-p"]) | ("vndservice", ["list"]) => String::new(),
            ("getprop", ["ro.build.fingerprint"]) => {
                "google/husky/test:user/release-keys\n".into()
            }
            _ => return Err(io::Error::from(io::ErrorKind::NotFound)),
        };
        Ok(CommandOutput {
            success: true,
            stdout,
            stderr: String::new(),
        })
    }

    fn collected_at(&self) -> String {
        "2026-07-17T00:00:00Z".into()
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[test]
fn qualified_targets_preserve_and_enforce_transport() {
    let targets = parse_targets(&format!(
        "# authorized target set\n  service:binder:{TARGET}  \n\n"
    ))
    .expect("target list should parse");

    assert_eq!(targets, vec![format!("service:binder:{TARGET}")]);

    let reader = FakeReader::default();
    let coverage = collect_coverage_with_reader(
        &reader,
        &[format!("service:hwbinder:{TARGET}")],
        &CoverageOptions::default(),
    )
    .expect("a missing qualified transport is unresolved evidence");
    let row = &coverage.rows[0];
    assert_eq!(row.endpoint, TARGET);
    assert_eq!(row.transport, "hwbinder");
    assert!(!row.live);
    assert!(!row.declared);
    assert_eq!(row.attribution.confidence, "unresolved");
    assert!(row.owner.is_none());
    assert!(!reader
        .operations()
        .iter()
        .any(|operation| operation == &format!("command:dumpsys --pid {TARGET}")));
}

#[test]
fn targets_reject_invalid_transport_qualifiers() {
    for target in [
        format!("service:rpc:{TARGET}"),
        "service:binder:".to_string(),
        format!("service:binder {TARGET}"),
    ] {
        assert!(parse_targets(&target).is_err(), "accepted {target}");
    }
}

#[test]
fn minimal_coverage_reads_only_target_owner_and_retains_provenance() {
    let reader = FakeReader::default();
    let targets = parse_targets(TARGET).unwrap();
    let coverage = collect_coverage_with_reader(
        &reader,
        &targets,
        &CoverageOptions {
            minimal: true,
            repeat: 2,
            ..CoverageOptions::default()
        },
    )
    .expect("stable scoped collection should succeed");
    let value = serde_json::to_value(coverage).expect("coverage should be serializable");

    assert_eq!(value["schema"], "neutron.surface-coverage/v1");
    assert_eq!(value["collection"]["minimal"], true);
    assert_eq!(value["collection"]["full_snapshot_retained"], false);
    assert_eq!(value["repeat"]["count"], 2);
    assert_eq!(value["repeat"]["semantic_drift"], Value::Array(Vec::new()));
    assert_eq!(value["health"]["status"], "complete");

    let rows = value["rows"].as_array().expect("coverage rows");
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row["endpoint"], TARGET);
    assert_eq!(row["declared"], true);
    assert_eq!(row["live"], true);
    assert_eq!(row["transport"], "binder");
    assert_eq!(row["owner"]["pid"], 42);
    assert_eq!(row["owner"]["starttime"], 4242);
    assert_eq!(row["owner"]["boot_id"], "boot-a");
    assert_eq!(
        row["owner"]["selinux_domain"],
        "u:r:hal_bluetooth_btlinux:s0"
    );
    assert_eq!(
        row["owner"]["executable"],
        "/vendor/bin/hw/android.hardware.bluetooth-service"
    );
    assert_eq!(row["attribution"]["confidence"], "exact");
    let sources = row["attribution"]["sources"]
        .as_array()
        .expect("structured attribution sources");
    assert!(!sources.is_empty());
    assert!(sources.iter().all(|source| {
        source["measured_by"] == "neutron"
            && source["evidence_sha256"].as_str().is_some_and(is_sha256)
    }));

    let operations = reader.operations();
    assert!(!operations.iter().any(|operation| {
        operation == "read_dir:/proc"
            || operation
                .split_once(':')
                .is_some_and(|(_, path)| path == "/dev" || path.starts_with("/dev/"))
            || operation.contains("/proc/42/maps")
            || operation.contains("/proc/42/fd")
            || operation.contains("/proc/99")
    }));
    assert_eq!(
        operations
            .iter()
            .filter(|operation| operation.as_str() == "read:/proc/42/stat")
            .count(),
        4,
        "each repeat must bracket owner collection with starttime reads"
    );
    let target_dumpsys = format!("command:dumpsys --pid {TARGET}");
    assert_eq!(
        operations
            .iter()
            .filter(|operation| operation.as_str() == target_dumpsys)
            .count(),
        2,
        "one target-only PID lookup is allowed per repeat"
    );
    assert!(!operations
        .iter()
        .any(|operation| operation == &format!("command:dumpsys --pid {UNRELATED}")));
}
