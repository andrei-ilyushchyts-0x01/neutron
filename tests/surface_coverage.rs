use std::cell::{Cell, RefCell};
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
    repeat_drift: bool,
    remap_during_revalidation: bool,
    disappear_during_revalidation: bool,
    pid_reuse_during_revalidation: bool,
    boot_drift: bool,
    boot_read_failure_on_start: bool,
    boot_read_failure_after_start: bool,
    reject_vintf_bounded_read: bool,
    service_list_calls: Cell<usize>,
    target_pid_calls: Cell<usize>,
    boot_id_calls: Cell<usize>,
    pid_42_stat_calls: Cell<usize>,
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
            Some("/proc/sys/kernel/random/boot_id") => {
                let call = self.boot_id_calls.get();
                self.boot_id_calls.set(call.saturating_add(1));
                if self.boot_read_failure_on_start && call == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "initial boot identity is unavailable",
                    ));
                }
                if self.boot_read_failure_after_start && call > 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "final boot identity is unavailable",
                    ));
                }
                if self.boot_drift && call > 0 {
                    "boot-b\n"
                } else {
                    "boot-a\n"
                }
            }
            Some("/system/build.prop") => {
                "ro.build.fingerprint=google/husky/test:user/release-keys\n"
            }
            Some("/proc/42/stat") => {
                let call = self.pid_42_stat_calls.get();
                self.pid_42_stat_calls.set(call.saturating_add(1));
                if self.pid_reuse_during_revalidation && call > 1 {
                    "42 (replacement) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 9000 19\n"
                } else {
                    "42 (bluetooth-hal) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 19\n"
                }
            }
            Some("/proc/43/stat") => {
                "43 (bluetooth-hal) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4343 19\n"
            }
            Some("/proc/42/status" | "/proc/43/status") => {
                "Name:\tbluetooth-hal\nUid:\t1002\t1002\t1002\t1002\nGid:\t1002\t1002\t1002\t1002\n"
            }
            Some("/proc/42/attr/current" | "/proc/43/attr/current") => {
                "u:r:hal_bluetooth_btlinux:s0\n"
            }
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

    fn read_bounded(&self, path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
        self.record("read_bounded", path.to_string_lossy());
        if self.reject_vintf_bounded_read && path == Path::new("/vendor/etc/vintf/manifest.xml") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("input exceeds {max_bytes} byte limit"),
            ));
        }
        let bytes = self.read(path)?;
        if bytes.len() > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("input exceeds {max_bytes} byte limit"),
            ));
        }
        Ok(bytes)
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
            Some("/proc/42/exe" | "/proc/43/exe") => Ok(PathBuf::from(
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
            ("service", ["list"]) => {
                let call = self.service_list_calls.get();
                self.service_list_calls.set(call.saturating_add(1));
                self.target_pid_calls.set(0);
                format!(
                    "Found 2 services:\n0\t{TARGET}: [vendor.google.bluetooth_ext.IBluetoothCcc]\n1\t{UNRELATED}: [vendor.example.unrelated.IUnrelated]\n"
                )
            }
            ("dumpsys", ["--pid", name]) if *name == TARGET => {
                let call = self.target_pid_calls.get();
                self.target_pid_calls.set(call.saturating_add(1));
                let pass = self.service_list_calls.get().saturating_sub(1);
                if self.disappear_during_revalidation && call > 0 {
                    String::new()
                } else if self.remap_during_revalidation && call > 0
                    || self.repeat_drift && pass > 0
                {
                    "43\n".into()
                } else {
                    "42\n".into()
                }
            }
            ("dumpsys", ["--pid", name]) if *name == UNRELATED => "99\n".into(),
            ("lshal", ["-i", "-p"]) | ("vndservice", ["list"]) => String::new(),
            ("getprop", ["ro.build.fingerprint"]) => "google/husky/test:user/release-keys\n".into(),
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

#[test]
fn repeat_drift_makes_coverage_incomplete() {
    let reader = FakeReader {
        repeat_drift: true,
        ..FakeReader::default()
    };
    let document = collect_coverage_with_reader(
        &reader,
        &[TARGET.to_string()],
        &CoverageOptions {
            minimal: true,
            repeat: 2,
        },
    )
    .expect("drift is reported as evidence health, not a parser error");

    assert!(!document.repeat.semantic_drift.is_empty());
    assert_eq!(document.health.status, "incomplete");
    assert!(document
        .health
        .warnings
        .iter()
        .any(|warning| warning.contains("drift")));
}

#[test]
fn endpoint_remap_during_owner_revalidation_is_never_exact() {
    let reader = FakeReader {
        remap_during_revalidation: true,
        ..FakeReader::default()
    };
    let document =
        collect_coverage_with_reader(&reader, &[TARGET.to_string()], &CoverageOptions::default())
            .expect("an endpoint remap is represented as incomplete evidence");

    assert_eq!(document.health.status, "incomplete");
    assert_eq!(document.summary.exact, 0);
    assert_eq!(document.rows[0].attribution.confidence, "unresolved");
    assert!(document.rows[0].owner.is_none());
    assert!(document
        .health
        .warnings
        .iter()
        .any(|warning| warning.contains("changed from PID 42 to PID 43")));
}

#[test]
fn endpoint_disappearance_during_owner_revalidation_is_never_exact() {
    let reader = FakeReader {
        disappear_during_revalidation: true,
        ..FakeReader::default()
    };
    let document =
        collect_coverage_with_reader(&reader, &[TARGET.to_string()], &CoverageOptions::default())
            .expect("endpoint disappearance is represented as incomplete evidence");

    assert_eq!(document.health.status, "incomplete");
    assert_eq!(document.summary.exact, 0);
    assert_eq!(document.rows[0].attribution.confidence, "unresolved");
    assert!(document.rows[0].owner.is_none());
    assert!(document
        .health
        .warnings
        .iter()
        .any(|warning| warning.contains("no longer proves an owner PID")));
}

#[test]
fn pid_reuse_after_endpoint_revalidation_is_never_exact() {
    let reader = FakeReader {
        pid_reuse_during_revalidation: true,
        ..FakeReader::default()
    };
    let document =
        collect_coverage_with_reader(&reader, &[TARGET.to_string()], &CoverageOptions::default())
            .expect("PID reuse is represented as incomplete evidence");

    assert_eq!(document.health.status, "incomplete");
    assert_eq!(document.summary.exact, 0);
    assert_eq!(document.rows[0].attribution.confidence, "unresolved");
    assert!(document.rows[0].owner.is_none());
    assert!(document
        .health
        .warnings
        .iter()
        .any(|warning| warning.contains("starttime changed from 4242 to 9000")));
}

#[test]
fn reboot_during_coverage_pass_makes_evidence_incomplete_and_unresolved() {
    let reader = FakeReader {
        boot_drift: true,
        ..FakeReader::default()
    };
    let document =
        collect_coverage_with_reader(&reader, &[TARGET.to_string()], &CoverageOptions::default())
            .expect("a reboot during collection is represented in evidence health");

    assert_eq!(document.health.status, "incomplete");
    assert_eq!(document.summary.exact, 0);
    assert_eq!(document.rows[0].attribution.confidence, "unresolved");
    assert!(document.rows[0].owner.is_none());
    assert!(document
        .health
        .warnings
        .iter()
        .any(|warning| warning.contains("boot identity changed during coverage pass")));
}

#[test]
fn final_boot_identity_read_failure_makes_health_unknown_and_owner_unresolved() {
    let reader = FakeReader {
        boot_read_failure_after_start: true,
        ..FakeReader::default()
    };
    let document =
        collect_coverage_with_reader(&reader, &[TARGET.to_string()], &CoverageOptions::default())
            .expect("a missing final boot identity is represented in evidence health");

    assert_eq!(document.health.status, "unknown");
    assert_eq!(document.summary.exact, 0);
    assert_eq!(document.rows[0].attribution.confidence, "unresolved");
    assert!(document.rows[0].owner.is_none());
    assert!(document
        .health
        .warnings
        .iter()
        .any(|warning| warning.contains("cannot revalidate boot identity")));
}

#[test]
fn initial_boot_identity_read_failure_makes_health_unknown_and_owner_unresolved() {
    let reader = FakeReader {
        boot_read_failure_on_start: true,
        ..FakeReader::default()
    };
    let document =
        collect_coverage_with_reader(&reader, &[TARGET.to_string()], &CoverageOptions::default())
            .expect("a missing initial boot identity is represented in evidence health");

    assert_eq!(document.health.status, "unknown");
    assert_eq!(document.summary.exact, 0);
    assert_eq!(document.rows[0].attribution.confidence, "unresolved");
    assert!(document.rows[0].owner.is_none());
    assert!(document
        .health
        .warnings
        .iter()
        .any(|warning| warning.contains("cannot read initial boot identity")));
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
    for collector in [
        "dumpsys_pid_revalidated",
        "proc_stat_endpoint_revalidated",
        "boot_id_revalidated",
    ] {
        assert!(sources
            .iter()
            .any(|source| source["collector"] == collector));
    }

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
        6,
        "each repeat must bracket owner collection and endpoint revalidation with starttime reads"
    );
    let target_dumpsys = format!("command:dumpsys --pid {TARGET}");
    assert_eq!(
        operations
            .iter()
            .filter(|operation| operation.as_str() == target_dumpsys)
            .count(),
        4,
        "each repeat must re-query the target-only PID mapping"
    );
    assert_eq!(
        operations
            .iter()
            .filter(|operation| { operation.as_str() == "read:/proc/sys/kernel/random/boot_id" })
            .count(),
        4,
        "each repeat must bracket the complete pass with boot identity reads"
    );
    assert!(!operations
        .iter()
        .any(|operation| operation == &format!("command:dumpsys --pid {UNRELATED}")));
}

#[test]
fn coverage_rejects_oversize_vintf_before_parsing_it() {
    let reader = FakeReader {
        reject_vintf_bounded_read: true,
        ..FakeReader::default()
    };
    let document =
        collect_coverage_with_reader(&reader, &[TARGET.to_string()], &CoverageOptions::default())
            .expect("oversize collector input should degrade evidence, not crash collection");

    assert_eq!(document.health.status, "degraded");
    assert!(!document.rows[0].declared);
    assert!(document
        .health
        .warnings
        .iter()
        .any(|warning| warning.contains("input exceeds")));
    assert!(reader
        .operations()
        .iter()
        .any(|operation| { operation == "read_bounded:/vendor/etc/vintf/manifest.xml" }));
}
