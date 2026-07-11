use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Cursor};
use std::path::{Path, PathBuf};

use neutron::surface::{
    import_capture, reachable, scan_with_reader, CommandOutput, FileKind, PlatformMetadata,
    PlatformReader, RootSelector,
};

#[derive(Default)]
struct FixtureReader {
    dirs: BTreeMap<PathBuf, Vec<PathBuf>>,
    files: BTreeMap<PathBuf, Vec<u8>>,
    links: BTreeMap<PathBuf, PathBuf>,
    canonical: BTreeMap<PathBuf, PathBuf>,
    metadata: BTreeMap<PathBuf, PlatformMetadata>,
    labels: BTreeMap<PathBuf, String>,
    commands: BTreeMap<String, CommandOutput>,
    denied: BTreeSet<PathBuf>,
    sequenced_files: BTreeMap<PathBuf, Vec<Vec<u8>>>,
    read_counts: RefCell<BTreeMap<PathBuf, usize>>,
    reverse_dirs: bool,
}

impl FixtureReader {
    fn command_key(program: &str, args: &[&str]) -> String {
        std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join("\0")
    }

    fn dir(&mut self, path: &str, children: &[&str]) {
        let path = PathBuf::from(path);
        self.metadata.insert(
            path.clone(),
            PlatformMetadata {
                kind: FileKind::Directory,
                mode: 0o755,
                ..PlatformMetadata::default()
            },
        );
        self.dirs.insert(
            path.clone(),
            children.iter().map(|name| path.join(name)).collect(),
        );
    }

    fn file(&mut self, path: &str, contents: impl AsRef<[u8]>) {
        let path = PathBuf::from(path);
        self.metadata.insert(
            path.clone(),
            PlatformMetadata {
                kind: FileKind::File,
                mode: 0o644,
                ..PlatformMetadata::default()
            },
        );
        self.files.insert(path, contents.as_ref().to_vec());
    }

    fn sequenced_file(&mut self, path: &str, contents: &[&str]) {
        self.sequenced_files.insert(
            PathBuf::from(path),
            contents
                .iter()
                .map(|contents| contents.as_bytes().to_vec())
                .collect(),
        );
    }

    fn symlink(&mut self, path: &str, target: &str, canonical: Option<&str>) {
        let path = PathBuf::from(path);
        self.metadata.insert(
            path.clone(),
            PlatformMetadata {
                kind: FileKind::Symlink,
                mode: 0o777,
                ..PlatformMetadata::default()
            },
        );
        self.links.insert(path.clone(), PathBuf::from(target));
        if let Some(canonical) = canonical {
            self.canonical.insert(path, PathBuf::from(canonical));
        }
    }

    fn command(&mut self, program: &str, args: &[&str], stdout: &str) {
        self.commands.insert(
            Self::command_key(program, args),
            CommandOutput {
                success: true,
                stdout: stdout.to_string(),
                stderr: String::new(),
            },
        );
    }
}

impl PlatformReader for FixtureReader {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        if self.denied.contains(path) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        if let Some(sequence) = self.sequenced_files.get(path) {
            let mut counts = self.read_counts.borrow_mut();
            let count = counts.entry(path.to_path_buf()).or_default();
            let value = sequence
                .get(*count)
                .or_else(|| sequence.last())
                .cloned()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            *count += 1;
            return Ok(value);
        }
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        if self.denied.contains(path) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        let mut entries = self
            .dirs
            .get(path)
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        if self.reverse_dirs {
            entries.reverse();
        }
        Ok(entries)
    }

    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        self.links
            .get(path)
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }

    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        if self.denied.contains(path) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        self.canonical
            .get(path)
            .cloned()
            .or_else(|| self.metadata.contains_key(path).then(|| path.to_path_buf()))
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }

    fn metadata(&self, path: &Path) -> io::Result<PlatformMetadata> {
        self.metadata
            .get(path)
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }

    fn selinux_context(&self, path: &Path) -> io::Result<Option<String>> {
        if self.denied.contains(path) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        Ok(self.labels.get(path).cloned())
    }

    fn command_output(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
        self.commands
            .get(&Self::command_key(program, args))
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }

    fn collected_at(&self) -> String {
        "2026-07-10T00:00:00Z".to_string()
    }
}

fn fixture() -> FixtureReader {
    let mut reader = FixtureReader::default();

    reader.dir("/proc", &["42"]);
    reader.dir("/proc/42", &["fd"]);
    reader.dir("/proc/42/fd", &["7"]);
    reader.file("/proc/sys/kernel/random/boot_id", "boot-a\n");
    reader.file("/proc/modules", "trusty_core 4096 0 - Live 0xffff0000\n");
    reader.file(
        "/proc/42/status",
        "Name:\tkeymint\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n",
    );
    reader.file(
        "/proc/42/cmdline",
        b"/vendor/bin/hw/android.hardware.security.keymint-service.trusty\0--foo\0",
    );
    reader.file(
        "/proc/42/stat",
        "42 (keymint worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 19\n",
    );
    reader.file("/proc/42/attr/current", "u:r:hal_keymint_default:s0\n");
    reader.file(
        "/proc/42/maps",
        "7000-8000 r-xp 00000000 00:01 1 /vendor/lib64/libtrusty.so\n\
         8000-9000 r--p 00000000 00:01 2 /vendor/lib64/libtrusty.so\n",
    );
    reader.symlink(
        "/proc/42/exe",
        "/vendor/bin/hw/android.hardware.security.keymint-service.trusty",
        Some("/vendor/bin/hw/android.hardware.security.keymint-service.trusty"),
    );
    reader.symlink(
        "/proc/42/fd/7",
        "/dev/trusty-ipc-dev0",
        Some("/dev/trusty-ipc-dev0"),
    );

    reader.dir("/dev", &["trusty-ipc-dev0", "trusty", "cycle-a", "cycle-b"]);
    reader.metadata.insert(
        PathBuf::from("/dev/trusty-ipc-dev0"),
        PlatformMetadata {
            kind: FileKind::CharacterDevice,
            mode: 0o660,
            uid: 0,
            gid: 1000,
            major: Some(10),
            minor: Some(55),
        },
    );
    reader.labels.insert(
        PathBuf::from("/dev/trusty-ipc-dev0"),
        "u:object_r:tee_device:s0".to_string(),
    );
    reader.symlink(
        "/dev/trusty",
        "trusty-ipc-dev0",
        Some("/dev/trusty-ipc-dev0"),
    );
    reader.symlink("/dev/cycle-a", "cycle-b", None);
    reader.symlink("/dev/cycle-b", "cycle-a", None);

    reader.dir("/sys/module", &["trusty_core"]);
    reader.dir("/sys/module/trusty_core", &[]);
    reader.dir("/sys/class", &["misc"]);
    reader.dir("/sys/class/misc", &["trusty-ipc-dev0"]);
    reader.symlink(
        "/sys/class/misc/trusty-ipc-dev0",
        "../../devices/platform/trusty/trusty-ipc-dev0",
        Some("/sys/devices/platform/trusty/trusty-ipc-dev0"),
    );
    reader.symlink(
        "/sys/dev/char/10:55",
        "../../devices/platform/trusty/trusty-ipc-dev0",
        Some("/sys/devices/platform/trusty/trusty-ipc-dev0"),
    );
    reader.symlink(
        "/sys/devices/platform/trusty/trusty-ipc-dev0/subsystem",
        "../../../../class/misc",
        Some("/sys/class/misc"),
    );
    reader.symlink(
        "/sys/devices/platform/trusty/trusty-ipc-dev0/driver",
        "../../../bus/platform/drivers/trusty-ipc",
        Some("/sys/bus/platform/drivers/trusty-ipc"),
    );
    reader.symlink(
        "/sys/bus/platform/drivers/trusty-ipc/module",
        "../../../../module/trusty_core",
        Some("/sys/module/trusty_core"),
    );

    reader.file(
        "/vendor/etc/vintf/manifest.xml",
        r#"<manifest version="1.0" type="device">
          <hal format="aidl"><name>android.hardware.security.keymint</name>
            <fqname>IKeyMintDevice/default</fqname></hal>
        </manifest>"#,
    );
    reader.file(
        "/system/build.prop",
        "ro.build.fingerprint=google/husky/test:user/release-keys\n",
    );

    reader.command(
        "service",
        &["list"],
        "0 android.hardware.security.keymint.IKeyMintDevice/default: [android.hardware.security.keymint.IKeyMintDevice]\n",
    );
    reader.command(
        "dumpsys",
        &[
            "--pid",
            "android.hardware.security.keymint.IKeyMintDevice/default",
        ],
        "42\n",
    );
    reader.command("lshal", &["-i", "-p"], "");
    reader.command("vndservice", &["list"], "");
    reader
}

#[test]
fn static_scan_is_deterministic_and_maps_process_service_device_and_module() {
    let forward = fixture();
    let mut reverse = fixture();
    reverse.reverse_dirs = true;

    let a = scan_with_reader(&forward).expect("static scan");
    let b = scan_with_reader(&reverse).expect("reverse-order static scan");
    assert_eq!(
        serde_json::to_value(&a).unwrap(),
        serde_json::to_value(&b).unwrap()
    );
    assert_eq!(a.schema, "neutron.surface/v1");
    assert_eq!(a.neutron_version, "1.4.0");
    assert_eq!(a.device.boot_id, "boot-a");
    assert_eq!(a.processes.len(), 1);
    assert_eq!(a.processes[0].pid, 42);
    assert_eq!(a.processes[0].starttime, 4242);
    assert_eq!(a.processes[0].libraries, vec!["/vendor/lib64/libtrusty.so"]);
    assert_eq!(a.processes[0].selinux_domain, "u:r:hal_keymint_default:s0");
    assert_eq!(a.devices.len(), 1);
    assert_eq!(a.devices[0].path, "/dev/trusty-ipc-dev0");
    assert_eq!(a.devices[0].aliases, vec!["/dev/trusty"]);
    assert_eq!(a.devices[0].driver.as_deref(), Some("trusty-ipc"));
    assert_eq!(a.devices[0].module.as_deref(), Some("trusty_core"));
    assert_eq!(a.modules[0].name, "trusty_core");
    assert_eq!(a.services[0].pid, Some(42));
    assert_eq!(
        a.services[0].executable.as_deref(),
        a.processes[0].executable.as_deref()
    );
    assert!(a
        .relations
        .iter()
        .any(|relation| relation.relation_type == "proc_fd"));
    assert_eq!(
        a.health.status, "degraded",
        "symlink cycles must be reported, not fatal"
    );
    assert!(a
        .health
        .warnings
        .iter()
        .any(|warning| warning.contains("cycle")));
}

#[test]
fn device_link_proves_driver_and_module_when_class_node_has_no_driver() {
    let mut reader = fixture();
    let class_driver = PathBuf::from("/sys/devices/platform/trusty/trusty-ipc-dev0/driver");
    reader.links.remove(&class_driver);
    reader.canonical.remove(&class_driver);
    reader.metadata.remove(&class_driver);
    reader.symlink(
        "/sys/devices/platform/trusty/trusty-ipc-dev0/device",
        "..",
        Some("/sys/devices/platform/trusty"),
    );
    reader.symlink(
        "/sys/devices/platform/trusty/driver",
        "../../../bus/platform/drivers/trusty-ipc",
        Some("/sys/bus/platform/drivers/trusty-ipc"),
    );

    let snapshot = scan_with_reader(&reader).expect("static scan");
    assert_eq!(snapshot.devices[0].driver.as_deref(), Some("trusty-ipc"));
    assert_eq!(snapshot.devices[0].module.as_deref(), Some("trusty_core"));
}

#[test]
fn individual_permission_error_degrades_but_missing_primary_source_is_fatal() {
    let mut partial = fixture();
    partial.denied.insert(PathBuf::from("/proc/42/maps"));
    partial.denied.insert(PathBuf::from(
        "/sys/devices/platform/trusty/trusty-ipc-dev0/driver",
    ));
    let snapshot = scan_with_reader(&partial).expect("partial scan remains usable");
    assert_eq!(snapshot.health.status, "degraded");
    assert!(snapshot.processes[0].libraries.is_empty());
    assert!(snapshot
        .health
        .warnings
        .iter()
        .any(|warning| warning.contains("sysfs driver")));

    let missing = FixtureReader::default();
    let error = scan_with_reader(&missing).unwrap_err();
    assert!(format!("{error:#}").contains("/proc"));
}

#[test]
fn symlink_alias_is_kept_when_it_targets_a_noncanonical_name_for_the_same_node() {
    let mut reader = fixture();
    let duplicate = PathBuf::from("/dev/zz-trusty-node");
    let alias = PathBuf::from("/dev/alias-to-zz");
    reader
        .dirs
        .get_mut(Path::new("/dev"))
        .unwrap()
        .extend([duplicate.clone(), alias.clone()]);
    reader.metadata.insert(
        duplicate.clone(),
        PlatformMetadata {
            kind: FileKind::CharacterDevice,
            mode: 0o660,
            uid: 0,
            gid: 1000,
            major: Some(10),
            minor: Some(55),
        },
    );
    reader.symlink(
        alias.to_str().unwrap(),
        "zz-trusty-node",
        duplicate.to_str(),
    );

    let snapshot = scan_with_reader(&reader).unwrap();
    assert!(snapshot.devices[0]
        .aliases
        .contains(&"/dev/alias-to-zz".to_string()));
}

#[test]
fn service_join_revalidates_process_starttime_to_reject_pid_reuse() {
    let mut reader = fixture();
    reader.sequenced_file(
        "/proc/42/stat",
        &[
            "42 (keymint) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 19\n",
            "42 (reused) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 9999 19\n",
        ],
    );

    let snapshot = scan_with_reader(&reader).expect("scan survives PID reuse");
    assert!(snapshot.processes.is_empty());
    assert!(!snapshot
        .relations
        .iter()
        .any(|relation| relation.from == "process:boot-a:42:4242"));
    let service = snapshot
        .services
        .iter()
        .find(|service| service.name.contains("keymint"))
        .expect("keymint service");
    assert!(service.process_id.is_none());
    assert!(snapshot
        .health
        .warnings
        .iter()
        .any(|warning| warning.contains("identity changed")));
}

#[test]
fn identical_names_from_distinct_binder_transports_remain_distinct_services() {
    let mut reader = fixture();
    reader.command(
        "service",
        &["list"],
        "0 collision/default: [example.ICollision]\n",
    );
    reader.command("dumpsys", &["--pid", "collision/default"], "42\n");
    reader.command(
        "vndservice",
        &["list"],
        "0 collision/default: [example.ICollision]\n",
    );

    let mut snapshot = scan_with_reader(&reader).unwrap();
    let transports: BTreeSet<_> = snapshot
        .services
        .iter()
        .filter(|service| service.name == "collision/default")
        .map(|service| service.transport.as_str())
        .collect();
    assert_eq!(transports, BTreeSet::from(["binder", "vndbinder"]));
    assert!(snapshot
        .services
        .iter()
        .filter(|service| service.name == "collision/default")
        .all(|service| !service.hal));

    let capture = r#"
{"type":"marker","phase":"start","name":"collision","scenario_id":"collision","trace_id":"trace-collision","root_package":"com.example.app"}
{"type":"binder","pid":100,"to_proc":99,"debug_id":1,"service":"collision/default","trace_id":"trace-collision","span_id":"binder-1","scenario_id":"collision","depth":0,"causal_relation":"exact"}
{"type":"capture_health","degraded":false,"root_package":"com.example.app","boot_id":"boot-a"}
"#;
    import_capture(&mut snapshot, Cursor::new(capture)).unwrap();
    assert!(snapshot.relations.iter().any(|relation| {
        relation.relation_type == "binder"
            && relation.from == "process:capture:trace-collision:100"
            && relation.to == "process:capture:trace-collision:99"
    }));
    assert!(!snapshot.relations.iter().any(|relation| {
        relation.relation_type == "binder"
            && relation.trace_id.as_deref() == Some("trace-collision")
            && relation.to.starts_with("service:")
    }));
}

#[test]
fn causal_capture_enriches_static_surface_and_reachability_ignores_proc_fd_edges() {
    let mut snapshot = scan_with_reader(&fixture()).expect("static scan");
    let capture = r#"
{"type":"marker","phase":"start","name":"surface-observe","scenario_id":"surface-observe","trace_id":"0000000000001234","root_package":"com.example.app","generation":1}
{"type":"binder","pid":100,"comm":"app","to_proc":42,"debug_id":7,"code":1,"target_node":2,"service":"android.hardware.security.keymint.IKeyMintDevice/default","trace_id":"0000000000001234","span_id":"0000000000000011","parent_span_id":"0000000000000010","scenario_id":"surface-observe","depth":1,"causal_relation":"exact"}
{"type":"syscall","pid":42,"tid":43,"uid":1000,"name":"ioctl","nr":29,"phase":"exit","ts_ns":30,"enter_ts_ns":20,"args":[7,1074295424,0,0,0,0],"fd_path":"/dev/trusty-ipc-dev0","trace_id":"0000000000001234","span_id":"0000000000000012","parent_span_id":"0000000000000011","scenario_id":"surface-observe","depth":2,"causal_relation":"exact"}
{"type":"capture_health","degraded":false,"root_package":"com.example.app","boot_id":"boot-a","fingerprint":"google/husky/test:user/release-keys"}
{"type":"marker","phase":"end","name":"surface-observe","scenario_id":"surface-observe","trace_id":"0000000000001234"}
"#;
    import_capture(&mut snapshot, Cursor::new(capture)).expect("capture import");

    let service = snapshot
        .services
        .iter()
        .find(|service| service.name.contains("keymint"))
        .expect("keymint service");
    assert_eq!(
        service.observed_devices,
        vec![snapshot.devices[0].id.clone()]
    );
    assert_eq!(service.observed_ioctls, vec!["TIPC_IOC_CONNECT"]);
    assert_eq!(snapshot.captures.len(), 1);
    assert!(snapshot.relations.iter().any(|relation| {
        relation.trace_id.as_deref() == Some("0000000000001234")
            && relation.causal_relation.as_deref() == Some("exact")
    }));

    let reached = reachable(
        &snapshot,
        &RootSelector::Package("com.example.app".to_string()),
    )
    .expect("causal reachability");
    assert!(reached.nodes.iter().any(|id| id == &service.id));
    assert!(reached.nodes.iter().any(|id| id == &snapshot.devices[0].id));
    assert_eq!(reached.health.status, "complete");
    assert_eq!(reached.health.confidence, "exact");
    assert_eq!(
        reached.health.captures,
        vec!["capture:0000000000001234:surface-observe"]
    );
    assert!(reached
        .relations
        .iter()
        .all(|relation| relation.relation_type != "proc_fd"));

    let root_relation = snapshot
        .relations
        .iter()
        .find(|relation| relation.relation_type == "root_process")
        .expect("root relation")
        .clone();
    let mut injected = root_relation;
    injected.id = "relation:injected-static".into();
    injected.relation_type = "driven_by".into();
    injected.to = "module:injected-static".into();
    injected.evidence.source = "sysfs".into();
    snapshot.relations.push(injected);
    let reached = reachable(
        &snapshot,
        &RootSelector::Package("com.example.app".to_string()),
    )
    .expect("strict causal reachability");
    assert!(!reached
        .nodes
        .iter()
        .any(|id| id == "module:injected-static"));
}

#[test]
fn reachability_distinguishes_missing_and_candidate_evidence() {
    let mut snapshot = scan_with_reader(&fixture()).unwrap();
    let missing = reachable(
        &snapshot,
        &RootSelector::Package("com.example.missing".into()),
    )
    .unwrap();
    assert_eq!(missing.health.status, "no_evidence");
    assert_eq!(missing.health.confidence, "none");
    assert!(missing
        .health
        .warnings
        .iter()
        .any(|warning| warning.contains("no matching capture")));

    let capture = r#"
{"type":"marker","phase":"start","name":"candidate","scenario_id":"candidate","trace_id":"trace-candidate","root_package":"com.example.candidate"}
{"type":"syscall","pid":42,"tid":42,"name":"ioctl","phase":"exit","args":[7,3227014671,0,0,0,0],"fd_path":"/dev/trusty-ipc-dev0","trace_id":"trace-candidate","span_id":"ioctl-candidate","depth":0,"causal_relation":"inferred"}
"#;
    import_capture(&mut snapshot, Cursor::new(capture)).unwrap();
    let candidate = reachable(
        &snapshot,
        &RootSelector::Package("com.example.candidate".into()),
    )
    .unwrap();
    assert_eq!(candidate.health.status, "degraded");
    assert_eq!(candidate.health.confidence, "candidate");
    assert!(candidate
        .health
        .warnings
        .iter()
        .any(|warning| warning.contains("degraded")));
}

#[test]
fn legacy_capture_keeps_edges_as_candidate_and_warns_about_pid_identity() {
    let mut snapshot = scan_with_reader(&fixture()).expect("static scan");
    let legacy = r#"
{"type":"marker","phase":"start","name":"old","scenario_id":"old","trace_id":"0000000000000001","root_uid":1000}
{"type":"syscall","pid":42,"tid":42,"name":"ioctl","nr":29,"phase":"exit","ts_ns":2,"args":[7,3227014671,0,0,0,0],"fd_path":"/dev/trusty-ipc-dev0","trace_id":"0000000000000001","span_id":"0000000000000002","parent_span_id":"0000000000000001","scenario_id":"old","depth":0,"causal_relation":"inferred"}
"#;
    import_capture(&mut snapshot, Cursor::new(legacy)).expect("legacy capture import");
    assert!(snapshot
        .health
        .warnings
        .iter()
        .any(|warning| { warning.contains("boot") && warning.contains("candidate") }));
    assert!(snapshot.relations.iter().any(|relation| {
        relation.trace_id.as_deref() == Some("0000000000000001")
            && relation.confidence == "candidate"
    }));
    assert_eq!(snapshot.captures[0].health, "degraded");
    assert!(snapshot
        .health
        .warnings
        .iter()
        .any(|warning| warning.contains("no final capture_health")));
}

#[test]
fn capture_can_create_services_from_exact_or_single_candidate_evidence() {
    let mut snapshot = scan_with_reader(&fixture()).expect("static scan");
    let capture = r#"
{"type":"marker","phase":"start","name":"new-services","scenario_id":"new-services","trace_id":"trace-new","root_package":"com.example.new"}
{"type":"binder","pid":100,"to_proc":200,"debug_id":1,"service":"vendor.example.INew/default","trace_id":"trace-new","span_id":"binder-1","scenario_id":"new-services","causal_relation":"exact"}
{"type":"binder","pid":101,"to_proc":201,"debug_id":2,"service_candidates":["vendor.example.ICandidate/default"],"trace_id":"trace-new","span_id":"binder-2","scenario_id":"new-services","causal_relation":"inferred"}
{"type":"binder","pid":102,"to_proc":202,"debug_id":3,"trace_id":"trace-new","span_id":"binder-3","scenario_id":"new-services","causal_relation":"exact"}
{"type":"binder","pid":103,"debug_id":4,"trace_id":"trace-new","span_id":"malformed"}
{"type":"capture_health","degraded":true,"root_package":"com.example.new","boot_id":"boot-a","fingerprint":"different/fingerprint","binder_depth_limit":1}
"#;

    import_capture(&mut snapshot, Cursor::new(capture)).expect("capture import");

    assert!(snapshot
        .services
        .iter()
        .any(|service| service.name == "vendor.example.INew/default"));
    let candidate = snapshot
        .services
        .iter()
        .find(|service| service.name == "vendor.example.ICandidate/default")
        .expect("candidate service");
    assert_eq!(candidate.confidence, "candidate");
    assert!(snapshot.relations.iter().any(|relation| {
        relation.to == candidate.id
            && relation.relation_type == "binder"
            && relation.confidence == "candidate"
    }));
    assert!(snapshot.relations.iter().any(|relation| {
        relation.from == candidate.id
            && relation.relation_type == "served_by"
            && relation.confidence == "candidate"
    }));
    assert!(snapshot.relations.iter().any(|relation| {
        relation.relation_type == "binder"
            && relation.from == "process:capture:trace-new:102"
            && relation.to == "process:capture:trace-new:202"
    }));
    assert!(snapshot
        .health
        .warnings
        .iter()
        .any(|warning| warning.contains("fingerprint differs")));
    assert!(snapshot
        .health
        .warnings
        .iter()
        .any(|warning| warning.contains("missing process endpoint")));
}

#[test]
fn capture_process_uids_come_from_each_event_not_the_root_selector() {
    let mut snapshot = scan_with_reader(&fixture()).unwrap();
    let capture = r#"
{"type":"marker","phase":"start","name":"uid-root","scenario_id":"uid-root","trace_id":"trace-uid","root_uid":10123}
{"type":"binder","pid":100,"caller_uid":10123,"to_proc":200,"debug_id":1,"service":"example.IFirst/default","trace_id":"trace-uid","span_id":"binder-1","scenario_id":"uid-root","depth":0,"causal_relation":"exact"}
{"type":"binder","pid":200,"caller_uid":1000,"to_proc":300,"debug_id":2,"service":"example.ISecond/default","trace_id":"trace-uid","span_id":"binder-2","scenario_id":"uid-root","depth":1,"causal_relation":"exact"}
{"type":"syscall","pid":200,"uid":1000,"tid":201,"name":"ioctl","phase":"exit","args":[7,1074295424,0,0,0,0],"fd_path":"/dev/trusty-ipc-dev0","trace_id":"trace-uid","span_id":"ioctl-1","parent_span_id":"binder-2","scenario_id":"uid-root","depth":2,"causal_relation":"exact"}
{"type":"capture_health","degraded":false,"root_uid":10123,"boot_id":"boot-a"}
"#;

    import_capture(&mut snapshot, Cursor::new(capture)).unwrap();
    let uid_by_pid: BTreeMap<_, _> = snapshot
        .processes
        .iter()
        .filter(|process| process.id.starts_with("process:capture:trace-uid:"))
        .map(|process| (process.pid, process.uid))
        .collect();
    assert_eq!(uid_by_pid.get(&100), Some(&10_123));
    assert_eq!(uid_by_pid.get(&200), Some(&1000));
    assert_eq!(uid_by_pid.get(&300), Some(&0));
}
