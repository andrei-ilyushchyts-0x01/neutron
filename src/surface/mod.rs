//! Deterministic Android service/process/device surface snapshots.

pub mod parse;
pub mod platform;

pub use parse::{
    ioctl_label, parse_dumpsys_pid, parse_lshal_inventory, parse_module_names,
    parse_process_starttime, parse_process_status, parse_service_list_inventory,
    parse_vintf_manifest, parse_vndservice_list,
};
pub use platform::{CommandOutput, FileKind, PlatformMetadata, PlatformReader, RealPlatformReader};

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Cursor, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::{ArgGroup, Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const SURFACE_SCHEMA: &str = "neutron.surface/v1";
const QUERY_SCHEMA: &str = "neutron.surface/query/v1";

#[derive(Subcommand, Debug)]
pub enum SurfaceCommand {
    /// Collect a deterministic on-device surface snapshot.
    Scan(SurfaceScanArgs),
    /// List Binder services.
    Services(SurfaceInputArgs),
    /// List declared and running HAL services.
    Hals(SurfaceInputArgs),
    /// List device nodes.
    Devices(SurfaceInputArgs),
    /// Show one PID (ambiguous reused PIDs are rejected).
    Process(SurfaceProcessArgs),
    /// Explain a service/device selector and its relations.
    Explain(SurfaceExplainArgs),
    /// Show only causally observed reachability from a package or UID.
    Reachable(SurfaceReachableArgs),
}

#[derive(Args, Debug)]
#[command(group(ArgGroup::new("from").args(["from_package", "from_uid"]).multiple(false)))]
pub struct SurfaceScanArgs {
    /// Import a causal NDJSON capture after static collection (`-` for stdin).
    #[arg(long, conflicts_with = "observe")]
    pub capture: Option<String>,
    /// Run one child trace for this duration (for example `30s`).
    #[arg(long, conflicts_with = "capture", requires = "from")]
    pub observe: Option<String>,
    /// Package root for live observation.
    #[arg(long, group = "from", requires = "observe", conflicts_with = "capture")]
    pub from_package: Option<String>,
    /// UID root for live observation.
    #[arg(long, group = "from", requires = "observe", conflicts_with = "capture")]
    pub from_uid: Option<u32>,
    /// Write JSON to this file (mode 0600) instead of stdout.
    #[arg(long)]
    pub output: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct SurfaceInputArgs {
    /// Surface snapshot (`-` for stdin).
    #[arg(long)]
    pub input: String,
    /// Write JSON to this file (mode 0600) instead of stdout.
    #[arg(long)]
    pub output: Option<String>,
}

#[derive(Args, Debug)]
pub struct SurfaceProcessArgs {
    pub pid: u32,
    #[command(flatten)]
    pub io: SurfaceInputArgs,
}

#[derive(Args, Debug)]
pub struct SurfaceExplainArgs {
    pub selector: String,
    #[command(flatten)]
    pub io: SurfaceInputArgs,
}

#[derive(Args, Debug)]
#[command(group(ArgGroup::new("from").required(true).args(["from_package", "from_uid"]).multiple(false)))]
pub struct SurfaceReachableArgs {
    #[arg(long, group = "from")]
    pub from_package: Option<String>,
    #[arg(long, group = "from")]
    pub from_uid: Option<u32>,
    #[command(flatten)]
    pub io: SurfaceInputArgs,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SurfaceSnapshot {
    pub schema: String,
    pub neutron_version: String,
    pub collected_at: String,
    pub device: DeviceIdentity,
    pub health: SurfaceHealth,
    pub services: Vec<Service>,
    pub processes: Vec<Process>,
    pub devices: Vec<Device>,
    pub modules: Vec<Module>,
    pub relations: Vec<Relation>,
    pub captures: Vec<CaptureRecord>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub fingerprint: String,
    pub boot_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SurfaceHealth {
    pub status: String,
    pub collectors: Vec<CollectorHealth>,
    pub warnings: Vec<String>,
}

impl Default for SurfaceHealth {
    fn default() -> Self {
        Self {
            status: "complete".into(),
            collectors: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CollectorHealth {
    pub name: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Service {
    pub id: String,
    pub name: String,
    pub transport: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selinux_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub libraries: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_devices: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_ioctls: Vec<String>,
    pub declared: bool,
    pub hal: bool,
    pub confidence: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Process {
    pub id: String,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cmdline: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    pub starttime: u64,
    pub boot_id: String,
    pub selinux_domain: String,
    pub libraries: Vec<String>,
    pub file_descriptors: Vec<OpenFile>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct OpenFile {
    pub fd: u32,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Device {
    pub id: String,
    pub path: String,
    pub aliases: Vec<String>,
    pub kind: String,
    pub major: u32,
    pub minor: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selinux_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sysfs_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subsystem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Module {
    pub id: String,
    pub name: String,
    pub loaded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sysfs_path: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Relation {
    pub id: String,
    #[serde(rename = "type")]
    pub relation_type: String,
    pub from: String,
    pub to: String,
    pub evidence: Evidence,
    pub confidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub causal_relation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scenario_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ioctl: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Evidence {
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CaptureRecord {
    pub id: String,
    pub trace_id: String,
    pub scenario_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_package: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    pub health: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootSelector {
    Package(String),
    Uid(u32),
}

impl RootSelector {
    fn id(&self) -> String {
        match self {
            Self::Package(package) => format!("package:{package}"),
            Self::Uid(uid) => format!("uid:{uid}"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReachableResult {
    pub schema: String,
    pub root: String,
    pub health: ReachabilityHealth,
    pub nodes: Vec<String>,
    pub relations: Vec<Relation>,
    pub services: Vec<Service>,
    pub processes: Vec<Process>,
    pub devices: Vec<Device>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReachabilityHealth {
    pub status: String,
    pub confidence: String,
    pub captures: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn run(command: SurfaceCommand) -> Result<()> {
    match command {
        SurfaceCommand::Scan(args) => run_scan(args),
        SurfaceCommand::Services(args) => {
            let snapshot = read_snapshot(&args.input)?;
            write_json(
                args.output.as_deref(),
                &json!({
                    "schema": QUERY_SCHEMA,
                    "services": snapshot.services,
                }),
            )
        }
        SurfaceCommand::Hals(args) => {
            let snapshot = read_snapshot(&args.input)?;
            let hals: Vec<_> = snapshot
                .services
                .into_iter()
                .filter(|service| service.hal)
                .collect();
            write_json(
                args.output.as_deref(),
                &json!({"schema": QUERY_SCHEMA, "hals": hals}),
            )
        }
        SurfaceCommand::Devices(args) => {
            let snapshot = read_snapshot(&args.input)?;
            write_json(
                args.output.as_deref(),
                &json!({
                    "schema": QUERY_SCHEMA,
                    "devices": snapshot.devices,
                }),
            )
        }
        SurfaceCommand::Process(args) => {
            let snapshot = read_snapshot(&args.io.input)?;
            let matches: Vec<_> = snapshot
                .processes
                .iter()
                .filter(|process| process.pid == args.pid)
                .collect();
            let process = match matches.as_slice() {
                [process] => *process,
                [] => bail!("PID {} is not present in the snapshot", args.pid),
                _ => bail!(
                    "PID {} is ambiguous because multiple process identities are present",
                    args.pid
                ),
            };
            write_json(
                args.io.output.as_deref(),
                &json!({
                    "schema": QUERY_SCHEMA,
                    "process": process,
                }),
            )
        }
        SurfaceCommand::Explain(args) => {
            let snapshot = read_snapshot(&args.io.input)?;
            let value = explain(&snapshot, &args.selector)?;
            write_json(args.io.output.as_deref(), &value)
        }
        SurfaceCommand::Reachable(args) => {
            let snapshot = read_snapshot(&args.io.input)?;
            let selector = match (args.from_package, args.from_uid) {
                (Some(package), None) => RootSelector::Package(package),
                (None, Some(uid)) => RootSelector::Uid(uid),
                _ => bail!("reachable requires exactly one --from-package or --from-uid"),
            };
            let result = reachable(&snapshot, &selector)?;
            write_json(args.io.output.as_deref(), &result)
        }
    }
}

fn run_scan(args: SurfaceScanArgs) -> Result<()> {
    let observed_capture = if let Some(duration) = args.observe.as_deref() {
        let selector = match (args.from_package, args.from_uid) {
            (Some(package), None) => RootSelector::Package(package),
            (None, Some(uid)) => RootSelector::Uid(uid),
            _ => bail!("--observe requires exactly one --from-package or --from-uid"),
        };
        Some(observe(parse_duration(duration)?, &selector)?)
    } else {
        None
    };

    // Live evidence must precede the static snapshot. This lets the later
    // /proc starttime read reject a PID that was recycled during observation.
    let mut snapshot = scan_with_reader(&RealPlatformReader)?;
    if let Some(capture) = observed_capture {
        import_capture(&mut snapshot, Cursor::new(capture))?;
    } else if let Some(path) = args.capture.as_deref() {
        let reader = open_input(path)?;
        import_capture(&mut snapshot, reader)?;
    }
    finish_snapshot(&mut snapshot);
    write_json(args.output.as_deref(), &snapshot)
}

#[derive(Default)]
struct HealthBuilder {
    collectors: BTreeMap<String, CollectorHealth>,
    warnings: BTreeSet<String>,
}

impl HealthBuilder {
    fn collector(&mut self, name: &str, scope: &[&str]) {
        self.collectors
            .entry(name.to_string())
            .or_insert_with(|| CollectorHealth {
                name: name.to_string(),
                status: "complete".into(),
                scope: scope.iter().map(|value| (*value).to_string()).collect(),
                warnings: Vec::new(),
            });
    }

    fn warn(&mut self, collector: &str, warning: impl Into<String>) {
        let warning = warning.into();
        let entry = self
            .collectors
            .entry(collector.to_string())
            .or_insert_with(|| CollectorHealth {
                name: collector.to_string(),
                status: "complete".into(),
                scope: Vec::new(),
                warnings: Vec::new(),
            });
        entry.status = "degraded".into();
        if !entry.warnings.contains(&warning) {
            entry.warnings.push(warning.clone());
        }
        self.warnings.insert(warning);
    }

    fn finish(self) -> SurfaceHealth {
        let mut collectors: Vec<_> = self.collectors.into_values().collect();
        for collector in &mut collectors {
            collector.scope.sort();
            collector.scope.dedup();
            collector.warnings.sort();
            collector.warnings.dedup();
        }
        let warnings: Vec<_> = self.warnings.into_iter().collect();
        SurfaceHealth {
            status: if warnings.is_empty() {
                "complete".into()
            } else {
                "degraded".into()
            },
            collectors,
            warnings,
        }
    }
}

/// Collect a static snapshot using an injectable platform boundary.
pub fn scan_with_reader(reader: &dyn PlatformReader) -> Result<SurfaceSnapshot> {
    let proc_entries = reader
        .read_dir(Path::new("/proc"))
        .context("reading required surface source /proc")?;
    let dev_entries = reader
        .read_dir(Path::new("/dev"))
        .context("reading required surface source /dev")?;

    let mut health = HealthBuilder::default();
    health.collector(
        "identity",
        &["/proc/sys/kernel/random/boot_id", "/system/build.prop"],
    );
    health.collector(
        "devices",
        &["/dev", "/sys/dev/char", "/sys/dev/block", "/sys/class"],
    );
    health.collector("modules", &["/proc/modules", "/sys/module"]);
    health.collector("processes", &["/proc/<pid>"]);
    health.collector(
        "services",
        &[
            "service list",
            "dumpsys --pid",
            "lshal -ip",
            "vndservice list",
        ],
    );
    health.collector(
        "vintf",
        &[
            "/system/etc/vintf",
            "/vendor/etc/vintf",
            "/product/etc/vintf",
            "/system_ext/etc/vintf",
            "/odm/etc/vintf",
        ],
    );

    let boot_id = match read_text(reader, "/proc/sys/kernel/random/boot_id") {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        Ok(_) => {
            health.warn("identity", "boot identity is empty");
            String::new()
        }
        Err(error) => {
            health.warn("identity", format!("cannot read boot identity: {error}"));
            String::new()
        }
    };
    let fingerprint = collect_fingerprint(reader, &mut health);
    let mut relations = Vec::new();
    let devices = collect_devices(reader, dev_entries, &mut health)?;
    let modules = collect_modules(reader, &mut health);
    for device in &devices {
        if let Some(module) = device.module.as_deref() {
            relations.push(make_relation(
                "driven_by",
                &device.id,
                &format!("module:{module}"),
                "sysfs",
                "exact",
                None,
                None,
                None,
                None,
            ));
        }
    }
    let processes = collect_processes(
        reader,
        proc_entries,
        &boot_id,
        &devices,
        &mut relations,
        &mut health,
    );
    let services = collect_services(reader, &processes, &mut relations, &mut health);

    let mut snapshot = SurfaceSnapshot {
        schema: SURFACE_SCHEMA.into(),
        neutron_version: env!("CARGO_PKG_VERSION").into(),
        collected_at: reader.collected_at(),
        device: DeviceIdentity {
            fingerprint,
            boot_id,
        },
        health: health.finish(),
        services,
        processes,
        devices,
        modules,
        relations,
        captures: Vec::new(),
    };
    finish_snapshot(&mut snapshot);
    Ok(snapshot)
}

fn collect_fingerprint(reader: &dyn PlatformReader, health: &mut HealthBuilder) -> String {
    if let Ok(build_prop) = read_text(reader, "/system/build.prop") {
        if let Some(value) = build_prop.lines().find_map(|line| {
            line.strip_prefix("ro.build.fingerprint=")
                .map(str::trim)
                .filter(|value| !value.is_empty())
        }) {
            return value.to_string();
        }
    }
    match reader.command_output("getprop", &["ro.build.fingerprint"]) {
        Ok(output) if output.success && !output.stdout.trim().is_empty() => {
            output.stdout.trim().to_string()
        }
        Ok(output) => {
            health.warn(
                "identity",
                format!(
                    "getprop did not return a fingerprint: {}",
                    output.stderr.trim()
                ),
            );
            String::new()
        }
        Err(error) => {
            health.warn(
                "identity",
                format!("cannot collect build fingerprint: {error}"),
            );
            String::new()
        }
    }
}

fn read_text(reader: &dyn PlatformReader, path: &str) -> io::Result<String> {
    let bytes = reader.read(Path::new(path))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn collect_devices(
    reader: &dyn PlatformReader,
    roots: Vec<PathBuf>,
    health: &mut HealthBuilder,
) -> Result<Vec<Device>> {
    let mut queue: VecDeque<PathBuf> = roots.into();
    let mut nodes = BTreeMap::<(String, u32, u32), Vec<(PathBuf, PlatformMetadata)>>::new();
    let mut aliases = Vec::<(PathBuf, PathBuf)>::new();

    while let Some(path) = queue.pop_front() {
        let metadata = match reader.metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                health.warn(
                    "devices",
                    format!("cannot stat {}: {error}", path.display()),
                );
                continue;
            }
        };
        match metadata.kind {
            FileKind::Directory => match reader.read_dir(&path) {
                Ok(mut entries) => {
                    entries.sort();
                    queue.extend(entries);
                }
                Err(error) => health.warn(
                    "devices",
                    format!("cannot read device directory {}: {error}", path.display()),
                ),
            },
            FileKind::CharacterDevice | FileKind::BlockDevice => {
                let (Some(major), Some(minor)) = (metadata.major, metadata.minor) else {
                    health.warn("devices", format!("{} has no major/minor", path.display()));
                    continue;
                };
                let kind = if metadata.kind == FileKind::CharacterDevice {
                    "char"
                } else {
                    "block"
                };
                nodes
                    .entry((kind.into(), major, minor))
                    .or_default()
                    .push((path, metadata));
            }
            FileKind::Symlink => match reader.canonicalize(&path) {
                Ok(target) if target != path => aliases.push((path, target)),
                Ok(_) => health.warn(
                    "devices",
                    format!("symlink cycle or unresolved alias {}", path.display()),
                ),
                Err(error) => health.warn(
                    "devices",
                    format!("symlink cycle or broken alias {}: {error}", path.display()),
                ),
            },
            FileKind::File | FileKind::Other => {}
        }
    }

    let mut devices = Vec::new();
    for ((kind, major, minor), mut paths) in nodes {
        paths.sort_by(|a, b| a.0.cmp(&b.0));
        let node_paths: BTreeSet<PathBuf> = paths.iter().map(|(path, _)| path.clone()).collect();
        let (canonical, metadata) = paths.remove(0);
        let mut device_aliases: BTreeSet<String> = paths
            .into_iter()
            .map(|(path, _)| path.to_string_lossy().into_owned())
            .collect();
        for (alias, target) in &aliases {
            if node_paths.contains(target) {
                device_aliases.insert(alias.to_string_lossy().into_owned());
            }
        }
        let label = match reader.selinux_context(&canonical) {
            Ok(label) => label,
            Err(error) => {
                health.warn(
                    "devices",
                    format!(
                        "cannot read SELinux xattr for {}: {error}",
                        canonical.display()
                    ),
                );
                None
            }
        };
        let mut device = Device {
            id: format!("device:{kind}:{major}:{minor}"),
            path: canonical.to_string_lossy().into_owned(),
            aliases: device_aliases.into_iter().collect(),
            kind: kind.clone(),
            major,
            minor,
            mode: metadata.mode,
            uid: metadata.uid,
            gid: metadata.gid,
            selinux_context: label,
            ..Device::default()
        };
        enrich_sysfs(reader, &mut device, health);
        devices.push(device);
    }
    enrich_sysfs_classes(reader, &mut devices, health);
    Ok(devices)
}

fn enrich_sysfs(reader: &dyn PlatformReader, device: &mut Device, health: &mut HealthBuilder) {
    let anchor = PathBuf::from(format!(
        "/sys/dev/{}/{}:{}",
        device.kind, device.major, device.minor
    ));
    let sysfs = match reader.canonicalize(&anchor) {
        Ok(path) => path,
        Err(error) => {
            health.warn(
                "devices",
                format!("cannot map {} through sysfs: {error}", device.path),
            );
            return;
        }
    };
    if !sysfs.starts_with("/sys/devices") {
        health.warn(
            "devices",
            format!(
                "sysfs anchor for {} resolves outside /sys/devices: {}",
                device.path,
                sysfs.display()
            ),
        );
        return;
    }
    device.sysfs_path = Some(sysfs.to_string_lossy().into_owned());
    match reader.canonicalize(&sysfs.join("subsystem")) {
        Ok(subsystem) => {
            let name = basename(&subsystem);
            device.class = name.clone();
            device.subsystem = name;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => health.warn(
            "devices",
            format!(
                "cannot resolve sysfs subsystem for {}: {error}",
                device.path
            ),
        ),
    }
    let mut driver_bases = vec![sysfs.clone()];
    let mut seen = BTreeSet::from([sysfs.clone()]);
    match reader.canonicalize(&sysfs.join("device")) {
        Ok(target) if target.starts_with("/sys/devices") => {
            for ancestor in target.ancestors().take(32) {
                if !ancestor.starts_with("/sys/devices") {
                    break;
                }
                if seen.insert(ancestor.to_path_buf()) {
                    driver_bases.push(ancestor.to_path_buf());
                }
            }
        }
        Ok(target) => health.warn(
            "devices",
            format!(
                "sysfs device link for {} resolves outside /sys/devices: {}",
                device.path,
                target.display()
            ),
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => health.warn(
            "devices",
            format!(
                "cannot resolve sysfs device link for {}: {error}",
                device.path
            ),
        ),
    }
    for ancestor in sysfs.ancestors().skip(1).take(32) {
        if !ancestor.starts_with("/sys/devices") {
            break;
        }
        if seen.insert(ancestor.to_path_buf()) {
            driver_bases.push(ancestor.to_path_buf());
        }
    }
    for base in driver_bases {
        match reader.canonicalize(&base.join("driver")) {
            Ok(driver) => {
                device.driver = basename(&driver);
                match reader.canonicalize(&driver.join("module")) {
                    Ok(module) => device.module = basename(&module),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => health.warn(
                        "devices",
                        format!("cannot resolve sysfs module for {}: {error}", device.path),
                    ),
                }
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => health.warn(
                "devices",
                format!("cannot resolve sysfs driver for {}: {error}", device.path),
            ),
        }
    }
}

fn enrich_sysfs_classes(
    reader: &dyn PlatformReader,
    devices: &mut [Device],
    health: &mut HealthBuilder,
) {
    let root = Path::new("/sys/class");
    let mut classes = match reader.read_dir(root) {
        Ok(classes) => classes,
        Err(error) => {
            health.warn("devices", format!("cannot enumerate /sys/class: {error}"));
            return;
        }
    };
    classes.sort();
    let by_sysfs: BTreeMap<String, usize> = devices
        .iter()
        .enumerate()
        .filter_map(|(index, device)| device.sysfs_path.clone().map(|path| (path, index)))
        .collect();
    for class in classes {
        let Some(class_name) = basename(&class) else {
            continue;
        };
        let mut entries = match reader.read_dir(&class) {
            Ok(entries) => entries,
            Err(error) => {
                health.warn(
                    "devices",
                    format!("cannot enumerate sysfs class {}: {error}", class.display()),
                );
                continue;
            }
        };
        entries.sort();
        for entry in entries {
            match reader.canonicalize(&entry) {
                Ok(target) => {
                    if let Some(index) = by_sysfs.get(&target.to_string_lossy().into_owned()) {
                        devices[*index].class = Some(class_name.clone());
                    }
                }
                Err(error) => health.warn(
                    "devices",
                    format!(
                        "cannot resolve sysfs class entry {}: {error}",
                        entry.display()
                    ),
                ),
            }
        }
    }
}

fn basename(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(|value| value.to_str())
        .map(str::to_string)
}

fn collect_modules(reader: &dyn PlatformReader, health: &mut HealthBuilder) -> Vec<Module> {
    let loaded = match read_text(reader, "/proc/modules") {
        Ok(text) => parse_module_names(&text)
            .into_iter()
            .collect::<BTreeSet<_>>(),
        Err(error) => {
            health.warn("modules", format!("cannot read /proc/modules: {error}"));
            BTreeSet::new()
        }
    };
    let mut names = loaded.clone();
    match reader.read_dir(Path::new("/sys/module")) {
        Ok(entries) => {
            names.extend(entries.iter().filter_map(|path| basename(path)));
        }
        Err(error) => health.warn("modules", format!("cannot read /sys/module: {error}")),
    }
    names
        .into_iter()
        .map(|name| Module {
            id: format!("module:{name}"),
            sysfs_path: Some(format!("/sys/module/{name}")),
            loaded: loaded.contains(&name),
            name,
        })
        .collect()
}

fn collect_processes(
    reader: &dyn PlatformReader,
    entries: Vec<PathBuf>,
    boot_id: &str,
    devices: &[Device],
    relations: &mut Vec<Relation>,
    health: &mut HealthBuilder,
) -> Vec<Process> {
    let mut device_by_path = BTreeMap::<String, String>::new();
    for device in devices {
        device_by_path.insert(device.path.clone(), device.id.clone());
        for alias in &device.aliases {
            device_by_path.insert(alias.clone(), device.id.clone());
        }
    }

    let mut processes = Vec::new();
    let mut entries = entries;
    entries.sort();
    for path in entries {
        let Some(pid) = basename(&path).and_then(|name| name.parse::<u32>().ok()) else {
            continue;
        };
        let starttime = match read_text(reader, &format!("/proc/{pid}/stat"))
            .and_then(|text| parse_process_starttime(&text).map_err(io::Error::other))
        {
            Ok(starttime) => starttime,
            Err(error) => {
                health.warn(
                    "processes",
                    format!("cannot establish identity for PID {pid}: {error}"),
                );
                continue;
            }
        };
        let status = match read_text(reader, &format!("/proc/{pid}/status"))
            .and_then(|text| parse_process_status(&text).map_err(io::Error::other))
        {
            Ok(status) => status,
            Err(error) => {
                health.warn(
                    "processes",
                    format!("cannot read status for PID {pid}: {error}"),
                );
                continue;
            }
        };
        let process_id = format!("process:{boot_id}:{pid}:{starttime}");
        let cmdline = match reader.read(Path::new(&format!("/proc/{pid}/cmdline"))) {
            Ok(raw) => raw
                .split(|byte| *byte == 0)
                .filter(|part| !part.is_empty())
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect(),
            Err(error) => {
                health.warn(
                    "processes",
                    format!("cannot read cmdline for PID {pid}: {error}"),
                );
                Vec::new()
            }
        };
        let executable = match reader.read_link(Path::new(&format!("/proc/{pid}/exe"))) {
            Ok(path) => Some(path.to_string_lossy().into_owned()),
            Err(error) => {
                health.warn(
                    "processes",
                    format!("cannot read executable for PID {pid}: {error}"),
                );
                None
            }
        };
        let selinux_domain = match read_text(reader, &format!("/proc/{pid}/attr/current")) {
            Ok(value) => value.trim().trim_end_matches('\0').to_string(),
            Err(error) => {
                health.warn(
                    "processes",
                    format!("cannot read SELinux domain for PID {pid}: {error}"),
                );
                String::new()
            }
        };
        let libraries = match read_text(reader, &format!("/proc/{pid}/maps")) {
            Ok(maps) => crate::symbolize::proc_maps::parse_maps_text(&maps)
                .into_iter()
                .filter_map(|entry| {
                    (entry.name.starts_with('/')
                        && (entry.name.ends_with(".so") || entry.name.contains(".so.")))
                    .then_some(entry.name)
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            Err(error) => {
                health.warn(
                    "processes",
                    format!("cannot read maps for PID {pid}: {error}"),
                );
                Vec::new()
            }
        };
        let relation_checkpoint = relations.len();
        let mut file_descriptors = Vec::new();
        match reader.read_dir(Path::new(&format!("/proc/{pid}/fd"))) {
            Ok(mut fds) => {
                fds.sort();
                for fd_path in fds {
                    let Some(fd) = basename(&fd_path).and_then(|name| name.parse::<u32>().ok())
                    else {
                        continue;
                    };
                    let target = match reader.read_link(&fd_path) {
                        Ok(target) => target.to_string_lossy().into_owned(),
                        Err(error) => {
                            health.warn(
                                "processes",
                                format!("cannot read PID {pid} fd {fd}: {error}"),
                            );
                            continue;
                        }
                    };
                    let target = target
                        .strip_suffix(" (deleted)")
                        .unwrap_or(&target)
                        .to_string();
                    let device_id = device_by_path.get(&target).cloned().or_else(|| {
                        reader.canonicalize(&fd_path).ok().and_then(|path| {
                            device_by_path
                                .get(&path.to_string_lossy().into_owned())
                                .cloned()
                        })
                    });
                    if let Some(device_id) = device_id.as_ref() {
                        relations.push(make_relation(
                            "proc_fd",
                            &process_id,
                            device_id,
                            "proc_fd",
                            "exact",
                            None,
                            None,
                            None,
                            None,
                        ));
                    }
                    file_descriptors.push(OpenFile {
                        fd,
                        target,
                        device_id,
                    });
                }
            }
            Err(error) => health.warn(
                "processes",
                format!("cannot enumerate file descriptors for PID {pid}: {error}"),
            ),
        }
        file_descriptors.sort_by_key(|fd| fd.fd);
        let final_starttime = read_text(reader, &format!("/proc/{pid}/stat"))
            .and_then(|text| parse_process_starttime(&text).map_err(io::Error::other));
        if !matches!(final_starttime, Ok(value) if value == starttime) {
            relations.truncate(relation_checkpoint);
            health.warn(
                "processes",
                format!("PID {pid} identity changed while collecting process evidence"),
            );
            continue;
        }
        processes.push(Process {
            id: process_id,
            pid,
            uid: status.uid,
            gid: status.gid,
            cmdline,
            executable,
            starttime,
            boot_id: boot_id.to_string(),
            selinux_domain,
            libraries,
            file_descriptors,
        });
    }
    processes
}

fn collect_services(
    reader: &dyn PlatformReader,
    processes: &[Process],
    relations: &mut Vec<Relation>,
    health: &mut HealthBuilder,
) -> Vec<Service> {
    let mut services = BTreeMap::<(String, String), Service>::new();

    match reader.command_output("service", &["list"]) {
        Ok(output) if output.success => {
            for item in parse_service_list_inventory(&output.stdout) {
                let mut service = inventory_service(&item.name, "binder", false);
                service.descriptor = item.descriptor;
                match reader.command_output("dumpsys", &["--pid", &item.name]) {
                    Ok(pid_output) if pid_output.success => {
                        service.pid = parse_dumpsys_pid(&pid_output.stdout);
                        if service.pid.is_none() {
                            health.warn(
                                "services",
                                format!("dumpsys --pid did not prove a PID for {}", item.name),
                            );
                        }
                    }
                    Ok(pid_output) => health.warn(
                        "services",
                        format!(
                            "dumpsys --pid {} failed: {}",
                            item.name,
                            pid_output.stderr.trim()
                        ),
                    ),
                    Err(error) => health.warn(
                        "services",
                        format!("cannot run dumpsys --pid {}: {error}", item.name),
                    ),
                }
                service.sources.push("service list + dumpsys --pid".into());
                merge_service(&mut services, service);
            }
        }
        Ok(output) => health.warn(
            "services",
            format!("service list failed: {}", output.stderr.trim()),
        ),
        Err(error) => health.warn("services", format!("cannot run service list: {error}")),
    }

    match reader.command_output("lshal", &["-i", "-p"]) {
        Ok(output) if output.success => {
            for item in parse_lshal_inventory(&output.stdout) {
                let mut service = inventory_service(&item.name, "hwbinder", true);
                service.pid = item.pid;
                service.sources.push("lshal -ip".into());
                merge_service(&mut services, service);
            }
        }
        Ok(output) => health.warn(
            "services",
            format!("lshal -ip failed: {}", output.stderr.trim()),
        ),
        Err(error) => health.warn("services", format!("cannot run lshal -ip: {error}")),
    }

    match reader.command_output("vndservice", &["list"]) {
        Ok(output) if output.success => {
            for item in parse_vndservice_list(&output.stdout) {
                let mut service = inventory_service(&item.name, "vndbinder", false);
                service.descriptor = item.descriptor;
                service.sources.push("vndservice list".into());
                merge_service(&mut services, service);
            }
        }
        Ok(output) => health.warn(
            "services",
            format!("vndservice list failed: {}", output.stderr.trim()),
        ),
        Err(error) => health.warn("services", format!("cannot run vndservice list: {error}")),
    }

    for path in vintf_paths(reader, health) {
        match reader.read(&path) {
            Ok(raw) => match parse_vintf_manifest(&String::from_utf8_lossy(&raw)) {
                Ok(declarations) => {
                    for declaration in declarations {
                        let name = declaration.fqname();
                        let mut service = inventory_service(
                            &name,
                            declaration
                                .transport
                                .as_deref()
                                .unwrap_or(&declaration.format),
                            true,
                        );
                        service.declared = true;
                        service.sources.push(path.to_string_lossy().into_owned());
                        let matching_keys: Vec<_> = services
                            .keys()
                            .filter(|(_, service_name)| service_name == &service.name)
                            .cloned()
                            .collect();
                        if let [key] = matching_keys.as_slice() {
                            merge_service_fields(
                                services.get_mut(key).expect("key exists"),
                                service,
                            );
                        } else {
                            merge_service(&mut services, service);
                        }
                    }
                }
                Err(error) => {
                    health.warn("vintf", format!("cannot parse {}: {error}", path.display()))
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => health.warn("vintf", format!("cannot read {}: {error}", path.display())),
        }
    }

    let by_pid: BTreeMap<u32, &Process> = processes
        .iter()
        .map(|process| (process.pid, process))
        .collect();
    for service in services.values_mut() {
        service.id = format!("service:{}:{}", service.transport, service.name);
        service.sources.sort();
        service.sources.dedup();
        if let Some(process) = service.pid.and_then(|pid| by_pid.get(&pid).copied()) {
            let stat_path = PathBuf::from(format!("/proc/{}/stat", process.pid));
            match reader
                .read(&stat_path)
                .ok()
                .and_then(|raw| parse_process_starttime(&String::from_utf8_lossy(&raw)).ok())
            {
                Some(starttime) if starttime == process.starttime => {}
                _ => {
                    health.warn(
                        "services",
                        format!(
                            "PID {} identity changed or could not be revalidated while joining service {}",
                            process.pid, service.name
                        ),
                    );
                    continue;
                }
            }
            service.process_id = Some(process.id.clone());
            service.selinux_domain =
                (!process.selinux_domain.is_empty()).then(|| process.selinux_domain.clone());
            service.executable = process.executable.clone();
            service.libraries = process.libraries.clone();
            service.devices = process
                .file_descriptors
                .iter()
                .filter_map(|fd| fd.device_id.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            relations.push(make_relation(
                "served_by",
                &service.id,
                &process.id,
                "inventory",
                "exact",
                None,
                None,
                None,
                None,
            ));
        }
    }
    services.into_values().collect()
}

fn inventory_service(name: &str, transport: &str, hal: bool) -> Service {
    Service {
        name: name.to_string(),
        transport: transport.to_string(),
        hal,
        confidence: "exact".into(),
        ..Service::default()
    }
}

fn merge_service(services: &mut BTreeMap<(String, String), Service>, incoming: Service) {
    let key = (incoming.transport.clone(), incoming.name.clone());
    if let Some(current) = services.get_mut(&key) {
        merge_service_fields(current, incoming);
    } else {
        services.insert(key, incoming);
    }
}

fn merge_service_fields(current: &mut Service, incoming: Service) {
    if current.pid.is_none() {
        current.pid = incoming.pid;
    }
    if current.descriptor.is_none() {
        current.descriptor = incoming.descriptor;
    }
    current.declared |= incoming.declared;
    current.hal |= incoming.hal;
    current.sources.extend(incoming.sources);
}

fn vintf_paths(reader: &dyn PlatformReader, health: &mut HealthBuilder) -> Vec<PathBuf> {
    const ROOTS: &[&str] = &["/system", "/vendor", "/product", "/system_ext", "/odm"];
    let mut paths = BTreeSet::new();
    for root in ROOTS {
        paths.insert(PathBuf::from(format!("{root}/etc/vintf/manifest.xml")));
        let fragments = PathBuf::from(format!("{root}/etc/vintf/manifest"));
        match reader.read_dir(&fragments) {
            Ok(entries) => {
                paths.extend(
                    entries.into_iter().filter(|path| {
                        path.extension().and_then(|ext| ext.to_str()) == Some("xml")
                    }),
                );
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => health.warn(
                "vintf",
                format!("cannot enumerate {}: {error}", fragments.display()),
            ),
        }
    }
    paths.into_iter().collect()
}

#[allow(clippy::too_many_arguments)]
fn make_relation(
    relation_type: &str,
    from: &str,
    to: &str,
    source: &str,
    confidence: &str,
    causal_relation: Option<String>,
    trace_id: Option<String>,
    scenario_id: Option<String>,
    span_id: Option<String>,
) -> Relation {
    let id = format!(
        "relation:{relation_type}:{from}:{to}:{}:{}",
        trace_id.as_deref().unwrap_or("static"),
        span_id.as_deref().unwrap_or("none")
    );
    Relation {
        id,
        relation_type: relation_type.into(),
        from: from.into(),
        to: to.into(),
        evidence: Evidence {
            source: source.into(),
            detail: None,
        },
        confidence: confidence.into(),
        causal_relation,
        trace_id,
        scenario_id,
        span_id,
        ioctl: None,
    }
}

#[derive(Clone, Debug, Default)]
struct TraceRoot {
    scenario_id: String,
    package: Option<String>,
    uid: Option<u32>,
}

/// Stream a causal NDJSON capture into an existing static snapshot.
pub fn import_capture<R: BufRead>(snapshot: &mut SurfaceSnapshot, reader: R) -> Result<()> {
    let capture = crate::capture_normalize::normalize_capture(reader)?;
    let health = capture.health.as_ref();
    if health.is_none() {
        add_snapshot_warning(
            snapshot,
            "imported capture has no final capture_health record",
        );
    }
    let merge_confidence = if health
        .and_then(|health| health.boot_id.as_deref())
        .is_some_and(|boot_id| !boot_id.is_empty() && boot_id == snapshot.device.boot_id)
    {
        "exact"
    } else {
        add_snapshot_warning(
            snapshot,
            "capture boot identity is missing or differs; current PID joins are candidate",
        );
        "candidate"
    };
    if let Some(health) = health {
        if health.degraded || health.output_cap_hit {
            add_snapshot_warning(snapshot, "imported capture health is degraded");
        }
        if let Some(fingerprint) = health.fingerprint.as_deref() {
            if !snapshot.device.fingerprint.is_empty() && fingerprint != snapshot.device.fingerprint
            {
                add_snapshot_warning(
                    snapshot,
                    "capture fingerprint differs from the static snapshot",
                );
            }
        }
    }
    for warning in &capture.health_warnings {
        add_snapshot_warning(snapshot, format!("capture health: {warning}"));
    }

    let mut roots = BTreeMap::<String, TraceRoot>::new();
    for marker in &capture.markers {
        let Some(trace_id) = marker.trace_id.as_ref() else {
            continue;
        };
        let root = roots.entry(trace_id.clone()).or_default();
        if marker.phase.as_deref() == Some("start") || root.scenario_id.is_empty() {
            root.scenario_id = marker
                .scenario_id
                .clone()
                .unwrap_or_else(|| marker.name.clone());
        }
        if marker.root_package.is_some() {
            root.package = marker.root_package.clone();
        }
        if marker.root_uid.is_some() {
            root.uid = marker.root_uid;
        }
    }
    for binder in &capture.binders {
        if let Some(trace_id) = binder.trace_id.as_ref() {
            let root = roots.entry(trace_id.clone()).or_default();
            root.scenario_id = binder
                .scenario_id
                .clone()
                .unwrap_or_else(|| root.scenario_id.clone());
            root.package = binder.root_package.clone().or(root.package.clone());
            root.uid = binder.root_uid.or(root.uid);
        }
    }
    for syscall in &capture.syscalls {
        if let Some(trace_id) = syscall.trace_id.as_ref() {
            let root = roots.entry(trace_id.clone()).or_default();
            root.scenario_id = syscall
                .scenario_id
                .clone()
                .unwrap_or_else(|| root.scenario_id.clone());
            root.package = syscall.root_package.clone().or(root.package.clone());
            root.uid = syscall.root_uid.or(root.uid);
        }
    }
    for denial in &capture.denials {
        if let Some(trace_id) = denial.trace_id.as_ref() {
            let root = roots.entry(trace_id.clone()).or_default();
            root.scenario_id = denial
                .scenario_id
                .clone()
                .unwrap_or_else(|| root.scenario_id.clone());
            root.package = denial.root_package.clone().or(root.package.clone());
            root.uid = denial.root_uid.or(root.uid);
        }
    }
    if let Some(health) = health {
        for root in roots.values_mut() {
            root.package = root.package.clone().or(health.root_package.clone());
            root.uid = root.uid.or(health.root_uid);
        }
    }

    let capture_health = if health.is_none()
        || health.is_some_and(|health| health.degraded || health.output_cap_hit)
    {
        "degraded"
    } else {
        "complete"
    };
    for (trace_id, root) in &roots {
        let scenario_id = if root.scenario_id.is_empty() {
            "unknown".to_string()
        } else {
            root.scenario_id.clone()
        };
        snapshot.captures.push(CaptureRecord {
            id: format!("capture:{trace_id}:{scenario_id}"),
            trace_id: trace_id.clone(),
            scenario_id,
            root_package: root.package.clone(),
            root_uid: root.uid,
            boot_id: health.and_then(|health| health.boot_id.clone()),
            fingerprint: health.and_then(|health| health.fingerprint.clone()),
            health: capture_health.into(),
        });
    }

    let mut span_service = BTreeMap::<(String, String), String>::new();
    let mut pid_service = BTreeMap::<(String, u32), BTreeSet<String>>::new();
    for binder in capture.binders {
        let Some(trace_id) = binder.trace_id.clone() else {
            continue;
        };
        let scenario_id = binder
            .scenario_id
            .clone()
            .or_else(|| roots.get(&trace_id).map(|root| root.scenario_id.clone()))
            .filter(|value| !value.is_empty());
        let root = roots.get(&trace_id).cloned().unwrap_or_default();
        let caller_uid = binder
            .caller_uid
            .or_else(|| (binder.depth == Some(0)).then_some(root.uid).flatten());
        let (caller, caller_confidence) = capture_process(
            snapshot,
            binder.caller_pid,
            &trace_id,
            caller_uid,
            merge_confidence,
            binder.ts_ns,
        );
        let (callee, callee_confidence) = capture_process(
            snapshot,
            binder.callee_pid,
            &trace_id,
            None,
            merge_confidence,
            binder.ts_ns,
        );
        if let Some(root_id) = root_id(&root) {
            snapshot.relations.push(make_relation(
                "root_process",
                &root_id,
                &caller,
                "capture",
                &caller_confidence,
                Some(relation_name(binder.relation).into()),
                Some(trace_id.clone()),
                scenario_id.clone(),
                binder.span_id.clone(),
            ));
        }

        let service = resolve_capture_service(
            snapshot,
            binder.service.as_deref(),
            binder.callee_pid,
            &binder.service_candidates,
        );
        match service {
            Some((service_id, service_confidence)) => {
                let attribution_confidence = weakest_confidence(&[
                    &caller_confidence,
                    service_confidence,
                    binder.attribution_confidence.as_deref().unwrap_or("exact"),
                ]);
                snapshot.relations.push(make_relation(
                    "binder",
                    &caller,
                    &service_id,
                    "capture",
                    attribution_confidence,
                    Some(relation_name(binder.relation).into()),
                    Some(trace_id.clone()),
                    scenario_id.clone(),
                    binder.span_id.clone(),
                ));
                snapshot.relations.push(make_relation(
                    "served_by",
                    &service_id,
                    &callee,
                    "capture",
                    weakest_confidence(&[&callee_confidence, service_confidence]),
                    Some("exact".into()),
                    Some(trace_id.clone()),
                    scenario_id.clone(),
                    binder.span_id.clone(),
                ));
                if let Some(span_id) = binder.span_id {
                    span_service.insert((trace_id.clone(), span_id), service_id.clone());
                }
                pid_service
                    .entry((trace_id, binder.callee_pid))
                    .or_default()
                    .insert(service_id);
            }
            None => snapshot.relations.push(make_relation(
                "binder",
                &caller,
                &callee,
                "capture",
                weakest_confidence(&[&caller_confidence, &callee_confidence]),
                Some(relation_name(binder.relation).into()),
                Some(trace_id),
                scenario_id,
                binder.span_id,
            )),
        }
    }

    let device_by_path = device_path_index(&snapshot.devices);
    for syscall in capture.syscalls {
        let Some(trace_id) = syscall.trace_id.clone() else {
            continue;
        };
        let root = roots.get(&trace_id).cloned().unwrap_or_default();
        let process_uid = syscall
            .uid
            .or_else(|| (syscall.depth == Some(0)).then_some(root.uid).flatten());
        let (process_id, process_confidence) = capture_process(
            snapshot,
            syscall.pid,
            &trace_id,
            process_uid,
            merge_confidence,
            syscall.ts_ns,
        );
        let scenario_id = syscall
            .scenario_id
            .clone()
            .or_else(|| roots.get(&trace_id).map(|root| root.scenario_id.clone()))
            .filter(|value| !value.is_empty());
        if syscall.depth == Some(0) {
            if let Some(root_id) = root_id(&root) {
                snapshot.relations.push(make_relation(
                    "root_process",
                    &root_id,
                    &process_id,
                    "capture",
                    &process_confidence,
                    Some(relation_name(syscall.relation).into()),
                    Some(trace_id.clone()),
                    scenario_id.clone(),
                    syscall.span_id.clone(),
                ));
            }
        }
        if syscall.name != "ioctl" && syscall.ioctl_cmd.is_none() {
            continue;
        }
        let Some(device_id) = syscall
            .fd_path
            .as_ref()
            .and_then(|path| device_by_path.get(path).cloned())
        else {
            continue;
        };
        let label = syscall
            .ioctl_name
            .clone()
            .or_else(|| syscall.ioctl_cmd.map(ioctl_label))
            .unwrap_or_else(|| "cmd=unknown".into());
        let mut relation = make_relation(
            "ioctl",
            &process_id,
            &device_id,
            "capture",
            &process_confidence,
            Some(relation_name(syscall.relation).into()),
            Some(trace_id.clone()),
            scenario_id.clone(),
            syscall.span_id.clone(),
        );
        relation.ioctl = Some(label.clone());
        relation.evidence.detail = Some(label.clone());
        snapshot.relations.push(relation);

        let service_id = syscall
            .parent_span_id
            .as_ref()
            .and_then(|parent| span_service.get(&(trace_id.clone(), parent.clone())))
            .cloned()
            .or_else(|| {
                pid_service
                    .get(&(trace_id.clone(), syscall.pid))
                    .and_then(|ids| {
                        (ids.len() == 1)
                            .then(|| ids.iter().next().cloned())
                            .flatten()
                    })
            });
        if let Some(service_id) = service_id {
            if let Some(service) = snapshot
                .services
                .iter_mut()
                .find(|service| service.id == service_id)
            {
                service.observed_devices.push(device_id);
                service.observed_ioctls.push(label);
            }
        }
    }

    for denial in capture.denials {
        let Some(trace_id) = denial.trace_id.clone() else {
            continue;
        };
        let root = roots.get(&trace_id).cloned().unwrap_or_default();
        let process_uid = denial
            .uid
            .or_else(|| (denial.depth == Some(0)).then_some(root.uid).flatten());
        let (process_id, process_confidence) = capture_process(
            snapshot,
            denial.pid,
            &trace_id,
            process_uid,
            merge_confidence,
            denial.ts_ns,
        );
        let scenario_id = denial
            .scenario_id
            .clone()
            .or_else(|| roots.get(&trace_id).map(|root| root.scenario_id.clone()))
            .filter(|value| !value.is_empty());
        if denial.depth == Some(0) {
            if let Some(root_id) = root_id(&root) {
                snapshot.relations.push(make_relation(
                    "root_process",
                    &root_id,
                    &process_id,
                    "capture",
                    &process_confidence,
                    Some(relation_name(denial.relation).into()),
                    Some(trace_id.clone()),
                    scenario_id.clone(),
                    denial.span_id.clone(),
                ));
            }
        }
        let Some(device_id) = denial
            .path
            .as_ref()
            .and_then(|path| device_by_path.get(path).cloned())
        else {
            continue;
        };
        let mut relation = make_relation(
            "selinux_denial",
            &process_id,
            &device_id,
            "capture",
            &process_confidence,
            Some(relation_name(denial.relation).into()),
            Some(trace_id),
            scenario_id,
            denial.span_id,
        );
        relation.evidence.detail = Some(format!(
            "{} {}:{} {{ {} }} {}",
            denial.source_domain,
            denial.target_type,
            denial.tclass,
            denial.permissions.join(" "),
            denial.result,
        ));
        snapshot.relations.push(relation);
    }

    finish_snapshot(snapshot);
    Ok(())
}

fn relation_name(relation: crate::capture_normalize::CausalRelation) -> &'static str {
    match relation {
        crate::capture_normalize::CausalRelation::Exact => "exact",
        crate::capture_normalize::CausalRelation::Inferred => "inferred",
    }
}

fn root_id(root: &TraceRoot) -> Option<String> {
    root.package
        .as_ref()
        .map(|package| format!("package:{package}"))
        .or_else(|| root.uid.map(|uid| format!("uid:{uid}")))
}

fn capture_process(
    snapshot: &mut SurfaceSnapshot,
    pid: u32,
    trace_id: &str,
    uid: Option<u32>,
    merge_confidence: &str,
    event_ts_ns: Option<u64>,
) -> (String, String) {
    if pid != 0 {
        let matches: Vec<_> = snapshot
            .processes
            .iter()
            .filter(|process| process.pid == pid && process.starttime != 0)
            .collect();
        if matches.len() == 1 {
            let process = matches[0];
            let exact_identity = merge_confidence == "exact"
                && event_ts_ns.is_some_and(|timestamp| process_started_by(process, timestamp));
            return (
                process.id.clone(),
                if exact_identity { "exact" } else { "candidate" }.into(),
            );
        }
    }
    let id = format!("process:capture:{trace_id}:{pid}");
    if let Some(process) = snapshot
        .processes
        .iter_mut()
        .find(|process| process.id == id)
    {
        if let Some(uid) = uid {
            process.uid = uid;
        }
    } else {
        snapshot.processes.push(Process {
            id: id.clone(),
            pid,
            uid: uid.unwrap_or_default(),
            boot_id: if merge_confidence == "exact" {
                snapshot.device.boot_id.clone()
            } else {
                String::new()
            },
            ..Process::default()
        });
    }
    (id, "exact".into())
}

fn process_started_by(process: &Process, timestamp_ns: u64) -> bool {
    // SAFETY: sysconf has no pointer arguments and only reads a process-wide constant.
    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks_per_second <= 0 {
        return false;
    }
    let start_ns =
        u128::from(process.starttime).saturating_mul(1_000_000_000) / ticks_per_second as u128;
    start_ns <= u128::from(timestamp_ns)
}

fn resolve_capture_service(
    snapshot: &mut SurfaceSnapshot,
    name: Option<&str>,
    callee_pid: u32,
    candidates: &[String],
) -> Option<(String, &'static str)> {
    if let Some(name) = name {
        return resolve_named_capture_service(snapshot, name, callee_pid, "exact")
            .map(|service| (service, "exact"));
    }
    if candidates.len() == 1 {
        let name = candidates.first()?.as_str();
        return resolve_named_capture_service(snapshot, name, callee_pid, "candidate")
            .map(|service| (service, "candidate"));
    }
    let matches: Vec<_> = snapshot
        .services
        .iter()
        .filter(|service| service.pid == Some(callee_pid))
        .collect();
    (matches.len() == 1).then(|| (matches[0].id.clone(), "candidate"))
}

fn resolve_named_capture_service(
    snapshot: &mut SurfaceSnapshot,
    name: &str,
    callee_pid: u32,
    confidence: &str,
) -> Option<String> {
    let matches: Vec<_> = snapshot
        .services
        .iter()
        .filter(|service| service.name == name)
        .collect();
    if let [service] = matches.as_slice() {
        return Some(service.id.clone());
    }
    if !matches.is_empty() {
        return None;
    }
    let id = format!("service:binder:{name}");
    snapshot.services.push(Service {
        id: id.clone(),
        name: name.into(),
        transport: "binder".into(),
        pid: (callee_pid != 0).then_some(callee_pid),
        hal: name.contains(".hardware.") || name.starts_with("vendor."),
        confidence: confidence.into(),
        sources: vec!["capture".into()],
        ..Service::default()
    });
    Some(id)
}

fn weakest_confidence(values: &[&str]) -> &'static str {
    if values.iter().all(|value| *value == "exact") {
        "exact"
    } else {
        "candidate"
    }
}

fn device_path_index(devices: &[Device]) -> BTreeMap<String, String> {
    let mut index = BTreeMap::new();
    for device in devices {
        index.insert(device.path.clone(), device.id.clone());
        for alias in &device.aliases {
            index.insert(alias.clone(), device.id.clone());
        }
    }
    index
}

fn add_snapshot_warning(snapshot: &mut SurfaceSnapshot, warning: impl Into<String>) {
    let warning = warning.into();
    snapshot.health.status = "degraded".into();
    if !snapshot.health.warnings.contains(&warning) {
        snapshot.health.warnings.push(warning.clone());
    }
    let collector = match snapshot
        .health
        .collectors
        .iter_mut()
        .find(|collector| collector.name == "capture")
    {
        Some(collector) => collector,
        None => {
            snapshot.health.collectors.push(CollectorHealth {
                name: "capture".into(),
                status: "complete".into(),
                scope: vec!["causal NDJSON".into()],
                warnings: Vec::new(),
            });
            snapshot.health.collectors.last_mut().expect("just pushed")
        }
    };
    collector.status = "degraded".into();
    if !collector.warnings.contains(&warning) {
        collector.warnings.push(warning);
    }
}

pub fn reachable(snapshot: &SurfaceSnapshot, selector: &RootSelector) -> Result<ReachableResult> {
    let root_id = selector.id();
    let matching_captures: Vec<_> = snapshot
        .captures
        .iter()
        .filter(|capture| match selector {
            RootSelector::Package(package) => capture.root_package.as_deref() == Some(package),
            RootSelector::Uid(uid) => capture.root_uid == Some(*uid),
        })
        .collect();
    let trace_ids: BTreeSet<String> = snapshot
        .captures
        .iter()
        .filter(|capture| match selector {
            RootSelector::Package(package) => capture.root_package.as_deref() == Some(package),
            RootSelector::Uid(uid) => capture.root_uid == Some(*uid),
        })
        .map(|capture| capture.trace_id.clone())
        .collect();
    let causal: Vec<Relation> = snapshot
        .relations
        .iter()
        .filter(|relation| {
            relation
                .trace_id
                .as_ref()
                .is_some_and(|trace_id| trace_ids.contains(trace_id))
                && relation.evidence.source == "capture"
                && matches!(
                    relation.relation_type.as_str(),
                    "root_process" | "binder" | "served_by" | "ioctl"
                )
        })
        .cloned()
        .collect();
    let mut nodes = BTreeSet::from([root_id.clone()]);
    loop {
        let before = nodes.len();
        for relation in &causal {
            if nodes.contains(&relation.from) {
                nodes.insert(relation.to.clone());
            }
        }
        if nodes.len() == before {
            break;
        }
    }
    let relations: Vec<_> = causal
        .into_iter()
        .filter(|relation| nodes.contains(&relation.from) && nodes.contains(&relation.to))
        .collect();
    let services = snapshot
        .services
        .iter()
        .filter(|service| nodes.contains(&service.id))
        .cloned()
        .collect();
    let processes = snapshot
        .processes
        .iter()
        .filter(|process| nodes.contains(&process.id))
        .cloned()
        .collect();
    let devices = snapshot
        .devices
        .iter()
        .filter(|device| nodes.contains(&device.id))
        .cloned()
        .collect();
    let mut warnings = Vec::new();
    let status = if matching_captures.is_empty() {
        warnings.push(format!("no matching capture for {root_id}"));
        "no_evidence"
    } else if matching_captures
        .iter()
        .any(|capture| capture.health != "complete")
    {
        warnings.push("reachable evidence is degraded or incomplete".into());
        "degraded"
    } else {
        "complete"
    };
    let confidence = if relations.is_empty() {
        if !matching_captures.is_empty() {
            warnings.push("matching capture contains no supported causal reachability edges".into());
        }
        "none"
    } else if relations.iter().all(|relation| {
        relation.confidence == "exact"
            && relation.causal_relation.as_deref() == Some("exact")
    }) {
        "exact"
    } else {
        "candidate"
    };
    let mut captures: Vec<_> = matching_captures
        .iter()
        .map(|capture| capture.id.clone())
        .collect();
    captures.sort();
    Ok(ReachableResult {
        schema: QUERY_SCHEMA.into(),
        root: root_id,
        health: ReachabilityHealth {
            status: status.into(),
            confidence: confidence.into(),
            captures,
            warnings,
        },
        nodes: nodes.into_iter().collect(),
        relations,
        services,
        processes,
        devices,
    })
}

fn explain(snapshot: &SurfaceSnapshot, selector: &str) -> Result<Value> {
    let mut matches = Vec::<(String, Value)>::new();
    for service in &snapshot.services {
        if service.id == selector || service.name == selector {
            matches.push((
                service.id.clone(),
                json!({"kind": "service", "value": service}),
            ));
        }
    }
    for device in &snapshot.devices {
        if device.id == selector
            || device.path == selector
            || device.aliases.iter().any(|alias| alias == selector)
        {
            matches.push((
                device.id.clone(),
                json!({"kind": "device", "value": device}),
            ));
        }
    }
    matches.sort_by(|a, b| a.0.cmp(&b.0));
    matches.dedup_by(|a, b| a.0 == b.0);
    let (id, entity) = match matches.as_slice() {
        [(id, entity)] => (id, entity),
        [] => bail!("surface selector '{selector}' did not match a service or device"),
        _ => bail!("surface selector '{selector}' is ambiguous"),
    };
    let relations: Vec<_> = snapshot
        .relations
        .iter()
        .filter(|relation| relation.from == *id || relation.to == *id)
        .collect();
    Ok(json!({
        "schema": QUERY_SCHEMA,
        "selector": selector,
        "entity": entity,
        "relations": relations,
    }))
}

fn finish_snapshot(snapshot: &mut SurfaceSnapshot) {
    for service in &mut snapshot.services {
        service.libraries.sort();
        service.libraries.dedup();
        service.devices.sort();
        service.devices.dedup();
        service.observed_devices.sort();
        service.observed_devices.dedup();
        service.observed_ioctls.sort();
        service.observed_ioctls.dedup();
        service.sources.sort();
        service.sources.dedup();
    }
    snapshot.services.sort_by(|a, b| a.id.cmp(&b.id));
    snapshot.services.dedup_by(|a, b| a.id == b.id);
    for process in &mut snapshot.processes {
        process.libraries.sort();
        process.libraries.dedup();
        process.file_descriptors.sort_by_key(|fd| fd.fd);
        process.file_descriptors.dedup_by_key(|fd| fd.fd);
    }
    snapshot.processes.sort_by(|a, b| a.id.cmp(&b.id));
    snapshot.processes.dedup_by(|a, b| a.id == b.id);
    for device in &mut snapshot.devices {
        device.aliases.sort();
        device.aliases.dedup();
    }
    snapshot.devices.sort_by(|a, b| a.id.cmp(&b.id));
    snapshot.devices.dedup_by(|a, b| a.id == b.id);
    snapshot.modules.sort_by(|a, b| a.id.cmp(&b.id));
    snapshot.modules.dedup_by(|a, b| a.id == b.id);
    snapshot.relations.sort_by(|a, b| a.id.cmp(&b.id));
    snapshot.relations.dedup_by(|a, b| a.id == b.id);
    snapshot.captures.sort_by(|a, b| a.id.cmp(&b.id));
    snapshot.captures.dedup_by(|a, b| a.id == b.id);
    snapshot
        .health
        .collectors
        .sort_by(|a, b| a.name.cmp(&b.name));
    for collector in &mut snapshot.health.collectors {
        collector.scope.sort();
        collector.scope.dedup();
        collector.warnings.sort();
        collector.warnings.dedup();
    }
    snapshot.health.warnings.sort();
    snapshot.health.warnings.dedup();
    if !snapshot.health.warnings.is_empty()
        || snapshot
            .health
            .collectors
            .iter()
            .any(|collector| collector.status == "degraded")
    {
        snapshot.health.status = "degraded".into();
    }
}

fn read_snapshot(path: &str) -> Result<SurfaceSnapshot> {
    let reader = open_input(path)?;
    let mut snapshot: SurfaceSnapshot = serde_json::from_reader(reader)
        .with_context(|| format!("parsing surface snapshot {path}"))?;
    if snapshot.schema != SURFACE_SCHEMA {
        bail!(
            "unsupported surface schema '{}' (expected {SURFACE_SCHEMA})",
            snapshot.schema
        );
    }
    finish_snapshot(&mut snapshot);
    Ok(snapshot)
}

fn open_input(path: &str) -> Result<Box<dyn BufRead>> {
    if path == "-" {
        Ok(Box::new(BufReader::new(io::stdin())))
    } else {
        let file = fs::File::open(path).with_context(|| format!("opening {path}"))?;
        Ok(Box::new(BufReader::new(file)))
    }
}

fn write_json<T: Serialize>(path: Option<&str>, value: &T) -> Result<()> {
    match path {
        Some(path) => {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)
                .with_context(|| format!("opening {path} for secure output"))?;
            let metadata = file
                .metadata()
                .with_context(|| format!("inspecting secure output {path}"))?;
            if !metadata.file_type().is_file()
                || metadata.nlink() != 1
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
            {
                bail!("secure output must be an owned regular file with one link: {path}");
            }
            file.set_len(0)
                .with_context(|| format!("truncating verified output {path}"))?;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod 0600 {path}"))?;
            serde_json::to_writer_pretty(&mut file, value)
                .with_context(|| format!("writing JSON to {path}"))?;
            writeln!(file).with_context(|| format!("finishing JSON output {path}"))?;
            file.flush().with_context(|| format!("flushing {path}"))
        }
        None => {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            serde_json::to_writer_pretty(&mut out, value).context("writing JSON to stdout")?;
            writeln!(out).context("finishing JSON output")
        }
    }
}

fn parse_duration(raw: &str) -> Result<Duration> {
    let raw = raw.trim();
    let (number, multiplier) = if let Some(value) = raw.strip_suffix("ms") {
        (value, 1_u64)
    } else if let Some(value) = raw.strip_suffix('s') {
        (value, 1_000)
    } else if let Some(value) = raw.strip_suffix('m') {
        (value, 60_000)
    } else if let Some(value) = raw.strip_suffix('h') {
        (value, 3_600_000)
    } else {
        bail!("invalid observation duration '{raw}' (expected ms, s, m, or h suffix)");
    };
    let value: u64 = number
        .parse()
        .with_context(|| format!("invalid observation duration '{raw}'"))?;
    let millis = value
        .checked_mul(multiplier)
        .context("observation duration overflow")?;
    if millis == 0 {
        bail!("observation duration must be greater than zero");
    }
    Ok(Duration::from_millis(millis))
}

struct ObservationDir {
    path: PathBuf,
    cleaned: bool,
}

impl ObservationDir {
    fn create() -> Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut bases = vec![PathBuf::from("/data/local"), std::env::temp_dir()];
        if !bases.iter().any(|path| path == Path::new("/tmp")) {
            bases.push(PathBuf::from("/tmp"));
        }
        let mut failures = Vec::new();
        for base in bases {
            match secure_observation_base(&base) {
                Ok(true) => {}
                Ok(false) => {
                    failures.push(format!("{} is not a trusted temp base", base.display()));
                    continue;
                }
                Err(error) => {
                    failures.push(format!("{}: {error}", base.display()));
                    continue;
                }
            }
            for attempt in 0..32_u32 {
                let path = base.join(format!(
                    "neutron-surface-{}-{nonce}-{attempt}",
                    std::process::id()
                ));
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => {
                        return Ok(Self {
                            path,
                            cleaned: false,
                        })
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        failures.push(format!("{}: {error}", base.display()));
                        break;
                    }
                }
            }
        }
        bail!(
            "could not allocate a secure observation directory: {}",
            failures.join("; ")
        )
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    fn cleanup(mut self) -> Result<()> {
        fs::remove_dir_all(&self.path)
            .with_context(|| format!("cleaning observation directory {}", self.path.display()))?;
        self.cleaned = true;
        Ok(())
    }
}

fn secure_observation_base(path: &Path) -> io::Result<bool> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Ok(false);
    }
    let mode = metadata.mode();
    let sticky = mode & libc::S_ISVTX != 0;
    let writable_by_others = mode & 0o022 != 0;
    let owner = metadata.uid();
    let euid = unsafe { libc::geteuid() };
    Ok((owner == euid && (!writable_by_others || sticky)) || (owner == 0 && sticky))
}

impl Drop for ObservationDir {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn observe(duration: Duration, selector: &RootSelector) -> Result<Vec<u8>> {
    let temp = ObservationDir::create()?;
    let result = observe_in(&temp, duration, selector);
    let cleanup = temp.cleanup();
    combine_cleanup(result, cleanup, "observation file cleanup")
}

fn observe_in(
    temp: &ObservationDir,
    duration: Duration,
    selector: &RootSelector,
) -> Result<Vec<u8>> {
    let capture_path = temp.file("capture.ndjson");
    let health_path = temp.file("health.ndjson");
    let socket_path = temp.file("control.sock");
    create_private_file(&capture_path)?;
    create_private_file(&health_path)?;

    // `/proc/self/exe` retains the running inode even if a shell-writable
    // deployment pathname is replaced between parent startup and child exec.
    let mut command = ProcessCommand::new("/proc/self/exe");
    command.arg("trace");
    match selector {
        RootSelector::Package(package) => {
            command.args(["--package", package]);
        }
        RootSelector::Uid(uid) => {
            command.args(["--root-uid", &uid.to_string()]);
        }
    }
    command
        .args(["--follow-services", "--follow-hal", "--json", "--raw"])
        .arg("--output")
        .arg(&capture_path)
        .arg("--health-output")
        .arg(&health_path)
        .arg("--control-socket")
        .arg(&socket_path)
        .args([
            "--fdgraph-interval",
            "off",
            "--lookback-events",
            "0",
            "--no-logcat",
        ])
        .stdout(Stdio::null());
    // SAFETY: the closure only calls async-signal-safe libc functions. The
    // death signal prevents an orphan root tracer if the surface parent is
    // interrupted or killed before normal child cleanup runs.
    unsafe {
        command.pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() == 1 {
                libc::_exit(128 + libc::SIGTERM);
            }
            Ok(())
        });
    }
    let mut child = command.spawn().context("starting child neutron trace")?;
    let result = (|| -> Result<Vec<u8>> {
        wait_for_socket(&mut child, &socket_path, Duration::from_secs(10))?;
        send_observation_mark(&socket_path, "start")?;
        wait_observation(&mut child, duration)?;
        send_observation_mark(&socket_path, "end")?;
        // SAFETY: child.id() is a live process ID owned by this parent.
        if unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) } != 0 {
            return Err(io::Error::last_os_error()).context("sending SIGINT to child trace");
        }
        let status = wait_for_child(&mut child, Duration::from_secs(10))?;
        if !status.success() {
            bail!("child neutron trace exited with {status}");
        }
        let health = fs::read_to_string(&health_path)
            .context("reading final child capture_health sidecar")?;
        if !ends_with_capture_health(health.as_bytes()) {
            bail!("child trace did not produce a final capture_health record");
        }
        let bytes = fs::read(&capture_path).context("reading child causal capture")?;
        let normalized = crate::capture_normalize::normalize_capture(Cursor::new(&bytes))?;
        let starts: Vec<_> = normalized
            .markers
            .iter()
            .filter(|marker| {
                marker.name == "surface-observe" && marker.phase.as_deref() == Some("start")
            })
            .collect();
        let ends: Vec<_> = normalized
            .markers
            .iter()
            .filter(|marker| {
                marker.name == "surface-observe" && marker.phase.as_deref() == Some("end")
            })
            .collect();
        if starts.len() != 1
            || ends.len() != 1
            || starts[0].trace_id.is_none()
            || starts[0].trace_id != ends[0].trace_id
        {
            bail!("child capture is missing one matched surface-observe start/end pair");
        }
        if normalized.health.is_none() || !ends_with_capture_health(&bytes) {
            bail!("child primary capture is missing its final capture_health record");
        }
        Ok(bytes)
    })();
    let child_cleanup = stop_child(&mut child);
    combine_cleanup(result, child_cleanup, "child trace cleanup")
}

fn ends_with_capture_health(input: &[u8]) -> bool {
    input
        .split(|byte| *byte == b'\n')
        .rev()
        .find(|line| !line.iter().all(u8::is_ascii_whitespace))
        .and_then(|line| serde_json::from_slice::<Value>(line).ok())
        .and_then(|value| value.get("type").and_then(Value::as_str).map(str::to_owned))
        .as_deref()
        == Some("capture_health")
}

fn combine_cleanup<T>(primary: Result<T>, cleanup: Result<()>, label: &str) -> Result<T> {
    match (primary, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => {
            Err(error.context(format!("{label} also failed: {cleanup:#}")))
        }
    }
}

fn stop_child(child: &mut Child) -> Result<()> {
    if child
        .try_wait()
        .context("checking child trace cleanup")?
        .is_some()
    {
        return Ok(());
    }
    // SAFETY: child.id() is a live process ID owned by this parent.
    if unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error).context("stopping child trace after observation failure");
        }
    }
    wait_for_child(child, Duration::from_secs(10)).map(|_| ())
}

fn create_private_file(path: &Path) -> Result<()> {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating private file {}", path.display()))?;
    Ok(())
}

fn wait_for_socket(child: &mut Child, path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        if let Some(status) = child.try_wait().context("polling child trace readiness")? {
            bail!("child neutron trace exited before control socket was ready: {status}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    bail!("timed out waiting for child trace control socket")
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> Result<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().context("waiting for child trace")? {
            return Ok(status);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    bail!("timed out waiting for child trace shutdown")
}

fn wait_observation(child: &mut Child, duration: Duration) -> Result<()> {
    let deadline = Instant::now()
        .checked_add(duration)
        .context("observation duration is too large")?;
    loop {
        if let Some(status) = child
            .try_wait()
            .context("polling child trace during observation")?
        {
            bail!("child neutron trace exited during observation: {status}");
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(());
        }
        std::thread::sleep((deadline - now).min(Duration::from_millis(20)));
    }
}

fn send_observation_mark(path: &Path, phase: &str) -> Result<()> {
    crate::causal::send_mark_request(
        path,
        &crate::causal::MarkRequest {
            name: "surface-observe".into(),
            phase: phase.into(),
            meta: BTreeMap::new(),
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_duration_is_validated_and_unit_aware() {
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("30").is_err());
    }

    #[test]
    fn observation_directory_cleanup_removes_private_artifacts() {
        let temp = ObservationDir::create().unwrap();
        let path = temp.path.clone();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        create_private_file(&temp.file("capture.ndjson")).unwrap();
        temp.cleanup().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn observation_base_requires_trusted_owner_or_sticky_protection() {
        let temp = ObservationDir::create().unwrap();
        let base = temp.file("candidate-base");
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(!secure_observation_base(&base).unwrap());
        fs::set_permissions(&base, fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(secure_observation_base(&base).unwrap());
        temp.cleanup().unwrap();
    }

    #[test]
    fn child_cleanup_stops_a_live_process() {
        let mut child = ProcessCommand::new("/bin/sleep").arg("60").spawn().unwrap();
        stop_child(&mut child).unwrap();
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn observation_wait_reports_early_child_exit() {
        let mut child = ProcessCommand::new("/bin/sh")
            .args(["-c", "exit 7"])
            .spawn()
            .unwrap();
        let error = wait_observation(&mut child, Duration::from_secs(1)).unwrap_err();
        assert!(format!("{error:#}").contains("exited during observation"));
    }

    #[test]
    fn observation_wait_finishes_while_child_remains_live() {
        let mut child = ProcessCommand::new("/bin/sleep").arg("60").spawn().unwrap();
        wait_observation(&mut child, Duration::from_millis(1)).unwrap();
        stop_child(&mut child).unwrap();
    }

    #[test]
    fn capture_health_must_be_the_final_nonempty_record() {
        assert!(ends_with_capture_health(
            b"{\"type\":\"marker\"}\n{\"type\":\"capture_health\"}\n\n"
        ));
        assert!(!ends_with_capture_health(
            b"{\"type\":\"capture_health\"}\n{\"type\":\"marker\"}\n"
        ));
    }

    #[test]
    fn observation_trace_collects_logcat_sources() {
        assert!(!observation_trace_args().contains(&"--no-logcat"));
    }
}
