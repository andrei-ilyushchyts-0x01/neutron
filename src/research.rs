//! Validated, data-only on-device research packs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Cursor, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::surface::{self, SurfaceSnapshot};

const PACK_SCHEMA: &str = "neutron.research-pack/v1";
const SERVICES_SCHEMA: &str = "neutron.research-services/v1";
const DEVICES_SCHEMA: &str = "neutron.research-devices/v1";
const SCENARIOS_SCHEMA: &str = "neutron.research-scenarios/v1";
const RUN_SCHEMA: &str = "neutron.research-run/v1";
const MAX_COMPONENTS: usize = 8;
const MAX_COMPONENT_BYTES: u64 = 1024 * 1024;
const MAX_PACK_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PARAMS: usize = 32;
const MAX_SETTLE_MS: u64 = 30_000;
const PROBE_PACKAGE: &str = "dev.neutron.probe";
const STIMULUS_ACTIONS: &[&str] = &[
    "keymint",
    "gpu",
    "camera",
    "media-codec",
    "bluetooth",
    "wifi",
    "usb",
];
const DRIVER_PACKS: &[&str] = &["binder", "kgsl", "mali", "alsa", "unix-socket", "media-hal"];
static RESEARCH_RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn research_signal_handler(_signal: libc::c_int) {
    RESEARCH_RUNNING.store(false, Ordering::SeqCst);
}

#[derive(Args, Debug, Clone)]
pub struct ResearchArgs {
    /// Built-in pack name or trusted local pack directory.
    #[arg(long, value_name = "NAME|PATH")]
    pub pack: String,
    /// Scenario ID; defaults to the pack's default scenario.
    #[arg(long)]
    pub scenario: Option<String>,
    /// Typed scenario parameter (`KEY=VALUE`).
    #[arg(long = "param", value_name = "KEY=VALUE")]
    pub params: Vec<String>,
    /// Override scenario duration (1s..10m).
    #[arg(long)]
    pub duration: Option<String>,
    /// New private artifact directory.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Pre-installed companion application package.
    #[arg(long, default_value = PROBE_PACKAGE)]
    pub probe_package: String,
    /// Confirm this is an authorized assessment and permit stimulus/temporary grants.
    #[arg(long)]
    pub authorized_use: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackManifest {
    pub schema: String,
    pub id: String,
    pub version: String,
    pub compatibility: Compatibility,
    pub default_scenario: String,
    pub components: Components,
    pub content_hash: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Compatibility {
    #[serde(default)]
    pub android_api_min: Option<u32>,
    #[serde(default)]
    pub android_api_max: Option<u32>,
    #[serde(default)]
    pub vendors: Vec<String>,
    #[serde(default)]
    pub kernel_prefixes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Components {
    pub services: String,
    pub devices: String,
    pub scenarios: String,
    pub rules: String,
    pub report: String,
    #[serde(default)]
    pub ioctls: Option<String>,
    #[serde(default)]
    pub aidl: Option<String>,
}

impl Components {
    fn paths(&self) -> Vec<&str> {
        let mut paths = vec![
            self.services.as_str(),
            self.devices.as_str(),
            self.scenarios.as_str(),
            self.rules.as_str(),
            self.report.as_str(),
        ];
        paths.extend(self.ioctls.iter().map(String::as_str));
        paths.extend(self.aidl.iter().map(String::as_str));
        paths
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServicesCatalog {
    pub schema: String,
    pub services: Vec<ServiceRequirement>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRequirement {
    pub id: String,
    pub required: bool,
    #[serde(default = "one")]
    pub min_count: usize,
    pub alternatives: Vec<ServiceSelector>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSelector {
    #[serde(default)]
    pub names: Vec<String>,
    #[serde(default)]
    pub descriptors: Vec<String>,
    #[serde(default)]
    pub process_patterns: Vec<String>,
    #[serde(default)]
    pub domain_patterns: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevicesCatalog {
    pub schema: String,
    pub devices: Vec<DeviceRequirement>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRequirement {
    pub id: String,
    pub required: bool,
    pub alternatives: Vec<DeviceSelector>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSelector {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub drivers: Vec<String>,
    #[serde(default)]
    pub modules: Vec<String>,
    #[serde(default)]
    pub sysfs_prefixes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScenariosCatalog {
    pub schema: String,
    pub scenarios: Vec<Scenario>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub id: String,
    pub root_package: String,
    #[serde(default)]
    pub follow_services: bool,
    #[serde(default)]
    pub follow_hal: bool,
    pub trace: TraceFilters,
    pub stimulus: Stimulus,
    pub duration: String,
    #[serde(default)]
    pub settle_ms: u64,
    #[serde(default)]
    pub required_params: Vec<String>,
    #[serde(default)]
    pub calibration: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceFilters {
    #[serde(default)]
    pub driver_packs: Vec<String>,
    #[serde(default)]
    pub syscalls: Vec<i32>,
    #[serde(default)]
    pub fd_paths: Vec<String>,
    #[serde(default)]
    pub ioctl_types: Vec<u32>,
    #[serde(default)]
    pub resolve_paths: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Stimulus {
    pub action: String,
    #[serde(default = "default_timeout")]
    pub timeout: String,
}

#[derive(Clone, Debug)]
pub struct LoadedPack {
    pub root: PathBuf,
    pub manifest: PackManifest,
    pub services: ServicesCatalog,
    pub devices: DevicesCatalog,
    pub scenarios: ScenariosCatalog,
    files: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, Debug, Serialize)]
struct Check {
    id: String,
    required: bool,
    status: String,
    matches: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct Preflight {
    compatibility: Vec<String>,
    services: Vec<Check>,
    devices: Vec<Check>,
    parameters: Vec<Check>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Validated,
    Preflight,
    AwaitingAuthorization,
    Capturing,
    Stimulated,
    Postflight,
    Unsupported,
    Failed,
    Reported,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::Validated => "validated",
            Self::Preflight => "preflight",
            Self::AwaitingAuthorization => "awaiting_authorization",
            Self::Capturing => "capturing",
            Self::Stimulated => "stimulated",
            Self::Postflight => "postflight",
            Self::Unsupported => "unsupported",
            Self::Failed => "failed",
            Self::Reported => "reported",
        }
    }
}

struct RunState {
    phase: Phase,
    history: Vec<&'static str>,
}

impl RunState {
    fn new() -> Self {
        Self {
            phase: Phase::Validated,
            history: vec![Phase::Validated.name()],
        }
    }

    fn transition(&mut self, next: Phase) -> Result<()> {
        let allowed = matches!(
            (self.phase, next),
            (Phase::Validated, Phase::Preflight)
                | (Phase::Preflight, Phase::AwaitingAuthorization)
                | (Phase::Preflight, Phase::Capturing)
                | (Phase::Preflight, Phase::Unsupported)
                | (Phase::Capturing, Phase::Stimulated)
                | (Phase::Capturing, Phase::Unsupported)
                | (Phase::Capturing, Phase::Failed)
                | (Phase::Stimulated, Phase::Postflight)
                | (Phase::AwaitingAuthorization, Phase::Reported)
                | (Phase::Unsupported, Phase::Reported)
                | (Phase::Failed, Phase::Reported)
                | (Phase::Postflight, Phase::Reported)
        );
        if !allowed {
            bail!("invalid research transition {:?} -> {next:?}", self.phase);
        }
        self.phase = next;
        self.history.push(next.name());
        Ok(())
    }
}

impl Preflight {
    fn supported(&self) -> bool {
        self.compatibility.is_empty()
            && self
                .services
                .iter()
                .chain(&self.devices)
                .chain(&self.parameters)
                .all(|check| !check.required || check.status == "present")
    }
}

fn one() -> usize {
    1
}

fn default_timeout() -> String {
    "10s".into()
}

pub fn parse_duration(raw: &str) -> Result<Duration> {
    let raw = raw.trim();
    let (number, multiplier) = if let Some(value) = raw.strip_suffix("ms") {
        (value, 1_u64)
    } else if let Some(value) = raw.strip_suffix('s') {
        (value, 1_000)
    } else if let Some(value) = raw.strip_suffix('m') {
        (value, 60_000)
    } else {
        bail!("duration must use ms, s, or m");
    };
    let millis = number
        .parse::<u64>()
        .context("invalid duration")?
        .checked_mul(multiplier)
        .context("duration overflow")?;
    if !(1_000..=600_000).contains(&millis) {
        bail!("duration must be between 1s and 10m");
    }
    Ok(Duration::from_millis(millis))
}

fn parse_timeout(raw: &str) -> Result<Duration> {
    let duration = parse_duration(raw)?;
    if duration > Duration::from_secs(30) {
        bail!("stimulus timeout exceeds 30s");
    }
    Ok(duration)
}

pub fn load_pack(root: &Path, enforce_local_trust: bool) -> Result<LoadedPack> {
    if enforce_local_trust {
        trusted_directory(root)?;
    }
    let manifest_bytes = read_component(root, "pack.yaml", enforce_local_trust)?;
    let manifest: PackManifest =
        serde_yaml::from_slice(&manifest_bytes).context("parsing strict pack.yaml")?;
    validate_manifest(&manifest)?;

    let mut files = BTreeMap::new();
    files.insert("pack.yaml".into(), manifest_bytes);
    let mut total = files["pack.yaml"].len() as u64;
    for path in manifest.components.paths() {
        validate_component_path(path)?;
        if files.contains_key(path) {
            bail!("duplicate component path '{path}'");
        }
        let bytes = read_component(root, path, enforce_local_trust)?;
        total = total
            .checked_add(bytes.len() as u64)
            .context("pack byte count overflow")?;
        if total > MAX_PACK_BYTES {
            bail!("research pack exceeds {MAX_PACK_BYTES} bytes");
        }
        files.insert(path.into(), bytes);
    }
    let expected_hash = hash_loaded(&manifest, &files)?;
    if manifest.content_hash != expected_hash {
        bail!("research pack content hash mismatch (expected {expected_hash})");
    }

    let services: ServicesCatalog = parse_json_component(&files, &manifest.components.services)?;
    let devices: DevicesCatalog = parse_json_component(&files, &manifest.components.devices)?;
    let scenarios: ScenariosCatalog = parse_yaml_component(&files, &manifest.components.scenarios)?;
    validate_components(&manifest, &services, &devices, &scenarios, &files)?;
    Ok(LoadedPack {
        root: root.to_path_buf(),
        manifest,
        services,
        devices,
        scenarios,
        files,
    })
}

pub fn compute_pack_hash(root: &Path) -> Result<String> {
    let manifest_bytes = read_component(root, "pack.yaml", false)?;
    let manifest: PackManifest = serde_yaml::from_slice(&manifest_bytes)?;
    validate_manifest(&manifest)?;
    let mut files = BTreeMap::from([("pack.yaml".into(), manifest_bytes)]);
    for path in manifest.components.paths() {
        validate_component_path(path)?;
        files.insert(path.into(), read_component(root, path, false)?);
    }
    hash_loaded(&manifest, &files)
}

fn validate_manifest(manifest: &PackManifest) -> Result<()> {
    if manifest.schema != PACK_SCHEMA {
        bail!("unsupported research pack schema '{}'", manifest.schema);
    }
    if !valid_id(&manifest.id) || manifest.version.trim().is_empty() {
        bail!("pack id/version is invalid");
    }
    let paths = manifest.components.paths();
    if paths.len() > MAX_COMPONENTS {
        bail!("research pack exceeds {MAX_COMPONENTS} components");
    }
    for path in paths {
        validate_component_path(path)?;
    }
    if !manifest.content_hash.starts_with("sha256:")
        || manifest.content_hash.len() != "sha256:".len() + 64
        || !manifest.content_hash["sha256:".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("pack content_hash must be sha256:<64 lowercase hex digits>");
    }
    Ok(())
}

fn validate_component_path(raw: &str) -> Result<()> {
    let path = Path::new(raw);
    if raw.is_empty()
        || path.is_absolute()
        || path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        bail!("component path must be one contained file name: '{raw}'");
    }
    Ok(())
}

fn read_component(root: &Path, name: &str, trusted: bool) -> Result<Vec<u8>> {
    validate_component_path(name)?;
    let path = root.join(name);
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("reading component metadata {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!(
            "component must be a regular non-symlink file: {}",
            path.display()
        );
    }
    if metadata.len() > MAX_COMPONENT_BYTES {
        bail!("component exceeds {MAX_COMPONENT_BYTES} bytes: {name}");
    }
    if trusted {
        trusted_metadata(&metadata, "component")?;
    }
    fs::read(&path).with_context(|| format!("reading component {}", path.display()))
}

fn trusted_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading pack directory {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("local pack must be a regular non-symlink directory");
    }
    trusted_metadata(&metadata, "pack directory")
}

fn trusted_metadata(metadata: &fs::Metadata, label: &str) -> Result<()> {
    let euid = unsafe { libc::geteuid() };
    if ![0, euid].contains(&metadata.uid()) || metadata.mode() & 0o022 != 0 {
        bail!("{label} must be owner-trusted and not group/world-writable");
    }
    Ok(())
}

fn hash_loaded(manifest: &PackManifest, files: &BTreeMap<String, Vec<u8>>) -> Result<String> {
    let mut unsigned = manifest.clone();
    unsigned.content_hash.clear();
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, "pack.yaml", &serde_json::to_vec(&unsigned)?);
    for path in manifest.components.paths() {
        hash_part(
            &mut hasher,
            path,
            files
                .get(path)
                .with_context(|| format!("missing loaded component {path}"))?,
        );
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn hash_part(hasher: &mut Sha256, name: &str, bytes: &[u8]) {
    hasher.update((name.len() as u64).to_le_bytes());
    hasher.update(name.as_bytes());
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn parse_json_component<T: for<'de> Deserialize<'de>>(
    files: &BTreeMap<String, Vec<u8>>,
    path: &str,
) -> Result<T> {
    serde_json::from_slice(&files[path]).with_context(|| format!("parsing strict {path}"))
}

fn parse_yaml_component<T: for<'de> Deserialize<'de>>(
    files: &BTreeMap<String, Vec<u8>>,
    path: &str,
) -> Result<T> {
    serde_yaml::from_slice(&files[path]).with_context(|| format!("parsing strict {path}"))
}

fn validate_components(
    manifest: &PackManifest,
    services: &ServicesCatalog,
    devices: &DevicesCatalog,
    scenarios: &ScenariosCatalog,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    if services.schema != SERVICES_SCHEMA
        || devices.schema != DEVICES_SCHEMA
        || scenarios.schema != SCENARIOS_SCHEMA
    {
        bail!("unsupported research component schema");
    }
    unique_ids(
        services.services.iter().map(|item| item.id.as_str()),
        "service",
    )?;
    unique_ids(
        devices.devices.iter().map(|item| item.id.as_str()),
        "device",
    )?;
    unique_ids(
        scenarios.scenarios.iter().map(|item| item.id.as_str()),
        "scenario",
    )?;
    for item in &services.services {
        if item.alternatives.is_empty() || item.min_count == 0 {
            bail!(
                "service requirement '{}' has no usable alternatives",
                item.id
            );
        }
    }
    for item in &devices.devices {
        if item.alternatives.is_empty() {
            bail!("device requirement '{}' has no alternatives", item.id);
        }
    }
    if !scenarios
        .scenarios
        .iter()
        .any(|scenario| scenario.id == manifest.default_scenario)
    {
        bail!("default scenario is not defined");
    }
    for scenario in &scenarios.scenarios {
        if !valid_id(&scenario.id)
            || !valid_package_or_probe(&scenario.root_package)
            || !STIMULUS_ACTIONS.contains(&scenario.stimulus.action.as_str())
        {
            bail!(
                "scenario '{}' contains a non-allowlisted field",
                scenario.id
            );
        }
        parse_duration(&scenario.duration)?;
        parse_timeout(&scenario.stimulus.timeout)?;
        if scenario.settle_ms > MAX_SETTLE_MS {
            bail!(
                "scenario '{}' settle_ms exceeds {MAX_SETTLE_MS}",
                scenario.id
            );
        }
        unique_ids(
            scenario.required_params.iter().map(String::as_str),
            "parameter",
        )?;
        if scenario.trace.syscalls.len() > 128
            || scenario.trace.fd_paths.len() > 64
            || scenario.trace.driver_packs.len() > 16
        {
            bail!("scenario '{}' exceeds trace filter limits", scenario.id);
        }
        if scenario
            .trace
            .driver_packs
            .iter()
            .any(|pack| !DRIVER_PACKS.contains(&pack.as_str()))
            || scenario
                .trace
                .syscalls
                .iter()
                .any(|syscall| !(0..=1024).contains(syscall))
            || scenario.trace.ioctl_types.iter().any(|value| *value > 0xff)
        {
            bail!(
                "scenario '{}' contains a non-allowlisted trace filter",
                scenario.id
            );
        }
    }
    neutron_rules::load_rules_yaml_str(
        std::str::from_utf8(&files[&manifest.components.rules])
            .context("rules.yaml is not UTF-8")?,
    )
    .context("validating research rules")?;
    if let Some(path) = manifest.components.aidl.as_deref() {
        crate::aidl::AidlCatalog::from_json(
            std::str::from_utf8(&files[path]).context("aidl.json is not UTF-8")?,
        )?;
    }
    if let Some(path) = manifest.components.ioctls.as_deref() {
        let pack: crate::ioctl_schema::SchemaPack = serde_json::from_slice(&files[path])?;
        pack.verify(&crate::ioctl_schema::RuntimeIdentity::current())?;
    }
    Ok(())
}

fn unique_ids<'a>(ids: impl Iterator<Item = &'a str>, label: &str) -> Result<()> {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !valid_id(id) || !seen.insert(id) {
            bail!("invalid or duplicate {label} id '{id}'");
        }
    }
    Ok(())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_package_or_probe(value: &str) -> bool {
    value == "probe"
        || (value.len() <= 255 && value.contains('.') && value.split('.').all(valid_id))
}

fn valid_param_value(value: &str) -> bool {
    value.len() <= 256
        && !value.is_empty()
        && value
            .chars()
            .all(|character| !character.is_control() && character != '\0')
}

fn parse_params(raw: &[String]) -> Result<BTreeMap<String, String>> {
    if raw.len() > MAX_PARAMS {
        bail!("too many scenario parameters");
    }
    let mut params = BTreeMap::new();
    for item in raw {
        let (key, value) = item
            .split_once('=')
            .with_context(|| format!("parameter must be KEY=VALUE: '{item}'"))?;
        if !valid_id(key)
            || !valid_param_value(value)
            || params.insert(key.into(), value.into()).is_some()
        {
            bail!("invalid or duplicate scenario parameter '{key}'");
        }
    }
    Ok(params)
}

fn resolve_pack(value: &str) -> Result<(PathBuf, bool)> {
    let explicit = PathBuf::from(value);
    if explicit.exists() {
        return Ok((explicit, true));
    }
    if !valid_id(value) {
        bail!("research pack name is invalid");
    }
    let mut roots = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        roots.extend(pack_roots_for_executable(&exe));
    }
    roots.extend([
        (PathBuf::from("/system/etc/neutron/packs"), true),
        (PathBuf::from("/vendor/etc/neutron/packs"), true),
        (
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("packs"),
            false,
        ),
    ]);
    for (root, trusted) in roots {
        let candidate = root.join(value);
        if candidate.exists() {
            return Ok((candidate, trusted));
        }
    }
    bail!("research pack '{value}' was not found");
}

fn pack_roots_for_executable(executable: &Path) -> Vec<(PathBuf, bool)> {
    let mut roots = Vec::new();
    if let Some(parent) = executable.parent() {
        // Self-contained Android archive layout:
        // /data/local/share/neutron/{neutron-agent,packs/}
        roots.push((parent.join("packs"), true));
        // Conventional host FHS layout: /usr/bin/neutron plus
        // /usr/share/neutron/packs/.
        if let Some(prefix) = parent.parent() {
            roots.push((prefix.join("share/neutron/packs"), true));
        }
    }
    roots
}

pub fn run(args: ResearchArgs) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("research failed: {error:#}");
            1
        }
    }
}

fn run_inner(args: ResearchArgs) -> Result<i32> {
    RESEARCH_RUNNING.store(true, Ordering::SeqCst);
    unsafe {
        let handler = research_signal_handler as *const () as libc::sighandler_t;
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
    let (pack_path, trust) = resolve_pack(&args.pack)?;
    let pack = load_pack(&pack_path, trust)?;
    let mut machine = RunState::new();
    let scenario_id = args
        .scenario
        .as_deref()
        .unwrap_or(&pack.manifest.default_scenario);
    let scenario = pack
        .scenarios
        .scenarios
        .iter()
        .find(|scenario| scenario.id == scenario_id)
        .with_context(|| format!("unknown scenario '{scenario_id}'"))?;
    let params = parse_params(&args.params)?;
    for key in params.keys() {
        if !scenario.required_params.contains(key) && !scenario.calibration.contains_key(key) {
            bail!("parameter '{key}' is not declared by scenario '{scenario_id}'");
        }
    }
    let duration = match args.duration.as_deref() {
        Some(raw) => parse_duration(raw)?,
        None => parse_duration(&scenario.duration)?,
    };
    let snapshot = surface::collect_snapshot().context("collecting research preflight surface")?;
    machine.transition(Phase::Preflight)?;
    let preflight = preflight(&pack, scenario, &params, &snapshot);
    let output = create_run_dir(args.output.as_deref(), &pack.manifest.id)?;
    copy_verified_pack(&pack, &output)?;
    write_private_json(&output.join("preflight.surface.json"), &snapshot, true)?;
    create_private(&output.join("capture.ndjson"))?;
    create_private(&output.join("capture.health.ndjson"))?;
    write_private_json(&output.join("surface.json"), &snapshot, true)?;

    let mut status = if args.authorized_use {
        "unsupported"
    } else {
        "authorization_required"
    };
    let mut code = if args.authorized_use { 3 } else { 2 };
    let mut notes = Vec::new();
    let mut execution_attempted = false;
    if !args.authorized_use {
        machine.transition(Phase::AwaitingAuthorization)?;
    } else if !preflight.supported() {
        machine.transition(Phase::Unsupported)?;
    } else {
        if unsafe { libc::geteuid() } != 0 {
            notes.push("research stimulus requires root".to_string());
            machine.transition(Phase::Unsupported)?;
        } else {
            machine.transition(Phase::Capturing)?;
            execution_attempted = true;
            let outcome = execute(
                &args, &pack, scenario, &params, duration, &output, &snapshot,
            );
            match outcome {
                Ok(outcome) if outcome.unsupported.is_some() => {
                    status = "unsupported";
                    code = 3;
                    notes.push(outcome.unsupported.expect("matched Some"));
                    machine.transition(Phase::Unsupported)?;
                }
                Ok(outcome) => {
                    status = if outcome.degraded {
                        "degraded"
                    } else {
                        "complete"
                    };
                    code = if outcome.degraded { 4 } else { 0 };
                    if !outcome.granted_permissions.is_empty() {
                        notes.push(format!(
                            "temporarily granted and restored: {}",
                            outcome.granted_permissions.join(", ")
                        ));
                    }
                    machine.transition(Phase::Stimulated)?;
                    machine.transition(Phase::Postflight)?;
                }
                Err(error) => {
                    status = "failed";
                    code = 1;
                    notes.push(format!("{error:#}"));
                    machine.transition(Phase::Failed)?;
                }
            }
        }
    }
    let stimulus = json!({
        "action": scenario.stimulus.action,
        "status": match (execution_attempted, code) {
            (_, 0 | 4) => "completed",
            (true, 3) => "unsupported",
            (true, _) => "failed",
            (false, _) => "not_executed",
        },
        "parameter_names": params.keys().collect::<Vec<_>>(),
        "permissions": permissions_for(&scenario.stimulus.action),
    });
    write_private_json(&output.join("stimulus.json"), &stimulus, true)?;
    write_report(&output, &pack, scenario, &preflight, status, &notes)?;
    machine.transition(Phase::Reported)?;
    write_private_json(
        &output.join("run.json"),
        &json!({
            "schema": RUN_SCHEMA,
            "status": status,
            "exit_code": code,
            "pack": pack.manifest.id,
            "pack_version": pack.manifest.version,
            "pack_hash": pack.manifest.content_hash,
            "scenario": scenario.id,
            "duration_ms": duration.as_millis(),
            "authorized_use": args.authorized_use,
            "artifact_mode": "private",
            "notes": notes,
            "phases": machine.history,
        }),
        true,
    )?;
    eprintln!("research report: {}", output.join("report.md").display());
    Ok(code)
}

fn preflight(
    pack: &LoadedPack,
    scenario: &Scenario,
    params: &BTreeMap<String, String>,
    snapshot: &SurfaceSnapshot,
) -> Preflight {
    let mut compatibility = Vec::new();
    let api = getprop("ro.build.version.sdk").and_then(|value| value.parse::<u32>().ok());
    if pack
        .manifest
        .compatibility
        .android_api_min
        .is_some_and(|minimum| api.map_or(true, |actual| actual < minimum))
    {
        compatibility.push("Android API is absent or below the pack minimum".into());
    }
    if pack
        .manifest
        .compatibility
        .android_api_max
        .is_some_and(|maximum| api.is_some_and(|actual| actual > maximum))
    {
        compatibility.push("Android API is above the pack maximum".into());
    }
    if !pack.manifest.compatibility.kernel_prefixes.is_empty() {
        let kernel = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        if !pack
            .manifest
            .compatibility
            .kernel_prefixes
            .iter()
            .any(|prefix| kernel.starts_with(prefix))
        {
            compatibility.push("kernel release does not match pack selectors".into());
        }
    }
    if !pack.manifest.compatibility.vendors.is_empty() {
        let vendor = getprop("ro.product.manufacturer").unwrap_or_default();
        if !pack
            .manifest
            .compatibility
            .vendors
            .iter()
            .any(|pattern| glob(pattern, &vendor))
        {
            compatibility.push("device vendor does not match pack selectors".into());
        }
    }
    let services = pack
        .services
        .services
        .iter()
        .map(|requirement| {
            let matches: Vec<_> = snapshot
                .services
                .iter()
                .filter(|service| {
                    requirement
                        .alternatives
                        .iter()
                        .any(|selector| matches_service(selector, service, snapshot))
                })
                .map(|service| service.id.clone())
                .collect();
            Check {
                id: requirement.id.clone(),
                required: requirement.required,
                status: if matches.len() >= requirement.min_count {
                    "present"
                } else {
                    "missing"
                }
                .into(),
                matches,
            }
        })
        .collect();
    let devices = pack
        .devices
        .devices
        .iter()
        .map(|requirement| {
            let matches: Vec<_> = snapshot
                .devices
                .iter()
                .filter(|device| {
                    requirement
                        .alternatives
                        .iter()
                        .any(|selector| matches_device(selector, device))
                })
                .map(|device| device.id.clone())
                .collect();
            Check {
                id: requirement.id.clone(),
                required: requirement.required,
                status: if matches.is_empty() {
                    "missing"
                } else {
                    "present"
                }
                .into(),
                matches,
            }
        })
        .collect();
    let parameters = scenario
        .required_params
        .iter()
        .map(|id| Check {
            id: id.clone(),
            required: true,
            status: if params.contains_key(id) {
                "present"
            } else {
                "missing"
            }
            .into(),
            matches: Vec::new(),
        })
        .collect();
    Preflight {
        compatibility,
        services,
        devices,
        parameters,
    }
}

fn matches_service(
    selector: &ServiceSelector,
    service: &surface::Service,
    snapshot: &SurfaceSnapshot,
) -> bool {
    let process = service
        .process_id
        .as_ref()
        .and_then(|id| snapshot.processes.iter().find(|process| &process.id == id));
    let identity_matches = (selector.names.is_empty() && selector.descriptors.is_empty())
        || selector.names.iter().any(|p| glob(p, &service.name))
        || service
            .descriptor
            .as_deref()
            .is_some_and(|value| selector.descriptors.iter().any(|p| glob(p, value)));
    identity_matches
        && (selector.process_patterns.is_empty()
            || process.is_some_and(|process| {
                let cmdline = process.cmdline.join(" ");
                selector.process_patterns.iter().any(|p| glob(p, &cmdline))
            }))
        && (selector.domain_patterns.is_empty()
            || service
                .selinux_domain
                .as_deref()
                .is_some_and(|value| selector.domain_patterns.iter().any(|p| glob(p, value))))
}

fn matches_device(selector: &DeviceSelector, device: &surface::Device) -> bool {
    (selector.paths.is_empty() || selector.paths.iter().any(|p| glob(p, &device.path)))
        && (selector.drivers.is_empty()
            || device
                .driver
                .as_deref()
                .is_some_and(|value| selector.drivers.iter().any(|p| glob(p, value))))
        && (selector.modules.is_empty()
            || device
                .module
                .as_deref()
                .is_some_and(|value| selector.modules.iter().any(|p| glob(p, value))))
        && (selector.sysfs_prefixes.is_empty()
            || device
                .sysfs_path
                .as_deref()
                .is_some_and(|value| selector.sysfs_prefixes.iter().any(|p| value.starts_with(p))))
}

fn glob(pattern: &str, value: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == value;
    }
    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');
    let mut remainder = value;
    for (index, part) in pattern
        .split('*')
        .filter(|part| !part.is_empty())
        .enumerate()
    {
        let Some(position) = remainder.find(part) else {
            return false;
        };
        if index == 0 && anchored_start && position != 0 {
            return false;
        }
        remainder = &remainder[position + part.len()..];
    }
    !anchored_end || remainder.is_empty()
}

fn getprop(name: &str) -> Option<String> {
    let output = std::process::Command::new("/system/bin/getprop")
        .arg(name)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn create_run_dir(explicit: Option<&Path>, pack: &str) -> Result<PathBuf> {
    let path = explicit.map(Path::to_path_buf).unwrap_or_else(|| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        PathBuf::from("/data/local/tmp/neutron/research")
            .join(format!("{pack}-{now}-{}", std::process::id()))
    });
    if explicit.is_none() {
        fs::create_dir_all(path.parent().expect("default output has parent"))?;
    }
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .with_context(|| format!("creating new private output {}", path.display()))?;
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        bail!("research output is not a private owned directory");
    }
    Ok(path)
}

fn create_private(path: &Path) -> Result<()> {
    crate::private_output::write(path, &[], false)
}

fn write_private(path: &Path, bytes: &[u8], overwrite: bool) -> Result<()> {
    crate::private_output::write(path, bytes, overwrite)
}

fn write_private_json<T: Serialize>(path: &Path, value: &T, overwrite: bool) -> Result<()> {
    crate::private_output::write_json(path, value, overwrite)
}

fn copy_verified_pack(pack: &LoadedPack, output: &Path) -> Result<()> {
    let destination = output.join("pack");
    fs::DirBuilder::new().mode(0o700).create(&destination)?;
    let mut lock = BTreeMap::new();
    for (name, bytes) in &pack.files {
        write_private(&destination.join(name), bytes, false)?;
        lock.insert(name, format!("sha256:{:x}", Sha256::digest(bytes)));
    }
    write_private_json(
        &output.join("pack.lock.json"),
        &json!({
            "schema": PACK_SCHEMA,
            "pack": pack.manifest.id,
            "content_hash": pack.manifest.content_hash,
            "files": lock,
        }),
        false,
    )
}

fn write_report(
    output: &Path,
    pack: &LoadedPack,
    scenario: &Scenario,
    preflight: &Preflight,
    status: &str,
    notes: &[String],
) -> Result<()> {
    let methodology = std::str::from_utf8(&pack.files[&pack.manifest.components.report])?;
    let mut report = format!(
        "# Neutron research: {}\n\nStatus: `{status}`  \nScenario: `{}`  \nPack hash: `{}`\n\n## Compatibility and preflight\n\n```json\n{}\n```\n\n## Service, PID, and SELinux evidence\n\nSee `preflight.surface.json` and `surface.json`.\n\n## Stimulus and permission lifecycle\n\nSee `stimulus.json`; only permissions from the compiled action registry are eligible for temporary grants.\n\n## Binder and AIDL calls\n\nCausal Binder evidence is retained in `capture.ndjson` and correlated into `surface.json`.\n\n## Devices and ioctls\n\nDevice requirements and decoded ioctl evidence are listed in the preflight and surface artifacts.\n\n## Findings\n\nRules are scenario-scoped; inventory evidence is not promoted to a trace finding.\n\n## Capture health\n\nSee `capture.health.ndjson`.\n\n## Negative-evidence caveats\n\nMissing events are not proof that an interface is unreachable. Capture health, kernel support, sampling, and scenario coverage bound every negative conclusion.\n\n## Pack methodology and limitations\n\n{methodology}\n",
        pack.manifest.id,
        scenario.id,
        pack.manifest.content_hash,
        serde_json::to_string_pretty(preflight)?,
    );
    if !notes.is_empty() {
        report.push_str("\n## Runtime notes\n\n");
        for note in notes {
            report.push_str("- ");
            report.push_str(&note.replace('\n', " "));
            report.push('\n');
        }
    }
    write_private(&output.join("report.md"), report.as_bytes(), false)
}

fn permissions_for(action: &str) -> &'static [&'static str] {
    match action {
        "camera" => &["android.permission.CAMERA"],
        "bluetooth" => &[
            "android.permission.BLUETOOTH_SCAN",
            "android.permission.BLUETOOTH_CONNECT",
        ],
        "wifi" => &[
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.NEARBY_WIFI_DEVICES",
        ],
        _ => &[],
    }
}

fn add_research_follow_guardrails(_args: &mut Vec<String>) {
    // Domain filters are rejected in 1.5 because they cannot be enforced at
    // the first-event BPF admission boundary. The causal follower's built-in
    // coordinator transit limits remain active.
}

// Filled below by the trace/stimulus implementation; it deliberately accepts
// only the typed Scenario model above, never argv from a pack.
#[derive(Default)]
struct ExecutionOutcome {
    degraded: bool,
    unsupported: Option<String>,
    granted_permissions: Vec<String>,
}

fn execute(
    args: &ResearchArgs,
    pack: &LoadedPack,
    scenario: &Scenario,
    params: &BTreeMap<String, String>,
    duration: Duration,
    output: &Path,
    preflight_snapshot: &SurfaceSnapshot,
) -> Result<ExecutionOutcome> {
    if !valid_package_or_probe(&args.probe_package) || args.probe_package == "probe" {
        bail!("--probe-package is not a valid Android package");
    }
    if !command_success("/system/bin/pm", &["path", &args.probe_package])? {
        return Ok(ExecutionOutcome {
            unsupported: Some(format!(
                "companion package '{}' is not installed",
                args.probe_package
            )),
            ..ExecutionOutcome::default()
        });
    }
    if matches!(scenario.stimulus.action.as_str(), "bluetooth" | "wifi") {
        let setting = if scenario.stimulus.action == "bluetooth" {
            "bluetooth_on"
        } else {
            "wifi_on"
        };
        let output = command_output("/system/bin/settings", &["get", "global", setting])?;
        if output.trim() != "1" {
            return Ok(ExecutionOutcome {
                unsupported: Some(format!(
                    "{} radio is disabled; research never enables radios",
                    scenario.stimulus.action
                )),
                ..ExecutionOutcome::default()
            });
        }
    }

    let mut permissions = PermissionGuard::new(&args.probe_package);
    for permission in permissions_for(&scenario.stimulus.action) {
        permissions.ensure(permission)?;
    }

    let capture_path = output.join("capture.ndjson");
    let health_path = output.join("capture.health.ndjson");
    let socket_path = output.join("control.sock");
    let copied_pack = output.join("pack");
    let mut trace_args = Vec::new();
    if scenario.follow_services {
        trace_args.push("--follow-services".into());
    }
    if scenario.follow_hal {
        trace_args.push("--follow-hal".into());
    }
    add_research_follow_guardrails(&mut trace_args);
    for driver_pack in &scenario.trace.driver_packs {
        trace_args.extend(["--driver-pack".into(), driver_pack.clone()]);
    }
    for syscall in &scenario.trace.syscalls {
        trace_args.extend(["--match-syscall".into(), syscall.to_string()]);
    }
    for path in &scenario.trace.fd_paths {
        trace_args.extend(["--match-fd".into(), path.clone()]);
    }
    for ioctl_type in &scenario.trace.ioctl_types {
        trace_args.extend(["--match-ioctl-type".into(), format!("{ioctl_type:#x}")]);
    }
    if scenario.trace.resolve_paths {
        trace_args.push("--resolve-paths".into());
    }
    trace_args.extend([
        "--binder".into(),
        "--alert-rwx".into(),
        "--rules".into(),
        copied_pack
            .join(&pack.manifest.components.rules)
            .to_string_lossy()
            .into_owned(),
    ]);
    if let Some(path) = pack.manifest.components.aidl.as_deref() {
        trace_args.extend([
            "--aidl-catalog".into(),
            copied_pack.join(path).to_string_lossy().into_owned(),
        ]);
    }
    if let Some(path) = pack.manifest.components.ioctls.as_deref() {
        trace_args.extend([
            "--schema-pack".into(),
            copied_pack.join(path).to_string_lossy().into_owned(),
        ]);
    }
    let root_package = if scenario.root_package == "probe" {
        args.probe_package.clone()
    } else {
        scenario.root_package.clone()
    };
    let root_selector = research_root_selector(&root_package, crate::android::resolve_package_uid)?;
    let timeout = parse_timeout(&scenario.stimulus.timeout)?;
    let stimulus = || {
        run_stimulus(
            &args.probe_package,
            &scenario.stimulus.action,
            params,
            timeout,
        )
    };
    let capture_duration = duration
        .checked_add(Duration::from_millis(scenario.settle_ms))
        .context("research duration plus settle_ms is too large")?;
    let capture = surface::run_trace_session(
        &capture_path,
        &health_path,
        &socket_path,
        &root_selector,
        &scenario.id,
        &trace_args,
        |child| {
            match stimulus()? {
                StimulusResult::Complete => {}
                StimulusResult::Unsupported(reason) => bail!("unsupported stimulus: {reason}"),
            }
            wait_research_trace(child, capture_duration)
        },
    );
    let granted_permissions = permissions.restore()?;
    let capture = match capture {
        Ok(capture) => capture,
        Err(error) => {
            let text = format!("{error:#}");
            if let Some(reason) = text.strip_prefix("unsupported stimulus: ") {
                return Ok(ExecutionOutcome {
                    unsupported: Some(reason.to_string()),
                    granted_permissions,
                    ..ExecutionOutcome::default()
                });
            }
            return Err(error);
        }
    };

    let mut postflight = surface::collect_snapshot()?;
    reject_pid_reuse(preflight_snapshot, &postflight)?;
    surface::import_capture(&mut postflight, Cursor::new(&capture))?;
    surface::finalize_snapshot(&mut postflight);
    write_private_json(&output.join("surface.json"), &postflight, true)?;
    let normalized = crate::capture_normalize::normalize_capture(Cursor::new(&capture))?;
    let degraded = normalized
        .health
        .as_ref()
        .map_or(true, |health| health.degraded || health.output_cap_hit);
    Ok(ExecutionOutcome {
        degraded,
        unsupported: None,
        granted_permissions,
    })
}

fn research_root_selector(
    root_package: &str,
    resolve_uid: impl FnOnce(&str) -> Result<u32>,
) -> Result<surface::RootSelector> {
    let uid = resolve_uid(root_package)
        .with_context(|| format!("resolving research root package {root_package}"))?;
    Ok(surface::RootSelector::Uid(uid))
}

fn command_success(program: &str, args: &[&str]) -> Result<bool> {
    Ok(Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("running {program}"))?
        .success())
}

fn command_output(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("running {program}"))?;
    if !output.status.success() {
        bail!("{program} exited with {}", output.status);
    }
    if output.stdout.len() > 16 * 1024 || output.stderr.len() > 16 * 1024 {
        bail!("{program} output exceeded 16 KiB");
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn permission_granted_from_package_dump(dump: &str, permission: &str) -> Result<bool> {
    let prefix = format!("{permission}:");
    let state = dump
        .lines()
        .find_map(|line| line.trim().strip_prefix(&prefix))
        .with_context(|| format!("runtime permission {permission} missing from package dump"))?;
    let granted = state
        .split(',')
        .map(str::trim)
        .find_map(|field| field.strip_prefix("granted="))
        .with_context(|| format!("runtime permission {permission} has no granted state"))?;
    match granted {
        "true" => Ok(true),
        "false" => Ok(false),
        value => bail!("runtime permission {permission} has invalid granted state '{value}'"),
    }
}

struct PermissionGuard<'a> {
    package: &'a str,
    granted: Vec<String>,
}

fn restore_permissions(
    granted: &mut Vec<String>,
    mut revoke: impl FnMut(&str) -> bool,
) -> Result<Vec<String>> {
    let pending = std::mem::take(granted);
    let mut failures = Vec::new();
    for permission in pending.iter().rev() {
        if !revoke(permission) {
            failures.push(permission.clone());
        }
    }
    if !failures.is_empty() {
        failures.reverse();
        *granted = failures;
        bail!("failed to restore permissions: {}", granted.join(", "));
    }
    Ok(pending)
}

impl<'a> PermissionGuard<'a> {
    fn new(package: &'a str) -> Self {
        Self {
            package,
            granted: Vec::new(),
        }
    }

    fn ensure(&mut self, permission: &str) -> Result<()> {
        let package_dump = command_output("/system/bin/dumpsys", &["package", self.package])?;
        let already_granted = permission_granted_from_package_dump(&package_dump, permission)?;
        if !already_granted {
            if !command_success("/system/bin/pm", &["grant", self.package, permission])? {
                bail!("failed to grant compiled permission {permission}");
            }
            self.granted.push(permission.into());
        }
        Ok(())
    }

    fn restore(&mut self) -> Result<Vec<String>> {
        restore_permissions(&mut self.granted, |permission| {
            command_success("/system/bin/pm", &["revoke", self.package, permission])
                .unwrap_or(false)
        })
    }
}

impl Drop for PermissionGuard<'_> {
    fn drop(&mut self) {
        for permission in self.granted.iter().rev() {
            let _ = Command::new("/system/bin/pm")
                .args(["revoke", self.package, permission])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

enum StimulusResult {
    Complete,
    Unsupported(String),
}

fn run_stimulus(
    package: &str,
    action: &str,
    params: &BTreeMap<String, String>,
    timeout: Duration,
) -> Result<StimulusResult> {
    let component = format!("{package}/.ResearchReceiver");
    let mut command = Command::new("/system/bin/am");
    command.args([
        "broadcast",
        "-a",
        "dev.neutron.probe.RESEARCH",
        "-n",
        &component,
        "--es",
        "action",
        action,
    ]);
    for (key, value) in params {
        command.args(["--es", key, value]);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .context("starting typed companion stimulus")?;
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("typed stimulus timed out");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    child
        .stdout
        .take()
        .context("missing stimulus stdout")?
        .take(16 * 1024 + 1)
        .read_to_end(&mut stdout)?;
    child
        .stderr
        .take()
        .context("missing stimulus stderr")?
        .take(16 * 1024 + 1)
        .read_to_end(&mut stderr)?;
    if stdout.len() > 16 * 1024 || stderr.len() > 16 * 1024 {
        bail!("typed stimulus output exceeded 16 KiB");
    }
    if !status.success() {
        bail!("typed stimulus launcher exited with {status}");
    }
    let output = String::from_utf8_lossy(&stdout);
    let result = output
        .lines()
        .find_map(|line| line.split_once("result=").map(|(_, value)| value.trim()))
        .and_then(|value| value.split(',').next())
        .and_then(|value| value.parse::<i32>().ok())
        .context("typed stimulus did not return a bounded result code")?;
    match result {
        0 => Ok(StimulusResult::Complete),
        3 => Ok(StimulusResult::Unsupported(
            "companion prerequisite unavailable".into(),
        )),
        code => bail!("typed stimulus failed with result code {code}"),
    }
}

fn reject_pid_reuse(before: &SurfaceSnapshot, after: &SurfaceSnapshot) -> Result<()> {
    let before: BTreeMap<_, _> = before
        .processes
        .iter()
        .map(|process| (process.pid, process.starttime))
        .collect();
    for process in &after.processes {
        if before
            .get(&process.pid)
            .is_some_and(|starttime| *starttime != process.starttime)
        {
            bail!("PID {} was reused during research capture", process.pid);
        }
    }
    Ok(())
}

fn wait_research_trace(child: &mut std::process::Child, duration: Duration) -> Result<()> {
    let deadline = std::time::Instant::now()
        .checked_add(duration)
        .context("research duration is too large")?;
    loop {
        if !RESEARCH_RUNNING.load(Ordering::SeqCst) {
            bail!("research interrupted");
        }
        if let Some(status) = child.try_wait()? {
            bail!("child neutron trace exited during research: {status}");
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return Ok(());
        }
        std::thread::sleep((deadline - now).min(Duration::from_millis(20)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_machine_rejects_partial_or_reordered_runs() {
        let mut state = RunState::new();
        assert!(state.transition(Phase::Capturing).is_err());
        state.transition(Phase::Preflight).unwrap();
        state.transition(Phase::Capturing).unwrap();
        state.transition(Phase::Stimulated).unwrap();
        state.transition(Phase::Postflight).unwrap();
        state.transition(Phase::Reported).unwrap();
        assert_eq!(state.history.last(), Some(&"reported"));
    }

    #[test]
    fn packaged_android_agent_resolves_sibling_pack_directory() {
        let roots = pack_roots_for_executable(Path::new("/data/local/share/neutron/neutron-agent"));
        assert_eq!(
            roots
                .first()
                .map(|(path, trusted)| (path.as_path(), *trusted)),
            Some((Path::new("/data/local/share/neutron/packs"), true))
        );
        assert!(roots.iter().any(
            |(path, trusted)| *trusted && path == Path::new("/data/local/share/neutron/packs")
        ));
    }

    #[test]
    fn permission_registry_cannot_be_extended_by_pack_data() {
        assert_eq!(permissions_for("keymint"), &[] as &[&str]);
        assert_eq!(permissions_for("camera"), &["android.permission.CAMERA"]);
        assert_eq!(permissions_for("arbitrary"), &[] as &[&str]);
    }

    #[test]
    fn research_trace_uses_dynamic_uid_root_for_a_receiver_only_probe() {
        let selector = research_root_selector("dev.neutron.probe", |_| Ok(10_123)).unwrap();

        assert!(matches!(selector, surface::RootSelector::Uid(10_123)));
    }

    #[test]
    fn research_trace_does_not_inject_rejected_domain_flags() {
        let mut args = Vec::new();
        add_research_follow_guardrails(&mut args);

        assert!(args.is_empty());
    }

    #[test]
    fn parses_runtime_permission_state_from_package_dump() {
        let dump = "runtime permissions:\n  android.permission.CAMERA: granted=true, flags=[]\n  android.permission.BLUETOOTH_SCAN: granted=false, flags=[]\n";

        assert!(permission_granted_from_package_dump(dump, "android.permission.CAMERA").unwrap());
        assert!(
            !permission_granted_from_package_dump(dump, "android.permission.BLUETOOTH_SCAN")
                .unwrap()
        );
        assert!(permission_granted_from_package_dump(
            dump,
            "android.permission.NEARBY_WIFI_DEVICES"
        )
        .is_err());
    }

    #[test]
    fn failed_permission_restore_remains_armed_for_drop() {
        let mut granted = vec!["camera".to_string(), "bluetooth".to_string()];
        let result = restore_permissions(&mut granted, |permission| permission == "camera");

        assert!(result.is_err());
        assert_eq!(granted, ["bluetooth"]);
    }

    #[test]
    fn wildcard_matching_handles_vendor_prefix_and_infix_patterns() {
        assert!(glob(
            "android.hardware.camera.provider.*",
            "android.hardware.camera.provider.ICameraProvider/default"
        ));
        assert!(glob(
            "*surfaceflinger*",
            "/system/bin/surfaceflinger --flag"
        ));
        assert!(!glob("/dev/video*", "/dev/media0"));
    }
}
