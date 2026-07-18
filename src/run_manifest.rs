//! Evidence-grade run bundle metadata and private artifact helpers.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{BufReader, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const RUN_MANIFEST_SCHEMA: &str = "neutron.run-manifest/v1";
const MAX_TARGETS: usize = 4096;
const MAX_TARGET_LENGTH: usize = 4096;
const MAX_ARTIFACT_NAME: usize = 255;
const MAX_TARGET_DOCUMENT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_COVERAGE_DOCUMENT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_COVERAGE_TSV_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TARGET_SUM_BYTES: u64 = 1024;
const MAX_CAPTURE_HEALTH_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_LIVE_CAPTURE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunKind {
    SurfaceStatic,
    TraceLive,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunHealthStatus {
    Complete,
    Degraded,
    Incomplete,
    Unknown,
}

impl RunHealthStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Degraded => "degraded",
            Self::Incomplete => "incomplete",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolIdentity {
    pub version: String,
    pub git_commit: String,
    pub git_dirty: bool,
    pub binary_sha256: String,
    pub build_timestamp: String,
    pub rustc: String,
    pub target: String,
    pub feature_set: Vec<String>,
}

impl ToolIdentity {
    pub fn current() -> Result<Self> {
        let info = crate::build_info::self_info();
        Ok(Self {
            version: info.tool.version.into(),
            git_commit: info.tool.git_commit.into(),
            git_dirty: info.tool.git_dirty,
            binary_sha256: sha256_running_executable()?,
            build_timestamp: info.tool.build_timestamp.into(),
            rustc: info.tool.rustc_version.into(),
            target: info.tool.target.into(),
            feature_set: info
                .tool
                .feature_set
                .into_iter()
                .map(str::to_owned)
                .collect(),
        })
    }

    pub fn provenance_issues(&self) -> Vec<String> {
        let mut issues = Vec::new();
        if self.git_commit.bytes().all(|byte| byte == b'0') {
            issues.push("source commit is unavailable".into());
        }
        if self.git_dirty {
            issues.push("userspace binary was built from a dirty source tree".into());
        }
        if self.build_timestamp == "unknown" {
            issues.push("build timestamp is unavailable".into());
        }
        if self.rustc == "rustc unknown" || self.rustc == "unknown" {
            issues.push("rustc identity is unavailable".into());
        }
        if self.target == "unknown" {
            issues.push("build target is unavailable".into());
        }
        if self.binary_sha256.bytes().all(|byte| byte == b'0') {
            issues.push("binary content identity is unavailable".into());
        }
        issues
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BpfIdentity {
    pub used: bool,
    pub object_sha256: Option<String>,
    pub abi_major: u16,
    pub abi_minor: u16,
    pub event_size: u32,
    pub feature_bits: Vec<String>,
    pub build_id: Option<String>,
}

impl BpfIdentity {
    pub fn unused_default() -> Self {
        let info = crate::build_info::self_info();
        Self {
            used: false,
            object_sha256: None,
            abi_major: crate::bpf_abi::BPF_ABI_MAJOR,
            abi_minor: crate::bpf_abi::BPF_ABI_MINOR,
            event_size: core::mem::size_of::<neutron_common::SyscallEvent>() as u32,
            feature_bits: info
                .bpf
                .feature_bits
                .into_iter()
                .map(str::to_owned)
                .collect(),
            build_id: None,
        }
    }

    pub fn from_loaded(identity: &crate::bpf_abi::BpfObjectIdentity) -> Self {
        Self {
            used: true,
            object_sha256: Some(identity.object_sha256.clone()),
            abi_major: identity.abi_major,
            abi_minor: identity.abi_minor,
            event_size: identity.syscall_event_size,
            feature_bits: bpf_feature_labels(identity.feature_bits),
            build_id: Some(identity.build_id.clone()),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceIdentity {
    pub serial_hash: Option<String>,
    pub model: Option<String>,
    pub product: Option<String>,
    pub build_id: Option<String>,
    pub fingerprint: Option<String>,
    pub api: Option<u32>,
    pub spl: Option<String>,
    pub kernel: Option<String>,
    pub boot_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResearchModel {
    pub observer_privilege: String,
    pub attacker_capability: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunCollection {
    pub target_count: usize,
    pub minimal: bool,
    pub full_snapshot_retained: bool,
    pub repeat: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunHealth {
    pub status: RunHealthStatus,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RunManifest {
    pub schema: String,
    pub run_id: String,
    pub run_kind: RunKind,
    pub started_at: String,
    pub completed_at: String,
    pub tool: ToolIdentity,
    pub bpf: BpfIdentity,
    pub device: DeviceIdentity,
    pub research_model: ResearchModel,
    pub collection: RunCollection,
    pub health: RunHealth,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_health: Option<RunHealth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_scope: Option<crate::health::CaptureScope>,
    pub bpf_loaded: bool,
    pub stimulus_executed: bool,
    pub configuration_changed: bool,
    pub artifacts: Vec<ArtifactIdentity>,
}

#[derive(Clone, Debug)]
pub struct StaticSurfaceManifest {
    pub run_id: String,
    pub started_at: String,
    pub completed_at: String,
    pub device: DeviceIdentity,
    pub research_model: ResearchModel,
    pub collection: RunCollection,
    pub health: RunHealth,
    pub artifacts: Vec<ArtifactIdentity>,
}

#[derive(Clone, Debug)]
pub struct LiveCaptureManifest {
    pub run_id: String,
    pub started_at: String,
    pub completed_at: String,
    pub device: DeviceIdentity,
    pub research_model: ResearchModel,
    pub bpf: BpfIdentity,
    pub capture_health: Value,
    pub artifacts: Vec<ArtifactIdentity>,
}

impl RunManifest {
    pub fn static_surface(input: StaticSurfaceManifest) -> Result<Self> {
        validate_run_id(&input.run_id)?;
        validate_label("started_at", &input.started_at)?;
        validate_label("completed_at", &input.completed_at)?;
        validate_label(
            "observer_privilege",
            &input.research_model.observer_privilege,
        )?;
        validate_label(
            "attacker_capability",
            &input.research_model.attacker_capability,
        )?;
        if let Some(serial_hash) = &input.device.serial_hash {
            if serial_hash.len() != 71
                || !serial_hash.starts_with("sha256:")
                || !serial_hash[7..]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                bail!("device serial_hash must be sha256:<64 lowercase hex digits>");
            }
        }
        if input.collection.target_count == 0 || input.collection.target_count > MAX_TARGETS {
            bail!("target_count must be in 1..={MAX_TARGETS}");
        }
        if !input.collection.minimal || input.collection.full_snapshot_retained {
            bail!("surface_static v1 requires minimal target-scoped collection");
        }
        if input.collection.repeat == 0 {
            bail!("repeat must be greater than zero");
        }
        let tool = ToolIdentity::current()?;
        let mut health = input.health;
        apply_tool_provenance(&tool, &mut health);
        let manifest = Self {
            schema: RUN_MANIFEST_SCHEMA.into(),
            run_id: input.run_id,
            run_kind: RunKind::SurfaceStatic,
            started_at: input.started_at,
            completed_at: input.completed_at,
            tool,
            bpf: BpfIdentity::unused_default(),
            device: input.device,
            research_model: input.research_model,
            collection: input.collection,
            health,
            transport_health: None,
            capture_scope: None,
            bpf_loaded: false,
            stimulus_executed: false,
            configuration_changed: false,
            artifacts: input.artifacts,
        };
        validate_manifest_fields(&manifest)?;
        Ok(manifest)
    }

    pub fn live_capture(input: LiveCaptureManifest) -> Result<Self> {
        validate_run_id(&input.run_id)?;
        validate_label("started_at", &input.started_at)?;
        validate_label("completed_at", &input.completed_at)?;
        validate_label(
            "observer_privilege",
            &input.research_model.observer_privilege,
        )?;
        validate_label(
            "attacker_capability",
            &input.research_model.attacker_capability,
        )?;
        let (transport_health, capture_scope) = capture_transport_health(&input.capture_health)?;
        let tool = ToolIdentity::current()?;
        let mut health = transport_health.clone();
        apply_tool_provenance(&tool, &mut health);
        let manifest = Self {
            schema: RUN_MANIFEST_SCHEMA.into(),
            run_id: input.run_id,
            run_kind: RunKind::TraceLive,
            started_at: input.started_at,
            completed_at: input.completed_at,
            tool,
            bpf: input.bpf,
            device: input.device,
            research_model: input.research_model,
            collection: RunCollection {
                target_count: 0,
                minimal: false,
                full_snapshot_retained: false,
                repeat: 1,
            },
            health,
            transport_health: Some(transport_health),
            capture_scope: Some(capture_scope),
            bpf_loaded: true,
            stimulus_executed: false,
            configuration_changed: false,
            artifacts: input.artifacts,
        };
        validate_capture_health_binding(&manifest, &input.capture_health)?;
        validate_manifest_fields(&manifest)?;
        Ok(manifest)
    }
}

fn apply_tool_provenance(tool: &ToolIdentity, health: &mut RunHealth) {
    for issue in tool.provenance_issues() {
        let reason = format!("tool provenance unknown: {issue}");
        if !health.reasons.contains(&reason) {
            health.reasons.push(reason);
        }
        health.status = RunHealthStatus::Unknown;
    }
    health.reasons.sort();
    health.reasons.dedup();
}

fn bpf_feature_labels(bits: u64) -> Vec<String> {
    let known = [
        (neutron_common::BPF_FEATURE_SYSCALL_TRACE, "syscall_trace"),
        (neutron_common::BPF_FEATURE_BINDER_TRACE, "binder_trace"),
        (neutron_common::BPF_FEATURE_PER_CPU_HEALTH, "per_cpu_health"),
        (neutron_common::BPF_FEATURE_STACKS, "stacks"),
        (neutron_common::BPF_FEATURE_PROCESS_EXIT, "process_exit"),
    ];
    let mut labels = Vec::new();
    let mut remaining = bits;
    for (bit, label) in known {
        if bits & bit != 0 {
            labels.push(label.to_string());
            remaining &= !bit;
        }
    }
    if remaining != 0 {
        labels.push(format!("unknown_0x{remaining:016x}"));
    }
    labels
}

fn bpf_feature_bits(labels: &[String]) -> Result<u64> {
    let mut bits = 0_u64;
    for label in labels {
        let bit = match label.as_str() {
            "syscall_trace" => neutron_common::BPF_FEATURE_SYSCALL_TRACE,
            "binder_trace" => neutron_common::BPF_FEATURE_BINDER_TRACE,
            "per_cpu_health" => neutron_common::BPF_FEATURE_PER_CPU_HEALTH,
            "stacks" => neutron_common::BPF_FEATURE_STACKS,
            "process_exit" => neutron_common::BPF_FEATURE_PROCESS_EXIT,
            value => {
                let Some(hex) = value.strip_prefix("unknown_0x") else {
                    bail!("unknown BPF feature label: {value}");
                };
                if hex.len() != 16 {
                    bail!("invalid unknown BPF feature label: {value}");
                }
                u64::from_str_radix(hex, 16)
                    .with_context(|| format!("invalid unknown BPF feature label: {value}"))?
            }
        };
        if bits & bit != 0 {
            bail!("overlapping BPF feature label: {label}");
        }
        bits |= bit;
    }
    if bpf_feature_labels(bits) != labels {
        bail!("BPF feature labels are not canonical");
    }
    Ok(bits)
}

fn capture_transport_health(value: &Value) -> Result<(RunHealth, crate::health::CaptureScope)> {
    let object = value
        .as_object()
        .context("capture.health.json must contain one JSON object")?;
    let declared_status = object.get("status").and_then(Value::as_str);
    let mut errors = crate::health::capture_health_contract_errors(object);
    if declared_status == Some("unknown") {
        errors.retain(|error| {
            !error.starts_with("mandatory counter ")
                && error != "unsupported mandatory counters make health unknown"
        });
    }
    if !errors.is_empty() {
        bail!("invalid final capture health: {}", errors.join("; "));
    }
    let status = match object.get("status").and_then(Value::as_str) {
        Some("complete") => RunHealthStatus::Complete,
        Some("degraded") => RunHealthStatus::Degraded,
        Some("incomplete") => RunHealthStatus::Incomplete,
        Some("unknown") => RunHealthStatus::Unknown,
        _ => unreachable!("capture health contract validated status"),
    };
    let capture_scope = crate::health::CaptureScope::from_json_value(
        object
            .get("capture_scope")
            .expect("capture health contract validated capture_scope"),
    )
    .map_err(anyhow::Error::msg)?;
    let mut reasons = Vec::new();
    for field in ["read_errors", "incomplete_reasons", "unknown_reasons"] {
        reasons.extend(
            object
                .get(field)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(|reason| format!("{field}: {reason}")),
        );
    }
    if status != RunHealthStatus::Complete && reasons.is_empty() {
        reasons.push(format!("capture transport status: {}", status.as_str()));
    }
    reasons.sort();
    reasons.dedup();
    Ok((RunHealth { status, reasons }, capture_scope))
}

/// Create a new owner-only run directory. Existing paths are never reused.
pub fn create_private_run_directory(path: &Path) -> Result<()> {
    crate::private_output::create_private_directory(path)?;
    verify_private_directory(path)
}

/// Write a root-level run artifact and return its content identity.
pub fn write_artifact(run_dir: &Path, name: &str, bytes: &[u8]) -> Result<ArtifactIdentity> {
    verify_private_directory(run_dir)?;
    let relative = safe_artifact_name(name)?;
    let path = run_dir.join(&relative);
    crate::private_output::write(&path, bytes, false)?;
    Ok(ArtifactIdentity {
        path: relative,
        sha256: sha256_file(&path)?,
    })
}

/// Identify a completed root-level artifact without reopening it through an
/// attacker-controlled path traversal. Streaming producers call this only
/// after flushing and closing their writer.
pub fn identify_artifact(run_dir: &Path, name: &str) -> Result<ArtifactIdentity> {
    verify_private_directory(run_dir)?;
    let relative = safe_artifact_name(name)?;
    Ok(ArtifactIdentity {
        sha256: sha256_beneath(run_dir, Path::new(&relative), None)?,
        path: relative,
    })
}

pub fn utc_timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as libc::c_long;
    let mut utc = std::mem::MaybeUninit::<libc::tm>::uninit();
    // SAFETY: `seconds` and `utc` remain valid for the call.
    let result = unsafe { libc::gmtime_r(&seconds, utc.as_mut_ptr()) };
    if result.is_null() {
        return format!("{seconds}Z");
    }
    // SAFETY: a non-null `gmtime_r` return initialized `utc`.
    let utc = unsafe { utc.assume_init() };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        utc.tm_year + 1900,
        utc.tm_mon + 1,
        utc.tm_mday,
        utc.tm_hour,
        utc.tm_min,
        utc.tm_sec,
    )
}

/// Write normalized targets plus the standalone digest used by operator logs.
pub fn write_targets(run_dir: &Path, targets: &[String]) -> Result<ArtifactIdentity> {
    if targets.is_empty() || targets.len() > MAX_TARGETS {
        bail!("target list must contain 1..={MAX_TARGETS} entries");
    }
    let mut unique = BTreeSet::new();
    for target in targets {
        if target.is_empty()
            || target.len() > MAX_TARGET_LENGTH
            || !target.bytes().all(|byte| byte.is_ascii_graphic())
        {
            bail!("target must contain printable ASCII without whitespace");
        }
        if !unique.insert(target) {
            bail!("duplicate target: {target}");
        }
    }
    verify_private_directory(run_dir)?;
    let path = run_dir.join("targets.json");
    crate::private_output::write_json(&path, &targets, false)?;
    let sha256 = sha256_file(&path)?;
    crate::private_output::write(
        &run_dir.join("targets.sha256"),
        format!("{sha256}  targets.json\n").as_bytes(),
        false,
    )?;
    Ok(ArtifactIdentity {
        path: "targets.json".into(),
        sha256,
    })
}

/// Write the manifest and content-address the current bundle with deterministic
/// checksums. This detects changes but does not authenticate the publisher.
pub fn finalize_bundle(run_dir: &Path, manifest: &RunManifest) -> Result<()> {
    verify_private_directory(run_dir)?;
    verify_static_manifest(run_dir, manifest)?;
    crate::private_output::write_json(&run_dir.join("manifest.json"), manifest, false)?;
    crate::evidence::refresh_checksums(run_dir)
}

/// Hash an artifact through a non-following file descriptor.
pub fn sha256_file(path: &Path) -> Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening artifact for hashing: {}", path.display()))?;
    if !file.metadata()?.is_file() {
        bail!("artifact is not a regular file: {}", path.display());
    }
    sha256_reader(file)
}

/// Hash the already-executing image through the kernel's open executable
/// reference. This cannot race with replacing the pathname used to launch us.
fn sha256_running_executable() -> Result<String> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/proc/self/exe")
        .context("opening the running executable through /proc/self/exe")?;

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let file = {
        let executable = std::env::current_exe().context("resolving current executable")?;
        OpenOptions::new()
            .read(true)
            .open(&executable)
            .with_context(|| format!("opening running executable {}", executable.display()))?
    };

    if !file.metadata()?.is_file() {
        bail!("the running executable is not a regular file");
    }
    sha256_reader(file)
}

fn sha256_reader(file: fs::File) -> Result<String> {
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn serial_hash(serial: &str) -> Result<String> {
    validate_label("serial", serial)?;
    Ok(format!("sha256:{:x}", Sha256::digest(serial.as_bytes())))
}

fn verify_private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting run directory {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        bail!(
            "run directory must be an owned, mode-private real directory: {}",
            path.display()
        );
    }
    Ok(())
}

/// Backward-compatible verifier entry point used by the evidence command.
/// Dispatch is based on the manifest kind; a live bundle never passes through
/// the weaker static-surface contract.
pub(crate) fn verify_static_manifest(run_dir: &Path, manifest: &RunManifest) -> Result<()> {
    match manifest.run_kind {
        RunKind::SurfaceStatic => verify_surface_static_manifest(run_dir, manifest),
        RunKind::TraceLive => verify_live_capture_manifest(run_dir, manifest),
    }
}

fn verify_surface_static_manifest(run_dir: &Path, manifest: &RunManifest) -> Result<()> {
    validate_manifest_fields(manifest)?;
    if manifest.run_kind != RunKind::SurfaceStatic
        || manifest.bpf.used
        || manifest.bpf_loaded
        || manifest.bpf.object_sha256.is_some()
        || manifest.stimulus_executed
        || manifest.configuration_changed
    {
        bail!("surface_static manifest records an incompatible runtime side effect");
    }
    let paths = verify_artifact_identities(run_dir, manifest)?;
    for required in ["targets.json", "surface.coverage.json"] {
        if !paths.contains(required) {
            bail!("surface_static manifest is missing artifact: {required}");
        }
    }

    let targets: Vec<String> = serde_json::from_slice(&read_regular_beneath(
        run_dir,
        Path::new("targets.json"),
        MAX_TARGET_DOCUMENT_BYTES,
    )?)
    .context("parsing targets.json")?;
    if targets.len() != manifest.collection.target_count {
        bail!("manifest target_count does not match targets.json");
    }
    if crate::surface::coverage::parse_targets(&targets.join("\n"))? != targets {
        bail!("targets.json is not normalized, unique, and sorted");
    }
    let targets_hash = sha256_beneath(
        run_dir,
        Path::new("targets.json"),
        Some(MAX_TARGET_DOCUMENT_BYTES),
    )?;
    let target_sum = String::from_utf8(read_regular_beneath(
        run_dir,
        Path::new("targets.sha256"),
        MAX_TARGET_SUM_BYTES,
    )?)
    .context("targets.sha256 is not UTF-8")?;
    if target_sum != format!("{targets_hash}  targets.json\n") {
        bail!("targets.sha256 does not match targets.json");
    }

    let coverage: crate::surface::coverage::CoverageDocument =
        serde_json::from_slice(&read_regular_beneath(
            run_dir,
            Path::new("surface.coverage.json"),
            MAX_COVERAGE_DOCUMENT_BYTES,
        )?)
        .context("parsing surface.coverage.json")?;
    if coverage.schema != "neutron.surface-coverage/v1"
        || coverage.neutron_version != manifest.tool.version
        || coverage.collection.target_count != manifest.collection.target_count
        || !coverage.collection.minimal
        || coverage.collection.full_snapshot_retained
        || coverage.repeat.count != manifest.collection.repeat
        || coverage.health.status != manifest.health.status.as_str()
        || coverage.health.warnings != manifest.health.reasons
    {
        bail!("surface.coverage.json does not match the static manifest");
    }
    let endpoints: Vec<_> = coverage
        .rows
        .iter()
        .map(|row| row.endpoint.clone())
        .collect();
    if coverage.rows.len() != targets.len()
        || crate::surface::coverage::parse_targets(&endpoints.join("\n"))? != targets
    {
        bail!("surface.coverage.json rows do not exactly cover targets.json");
    }
    let exact = coverage
        .rows
        .iter()
        .filter(|row| row.attribution.confidence == "exact")
        .count();
    let unresolved = coverage
        .rows
        .iter()
        .filter(|row| row.attribution.confidence == "unresolved")
        .count();
    let ambiguous = coverage
        .rows
        .iter()
        .filter(|row| row.attribution.confidence == "ambiguous")
        .count();
    if (exact, unresolved, ambiguous)
        != (
            coverage.summary.exact,
            coverage.summary.unresolved,
            coverage.summary.ambiguous,
        )
        || exact + unresolved + ambiguous != coverage.rows.len()
    {
        bail!("surface.coverage.json summary does not match its rows");
    }
    if !coverage.repeat.semantic_drift.is_empty()
        && manifest.health.status != RunHealthStatus::Incomplete
    {
        bail!("semantic drift requires incomplete run health");
    }
    if manifest.device.fingerprint.as_deref() != nonempty(&coverage.device.fingerprint)
        || manifest.device.boot_id.as_deref() != nonempty(&coverage.device.boot_id)
    {
        bail!("surface.coverage.json device identity does not match the manifest");
    }
    validate_coverage_provenance(&coverage)?;
    Ok(())
}

fn verify_live_capture_manifest(run_dir: &Path, manifest: &RunManifest) -> Result<()> {
    validate_manifest_fields(manifest)?;
    let paths = verify_artifact_identities(run_dir, manifest)?;
    for required in ["capture.ndjson", "capture.health.json"] {
        if !paths.contains(required) {
            bail!("trace_live manifest is missing artifact: {required}");
        }
    }

    let health: Value = serde_json::from_slice(&read_regular_beneath(
        run_dir,
        Path::new("capture.health.json"),
        MAX_CAPTURE_HEALTH_BYTES,
    )?)
    .context("parsing capture.health.json")?;
    validate_capture_health_binding(manifest, &health)?;
    verify_capture_stream(run_dir, &health)?;
    Ok(())
}

fn verify_artifact_identities(run_dir: &Path, manifest: &RunManifest) -> Result<BTreeSet<String>> {
    let mut paths = BTreeSet::new();
    for artifact in &manifest.artifacts {
        let name = safe_artifact_name(&artifact.path)?;
        if !paths.insert(name.clone()) {
            bail!("duplicate manifest artifact: {name}");
        }
        validate_lower_hex("manifest artifact sha256", &artifact.sha256, 64)?;
        let maximum = match (manifest.run_kind.clone(), name.as_str()) {
            (RunKind::SurfaceStatic, "targets.json") => MAX_TARGET_DOCUMENT_BYTES,
            (RunKind::SurfaceStatic, "surface.coverage.json") => MAX_COVERAGE_DOCUMENT_BYTES,
            (RunKind::SurfaceStatic, "surface.coverage.tsv") => MAX_COVERAGE_TSV_BYTES,
            (RunKind::TraceLive, "capture.ndjson") => MAX_LIVE_CAPTURE_BYTES,
            (RunKind::TraceLive, "capture.health.json") => MAX_CAPTURE_HEALTH_BYTES,
            _ => bail!("manifest contains an unsupported artifact for its run kind: {name}"),
        };
        let actual = sha256_beneath(run_dir, Path::new(&name), Some(maximum))?;
        if actual != artifact.sha256 {
            bail!("manifest artifact hash mismatch: {name}");
        }
    }
    Ok(paths)
}

fn verify_capture_stream(run_dir: &Path, expected_health: &Value) -> Result<()> {
    let file = crate::private_output::open_regular_beneath(
        run_dir,
        Path::new("capture.ndjson"),
        Some(MAX_LIVE_CAPTURE_BYTES),
    )?;
    let mut reader = BufReader::new(file);
    let mut record = Vec::new();
    let mut record_number = 0_usize;
    let mut health_record = None;
    let mut last_nonempty = 0_usize;
    let mut invalid_binder_caller_records = 0_usize;
    let mut zero_binder_receive_records = 0_usize;
    let mut scenarios = LiveScenarioLifecycle::default();
    loop {
        record_number = record_number.saturating_add(1);
        if !crate::capture_input::read_capture_record(&mut reader, &mut record, record_number)? {
            break;
        }
        if record.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let value: Value = serde_json::from_slice(&record)
            .with_context(|| format!("parsing capture.ndjson record {record_number}"))?;
        crate::capture_input::validate_capture_strings(&value, record_number)?;
        let object = value
            .as_object()
            .with_context(|| format!("capture.ndjson record {record_number} is not an object"))?;
        let kind = object
            .get("type")
            .and_then(Value::as_str)
            .with_context(|| format!("capture.ndjson record {record_number} has no type"))?;
        if kind != "capture_health" && !valid_live_capture_record(kind, object) {
            bail!(
                "capture.ndjson record {record_number} is not a semantically valid recognized event"
            );
        }
        let scenario_bound = object.contains_key("scenario_id") || object.contains_key("trace_id");
        if scenario_bound && unusable_raw_binder_identity(kind, object) {
            match kind {
                "binder" => {
                    invalid_binder_caller_records = invalid_binder_caller_records.saturating_add(1);
                }
                "binder_received" => {
                    zero_binder_receive_records = zero_binder_receive_records.saturating_add(1);
                }
                _ => {}
            }
        }
        if kind != "capture_health" {
            scenarios.observe(kind, object).with_context(|| {
                format!("validating scenario binding at record {record_number}")
            })?;
        }
        last_nonempty = record_number;
        if kind == "capture_health" && health_record.replace((record_number, value)).is_some() {
            bail!("capture.ndjson contains more than one capture_health record");
        }
    }
    match health_record {
        Some((number, actual)) => {
            if number != last_nonempty {
                bail!("capture_health must be the final capture.ndjson record");
            }
            if actual != *expected_health {
                bail!("capture.ndjson health record does not match capture.health.json");
            }
        }
        None if expected_health
            .get("output_cap_hit")
            .and_then(Value::as_bool)
            == Some(true) => {}
        None => bail!("capture.ndjson is missing its final capture_health record"),
    }
    let unusable_binder_identity_records =
        invalid_binder_caller_records.saturating_add(zero_binder_receive_records);
    if unusable_binder_identity_records > 0 {
        let status = expected_health.get("status").and_then(Value::as_str);
        if !matches!(status, Some("incomplete" | "unknown")) {
            bail!(
                "capture contains {unusable_binder_identity_records} scenario-bound raw Binder identity record(s) without matching incomplete health accounting"
            );
        }
        if expected_health
            .get("binder_tracker_enabled")
            .and_then(Value::as_bool)
            != Some(false)
        {
            let invalid_callers = expected_health
                .get("binder_invalid_callers")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if invalid_callers < invalid_binder_caller_records as u64 {
                bail!(
                    "binder_invalid_callers health counter {invalid_callers} is below {invalid_binder_caller_records} observed scenario-bound invalid caller record(s)"
                );
            }
            let unmatched_receives = expected_health
                .get("binder_unmatched_receives")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if unmatched_receives < zero_binder_receive_records as u64 {
                bail!(
                    "binder_unmatched_receives health counter {unmatched_receives} is below {zero_binder_receive_records} observed scenario-bound zero-identity receive record(s)"
                );
            }
        }
    }
    scenarios.finish(expected_health)?;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActiveLiveScenario {
    scenario_id: String,
    trace_id: String,
    generation: u16,
    root_package: Option<String>,
    root_uid: Option<u32>,
    root_pid: Option<u32>,
    start_ts_ns: u64,
    max_event_ts_ns: u64,
}

#[derive(Default)]
struct LiveScenarioLifecycle {
    active: Option<ActiveLiveScenario>,
    seen_scenarios: BTreeSet<String>,
    seen_trace_ids: BTreeSet<String>,
    seen_generations: BTreeSet<u16>,
    completed: usize,
    last_boundary_ts_ns: u64,
}

impl LiveScenarioLifecycle {
    fn observe(&mut self, kind: &str, object: &serde_json::Map<String, Value>) -> Result<()> {
        if kind == "marker" {
            self.observe_marker(object)
        } else {
            self.observe_event(object)
        }
    }

    fn observe_marker(&mut self, object: &serde_json::Map<String, Value>) -> Result<()> {
        let scenario_id = required_record_text(object, "scenario_id")?;
        validate_scenario_id(scenario_id)?;
        if required_record_text(object, "name")? != scenario_id {
            bail!("scenario marker name and scenario_id differ");
        }
        let trace_id = required_record_text(object, "trace_id")?;
        validate_trace_id(trace_id)?;
        let generation = object
            .get("generation")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .filter(|value| *value > 0)
            .context("scenario marker is missing a valid generation")?;
        let timestamp = object
            .get("ts_ns")
            .and_then(Value::as_u64)
            .filter(|value| *value > 0)
            .context("scenario marker is missing a positive timestamp")?;
        if timestamp < self.last_boundary_ts_ns {
            bail!("scenario boundary timestamps are not monotonic");
        }
        let root_package = optional_record_text(object, "root_package")?;
        let root_uid = optional_record_u32(object, "root_uid", false)?;
        let root_pid = optional_record_u32(object, "root_pid", true)?;
        if root_package.is_none() && root_uid.is_none() && root_pid.is_none() {
            bail!("scenario marker is missing a package, UID, or PID root selector");
        }

        match required_record_text(object, "phase")? {
            "start" => {
                if self.active.is_some() {
                    bail!("scenario markers overlap or contain duplicate starts");
                }
                if !self.seen_scenarios.insert(scenario_id.to_owned()) {
                    bail!("scenario_id was reused in one capture");
                }
                if !self.seen_trace_ids.insert(trace_id.to_owned()) {
                    bail!("trace_id was reused in one capture");
                }
                if !self.seen_generations.insert(generation) {
                    bail!("scenario generation was reused in one capture");
                }
                self.active = Some(ActiveLiveScenario {
                    scenario_id: scenario_id.to_owned(),
                    trace_id: trace_id.to_owned(),
                    generation,
                    root_package,
                    root_uid,
                    root_pid,
                    start_ts_ns: timestamp,
                    max_event_ts_ns: timestamp,
                });
                self.last_boundary_ts_ns = timestamp;
            }
            "end" => {
                let active = self
                    .active
                    .take()
                    .context("scenario end marker has no matching start")?;
                if active.scenario_id != scenario_id
                    || active.trace_id != trace_id
                    || active.generation != generation
                    || active.root_package != root_package
                    || active.root_uid != root_uid
                    || active.root_pid != root_pid
                {
                    bail!("scenario start/end identity does not match");
                }
                if timestamp < active.start_ts_ns || timestamp < active.max_event_ts_ns {
                    bail!("scenario end timestamp precedes its bounded records");
                }
                self.completed = self.completed.saturating_add(1);
                self.last_boundary_ts_ns = timestamp;
            }
            _ => bail!("scenario marker phase must be start or end"),
        }
        Ok(())
    }

    fn observe_event(&mut self, object: &serde_json::Map<String, Value>) -> Result<()> {
        let has_scenario = object.contains_key("scenario_id");
        let has_trace = object.contains_key("trace_id");
        if !has_scenario && !has_trace {
            return Ok(());
        }
        let scenario_id = required_record_text(object, "scenario_id")?;
        let trace_id = required_record_text(object, "trace_id")?;
        validate_scenario_id(scenario_id)?;
        validate_trace_id(trace_id)?;
        let active = self
            .active
            .as_mut()
            .context("causally tagged record is outside a scenario interval")?;
        if active.scenario_id != scenario_id || active.trace_id != trace_id {
            bail!("causal record scenario_id/trace_id does not match the active scenario");
        }
        if let Some(generation) = optional_record_u32(object, "generation", true)? {
            if generation != u32::from(active.generation) {
                bail!("causal record generation does not match the active scenario");
            }
        }
        if let Some(root_package) = optional_record_text(object, "root_package")? {
            if active.root_package.as_deref() != Some(root_package.as_str()) {
                bail!("causal record package root does not match the active scenario");
            }
        }
        if let Some(root_uid) = optional_record_u32(object, "root_uid", false)? {
            if active.root_uid != Some(root_uid) {
                bail!("causal record UID root does not match the active scenario");
            }
        }
        if let Some(root_pid) = optional_record_u32(object, "root_pid", true)? {
            if active.root_pid != Some(root_pid) {
                bail!("causal record PID root does not match the active scenario");
            }
        }
        if let Some(timestamp) = object.get("ts_ns").or_else(|| object.get("timestamp_ns")) {
            let timestamp = timestamp
                .as_u64()
                .filter(|value| *value > 0)
                .context("causal record has an invalid timestamp")?;
            if timestamp < active.start_ts_ns {
                bail!("causal record timestamp precedes its scenario start");
            }
            active.max_event_ts_ns = active.max_event_ts_ns.max(timestamp);
        }
        Ok(())
    }

    fn finish(self, expected_health: &Value) -> Result<()> {
        if let Some(active) = self.active {
            let status = expected_health.get("status").and_then(Value::as_str);
            let expected_reason = format!(
                "scenario '{}' ended without a closing marker",
                active.scenario_id
            );
            let reason_recorded = expected_health
                .get("incomplete_reasons")
                .and_then(Value::as_array)
                .is_some_and(|reasons| {
                    reasons
                        .iter()
                        .any(|reason| reason.as_str() == Some(expected_reason.as_str()))
                });
            if !matches!(status, Some("incomplete" | "unknown")) || !reason_recorded {
                bail!("scenario start marker has no matching end");
            }
            return Ok(());
        }
        if self.completed == 0 {
            bail!("capture has no paired scenario lifecycle markers");
        }
        Ok(())
    }
}

fn required_record_text<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a str> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("record is missing {field}"))?;
    validate_label(field, value)?;
    Ok(value)
}

fn optional_record_text(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<String>> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .filter(|value| !value.is_empty())
        .with_context(|| format!("record contains invalid {field}"))?;
    validate_label(field, value)?;
    Ok(Some(value.to_owned()))
}

fn optional_record_u32(
    object: &serde_json::Map<String, Value>,
    field: &str,
    positive: bool,
) -> Result<Option<u32>> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    let value = value
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| !positive || *value > 0)
        .with_context(|| format!("record contains invalid {field}"))?;
    Ok(Some(value))
}

fn validate_scenario_id(value: &str) -> Result<()> {
    if value.len() > 128 || value.trim().is_empty() || value.chars().any(char::is_control) {
        bail!("scenario_id must be at most 128 printable characters");
    }
    Ok(())
}

fn validate_trace_id(value: &str) -> Result<()> {
    validate_lower_hex("trace_id", value, 16)?;
    if value.bytes().all(|byte| byte == b'0') {
        bail!("trace_id must be non-zero");
    }
    Ok(())
}

fn valid_live_capture_record(kind: &str, object: &serde_json::Map<String, Value>) -> bool {
    let positive = |field| {
        object
            .get(field)
            .and_then(Value::as_u64)
            .is_some_and(|value| value > 0)
    };
    let u32_value = |field| {
        object
            .get(field)
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .is_some()
    };
    let text = |field| object.get(field).and_then(Value::as_str);
    let syscall_named = text("name").is_some_and(|value| !value.is_empty())
        || text("syscall").is_some_and(|value| !value.is_empty())
        || object
            .get("nr")
            .or_else(|| object.get("syscall_nr"))
            .and_then(Value::as_i64)
            .is_some_and(|value| value >= 0);
    match kind {
        "syscall" => positive("pid") && syscall_named,
        "binder" => {
            positive("pid")
                && u32_value("to_proc")
                && object.get("debug_id").and_then(Value::as_i64).is_some()
        }
        "binder_call" => {
            positive("caller_pid")
                && positive("callee_pid")
                && object
                    .get("debug_id")
                    .and_then(Value::as_i64)
                    .is_some_and(|value| value != 0)
        }
        "binder_received" => {
            positive("pid") && object.get("debug_id").and_then(Value::as_i64).is_some()
        }
        "process_exit" | "selinux_denial" | "fd_snapshot" => positive("pid"),
        "finding" => text("rule_id").is_some_and(|value| !value.is_empty()),
        "marker" => {
            let scenario = text("scenario_id").filter(|value| !value.is_empty());
            text("name").filter(|value| !value.is_empty()) == scenario
                && text("phase").is_some_and(|value| matches!(value, "start" | "end"))
                && text("trace_id").is_some_and(|value| !value.is_empty())
                && object
                    .get("generation")
                    .and_then(Value::as_u64)
                    .is_some_and(|value| value > 0 && value <= u64::from(u16::MAX))
                && positive("ts_ns")
                && (text("root_package").is_some_and(|value| !value.is_empty())
                    || object.get("root_uid").and_then(Value::as_u64).is_some()
                    || positive("root_pid"))
        }
        "process_maps" => positive("pid") && object.get("mappings").is_some_and(Value::is_array),
        "stack_trace" => {
            positive("pid") && text("stack_trace_ref").is_some_and(|value| !value.is_empty())
        }
        "follow_guardrail" => {
            positive("caller_pid")
                && positive("callee_pid")
                && text("status").is_some()
                && text("reason").is_some()
        }
        _ => false,
    }
}

fn unusable_raw_binder_identity(kind: &str, object: &serde_json::Map<String, Value>) -> bool {
    match kind {
        "binder" => {
            object.get("debug_id").and_then(Value::as_i64) == Some(0)
                || object.get("to_proc").and_then(Value::as_u64) == Some(0)
        }
        "binder_received" => object.get("debug_id").and_then(Value::as_i64) == Some(0),
        _ => false,
    }
}

fn validate_capture_health_binding(manifest: &RunManifest, health: &Value) -> Result<()> {
    let (transport, scope) = capture_transport_health(health)?;
    if manifest.transport_health.as_ref() != Some(&transport)
        || manifest.capture_scope.as_ref() != Some(&scope)
    {
        bail!("capture.health.json transport health or scope does not match the manifest");
    }
    let object = health
        .as_object()
        .expect("capture_transport_health validated object");
    let bpf_sha256 = object.get("bpf_object_sha256").and_then(Value::as_str);
    let bpf_build_id = object.get("bpf_build_id").and_then(Value::as_str);
    let recorded_feature_bits = object.get("bpf_feature_bits").and_then(Value::as_u64);
    if manifest.bpf.object_sha256.as_deref() != bpf_sha256
        || manifest.bpf.build_id.as_deref() != bpf_build_id
        || Some(manifest.bpf.abi_major as u64)
            != object.get("bpf_abi_major").and_then(Value::as_u64)
        || Some(manifest.bpf.abi_minor as u64)
            != object.get("bpf_abi_minor").and_then(Value::as_u64)
        || Some(manifest.bpf.event_size as u64)
            != object.get("bpf_event_size").and_then(Value::as_u64)
        || Some(bpf_feature_bits(&manifest.bpf.feature_bits)?) != recorded_feature_bits
    {
        bail!("capture.health.json BPF identity does not match the manifest");
    }
    for (field, expected) in [
        ("boot_id", manifest.device.boot_id.as_deref()),
        ("fingerprint", manifest.device.fingerprint.as_deref()),
    ] {
        let actual = object.get(field).and_then(Value::as_str);
        if actual != expected {
            bail!("capture.health.json {field} does not match the manifest");
        }
    }
    Ok(())
}

fn validate_coverage_provenance(
    coverage: &crate::surface::coverage::CoverageDocument,
) -> Result<()> {
    for row in &coverage.rows {
        validate_label("coverage endpoint", &row.endpoint)?;
        validate_label("coverage transport", &row.transport)?;

        let mut sources = BTreeSet::new();
        let mut collectors = BTreeSet::new();
        let mut declared_transports = BTreeSet::new();
        let mut live_transports = BTreeSet::new();
        let mut live_pids = BTreeSet::new();
        for source in &row.attribution.sources {
            if source.measured_by != "neutron" {
                bail!(
                    "coverage source for {} was not measured by neutron",
                    row.endpoint
                );
            }
            validate_label("coverage source collector", &source.collector)?;
            validate_label("coverage source path", &source.source)?;
            validate_label("coverage evidence excerpt", &source.evidence)?;
            validate_lower_hex("coverage evidence_sha256", &source.evidence_sha256, 64)?;
            let actual = format!("{:x}", Sha256::digest(source.evidence.as_bytes()));
            if actual != source.evidence_sha256 {
                bail!(
                    "coverage evidence hash mismatch for {} collector {}",
                    row.endpoint,
                    source.collector
                );
            }
            if let Some(source_sha256) = &source.source_sha256 {
                validate_lower_hex("coverage source_sha256", source_sha256, 64)?;
            }
            if !sources.insert(source) {
                bail!("coverage row {} contains duplicate evidence", row.endpoint);
            }
            collectors.insert(source.collector.as_str());
            match source.collector.as_str() {
                "vintf" => {
                    require_evidence_field(source, "endpoint", &row.endpoint)?;
                    let transport = evidence_field_value(&source.evidence, "transport")
                        .context("VINTF evidence lacks transport")?;
                    declared_transports.insert(transport);
                }
                "service_list" => {
                    require_evidence_field(source, "name", &row.endpoint)?;
                    live_transports.insert("binder");
                }
                "lshal" => {
                    require_evidence_field(source, "name", &row.endpoint)?;
                    live_transports.insert("hwbinder");
                    if let Some(pid) = evidence_field_value(&source.evidence, "pid")
                        .and_then(|value| value.parse::<u32>().ok())
                        .filter(|pid| *pid != 0)
                    {
                        live_pids.insert(pid);
                    }
                }
                "vndservice_list" => {
                    require_evidence_field(source, "name", &row.endpoint)?;
                    live_transports.insert("vndbinder");
                }
                "dumpsys_pid" => {
                    require_evidence_field(source, "endpoint", &row.endpoint)?;
                    if let Some(pid) = evidence_field_value(&source.evidence, "pid")
                        .and_then(|value| value.parse::<u32>().ok())
                        .filter(|pid| *pid != 0)
                    {
                        live_pids.insert(pid);
                    }
                }
                _ => {}
            }
        }

        if row.declared != !declared_transports.is_empty() {
            bail!(
                "coverage row {} declaration flag contradicts VINTF evidence",
                row.endpoint
            );
        }
        if row.live != !live_transports.is_empty() {
            bail!(
                "coverage row {} live flag contradicts service evidence",
                row.endpoint
            );
        }
        let effective_transports = if live_transports.is_empty() {
            &declared_transports
        } else {
            &live_transports
        };
        let expected_transport = match effective_transports.len() {
            0 => "unknown",
            1 => effective_transports
                .iter()
                .next()
                .copied()
                .unwrap_or("unknown"),
            _ => "ambiguous",
        };
        if row.transport != expected_transport {
            bail!(
                "coverage row {} transport contradicts its endpoint evidence",
                row.endpoint
            );
        }

        match row.attribution.confidence.as_str() {
            "exact" => validate_exact_coverage_row(row, &collectors, &coverage.device.boot_id)?,
            "unresolved" => {
                if row.owner.is_some() {
                    bail!(
                        "unresolved coverage row {} must not claim an exact owner",
                        row.endpoint
                    );
                }
                if expected_transport == "ambiguous" || live_pids.len() > 1 {
                    bail!("ambiguous coverage evidence cannot be labeled unresolved");
                }
            }
            "ambiguous" => {
                if !row.live || (expected_transport != "ambiguous" && live_pids.len() <= 1) {
                    bail!("ambiguous coverage row lacks conflicting live evidence");
                }
            }
            other => bail!(
                "coverage row {} has unknown confidence {other}",
                row.endpoint
            ),
        }

        if let Some(owner) = &row.owner {
            if owner.pid == 0
                || owner.starttime == 0
                || owner.boot_id.is_empty()
                || owner.selinux_domain.is_empty()
                || owner.executable.is_empty()
            {
                bail!(
                    "coverage row {} has an invalid owner identity",
                    row.endpoint
                );
            }
            for (name, value) in [
                ("owner.boot_id", owner.boot_id.as_str()),
                ("owner.selinux_domain", owner.selinux_domain.as_str()),
                ("owner.executable", owner.executable.as_str()),
            ] {
                validate_label(name, value)?;
            }
            if owner.boot_id != coverage.device.boot_id {
                bail!(
                    "coverage owner boot identity differs from the collection for {}",
                    row.endpoint
                );
            }
            validate_owner_evidence(row, owner)?;
        }
    }
    Ok(())
}

fn validate_exact_coverage_row(
    row: &crate::surface::coverage::CoverageRow,
    collectors: &BTreeSet<&str>,
    collection_boot_id: &str,
) -> Result<()> {
    if !row.live {
        bail!("exact coverage row {} is not live", row.endpoint);
    }
    let owner = row
        .owner
        .as_ref()
        .with_context(|| format!("exact coverage row {} has no owner", row.endpoint))?;
    if collection_boot_id.is_empty() || owner.boot_id != collection_boot_id {
        bail!(
            "exact coverage row {} lacks a matching boot identity",
            row.endpoint
        );
    }

    let required: &[&str] = match row.transport.as_str() {
        "binder" => &[
            "service_list",
            "dumpsys_pid",
            "dumpsys_pid_revalidated",
            "boot_id",
            "boot_id_revalidated",
            "proc_stat",
            "proc_stat_revalidated",
            "proc_stat_endpoint_revalidated",
            "proc_status",
            "proc_attr",
            "proc_exe",
        ],
        "hwbinder" => &[
            "lshal",
            "lshal_revalidated",
            "boot_id",
            "boot_id_revalidated",
            "proc_stat",
            "proc_stat_revalidated",
            "proc_stat_endpoint_revalidated",
            "proc_status",
            "proc_attr",
            "proc_exe",
        ],
        other => {
            bail!(
                "exact coverage row {} has unsupported transport {other}",
                row.endpoint
            )
        }
    };
    for collector in required {
        if !collectors.contains(collector) {
            bail!(
                "exact coverage row {} lacks required {collector} evidence",
                row.endpoint
            );
        }
    }
    let expected_inventory = match row.transport.as_str() {
        "binder" => ("service_list", format!("name={} ", row.endpoint)),
        "hwbinder" => ("lshal", format!("name={} pid={}", row.endpoint, owner.pid)),
        _ => unreachable!("transport was validated above"),
    };
    require_evidence_prefix(row, expected_inventory.0, &expected_inventory.1)?;
    if row.transport == "binder" {
        require_evidence_exact(
            row,
            "dumpsys_pid",
            &format!("endpoint={} pid={}", row.endpoint, owner.pid),
        )?;
        require_evidence_exact(
            row,
            "dumpsys_pid_revalidated",
            &format!("endpoint={} pid={}", row.endpoint, owner.pid),
        )?;
    } else {
        require_evidence_exact(
            row,
            "lshal_revalidated",
            &format!("endpoint={} pids={}", row.endpoint, owner.pid),
        )?;
    }
    require_evidence_exact(row, "boot_id", &format!("boot_id={}", owner.boot_id))?;
    require_evidence_exact(
        row,
        "boot_id_revalidated",
        &format!("boot_id={}", owner.boot_id),
    )?;
    let process_identity = format!("pid={} starttime={}", owner.pid, owner.starttime);
    require_evidence_exact(row, "proc_stat", &process_identity)?;
    require_evidence_exact(row, "proc_stat_revalidated", &process_identity)?;
    require_evidence_exact(
        row,
        "proc_stat_endpoint_revalidated",
        &format!("endpoint={} {process_identity}", row.endpoint),
    )?;
    require_evidence_exact(
        row,
        "proc_status",
        &format!("pid={} uid={} gid={}", owner.pid, owner.uid, owner.gid),
    )?;
    require_evidence_exact(
        row,
        "proc_attr",
        &format!("pid={} selinux_domain={}", owner.pid, owner.selinux_domain),
    )?;
    require_evidence_exact(
        row,
        "proc_exe",
        &format!("pid={} executable={}", owner.pid, owner.executable),
    )?;
    Ok(())
}

fn require_evidence_exact(
    row: &crate::surface::coverage::CoverageRow,
    collector: &str,
    expected: &str,
) -> Result<()> {
    if row
        .attribution
        .sources
        .iter()
        .any(|source| source.collector == collector && source.evidence == expected)
    {
        Ok(())
    } else {
        bail!(
            "exact coverage row {} has {collector} evidence inconsistent with its owner",
            row.endpoint
        )
    }
}

fn require_evidence_prefix(
    row: &crate::surface::coverage::CoverageRow,
    collector: &str,
    prefix: &str,
) -> Result<()> {
    if row
        .attribution
        .sources
        .iter()
        .any(|source| source.collector == collector && source.evidence.starts_with(prefix))
    {
        Ok(())
    } else {
        bail!(
            "exact coverage row {} has {collector} evidence inconsistent with its endpoint",
            row.endpoint
        )
    }
}

fn validate_manifest_fields(manifest: &RunManifest) -> Result<()> {
    if manifest.schema != RUN_MANIFEST_SCHEMA {
        bail!("manifest schema must be {RUN_MANIFEST_SCHEMA}");
    }
    validate_run_id(&manifest.run_id)?;
    for (name, value) in [
        ("started_at", manifest.started_at.as_str()),
        ("completed_at", manifest.completed_at.as_str()),
        ("tool.version", manifest.tool.version.as_str()),
        (
            "tool.build_timestamp",
            manifest.tool.build_timestamp.as_str(),
        ),
        ("tool.rustc", manifest.tool.rustc.as_str()),
        ("tool.target", manifest.tool.target.as_str()),
        (
            "observer_privilege",
            manifest.research_model.observer_privilege.as_str(),
        ),
        (
            "attacker_capability",
            manifest.research_model.attacker_capability.as_str(),
        ),
    ] {
        validate_label(name, value)?;
    }
    validate_lower_hex("tool.git_commit", &manifest.tool.git_commit, 40)?;
    validate_lower_hex("tool.binary_sha256", &manifest.tool.binary_sha256, 64)?;
    let provenance_issues = manifest.tool.provenance_issues();
    for issue in &provenance_issues {
        let reason = format!("tool provenance unknown: {issue}");
        if manifest.health.status != RunHealthStatus::Unknown
            || !manifest.health.reasons.contains(&reason)
        {
            bail!("incomplete tool provenance requires explicit unknown run health");
        }
    }
    validate_unique_labels("tool.feature_set", &manifest.tool.feature_set)?;
    validate_unique_labels("bpf.feature_bits", &manifest.bpf.feature_bits)?;
    if manifest.bpf.abi_major != crate::bpf_abi::BPF_ABI_MAJOR
        || manifest.bpf.abi_minor != crate::bpf_abi::BPF_ABI_MINOR
        || manifest.bpf.event_size != core::mem::size_of::<neutron_common::SyscallEvent>() as u32
    {
        bail!("manifest has incompatible BPF ABI metadata");
    }
    if let Some(serial_hash) = &manifest.device.serial_hash {
        let Some(value) = serial_hash.strip_prefix("sha256:") else {
            bail!("device serial_hash must be sha256:<64 lowercase hex digits>");
        };
        validate_lower_hex("device.serial_hash", value, 64)?;
    }
    for (name, value) in [
        ("device.model", manifest.device.model.as_deref()),
        ("device.product", manifest.device.product.as_deref()),
        ("device.build_id", manifest.device.build_id.as_deref()),
        ("device.fingerprint", manifest.device.fingerprint.as_deref()),
        ("device.spl", manifest.device.spl.as_deref()),
        ("device.kernel", manifest.device.kernel.as_deref()),
        ("device.boot_id", manifest.device.boot_id.as_deref()),
    ] {
        if let Some(value) = value {
            validate_label(name, value)?;
        }
    }
    validate_run_health("health", &manifest.health)?;
    if manifest.stimulus_executed || manifest.configuration_changed {
        bail!("run-manifest/v1 does not permit inferred stimulus or configuration changes");
    }
    match manifest.run_kind {
        RunKind::SurfaceStatic => {
            if manifest.bpf.used
                || manifest.bpf_loaded
                || manifest.bpf.object_sha256.is_some()
                || manifest.bpf.build_id.is_some()
                || manifest.transport_health.is_some()
                || manifest.capture_scope.is_some()
            {
                bail!("surface_static manifest records an incompatible runtime side effect");
            }
            if manifest.collection.target_count == 0
                || manifest.collection.target_count > MAX_TARGETS
            {
                bail!("target_count must be in 1..={MAX_TARGETS}");
            }
            if !manifest.collection.minimal || manifest.collection.full_snapshot_retained {
                bail!("surface_static v1 requires minimal target-scoped collection");
            }
            if manifest.collection.repeat == 0 || manifest.collection.repeat > 32 {
                bail!("repeat must be in 1..=32");
            }
        }
        RunKind::TraceLive => {
            let serial_hash = manifest
                .device
                .serial_hash
                .as_deref()
                .context("trace_live requires device.serial_hash")?;
            let serial_digest = serial_hash
                .strip_prefix("sha256:")
                .context("device.serial_hash must use the sha256: prefix")?;
            validate_lower_hex("device.serial_hash", serial_digest, 64)?;
            if serial_digest.bytes().all(|byte| byte == b'0') {
                bail!("trace_live device.serial_hash cannot be a zero placeholder");
            }
            for (name, value) in [
                ("device.model", manifest.device.model.as_deref()),
                ("device.product", manifest.device.product.as_deref()),
                ("device.build_id", manifest.device.build_id.as_deref()),
                ("device.fingerprint", manifest.device.fingerprint.as_deref()),
                ("device.spl", manifest.device.spl.as_deref()),
                ("device.kernel", manifest.device.kernel.as_deref()),
            ] {
                let value = value.with_context(|| format!("trace_live requires {name}"))?;
                validate_label(name, value)?;
            }
            if !manifest
                .device
                .api
                .is_some_and(|api| (1..=10_000).contains(&api))
            {
                bail!("trace_live requires device.api in 1..=10000");
            }
            let boot_id = manifest
                .device
                .boot_id
                .as_deref()
                .context("trace_live requires device.boot_id")?;
            if !is_lower_uuid(boot_id) {
                bail!("trace_live device.boot_id must be a lowercase UUID");
            }
            if !manifest.bpf.used || !manifest.bpf_loaded {
                bail!("trace_live requires a loaded BPF object");
            }
            let object_sha256 = manifest
                .bpf
                .object_sha256
                .as_deref()
                .context("trace_live requires bpf.object_sha256")?;
            validate_lower_hex("bpf.object_sha256", object_sha256, 64)?;
            let build_id = manifest
                .bpf
                .build_id
                .as_deref()
                .context("trace_live requires bpf.build_id")?;
            validate_lower_hex("bpf.build_id", build_id, 40)?;
            if object_sha256.bytes().all(|byte| byte == b'0')
                || build_id.bytes().all(|byte| byte == b'0')
            {
                bail!("trace_live BPF identity cannot use zero placeholders");
            }
            let feature_bits = bpf_feature_bits(&manifest.bpf.feature_bits)?;
            let required = neutron_common::BPF_FEATURE_SYSCALL_TRACE
                | neutron_common::BPF_FEATURE_PROCESS_EXIT
                | neutron_common::BPF_FEATURE_PER_CPU_HEALTH;
            if feature_bits & required != required {
                bail!("trace_live BPF identity omits a mandatory capture capability");
            }
            if manifest.collection
                != (RunCollection {
                    target_count: 0,
                    minimal: false,
                    full_snapshot_retained: false,
                    repeat: 1,
                })
            {
                bail!("trace_live has incompatible collection metadata");
            }
            let scope = manifest
                .capture_scope
                .as_ref()
                .context("trace_live requires capture_scope")?;
            crate::health::CaptureScope::from_json_value(&serde_json::to_value(scope)?)
                .map_err(anyhow::Error::msg)?;
            if scope.producer.userspace_binary_sha256 != manifest.tool.binary_sha256
                || scope.producer.userspace_version != manifest.tool.version
                || scope.producer.userspace_git_commit != manifest.tool.git_commit
                || scope.producer.userspace_git_dirty != manifest.tool.git_dirty
                || manifest.bpf.object_sha256.as_deref()
                    != Some(scope.producer.bpf_object_sha256.as_str())
                || manifest.bpf.build_id.as_deref() != Some(scope.producer.bpf_build_id.as_str())
                || bpf_feature_bits(&manifest.bpf.feature_bits)? != scope.producer.bpf_feature_bits
            {
                bail!("trace_live manifest producer identity contradicts capture_scope");
            }
            let transport = manifest
                .transport_health
                .as_ref()
                .context("trace_live requires transport_health")?;
            validate_run_health("transport_health", transport)?;
            let mut expected_health = transport.clone();
            apply_tool_provenance(&manifest.tool, &mut expected_health);
            if manifest.health != expected_health {
                bail!("trace_live aggregate health contradicts transport/provenance health");
            }
            if scope.output.destination != "file"
                || scope.output.serialization != "ndjson"
                || scope.output.rotate_output_bytes.is_some()
            {
                bail!("trace_live run bundles require one non-rotating NDJSON capture file");
            }
        }
    }
    Ok(())
}

fn validate_run_health(name: &str, health: &RunHealth) -> Result<()> {
    validate_unique_labels(&format!("{name}.reasons"), &health.reasons)?;
    match health.status {
        RunHealthStatus::Complete if !health.reasons.is_empty() => {
            bail!("complete {name} must not contain degradation reasons")
        }
        RunHealthStatus::Complete => Ok(()),
        _ if health.reasons.is_empty() => {
            bail!("non-complete {name} must explain why evidence is not complete")
        }
        _ => Ok(()),
    }
}

fn evidence_field_equals(evidence: &str, field: &str, expected: &str) -> bool {
    evidence_field_value(evidence, field) == Some(expected)
}

fn evidence_field_value<'a>(evidence: &'a str, field: &str) -> Option<&'a str> {
    let prefix = format!("{field}=");
    evidence
        .split_ascii_whitespace()
        .find_map(|token| token.strip_prefix(&prefix))
}

fn require_evidence_field(
    source: &crate::surface::coverage::SourceEvidence,
    field: &str,
    expected: &str,
) -> Result<()> {
    if evidence_field_equals(&source.evidence, field, expected) {
        Ok(())
    } else {
        bail!(
            "{} evidence has {field} for a different endpoint",
            source.collector
        )
    }
}

fn validate_owner_evidence(
    row: &crate::surface::coverage::CoverageRow,
    owner: &crate::surface::coverage::CoverageOwner,
) -> Result<()> {
    require_evidence_exact(row, "boot_id", &format!("boot_id={}", owner.boot_id))?;
    let process_identity = format!("pid={} starttime={}", owner.pid, owner.starttime);
    require_evidence_exact(row, "proc_stat", &process_identity)?;
    require_evidence_exact(row, "proc_stat_revalidated", &process_identity)?;
    require_evidence_exact(
        row,
        "proc_status",
        &format!("pid={} uid={} gid={}", owner.pid, owner.uid, owner.gid),
    )?;
    require_evidence_exact(
        row,
        "proc_attr",
        &format!("pid={} selinux_domain={}", owner.pid, owner.selinux_domain),
    )?;
    require_evidence_exact(
        row,
        "proc_exe",
        &format!("pid={} executable={}", owner.pid, owner.executable),
    )
}

fn validate_unique_labels(name: &str, values: &[String]) -> Result<()> {
    let mut unique = BTreeSet::new();
    for value in values {
        validate_label(name, value)?;
        if !unique.insert(value) {
            bail!("{name} contains a duplicate value");
        }
    }
    Ok(())
}

fn validate_lower_hex(name: &str, value: &str, length: usize) -> Result<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{name} must contain {length} lowercase hexadecimal digits");
    }
    Ok(())
}

fn is_lower_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'),
        })
}

fn nonempty(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn read_regular_beneath(root: &Path, relative: &Path, maximum: u64) -> Result<Vec<u8>> {
    let mut file = crate::private_output::open_regular_beneath(root, relative, Some(maximum))?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        bail!(
            "run artifact exceeds {maximum} bytes: {}",
            relative.display()
        );
    }
    Ok(bytes)
}

fn sha256_beneath(root: &Path, relative: &Path, maximum: Option<u64>) -> Result<String> {
    let file = crate::private_output::open_regular_beneath(root, relative, maximum)?;
    sha256_reader(file)
}

fn safe_artifact_name(name: &str) -> Result<String> {
    let path = Path::new(name);
    if name.is_empty()
        || name.len() > MAX_ARTIFACT_NAME
        || name == "manifest.json"
        || name == "SHA256SUMS"
        || path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
        || name.chars().any(char::is_control)
    {
        bail!("unsafe run artifact name: {name}");
    }
    Ok(name.into())
}

fn validate_run_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("run_id must use 1-128 ASCII letters, digits, dot, underscore, or dash");
    }
    Ok(())
}

fn validate_label(name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        bail!("{name} must be a bounded printable string");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::surface::coverage::{
        CoverageAttribution, CoverageCollection, CoverageDevice, CoverageDocument, CoverageHealth,
        CoverageOwner, CoverageRepeat, CoverageRow, CoverageSummary, SourceEvidence,
    };
    use std::path::PathBuf;
    use std::sync::OnceLock;
    use std::time::{SystemTime, UNIX_EPOCH};

    const LIVE_BOOT_ID: &str = "5ec7279f-c488-45f1-a625-7737c250b110";

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            Self(std::env::temp_dir().join(format!(
                "neutron-run-manifest-{}-{nonce}",
                std::process::id()
            )))
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn manifest(artifacts: Vec<ArtifactIdentity>) -> RunManifest {
        RunManifest::static_surface(StaticSurfaceManifest {
            run_id: "static-test".into(),
            started_at: "2026-07-17T06:39:01Z".into(),
            completed_at: "2026-07-17T06:39:02Z".into(),
            device: DeviceIdentity::default(),
            research_model: ResearchModel {
                observer_privilege: "root/test".into(),
                attacker_capability: "ordinary_installed_app".into(),
            },
            collection: RunCollection {
                target_count: 1,
                minimal: true,
                full_snapshot_retained: false,
                repeat: 2,
            },
            health: RunHealth {
                status: RunHealthStatus::Complete,
                reasons: Vec::new(),
            },
            artifacts,
        })
        .unwrap()
    }

    fn source(collector: &str, evidence: String) -> SourceEvidence {
        SourceEvidence {
            measured_by: "neutron".into(),
            collector: collector.into(),
            source: format!("test:{collector}"),
            evidence_sha256: format!("{:x}", Sha256::digest(evidence.as_bytes())),
            evidence,
            source_sha256: Some("0".repeat(64)),
        }
    }

    fn unresolved_coverage(repeat: usize) -> CoverageDocument {
        let provenance_reasons: Vec<_> = ToolIdentity::current()
            .unwrap()
            .provenance_issues()
            .into_iter()
            .map(|issue| format!("tool provenance unknown: {issue}"))
            .collect();
        CoverageDocument {
            schema: "neutron.surface-coverage/v1".into(),
            neutron_version: env!("CARGO_PKG_VERSION").into(),
            collected_at: "2026-07-17T06:39:02Z".into(),
            device: CoverageDevice::default(),
            collection: CoverageCollection {
                target_count: 1,
                minimal: true,
                full_snapshot_retained: false,
            },
            repeat: CoverageRepeat {
                count: repeat,
                semantic_drift: Vec::new(),
            },
            health: CoverageHealth {
                status: if provenance_reasons.is_empty() {
                    "complete".into()
                } else {
                    "unknown".into()
                },
                warnings: provenance_reasons,
            },
            summary: CoverageSummary {
                exact: 0,
                unresolved: 1,
                ambiguous: 0,
            },
            rows: vec![CoverageRow {
                endpoint: "vendor.example.IExample/default".into(),
                declared: false,
                live: false,
                transport: "unknown".into(),
                owner: None,
                attribution: CoverageAttribution {
                    confidence: "unresolved".into(),
                    sources: Vec::new(),
                },
            }],
        }
    }

    fn exact_coverage() -> CoverageDocument {
        let boot_id = "8b2d6c98-20a1-4e7e-944f-53f61b52d5ef";
        let mut document = unresolved_coverage(1);
        document.device.boot_id = boot_id.into();
        document.summary = CoverageSummary {
            exact: 1,
            unresolved: 0,
            ambiguous: 0,
        };
        document.rows[0] = CoverageRow {
            endpoint: "vendor.example.IExample/default".into(),
            declared: false,
            live: true,
            transport: "binder".into(),
            owner: Some(CoverageOwner {
                pid: 123,
                uid: 1000,
                gid: 1000,
                starttime: 456,
                boot_id: boot_id.into(),
                selinux_domain: "u:r:hal_example:s0".into(),
                executable: "/vendor/bin/hw/example".into(),
            }),
            attribution: CoverageAttribution {
                confidence: "exact".into(),
                sources: [
                    "service_list",
                    "dumpsys_pid",
                    "dumpsys_pid_revalidated",
                    "boot_id",
                    "boot_id_revalidated",
                    "proc_stat",
                    "proc_stat_revalidated",
                    "proc_stat_endpoint_revalidated",
                    "proc_status",
                    "proc_attr",
                    "proc_exe",
                ]
                .into_iter()
                .map(|collector| {
                    let evidence = match collector {
                        "service_list" => {
                            "name=vendor.example.IExample/default descriptor=vendor.example.IExample"
                                .into()
                        }
                        "dumpsys_pid" => {
                            "endpoint=vendor.example.IExample/default pid=123".into()
                        }
                        "dumpsys_pid_revalidated" => {
                            "endpoint=vendor.example.IExample/default pid=123".into()
                        }
                        "boot_id" => format!("boot_id={boot_id}"),
                        "boot_id_revalidated" => format!("boot_id={boot_id}"),
                        "proc_stat" | "proc_stat_revalidated" => {
                            "pid=123 starttime=456".into()
                        }
                        "proc_stat_endpoint_revalidated" => {
                            "endpoint=vendor.example.IExample/default pid=123 starttime=456".into()
                        }
                        "proc_status" => "pid=123 uid=1000 gid=1000".into(),
                        "proc_attr" => "pid=123 selinux_domain=u:r:hal_example:s0".into(),
                        "proc_exe" => {
                            "pid=123 executable=/vendor/bin/hw/example".into()
                        }
                        _ => unreachable!(),
                    };
                    source(collector, evidence)
                })
                .collect(),
            },
        };
        document
    }

    fn live_capture_scope() -> crate::health::CaptureScope {
        let mut scope = crate::health::CaptureScope::unfiltered_raw_ndjson();
        let tool = live_tool_identity();
        scope.output.destination = "file".into();
        scope.producer.userspace_binary_sha256 = tool.binary_sha256.clone();
        scope.producer.userspace_version = tool.version.clone();
        scope.producer.userspace_git_commit = tool.git_commit.clone();
        scope.producer.userspace_git_dirty = tool.git_dirty;
        scope.producer.bpf_build_id = tool.git_commit.clone();
        scope.recompute_claim_scope()
    }

    fn live_tool_identity() -> &'static ToolIdentity {
        static TOOL: OnceLock<ToolIdentity> = OnceLock::new();
        TOOL.get_or_init(|| ToolIdentity::current().unwrap())
    }

    fn live_bpf_identity() -> BpfIdentity {
        BpfIdentity {
            used: true,
            object_sha256: Some("1".repeat(64)),
            abi_major: crate::bpf_abi::BPF_ABI_MAJOR,
            abi_minor: crate::bpf_abi::BPF_ABI_MINOR,
            event_size: core::mem::size_of::<neutron_common::SyscallEvent>() as u32,
            feature_bits: vec![
                "syscall_trace".into(),
                "per_cpu_health".into(),
                "process_exit".into(),
            ],
            build_id: Some(live_tool_identity().git_commit.clone()),
        }
    }

    fn live_health(status: RunHealthStatus) -> serde_json::Value {
        let mut health = crate::health::CaptureHealth::default();
        let mut user = crate::health::UserspaceHealth::default();
        match status {
            RunHealthStatus::Complete => {}
            RunHealthStatus::Incomplete => user.output_cap_hit = true,
            RunHealthStatus::Unknown => health = crate::health::CaptureHealth::unknown("test:EIO"),
            RunHealthStatus::Degraded => {
                health.slots[neutron_common::COUNTER_PATH_TRUNCATED as usize] = 1;
            }
        }
        let metadata = crate::health::CaptureMetadata {
            capture_scope: Some(live_capture_scope()),
            attached_programs: vec![
                "trace_sys_enter".into(),
                "trace_sys_exit".into(),
                "trace_sched_process_exit".into(),
            ],
            boot_id: Some(LIVE_BOOT_ID.into()),
            fingerprint: Some("vendor/device/build".into()),
            max_depth: 4,
            max_processes: 64,
            bpf_object_sha256: Some("1".repeat(64)),
            bpf_build_id: Some(live_tool_identity().git_commit.clone()),
            bpf_abi_major: Some(crate::bpf_abi::BPF_ABI_MAJOR),
            bpf_abi_minor: Some(crate::bpf_abi::BPF_ABI_MINOR),
            bpf_event_size: Some(core::mem::size_of::<neutron_common::SyscallEvent>() as u32),
            bpf_feature_bits: Some(
                neutron_common::BPF_FEATURE_SYSCALL_TRACE
                    | neutron_common::BPF_FEATURE_PER_CPU_HEALTH
                    | neutron_common::BPF_FEATURE_PROCESS_EXIT,
            ),
            ring_size_bytes: Some(1 << 20),
            ..crate::health::CaptureMetadata::default()
        };
        serde_json::from_str(&crate::health::format_capture_health_json_with_metadata(
            &health, &user, 0, &metadata,
        ))
        .unwrap()
    }

    fn live_device_identity() -> DeviceIdentity {
        DeviceIdentity {
            serial_hash: Some(format!("sha256:{}", "a".repeat(64))),
            model: Some("Pixel 8 Pro".into()),
            product: Some("husky".into()),
            build_id: Some("CP2A.260705.006".into()),
            fingerprint: Some("vendor/device/build".into()),
            api: Some(37),
            spl: Some("2026-07-05".into()),
            kernel: Some("6.1.0-android17".into()),
            boot_id: Some(LIVE_BOOT_ID.into()),
        }
    }

    fn live_manifest(artifacts: Vec<ArtifactIdentity>, status: RunHealthStatus) -> RunManifest {
        live_manifest_with_health(artifacts, live_health(status))
    }

    fn live_manifest_with_health(
        artifacts: Vec<ArtifactIdentity>,
        capture_health: Value,
    ) -> RunManifest {
        RunManifest::live_capture(LiveCaptureManifest {
            run_id: "trace-test".into(),
            started_at: "2026-07-17T06:39:01Z".into(),
            completed_at: "2026-07-17T06:39:02Z".into(),
            device: live_device_identity(),
            research_model: ResearchModel {
                observer_privilege: "root".into(),
                attacker_capability: "not_tested".into(),
            },
            bpf: live_bpf_identity(),
            capture_health,
            artifacts,
        })
        .unwrap()
    }

    fn live_marker(
        phase: &str,
        scenario_id: &str,
        trace_id: &str,
        generation: u64,
        ts_ns: u64,
    ) -> Value {
        serde_json::json!({
            "type": "marker",
            "ts_ns": ts_ns,
            "name": scenario_id,
            "phase": phase,
            "scenario_id": scenario_id,
            "trace_id": trace_id,
            "generation": generation,
            "root_package": "com.example.app",
            "root_uid": 10123,
            "root_pid": 42
        })
    }

    fn causal_syscall(scenario_id: &str, trace_id: &str, ts_ns: u64) -> Value {
        serde_json::json!({
            "type": "syscall",
            "pid": 42,
            "nr": 0,
            "ts_ns": ts_ns,
            "scenario_id": scenario_id,
            "trace_id": trace_id,
            "root_package": "com.example.app",
            "root_uid": 10123
        })
    }

    fn bounded_capture_bytes(health: &Value) -> Vec<u8> {
        let trace_id = "0000000000001234";
        let records = [
            live_marker("start", "scenario", trace_id, 1, 10),
            causal_syscall("scenario", trace_id, 15),
            live_marker("end", "scenario", trace_id, 1, 20),
            health.clone(),
        ];
        records
            .into_iter()
            .map(|record| serde_json::to_string(&record).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()
    }

    fn verify_live_records(records: Vec<Value>) -> Result<()> {
        verify_live_records_with_health(records, live_health(RunHealthStatus::Complete))
    }

    fn verify_live_records_with_health(records: Vec<Value>, health: Value) -> Result<()> {
        let directory = TestDir::new();
        create_private_run_directory(&directory.0)?;
        let mut lines = records
            .into_iter()
            .map(|record| serde_json::to_string(&record))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        lines.push(serde_json::to_string(&health)?);
        let mut bytes = lines.join("\n").into_bytes();
        bytes.push(b'\n');
        write_artifact(&directory.0, "capture.ndjson", &bytes)?;
        verify_capture_stream(&directory.0, &health)
    }

    #[test]
    fn static_surface_manifest_records_no_runtime_side_effects() {
        let manifest = manifest(Vec::new());

        assert_eq!(manifest.schema, RUN_MANIFEST_SCHEMA);
        assert_eq!(manifest.run_kind, RunKind::SurfaceStatic);
        assert!(!manifest.bpf.used && !manifest.bpf_loaded);
        assert!(!manifest.stimulus_executed && !manifest.configuration_changed);
        assert_eq!(manifest.tool.binary_sha256.len(), 64);
    }

    #[test]
    fn live_capture_manifest_binds_scope_transport_and_bpf_identity() {
        let manifest = live_manifest(Vec::new(), RunHealthStatus::Complete);

        assert_eq!(manifest.run_kind, RunKind::TraceLive);
        assert!(manifest.bpf.used && manifest.bpf_loaded);
        assert_eq!(
            manifest.bpf.object_sha256.as_deref(),
            Some("1".repeat(64).as_str())
        );
        assert_eq!(
            manifest.bpf.build_id.as_deref(),
            Some(manifest.tool.git_commit.as_str())
        );
        assert_eq!(
            manifest
                .transport_health
                .as_ref()
                .map(|health| health.status),
            Some(RunHealthStatus::Complete)
        );
        assert_eq!(
            manifest
                .capture_scope
                .as_ref()
                .map(|scope| scope.output.destination.as_str()),
            Some("file")
        );
        assert_eq!(manifest.research_model.attacker_capability, "not_tested");
        assert!(!manifest.stimulus_executed && !manifest.configuration_changed);
    }

    #[test]
    fn live_manifest_rejects_tampered_duplicate_producer_identities() {
        let baseline = live_manifest(Vec::new(), RunHealthStatus::Complete);
        validate_manifest_fields(&baseline).unwrap();
        let mut variants = Vec::new();

        let mut manifest = baseline.clone();
        manifest.tool.binary_sha256 = "9".repeat(64);
        variants.push(("userspace binary", manifest));
        let mut manifest = baseline.clone();
        manifest.tool.version = "1.5.0-forged".into();
        variants.push(("userspace version", manifest));
        let mut manifest = baseline.clone();
        manifest.tool.git_commit = "8".repeat(40);
        variants.push(("userspace source commit", manifest));
        let mut manifest = baseline.clone();
        manifest.tool.git_dirty = !manifest.tool.git_dirty;
        variants.push(("userspace dirty state", manifest));
        let mut manifest = baseline.clone();
        manifest.bpf.object_sha256 = Some("7".repeat(64));
        variants.push(("BPF object", manifest));
        let mut manifest = baseline.clone();
        manifest.bpf.build_id = Some("6".repeat(40));
        variants.push(("BPF build", manifest));
        let mut manifest = baseline.clone();
        manifest.bpf.feature_bits.insert(1, "binder_trace".into());
        variants.push(("BPF features", manifest));

        for (identity, manifest) in variants {
            let error = validate_manifest_fields(&manifest).unwrap_err();
            assert!(
                error.to_string().contains("producer identity"),
                "tampered {identity} failed for the wrong reason: {error:#}"
            );
        }

        let mut broken_source_chain = baseline;
        broken_source_chain.bpf.build_id = Some("5".repeat(40));
        broken_source_chain
            .capture_scope
            .as_mut()
            .unwrap()
            .producer
            .bpf_build_id = "5".repeat(40);
        let error = validate_manifest_fields(&broken_source_chain).unwrap_err();
        assert!(error.to_string().contains("source commit"));
    }

    #[test]
    fn live_capture_bundle_verifies_transport_states_and_detects_tampering() {
        for status in [
            RunHealthStatus::Complete,
            RunHealthStatus::Incomplete,
            RunHealthStatus::Unknown,
        ] {
            let directory = TestDir::new();
            create_private_run_directory(&directory.0).unwrap();
            let health = live_health(status);
            let mut capture_bytes = bounded_capture_bytes(&health);
            capture_bytes.push(b'\n');
            let capture = write_artifact(&directory.0, "capture.ndjson", &capture_bytes).unwrap();
            let mut line = serde_json::to_vec(&health).unwrap();
            line.push(b'\n');
            let sidecar = write_artifact(&directory.0, "capture.health.json", &line).unwrap();
            let manifest = live_manifest(vec![capture, sidecar], status);
            finalize_bundle(&directory.0, &manifest).unwrap();
            verify_static_manifest(&directory.0, &manifest).unwrap();
            crate::evidence::verify(&directory.0).unwrap();

            crate::private_output::write(
                &directory.0.join("capture.ndjson"),
                b"{\"type\":\"tampered\"}\n",
                true,
            )
            .unwrap();
            assert!(verify_static_manifest(&directory.0, &manifest).is_err());
        }
    }

    #[test]
    fn live_capture_bundle_rejects_unknown_and_invalid_known_records() {
        for invalid in [
            r#"{"type":"future_event"}"#,
            r#"{"type":"syscall"}"#,
            r#"{"type":"syscall","pid":1,"name":""}"#,
            r#"{"type":"binder_call","caller_pid":1,"callee_pid":2}"#,
            r#"{"type":"marker","ts_ns":1,"name":"scenario","phase":"start"}"#,
        ] {
            let directory = TestDir::new();
            create_private_run_directory(&directory.0).unwrap();
            let health = live_health(RunHealthStatus::Complete);
            let line = serde_json::to_string(&health).unwrap();
            let capture_bytes = format!("{invalid}\n{line}\n");
            let capture =
                write_artifact(&directory.0, "capture.ndjson", capture_bytes.as_bytes()).unwrap();
            let sidecar = write_artifact(
                &directory.0,
                "capture.health.json",
                format!("{line}\n").as_bytes(),
            )
            .unwrap();
            let manifest = live_manifest(vec![capture, sidecar], RunHealthStatus::Complete);

            let error = finalize_bundle(&directory.0, &manifest).unwrap_err();
            assert!(error.to_string().contains("semantically valid"));
        }
    }

    #[test]
    fn incomplete_live_capture_accepts_structural_zero_binder_identity() {
        let trace_id = "0000000000001234";
        let mut health = live_health(RunHealthStatus::Incomplete);
        health["binder_invalid_callers"] = 1.into();
        health["incomplete_reasons"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!(
                "Binder tracker rejected 1 caller event(s) with unusable identity"
            ));
        let records = [
            live_marker("start", "scenario", trace_id, 1, 10),
            serde_json::json!({
                "type": "binder",
                "ts_ns": 15,
                "pid": 42,
                "to_proc": 0,
                "debug_id": 0,
                "scenario_id": "scenario",
                "trace_id": trace_id,
                "root_package": "com.example.app",
                "root_uid": 10123,
                "root_pid": 42
            }),
            live_marker("end", "scenario", trace_id, 1, 20),
            health.clone(),
        ];
        let mut capture_bytes = records
            .into_iter()
            .map(|record| serde_json::to_string(&record).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes();
        capture_bytes.push(b'\n');

        let directory = TestDir::new();
        create_private_run_directory(&directory.0).unwrap();
        let capture = write_artifact(&directory.0, "capture.ndjson", &capture_bytes).unwrap();
        let sidecar = write_artifact(
            &directory.0,
            "capture.health.json",
            format!("{}\n", serde_json::to_string(&health).unwrap()).as_bytes(),
        )
        .unwrap();
        let manifest = live_manifest_with_health(vec![capture, sidecar], health);

        finalize_bundle(&directory.0, &manifest).unwrap();
    }

    #[test]
    fn complete_live_capture_rejects_structural_zero_binder_identity() {
        let trace_id = "0000000000001234";
        let records = vec![
            live_marker("start", "scenario", trace_id, 1, 10),
            serde_json::json!({
                "type": "binder",
                "ts_ns": 15,
                "pid": 42,
                "to_proc": 0,
                "debug_id": 0,
                "scenario_id": "scenario",
                "trace_id": trace_id,
                "root_package": "com.example.app",
                "root_uid": 10123,
                "root_pid": 42
            }),
            live_marker("end", "scenario", trace_id, 1, 20),
        ];

        let error = verify_live_records(records).unwrap_err();
        assert!(error.to_string().contains("Binder identity"), "{error:#}");
    }

    #[test]
    fn unscoped_zero_binder_outside_markers_does_not_taint_bounded_health() {
        let trace_id = "0000000000001234";
        verify_live_records(vec![
            serde_json::json!({
                "type": "binder",
                "ts_ns": 5,
                "pid": 1545,
                "to_proc": 0,
                "debug_id": 0
            }),
            live_marker("start", "scenario", trace_id, 1, 10),
            live_marker("end", "scenario", trace_id, 1, 20),
        ])
        .unwrap();
    }

    #[test]
    fn binder_received_zero_identity_requires_incomplete_health() {
        let trace_id = "0000000000001234";
        let event = serde_json::json!({
            "type": "binder_received",
            "ts_ns": 15,
            "pid": 536,
            "debug_id": 0,
            "scenario_id": "scenario",
            "trace_id": trace_id,
            "root_package": "com.example.app",
            "root_uid": 10123,
            "root_pid": 42
        });
        let records = || {
            vec![
                live_marker("start", "scenario", trace_id, 1, 10),
                event.clone(),
                live_marker("end", "scenario", trace_id, 1, 20),
            ]
        };

        let error = verify_live_records(records()).unwrap_err();
        assert!(error.to_string().contains("Binder identity"), "{error:#}");

        let mut health = live_health(RunHealthStatus::Incomplete);
        health["binder_unmatched_receives"] = 1.into();
        health["incomplete_reasons"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!(
                "Binder tracker observed 1 receive event(s) without a matching caller"
            ));
        verify_live_records_with_health(records(), health).unwrap();
    }

    #[test]
    fn unrelated_incomplete_reason_cannot_mask_missing_binder_identity_counters() {
        let trace_id = "0000000000001234";
        for event in [
            serde_json::json!({
                "type": "binder",
                "ts_ns": 15,
                "pid": 42,
                "to_proc": 0,
                "debug_id": 0,
                "scenario_id": "scenario",
                "trace_id": trace_id
            }),
            serde_json::json!({
                "type": "binder_received",
                "ts_ns": 15,
                "pid": 536,
                "debug_id": 0,
                "scenario_id": "scenario",
                "trace_id": trace_id
            }),
        ] {
            let records = vec![
                live_marker("start", "scenario", trace_id, 1, 10),
                event,
                live_marker("end", "scenario", trace_id, 1, 20),
            ];
            let error =
                verify_live_records_with_health(records, live_health(RunHealthStatus::Incomplete))
                    .unwrap_err();
            assert!(error.to_string().contains("health counter"), "{error:#}");
        }
    }

    #[test]
    fn disabled_binder_tracker_is_explicit_zero_identity_accounting() {
        let trace_id = "0000000000001234";
        let mut health = live_health(RunHealthStatus::Incomplete);
        health["binder_tracker_enabled"] = false.into();
        health["incomplete_reasons"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!(
                "Binder transaction correlation was disabled for this capture"
            ));
        verify_live_records_with_health(
            vec![
                live_marker("start", "scenario", trace_id, 1, 10),
                serde_json::json!({
                    "type": "binder",
                    "ts_ns": 15,
                    "pid": 42,
                    "to_proc": 0,
                    "debug_id": 0,
                    "scenario_id": "scenario",
                    "trace_id": trace_id
                }),
                live_marker("end", "scenario", trace_id, 1, 20),
            ],
            health,
        )
        .unwrap();
    }

    #[test]
    fn synthetic_binder_call_requires_nonzero_debug_identity() {
        let object = serde_json::json!({
            "type": "binder_call",
            "caller_pid": 42,
            "callee_pid": 536,
            "debug_id": 0
        });

        assert!(!valid_live_capture_record(
            "binder_call",
            object.as_object().unwrap()
        ));
    }

    #[test]
    fn live_capture_rejects_missing_or_invalid_binder_identity_fields() {
        let valid = serde_json::json!({
            "type": "binder",
            "pid": 42,
            "to_proc": 0,
            "debug_id": 0
        });
        for invalid in [
            serde_json::json!({"type": "binder", "pid": 42, "to_proc": 0}),
            serde_json::json!({"type": "binder", "pid": 42, "debug_id": 0}),
            serde_json::json!({"type": "binder", "pid": 42, "to_proc": "0", "debug_id": 0}),
            serde_json::json!({"type": "binder", "pid": 42, "to_proc": 0, "debug_id": "0"}),
        ] {
            let object = invalid.as_object().unwrap();
            assert!(
                !valid_live_capture_record("binder", object),
                "accepted {invalid}"
            );
        }
        assert!(valid_live_capture_record(
            "binder",
            valid.as_object().unwrap()
        ));
    }

    #[test]
    fn live_capture_requires_one_or_more_exactly_paired_scenarios() {
        let trace_id = "0000000000001234";
        for records in [
            Vec::new(),
            vec![live_marker("start", "scenario", trace_id, 1, 10)],
            vec![live_marker("end", "scenario", trace_id, 1, 20)],
            vec![
                live_marker("start", "scenario", "0000000000000000", 1, 10),
                live_marker("end", "scenario", "0000000000000000", 1, 20),
            ],
            vec![
                live_marker("start", "scenario", trace_id, 0, 10),
                live_marker("end", "scenario", trace_id, 0, 20),
            ],
            vec![
                live_marker("start", "first", trace_id, 1, 10),
                live_marker("start", "second", "0000000000005678", 2, 11),
                live_marker("end", "second", "0000000000005678", 2, 12),
                live_marker("end", "first", trace_id, 1, 13),
            ],
            vec![
                live_marker("start", "scenario", trace_id, 1, 10),
                live_marker("end", "scenario", trace_id, 1, 20),
                live_marker("start", "scenario", "0000000000005678", 2, 30),
                live_marker("end", "scenario", "0000000000005678", 2, 40),
            ],
        ] {
            assert!(verify_live_records(records).is_err());
        }
    }

    #[test]
    fn live_capture_rejects_mismatched_scenario_boundaries() {
        let trace_id = "0000000000001234";
        let start = live_marker("start", "scenario", trace_id, 1, 10);
        for end in [
            live_marker("end", "other", trace_id, 1, 20),
            live_marker("end", "scenario", "0000000000005678", 1, 20),
            live_marker("end", "scenario", trace_id, 2, 20),
            {
                let mut marker = live_marker("end", "scenario", trace_id, 1, 20);
                marker["root_package"] = Value::String("com.example.other".into());
                marker
            },
            {
                let mut marker = live_marker("end", "scenario", trace_id, 1, 20);
                marker["root_uid"] = Value::from(10124);
                marker
            },
            {
                let mut marker = live_marker("end", "scenario", trace_id, 1, 20);
                marker["root_pid"] = Value::from(43);
                marker
            },
        ] {
            assert!(verify_live_records(vec![start.clone(), end]).is_err());
        }
    }

    #[test]
    fn live_capture_rejects_non_monotonic_scenario_timestamps() {
        let trace_id = "0000000000001234";
        assert!(verify_live_records(vec![
            live_marker("start", "scenario", trace_id, 1, 20),
            live_marker("end", "scenario", trace_id, 1, 10),
        ])
        .is_err());
        assert!(verify_live_records(vec![
            live_marker("start", "first", trace_id, 1, 10),
            live_marker("end", "first", trace_id, 1, 20),
            live_marker("start", "second", "0000000000005678", 2, 19),
            live_marker("end", "second", "0000000000005678", 2, 30),
        ])
        .is_err());
    }

    #[test]
    fn live_capture_binds_causal_records_to_the_active_scenario_interval() {
        let trace_id = "0000000000001234";
        let start = live_marker("start", "scenario", trace_id, 1, 10);
        let end = live_marker("end", "scenario", trace_id, 1, 20);
        let valid = causal_syscall("scenario", trace_id, 15);
        verify_live_records(vec![
            serde_json::json!({"type":"syscall", "pid":7, "nr":1, "ts_ns":1}),
            start.clone(),
            valid.clone(),
            end.clone(),
            serde_json::json!({"type":"syscall", "pid":7, "nr":1, "ts_ns":30}),
        ])
        .unwrap();

        let mut wrong_root = valid.clone();
        wrong_root["root_uid"] = Value::from(10124);
        let mut before_start_timestamp = valid.clone();
        before_start_timestamp["ts_ns"] = Value::from(9);
        let mut after_end_timestamp = valid.clone();
        after_end_timestamp["ts_ns"] = Value::from(21);
        for records in [
            vec![valid.clone(), start.clone(), end.clone()],
            vec![start.clone(), end.clone(), valid.clone()],
            vec![
                start.clone(),
                causal_syscall("other", trace_id, 15),
                end.clone(),
            ],
            vec![
                start.clone(),
                causal_syscall("scenario", "0000000000005678", 15),
                end.clone(),
            ],
            vec![start.clone(), wrong_root, end.clone()],
            vec![start.clone(), before_start_timestamp, end.clone()],
            vec![start.clone(), after_end_timestamp, end.clone()],
        ] {
            assert!(verify_live_records(records).is_err());
        }
    }

    #[test]
    fn interrupted_live_capture_preserves_a_verifiable_open_scenario() {
        let trace_id = "0000000000001234";
        let start = live_marker("start", "scenario", trace_id, 1, 10);
        let event = causal_syscall("scenario", trace_id, 15);
        let mut health = live_health(RunHealthStatus::Incomplete);
        health["status"] = Value::String("incomplete".into());
        health["degraded"] = Value::Bool(true);
        health["incomplete_reasons"] =
            serde_json::json!(["scenario 'scenario' ended without a closing marker"]);

        verify_live_records_with_health(vec![start.clone(), event], health).unwrap();

        let mut forged_complete = live_health(RunHealthStatus::Complete);
        forged_complete["incomplete_reasons"] =
            serde_json::json!(["scenario 'scenario' ended without a closing marker"]);
        assert!(verify_live_records_with_health(vec![start.clone()], forged_complete).is_err());

        let mut missing_reason = live_health(RunHealthStatus::Incomplete);
        missing_reason["status"] = Value::String("incomplete".into());
        missing_reason["degraded"] = Value::Bool(true);
        assert!(verify_live_records_with_health(vec![start], missing_reason).is_err());
    }

    #[test]
    fn live_capture_bundle_rejects_oversized_sparse_artifact_before_hashing() {
        let directory = TestDir::new();
        create_private_run_directory(&directory.0).unwrap();
        crate::private_output::write(&directory.0.join("capture.ndjson"), b"", false).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(directory.0.join("capture.ndjson"))
            .unwrap()
            .set_len(MAX_LIVE_CAPTURE_BYTES + 1)
            .unwrap();
        let health = live_health(RunHealthStatus::Complete);
        let line = serde_json::to_string(&health).unwrap();
        let sidecar = write_artifact(
            &directory.0,
            "capture.health.json",
            format!("{line}\n").as_bytes(),
        )
        .unwrap();
        let capture = ArtifactIdentity {
            path: "capture.ndjson".into(),
            sha256: "1".repeat(64),
        };
        let manifest = live_manifest(vec![capture, sidecar], RunHealthStatus::Complete);

        let error = finalize_bundle(&directory.0, &manifest).unwrap_err();
        assert!(format!("{error:#}").contains("exceeds"));
    }

    #[test]
    fn prefinal_live_directory_cannot_verify() {
        let directory = TestDir::new();
        create_private_run_directory(&directory.0).unwrap();
        write_artifact(&directory.0, "capture.ndjson", b"{}\n").unwrap();

        assert!(crate::private_output::open_regular_beneath(
            &directory.0,
            Path::new("manifest.json"),
            None,
        )
        .is_err());
        assert!(crate::private_output::open_regular_beneath(
            &directory.0,
            Path::new("SHA256SUMS"),
            None,
        )
        .is_err());
    }

    #[test]
    fn shipped_manifest_schema_dispatches_static_and_live_contracts() {
        let schema: Value = serde_json::from_str(include_str!(
            "../schemas/neutron.run-manifest-v1.schema.json"
        ))
        .unwrap();
        assert_eq!(
            schema["properties"]["run_kind"]["enum"],
            serde_json::json!(["surface_static", "trace_live"])
        );
        assert_eq!(schema["oneOf"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            schema["$defs"]["traceLiveRun"]["required"],
            serde_json::json!(["transport_health", "capture_scope"])
        );
        assert_eq!(
            schema["$defs"]["traceLiveRun"]["properties"]["bpf_loaded"]["const"],
            true
        );
        assert_eq!(
            schema["$defs"]["traceLiveRun"]["properties"]["device"]["properties"]["boot_id"]
                ["pattern"],
            "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        );
        let live_device_fields = schema["$defs"]["traceLiveRun"]["properties"]["device"]
            ["required"]
            .as_array()
            .unwrap();
        for field in [
            "serial_hash",
            "model",
            "product",
            "build_id",
            "fingerprint",
            "api",
            "spl",
            "kernel",
            "boot_id",
        ] {
            assert!(live_device_fields.iter().any(|value| value == field));
        }
        assert!(schema["properties"]["capture_scope"]["$ref"]
            .as_str()
            .is_some_and(|reference| reference.ends_with("#/$defs/captureScope")));
    }

    #[test]
    fn private_bundle_is_content_addressed() {
        let directory = TestDir::new();
        create_private_run_directory(&directory.0).unwrap();
        let targets =
            write_targets(&directory.0, &["vendor.example.IExample/default".into()]).unwrap();
        let mut bytes = serde_json::to_vec_pretty(&unresolved_coverage(2)).unwrap();
        bytes.push(b'\n');
        let coverage = write_artifact(&directory.0, "surface.coverage.json", &bytes).unwrap();
        finalize_bundle(&directory.0, &manifest(vec![targets, coverage])).unwrap();

        let sums = fs::read_to_string(directory.0.join("SHA256SUMS")).unwrap();
        assert!(sums.contains("  manifest.json\n"));
        assert!(sums.contains("  surface.coverage.json\n"));
        let mode = fs::metadata(&directory.0).unwrap().mode();
        assert_eq!(mode & 0o077, 0);
    }

    #[test]
    fn artifact_writer_rejects_path_traversal() {
        let directory = TestDir::new();
        create_private_run_directory(&directory.0).unwrap();

        let error = write_artifact(&directory.0, "../outside", b"bad").unwrap_err();
        assert!(error.to_string().contains("unsafe run artifact name"));
    }

    #[test]
    fn exact_coverage_requires_a_complete_chain_of_proof() {
        let document = exact_coverage();
        validate_coverage_provenance(&document).unwrap();

        let mut missing_pid_proof = document.clone();
        missing_pid_proof.rows[0]
            .attribution
            .sources
            .retain(|source| source.collector != "dumpsys_pid");
        let error = validate_coverage_provenance(&missing_pid_proof).unwrap_err();
        assert!(error.to_string().contains("dumpsys_pid"));
    }

    #[test]
    fn exact_binder_coverage_requires_final_revalidation_evidence() {
        for collector in [
            "dumpsys_pid_revalidated",
            "proc_stat_endpoint_revalidated",
            "boot_id_revalidated",
        ] {
            let mut document = exact_coverage();
            document.rows[0]
                .attribution
                .sources
                .retain(|source| source.collector != collector);

            let error = validate_coverage_provenance(&document).unwrap_err();
            assert!(
                error.to_string().contains(collector),
                "unexpected error for missing {collector}: {error:#}"
            );
        }
    }

    #[test]
    fn exact_hwbinder_coverage_requires_final_lshal_revalidation() {
        let mut document = exact_coverage();
        {
            let row = &mut document.rows[0];
            row.transport = "hwbinder".into();
            row.attribution.sources.retain(|source| {
                !matches!(
                    source.collector.as_str(),
                    "service_list" | "dumpsys_pid" | "dumpsys_pid_revalidated"
                )
            });
            row.attribution.sources.extend([
                source(
                    "lshal",
                    "name=vendor.example.IExample/default pid=123".into(),
                ),
                source(
                    "lshal_revalidated",
                    "endpoint=vendor.example.IExample/default pids=123".into(),
                ),
            ]);
        }
        validate_coverage_provenance(&document).unwrap();

        document.rows[0]
            .attribution
            .sources
            .retain(|source| source.collector != "lshal_revalidated");
        let error = validate_coverage_provenance(&document).unwrap_err();
        assert!(error.to_string().contains("lshal_revalidated"));
    }

    #[test]
    fn exact_coverage_rejects_tampered_final_revalidation_fields() {
        for (collector, evidence) in [
            (
                "dumpsys_pid_revalidated",
                "endpoint=vendor.other.IExample/default pid=123",
            ),
            (
                "dumpsys_pid_revalidated",
                "endpoint=vendor.example.IExample/default pid=999",
            ),
            (
                "proc_stat_endpoint_revalidated",
                "endpoint=vendor.other.IExample/default pid=123 starttime=456",
            ),
            (
                "proc_stat_endpoint_revalidated",
                "endpoint=vendor.example.IExample/default pid=999 starttime=456",
            ),
            (
                "proc_stat_endpoint_revalidated",
                "endpoint=vendor.example.IExample/default pid=123 starttime=999",
            ),
            (
                "boot_id_revalidated",
                "boot_id=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            ),
        ] {
            let mut document = exact_coverage();
            let proof = document.rows[0]
                .attribution
                .sources
                .iter_mut()
                .find(|source| source.collector == collector)
                .unwrap();
            proof.evidence = evidence.into();
            proof.evidence_sha256 = format!("{:x}", Sha256::digest(evidence.as_bytes()));

            let error = validate_coverage_provenance(&document).unwrap_err();
            assert!(
                error.to_string().contains(collector),
                "unexpected error for tampered {collector}: {error:#}"
            );
        }
    }

    #[test]
    fn trace_live_requires_matching_lowercase_uuid_boot_identity() {
        let valid_health = live_health(RunHealthStatus::Complete);
        let mut missing_manifest = live_manifest(Vec::new(), RunHealthStatus::Complete);
        missing_manifest.device.boot_id = None;
        let error = validate_manifest_fields(&missing_manifest).unwrap_err();
        assert!(error.to_string().contains("boot_id"));

        let mut invalid_manifest = live_manifest(Vec::new(), RunHealthStatus::Complete);
        invalid_manifest.device.boot_id = Some("boot-live".into());
        let error = validate_manifest_fields(&invalid_manifest).unwrap_err();
        assert!(error.to_string().contains("lowercase UUID"));

        let error = RunManifest::live_capture(LiveCaptureManifest {
            run_id: "trace-boot-test".into(),
            started_at: "2026-07-17T06:39:01Z".into(),
            completed_at: "2026-07-17T06:39:02Z".into(),
            device: DeviceIdentity {
                boot_id: Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into()),
                ..live_device_identity()
            },
            research_model: ResearchModel {
                observer_privilege: "root".into(),
                attacker_capability: "not_tested".into(),
            },
            bpf: live_bpf_identity(),
            capture_health: valid_health,
            artifacts: Vec::new(),
        })
        .unwrap_err();
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn trace_live_requires_complete_android_device_identity() {
        let valid = live_manifest(Vec::new(), RunHealthStatus::Complete);
        let mut cases = Vec::new();
        for field in [
            "model",
            "product",
            "build_id",
            "fingerprint",
            "spl",
            "kernel",
        ] {
            let mut manifest = valid.clone();
            match field {
                "model" => manifest.device.model = None,
                "product" => manifest.device.product = None,
                "build_id" => manifest.device.build_id = None,
                "fingerprint" => manifest.device.fingerprint = None,
                "spl" => manifest.device.spl = None,
                "kernel" => manifest.device.kernel = None,
                _ => unreachable!(),
            }
            cases.push((field, manifest));
        }
        let mut empty_model = valid.clone();
        empty_model.device.model = Some(String::new());
        cases.push(("model", empty_model));
        let mut missing_serial = valid.clone();
        missing_serial.device.serial_hash = None;
        cases.push(("serial_hash", missing_serial));
        let mut zero_serial = valid.clone();
        zero_serial.device.serial_hash = Some(format!("sha256:{}", "0".repeat(64)));
        cases.push(("serial_hash", zero_serial));
        let mut missing_api = valid.clone();
        missing_api.device.api = None;
        cases.push(("api", missing_api));
        let mut zero_api = valid;
        zero_api.device.api = Some(0);
        cases.push(("api", zero_api));

        for (field, manifest) in cases {
            let error = validate_manifest_fields(&manifest).unwrap_err();
            assert!(
                error.to_string().contains(field),
                "unexpected error for missing device.{field}: {error:#}"
            );
        }
    }

    #[test]
    fn coverage_evidence_excerpt_hash_is_recomputed() {
        let mut document = exact_coverage();
        document.rows[0].attribution.sources[0].evidence = "forged excerpt".into();
        let error = validate_coverage_provenance(&document).unwrap_err();
        assert!(error.to_string().contains("evidence hash mismatch"));
    }

    #[test]
    fn exact_owner_fields_must_match_their_evidence_excerpts() {
        let mut document = exact_coverage();
        let dumpsys = document.rows[0]
            .attribution
            .sources
            .iter_mut()
            .find(|source| source.collector == "dumpsys_pid")
            .unwrap();
        dumpsys.evidence = "endpoint=vendor.example.IExample/default pid=999".into();
        dumpsys.evidence_sha256 = format!("{:x}", Sha256::digest(dumpsys.evidence.as_bytes()));

        let error = validate_coverage_provenance(&document).unwrap_err();
        assert!(error.to_string().contains("inconsistent with its owner"));
    }
}
