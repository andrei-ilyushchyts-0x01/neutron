//! Target-scoped Android service/HAL ownership coverage.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::run_manifest::{
    self, DeviceIdentity, ResearchModel, RunCollection, RunHealth, RunHealthStatus, RunManifest,
    StaticSurfaceManifest,
};

use super::{
    parse_dumpsys_pid, parse_lshal_inventory, parse_process_starttime, parse_process_status,
    parse_service_list_inventory, parse_vintf_manifest, parse_vndservice_list, PlatformReader,
    RealPlatformReader,
};

const COVERAGE_SCHEMA: &str = "neutron.surface-coverage/v1";
const MAX_TARGET_BYTES: usize = 1024 * 1024;
const MAX_TARGETS: usize = 4096;
const MAX_TARGET_LENGTH: usize = 4096;
const MAX_REPEAT: usize = 32;
const MAX_COLLECTOR_BYTES: usize = 16 * 1024 * 1024;

#[derive(Args, Debug)]
pub struct CoverageArgs {
    /// One exact service/HAL endpoint per line.
    #[arg(long)]
    pub targets: PathBuf,
    /// Explicitly select privacy-preserving target-only collection.
    #[arg(long, required = true)]
    pub minimal: bool,
    /// Repeat collection to expose semantic drift.
    #[arg(
        long,
        default_value_t = 1,
        value_parser = clap::value_parser!(u32).range(1..=32)
    )]
    pub repeat: u32,
    /// Write the versioned coverage document to this private file.
    #[arg(long = "json")]
    pub json_output: PathBuf,
    /// Write the coverage table to this private file.
    #[arg(long = "tsv")]
    pub tsv_output: PathBuf,
    /// Create a private neutron.run-manifest/v1 bundle with deterministic
    /// content checksums. Checksums detect later changes but do not establish
    /// publisher authenticity without an external signature or attestation.
    #[arg(long)]
    pub run_dir: Option<PathBuf>,
    /// Attacker model associated with this evidence run (no stimulus is implied).
    #[arg(long, default_value = "not_tested")]
    pub attacker_capability: String,
    /// Return an error when any target lacks exact owner attribution.
    #[arg(long)]
    pub fail_unresolved: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageOptions {
    pub minimal: bool,
    pub repeat: usize,
}

impl Default for CoverageOptions {
    fn default() -> Self {
        Self {
            minimal: true,
            repeat: 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoverageDocument {
    pub schema: String,
    pub neutron_version: String,
    pub collected_at: String,
    pub device: CoverageDevice,
    pub collection: CoverageCollection,
    pub repeat: CoverageRepeat,
    pub health: CoverageHealth,
    pub summary: CoverageSummary,
    pub rows: Vec<CoverageRow>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoverageDevice {
    pub fingerprint: String,
    pub boot_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoverageCollection {
    pub target_count: usize,
    pub minimal: bool,
    pub full_snapshot_retained: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoverageRepeat {
    pub count: usize,
    pub semantic_drift: Vec<SemanticDrift>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SemanticDrift {
    pub baseline_pass: usize,
    pub current_pass: usize,
    pub endpoints: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoverageHealth {
    pub status: String,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoverageSummary {
    pub exact: usize,
    pub unresolved: usize,
    pub ambiguous: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoverageRow {
    pub endpoint: String,
    pub declared: bool,
    pub live: bool,
    pub transport: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<CoverageOwner>,
    pub attribution: CoverageAttribution,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoverageOwner {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub starttime: u64,
    pub boot_id: String,
    pub selinux_domain: String,
    pub executable: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoverageAttribution {
    pub confidence: String,
    pub sources: Vec<SourceEvidence>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct SourceEvidence {
    pub measured_by: String,
    pub collector: String,
    pub source: String,
    pub evidence: String,
    pub evidence_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_sha256: Option<String>,
}

#[derive(Default)]
struct TargetState {
    required_transport: Option<String>,
    declared: bool,
    live: bool,
    live_transports: BTreeSet<String>,
    declared_transports: BTreeSet<String>,
    pids: BTreeSet<u32>,
    sources: BTreeSet<SourceEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TargetSpec {
    endpoint: String,
    transport: Option<String>,
}

impl TargetSpec {
    fn canonical(&self) -> String {
        self.transport.as_ref().map_or_else(
            || self.endpoint.clone(),
            |transport| format!("service:{transport}:{}", self.endpoint),
        )
    }
}

struct OwnerRecord {
    owner: CoverageOwner,
    sources: Vec<SourceEvidence>,
}

#[derive(Default)]
struct EndpointRevalidation {
    valid: bool,
    sources: Vec<SourceEvidence>,
}

struct MappingObservation {
    pids: BTreeSet<u32>,
    evidence: SourceEvidence,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum PassValidity {
    #[default]
    Valid,
    Incomplete,
    Unknown,
}

impl PassValidity {
    fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Incomplete, _) | (_, Self::Incomplete) => Self::Incomplete,
            _ => Self::Valid,
        }
    }
}

struct CoveragePass {
    collected_at: String,
    device: CoverageDevice,
    rows: Vec<CoverageRow>,
    warnings: Vec<String>,
    validity: PassValidity,
}

pub fn run(args: CoverageArgs) -> Result<()> {
    let targets_path = resolved_create_path(&args.targets)?;
    let json_path = resolved_create_path(&args.json_output)?;
    let tsv_path = resolved_create_path(&args.tsv_output)?;
    if json_path == tsv_path {
        bail!("--json and --tsv must name different files");
    }
    if targets_path == json_path || targets_path == tsv_path {
        bail!("--targets must be different from --json and --tsv outputs");
    }
    if let Some(run_dir) = &args.run_dir {
        let run_path = resolved_create_path(run_dir)?;
        if json_path.starts_with(&run_path) || tsv_path.starts_with(&run_path) {
            bail!("--json and --tsv must be outside --run-dir");
        }
    }
    let input = read_target_file(&args.targets)?;
    let input = String::from_utf8(input).context("target list is not UTF-8")?;
    let targets = parse_targets(&input)?;
    let reader = RealPlatformReader;
    let started_at = reader.collected_at();
    let mut document = collect_coverage_with_reader(
        &reader,
        &targets,
        &CoverageOptions {
            minimal: args.minimal,
            repeat: args.repeat as usize,
        },
    )?;
    apply_tool_provenance_health(&mut document)?;
    let completed_at = reader.collected_at();
    crate::private_output::write_json(&args.json_output, &document, true)?;
    let tsv = render_tsv(&document);
    crate::private_output::write(&args.tsv_output, tsv.as_bytes(), true)?;
    if let Some(run_dir) = &args.run_dir {
        write_run_bundle(
            &reader,
            run_dir,
            &targets,
            &document,
            &tsv,
            &started_at,
            &completed_at,
            &args.attacker_capability,
        )?;
    }
    if !document.repeat.semantic_drift.is_empty() {
        bail!("repeat collection detected semantic drift");
    }
    if args.fail_unresolved && document.summary.exact != document.collection.target_count {
        bail!(
            "{} of {} targets lack exact owner attribution",
            document.collection.target_count - document.summary.exact,
            document.collection.target_count
        );
    }
    Ok(())
}

fn apply_tool_provenance_health(document: &mut CoverageDocument) -> Result<()> {
    let tool = run_manifest::ToolIdentity::current()?;
    for issue in tool.provenance_issues() {
        document
            .health
            .warnings
            .push(format!("tool provenance unknown: {issue}"));
        document.health.status = "unknown".into();
    }
    document.health.warnings.sort();
    document.health.warnings.dedup();
    Ok(())
}

fn resolved_create_path(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return std::fs::canonicalize(path)
            .with_context(|| format!("resolving output path {}", path.display()));
    }
    let name = path
        .file_name()
        .context("output path must end in a file or directory name")?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(std::fs::canonicalize(parent)
        .with_context(|| format!("resolving output parent {}", parent.display()))?
        .join(name))
}

#[allow(clippy::too_many_arguments)]
fn write_run_bundle(
    reader: &dyn PlatformReader,
    run_dir: &Path,
    targets: &[String],
    document: &CoverageDocument,
    tsv: &str,
    started_at: &str,
    completed_at: &str,
    attacker_capability: &str,
) -> Result<()> {
    run_manifest::create_private_run_directory(run_dir)?;
    let target_artifact = run_manifest::write_targets(run_dir, targets)?;
    let mut json = serde_json::to_vec_pretty(document)?;
    json.push(b'\n');
    let coverage_artifact = run_manifest::write_artifact(run_dir, "surface.coverage.json", &json)?;
    let tsv_artifact =
        run_manifest::write_artifact(run_dir, "surface.coverage.tsv", tsv.as_bytes())?;

    let run_id_material = format!(
        "{started_at}\0{completed_at}\0{}\0{}",
        document.device.boot_id,
        std::process::id()
    );
    let run_id = format!("surface-{:x}", Sha256::digest(run_id_material.as_bytes()));
    let manifest = RunManifest::static_surface(StaticSurfaceManifest {
        run_id,
        started_at: started_at.into(),
        completed_at: completed_at.into(),
        device: collect_manifest_device(reader, document),
        research_model: ResearchModel {
            observer_privilege: collect_observer_privilege(reader),
            attacker_capability: attacker_capability.into(),
        },
        collection: RunCollection {
            target_count: document.collection.target_count,
            minimal: document.collection.minimal,
            full_snapshot_retained: document.collection.full_snapshot_retained,
            repeat: document.repeat.count,
        },
        health: RunHealth {
            status: manifest_health_status(&document.health.status),
            reasons: document.health.warnings.clone(),
        },
        artifacts: vec![target_artifact, coverage_artifact, tsv_artifact],
    })?;
    run_manifest::finalize_bundle(run_dir, &manifest)
}

fn manifest_health_status(status: &str) -> RunHealthStatus {
    match status {
        "complete" => RunHealthStatus::Complete,
        "degraded" => RunHealthStatus::Degraded,
        "incomplete" => RunHealthStatus::Incomplete,
        _ => RunHealthStatus::Unknown,
    }
}

fn collect_manifest_device(
    reader: &dyn PlatformReader,
    document: &CoverageDocument,
) -> DeviceIdentity {
    let serial_hash =
        property(reader, "ro.serialno").and_then(|serial| run_manifest::serial_hash(&serial).ok());
    DeviceIdentity {
        serial_hash,
        model: property(reader, "ro.product.model"),
        product: property(reader, "ro.product.device"),
        build_id: property(reader, "ro.build.id"),
        fingerprint: bounded_value(&document.device.fingerprint),
        api: property(reader, "ro.build.version.sdk").and_then(|value| value.parse().ok()),
        spl: property(reader, "ro.build.version.security_patch"),
        kernel: reader
            .read_bounded(Path::new("/proc/sys/kernel/osrelease"), MAX_COLLECTOR_BYTES)
            .ok()
            .and_then(|value| String::from_utf8(value).ok())
            .and_then(|value| bounded_value(&value)),
        boot_id: bounded_value(&document.device.boot_id),
    }
}

fn property(reader: &dyn PlatformReader, name: &str) -> Option<String> {
    let output = reader.command_output("getprop", &[name]).ok()?;
    if !output.success || output.stdout.len() > 4096 || !output.stderr.is_empty() {
        return None;
    }
    bounded_value(&output.stdout)
}

fn bounded_value(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control))
        .then(|| value.to_string())
}

fn collect_observer_privilege(reader: &dyn PlatformReader) -> String {
    let euid = unsafe { libc::geteuid() };
    let base = if euid == 0 {
        "root".to_string()
    } else {
        format!("uid:{euid}")
    };
    let domain = reader
        .read_bounded(Path::new("/proc/self/attr/current"), MAX_COLLECTOR_BYTES)
        .ok()
        .and_then(|value| String::from_utf8(value).ok())
        .and_then(|value| bounded_value(value.trim_end_matches('\0')));
    domain.map_or(base.clone(), |domain| format!("{base}/{domain}"))
}

fn read_target_file(path: &Path) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("opening target list {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting target list {}", path.display()))?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        bail!("target list must be a single-link regular file");
    }
    if metadata.len() > MAX_TARGET_BYTES as u64 {
        bail!("target list exceeds {MAX_TARGET_BYTES} bytes");
    }
    let mut input = Vec::new();
    file.take((MAX_TARGET_BYTES as u64).saturating_add(1))
        .read_to_end(&mut input)
        .with_context(|| format!("reading target list {}", path.display()))?;
    if input.len() > MAX_TARGET_BYTES {
        bail!("target list exceeds {MAX_TARGET_BYTES} bytes");
    }
    Ok(input)
}

pub fn parse_targets(input: &str) -> Result<Vec<String>> {
    if input.len() > MAX_TARGET_BYTES {
        bail!("target list exceeds {MAX_TARGET_BYTES} bytes");
    }
    let mut targets = BTreeMap::new();
    for (index, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let target =
            parse_target(line).with_context(|| format!("invalid target on line {}", index + 1))?;
        if targets
            .insert(target.endpoint.clone(), target.clone())
            .is_some()
        {
            bail!("duplicate normalized target '{}'", target.endpoint);
        }
        if targets.len() > MAX_TARGETS {
            bail!("target list exceeds {MAX_TARGETS} entries");
        }
    }
    if targets.is_empty() {
        bail!("target list is empty");
    }
    Ok(targets
        .into_values()
        .map(|target| target.canonical())
        .collect())
}

fn parse_target(value: &str) -> Result<TargetSpec> {
    let (transport, endpoint) = match value.strip_prefix("service:") {
        Some(rest) => {
            let (transport, endpoint) = rest
                .split_once(':')
                .context("service target must include transport and endpoint")?;
            if !matches!(transport, "binder" | "hwbinder" | "vndbinder") {
                bail!("unsupported service transport '{transport}'");
            }
            (Some(transport.to_string()), endpoint)
        }
        None => (None, value),
    };
    if endpoint.is_empty() || endpoint.len() > MAX_TARGET_LENGTH {
        bail!("target must contain 1..={MAX_TARGET_LENGTH} bytes");
    }
    if endpoint.starts_with('-') || !endpoint.bytes().all(|byte| byte.is_ascii_graphic()) {
        bail!("target must contain printable ASCII without whitespace");
    }
    Ok(TargetSpec {
        endpoint: endpoint.to_string(),
        transport,
    })
}

pub fn collect_coverage_with_reader(
    reader: &dyn PlatformReader,
    targets: &[String],
    options: &CoverageOptions,
) -> Result<CoverageDocument> {
    if !options.minimal {
        bail!("only minimal target-scoped coverage is supported");
    }
    if !(1..=MAX_REPEAT).contains(&options.repeat) {
        bail!("repeat must be in 1..={MAX_REPEAT}");
    }
    let normalized = parse_targets(&targets.join("\n"))?;
    let targets = normalized
        .iter()
        .map(|target| parse_target(target))
        .collect::<Result<Vec<_>>>()?;
    let mut passes = Vec::with_capacity(options.repeat);
    for _ in 0..options.repeat {
        passes.push(collect_pass(reader, &targets)?);
    }

    let semantic_drift = compare_passes(&passes);
    let mut warnings = BTreeSet::new();
    for pass in &passes {
        warnings.extend(pass.warnings.iter().cloned());
    }
    let has_drift = !semantic_drift.is_empty();
    if has_drift {
        warnings.insert("repeat collection detected semantic drift".into());
    }
    let warnings: Vec<_> = warnings.into_iter().collect();
    let validity = passes.iter().fold(PassValidity::Valid, |validity, pass| {
        validity.combine(pass.validity)
    });
    let final_pass = passes.last().context("coverage produced no pass")?;
    let summary = summarize(&final_pass.rows);
    Ok(CoverageDocument {
        schema: COVERAGE_SCHEMA.into(),
        neutron_version: env!("CARGO_PKG_VERSION").into(),
        collected_at: final_pass.collected_at.clone(),
        device: final_pass.device.clone(),
        collection: CoverageCollection {
            target_count: targets.len(),
            minimal: true,
            full_snapshot_retained: false,
        },
        repeat: CoverageRepeat {
            count: options.repeat,
            semantic_drift,
        },
        health: CoverageHealth {
            status: (match validity {
                PassValidity::Unknown => "unknown",
                PassValidity::Incomplete => "incomplete",
                PassValidity::Valid if has_drift => "incomplete",
                PassValidity::Valid if warnings.is_empty() => "complete",
                PassValidity::Valid => "degraded",
            })
            .into(),
            warnings,
        },
        summary,
        rows: final_pass.rows.clone(),
    })
}

fn collect_pass(reader: &dyn PlatformReader, targets: &[TargetSpec]) -> Result<CoveragePass> {
    let endpoints: Vec<_> = targets
        .iter()
        .map(|target| target.endpoint.clone())
        .collect();
    let target_set: BTreeSet<_> = endpoints.iter().cloned().collect();
    let mut states: BTreeMap<String, TargetState> = targets
        .iter()
        .map(|target| {
            (
                target.endpoint.clone(),
                TargetState {
                    required_transport: target.transport.clone(),
                    ..TargetState::default()
                },
            )
        })
        .collect();
    let mut warnings = BTreeSet::new();
    let mut validity = PassValidity::Valid;

    // Bracket the entire pass with boot identity reads. An owner assembled
    // across a reboot is not a coherent process identity, even when its PID
    // and starttime happen to match.
    let (boot_id, boot_raw) = match read_utf8(reader, Path::new("/proc/sys/kernel/random/boot_id"))
    {
        Ok(value) if !value.trim().is_empty() => (value.trim().to_string(), value),
        Ok(_) => {
            warnings.insert("initial boot identity is empty".into());
            validity = validity.combine(PassValidity::Unknown);
            (String::new(), String::new())
        }
        Err(error) => {
            warnings.insert(format!("cannot read initial boot identity: {error:#}"));
            validity = validity.combine(PassValidity::Unknown);
            (String::new(), String::new())
        }
    };

    collect_binder_inventory(reader, &target_set, &mut states, &mut warnings);
    collect_lshal_inventory(reader, &target_set, &mut states, &mut warnings);
    collect_vndbinder_inventory(reader, &target_set, &mut states, &mut warnings);
    collect_vintf_inventory(reader, &target_set, &mut states, &mut warnings);

    let fingerprint = collect_fingerprint(reader, &mut warnings);

    let pids: BTreeSet<u32> = states
        .values()
        .flat_map(|state| state.pids.iter().copied())
        .collect();
    let mut owners = BTreeMap::new();
    for pid in pids {
        match collect_owner(reader, pid, &boot_id, &boot_raw) {
            Ok(owner) => {
                owners.insert(pid, owner);
            }
            Err(error) => {
                warnings.insert(format!("cannot prove owner PID {pid}: {error:#}"));
            }
        }
    }

    let endpoint_revalidations = revalidate_endpoint_owners(
        reader,
        &endpoints,
        &states,
        &owners,
        &mut warnings,
        &mut validity,
    );

    let (boot_stable, final_boot_evidence, device_boot_id) =
        match read_utf8(reader, Path::new("/proc/sys/kernel/random/boot_id")) {
            Ok(value) if value.trim().is_empty() => {
                warnings.insert("cannot revalidate boot identity: value is empty".into());
                validity = validity.combine(PassValidity::Unknown);
                (false, None, String::new())
            }
            Ok(_) if boot_id.is_empty() => (false, None, String::new()),
            Ok(value) if value.trim() != boot_id => {
                warnings.insert("boot identity changed during coverage pass".into());
                validity = validity.combine(PassValidity::Incomplete);
                (false, None, String::new())
            }
            Ok(value) => (
                true,
                Some(evidence_from_source(
                    "boot_id_revalidated",
                    "/proc/sys/kernel/random/boot_id",
                    format!("boot_id={boot_id}"),
                    value.as_bytes(),
                )),
                boot_id.clone(),
            ),
            Err(error) => {
                warnings.insert(format!("cannot revalidate boot identity: {error:#}"));
                validity = validity.combine(PassValidity::Unknown);
                (false, None, String::new())
            }
        };

    let mut rows = Vec::with_capacity(targets.len());
    for endpoint in &endpoints {
        let state = states.get(endpoint).expect("target state exists");
        let ambiguous = state.live_transports.len() > 1 || state.pids.len() > 1;
        let endpoint_revalidation = endpoint_revalidations.get(endpoint);
        let owner_record = state
            .pids
            .iter()
            .next()
            .filter(|_| state.pids.len() == 1 && state.live && !ambiguous && boot_stable)
            .filter(|_| endpoint_revalidation.is_some_and(|result| result.valid))
            .and_then(|pid| owners.get(pid));
        let confidence = if ambiguous {
            "ambiguous"
        } else if state.live && owner_record.is_some() {
            "exact"
        } else {
            "unresolved"
        };
        let mut sources = state.sources.clone();
        if let Some(revalidation) = endpoint_revalidation {
            sources.extend(revalidation.sources.iter().cloned());
        }
        if let Some(owner) = owner_record {
            sources.extend(owner.sources.iter().cloned());
            if let Some(evidence) = &final_boot_evidence {
                sources.insert(evidence.clone());
            }
        }
        rows.push(CoverageRow {
            endpoint: endpoint.clone(),
            declared: state.declared,
            live: state.live,
            transport: selected_transport(state),
            owner: owner_record.map(|record| record.owner.clone()),
            attribution: CoverageAttribution {
                confidence: confidence.into(),
                sources: sources.into_iter().collect(),
            },
        });
    }

    Ok(CoveragePass {
        collected_at: reader.collected_at(),
        device: CoverageDevice {
            fingerprint,
            boot_id: device_boot_id,
        },
        rows,
        warnings: warnings.into_iter().collect(),
        validity,
    })
}

fn revalidate_endpoint_owners(
    reader: &dyn PlatformReader,
    targets: &[String],
    states: &BTreeMap<String, TargetState>,
    owners: &BTreeMap<u32, OwnerRecord>,
    warnings: &mut BTreeSet<String>,
    validity: &mut PassValidity,
) -> BTreeMap<String, EndpointRevalidation> {
    let needs_hwbinder_snapshot = targets.iter().any(|endpoint| {
        let state = states.get(endpoint).expect("target state exists");
        state.live
            && state.live_transports.len() == 1
            && state.live_transports.contains("hwbinder")
            && state.pids.len() == 1
            && state
                .pids
                .iter()
                .next()
                .is_some_and(|pid| owners.contains_key(pid))
    });
    let hwbinder_snapshot =
        needs_hwbinder_snapshot.then(|| revalidation_command(reader, "lshal", &["-i", "-p"]));

    let mut results = BTreeMap::new();
    for endpoint in targets {
        let state = states.get(endpoint).expect("target state exists");
        if !state.live || state.live_transports.len() != 1 || state.pids.len() != 1 {
            continue;
        }
        let pid = *state.pids.iter().next().expect("one owner PID");
        let Some(owner) = owners.get(&pid) else {
            continue;
        };
        let transport = state
            .live_transports
            .iter()
            .next()
            .expect("one live transport");
        let observation = match transport.as_str() {
            "binder" => revalidation_command(reader, "dumpsys", &["--pid", endpoint])
                .map(|output| binder_mapping_observation(endpoint, &output)),
            "hwbinder" => match hwbinder_snapshot.as_ref().expect("snapshot requested") {
                Ok(output) => Ok(hwbinder_mapping_observation(endpoint, output)),
                Err(error) => Err(error.clone()),
            },
            _ => continue,
        };

        let mut result = EndpointRevalidation::default();
        let observation = match observation {
            Ok(observation) => observation,
            Err(error) => {
                warnings.insert(format!(
                    "cannot revalidate owner mapping for {endpoint}: {error}"
                ));
                *validity = validity.combine(PassValidity::Unknown);
                results.insert(endpoint.clone(), result);
                continue;
            }
        };
        result.sources.push(observation.evidence);

        let observed_pid = match observation.pids.len() {
            0 => {
                warnings.insert(format!(
                    "endpoint {endpoint} no longer proves an owner PID during revalidation"
                ));
                *validity = validity.combine(PassValidity::Incomplete);
                results.insert(endpoint.clone(), result);
                continue;
            }
            1 => *observation.pids.iter().next().expect("one observed PID"),
            _ => {
                warnings.insert(format!(
                    "endpoint {endpoint} reports multiple owner PIDs during revalidation"
                ));
                *validity = validity.combine(PassValidity::Incomplete);
                results.insert(endpoint.clone(), result);
                continue;
            }
        };
        if observed_pid != pid {
            warnings.insert(format!(
                "endpoint {endpoint} changed from PID {pid} to PID {observed_pid} during revalidation"
            ));
            *validity = validity.combine(PassValidity::Incomplete);
            results.insert(endpoint.clone(), result);
            continue;
        }

        let stat_path = PathBuf::from(format!("/proc/{pid}/stat"));
        let stat = match read_utf8(reader, &stat_path) {
            Ok(stat) => stat,
            Err(error) => {
                warnings.insert(format!(
                    "cannot revalidate process identity for endpoint {endpoint}: {error:#}"
                ));
                *validity = validity.combine(PassValidity::Unknown);
                results.insert(endpoint.clone(), result);
                continue;
            }
        };
        let starttime = match parse_process_starttime(&stat) {
            Ok(starttime) => starttime,
            Err(error) => {
                warnings.insert(format!(
                    "cannot parse revalidated process identity for endpoint {endpoint}: {error:#}"
                ));
                *validity = validity.combine(PassValidity::Unknown);
                results.insert(endpoint.clone(), result);
                continue;
            }
        };
        if starttime != owner.owner.starttime {
            warnings.insert(format!(
                "owner PID {pid} starttime changed from {} to {starttime} during endpoint revalidation",
                owner.owner.starttime
            ));
            *validity = validity.combine(PassValidity::Incomplete);
            results.insert(endpoint.clone(), result);
            continue;
        }
        result.sources.push(evidence_from_source(
            "proc_stat_endpoint_revalidated",
            stat_path.to_string_lossy(),
            format!("endpoint={endpoint} pid={pid} starttime={starttime}"),
            stat.as_bytes(),
        ));
        result.valid = true;
        results.insert(endpoint.clone(), result);
    }
    results
}

fn revalidation_command(
    reader: &dyn PlatformReader,
    program: &str,
    args: &[&str],
) -> std::result::Result<super::CommandOutput, String> {
    match reader.command_output(program, args) {
        Ok(output)
            if output.stdout.len() > MAX_COLLECTOR_BYTES
                || output.stderr.len() > MAX_COLLECTOR_BYTES =>
        {
            Err(format!("{program} output exceeds collector size limit"))
        }
        Ok(output) if !output.success => Err(format!("{program} {} failed", args.join(" "))),
        Ok(output) => Ok(output),
        Err(error) => Err(format!("cannot run {program} {}: {error}", args.join(" "))),
    }
}

fn binder_mapping_observation(endpoint: &str, output: &super::CommandOutput) -> MappingObservation {
    let pids = parse_dumpsys_pid(&output.stdout).into_iter().collect();
    MappingObservation {
        pids,
        evidence: evidence_from_source(
            "dumpsys_pid_revalidated",
            format!("dumpsys --pid {endpoint}"),
            format!("endpoint={endpoint} pid={}", output.stdout.trim()),
            output.stdout.as_bytes(),
        ),
    }
}

fn hwbinder_mapping_observation(
    endpoint: &str,
    output: &super::CommandOutput,
) -> MappingObservation {
    let pids: BTreeSet<_> = parse_lshal_inventory(&output.stdout)
        .into_iter()
        .filter(|item| item.name == endpoint)
        .filter_map(|item| item.pid)
        .collect();
    let rendered_pids = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    MappingObservation {
        pids,
        evidence: evidence_from_source(
            "lshal_revalidated",
            "lshal -ip",
            format!("endpoint={endpoint} pids={rendered_pids}"),
            output.stdout.as_bytes(),
        ),
    }
}

fn collect_binder_inventory(
    reader: &dyn PlatformReader,
    targets: &BTreeSet<String>,
    states: &mut BTreeMap<String, TargetState>,
    warnings: &mut BTreeSet<String>,
) {
    let Some(output) = command(reader, "service", &["list"], warnings) else {
        return;
    };
    for item in parse_service_list_inventory(&output.stdout) {
        if !targets.contains(&item.name) {
            continue;
        }
        let state = states.get_mut(&item.name).expect("target state exists");
        if !accepts_transport(state, "binder") {
            continue;
        }
        state.live = true;
        state.live_transports.insert("binder".into());
        state.sources.insert(evidence_from_source(
            "service_list",
            "service list",
            format!(
                "name={} descriptor={}",
                item.name,
                item.descriptor.as_deref().unwrap_or("")
            ),
            output.stdout.as_bytes(),
        ));
        match reader.command_output("dumpsys", &["--pid", &item.name]) {
            Ok(pid_output)
                if pid_output.success
                    && pid_output.stdout.len() <= MAX_COLLECTOR_BYTES
                    && pid_output.stderr.len() <= MAX_COLLECTOR_BYTES =>
            {
                state.sources.insert(evidence_from_source(
                    "dumpsys_pid",
                    format!("dumpsys --pid {}", item.name),
                    format!("endpoint={} pid={}", item.name, pid_output.stdout.trim()),
                    pid_output.stdout.as_bytes(),
                ));
                match parse_dumpsys_pid(&pid_output.stdout) {
                    Some(pid) => {
                        state.pids.insert(pid);
                    }
                    None => {
                        warnings.insert(format!(
                            "dumpsys --pid did not prove a PID for {}",
                            item.name
                        ));
                    }
                }
            }
            Ok(_) => {
                warnings.insert(format!("dumpsys --pid {} failed", item.name));
            }
            Err(error) => {
                warnings.insert(format!("cannot run dumpsys --pid {}: {error}", item.name));
            }
        }
    }
}

fn collect_lshal_inventory(
    reader: &dyn PlatformReader,
    targets: &BTreeSet<String>,
    states: &mut BTreeMap<String, TargetState>,
    warnings: &mut BTreeSet<String>,
) {
    let Some(output) = command(reader, "lshal", &["-i", "-p"], warnings) else {
        return;
    };
    for item in parse_lshal_inventory(&output.stdout) {
        if !targets.contains(&item.name) {
            continue;
        }
        let state = states.get_mut(&item.name).expect("target state exists");
        if !accepts_transport(state, "hwbinder") {
            continue;
        }
        state.live = true;
        state.live_transports.insert("hwbinder".into());
        state.pids.extend(item.pid);
        state.sources.insert(evidence_from_source(
            "lshal",
            "lshal -ip",
            format!("name={} pid={}", item.name, item.pid.unwrap_or_default()),
            output.stdout.as_bytes(),
        ));
    }
}

fn collect_vndbinder_inventory(
    reader: &dyn PlatformReader,
    targets: &BTreeSet<String>,
    states: &mut BTreeMap<String, TargetState>,
    warnings: &mut BTreeSet<String>,
) {
    let Some(output) = command(reader, "vndservice", &["list"], warnings) else {
        return;
    };
    for item in parse_vndservice_list(&output.stdout) {
        if !targets.contains(&item.name) {
            continue;
        }
        let state = states.get_mut(&item.name).expect("target state exists");
        if !accepts_transport(state, "vndbinder") {
            continue;
        }
        state.live = true;
        state.live_transports.insert("vndbinder".into());
        state.sources.insert(evidence_from_source(
            "vndservice_list",
            "vndservice list",
            format!(
                "name={} descriptor={}",
                item.name,
                item.descriptor.as_deref().unwrap_or("")
            ),
            output.stdout.as_bytes(),
        ));
    }
}

fn collect_vintf_inventory(
    reader: &dyn PlatformReader,
    targets: &BTreeSet<String>,
    states: &mut BTreeMap<String, TargetState>,
    warnings: &mut BTreeSet<String>,
) {
    for path in vintf_paths(reader, warnings) {
        let raw = match reader.read_bounded(&path, MAX_COLLECTOR_BYTES) {
            Ok(raw) => raw,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                warnings.insert(format!("cannot read {}: {error}", path.display()));
                continue;
            }
        };
        let text = String::from_utf8_lossy(&raw);
        let declarations = match parse_vintf_manifest(&text) {
            Ok(declarations) => declarations,
            Err(error) => {
                warnings.insert(format!("cannot parse {}: {error}", path.display()));
                continue;
            }
        };
        for declaration in declarations {
            let endpoint = declaration.fqname();
            if !targets.contains(&endpoint) {
                continue;
            }
            let transport = declaration.transport.clone().unwrap_or_else(|| {
                if declaration.format == "aidl" {
                    "binder".into()
                } else if declaration.format == "hidl" {
                    "hwbinder".into()
                } else {
                    declaration.format.clone()
                }
            });
            let state = states.get_mut(&endpoint).expect("target state exists");
            if !accepts_transport(state, &transport) {
                continue;
            }
            state.declared = true;
            state.declared_transports.insert(transport.clone());
            state.sources.insert(evidence_from_source(
                "vintf",
                path.to_string_lossy(),
                format!(
                    "format={} transport={} endpoint={endpoint}",
                    declaration.format, transport
                ),
                &raw,
            ));
        }
    }
}

fn command(
    reader: &dyn PlatformReader,
    program: &str,
    args: &[&str],
    warnings: &mut BTreeSet<String>,
) -> Option<super::CommandOutput> {
    match reader.command_output(program, args) {
        Ok(output)
            if output.success
                && output.stdout.len() <= MAX_COLLECTOR_BYTES
                && output.stderr.len() <= MAX_COLLECTOR_BYTES =>
        {
            Some(output)
        }
        Ok(output)
            if output.stdout.len() > MAX_COLLECTOR_BYTES
                || output.stderr.len() > MAX_COLLECTOR_BYTES =>
        {
            warnings.insert(format!("{program} output exceeds collector size limit"));
            None
        }
        Ok(_) => {
            warnings.insert(format!("{program} {} failed", args.join(" ")));
            None
        }
        Err(error) => {
            warnings.insert(format!("cannot run {program} {}: {error}", args.join(" ")));
            None
        }
    }
}

fn vintf_paths(reader: &dyn PlatformReader, warnings: &mut BTreeSet<String>) -> Vec<PathBuf> {
    const ROOTS: &[&str] = &["/system", "/vendor", "/product", "/system_ext", "/odm"];
    let mut paths = BTreeSet::new();
    for root in ROOTS {
        paths.insert(PathBuf::from(format!("{root}/etc/vintf/manifest.xml")));
        let fragments = PathBuf::from(format!("{root}/etc/vintf/manifest"));
        match reader.read_dir(&fragments) {
            Ok(entries) => paths.extend(entries.into_iter().filter(|path| {
                path.extension().and_then(|extension| extension.to_str()) == Some("xml")
            })),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                warnings.insert(format!("cannot enumerate {}: {error}", fragments.display()));
            }
        }
    }
    paths.into_iter().collect()
}

fn collect_owner(
    reader: &dyn PlatformReader,
    pid: u32,
    boot_id: &str,
    boot_raw: &str,
) -> Result<OwnerRecord> {
    if boot_id.is_empty() {
        bail!("boot identity is unavailable");
    }
    let stat_path = PathBuf::from(format!("/proc/{pid}/stat"));
    let status_path = PathBuf::from(format!("/proc/{pid}/status"));
    let attr_path = PathBuf::from(format!("/proc/{pid}/attr/current"));
    let exe_path = PathBuf::from(format!("/proc/{pid}/exe"));
    let stat = read_utf8(reader, &stat_path).context("reading initial process identity")?;
    let starttime = parse_process_starttime(&stat)?;
    let status_raw = read_utf8(reader, &status_path).context("reading process status")?;
    let status = parse_process_status(&status_raw)?;
    let domain_raw = read_utf8(reader, &attr_path).context("reading process SELinux domain")?;
    let selinux_domain = domain_raw.trim().trim_end_matches('\0').to_string();
    if selinux_domain.is_empty() {
        bail!("process SELinux domain is empty");
    }
    let executable = reader
        .read_link(&exe_path)
        .context("reading process executable")?
        .to_string_lossy()
        .into_owned();
    if executable.is_empty() {
        bail!("process executable is empty");
    }
    let final_stat = read_utf8(reader, &stat_path).context("revalidating process identity")?;
    if parse_process_starttime(&final_stat)? != starttime {
        bail!("process identity changed during collection");
    }
    Ok(OwnerRecord {
        owner: CoverageOwner {
            pid,
            uid: status.uid,
            gid: status.gid,
            starttime,
            boot_id: boot_id.into(),
            selinux_domain: selinux_domain.clone(),
            executable: executable.clone(),
        },
        sources: vec![
            evidence_from_source(
                "boot_id",
                "/proc/sys/kernel/random/boot_id",
                format!("boot_id={boot_id}"),
                boot_raw.as_bytes(),
            ),
            evidence_from_source(
                "proc_stat",
                stat_path.to_string_lossy(),
                format!("pid={pid} starttime={starttime}"),
                stat.as_bytes(),
            ),
            evidence_from_source(
                "proc_stat_revalidated",
                stat_path.to_string_lossy(),
                format!("pid={pid} starttime={starttime}"),
                final_stat.as_bytes(),
            ),
            evidence_from_source(
                "proc_status",
                status_path.to_string_lossy(),
                format!("pid={pid} uid={} gid={}", status.uid, status.gid),
                status_raw.as_bytes(),
            ),
            evidence_from_source(
                "proc_attr",
                attr_path.to_string_lossy(),
                format!("pid={pid} selinux_domain={selinux_domain}"),
                domain_raw.as_bytes(),
            ),
            evidence_from_source(
                "proc_exe",
                exe_path.to_string_lossy(),
                format!("pid={pid} executable={executable}"),
                executable.as_bytes(),
            ),
        ],
    })
}

fn read_utf8(reader: &dyn PlatformReader, path: &Path) -> Result<String> {
    let bytes = reader.read_bounded(path, MAX_COLLECTOR_BYTES)?;
    String::from_utf8(bytes).with_context(|| format!("{} is not UTF-8", path.display()))
}

fn collect_fingerprint(reader: &dyn PlatformReader, warnings: &mut BTreeSet<String>) -> String {
    if let Ok(build_prop) = read_utf8(reader, Path::new("/system/build.prop")) {
        if let Some(fingerprint) = build_prop.lines().find_map(|line| {
            line.strip_prefix("ro.build.fingerprint=")
                .map(str::trim)
                .filter(|value| !value.is_empty())
        }) {
            return fingerprint.into();
        }
    }
    match reader.command_output("getprop", &["ro.build.fingerprint"]) {
        Ok(output)
            if output.success
                && output.stdout.len() <= MAX_COLLECTOR_BYTES
                && !output.stdout.trim().is_empty() =>
        {
            output.stdout.trim().into()
        }
        Ok(_) => {
            warnings.insert("getprop did not return a build fingerprint".into());
            String::new()
        }
        Err(error) => {
            warnings.insert(format!("cannot collect build fingerprint: {error}"));
            String::new()
        }
    }
}

fn selected_transport(state: &TargetState) -> String {
    if let Some(transport) = &state.required_transport {
        return transport.clone();
    }
    let transports = if state.live_transports.is_empty() {
        &state.declared_transports
    } else {
        &state.live_transports
    };
    match transports.len() {
        0 => "unknown".into(),
        1 => transports.iter().next().cloned().expect("one transport"),
        _ => "ambiguous".into(),
    }
}

fn accepts_transport(state: &TargetState, transport: &str) -> bool {
    transport_matches(state.required_transport.as_deref(), transport)
}

fn transport_matches(required: Option<&str>, actual: &str) -> bool {
    match required {
        Some(required) => required == actual,
        None => true,
    }
}

pub(super) fn explain(document: &CoverageDocument, selector: &str) -> Result<Value> {
    if document.schema != COVERAGE_SCHEMA {
        bail!(
            "unsupported surface schema '{}' (expected {COVERAGE_SCHEMA})",
            document.schema
        );
    }
    let selector = parse_target(selector).context("invalid coverage selector")?;
    let matches: Vec<_> = document
        .rows
        .iter()
        .filter(|row| row.endpoint == selector.endpoint)
        .filter(|row| transport_matches(selector.transport.as_deref(), &row.transport))
        .collect();
    let row = match matches.as_slice() {
        [row] => *row,
        [] => bail!(
            "surface selector '{}' did not match a coverage row",
            selector.canonical()
        ),
        _ => bail!("surface selector '{}' is ambiguous", selector.canonical()),
    };

    let mut chain = Vec::new();
    if row.live {
        push_proof_step(
            &mut chain,
            format!("live {} service {}", row.transport, row.endpoint),
            sources_by_collector(row, &["service_list", "lshal", "vndservice_list"]),
        );
    }
    if let Some(owner) = &row.owner {
        push_proof_step(
            &mut chain,
            format!("owner PID {}", owner.pid),
            sources_by_collector(
                row,
                &[
                    "dumpsys_pid",
                    "dumpsys_pid_revalidated",
                    "lshal",
                    "lshal_revalidated",
                ],
            ),
        );
        push_proof_step(
            &mut chain,
            format!(
                "process identity PID {}, starttime {}, boot ID {}",
                owner.pid, owner.starttime, owner.boot_id
            ),
            sources_by_collector(
                row,
                &[
                    "boot_id",
                    "boot_id_revalidated",
                    "proc_stat",
                    "proc_stat_revalidated",
                    "proc_stat_endpoint_revalidated",
                ],
            ),
        );
        push_proof_step(
            &mut chain,
            format!("SELinux domain {}", owner.selinux_domain),
            sources_by_collector(row, &["proc_attr"]),
        );
        push_proof_step(
            &mut chain,
            format!("executable {}", owner.executable),
            sources_by_collector(row, &["proc_exe"]),
        );
    }
    if row.declared {
        push_proof_step(
            &mut chain,
            format!("declared {} service {}", row.transport, row.endpoint),
            sources_by_collector(row, &["vintf"]),
        );
    }

    Ok(json!({
        "schema": super::QUERY_SCHEMA,
        "selector": selector.canonical(),
        "entity": {"kind": "coverage", "value": row},
        "chain_of_proof": chain,
    }))
}

fn sources_by_collector(row: &CoverageRow, collectors: &[&str]) -> Vec<SourceEvidence> {
    let mut sources: Vec<_> = row
        .attribution
        .sources
        .iter()
        .filter(|source| collectors.contains(&source.collector.as_str()))
        .cloned()
        .collect();
    sources.sort();
    sources.dedup();
    sources
}

fn push_proof_step(chain: &mut Vec<Value>, claim: String, sources: Vec<SourceEvidence>) {
    if !sources.is_empty() {
        chain.push(json!({"claim": claim, "sources": sources}));
    }
}

fn evidence(
    collector: impl Into<String>,
    source: impl Into<String>,
    value: impl Into<String>,
) -> SourceEvidence {
    let value = value.into();
    SourceEvidence {
        measured_by: "neutron".into(),
        collector: collector.into(),
        source: source.into(),
        evidence_sha256: format!("{:x}", Sha256::digest(value.as_bytes())),
        evidence: value,
        source_sha256: None,
    }
}

fn evidence_from_source(
    collector: impl Into<String>,
    source: impl Into<String>,
    excerpt: impl Into<String>,
    raw_source: &[u8],
) -> SourceEvidence {
    let mut result = evidence(collector, source, excerpt);
    result.source_sha256 = Some(format!("{:x}", Sha256::digest(raw_source)));
    result
}

fn compare_passes(passes: &[CoveragePass]) -> Vec<SemanticDrift> {
    let Some(baseline) = passes.first() else {
        return Vec::new();
    };
    passes
        .iter()
        .enumerate()
        .skip(1)
        .filter_map(|(index, current)| {
            let baseline_rows: BTreeMap<_, _> = baseline
                .rows
                .iter()
                .map(|row| (row.endpoint.clone(), row))
                .collect();
            let current_rows: BTreeMap<_, _> = current
                .rows
                .iter()
                .map(|row| (row.endpoint.clone(), row))
                .collect();
            let mut endpoints: Vec<_> = baseline_rows
                .keys()
                .chain(current_rows.keys())
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .filter(|endpoint| {
                    match (baseline_rows.get(endpoint), current_rows.get(endpoint)) {
                        (Some(before), Some(after)) => !same_semantics(before, after),
                        (None, None) => false,
                        _ => true,
                    }
                })
                .collect();
            if baseline.device.boot_id != current.device.boot_id {
                endpoints.push("@device.boot_id".to_string());
            }
            if baseline.device.fingerprint != current.device.fingerprint {
                endpoints.push("@device.fingerprint".to_string());
            }
            endpoints.sort();
            endpoints.dedup();
            (!endpoints.is_empty()).then_some(SemanticDrift {
                baseline_pass: 1,
                current_pass: index + 1,
                endpoints,
            })
        })
        .collect()
}

fn same_semantics(before: &CoverageRow, after: &CoverageRow) -> bool {
    before.endpoint == after.endpoint
        && before.declared == after.declared
        && before.live == after.live
        && before.transport == after.transport
        && before.owner == after.owner
        && before.attribution.confidence == after.attribution.confidence
}

fn summarize(rows: &[CoverageRow]) -> CoverageSummary {
    CoverageSummary {
        exact: rows
            .iter()
            .filter(|row| row.attribution.confidence == "exact")
            .count(),
        unresolved: rows
            .iter()
            .filter(|row| row.attribution.confidence == "unresolved")
            .count(),
        ambiguous: rows
            .iter()
            .filter(|row| row.attribution.confidence == "ambiguous")
            .count(),
    }
}

fn render_tsv(document: &CoverageDocument) -> String {
    let mut output = String::from(
        "endpoint\tdeclared\tlive\ttransport\tattribution\tpid\tstarttime\tboot_id\tselinux_domain\texecutable\tcollectors\thealth\n",
    );
    for row in &document.rows {
        let owner = row.owner.as_ref();
        let collectors = row
            .attribution
            .sources
            .iter()
            .map(|source| source.collector.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(",");
        let fields = [
            row.endpoint.clone(),
            row.declared.to_string(),
            row.live.to_string(),
            row.transport.clone(),
            row.attribution.confidence.clone(),
            owner.map(|owner| owner.pid.to_string()).unwrap_or_default(),
            owner
                .map(|owner| owner.starttime.to_string())
                .unwrap_or_default(),
            owner.map(|owner| owner.boot_id.clone()).unwrap_or_default(),
            owner
                .map(|owner| owner.selinux_domain.clone())
                .unwrap_or_default(),
            owner
                .map(|owner| owner.executable.clone())
                .unwrap_or_default(),
            collectors,
            document.health.status.clone(),
        ];
        output.push_str(
            &fields
                .iter()
                .map(|field| tsv_cell(field))
                .collect::<Vec<_>>()
                .join("\t"),
        );
        output.push('\n');
    }
    output
}

fn tsv_cell(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn target_reader_rejects_a_fifo_without_blocking() {
        let directory = std::env::temp_dir().join(format!(
            "neutron-coverage-unit-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let fifo = directory.join("targets.fifo");
        let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);

        let started = Instant::now();
        let error = read_target_file(&fifo).unwrap_err();
        assert!(error.to_string().contains("single-link regular file"));
        assert!(started.elapsed() < Duration::from_millis(500));

        fs::remove_dir_all(directory).unwrap();
    }
}
