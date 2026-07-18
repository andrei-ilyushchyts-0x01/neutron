//! Run-bundle verification and typed external evidence import.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

const MAX_IMPORTED_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ANNOTATION_BYTES: u64 = 1024 * 1024;
const MAX_PROBE_IDENTITY_BYTES: u64 = 64 * 1024;
const MAX_VERIFIED_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_VERIFIED_BUNDLE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_BUNDLE_FILES: usize = 16_384;
const MAX_BUNDLE_DEPTH: usize = 32;

#[derive(Subcommand, Debug)]
pub enum EvidenceCommand {
    /// Verify every artifact listed by a run bundle without following links.
    Verify(VerifyArgs),
    /// Copy a bounded external result into a run bundle as typed evidence.
    Import(ImportArgs),
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    pub run_dir: PathBuf,
}

#[derive(Args, Debug)]
pub struct ImportArgs {
    #[arg(long)]
    pub run_dir: PathBuf,
    #[arg(long)]
    pub input: PathBuf,
    #[arg(long)]
    pub id: String,
    #[arg(long, value_enum)]
    pub claim: ClaimType,
    #[arg(long)]
    pub imported_from: String,
    /// Exact neutron service ID this external observation annotates.
    #[arg(long)]
    pub subject_id: String,
    /// JSON object with procedure, caller, and a positive attempt_count.
    /// Required for `not-observed-clean`; never implies global reachability.
    #[arg(long)]
    pub claim_scope: Option<ExternalClaimScope>,
    /// External probe's typed build/install/runtime identity JSON.
    /// Required for app behavioral claims.
    #[arg(long)]
    pub probe_identity: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "unknown")]
    pub health_status: EvidenceHealth,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimType {
    Declared,
    LiveMapped,
    ObservedEdge,
    NotObservedClean,
    LookupUnavailable,
    CallDenied,
    CallSucceeded,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceHealth {
    Complete,
    Degraded,
    Incomplete,
    Unknown,
}

/// Explicitly bounded behavioral scope for evidence measured by an external
/// probe. Free-form labels are retained for interoperability, but the
/// procedure, caller model, and numeric attempt bound cannot be conflated.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalClaimScope {
    pub procedure: String,
    pub caller: String,
    pub attempt_count: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeInstallState {
    InstalledEnabled,
    InstalledDisabled,
    NotInstalled,
    Unknown,
}

/// Runtime identity asserted by the external probe collector. This is kept
/// separate from Neutron-measured evidence and binds ordinary-app claims to a
/// concrete APK, signer, install, UID, permission set, and device boot.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalProbeRuntimeIdentity {
    pub schema: String,
    pub apk_sha256: String,
    pub signing_certificate_sha256: String,
    pub package: String,
    pub version_code: u64,
    pub version_name: String,
    pub target_sdk: u32,
    pub device_boot_id: String,
    pub uid: u32,
    pub install_state: ProbeInstallState,
    pub granted_permissions: Vec<String>,
}

impl FromStr for ExternalClaimScope {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let scope: Self = serde_json::from_str(value).map_err(|error| {
            format!(
                "claim scope must be JSON like {{\"procedure\":\"direct_call\",\"caller\":\"ordinary_installed_app\",\"attempt_count\":1}}: {error}"
            )
        })?;
        validate_external_claim_scope(&scope).map_err(|error| error.to_string())?;
        Ok(scope)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEvidence {
    pub schema: String,
    pub id: String,
    pub subject_id: String,
    pub measured_by: String,
    pub claim_type: ClaimType,
    pub imported_from: String,
    pub artifact_path: String,
    pub artifact_sha256: String,
    pub health_status: EvidenceHealth,
    pub claim_scope: Option<ExternalClaimScope>,
    pub probe_identity: Option<ExternalProbeRuntimeIdentity>,
}

pub fn run(command: EvidenceCommand) -> Result<()> {
    match command {
        EvidenceCommand::Verify(args) => verify(&args.run_dir),
        EvidenceCommand::Import(args) => import(args),
    }
}

pub fn verify(run_dir: &Path) -> Result<()> {
    let verified = verify_bundle(run_dir)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": "neutron.evidence-verification/v1",
            "status": "integrity_verified",
            "authenticity": "not_verified",
            "scope": "internal_content_hashes_and_contracts",
            "artifacts": verified,
        }))?
    );
    Ok(())
}

fn verify_bundle(run_dir: &Path) -> Result<u64> {
    verify_directory(run_dir)?;
    let manifest_path = run_dir.join("manifest.json");
    let manifest = read_regular_beneath(run_dir, Path::new("manifest.json"), MAX_MANIFEST_BYTES)?;
    let manifest: crate::run_manifest::RunManifest = serde_json::from_slice(&manifest)
        .with_context(|| format!("parsing {}", manifest_path.display()))?;
    crate::run_manifest::verify_static_manifest(run_dir, &manifest)?;

    let sums = String::from_utf8(read_regular_beneath(
        run_dir,
        Path::new("SHA256SUMS"),
        MAX_CHECKSUM_BYTES,
    )?)
    .context("SHA256SUMS is not UTF-8")?;
    let mut seen = BTreeSet::new();
    let mut verified = 0_u64;
    let mut verified_bytes = 0_u64;
    for (line_number, line) in sums.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let (expected, relative) = line.split_once("  ").ok_or_else(|| {
            anyhow::anyhow!("invalid SHA256SUMS line {}", line_number.saturating_add(1))
        })?;
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("invalid SHA-256 on line {}", line_number.saturating_add(1));
        }
        let relative = safe_relative_path(relative)?;
        let relative_text = relative.to_string_lossy().into_owned();
        if !seen.insert(relative_text.clone()) {
            bail!("duplicate artifact path in SHA256SUMS: {relative_text}");
        }
        let (actual, artifact_bytes) =
            hash_file_beneath(run_dir, &relative, Some(MAX_VERIFIED_ARTIFACT_BYTES))?;
        verified_bytes = verified_bytes
            .checked_add(artifact_bytes)
            .context("verified bundle byte count overflow")?;
        if verified_bytes > MAX_VERIFIED_BUNDLE_BYTES {
            bail!("verified bundle exceeds {MAX_VERIFIED_BUNDLE_BYTES} bytes");
        }
        if !actual.eq_ignore_ascii_case(expected) {
            bail!("SHA-256 mismatch for {relative_text}: expected {expected}, got {actual}");
        }
        verified = verified.saturating_add(1);
    }
    if !seen.contains("manifest.json") {
        bail!("SHA256SUMS does not cover manifest.json");
    }
    let mut bundle_files = Vec::new();
    collect_regular_files(run_dir, run_dir, &mut bundle_files, 0)?;
    for relative in bundle_files {
        let relative_text = relative.to_string_lossy();
        if relative != Path::new("SHA256SUMS") && !seen.contains(relative_text.as_ref()) {
            bail!("SHA256SUMS does not cover artifact: {relative_text}");
        }
    }
    verify_external_evidence(run_dir)?;
    Ok(verified)
}

fn import(args: ImportArgs) -> Result<()> {
    verify_private_owned_directory(&args.run_dir)?;
    let _mutation_lock = EvidenceMutationLock::acquire(&args.run_dir)?;
    // Never refresh hashes over an already-tampered bundle. Keep the lock for
    // the complete verify/create/reseal transaction so imports cannot race.
    verify_bundle(&args.run_dir)?;
    validate_id(&args.id)?;
    validate_label("imported-from", &args.imported_from)?;
    validate_subject_id(&args.subject_id)?;
    if let Some(scope) = args.claim_scope.as_ref() {
        validate_external_claim_scope(scope)?;
    }
    verify_subject_if_coverage_present(&args.run_dir, &args.subject_id)?;
    if args.claim == ClaimType::NotObservedClean && args.health_status != EvidenceHealth::Complete {
        bail!("not_observed_clean requires complete health");
    }
    if args.claim == ClaimType::NotObservedClean && args.claim_scope.is_none() {
        bail!("not_observed_clean requires an explicit bounded --claim-scope");
    }
    let probe_identity = match args.probe_identity.as_deref() {
        Some(path) => {
            let identity: ExternalProbeRuntimeIdentity =
                serde_json::from_slice(&read_regular(path, Some(MAX_PROBE_IDENTITY_BYTES))?)
                    .with_context(|| {
                        format!("parsing external probe identity {}", path.display())
                    })?;
            validate_probe_runtime_identity(&identity)?;
            verify_probe_identity_matches_run(&args.run_dir, &identity)?;
            Some(identity)
        }
        None => None,
    };
    if claim_requires_probe_identity(args.claim) && probe_identity.is_none() {
        bail!("behavioral app evidence requires --probe-identity");
    }

    let artifact = read_regular(&args.input, Some(MAX_IMPORTED_ARTIFACT_BYTES))?;
    let artifact_sha256 = hash_bytes(&artifact);
    let external_dir = args.run_dir.join("external-evidence");
    ensure_private_directory(&external_dir)?;
    let artifact_name = format!("{}.artifact", args.id);
    let annotation_name = format!("{}.json", args.id);
    let artifact_path = external_dir.join(&artifact_name);
    let annotation_path = external_dir.join(&annotation_name);
    require_missing_import_destination(&artifact_path)?;
    require_missing_import_destination(&annotation_path)?;
    let annotation = ExternalEvidence {
        schema: "neutron.external-evidence/v1".into(),
        id: args.id,
        subject_id: args.subject_id,
        measured_by: "external_probe".into(),
        claim_type: args.claim,
        imported_from: args.imported_from,
        artifact_path: format!("external-evidence/{artifact_name}"),
        artifact_sha256,
        health_status: args.health_status,
        claim_scope: args.claim_scope,
        probe_identity,
    };
    let mut artifact_created = false;
    let mut annotation_created = false;
    let result = (|| -> Result<()> {
        crate::private_output::write(&artifact_path, &artifact, false)?;
        artifact_created = true;
        crate::private_output::write_json(&annotation_path, &annotation, false)?;
        annotation_created = true;
        refresh_checksums_locked(&args.run_dir)
    })();
    if let Err(error) = result {
        if annotation_created {
            let _ = fs::remove_file(&annotation_path);
        }
        if artifact_created {
            let _ = fs::remove_file(&artifact_path);
        }
        let _ = refresh_checksums_locked(&args.run_dir);
        return Err(error).context("external evidence import rolled back");
    }
    Ok(())
}

fn verify_external_evidence(run_dir: &Path) -> Result<()> {
    let external_dir = run_dir.join("external-evidence");
    match fs::symlink_metadata(&external_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspecting external-evidence"),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("external-evidence must be a real directory")
        }
        Ok(_) => {}
    }
    let mut actual_files = BTreeSet::new();
    for entry in fs::read_dir(&external_dir).context("reading external-evidence")? {
        let entry = entry?;
        let metadata = entry
            .file_type()
            .with_context(|| format!("inspecting {}", entry.path().display()))?;
        if !metadata.is_file() || metadata.is_symlink() {
            bail!(
                "external-evidence may contain only regular files: {}",
                entry.path().display()
            );
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("external-evidence filename is not UTF-8"))?;
        if !actual_files.insert(name) {
            bail!("duplicate external-evidence filename");
        }
    }

    if !actual_files.contains("SHA256SUMS") {
        bail!("external-evidence is missing SHA256SUMS");
    }
    let nested_sums = String::from_utf8(read_regular_beneath(
        &external_dir,
        Path::new("SHA256SUMS"),
        MAX_CHECKSUM_BYTES,
    )?)
    .context("external-evidence/SHA256SUMS is not UTF-8")?;
    let mut nested_seen = BTreeSet::new();
    for (line_number, line) in nested_sums.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let (expected, relative) = line.split_once("  ").ok_or_else(|| {
            anyhow::anyhow!(
                "invalid external-evidence/SHA256SUMS line {}",
                line_number.saturating_add(1)
            )
        })?;
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!(
                "invalid external evidence SHA-256 on line {}",
                line_number.saturating_add(1)
            );
        }
        let relative = safe_relative_path(relative)?;
        if relative.components().count() != 1 || relative == Path::new("SHA256SUMS") {
            bail!("external evidence checksum paths must name one evidence file");
        }
        let name = relative.to_string_lossy().into_owned();
        if !nested_seen.insert(name.clone()) {
            bail!("duplicate path in external-evidence/SHA256SUMS: {name}");
        }
        let (actual, _) =
            hash_file_beneath(&external_dir, &relative, Some(MAX_VERIFIED_ARTIFACT_BYTES))?;
        if !actual.eq_ignore_ascii_case(expected) {
            bail!("external evidence SHA-256 mismatch for {name}");
        }
    }

    let expected_nested: BTreeSet<String> = actual_files
        .iter()
        .filter(|name| name.as_str() != "SHA256SUMS")
        .cloned()
        .collect();
    if nested_seen != expected_nested {
        bail!("external-evidence/SHA256SUMS does not exactly cover its directory");
    }

    let mut attributed_files = BTreeSet::from(["SHA256SUMS".to_string()]);
    for name in actual_files.iter().filter(|name| name.ends_with(".json")) {
        let path = external_dir.join(name);
        let annotation: ExternalEvidence = serde_json::from_slice(&read_regular_beneath(
            &external_dir,
            Path::new(name),
            MAX_ANNOTATION_BYTES,
        )?)
        .with_context(|| format!("parsing {}", path.display()))?;
        if annotation.schema != "neutron.external-evidence/v1"
            || annotation.measured_by != "external_probe"
        {
            bail!("invalid external evidence contract in {}", path.display());
        }
        validate_id(&annotation.id)?;
        validate_label("imported-from", &annotation.imported_from)?;
        validate_subject_id(&annotation.subject_id)?;
        verify_subject_if_coverage_present(run_dir, &annotation.subject_id)?;
        if annotation.claim_type == ClaimType::NotObservedClean
            && annotation.health_status != EvidenceHealth::Complete
        {
            bail!("not_observed_clean requires complete health");
        }
        if annotation.claim_type == ClaimType::NotObservedClean && annotation.claim_scope.is_none()
        {
            bail!("not_observed_clean requires an explicit bounded claim_scope");
        }
        if let Some(scope) = annotation.claim_scope.as_ref() {
            validate_external_claim_scope(scope)?;
        }
        if let Some(identity) = annotation.probe_identity.as_ref() {
            validate_probe_runtime_identity(identity)?;
            verify_probe_identity_matches_run(run_dir, identity)?;
        }
        if claim_requires_probe_identity(annotation.claim_type)
            && annotation.probe_identity.is_none()
        {
            bail!("behavioral app evidence requires a probe_identity");
        }
        let expected_annotation = format!("{}.json", annotation.id);
        if path.file_name().and_then(|value| value.to_str()) != Some(expected_annotation.as_str()) {
            bail!("external evidence annotation filename does not match its id");
        }
        let expected_artifact = format!("external-evidence/{}.artifact", annotation.id);
        if annotation.artifact_path != expected_artifact {
            bail!("external evidence artifact path does not match its id");
        }
        attributed_files.insert(expected_annotation);
        attributed_files.insert(format!("{}.artifact", annotation.id));
        if annotation.artifact_sha256.len() != 64
            || !annotation
                .artifact_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("external evidence artifact hash is not SHA-256");
        }
        let artifact_relative = safe_relative_path(&annotation.artifact_path)?;
        let (actual, _) = hash_file_beneath(
            run_dir,
            &artifact_relative,
            Some(MAX_VERIFIED_ARTIFACT_BYTES),
        )?;
        if actual != annotation.artifact_sha256 {
            bail!(
                "external evidence artifact hash mismatch: {}",
                path.display()
            );
        }
    }
    if attributed_files != actual_files {
        bail!("external-evidence contains orphan or unattributed files");
    }
    Ok(())
}

pub fn refresh_checksums(run_dir: &Path) -> Result<()> {
    verify_private_owned_directory(run_dir)?;
    let _mutation_lock = EvidenceMutationLock::acquire(run_dir)?;
    refresh_checksums_locked(run_dir)
}

fn refresh_checksums_locked(run_dir: &Path) -> Result<()> {
    verify_directory(run_dir)?;
    let mut files = Vec::new();
    collect_regular_files(run_dir, run_dir, &mut files, 0)?;
    files.sort();
    let mut external_lines = String::new();
    for relative in &files {
        if relative == Path::new("SHA256SUMS")
            || relative == Path::new("external-evidence/SHA256SUMS")
        {
            continue;
        }
        let (hash, _) = hash_file_beneath(run_dir, relative, None)?;
        if let Ok(external_relative) = relative.strip_prefix("external-evidence") {
            external_lines.push_str(&format!(
                "{hash}  {}\n",
                external_relative.to_string_lossy()
            ));
        }
    }
    let external_dir = run_dir.join("external-evidence");
    if external_dir.is_dir() {
        crate::private_output::write(
            &external_dir.join("SHA256SUMS"),
            external_lines.as_bytes(),
            true,
        )?;
    }

    // Build the root manifest after the nested manifest exists so every
    // artifact except the root checksum file itself is content-addressed.
    files.clear();
    collect_regular_files(run_dir, run_dir, &mut files, 0)?;
    files.sort();
    let mut root_lines = String::new();
    for relative in files {
        if relative == Path::new("SHA256SUMS") {
            continue;
        }
        let (hash, _) = hash_file_beneath(run_dir, &relative, None)?;
        root_lines.push_str(&format!("{hash}  {}\n", relative.to_string_lossy()));
    }
    crate::private_output::write(&run_dir.join("SHA256SUMS"), root_lines.as_bytes(), true)?;
    Ok(())
}

fn require_missing_import_destination(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
        Ok(_) => bail!("external evidence id already exists: {}", path.display()),
    }
}

/// Cross-process checksum mutation lock stored beside (never inside) the run
/// bundle, so verification cannot mistake it for an evidence artifact.
struct EvidenceMutationLock {
    file: File,
}

impl EvidenceMutationLock {
    fn acquire(run_dir: &Path) -> Result<Self> {
        let parent = run_dir
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let name = run_dir
            .file_name()
            .context("run directory must end in a directory name")?
            .to_string_lossy();
        let path = parent.join(format!(".{name}.neutron-evidence.lock"));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)
            .with_context(|| format!("opening evidence mutation lock {}", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("inspecting evidence mutation lock {}", path.display()))?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            bail!(
                "evidence mutation lock must be an owned, single-link private regular file: {}",
                path.display()
            );
        }
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", path.display()))?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            bail!(
                "another evidence mutation is already in progress for {}: {}",
                run_dir.display(),
                error
            );
        }
        Ok(Self { file })
    }
}

impl Drop for EvidenceMutationLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn collect_regular_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<PathBuf>,
    depth: usize,
) -> Result<()> {
    if depth > MAX_BUNDLE_DEPTH {
        bail!("bundle nesting exceeds {MAX_BUNDLE_DEPTH} directories");
    }
    for entry in fs::read_dir(directory)
        .with_context(|| format!("reading bundle directory {}", directory.display()))?
    {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            bail!("bundle contains symlink: {}", path.display());
        }
        if metadata.is_dir() {
            collect_regular_files(root, &path, files, depth.saturating_add(1))?;
        } else if metadata.is_file() {
            files.push(path.strip_prefix(root)?.to_path_buf());
            if files.len() > MAX_BUNDLE_FILES {
                bail!("bundle contains more than {MAX_BUNDLE_FILES} files");
            }
        } else {
            bail!("bundle contains non-regular artifact: {}", path.display());
        }
    }
    Ok(())
}

fn verify_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting run directory {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("run directory must be a real directory: {}", path.display());
    }
    Ok(())
}

fn verify_private_owned_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting private run directory {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        bail!(
            "external evidence import requires an owned mode-private run directory: {}",
            path.display()
        );
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!(
                "artifact directory must be a real directory: {}",
                path.display()
            )
        }
        Ok(metadata) => {
            if metadata.uid() != unsafe { libc::geteuid() } {
                bail!("artifact directory is not owned by the current user");
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn read_regular(path: &Path, maximum: Option<u64>) -> Result<Vec<u8>> {
    let mut file = open_regular(path, maximum)?;
    let mut bytes = Vec::new();
    match maximum {
        Some(limit) => {
            file.take(limit.saturating_add(1))
                .read_to_end(&mut bytes)
                .with_context(|| format!("reading artifact {}", path.display()))?;
            if bytes.len() as u64 > limit {
                bail!("artifact exceeds the {limit} byte import limit");
            }
        }
        None => {
            file.read_to_end(&mut bytes)
                .with_context(|| format!("reading artifact {}", path.display()))?;
        }
    }
    Ok(bytes)
}

fn open_regular(path: &Path, maximum: Option<u64>) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening regular artifact {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting regular artifact {}", path.display()))?;
    if !metadata.is_file() {
        bail!("artifact must be a regular file: {}", path.display());
    }
    if metadata.nlink() != 1 {
        bail!("artifact must have one link: {}", path.display());
    }
    if let Some(limit) = maximum {
        if metadata.len() > limit {
            bail!("artifact exceeds the {limit} byte import limit");
        }
    }
    Ok(file)
}

fn safe_relative_path(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_))
                || component
                    .as_os_str()
                    .to_string_lossy()
                    .chars()
                    .any(|character| matches!(character, '\n' | '\r' | '\0'))
        })
    {
        bail!("unsafe artifact path: {value}");
    }
    Ok(path.to_path_buf())
}

fn hash_file_beneath(root: &Path, relative: &Path, maximum: Option<u64>) -> Result<(String, u64)> {
    let file = crate::private_output::open_regular_beneath(root, relative, maximum)?;
    let length = file.metadata()?.len();
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
    Ok((format!("{:x}", hasher.finalize()), length))
}

fn read_regular_beneath(root: &Path, relative: &Path, maximum: u64) -> Result<Vec<u8>> {
    let file = crate::private_output::open_regular_beneath(root, relative, Some(maximum))?;
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading artifact {}", relative.display()))?;
    if bytes.len() as u64 > maximum {
        bail!("artifact exceeds the {maximum} byte limit");
    }
    Ok(bytes)
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("evidence id must use 1-128 ASCII letters, digits, dot, underscore, or dash");
    }
    Ok(())
}

fn validate_label(name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        bail!("{name} must be a bounded printable string");
    }
    Ok(())
}

fn validate_external_claim_scope(scope: &ExternalClaimScope) -> Result<()> {
    validate_label("claim-scope procedure", &scope.procedure)?;
    validate_label("claim-scope caller", &scope.caller)?;
    if scope.attempt_count == 0 || scope.attempt_count > 1_000_000 {
        bail!("claim-scope attempt_count must be within 1..=1000000");
    }
    Ok(())
}

fn claim_requires_probe_identity(claim: ClaimType) -> bool {
    matches!(
        claim,
        ClaimType::NotObservedClean
            | ClaimType::LookupUnavailable
            | ClaimType::CallDenied
            | ClaimType::CallSucceeded
    )
}

fn validate_probe_runtime_identity(identity: &ExternalProbeRuntimeIdentity) -> Result<()> {
    if identity.schema != "neutron.external-probe-runtime/v1" {
        bail!("probe identity schema must be neutron.external-probe-runtime/v1");
    }
    validate_lower_hex("probe identity apk_sha256", &identity.apk_sha256, 64)?;
    validate_lower_hex(
        "probe identity signing_certificate_sha256",
        &identity.signing_certificate_sha256,
        64,
    )?;
    if identity.package.is_empty()
        || identity.package.len() > 255
        || !identity
            .package
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_'))
        || !identity.package.contains('.')
    {
        bail!("probe identity package must be a bounded Android package name");
    }
    if identity.version_code == 0 {
        bail!("probe identity version_code must be greater than zero");
    }
    validate_label("probe identity version_name", &identity.version_name)?;
    if identity.target_sdk == 0 || identity.target_sdk > 10_000 {
        bail!("probe identity target_sdk is outside the supported numeric bound");
    }
    if !is_lower_uuid(&identity.device_boot_id) {
        bail!("probe identity device_boot_id must be a lowercase UUID");
    }
    if identity.uid == 0 {
        bail!("probe identity uid must be greater than zero");
    }
    if identity.install_state != ProbeInstallState::InstalledEnabled {
        bail!("behavioral probe identity must record install_state=installed_enabled");
    }
    if identity.granted_permissions.len() > 256 {
        bail!("probe identity granted_permissions exceeds 256 entries");
    }
    let mut previous: Option<&str> = None;
    for permission in &identity.granted_permissions {
        if permission.is_empty()
            || permission.len() > 512
            || !permission.bytes().all(|byte| byte.is_ascii_graphic())
        {
            bail!("probe identity granted_permissions contains an invalid permission");
        }
        if previous.is_some_and(|value| value >= permission.as_str()) {
            bail!("probe identity granted_permissions must be sorted and unique");
        }
        previous = Some(permission);
    }
    Ok(())
}

fn validate_lower_hex(name: &str, value: &str, length: usize) -> Result<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{name} must contain exactly {length} lowercase hexadecimal characters");
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

fn validate_subject_id(value: &str) -> Result<()> {
    if !value.starts_with("service:")
        || value.len() > 4096
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        bail!("subject-id must be an exact printable neutron service ID");
    }
    Ok(())
}

fn verify_probe_identity_matches_run(
    run_dir: &Path,
    identity: &ExternalProbeRuntimeIdentity,
) -> Result<()> {
    let manifest: crate::run_manifest::RunManifest = serde_json::from_slice(&read_regular_beneath(
        run_dir,
        Path::new("manifest.json"),
        MAX_MANIFEST_BYTES,
    )?)
    .context("parsing manifest.json for probe identity binding")?;
    let run_boot_id = manifest
        .device
        .boot_id
        .as_deref()
        .context("behavioral app evidence requires a run manifest device boot_id")?;
    if run_boot_id != identity.device_boot_id {
        bail!("probe identity device_boot_id does not match the run manifest boot_id");
    }
    Ok(())
}

fn verify_subject_if_coverage_present(run_dir: &Path, subject_id: &str) -> Result<()> {
    let path = run_dir.join("surface.coverage.json");
    if !path.exists() {
        return Ok(());
    }
    let document: serde_json::Value = serde_json::from_slice(&read_regular_beneath(
        run_dir,
        Path::new("surface.coverage.json"),
        MAX_MANIFEST_BYTES,
    )?)
    .context("parsing surface.coverage.json")?;
    let present = document
        .get("rows")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|rows| {
            rows.iter().any(|row| {
                let endpoint = row.get("endpoint").and_then(serde_json::Value::as_str);
                let transport = row.get("transport").and_then(serde_json::Value::as_str);
                match (transport, endpoint) {
                    (Some(transport), Some(endpoint)) => {
                        format!("service:{transport}:{endpoint}") == subject_id
                    }
                    _ => false,
                }
            })
        });
    if !present {
        bail!("subject-id is not present in surface.coverage.json");
    }
    Ok(())
}
