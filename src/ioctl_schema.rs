//! Host-generated, data-only ioctl ABI schemas and the bounded runtime decoder.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{OnceLock, RwLock};

use anyhow::{bail, Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const SCHEMA_VERSION: &str = "neutron.ioctl-schema/v1";
const MAX_PACK_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DESCRIPTORS: usize = 4096;
const MAX_LAYOUTS: usize = 4096;
const MAX_FIELDS: usize = 256;
const MAX_REFRESH_CMDS: usize = 64;
const CAPTURE_BYTES: usize = 124;

#[derive(Args, Debug, Clone)]
pub struct GenerateArgs {
    /// Kernel source tree containing the selected UAPI/vendor headers.
    #[arg(long)]
    pub kernel_tree: PathBuf,

    /// Header root relative to --kernel-tree (repeatable).
    #[arg(long, required = true)]
    pub headers: Vec<PathBuf>,

    /// Output directory, or an explicit .json pack path.
    #[arg(long)]
    pub output: PathBuf,

    /// Optional compile_commands.json used for include/define/target flags.
    #[arg(long)]
    pub compile_commands: Option<PathBuf>,

    /// Additional clang argument (repeatable).
    #[arg(long, allow_hyphen_values = true)]
    pub clang_arg: Vec<String>,

    /// Optional exact driver mapping overrides.
    #[arg(long)]
    pub manifest: Option<PathBuf>,

    /// Also emit stable Rust constants for an embedded baseline.
    #[arg(long)]
    pub emit_rust: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Selectors {
    #[serde(default)]
    pub fingerprint: Vec<String>,
    #[serde(default)]
    pub device: Vec<String>,
    #[serde(default)]
    pub kernel_release: Vec<String>,
}

impl Selectors {
    fn matches(&self, identity: &RuntimeIdentity) -> bool {
        selector_matches(&self.fingerprint, identity.fingerprint.as_deref())
            && selector_matches(&self.device, identity.device.as_deref())
            && selector_matches(&self.kernel_release, identity.kernel_release.as_deref())
    }

    fn specificity(&self) -> usize {
        [&self.fingerprint, &self.device, &self.kernel_release]
            .into_iter()
            .filter(|values| !values.is_empty())
            .count()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackMetadata {
    pub name: String,
    pub target_abi: String,
    #[serde(default)]
    pub selectors: Selectors,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    #[serde(default)]
    pub clang_invocation: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub name: String,
    pub offset: u32,
    pub size: u32,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    #[serde(default)]
    pub opaque: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PointerDirection {
    In,
    Out,
    InOut,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PointerDescriptor {
    pub field: String,
    pub pointee_layout: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length_expression: Option<String>,
    pub direction: PointerDirection,
}

impl Field {
    pub fn scalar(name: &str, offset: u32, size: u32, kind: &str) -> Self {
        Self {
            name: name.into(),
            offset,
            size,
            kind: kind.into(),
            count: None,
            opaque: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub id: String,
    pub name: String,
    pub cmd: u32,
    pub magic: u32,
    pub nr: u32,
    pub direction: u32,
    pub size: u32,
    pub type_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default)]
    pub fd_paths: Vec<String>,
    #[serde(default)]
    pub fields: Vec<Field>,
    pub capture_eligible: bool,
    #[serde(default)]
    pub provenance: Vec<String>,
    #[serde(default)]
    pub replaces: Vec<String>,
    #[serde(default)]
    pub pointers: Vec<PointerDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Layout {
    pub id: String,
    pub type_name: String,
    pub size: u32,
    pub align: u32,
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DriverEvidence {
    pub descriptor_id: String,
    pub confidence: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SchemaPack {
    pub schema: String,
    pub metadata: PackMetadata,
    pub descriptors: Vec<Descriptor>,
    #[serde(default)]
    pub layouts: Vec<Layout>,
    #[serde(default)]
    pub driver_evidence: Vec<DriverEvidence>,
    pub content_hash: String,
}

impl SchemaPack {
    pub fn seal(&mut self) -> Result<()> {
        self.validate_model()?;
        self.content_hash.clear();
        self.content_hash = content_hash(self)?;
        Ok(())
    }

    pub fn verify(&self, identity: &RuntimeIdentity) -> Result<()> {
        self.verify_for(identity, true)
    }

    fn verify_for(&self, identity: &RuntimeIdentity, match_selectors: bool) -> Result<()> {
        self.validate_model()?;
        if self.metadata.target_abi != "any" && self.metadata.target_abi != identity.abi {
            bail!(
                "schema pack ABI '{}' does not match runtime ABI '{}'",
                self.metadata.target_abi,
                identity.abi
            );
        }
        if match_selectors && !self.metadata.selectors.matches(identity) {
            bail!("schema pack selectors do not match this runtime");
        }
        let expected = content_hash(self)?;
        if self.content_hash != expected {
            bail!("schema pack content hash mismatch");
        }
        Ok(())
    }

    fn validate_model(&self) -> Result<()> {
        if self.schema != SCHEMA_VERSION {
            bail!("unsupported ioctl schema version '{}'", self.schema);
        }
        if self.metadata.name.is_empty() || self.metadata.target_abi.is_empty() {
            bail!("schema pack name and target ABI must be non-empty");
        }
        if self.descriptors.len() > MAX_DESCRIPTORS || self.layouts.len() > MAX_LAYOUTS {
            bail!("schema pack exceeds descriptor/layout limits");
        }
        let mut ids = HashSet::new();
        for descriptor in &self.descriptors {
            if !ids.insert(&descriptor.id) {
                bail!("duplicate descriptor id '{}'", descriptor.id);
            }
            if descriptor.id.is_empty()
                || descriptor.name.is_empty()
                || descriptor.fields.len() > MAX_FIELDS
                || descriptor.magic > 0xff
                || descriptor.nr > 0xff
                || descriptor.direction > 3
                || descriptor.size > 0x3fff
                || descriptor.magic != ((descriptor.cmd >> 8) & 0xff)
                || descriptor.nr != (descriptor.cmd & 0xff)
                || descriptor.direction != ((descriptor.cmd >> 30) & 3)
                || descriptor.size != ((descriptor.cmd >> 16) & 0x3fff)
            {
                bail!("invalid descriptor '{}'", descriptor.id);
            }
            for field in &descriptor.fields {
                let end = field
                    .offset
                    .checked_add(field.size)
                    .context("field offset overflow")?;
                if field.name.is_empty()
                    || (!field.opaque && field.size == 0)
                    || end > descriptor.size
                    || !valid_field_type(field)
                {
                    bail!("invalid field '{}' in '{}'", field.name, descriptor.id);
                }
            }
            let eligible = descriptor.fields.iter().any(|field| {
                !field.opaque && field.offset.saturating_add(field.size) <= CAPTURE_BYTES as u32
            });
            if descriptor.capture_eligible != eligible {
                bail!("invalid capture eligibility for '{}'", descriptor.id);
            }
        }
        for layout in &self.layouts {
            if layout.id.is_empty() || !ids.insert(&layout.id) || layout.fields.len() > MAX_FIELDS {
                bail!("layout '{}' exceeds field limit", layout.id);
            }
            for field in &layout.fields {
                let end = field
                    .offset
                    .checked_add(field.size)
                    .context("layout field offset overflow")?;
                if field.name.is_empty()
                    || (!field.opaque && field.size == 0)
                    || end > layout.size
                    || !valid_field_type(field)
                {
                    bail!("invalid field '{}' in layout '{}'", field.name, layout.id);
                }
            }
        }
        for descriptor in &self.descriptors {
            for pointer in &descriptor.pointers {
                let field = descriptor
                    .fields
                    .iter()
                    .find(|field| field.name == pointer.field && field.kind == "pointer")
                    .with_context(|| {
                        format!(
                            "pointer '{}' in '{}' does not name a pointer field",
                            pointer.field, descriptor.id
                        )
                    })?;
                if field.size != 8
                    || !self
                        .layouts
                        .iter()
                        .any(|layout| layout.id == pointer.pointee_layout)
                    || (pointer.length_field.is_some() == pointer.length_expression.is_some())
                {
                    bail!(
                        "invalid pointer descriptor '{}' in '{}'",
                        pointer.field,
                        descriptor.id
                    );
                }
                if let Some(length_field) = &pointer.length_field {
                    if !descriptor.fields.iter().any(|candidate| {
                        candidate.name == *length_field
                            && candidate.count.is_none()
                            && matches!(candidate.size, 1 | 2 | 4 | 8)
                    }) {
                        bail!(
                            "pointer '{}' in '{}' has unknown length field '{}'",
                            pointer.field,
                            descriptor.id,
                            length_field
                        );
                    }
                }
                if pointer
                    .length_expression
                    .as_deref()
                    .is_some_and(|expression| expression.trim().is_empty())
                {
                    bail!("empty pointer length expression in '{}'", descriptor.id);
                }
            }
        }
        for evidence in &self.driver_evidence {
            if !matches!(evidence.confidence.as_str(), "exact" | "candidate")
                || !self
                    .descriptors
                    .iter()
                    .any(|descriptor| descriptor.id == evidence.descriptor_id)
            {
                bail!("invalid driver evidence for '{}'", evidence.descriptor_id);
            }
        }
        Ok(())
    }
}

fn valid_field_type(field: &Field) -> bool {
    if field.opaque {
        return true;
    }
    matches!(
        field.kind.as_str(),
        "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" | "bool" | "pointer" | "enum"
    ) && field.count.map_or(true, |count| {
        count > 0
            && field
                .size
                .checked_rem(count)
                .is_some_and(|remainder| remainder == 0)
    })
}

fn content_hash(pack: &SchemaPack) -> Result<String> {
    let mut unsigned = pack.clone();
    unsigned.content_hash.clear();
    let bytes = serde_json::to_vec(&unsigned).context("serializing schema for content hash")?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

#[derive(Debug, Clone)]
pub struct RuntimeIdentity {
    pub abi: String,
    pub fingerprint: Option<String>,
    pub device: Option<String>,
    pub kernel_release: Option<String>,
}

impl RuntimeIdentity {
    pub fn current() -> Self {
        Self {
            abi: std::env::consts::ARCH.into(),
            fingerprint: getprop("ro.build.fingerprint"),
            device: getprop("ro.product.device"),
            kernel_release: fs::read_to_string("/proc/sys/kernel/osrelease")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        }
    }
}

fn getprop(key: &str) -> Option<String> {
    let output = Command::new("/system/bin/getprop").arg(key).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn selector_matches(patterns: &[String], value: Option<&str>) -> bool {
    patterns.is_empty()
        || value.is_some_and(|value| patterns.iter().any(|pattern| glob_matches(pattern, value)))
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == value;
    }
    let mut rest = value;
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        let Some(offset) = rest.find(part) else {
            return false;
        };
        if index == 0 && !pattern.starts_with('*') && offset != 0 {
            return false;
        }
        rest = &rest[offset + part.len()..];
    }
    pattern.ends_with('*') || rest.is_empty()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GenericIoctlFields {
    pub expected_size: u32,
    pub captured_size: u32,
    pub truncated: bool,
    pub values: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericDecodedIoctl {
    pub name: String,
    pub family: Option<String>,
    pub fields: GenericIoctlFields,
}

#[derive(Debug, Clone, Default)]
pub struct SchemaRegistry {
    descriptors: Vec<Descriptor>,
    layouts: HashMap<String, Layout>,
    refresh_cmds: BTreeSet<u32>,
}

impl SchemaRegistry {
    pub fn from_packs(packs: Vec<SchemaPack>) -> Result<Self> {
        let mut descriptors: Vec<Descriptor> = Vec::new();
        let mut layouts = HashMap::new();
        for pack in packs {
            pack.validate_model()?;
            for layout in pack.layouts {
                match layouts.get(&layout.id) {
                    Some(existing) if existing != &layout => {
                        bail!("conflicting layout '{}'", layout.id)
                    }
                    Some(_) => {}
                    None => {
                        layouts.insert(layout.id.clone(), layout);
                    }
                }
            }
            for mut descriptor in pack.descriptors {
                descriptor.fd_paths.sort();
                descriptor.fd_paths.dedup();
                if descriptors.iter().any(|existing| existing == &descriptor) {
                    continue;
                }
                if !descriptor.replaces.is_empty() {
                    descriptors.retain(|existing| !descriptor.replaces.contains(&existing.id));
                }
                if let Some(existing) = descriptors.iter().find(|existing| {
                    existing.id == descriptor.id || same_scope(existing, &descriptor)
                }) {
                    bail!(
                        "descriptor '{}' conflicts with '{}'; later pack must declare replaces",
                        descriptor.id,
                        existing.id
                    );
                }
                descriptors.push(descriptor);
            }
        }
        let refresh_cmds: BTreeSet<u32> = descriptors
            .iter()
            .filter(|d| d.capture_eligible && matches!(d.direction, 2 | 3))
            .map(|d| d.cmd)
            .collect();
        if refresh_cmds.len() > MAX_REFRESH_CMDS {
            bail!(
                "schema packs require {} ioctl refresh commands; BPF capacity is {}",
                refresh_cmds.len(),
                MAX_REFRESH_CMDS
            );
        }
        Ok(Self {
            descriptors,
            layouts,
            refresh_cmds,
        })
    }

    pub fn descriptor(
        &self,
        cmd: u32,
        fd_path: Option<&str>,
        family: Option<&str>,
    ) -> Option<&Descriptor> {
        self.descriptors
            .iter()
            .enumerate()
            .filter(|(_, descriptor)| {
                descriptor.cmd == cmd
                    && descriptor.family.as_deref().map_or(true, |required| {
                        family.map_or(true, |actual| actual == required)
                    })
                    && (descriptor.fd_paths.is_empty()
                        || fd_path.is_some_and(|path| {
                            descriptor
                                .fd_paths
                                .iter()
                                .any(|pattern| glob_matches(pattern, path))
                        }))
            })
            .max_by_key(|(index, descriptor)| {
                let path_specificity = descriptor
                    .fd_paths
                    .iter()
                    .map(|pattern| pattern.bytes().filter(|byte| *byte != b'*').count())
                    .max()
                    .unwrap_or(0);
                (
                    path_specificity,
                    usize::from(descriptor.family.is_some()),
                    *index,
                )
            })
            .map(|(_, descriptor)| descriptor)
    }

    pub fn layout(&self, id: &str) -> Option<&Layout> {
        self.layouts.get(id)
    }

    pub fn decode(
        &self,
        cmd: u32,
        payload: &[u8],
        fd_path: Option<&str>,
        family: Option<&str>,
    ) -> Option<GenericDecodedIoctl> {
        let descriptor = self.descriptor(cmd, fd_path, family)?;
        Some(GenericDecodedIoctl {
            name: descriptor.name.clone(),
            family: descriptor.family.clone(),
            fields: decode_fields(descriptor, payload),
        })
    }

    pub fn refresh_cmds(&self) -> impl Iterator<Item = u32> + '_ {
        self.refresh_cmds.iter().copied()
    }
}

fn same_scope(left: &Descriptor, right: &Descriptor) -> bool {
    left.cmd == right.cmd && left.family == right.family && left.fd_paths == right.fd_paths
}

fn decode_fields(descriptor: &Descriptor, payload: &[u8]) -> GenericIoctlFields {
    let captured = payload
        .len()
        .min(CAPTURE_BYTES)
        .min(descriptor.size as usize);
    let mut values = BTreeMap::new();
    for field in &descriptor.fields {
        let start = field.offset as usize;
        let end = start.saturating_add(field.size as usize);
        if field.opaque || end > captured {
            continue;
        }
        if let Some(value) = decode_field(field, &payload[start..end]) {
            values.insert(field.name.clone(), value);
        }
    }
    GenericIoctlFields {
        expected_size: descriptor.size,
        captured_size: captured as u32,
        truncated: captured < descriptor.size as usize,
        values,
    }
}

fn decode_field(field: &Field, bytes: &[u8]) -> Option<Value> {
    if let Some(count) = field.count {
        let width = bytes.len().checked_div(count as usize)?;
        if width == 0 || width * count as usize != bytes.len() {
            return None;
        }
        return (0..count as usize)
            .map(|index| decode_scalar(&field.kind, &bytes[index * width..(index + 1) * width]))
            .collect::<Option<Vec<_>>>()
            .map(Value::Array);
    }
    decode_scalar(&field.kind, bytes)
}

fn decode_scalar(kind: &str, bytes: &[u8]) -> Option<Value> {
    let unsigned = || {
        let mut value = [0u8; 8];
        value[..bytes.len()].copy_from_slice(bytes);
        u64::from_le_bytes(value)
    };
    match (kind, bytes.len()) {
        ("u8" | "u16" | "u32" | "u64" | "pointer" | "enum", 1 | 2 | 4 | 8) => {
            Some(Value::from(unsigned()))
        }
        ("i8" | "i16" | "i32" | "i64", 1 | 2 | 4 | 8) => {
            let shift = 64 - bytes.len() * 8;
            Some(Value::from(((unsigned() << shift) as i64) >> shift))
        }
        ("bool", 1 | 2 | 4 | 8) => Some(Value::from(unsigned() != 0)),
        _ => None,
    }
}

static ACTIVE_REGISTRY: OnceLock<RwLock<SchemaRegistry>> = OnceLock::new();

pub fn install_registry(registry: SchemaRegistry) {
    *ACTIVE_REGISTRY
        .get_or_init(|| RwLock::new(SchemaRegistry::default()))
        .write()
        .expect("ioctl schema registry poisoned") = registry;
}

pub fn decode_active(
    cmd: u32,
    payload: &[u8],
    fd_path: Option<&str>,
    family: Option<&str>,
) -> Option<GenericDecodedIoctl> {
    ACTIVE_REGISTRY
        .get()?
        .read()
        .ok()?
        .decode(cmd, payload, fd_path, family)
}

pub fn load_selected_packs(
    explicit: &[String],
    no_auto: bool,
    identity: &RuntimeIdentity,
) -> Result<Vec<SchemaPack>> {
    if !explicit.is_empty() {
        return explicit
            .iter()
            .map(|value| {
                resolve_explicit_pack(value)
                    .and_then(|path| load_pack_with_selectors(&path, identity, false))
            })
            .collect();
    }
    if no_auto {
        return Ok(Vec::new());
    }
    let mut packs = Vec::new();
    for directory in schema_directories() {
        if !trusted_directory(&directory) {
            continue;
        }
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
        paths.sort();
        for path in paths {
            let path = if path.is_dir() {
                path.join("schema.json")
            } else {
                path
            };
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            if !trusted_pack_file(&path) {
                log::warn!("ignoring untrusted schema pack {}", path.display());
                continue;
            }
            match load_pack(&path, identity) {
                Ok(pack) => packs.push(pack),
                Err(error) => log::warn!("ignoring schema pack {}: {error:#}", path.display()),
            }
        }
    }
    packs.sort_by(|left, right| {
        left.metadata
            .selectors
            .specificity()
            .cmp(&right.metadata.selectors.specificity())
            .then_with(|| natural_cmp(&left.metadata.name, &right.metadata.name))
    });
    Ok(packs)
}

pub fn load_pack(path: &Path, identity: &RuntimeIdentity) -> Result<SchemaPack> {
    load_pack_with_selectors(path, identity, true)
}

fn load_pack_with_selectors(
    path: &Path,
    identity: &RuntimeIdentity,
    match_selectors: bool,
) -> Result<SchemaPack> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("reading schema pack metadata {}", path.display()))?;
    if metadata.len() > MAX_PACK_BYTES {
        bail!("schema pack exceeds {} bytes", MAX_PACK_BYTES);
    }
    let bytes =
        fs::read(path).with_context(|| format!("reading schema pack {}", path.display()))?;
    let pack: SchemaPack = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing schema pack {}", path.display()))?;
    pack.verify_for(identity, match_selectors)
        .with_context(|| format!("validating schema pack {}", path.display()))?;
    Ok(pack)
}

fn schema_directories() -> Vec<PathBuf> {
    let mut directories = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(prefix) = exe.parent().and_then(Path::parent) {
            directories.push(prefix.join("share/neutron/schemas"));
        }
    }
    directories.extend([
        PathBuf::from("/system/etc/neutron/schemas"),
        PathBuf::from("/vendor/etc/neutron/schemas"),
        PathBuf::from("/data/local/tmp/neutron/schemas"),
    ]);
    directories
}

fn resolve_explicit_pack(value: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if path.exists() {
        return Ok(if path.is_dir() {
            path.join("schema.json")
        } else {
            path
        });
    }
    for directory in schema_directories() {
        for candidate in [
            directory.join(value),
            directory.join(format!("{value}.json")),
        ] {
            if candidate.exists() {
                return Ok(if candidate.is_dir() {
                    candidate.join("schema.json")
                } else {
                    candidate
                });
            }
        }
    }
    bail!("schema pack '{value}' was not found")
}

#[cfg(unix)]
fn trusted_directory(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path)
        .map(|metadata| metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
        .unwrap_or(false)
}

#[cfg(unix)]
fn trusted_pack_file(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn trusted_directory(_path: &Path) -> bool {
    false
}

#[cfg(not(unix))]
fn trusted_pack_file(_path: &Path) -> bool {
    false
}

fn natural_cmp(left: &str, right: &str) -> Ordering {
    let mut left = left.as_bytes();
    let mut right = right.as_bytes();
    while !left.is_empty() && !right.is_empty() {
        if left[0].is_ascii_digit() && right[0].is_ascii_digit() {
            let ln = left
                .iter()
                .position(|b| !b.is_ascii_digit())
                .unwrap_or(left.len());
            let rn = right
                .iter()
                .position(|b| !b.is_ascii_digit())
                .unwrap_or(right.len());
            let left_digits = &left[..ln];
            let right_digits = &right[..rn];
            let left_value = left_digits.iter().position(|byte| *byte != b'0').map_or(
                &left_digits[left_digits.len().saturating_sub(1)..],
                |start| &left_digits[start..],
            );
            let right_value = right_digits.iter().position(|byte| *byte != b'0').map_or(
                &right_digits[right_digits.len().saturating_sub(1)..],
                |start| &right_digits[start..],
            );
            let order = left_value
                .len()
                .cmp(&right_value.len())
                .then_with(|| left_value.cmp(right_value))
                .then_with(|| left_digits.len().cmp(&right_digits.len()));
            if order != Ordering::Equal {
                return order;
            }
            left = &left[ln..];
            right = &right[rn..];
        } else {
            let order = left[0].cmp(&right[0]);
            if order != Ordering::Equal {
                return order;
            }
            left = &left[1..];
            right = &right[1..];
        }
    }
    left.len().cmp(&right.len())
}

pub fn generate(args: &GenerateArgs) -> Result<()> {
    let kernel_tree = args
        .kernel_tree
        .canonicalize()
        .with_context(|| format!("canonicalizing {}", args.kernel_tree.display()))?;
    let mut headers = Vec::new();
    for root in &args.headers {
        let root = kernel_tree.join(root).canonicalize().with_context(|| {
            format!(
                "canonicalizing header root {}",
                kernel_tree.join(root).display()
            )
        })?;
        if !root.starts_with(&kernel_tree) {
            bail!("header root {} escapes kernel tree", root.display());
        }
        collect_headers(&root, &kernel_tree, &mut headers, &mut HashSet::new())?;
    }
    headers.sort();
    headers.dedup();
    if headers.len() > 10_000 {
        bail!("header scan exceeds 10000 files");
    }

    let discovered = discover_macro_names(&headers)?;
    let ioctl_headers = headers_defining(&headers, &discovered)?;
    let mut clang_args = compile_database_args(args.compile_commands.as_deref())?;
    if !clang_args
        .iter()
        .any(|arg| arg == "--target" || arg.starts_with("--target="))
        && !args
            .clang_arg
            .iter()
            .any(|arg| arg == "--target" || arg.starts_with("--target="))
    {
        clang_args.push("--target=aarch64-linux-gnu".into());
    }
    for include in default_include_paths(&kernel_tree, &args.headers) {
        clang_args.push(format!("-I{}", include.display()));
    }
    clang_args.extend(args.clang_arg.clone());
    let tu = synthetic_tu(&ioctl_headers, &[]);
    let definitions = clang_definitions(&tu, &clang_args)?;
    let mut candidates = Vec::new();
    for name in discovered {
        if let Some(body) = resolve_ioctl_body(&name, &definitions, 0) {
            candidates.push((name, body));
        } else {
            eprintln!("neutron: unresolved ioctl macro {name}");
        }
    }
    let constants = clang_constants(&ioctl_headers, &candidates, &clang_args)?;
    let layouts = clang_layouts(&ioctl_headers, &clang_args)?;
    let manifest = read_manifest(args.manifest.as_deref())?;
    let mut descriptors = Vec::new();
    let mut used_layouts = BTreeMap::new();
    let mut evidence = Vec::new();

    for (name, body) in candidates {
        let Some(cmd) = constants.get(&name).copied() else {
            eprintln!("neutron: unresolved ioctl macro {name}");
            continue;
        };
        let type_name = ioctl_type_argument(&body).unwrap_or_default();
        let layout = layouts.get(&type_name);
        let fields = layout
            .map(|layout| layout.fields.clone())
            .unwrap_or_default();
        if !type_name.is_empty() && layout.is_none() {
            eprintln!("neutron: unresolved ioctl type {type_name} for {name}");
        }
        let mapping = manifest.get(&name);
        let id = natural_id(&name);
        let provenance = macro_provenance(&ioctl_headers, &name);
        evidence.push(DriverEvidence {
            descriptor_id: id.clone(),
            confidence: mapping
                .map_or("candidate", |m| m.confidence.as_str())
                .into(),
            evidence: mapping
                .map(|m| m.evidence.clone())
                .unwrap_or_else(|| "header association only".into()),
        });
        if let Some(layout) = layout {
            used_layouts.insert(layout.id.clone(), layout.clone());
        }
        if let Some(mapping) = mapping {
            for pointer in &mapping.pointers {
                if let Some(layout) = layouts
                    .values()
                    .find(|layout| layout.id == pointer.pointee_layout)
                {
                    used_layouts.insert(layout.id.clone(), layout.clone());
                }
            }
        }
        let size = (cmd >> 16) & 0x3fff;
        descriptors.push(Descriptor {
            id,
            name,
            cmd,
            magic: (cmd >> 8) & 0xff,
            nr: cmd & 0xff,
            direction: (cmd >> 30) & 3,
            size,
            type_name,
            family: mapping.and_then(|m| m.family.clone()),
            fd_paths: mapping.map(|m| m.fd_paths.clone()).unwrap_or_default(),
            capture_eligible: fields.iter().any(|field| {
                !field.opaque && field.offset.saturating_add(field.size) <= CAPTURE_BYTES as u32
            }),
            fields,
            provenance,
            replaces: mapping.map(|m| m.replaces.clone()).unwrap_or_default(),
            pointers: mapping.map(|m| m.pointers.clone()).unwrap_or_default(),
        });
    }
    descriptors.sort_by(|left, right| natural_cmp(&left.id, &right.id));
    let mut unique: Vec<Descriptor> = Vec::new();
    for mut descriptor in descriptors {
        if let Some(existing) = unique.iter_mut().find(|existing| {
            existing.cmd == descriptor.cmd
                && existing.type_name == descriptor.type_name
                && existing.family == descriptor.family
                && existing.fd_paths == descriptor.fd_paths
                && existing.fields == descriptor.fields
        }) {
            existing.provenance.append(&mut descriptor.provenance);
            existing.provenance.sort();
            existing.provenance.dedup();
        } else {
            unique.push(descriptor);
        }
    }
    descriptors = unique;
    if descriptors.is_empty() {
        bail!("no valid ioctl descriptors were generated");
    }
    let descriptor_ids: HashSet<&str> = descriptors.iter().map(|d| d.id.as_str()).collect();
    evidence.retain(|item| descriptor_ids.contains(item.descriptor_id.as_str()));
    evidence.sort_by(|left, right| natural_cmp(&left.descriptor_id, &right.descriptor_id));
    let invocation = std::iter::once("clang".to_string())
        .chain(clang_args.iter().cloned())
        .collect();
    let mut pack = SchemaPack {
        schema: SCHEMA_VERSION.into(),
        metadata: PackMetadata {
            name: output_name(&args.output),
            target_abi: target_abi(&clang_args),
            selectors: Selectors::default(),
            source_revision: git_revision(&kernel_tree),
            clang_invocation: invocation,
        },
        descriptors,
        layouts: used_layouts.into_values().collect(),
        driver_evidence: evidence,
        content_hash: String::new(),
    };
    pack.seal()?;
    SchemaRegistry::from_packs(vec![pack.clone()])
        .context("generated descriptor conflicts or refresh policy")?;
    let bytes = serde_json::to_vec_pretty(&pack).context("serializing generated schema pack")?;
    if bytes.len() as u64 > MAX_PACK_BYTES {
        bail!("generated schema pack exceeds {} bytes", MAX_PACK_BYTES);
    }
    let output = pack_output_path(&args.output);
    atomic_write(&output, &bytes)?;
    if let Some(path) = &args.emit_rust {
        atomic_write(path, emit_rust(&pack).as_bytes())?;
    }
    Ok(())
}

fn collect_headers(
    directory: &Path,
    kernel_tree: &Path,
    output: &mut Vec<PathBuf>,
    visited: &mut HashSet<PathBuf>,
) -> Result<()> {
    let directory = directory.canonicalize()?;
    if !directory.starts_with(kernel_tree) || !visited.insert(directory.clone()) {
        return Ok(());
    }
    let mut entries: Vec<_> = fs::read_dir(&directory)
        .with_context(|| format!("reading header root {}", directory.display()))?
        .collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let canonical = path
            .canonicalize()
            .with_context(|| format!("canonicalizing header path {}", path.display()))?;
        if !canonical.starts_with(kernel_tree) {
            continue;
        }
        if canonical.is_dir() {
            collect_headers(&canonical, kernel_tree, output, visited)?;
        } else if canonical.extension().and_then(|value| value.to_str()) == Some("h") {
            output.push(canonical);
        }
    }
    Ok(())
}

fn discover_macro_names(headers: &[PathBuf]) -> Result<BTreeSet<String>> {
    let mut definitions = BTreeMap::new();
    for header in headers {
        let source = fs::read_to_string(header)
            .with_context(|| format!("reading header {}", header.display()))?;
        for line in logical_lines(&source) {
            if let Some((name, body)) = parse_object_define(&line) {
                definitions.insert(name, body);
            }
        }
    }
    let mut selected: BTreeSet<String> = definitions
        .iter()
        .filter(|(_, body)| contains_ioctl_invocation(body))
        .map(|(name, _)| name.clone())
        .collect();
    loop {
        let aliases: Vec<String> = definitions
            .iter()
            .filter(|(name, body)| {
                !selected.contains(*name)
                    && body
                        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                        .any(|token| selected.contains(token))
            })
            .map(|(name, _)| name.clone())
            .collect();
        if aliases.is_empty() {
            break;
        }
        selected.extend(aliases);
    }
    Ok(selected)
}

fn headers_defining(headers: &[PathBuf], names: &BTreeSet<String>) -> Result<Vec<PathBuf>> {
    let mut selected = Vec::new();
    for header in headers {
        let source = fs::read_to_string(header)
            .with_context(|| format!("reading header {}", header.display()))?;
        if logical_lines(&source)
            .iter()
            .any(|line| parse_object_define(line).is_some_and(|(name, _)| names.contains(&name)))
        {
            selected.push(header.clone());
        }
    }
    Ok(selected)
}

fn logical_lines(source: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for line in source.lines() {
        current.push_str(line.trim_end_matches('\\'));
        if line.ends_with('\\') {
            current.push(' ');
        } else {
            lines.push(std::mem::take(&mut current));
        }
    }
    lines
}

fn parse_object_define(line: &str) -> Option<(String, String)> {
    let rest = line.trim_start().strip_prefix("#define")?.trim_start();
    let split = rest.find(char::is_whitespace)?;
    let name = &rest[..split];
    if name.contains('(') || name.is_empty() {
        return None;
    }
    Some((name.into(), rest[split..].trim().into()))
}

fn contains_ioctl_invocation(body: &str) -> bool {
    ["_IO(", "_IOR(", "_IOW(", "_IOWR("]
        .iter()
        .any(|needle| body.contains(needle))
}

fn synthetic_tu(headers: &[PathBuf], tail: &[String]) -> String {
    let mut source = String::new();
    for header in headers {
        source.push_str(&format!("#include {:?}\n", header));
    }
    for line in tail {
        source.push_str(line);
        source.push('\n');
    }
    source
}

fn run_clang(source: &str, args: &[String], extra: &[&str]) -> Result<std::process::Output> {
    let mut child = Command::new("clang")
        .args(args)
        .args(extra)
        .arg("-x")
        .arg("c")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("starting clang")?;
    child
        .stdin
        .take()
        .context("opening clang stdin")?
        .write_all(source.as_bytes())
        .context("writing clang translation unit")?;
    let output = child.wait_with_output().context("waiting for clang")?;
    if !output.status.success() {
        bail!(
            "clang failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output)
}

fn clang_definitions(source: &str, args: &[String]) -> Result<BTreeMap<String, String>> {
    let output = run_clang(source, args, &["-E", "-dM"])?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_object_define)
        .collect())
}

fn resolve_ioctl_body(
    name: &str,
    definitions: &BTreeMap<String, String>,
    depth: usize,
) -> Option<String> {
    if depth > 16 {
        return None;
    }
    let body = definitions.get(name)?.trim();
    if contains_ioctl_invocation(body) {
        return Some(body.into());
    }
    let alias = body
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .find(|token| definitions.contains_key(*token))?;
    resolve_ioctl_body(alias, definitions, depth + 1)
}

fn clang_constants(
    headers: &[PathBuf],
    candidates: &[(String, String)],
    args: &[String],
) -> Result<HashMap<String, u32>> {
    let tail: Vec<String> = candidates
        .iter()
        .enumerate()
        .map(|(index, (name, _))| format!("enum {{ __neutron_{index} = (unsigned int)({name}) }};"))
        .collect();
    let output = run_clang(
        &synthetic_tu(headers, &tail),
        args,
        &["-Xclang", "-ast-dump=json", "-fsyntax-only"],
    )?;
    let ast: Value = serde_json::from_slice(&output.stdout).context("parsing clang AST JSON")?;
    let mut values = HashMap::new();
    collect_enum_values(&ast, &mut values);
    Ok(candidates
        .iter()
        .enumerate()
        .filter_map(|(index, (name, _))| {
            values
                .get(&format!("__neutron_{index}"))
                .copied()
                .map(|value| (name.clone(), value as u32))
        })
        .collect())
}

fn collect_enum_values(value: &Value, output: &mut HashMap<String, u64>) {
    if value.get("kind").and_then(Value::as_str) == Some("EnumConstantDecl") {
        if let Some(name) = value.get("name").and_then(Value::as_str) {
            if let Some(number) = find_ast_value(value) {
                output.insert(name.into(), number);
            }
        }
    }
    match value {
        Value::Array(values) => values
            .iter()
            .for_each(|value| collect_enum_values(value, output)),
        Value::Object(values) => values
            .values()
            .for_each(|value| collect_enum_values(value, output)),
        _ => {}
    }
}

fn find_ast_value(value: &Value) -> Option<u64> {
    if let Some(value) = value.get("value").and_then(Value::as_str) {
        return value.parse().ok();
    }
    value
        .get("inner")?
        .as_array()?
        .iter()
        .find_map(find_ast_value)
}

fn clang_layouts(headers: &[PathBuf], args: &[String]) -> Result<BTreeMap<String, Layout>> {
    let output = run_clang(
        &synthetic_tu(headers, &[]),
        args,
        &["-Xclang", "-fdump-record-layouts-complete", "-fsyntax-only"],
    )?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(parse_layout_dump(&text))
}

fn parse_layout_dump(text: &str) -> BTreeMap<String, Layout> {
    let blocks = text.split("*** Dumping AST Record Layout").skip(1);
    let mut layouts = BTreeMap::new();
    for block in blocks {
        let mut lines = block.lines().filter(|line| line.contains('|'));
        let Some(header) = lines.next() else { continue };
        let Some((_, raw_type)) = header.split_once('|') else {
            continue;
        };
        let type_name = raw_type.trim().to_string();
        if !(type_name.starts_with("struct ") || type_name.starts_with("union ")) {
            continue;
        }
        let mut raw_fields = Vec::new();
        let mut size = 0;
        let mut align = 0;
        for line in lines {
            let Some((raw_offset, raw_field)) = line.split_once('|') else {
                continue;
            };
            if let Some(summary) = raw_field.trim().strip_prefix("[sizeof=") {
                let values: Vec<_> = summary.trim_end_matches(']').split(',').collect();
                size = values.first().and_then(|v| v.parse().ok()).unwrap_or(0);
                align = values
                    .get(1)
                    .and_then(|v| v.trim().strip_prefix("align="))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                break;
            }
            if raw_field.starts_with("   ") && !raw_field.starts_with("     ") {
                raw_fields.push((raw_offset.trim().to_string(), raw_field.trim().to_string()));
            }
        }
        if size == 0 {
            continue;
        }
        let mut fields: Vec<Field> = raw_fields
            .iter()
            .enumerate()
            .map(|(index, (offset, declaration))| {
                layout_field(offset, declaration, size, raw_fields.get(index + 1))
            })
            .collect();
        if type_name.starts_with("union ") {
            fields.iter_mut().for_each(|field| field.opaque = true);
        }
        layouts.insert(
            type_name.clone(),
            Layout {
                id: natural_id(&type_name),
                type_name,
                size,
                align,
                fields,
            },
        );
    }
    layouts
}

fn layout_field(
    raw_offset: &str,
    declaration: &str,
    layout_size: u32,
    next: Option<&(String, String)>,
) -> Field {
    let bitfield = raw_offset.contains(':');
    let offset = raw_offset
        .split(':')
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let name = declaration
        .split_whitespace()
        .last()
        .unwrap_or("_anonymous")
        .trim_start_matches('*')
        .to_string();
    let raw_type = declaration
        .strip_suffix(&name)
        .unwrap_or(declaration)
        .trim()
        .trim_end_matches('*')
        .trim();
    let (kind, count, known_size, opaque) = classify_c_type(raw_type, declaration);
    let next_offset = next
        .and_then(|(value, _)| value.split(':').next()?.parse().ok())
        .unwrap_or(layout_size);
    Field {
        name,
        offset,
        size: known_size.unwrap_or_else(|| next_offset.saturating_sub(offset)),
        kind,
        count,
        opaque: opaque || bitfield,
    }
}

fn classify_c_type(raw_type: &str, declaration: &str) -> (String, Option<u32>, Option<u32>, bool) {
    if declaration.contains('*') {
        return ("pointer".into(), None, None, false);
    }
    if let Some(open) = raw_type.rfind('[') {
        let count = raw_type[open + 1..]
            .trim_end_matches(']')
            .parse::<u32>()
            .ok();
        let (kind, _, size, opaque) = classify_c_type(raw_type[..open].trim(), raw_type);
        return (
            kind,
            count,
            count.zip(size).map(|(count, size)| count * size),
            opaque || count.is_none(),
        );
    }
    let normalized = raw_type.trim_start_matches("const ").trim();
    let (kind, size) = match normalized {
        "char" | "signed char" | "__s8" | "int8_t" => ("i8", 1),
        "unsigned char" | "__u8" | "uint8_t" => ("u8", 1),
        "short" | "short int" | "__s16" | "int16_t" => ("i16", 2),
        "unsigned short" | "__u16" | "uint16_t" => ("u16", 2),
        "int" | "__s32" | "int32_t" => ("i32", 4),
        "unsigned" | "unsigned int" | "__u32" | "uint32_t" => ("u32", 4),
        "long" | "long long" | "__s64" | "int64_t" => ("i64", 8),
        "unsigned long" | "unsigned long long" | "__u64" | "uint64_t" => ("u64", 8),
        "_Bool" | "bool" => ("bool", 1),
        value if value.starts_with("enum ") => ("enum", 4),
        _ => return ("opaque".into(), None, None, true),
    };
    (kind.into(), None, Some(size), false)
}

fn ioctl_type_argument(body: &str) -> Option<String> {
    let (_, start) = ["_IOWR(", "_IOR(", "_IOW(", "_IO("]
        .iter()
        .filter_map(|needle| body.find(needle).map(|index| (*needle, index)))
        .min_by_key(|(_, index)| *index)?;
    let open = body[start..].find('(')? + start;
    let args = split_c_args(&body[open + 1..body.rfind(')')?]);
    args.get(2).map(|value| value.trim().to_string())
}

fn split_c_args(value: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (index, ch) in value.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                args.push(value[start..index].trim().into());
                start = index + 1;
            }
            _ => {}
        }
    }
    args.push(value[start..].trim().into());
    args
}

fn default_include_paths(kernel: &Path, roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = roots.iter().map(|root| kernel.join(root)).collect();
    paths.extend([
        kernel.join("include/uapi"),
        kernel.join("include"),
        kernel.join("include/generated/uapi"),
        kernel.join("include/generated"),
        kernel.join("arch/arm64/include/uapi"),
        kernel.join("arch/arm64/include"),
        kernel.join("arch/arm64/include/generated/uapi"),
        kernel.join("arch/arm64/include/generated"),
    ]);
    paths.retain(|path| path.exists());
    paths.sort();
    paths.dedup();
    paths
}

fn compile_database_args(path: Option<&Path>) -> Result<Vec<String>> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let value: Value = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("parsing {}", path.display()))?;
    let entry = value
        .as_array()
        .and_then(|entries| entries.first())
        .context("compile database is empty")?;
    let directory = entry
        .get("directory")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            path.parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf()
        });
    let raw: Vec<String> = if let Some(args) = entry.get("arguments").and_then(Value::as_array) {
        args.iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    } else if let Some(command) = entry.get("command").and_then(Value::as_str) {
        split_command_line(command)?
    } else {
        bail!("compile database entry has no arguments or command");
    };
    let mut filtered = Vec::new();
    let mut index = 1;
    while index < raw.len() {
        let arg = &raw[index];
        if matches!(
            arg.as_str(),
            "-I" | "-D" | "-U" | "-isystem" | "-include" | "--target"
        ) {
            if let Some(value) = raw.get(index + 1) {
                filtered.push(arg.clone());
                filtered.push(
                    if matches!(arg.as_str(), "-I" | "-isystem" | "-include")
                        && Path::new(value).is_relative()
                    {
                        directory.join(value).to_string_lossy().into_owned()
                    } else {
                        value.clone()
                    },
                );
                index += 2;
                continue;
            }
        } else if let Some(include) = arg.strip_prefix("-I").filter(|value| !value.is_empty()) {
            filtered.push(format!(
                "-I{}",
                if Path::new(include).is_relative() {
                    directory.join(include).to_string_lossy().into_owned()
                } else {
                    include.into()
                }
            ));
        } else if arg.starts_with("-D")
            || arg.starts_with("-U")
            || arg.starts_with("--target=")
            || arg.starts_with("-std=")
        {
            filtered.push(arg.clone());
        }
        index += 1;
    }
    Ok(filtered)
}

fn split_command_line(command: &str) -> Result<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    for ch in command.chars() {
        if escaped {
            word.push(ch);
            escaped = false;
        } else if ch == '\\' && quote != Some('\'') {
            escaped = true;
        } else if matches!(ch, '\'' | '"') {
            if quote == Some(ch) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(ch);
            } else {
                word.push(ch);
            }
        } else if ch.is_whitespace() && quote.is_none() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
        } else {
            word.push(ch);
        }
    }
    if escaped || quote.is_some() {
        bail!("unterminated quote or escape in compile database command");
    }
    if !word.is_empty() {
        words.push(word);
    }
    Ok(words)
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ManifestEntry {
    family: Option<String>,
    #[serde(default)]
    fd_paths: Vec<String>,
    #[serde(default = "exact_confidence")]
    confidence: String,
    #[serde(default = "manifest_evidence")]
    evidence: String,
    #[serde(default)]
    replaces: Vec<String>,
    #[serde(default)]
    pointers: Vec<PointerDescriptor>,
}

fn exact_confidence() -> String {
    "exact".into()
}
fn manifest_evidence() -> String {
    "manifest override".into()
}

fn read_manifest(path: Option<&Path>) -> Result<BTreeMap<String, ManifestEntry>> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    let value: Value = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("parsing {}", path.display()))?;
    let mappings = value.get("descriptors").unwrap_or(&value).clone();
    serde_json::from_value(mappings).context("parsing driver manifest mappings")
}

fn macro_provenance(headers: &[PathBuf], name: &str) -> Vec<String> {
    headers
        .iter()
        .filter_map(|header| {
            fs::read_to_string(header).ok().and_then(|source| {
                source.lines().enumerate().find_map(|(line, text)| {
                    text.contains(name)
                        .then(|| format!("{}:{}", header.display(), line + 1))
                })
            })
        })
        .collect()
}

fn natural_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '.'
            }
        })
        .collect::<String>()
        .split('.')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(".")
}

fn target_abi(args: &[String]) -> String {
    args.iter()
        .enumerate()
        .find_map(|(index, arg)| {
            arg.strip_prefix("--target=").or_else(|| {
                (arg == "--target")
                    .then(|| args.get(index + 1))
                    .flatten()
                    .map(String::as_str)
            })
        })
        .map(|target| target.split('-').next().unwrap_or(target).to_string())
        .unwrap_or_else(|| "aarch64".into())
}

fn git_revision(kernel_tree: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(kernel_tree)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn output_name(path: &Path) -> String {
    path.file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("generated")
        .to_string()
}

fn pack_output_path(path: &Path) -> PathBuf {
    if path.extension().and_then(|value| value.to_str()) == Some("json") {
        path.into()
    } else {
        path.join("schema.json")
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("output path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .with_context(|| format!("creating temporary output {}", temporary.display()))?;
    let result = (|| {
        file.write_all(bytes)
            .with_context(|| format!("writing temporary output {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing temporary output {}", temporary.display()))?;
        fs::rename(&temporary, path)
            .with_context(|| format!("installing generated output {}", path.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    Ok(())
}

fn emit_rust(pack: &SchemaPack) -> String {
    let mut output = String::from(
        "// @generated by neutron ioctl generate; do not edit.\n\
         pub struct Field { pub name: &'static str, pub offset: u32, pub size: u32, pub kind: &'static str, pub count: Option<u32>, pub opaque: bool }\n\
         pub struct PointerDescriptor { pub field: &'static str, pub pointee_layout: &'static str, pub length_field: Option<&'static str>, pub length_expression: Option<&'static str>, pub direction: &'static str }\n\
         pub struct IoctlDescriptor { pub id: &'static str, pub name: &'static str, pub cmd: u32, pub magic: u32, pub nr: u32, pub direction: u32, pub size: u32, pub type_name: &'static str, pub family: Option<&'static str>, pub fd_paths: &'static [&'static str], pub capture_eligible: bool, pub provenance: &'static [&'static str], pub replaces: &'static [&'static str], pub fields: &'static [Field], pub pointers: &'static [PointerDescriptor] }\n\n",
    );
    for (index, descriptor) in pack.descriptors.iter().enumerate() {
        output.push_str(&format!("const FIELDS_{index}: &[Field] = &[\n"));
        for field in &descriptor.fields {
            output.push_str(&format!(
                "    Field {{ name: {:?}, offset: {}, size: {}, kind: {:?}, count: {:?}, opaque: {} }},\n",
                field.name, field.offset, field.size, field.kind, field.count, field.opaque
            ));
        }
        output.push_str("];\n");
        output.push_str(&format!(
            "const POINTERS_{index}: &[PointerDescriptor] = &[\n"
        ));
        for pointer in &descriptor.pointers {
            let direction = match pointer.direction {
                PointerDirection::In => "in",
                PointerDirection::Out => "out",
                PointerDirection::InOut => "in_out",
            };
            output.push_str(&format!(
                "    PointerDescriptor {{ field: {:?}, pointee_layout: {:?}, length_field: {:?}, length_expression: {:?}, direction: {:?} }},\n",
                pointer.field,
                pointer.pointee_layout,
                pointer.length_field.as_deref(),
                pointer.length_expression.as_deref(),
                direction,
            ));
        }
        output.push_str("];\n");
    }
    output.push_str("pub const IOCTL_DESCRIPTORS: &[IoctlDescriptor] = &[\n");
    for (index, descriptor) in pack.descriptors.iter().enumerate() {
        output.push_str(&format!(
            "    IoctlDescriptor {{ id: {:?}, name: {:?}, cmd: {:#010x}, magic: {}, nr: {}, direction: {}, size: {}, type_name: {:?}, family: {:?}, fd_paths: &{:?}, capture_eligible: {}, provenance: &{:?}, replaces: &{:?}, fields: FIELDS_{}, pointers: POINTERS_{} }},\n",
            descriptor.id,
            descriptor.name,
            descriptor.cmd,
            descriptor.magic,
            descriptor.nr,
            descriptor.direction,
            descriptor.size,
            descriptor.type_name,
            descriptor.family.as_deref(),
            descriptor.fd_paths,
            descriptor.capture_eligible,
            descriptor.provenance,
            descriptor.replaces,
            index,
            index,
        ));
    }
    output.push_str("];\n");
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn natural_sort_orders_numeric_segments_by_value() {
        assert_eq!(natural_cmp("ioctl.2", "ioctl.10"), Ordering::Less);
        assert_eq!(natural_cmp("ioctl.02", "ioctl.2"), Ordering::Greater);
    }

    #[test]
    fn top_level_union_layout_is_entirely_opaque() {
        let layouts = parse_layout_dump(
            "*** Dumping AST Record Layout\n\
             0 | union sample\n\
             0 |   unsigned int one\n\
             0 |   unsigned long two\n\
               | [sizeof=8, align=8]\n",
        );
        assert!(layouts["union sample"]
            .fields
            .iter()
            .all(|field| field.opaque));
    }

    #[test]
    fn compile_command_split_preserves_quoted_arguments() {
        assert_eq!(
            split_command_line(r#"clang -I"vendor headers" '-DNAME=a b' file.c"#).unwrap(),
            ["clang", "-Ivendor headers", "-DNAME=a b", "file.c"]
        );
        assert!(split_command_line("clang 'unterminated").is_err());
    }
}
