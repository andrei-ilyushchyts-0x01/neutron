//! Deterministic AIDL catalogs and bounded offline Parcel decoding.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::harness::{Metadata, ResourceCatalog, ResourceStatus, HARNESS_SCHEMA};

pub const CATALOG_SCHEMA: &str = "neutron.aidl-catalog/v1";
pub const DECODED_SCHEMA: &str = "neutron.decoded-aidl/v1";
const MAX_PARCEL_BYTES: usize = 64 * 1024;

#[derive(Args, Debug, Clone)]
pub struct IndexArgs {
    /// AOSP source tree root.
    pub aosp_root: PathBuf,
    /// Additional vendor source trees.
    #[arg(long, value_name = "PATH")]
    pub vendor_tree: Vec<PathBuf>,
    /// Deterministic catalog destination.
    #[arg(long, value_name = "FILE")]
    pub output: PathBuf,
    /// Explicit AIDL compiler. Falls back to PATH, then AOSP prebuilts.
    #[arg(long, value_name = "FILE")]
    pub aidl_bin: Option<PathBuf>,
    /// Fail if any interface cannot be compiled or indexed.
    #[arg(long)]
    pub strict: bool,
}

#[derive(Args, Debug, Clone)]
pub struct DecodeArgs {
    /// Complete Binder harness testcase directory.
    pub testcase: PathBuf,
    #[arg(long, value_name = "FILE")]
    pub catalog: PathBuf,
    #[arg(long, value_name = "NAME")]
    pub plugin: String,
    #[arg(long, value_name = "FILE")]
    pub output: PathBuf,
    /// Include sensitive byte arrays instead of only length and SHA-256.
    #[arg(long)]
    pub show_sensitive_bytes: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AidlArgument {
    pub name: String,
    #[serde(rename = "type")]
    pub type_name: String,
    pub direction: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AidlMethod {
    pub code: u32,
    pub method: String,
    pub return_type: String,
    pub oneway: bool,
    pub arguments: Vec<AidlArgument>,
    pub source: String,
    pub confidence: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AidlVersion {
    pub version: String,
    pub stability: String,
    pub provenance: Vec<String>,
    pub transactions: Vec<AidlMethod>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AidlInterface {
    pub descriptor: String,
    pub versions: Vec<AidlVersion>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AidlCatalog {
    pub schema: String,
    pub interfaces: Vec<AidlInterface>,
    #[serde(default)]
    pub diagnostics: Vec<String>,
}

pub struct CatalogLookup<'a> {
    pub method: &'a AidlMethod,
    pub version: Option<String>,
    pub source: &'a str,
}

impl AidlCatalog {
    pub fn from_json(raw: &str) -> Result<Self> {
        let mut catalog: Self = serde_json::from_str(raw).context("parsing AIDL catalog JSON")?;
        catalog.canonicalize()?;
        Ok(catalog)
    }

    pub fn load_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        Self::from_json(
            &fs::read_to_string(path)
                .with_context(|| format!("reading AIDL catalog: {}", path.display()))?,
        )
        .with_context(|| format!("validating AIDL catalog: {}", path.display()))
    }

    pub fn to_pretty_json(&self) -> Result<String> {
        let mut catalog = self.clone();
        catalog.canonicalize()?;
        let mut json = serde_json::to_string_pretty(&catalog)?;
        json.push('\n');
        Ok(json)
    }

    pub fn lookup(&self, descriptor: &str, code: u32) -> Option<CatalogLookup<'_>> {
        let descriptor = normalize_descriptor(descriptor);
        let interface = self
            .interfaces
            .binary_search_by(|item| item.descriptor.as_str().cmp(descriptor))
            .ok()
            .map(|index| &self.interfaces[index])?;
        let mut matches = interface.versions.iter().filter_map(|version| {
            version
                .transactions
                .binary_search_by_key(&code, |method| method.code)
                .ok()
                .map(|index| (version, &version.transactions[index]))
        });
        let (first_version, first_method) = matches.next()?;
        let mut versions = vec![first_version.version.as_str()];
        for (version, method) in matches {
            if !same_signature(first_method, method) {
                return None;
            }
            versions.push(version.version.as_str());
        }
        Some(CatalogLookup {
            method: first_method,
            version: (versions.len() == 1).then(|| versions[0].to_string()),
            source: &first_method.source,
        })
    }

    pub fn contains_descriptor(&self, descriptor: &str) -> bool {
        let descriptor = normalize_descriptor(descriptor);
        self.interfaces
            .binary_search_by(|item| item.descriptor.as_str().cmp(descriptor))
            .is_ok()
    }

    fn canonicalize(&mut self) -> Result<()> {
        if self.schema != CATALOG_SCHEMA {
            bail!("unsupported AIDL catalog schema '{}'", self.schema);
        }
        self.interfaces
            .sort_by(|a, b| a.descriptor.cmp(&b.descriptor));
        self.diagnostics.sort();
        self.diagnostics.dedup();
        let mut descriptors = BTreeSet::new();
        for interface in &mut self.interfaces {
            if interface.descriptor.is_empty() || !descriptors.insert(interface.descriptor.clone())
            {
                bail!(
                    "duplicate or empty AIDL descriptor '{}'",
                    interface.descriptor
                );
            }
            interface.versions.sort_by(|a, b| a.version.cmp(&b.version));
            let mut versions = BTreeSet::new();
            for version in &mut interface.versions {
                if !versions.insert(version.version.clone()) {
                    bail!(
                        "duplicate AIDL version '{}' for {}",
                        version.version,
                        interface.descriptor
                    );
                }
                version.provenance.sort();
                version.provenance.dedup();
                version.transactions.sort_by_key(|method| method.code);
                let mut codes = BTreeSet::new();
                for method in &version.transactions {
                    if !codes.insert(method.code) {
                        bail!(
                            "duplicate transaction code {} for {} version {}",
                            method.code,
                            interface.descriptor,
                            version.version
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

fn same_signature(left: &AidlMethod, right: &AidlMethod) -> bool {
    left.code == right.code
        && left.method == right.method
        && left.return_type == right.return_type
        && left.oneway == right.oneway
        && left.arguments == right.arguments
}

pub fn normalize_descriptor(label: &str) -> &str {
    label
        .split_once('/')
        .map_or(label, |(descriptor, _)| descriptor)
}

#[derive(Clone)]
struct SourceRoot {
    path: PathBuf,
    label: String,
    vendor: bool,
}

#[derive(Clone)]
struct ParsedInterface {
    descriptor: String,
    methods: Vec<ParsedMethod>,
    stability: String,
}

#[derive(Clone)]
struct ParsedMethod {
    name: String,
    return_type: String,
    oneway: bool,
    arguments: Vec<AidlArgument>,
}

pub fn index_catalog(args: &IndexArgs) -> Result<AidlCatalog> {
    let compiler = find_aidl_compiler(args)?;
    let mut roots = vec![SourceRoot {
        path: args.aosp_root.clone(),
        label: "aosp".into(),
        vendor: false,
    }];
    roots.extend(
        args.vendor_tree
            .iter()
            .enumerate()
            .map(|(index, path)| SourceRoot {
                path: path.clone(),
                label: format!("vendor-{}", index + 1),
                vendor: true,
            }),
    );
    for root in &roots {
        if !root.path.is_dir() {
            bail!(
                "AIDL source root is not a directory: {}",
                root.path.display()
            );
        }
    }

    let mut inputs = Vec::new();
    for root in &roots {
        collect_aidl_files(&root.path, root, &mut inputs)?;
    }
    inputs.sort_by(|(root_a, path_a), (root_b, path_b)| {
        root_a
            .label
            .cmp(&root_b.label)
            .then_with(|| path_a.cmp(path_b))
    });

    let mut include_roots = roots
        .iter()
        .map(|root| root.path.clone())
        .collect::<Vec<_>>();
    for (_, path) in &inputs {
        if let Ok(source) = fs::read_to_string(path) {
            if let Some(package) = parse_package(&strip_comments(&source)) {
                if let Some(root) = infer_include_root(path, &package) {
                    include_roots.push(root);
                }
            }
        }
    }
    include_roots.sort();
    include_roots.dedup();

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp =
        std::env::temp_dir().join(format!("neutron-aidl-index-{}-{nonce}", std::process::id()));
    let _ = fs::remove_dir_all(&temp);
    fs::create_dir(&temp).context("creating AIDL compiler scratch directory")?;
    let result = build_catalog(&compiler, &inputs, &include_roots, &temp, args.strict);
    let _ = fs::remove_dir_all(&temp);
    result
}

fn build_catalog(
    compiler: &Path,
    inputs: &[(SourceRoot, PathBuf)],
    include_roots: &[PathBuf],
    temp: &Path,
    strict: bool,
) -> Result<AidlCatalog> {
    let mut diagnostics = Vec::new();
    let mut versions = BTreeMap::<(String, String), AidlVersion>::new();
    let mut vendors = BTreeMap::<(String, String, u32), bool>::new();
    let mut unresolved = BTreeSet::<(String, String, u32)>::new();

    for (index, (root, path)) in inputs.iter().enumerate() {
        let relative = relative_source(root, path);
        let source = match fs::read_to_string(path) {
            Ok(source) => source,
            Err(error) => {
                diagnostics.push(format!("{relative}: unreadable: {error}"));
                continue;
            }
        };
        let parsed = match parse_interface(&source) {
            Some(parsed) => parsed,
            None if strip_comments(&source).contains("interface") => {
                diagnostics.push(format!("{relative}: unsupported interface declaration"));
                continue;
            }
            None => continue,
        };
        let output = temp.join(index.to_string());
        fs::create_dir(&output)?;
        let generated = match compile_interface(compiler, path, include_roots, &output) {
            Ok(generated) => generated,
            Err(error) => {
                diagnostics.push(format!("{relative}: unsupported: {error:#}"));
                continue;
            }
        };
        match parse_generated_descriptor(&generated) {
            Some(descriptor) if descriptor == parsed.descriptor => {}
            Some(descriptor) => {
                diagnostics.push(format!(
                    "{relative}: generated descriptor {descriptor} does not match {}",
                    parsed.descriptor
                ));
                continue;
            }
            None => {
                diagnostics.push(format!("{relative}: generated descriptor missing"));
                continue;
            }
        }
        let constants = parse_generated_constants(&generated);
        if constants.is_empty() && !parsed.methods.is_empty() {
            diagnostics.push(format!("{relative}: no generated transaction constants"));
            continue;
        }
        let version_name = source_version(root, path);
        let key = (parsed.descriptor.clone(), version_name.clone());
        let version = versions.entry(key.clone()).or_insert_with(|| AidlVersion {
            version: version_name.clone(),
            stability: parsed.stability.clone(),
            provenance: Vec::new(),
            transactions: Vec::new(),
        });
        version.provenance.push(relative.clone());
        for method in parsed.methods {
            let Some(code) = constants.get(&method.name).copied() else {
                diagnostics.push(format!(
                    "{relative}: generated constant missing for {}",
                    method.name
                ));
                continue;
            };
            let conflict_key = (parsed.descriptor.clone(), version_name.clone(), code);
            if unresolved.contains(&conflict_key) {
                continue;
            }
            let incoming = AidlMethod {
                code,
                method: method.name,
                return_type: method.return_type,
                oneway: method.oneway,
                arguments: method.arguments,
                source: relative.clone(),
                confidence: "verified".into(),
            };
            if let Some(existing_index) = version
                .transactions
                .iter()
                .position(|existing| existing.code == code)
            {
                if same_signature(&version.transactions[existing_index], &incoming) {
                    if root.vendor && !vendors.get(&conflict_key).copied().unwrap_or(false) {
                        version.transactions[existing_index] = incoming;
                        vendors.insert(conflict_key, true);
                    }
                } else {
                    let existing = version.transactions.remove(existing_index);
                    diagnostics.push(format!(
                        "{} version {} code {} conflicts: {} vs {}",
                        parsed.descriptor, version_name, code, existing.source, relative
                    ));
                    unresolved.insert(conflict_key);
                }
            } else {
                version.transactions.push(incoming);
                vendors.insert(conflict_key, root.vendor);
            }
        }
    }

    diagnostics.sort();
    if strict && !diagnostics.is_empty() {
        bail!("AIDL indexing diagnostics:\n{}", diagnostics.join("\n"));
    }
    let mut by_descriptor = BTreeMap::<String, Vec<AidlVersion>>::new();
    for ((descriptor, _), version) in versions {
        by_descriptor.entry(descriptor).or_default().push(version);
    }
    let mut catalog = AidlCatalog {
        schema: CATALOG_SCHEMA.into(),
        interfaces: by_descriptor
            .into_iter()
            .map(|(descriptor, versions)| AidlInterface {
                descriptor,
                versions,
            })
            .collect(),
        diagnostics,
    };
    catalog.canonicalize()?;
    Ok(catalog)
}

pub fn run_index(args: IndexArgs) -> Result<()> {
    let catalog = index_catalog(&args)?;
    fs::write(&args.output, catalog.to_pretty_json()?)
        .with_context(|| format!("writing {}", args.output.display()))
}

fn collect_aidl_files(
    root: &Path,
    source_root: &SourceRoot,
    output: &mut Vec<(SourceRoot, PathBuf)>,
) -> Result<()> {
    for entry in fs::read_dir(root).with_context(|| format!("reading {}", root.display()))? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_aidl_files(&entry.path(), source_root, output)?;
        } else if entry.path().extension().and_then(|value| value.to_str()) == Some("aidl") {
            output.push((source_root.clone(), entry.path()));
        }
    }
    Ok(())
}

fn find_aidl_compiler(args: &IndexArgs) -> Result<PathBuf> {
    if let Some(path) = &args.aidl_bin {
        if path.is_file() {
            return Ok(path.clone());
        }
        bail!("--aidl-bin is not a file: {}", path.display());
    }
    if Command::new("aidl").arg("--help").output().is_ok() {
        return Ok(PathBuf::from("aidl"));
    }
    for relative in [
        "prebuilts/build-tools/linux-x86/bin/aidl",
        "out/host/linux-x86/bin/aidl",
    ] {
        let path = args.aosp_root.join(relative);
        if path.is_file() {
            return Ok(path);
        }
    }
    bail!("AIDL compiler not found; use --aidl-bin")
}

fn compile_interface(
    compiler: &Path,
    input: &Path,
    includes: &[PathBuf],
    output: &Path,
) -> Result<String> {
    let mut command = Command::new(compiler);
    command.arg("--lang=java").arg("--transaction_names");
    for include in includes {
        command.arg("-I").arg(include);
    }
    let result = command.arg("-o").arg(output).arg(input).output()?;
    if !result.status.success() {
        bail!(
            "aidl failed: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        );
    }
    let mut files = Vec::new();
    collect_generated_files(output, &mut files)?;
    files.sort();
    let mut generated = String::new();
    for file in files {
        generated.push_str(&fs::read_to_string(file)?);
        generated.push('\n');
    }
    Ok(generated)
}

fn collect_generated_files(root: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            collect_generated_files(&entry.path(), output)?;
        } else if matches!(
            entry.path().extension().and_then(|value| value.to_str()),
            Some("java" | "h" | "cpp" | "cc")
        ) {
            output.push(entry.path());
        }
    }
    Ok(())
}

fn parse_generated_constants(generated: &str) -> BTreeMap<String, u32> {
    let mut constants = BTreeMap::new();
    for fragment in generated.split(';') {
        if !fragment.contains("static final int TRANSACTION_") {
            continue;
        }
        let Some(start) = fragment.find("TRANSACTION_") else {
            continue;
        };
        let rest = &fragment[start + "TRANSACTION_".len()..];
        let name_len = rest
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            .count();
        let name = &rest[..name_len];
        let Some(expression) = rest[name_len..].split_once('=').map(|(_, value)| value) else {
            continue;
        };
        let numbers = expression
            .split(|character: char| !character.is_ascii_digit())
            .filter(|value| !value.is_empty())
            .filter_map(|value| value.parse::<u32>().ok())
            .collect::<Vec<_>>();
        let Some(number) = numbers.last().copied() else {
            continue;
        };
        let code = if expression.contains("FIRST_CALL_TRANSACTION") {
            number.checked_add(1)
        } else {
            Some(number)
        };
        if let Some(code) = code {
            constants.insert(name.to_string(), code);
        }
    }
    constants
}

fn parse_generated_descriptor(generated: &str) -> Option<String> {
    generated.lines().find_map(|line| {
        if !line.contains("DESCRIPTOR") || !line.contains('=') {
            return None;
        }
        let value = line.split_once('=')?.1;
        let start = value.find('"')? + 1;
        let end = value[start..].find('"')? + start;
        Some(value[start..end].to_string())
    })
}

fn strip_comments(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes.get(index..index + 2) == Some(b"//") {
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
        } else if bytes.get(index..index + 2) == Some(b"/*") {
            output.push_str("  ");
            index += 2;
            while index < bytes.len() && bytes.get(index..index + 2) != Some(b"*/") {
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
            if index < bytes.len() {
                output.push_str("  ");
                index += 2;
            }
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn parse_package(source: &str) -> Option<String> {
    let start = source.find("package")? + "package".len();
    let end = source[start..].find(';')? + start;
    Some(source[start..end].trim().to_string())
}

fn parse_interface(source: &str) -> Option<ParsedInterface> {
    let source = strip_comments(source);
    let package = parse_package(&source)?;
    let interface_at = source.find("interface ")?;
    let name_start = interface_at + "interface ".len();
    let name = source[name_start..]
        .trim_start()
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .next()?;
    let body_start = source[name_start..].find('{')? + name_start;
    let body_end = matching_brace(&source, body_start)?;
    let interface_prefix = &source[..interface_at];
    let interface_oneway = interface_prefix
        .split_whitespace()
        .next_back()
        .is_some_and(|value| value == "oneway");
    let stability = if interface_prefix.contains("@VintfStability") {
        "vintf"
    } else {
        "unstable"
    };
    let mut methods = Vec::new();
    for statement in split_top_level(&source[body_start + 1..body_end], ';') {
        if let Some(method) = parse_method(statement, interface_oneway) {
            methods.push(method);
        }
    }
    Some(ParsedInterface {
        descriptor: format!("{package}.{name}"),
        methods,
        stability: stability.into(),
    })
}

fn matching_brace(source: &str, start: usize) -> Option<usize> {
    let mut depth = 0u32;
    for (offset, byte) in source.as_bytes()[start..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(start + offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_top_level(input: &str, separator: char) -> Vec<&str> {
    let mut output = Vec::new();
    let mut start = 0;
    let mut depth = 0i32;
    for (index, character) in input.char_indices() {
        match character {
            '(' | '[' | '<' | '{' => depth += 1,
            ')' | ']' | '>' | '}' => depth -= 1,
            _ if character == separator && depth == 0 => {
                output.push(input[start..index].trim());
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    let tail = input[start..].trim();
    if !tail.is_empty() {
        output.push(tail);
    }
    output
}

fn strip_annotations(mut input: &str) -> &str {
    input = input.trim();
    while input.starts_with('@') {
        let mut depth = 0i32;
        let mut end = input.len();
        for (index, character) in input.char_indices() {
            match character {
                '(' => depth += 1,
                ')' => depth -= 1,
                character if character.is_whitespace() && depth == 0 => {
                    end = index;
                    break;
                }
                _ => {}
            }
        }
        input = input[end..].trim_start();
    }
    input
}

fn parse_method(statement: &str, interface_oneway: bool) -> Option<ParsedMethod> {
    let statement = strip_annotations(statement);
    let open = statement.find('(')?;
    let close = statement.rfind(')')?;
    let prefix = statement[..open].trim();
    let mut tokens = prefix.split_whitespace().collect::<Vec<_>>();
    let name = tokens.pop()?.to_string();
    let oneway = interface_oneway || tokens.first().is_some_and(|value| *value == "oneway");
    if tokens.first().is_some_and(|value| *value == "oneway") {
        tokens.remove(0);
    }
    let return_type = tokens.join(" ");
    if return_type.is_empty() {
        return None;
    }
    let arguments = split_top_level(&statement[open + 1..close], ',')
        .into_iter()
        .filter(|value| !value.is_empty())
        .filter_map(parse_argument)
        .collect();
    Some(ParsedMethod {
        name,
        return_type,
        oneway,
        arguments,
    })
}

fn parse_argument(argument: &str) -> Option<AidlArgument> {
    let argument = strip_annotations(argument);
    let mut tokens = argument.split_whitespace().collect::<Vec<_>>();
    let name = tokens.pop()?.to_string();
    let direction = if matches!(tokens.first(), Some(&"in" | &"out" | &"inout")) {
        tokens.remove(0).to_string()
    } else {
        "in".into()
    };
    Some(AidlArgument {
        name,
        type_name: tokens.join(" "),
        direction,
    })
}

fn infer_include_root(path: &Path, package: &str) -> Option<PathBuf> {
    let suffix = PathBuf::from(package.replace('.', "/"));
    let parent = path.parent()?;
    let parent_text = parent.to_string_lossy();
    let suffix_text = suffix.to_string_lossy();
    parent_text
        .strip_suffix(suffix_text.as_ref())
        .map(|root| PathBuf::from(root.trim_end_matches('/')))
}

fn source_version(root: &SourceRoot, path: &Path) -> String {
    let components = path
        .strip_prefix(&root.path)
        .unwrap_or(path)
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>();
    components
        .iter()
        .position(|component| component == "aidl_api")
        .and_then(|index| components.get(index + 2))
        .cloned()
        .unwrap_or_else(|| "unversioned".into())
}

fn relative_source(root: &SourceRoot, path: &Path) -> String {
    format!(
        "{}:{}",
        root.label,
        path.strip_prefix(&root.path)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/")
    )
}

#[derive(Clone, Copy)]
pub struct ParcelView<'a> {
    data: &'a [u8],
    offsets: &'a [u64],
}

impl<'a> ParcelView<'a> {
    pub fn new(data: &'a [u8], offsets: &'a [u64]) -> Result<Self> {
        if data.len() > MAX_PARCEL_BYTES {
            bail!("Parcel exceeds 64 KiB limit");
        }
        let mut previous = None;
        for offset in offsets {
            let offset = usize::try_from(*offset).context("Binder object offset overflow")?;
            if offset % 4 != 0 || offset.checked_add(4).map_or(true, |end| end > data.len()) {
                bail!("invalid Binder object offset {offset}");
            }
            if previous.is_some_and(|value| value >= offset) {
                bail!("Binder object offsets are not strictly increasing");
            }
            previous = Some(offset);
        }
        Ok(Self { data, offsets })
    }
}

struct ParcelReader<'a> {
    data: &'a [u8],
    cursor: usize,
    end: usize,
}

#[derive(Debug)]
struct DecodeError {
    status: &'static str,
    message: String,
}

impl<'a> ParcelReader<'a> {
    fn read_i32(&mut self) -> std::result::Result<i32, DecodeError> {
        let bytes = self.take(4)?;
        Ok(i32::from_le_bytes(bytes.try_into().expect("four bytes")))
    }

    fn read_i64(&mut self) -> std::result::Result<i64, DecodeError> {
        let bytes = self.take(8)?;
        Ok(i64::from_le_bytes(bytes.try_into().expect("eight bytes")))
    }

    fn take(&mut self, length: usize) -> std::result::Result<&'a [u8], DecodeError> {
        let end = self.cursor.checked_add(length).ok_or_else(|| DecodeError {
            status: "malformed",
            message: "Parcel length overflow".into(),
        })?;
        if end > self.end {
            return Err(DecodeError {
                status: "truncated",
                message: "Parcel value is truncated".into(),
            });
        }
        let bytes = &self.data[self.cursor..end];
        self.cursor = end;
        Ok(bytes)
    }

    fn align4(&mut self) -> std::result::Result<(), DecodeError> {
        let aligned = self
            .cursor
            .checked_add(3)
            .map(|value| value & !3)
            .ok_or_else(|| DecodeError {
                status: "malformed",
                message: "Parcel alignment overflow".into(),
            })?;
        if aligned > self.end {
            return Err(DecodeError {
                status: "truncated",
                message: "Parcel padding is truncated".into(),
            });
        }
        self.cursor = aligned;
        Ok(())
    }
}

pub fn decode_plugin(
    plugin: &str,
    view: ParcelView<'_>,
    descriptor: &str,
    method: &str,
    signature: &AidlMethod,
    show_sensitive_bytes: bool,
) -> Value {
    if plugin != "keymint" {
        return json!({"status":"unsupported","error":format!("unknown plugin '{plugin}'")});
    }
    if descriptor != "android.hardware.security.keymint.IKeyMintDevice"
        || method != "generateKey"
        || signature.method != "generateKey"
        || signature
            .arguments
            .first()
            .map_or(true, |argument| argument.type_name != "KeyParameter[]")
    {
        return json!({"status":"unsupported","error":"keymint supports only IKeyMintDevice.generateKey(KeyParameter[])"});
    }
    if !view.offsets.is_empty() {
        return json!({"status":"malformed","error":"generateKey request contains unexpected Binder objects"});
    }
    match decode_keymint(view, descriptor, show_sensitive_bytes) {
        Ok((parameters, unsupported)) => json!({
            "status": if unsupported { "unsupported" } else { "decoded" },
            "arguments": {"keyParams": parameters}
        }),
        Err(error) => json!({"status":error.status,"error":error.message}),
    }
}

fn decode_keymint(
    view: ParcelView<'_>,
    descriptor: &str,
    show_sensitive_bytes: bool,
) -> std::result::Result<(Vec<Value>, bool), DecodeError> {
    let payload = find_interface_payload(view.data, descriptor)?;
    let mut reader = ParcelReader {
        data: view.data,
        cursor: payload,
        end: view.data.len(),
    };
    let count = reader.read_i32()?;
    if !(0..=4096).contains(&count) {
        return Err(DecodeError {
            status: "malformed",
            message: format!("invalid KeyParameter array length {count}"),
        });
    }
    let mut output = Vec::with_capacity(count as usize);
    let mut unsupported = false;
    for _ in 0..count {
        let start = reader.cursor;
        let size = reader.read_i32()?;
        if size < 12 {
            return Err(DecodeError {
                status: "malformed",
                message: format!("invalid KeyParameter parcelable size {size}"),
            });
        }
        let end = start
            .checked_add(size as usize)
            .filter(|end| *end <= reader.end)
            .ok_or_else(|| DecodeError {
                status: "truncated",
                message: "KeyParameter parcelable is truncated".into(),
            })?;
        let saved_end = reader.end;
        reader.end = end;
        let tag = reader.read_i32()?;
        let union_tag = reader.read_i32()?;
        let value_start = reader.cursor;
        let (mut value, known) =
            decode_keymint_value(&mut reader, union_tag, show_sensitive_bytes)?;
        if !show_sensitive_bytes && tag as u32 == 0xa000_01f6 {
            let bytes = &reader.data[value_start..reader.cursor];
            value = json!({
                "variant":value.get("variant").cloned().unwrap_or(Value::String("longInteger".into())),
                "length":bytes.len(),
                "sha256":format!("{:x}", Sha256::digest(bytes))
            });
        }
        unsupported |= !known;
        reader.cursor = end;
        reader.end = saved_end;
        output.push(json!({
            "tag": tag,
            "tag_name": keymint_tag_name(tag),
            "value": value
        }));
    }
    let _ = view.offsets;
    Ok((output, unsupported))
}

fn find_interface_payload(
    data: &[u8],
    descriptor: &str,
) -> std::result::Result<usize, DecodeError> {
    let units = descriptor.encode_utf16().collect::<Vec<_>>();
    let byte_len = units.len().checked_mul(2).ok_or_else(|| DecodeError {
        status: "malformed",
        message: "descriptor length overflow".into(),
    })?;
    for start in (0..data.len().min(64)).step_by(4) {
        let Some(length_bytes) = data.get(start..start + 4) else {
            break;
        };
        if i32::from_le_bytes(length_bytes.try_into().expect("four bytes")) != units.len() as i32 {
            continue;
        }
        let text_start = start + 4;
        let Some(text) = data.get(text_start..text_start + byte_len) else {
            continue;
        };
        if text
            .chunks_exact(2)
            .zip(&units)
            .all(|(bytes, unit)| u16::from_le_bytes([bytes[0], bytes[1]]) == *unit)
        {
            let after_nul = text_start + byte_len + 2;
            if data.get(text_start + byte_len..after_nul) != Some(&[0, 0]) {
                continue;
            }
            return Ok((after_nul + 3) & !3);
        }
    }
    Err(DecodeError {
        status: "truncated",
        message: "complete interface token not found".into(),
    })
}

fn decode_keymint_value(
    reader: &mut ParcelReader<'_>,
    union_tag: i32,
    show_sensitive_bytes: bool,
) -> std::result::Result<(Value, bool), DecodeError> {
    let variant = match union_tag {
        0 => "invalid",
        1 => "algorithm",
        2 => "blockMode",
        3 => "paddingMode",
        4 => "digest",
        5 => "ecCurve",
        6 => "origin",
        7 => "keyPurpose",
        8 => "hardwareAuthenticatorType",
        9 => "securityLevel",
        10 => "boolValue",
        11 => "integer",
        12 => "longInteger",
        13 => "dateTime",
        14 => "blob",
        _ => {
            return Ok((json!({"union_tag":union_tag}), false));
        }
    };
    let value = match union_tag {
        0..=11 => json!({"variant":variant,"value":reader.read_i32()?}),
        12 | 13 => json!({"variant":variant,"value":reader.read_i64()?}),
        14 => {
            let length = reader.read_i32()?;
            if !(0..=MAX_PARCEL_BYTES as i32).contains(&length) {
                return Err(DecodeError {
                    status: "malformed",
                    message: format!("invalid KeyMint blob length {length}"),
                });
            }
            let bytes = reader.take(length as usize)?;
            reader.align4()?;
            let mut value = json!({
                "variant":variant,
                "length":bytes.len(),
                "sha256":format!("{:x}", Sha256::digest(bytes))
            });
            if show_sensitive_bytes {
                value["bytes"] = Value::String(hex(bytes));
            }
            value
        }
        _ => unreachable!(),
    };
    Ok((value, true))
}

fn keymint_tag_name(tag: i32) -> &'static str {
    match tag as u32 {
        0x1000_0002 => "ALGORITHM",
        0x3000_0003 => "KEY_SIZE",
        0x2000_0001 => "PURPOSE",
        0x2000_0004 => "BLOCK_MODE",
        0x2000_0005 => "DIGEST",
        0x2000_0006 => "PADDING",
        0x7000_0007 => "CALLER_NONCE",
        0x3000_0008 => "MIN_MAC_LENGTH",
        0x1000_000a => "EC_CURVE",
        0x5000_00c8 => "RSA_PUBLIC_EXPONENT",
        0x9000_0259 => "APPLICATION_ID",
        0x9000_02bc => "APPLICATION_DATA",
        0x6000_0190 => "ACTIVE_DATETIME",
        0x6000_0191 => "ORIGINATION_EXPIRE_DATETIME",
        0x6000_0192 => "USAGE_EXPIRE_DATETIME",
        0x7000_01f7 => "NO_AUTH_REQUIRED",
        0xa000_01f6 => "USER_SECURE_ID",
        0x1000_02be => "ORIGIN",
        0x3000_02c1 => "OS_VERSION",
        0x3000_02c2 => "OS_PATCHLEVEL",
        _ => "UNKNOWN",
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    output
}

pub fn run_decode(args: DecodeArgs) -> Result<()> {
    if args.plugin != "keymint" {
        bail!("unknown AIDL decoder plugin '{}'", args.plugin);
    }
    ensure_separate_output(&args.testcase, &args.output)?;
    let catalog = AidlCatalog::load_file(&args.catalog)?;
    let metadata: Metadata = crate::harness::validate_artifact(&args.testcase)
        .context("validating complete harness testcase")?;
    let resources: ResourceCatalog =
        serde_json::from_slice(&fs::read(args.testcase.join("resources.json"))?)?;
    if metadata.schema != HARNESS_SCHEMA || resources.schema != HARNESS_SCHEMA {
        bail!("unsupported harness testcase schema");
    }
    if metadata.replay_status != "ready"
        || !metadata.blocked_reasons.is_empty()
        || !resources.unresolved.is_empty()
        || resources
            .resources
            .iter()
            .any(|resource| resource.status != ResourceStatus::Complete)
    {
        bail!("AIDL decoding requires a complete, unblocked Binder harness testcase");
    }
    let stream_resource = resources
        .resources
        .iter()
        .find(|resource| resource.id == "binder.write_stream" && resource.kind == "binder_stream")
        .context("testcase has no complete Binder write stream")?;
    let stream = read_testcase_blob(&args.testcase, stream_resource)?;
    let codes = transaction_codes(&stream)?;
    let mut transactions = Vec::new();
    for transaction in &metadata.transactions {
        let parcel_resource = resources
            .resources
            .iter()
            .find(|resource| resource.id == format!("{transaction}.parcel"))
            .with_context(|| format!("missing {transaction} Parcel"))?;
        let offsets_resource = resources
            .resources
            .iter()
            .find(|resource| resource.id == format!("{transaction}.offsets"))
            .with_context(|| format!("missing {transaction} offsets"))?;
        let parcel = read_testcase_blob(&args.testcase, parcel_resource)?;
        let offset_bytes = read_testcase_blob(&args.testcase, offsets_resource)?;
        if offset_bytes.len() % 8 != 0 {
            bail!("{transaction} Binder offsets are malformed");
        }
        let offsets = offset_bytes
            .chunks_exact(8)
            .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
            .collect::<Vec<_>>();
        let view = ParcelView::new(&parcel, &offsets)?;
        let descriptor = catalog
            .interfaces
            .iter()
            .map(|interface| interface.descriptor.as_str())
            .find(|descriptor| find_interface_payload(&parcel, descriptor).is_ok())
            .context("Parcel interface descriptor is absent from the catalog")?;
        let index = transaction
            .rsplit('.')
            .next()
            .and_then(|value| value.parse::<usize>().ok())
            .context("invalid harness transaction id")?;
        let code = *codes
            .get(index)
            .context("Binder transaction code missing")?;
        let Some(lookup) = catalog.lookup(descriptor, code) else {
            transactions.push(json!({
                "transaction":transaction,
                "interface_descriptor":descriptor,
                "code":code,
                "status":"unsupported"
            }));
            continue;
        };
        transactions.push(json!({
            "transaction":transaction,
            "interface_descriptor":descriptor,
            "code":code,
            "method":lookup.method.method,
            "aidl_version":lookup.version,
            "catalog_source":lookup.source,
            "decoded":decode_plugin(
                &args.plugin,
                view,
                descriptor,
                &lookup.method.method,
                lookup.method,
                args.show_sensitive_bytes,
            )
        }));
    }
    let document = json!({
        "schema":DECODED_SCHEMA,
        "plugin":args.plugin,
        "transactions":transactions
    });
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&args.output)
        .with_context(|| format!("creating {}", args.output.display()))?;
    file.write_all(&serde_json::to_vec_pretty(&document)?)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn ensure_separate_output(testcase: &Path, output: &Path) -> Result<()> {
    let testcase = fs::canonicalize(testcase)
        .with_context(|| format!("opening testcase {}", testcase.display()))?;
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent)
        .with_context(|| format!("opening output directory {}", parent.display()))?;
    if parent.starts_with(&testcase) {
        bail!("decoded output must be outside the testcase directory");
    }
    Ok(())
}

fn read_testcase_blob(
    testcase: &Path,
    resource: &crate::harness::HarnessResource,
) -> Result<Vec<u8>> {
    let digest = resource
        .sha256
        .as_deref()
        .context("complete resource has no SHA-256")?;
    let digest = digest.strip_prefix("sha256:").unwrap_or(digest);
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid testcase blob digest");
    }
    let path = testcase.join("blobs").join(digest);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_file() {
        bail!("testcase blob is not a regular file");
    }
    let bytes = fs::read(&path)?;
    if bytes.len() as u64 != resource.length {
        bail!("testcase blob length mismatch");
    }
    if format!("{:x}", Sha256::digest(&bytes)) != digest.to_ascii_lowercase() {
        bail!("testcase blob hash mismatch");
    }
    Ok(bytes)
}

fn transaction_codes(stream: &[u8]) -> Result<Vec<u32>> {
    let mut cursor = 0usize;
    let mut codes = Vec::new();
    while cursor + 4 <= stream.len() {
        let command =
            u32::from_le_bytes(stream[cursor..cursor + 4].try_into().expect("four bytes"));
        cursor += 4;
        let command_type = (command >> 8) & 0xff;
        let command_nr = command & 0xff;
        let command_size = ((command >> 16) & 0x3fff) as usize;
        let end = cursor
            .checked_add(command_size)
            .context("Binder command length overflow")?;
        if end > stream.len() {
            bail!("truncated Binder command stream");
        }
        if command_type == b'c' as u32 && matches!(command_nr, 0 | 1 | 17) {
            if command_size < 64 {
                bail!("truncated Binder transaction command");
            }
            codes.push(u32::from_le_bytes(
                stream[cursor + 16..cursor + 20]
                    .try_into()
                    .expect("four bytes"),
            ));
        }
        cursor = end;
    }
    Ok(codes)
}
