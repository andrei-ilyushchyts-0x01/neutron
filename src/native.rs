//! Reproducible offline mapping of captured userspace instruction pointers.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Args;
use goblin::elf::{header, note, program_header, Elf};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::symbolize::elf::ElfSymbols;

pub const MAX_MAPPINGS: usize = 4_096;
pub const MAX_FRAMES: usize = 127;
pub const MAX_PATH_BYTES: usize = 4 * 1_024;
const MAX_ARTIFACTS: usize = 256;
const MAX_ARTIFACT_BYTES: u64 = 512 * 1_024 * 1_024;
const MAX_TOTAL_ARTIFACT_BYTES: u64 = 4 * 1_024 * 1_024 * 1_024;
const MAX_EXEMPLARS: usize = 32;
const MAX_SYMBOL_DEPTH: usize = 32;

#[derive(Args, Debug, Clone)]
pub struct NativeMapArgs {
    pub capture: PathBuf,
    #[arg(long, value_name = "DIR")]
    pub symbols: Vec<PathBuf>,
    #[arg(long)]
    pub pull_apk: bool,
    #[arg(long)]
    pub pull_libs: bool,
    #[arg(long)]
    pub adb_serial: Option<String>,
    #[arg(long)]
    pub package: Option<String>,
    #[arg(long)]
    pub artifact_dir: Option<PathBuf>,
    #[arg(long)]
    pub json_output: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct GhidraExportArgs {
    pub capture: PathBuf,
    #[arg(long, value_name = "DIR")]
    pub symbols: Vec<PathBuf>,
    #[arg(long)]
    pub artifact_dir: Option<PathBuf>,
    #[arg(long, default_value = "5s")]
    pub crash_window: String,
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapturedMapping {
    pub start: u64,
    pub end: u64,
    pub offset: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device: String,
    #[serde(default)]
    pub inode: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elf_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_bias: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMapsRecord {
    #[serde(rename = "type")]
    pub record_type: String,
    pub pid: u32,
    pub starttime: u64,
    pub maps_generation: u64,
    pub timestamp_ns: u64,
    pub mappings: Vec<CapturedMapping>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackTraceRecord {
    #[serde(rename = "type")]
    pub record_type: String,
    pub stack_trace_ref: String,
    pub pid: u32,
    pub starttime: u64,
    pub stack_kind: String,
    pub stack_id: i32,
    pub maps_generation: u64,
    pub timestamp_ns: u64,
    pub ips: Vec<u64>,
    pub rendered: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfMapMetadata {
    pub elf_type: Option<String>,
    pub build_id: Option<String>,
    pub load_bias: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeConfidence {
    Exact,
    Candidate,
    Captured,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranslatedAddress {
    pub elf_vaddr: u64,
    pub file_offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramIdentity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub captured_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeFrame {
    pub order: usize,
    pub runtime_ip: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elf_vaddr: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_offset: Option<u64>,
    pub symbol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<ProgramIdentity>,
    pub confidence: NativeConfidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeEvent {
    pub event_id: String,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub context: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    pub stack_trace_ref: String,
    pub frames: Vec<NativeFrame>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeMapDocument {
    pub schema: String,
    pub capture: String,
    pub events: Vec<NativeEvent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhidraDocument {
    pub schema: String,
    pub programs: Vec<GhidraProgram>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhidraProgram {
    pub program: ProgramIdentity,
    pub bookmarks: Vec<GhidraBookmark>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhidraBookmark {
    pub elf_vaddr: u64,
    pub label: String,
    pub contexts: Vec<String>,
    pub frequency: u64,
    pub first_timestamp_ns: u64,
    pub last_timestamp_ns: u64,
    pub event_exemplars: Vec<String>,
    pub related_crash_ids: Vec<String>,
    pub confidence: NativeConfidence,
}

#[derive(Debug, Clone)]
pub struct GhidraBookmarkInput {
    pub program: ProgramIdentity,
    pub elf_vaddr: u64,
    pub label: String,
    pub context: String,
    pub timestamp_ns: u64,
    pub event_id: String,
    pub related_crash_ids: Vec<String>,
    pub confidence: NativeConfidence,
}

impl GhidraBookmarkInput {
    pub fn fixture(build_id: &str, elf_vaddr: u64, context: &str, timestamp_ns: u64) -> Self {
        Self {
            program: ProgramIdentity {
                build_id: Some(build_id.into()),
                sha256: None,
                captured_paths: vec!["/fixture.so".into()],
            },
            elf_vaddr,
            label: context.into(),
            context: context.into(),
            timestamp_ns,
            event_id: timestamp_ns.to_string(),
            related_crash_ids: Vec::new(),
            confidence: NativeConfidence::Exact,
        }
    }
}

pub fn elf_map_metadata(bytes: &[u8], map_start: u64, map_offset: u64) -> Option<ElfMapMetadata> {
    let elf = Elf::parse(bytes).ok()?;
    let segment = elf.program_headers.iter().find(|ph| {
        let alignment = ph.p_align.max(1);
        let file_start = ph.p_offset / alignment * alignment;
        let file_end = ph
            .p_offset
            .saturating_add(ph.p_filesz)
            .saturating_add(alignment - 1)
            / alignment
            * alignment;
        ph.p_type == program_header::PT_LOAD
            && map_offset >= file_start
            && map_offset < file_end.max(file_start + 1)
    });
    let load_bias = segment.and_then(|ph| {
        let alignment = ph.p_align.max(1);
        let file_start = ph.p_offset / alignment * alignment;
        let vaddr_start = ph.p_vaddr / alignment * alignment;
        map_start.checked_sub(vaddr_start.saturating_add(map_offset - file_start))
    });
    Some(ElfMapMetadata {
        elf_type: match elf.header.e_type {
            header::ET_DYN => Some("ET_DYN".into()),
            header::ET_EXEC => Some("ET_EXEC".into()),
            _ => None,
        },
        build_id: elf_build_id(&elf, bytes),
        load_bias,
    })
}

fn elf_build_id(elf: &Elf<'_>, bytes: &[u8]) -> Option<String> {
    let notes = elf
        .iter_note_headers(bytes)
        .into_iter()
        .flatten()
        .chain(elf.iter_note_sections(bytes, None).into_iter().flatten());
    notes
        .filter_map(Result::ok)
        .find(|entry| entry.n_type == note::NT_GNU_BUILD_ID && entry.name == "GNU")
        .map(|entry| hex(entry.desc))
}

pub fn translate_ip(mapping: &CapturedMapping, runtime_ip: u64) -> Option<TranslatedAddress> {
    if runtime_ip < mapping.start || runtime_ip >= mapping.end {
        return None;
    }
    Some(TranslatedAddress {
        elf_vaddr: runtime_ip.checked_sub(mapping.load_bias?)?,
        file_offset: mapping.offset + (runtime_ip - mapping.start),
    })
}

pub fn parse_maps_text(text: &str) -> Vec<CapturedMapping> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let (start, end) = parts.next()?.split_once('-')?;
            let perms = parts.next()?;
            let offset = u64::from_str_radix(parts.next()?, 16).ok()?;
            let device = parts.next()?.to_string();
            let inode = parts.next()?.parse().ok()?;
            let path = parts.collect::<Vec<_>>().join(" ");
            if !perms.as_bytes().get(2).is_some_and(|byte| *byte == b'x') {
                return None;
            }
            Some(CapturedMapping {
                start: u64::from_str_radix(start, 16).ok()?,
                end: u64::from_str_radix(end, 16).ok()?,
                offset,
                device,
                inode,
                path: truncate_utf8(&path, MAX_PATH_BYTES),
                ..Default::default()
            })
        })
        .take(MAX_MAPPINGS)
        .collect()
}

fn truncate_utf8(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.into();
    }
    let mut boundary = max;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value[..boundary].into()
}

#[derive(Default)]
pub struct CaptureNativeState {
    processes: HashMap<(u32, u64), CaptureProcess>,
    invalidated: HashSet<u32>,
    pub maps_truncated: u64,
    pub stacks_truncated: u64,
    pub refresh_failed: u64,
}

pub struct CapturedStack {
    pub records: Vec<String>,
    pub reference: String,
}

#[derive(Default)]
struct CaptureProcess {
    generation: u64,
    maps: Vec<CapturedMapping>,
    emitted_maps: bool,
    maps_truncated: bool,
    stacks: HashSet<(String, i32, u64)>,
    unmapped_refreshed: HashSet<u64>,
}

impl CaptureNativeState {
    pub fn invalidate(&mut self, pid: u32) {
        self.invalidated.insert(pid);
    }

    pub fn clear_invalidation(&mut self, pid: u32) {
        self.invalidated.remove(&pid);
    }

    pub fn capture_stack(
        &mut self,
        pid: u32,
        timestamp_ns: u64,
        kind: &str,
        stack_id: i32,
        ips: &[u64],
        rendered: &[String],
    ) -> Option<CapturedStack> {
        let Some(starttime) = read_starttime(pid) else {
            self.refresh_failed += 1;
            return None;
        };
        let key = (pid, starttime);
        let needs_snapshot = kind == "user"
            && (self
                .processes
                .get(&key)
                .map_or(true, |process| process.maps.is_empty())
                || self.invalidated.remove(&pid));
        if needs_snapshot {
            match capture_maps(pid) {
                Some((maps, truncated)) => {
                    self.maps_truncated += u64::from(truncated);
                    let previous = self.processes.get(&key).map_or(0, |p| p.generation);
                    self.processes.insert(
                        key,
                        CaptureProcess {
                            generation: previous + 1,
                            maps,
                            maps_truncated: truncated,
                            ..Default::default()
                        },
                    );
                }
                None => {
                    self.refresh_failed += 1;
                    return None;
                }
            }
        }
        let process = self.processes.entry(key).or_default();
        let refresh_ip = if kind == "user" {
            ips.iter().copied().find(|ip| {
                !process
                    .maps
                    .iter()
                    .any(|map| *ip >= map.start && *ip < map.end)
                    && !process.unmapped_refreshed.contains(ip)
            })
        } else {
            None
        };
        if let Some(ip) = refresh_ip {
            process.unmapped_refreshed.insert(ip);
            if let Some((maps, truncated)) = capture_maps(pid) {
                process.generation += 1;
                process.maps = maps;
                process.emitted_maps = false;
                process.maps_truncated = truncated;
                self.maps_truncated += u64::from(truncated);
            } else {
                self.refresh_failed += 1;
            }
        }
        let generation = process.generation;
        let reference = stack_ref(pid, starttime, generation, kind, stack_id);
        if !process.stacks.insert((kind.into(), stack_id, generation)) {
            return Some(CapturedStack {
                records: Vec::new(),
                reference,
            });
        }
        let mut records = Vec::new();
        if kind == "user" && !process.emitted_maps {
            let record = ProcessMapsRecord {
                record_type: "process_maps".into(),
                pid,
                starttime,
                maps_generation: generation,
                timestamp_ns,
                mappings: process.maps.clone(),
                truncated: process.maps_truncated,
            };
            records.push(serde_json::to_string(&record).expect("serializing process maps"));
            process.emitted_maps = true;
        }
        let truncated = ips.len() > MAX_FRAMES;
        self.stacks_truncated += u64::from(truncated);
        let stack = StackTraceRecord {
            record_type: "stack_trace".into(),
            stack_trace_ref: reference.clone(),
            pid,
            starttime,
            stack_kind: kind.into(),
            stack_id,
            maps_generation: generation,
            timestamp_ns,
            ips: ips.iter().copied().take(MAX_FRAMES).collect(),
            rendered: rendered.iter().take(MAX_FRAMES).cloned().collect(),
            truncated,
        };
        records.push(serde_json::to_string(&stack).expect("serializing stack trace"));
        Some(CapturedStack { records, reference })
    }

    pub fn degraded(&self) -> bool {
        self.maps_truncated != 0 || self.stacks_truncated != 0 || self.refresh_failed != 0
    }
}

fn stack_ref(pid: u32, starttime: u64, generation: u64, kind: &str, stack_id: i32) -> String {
    format!("{pid}:{starttime}:{generation}:{kind}:{stack_id}")
}

fn read_starttime(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = stat.rfind(')')?;
    stat[end + 1..].split_whitespace().nth(19)?.parse().ok()
}

fn capture_maps(pid: u32) -> Option<(Vec<CapturedMapping>, bool)> {
    let text = fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    let executable: Vec<_> = text
        .lines()
        .filter(|line| {
            line.split_whitespace()
                .nth(1)
                .is_some_and(|p| p.as_bytes().get(2) == Some(&b'x'))
        })
        .collect();
    let bounds_exceeded = executable.len() > MAX_MAPPINGS
        || executable.iter().any(|line| {
            line.split_whitespace()
                .skip(5)
                .collect::<Vec<_>>()
                .join(" ")
                .len()
                > MAX_PATH_BYTES
        });
    let mut mappings = parse_maps_text(&text);
    for mapping in &mut mappings {
        let path = mapping
            .path
            .strip_suffix(" (deleted)")
            .unwrap_or(&mapping.path);
        let map_file = format!(
            "/proc/{pid}/map_files/{:x}-{:x}",
            mapping.start, mapping.end
        );
        if let Ok(bytes) = fs::read(path).or_else(|_| fs::read(map_file)) {
            if let Some(meta) = elf_map_metadata(&bytes, mapping.start, mapping.offset) {
                mapping.elf_type = meta.elf_type;
                mapping.build_id = meta.build_id;
                mapping.load_bias = meta.load_bias;
            }
        }
    }
    Some((mappings, bounds_exceeded))
}

pub fn add_stack_references(line: &str, references: &[String]) -> String {
    if references.is_empty() {
        return line.into();
    }
    let Ok(mut value) = serde_json::from_str::<Value>(line) else {
        return line.into();
    };
    if let Some(object) = value.as_object_mut() {
        object.insert("stack_trace_refs".into(), serde_json::json!(references));
    }
    serde_json::to_string(&value).unwrap_or_else(|_| line.into())
}

pub fn run_native_map(args: NativeMapArgs) -> Result<()> {
    validate_pull_args(&args)?;
    let artifact_dir = args
        .artifact_dir
        .clone()
        .unwrap_or_else(|| default_artifact_dir(&args.capture));
    if args.pull_apk || args.pull_libs {
        pull_artifacts(&args, &artifact_dir)?;
    }
    let document = resolve_capture(&args.capture, &args.symbols, Some(&artifact_dir))?;
    print_native_chains(&document);
    if let Some(path) = &args.json_output {
        write_json_private(path, &document)?;
    }
    Ok(())
}

pub fn run_ghidra_export(args: GhidraExportArgs) -> Result<()> {
    let window_ns = parse_duration_ns(&args.crash_window)?;
    let artifact_dir = args
        .artifact_dir
        .unwrap_or_else(|| default_artifact_dir(&args.capture));
    let native = resolve_capture(&args.capture, &args.symbols, Some(&artifact_dir))?;
    let crashes = collect_crashes(&read_capture_values(&args.capture)?);
    let mut inputs = Vec::new();
    for event in &native.events {
        for frame in &event.frames {
            if let (Some(program), Some(elf_vaddr)) = (&frame.module, frame.elf_vaddr) {
                inputs.push(GhidraBookmarkInput {
                    program: program.clone(),
                    elf_vaddr,
                    label: frame.symbol.clone(),
                    context: event.context.clone(),
                    timestamp_ns: event.timestamp_ns,
                    event_id: event.event_id.clone(),
                    related_crash_ids: related_crashes(event, &crashes, window_ns),
                    confidence: frame.confidence,
                });
            }
        }
    }
    let mut document = aggregate_bookmarks(inputs, MAX_EXEMPLARS);
    document.unresolved = native.unresolved;
    write_json_private(&args.output, &document)
}

pub fn aggregate_bookmarks(
    inputs: Vec<GhidraBookmarkInput>,
    exemplar_limit: usize,
) -> GhidraDocument {
    let mut grouped: BTreeMap<(String, u64), (ProgramIdentity, Vec<GhidraBookmarkInput>)> =
        BTreeMap::new();
    for input in inputs {
        let key = program_key(&input.program);
        grouped
            .entry((key, input.elf_vaddr))
            .or_insert_with(|| (input.program.clone(), Vec::new()))
            .1
            .push(input);
    }
    let mut programs: BTreeMap<String, GhidraProgram> = BTreeMap::new();
    for ((key, elf_vaddr), (mut identity, mut items)) in grouped {
        items.sort_by_key(|item| (item.timestamp_ns, item.event_id.clone()));
        identity.captured_paths.extend(
            items
                .iter()
                .flat_map(|item| item.program.captured_paths.iter().cloned()),
        );
        identity.captured_paths.sort();
        identity.captured_paths.dedup();
        let contexts: BTreeSet<_> = items.iter().map(|item| item.context.clone()).collect();
        let crashes: BTreeSet<_> = items
            .iter()
            .flat_map(|item| item.related_crash_ids.clone())
            .collect();
        let exemplars: BTreeSet<_> = items.iter().map(|item| item.event_id.clone()).collect();
        let confidence = items
            .iter()
            .map(|item| item.confidence)
            .max_by_key(confidence_rank)
            .unwrap_or(NativeConfidence::Unresolved);
        let bookmark = GhidraBookmark {
            elf_vaddr,
            label: items[0].label.clone(),
            contexts: contexts.into_iter().collect(),
            frequency: items.len() as u64,
            first_timestamp_ns: items.first().unwrap().timestamp_ns,
            last_timestamp_ns: items.last().unwrap().timestamp_ns,
            event_exemplars: exemplars.into_iter().take(exemplar_limit).collect(),
            related_crash_ids: crashes.into_iter().take(exemplar_limit).collect(),
            confidence,
        };
        let program = programs.entry(key).or_insert_with(|| GhidraProgram {
            program: identity.clone(),
            bookmarks: Vec::new(),
        });
        program
            .program
            .captured_paths
            .extend(identity.captured_paths);
        program.program.captured_paths.sort();
        program.program.captured_paths.dedup();
        program.bookmarks.push(bookmark);
    }
    GhidraDocument {
        schema: "neutron.ghidra-bookmarks/v1".into(),
        programs: programs.into_values().collect(),
        unresolved: Vec::new(),
    }
}

fn confidence_rank(value: &NativeConfidence) -> u8 {
    match value {
        NativeConfidence::Exact => 0,
        NativeConfidence::Candidate => 1,
        NativeConfidence::Captured => 2,
        NativeConfidence::Unresolved => 3,
    }
}

fn program_key(program: &ProgramIdentity) -> String {
    program
        .build_id
        .clone()
        .or_else(|| program.sha256.clone())
        .unwrap_or_else(|| program.captured_paths.first().cloned().unwrap_or_default())
}

fn resolve_capture(
    capture: &Path,
    symbol_dirs: &[PathBuf],
    artifact_dir: Option<&Path>,
) -> Result<NativeMapDocument> {
    let file =
        File::open(capture).with_context(|| format!("opening capture {}", capture.display()))?;
    let mut maps = HashMap::new();
    let mut stacks = HashMap::new();
    let mut events = Vec::new();
    let mut legacy = Vec::new();
    let mut warnings = Vec::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line.with_context(|| format!("reading capture line {}", index + 1))?;
        let value: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(_) => continue,
        };
        match value.get("type").and_then(Value::as_str) {
            Some("process_maps") => {
                let record: ProcessMapsRecord = serde_json::from_value(value)?;
                if record.truncated {
                    warnings.push(format!(
                        "process_maps pid={} generation={} was truncated",
                        record.pid, record.maps_generation
                    ));
                }
                maps.insert(
                    (record.pid, record.starttime, record.maps_generation),
                    record,
                );
            }
            Some("stack_trace") => {
                let record: StackTraceRecord = serde_json::from_value(value)?;
                if record.truncated {
                    warnings.push(format!(
                        "stack_trace {} was truncated",
                        record.stack_trace_ref
                    ));
                }
                stacks.insert(record.stack_trace_ref.clone(), record);
            }
            Some("capture_health") => {}
            _ => {
                if value.get("stack_trace_refs").is_some() {
                    events.push(value);
                } else if value.get("stack").is_some() {
                    legacy.push(format!("legacy-line-{}", index + 1));
                }
            }
        }
    }
    let index = SymbolIndex::build(symbol_dirs, artifact_dir)?;
    let mut resolved_events = Vec::new();
    let mut unresolved = legacy;
    for event in events {
        let timestamp_ns = timestamp(&event);
        let pid = event.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32;
        let event_id = event
            .get("event_id")
            .map(value_id)
            .unwrap_or_else(|| timestamp_ns.to_string());
        let context = event_context(&event);
        for reference in event
            .get("stack_trace_refs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            let Some(stack) = stacks.get(reference) else {
                unresolved.push(format!("missing stack_trace {reference}"));
                continue;
            };
            if stack.stack_kind != "user" {
                continue;
            }
            let map_record = maps.get(&(stack.pid, stack.starttime, stack.maps_generation));
            let frames = stack
                .ips
                .iter()
                .enumerate()
                .map(|(order, ip)| {
                    resolve_frame(order, *ip, stack.rendered.get(order), map_record, &index)
                })
                .collect();
            resolved_events.push(NativeEvent {
                event_id: event_id.clone(),
                timestamp_ns,
                pid,
                context: context.clone(),
                trace_id: event.get("trace_id").map(value_id),
                stack_trace_ref: reference.into(),
                frames,
            });
        }
    }
    resolved_events.sort_by_key(|event| {
        (
            event.timestamp_ns,
            event.event_id.clone(),
            event.stack_trace_ref.clone(),
        )
    });
    unresolved.sort();
    warnings.sort();
    warnings.dedup();
    Ok(NativeMapDocument {
        schema: "neutron.native-map/v1".into(),
        capture: capture.display().to_string(),
        events: resolved_events,
        unresolved,
        warnings,
    })
}

fn resolve_frame(
    order: usize,
    ip: u64,
    captured: Option<&String>,
    maps: Option<&ProcessMapsRecord>,
    index: &SymbolIndex,
) -> NativeFrame {
    let Some(mapping) = maps.and_then(|record| {
        record
            .mappings
            .iter()
            .find(|map| ip >= map.start && ip < map.end)
    }) else {
        return NativeFrame {
            order,
            runtime_ip: ip,
            elf_vaddr: None,
            file_offset: None,
            symbol: captured.cloned().unwrap_or_else(|| format!("{ip:#x}")),
            module: None,
            confidence: NativeConfidence::Unresolved,
            warnings: vec!["IP is absent from captured executable maps".into()],
        };
    };
    if mapping.path.is_empty() || crate::symbolize::art::is_jit_region(&mapping.path) {
        return NativeFrame {
            order,
            runtime_ip: ip,
            elf_vaddr: None,
            file_offset: None,
            symbol: captured.cloned().unwrap_or_else(|| format!("{ip:#x}")),
            module: None,
            confidence: NativeConfidence::Unresolved,
            warnings: vec!["anonymous/ART JIT frame has no stable ELF address".into()],
        };
    }
    let translated = translate_ip(mapping, ip);
    let artifact = mapping
        .build_id
        .as_ref()
        .and_then(|id| index.by_build_id.get(id))
        .or_else(|| {
            if mapping.build_id.is_some() {
                return None;
            }
            let name = Path::new(&mapping.path).file_name()?.to_str()?;
            index.by_basename.get(name)
        });
    let exact = mapping.build_id.is_some() && artifact.is_some();
    let symbol = translated
        .as_ref()
        .and_then(|address| {
            artifact.and_then(|item| item.symbols.as_ref()?.lookup_vaddr(address.elf_vaddr))
        })
        .or_else(|| captured.cloned())
        .unwrap_or_else(|| {
            translated
                .as_ref()
                .map(|a| format!("{}+{:#x}", mapping.path, a.elf_vaddr))
                .unwrap_or_else(|| format!("{}+{:#x}", mapping.path, ip - mapping.start))
        });
    let program = ProgramIdentity {
        build_id: mapping.build_id.clone(),
        sha256: artifact.map(|item| item.sha256.clone()),
        captured_paths: vec![mapping.path.clone()],
    };
    NativeFrame {
        order,
        runtime_ip: ip,
        elf_vaddr: translated.as_ref().map(|value| value.elf_vaddr),
        file_offset: translated.as_ref().map(|value| value.file_offset),
        symbol,
        module: Some(program),
        confidence: if exact {
            NativeConfidence::Exact
        } else if artifact.is_some() {
            NativeConfidence::Candidate
        } else if captured.is_some() {
            NativeConfidence::Captured
        } else {
            NativeConfidence::Candidate
        },
        warnings: if mapping.build_id.is_some() && artifact.is_none() {
            vec!["no artifact matched captured GNU build-id".into()]
        } else {
            Vec::new()
        },
    }
}

struct Artifact {
    sha256: String,
    symbols: Option<ElfSymbols>,
}

#[derive(Default)]
struct SymbolIndex {
    by_build_id: HashMap<String, Artifact>,
    by_basename: HashMap<String, Artifact>,
}

impl SymbolIndex {
    fn build(symbol_dirs: &[PathBuf], artifact_dir: Option<&Path>) -> Result<Self> {
        let mut paths = Vec::new();
        for root in symbol_dirs.iter().map(PathBuf::as_path) {
            collect_files(root, &mut paths)?;
        }
        paths.sort();
        if let Some(artifact_dir) = artifact_dir {
            let mut artifacts = Vec::new();
            collect_files(artifact_dir, &mut artifacts)?;
            artifacts.sort();
            if paths.len().saturating_add(artifacts.len()) > MAX_ARTIFACTS {
                bail!("symbol artifact count exceeds {MAX_ARTIFACTS}");
            }
            paths.extend(artifacts);
        }
        let mut index = Self::default();
        let mut total_bytes = 0u64;
        for path in paths {
            let size = match fs::metadata(&path) {
                Ok(metadata) => metadata.len(),
                Err(_) => continue,
            };
            total_bytes = total_bytes
                .checked_add(size)
                .context("symbol artifact size overflow")?;
            if size > MAX_ARTIFACT_BYTES || total_bytes > MAX_TOTAL_ARTIFACT_BYTES {
                bail!("symbol artifact byte limit exceeded");
            }
            let Ok(bytes) = fs::read(&path) else { continue };
            let Ok(elf) = Elf::parse(&bytes) else {
                continue;
            };
            let artifact = Artifact {
                sha256: hex(&Sha256::digest(&bytes)),
                symbols: ElfSymbols::from_bytes(&bytes),
            };
            if let Some(id) = elf_build_id(&elf, &bytes) {
                index.by_build_id.entry(id).or_insert(artifact);
            } else if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                index.by_basename.entry(name.into()).or_insert(artifact);
            }
        }
        Ok(index)
    }
}

fn collect_files(root: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    collect_files_at(root, files, 0)
}

fn collect_files_at(root: &Path, files: &mut Vec<PathBuf>, depth: usize) -> Result<()> {
    if depth > MAX_SYMBOL_DEPTH {
        bail!("symbol directory depth exceeds {MAX_SYMBOL_DEPTH}");
    }
    if root.is_file() {
        if files.len() >= MAX_ARTIFACTS {
            bail!("symbol artifact count exceeds {MAX_ARTIFACTS}");
        }
        files.push(root.to_path_buf());
        return Ok(());
    }
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root)
        .with_context(|| format!("reading symbol directory {}", root.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            collect_files_at(&path, files, depth + 1)?;
        } else if file_type.is_file() {
            if files.len() >= MAX_ARTIFACTS {
                bail!("symbol artifact count exceeds {MAX_ARTIFACTS}");
            }
            files.push(path);
        }
    }
    Ok(())
}

fn validate_pull_args(args: &NativeMapArgs) -> Result<()> {
    if (args.pull_apk || args.pull_libs) && args.adb_serial.as_deref().map_or(true, str::is_empty) {
        bail!("--pull-apk/--pull-libs require explicit --adb-serial");
    }
    Ok(())
}

fn default_artifact_dir(capture: &Path) -> PathBuf {
    let stem = capture
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("capture");
    capture.with_file_name(format!("{stem}.native-artifacts"))
}

fn pull_artifacts(args: &NativeMapArgs, artifact_dir: &Path) -> Result<()> {
    let serial = args.adb_serial.as_deref().expect("validated serial");
    let values = read_capture_values(&args.capture)?;
    verify_device_identity(serial, &values)?;
    create_private_dir(artifact_dir)?;
    let staging = artifact_dir.join(format!(".pull-partial-{}", std::process::id()));
    remove_path(&staging)?;
    create_private_dir(&staging)?;
    if let Err(error) = pull_artifacts_into(args, serial, &values, &staging) {
        let _ = remove_path(&staging);
        return Err(error);
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let session = artifact_dir.join(format!("pull-{}-{nonce}", std::process::id()));
    if let Err(error) = fs::rename(&staging, session) {
        let _ = remove_path(&staging);
        return Err(error.into());
    }
    Ok(())
}

fn pull_artifacts_into(
    args: &NativeMapArgs,
    serial: &str,
    values: &[Value],
    artifact_dir: &Path,
) -> Result<()> {
    let mut remote_paths = BTreeSet::new();
    if args.pull_libs {
        for value in values {
            if value.get("type").and_then(Value::as_str) != Some("process_maps") {
                continue;
            }
            if let Ok(record) = serde_json::from_value::<ProcessMapsRecord>(value.clone()) {
                remote_paths.extend(
                    record
                        .mappings
                        .into_iter()
                        .filter(|map| map.elf_type.is_some())
                        .map(|map| map.path)
                        .filter(|path| allowed_library_path(path)),
                );
            }
        }
    }
    if args.pull_apk {
        let package = select_package(args.package.as_deref(), values)?;
        let output = adb_output(serial, &["shell", "cmd", "package", "path", &package])?;
        for line in output.lines() {
            if let Some(path) = line.strip_prefix("package:") {
                if allowed_apk_path(path) {
                    remote_paths.insert(path.into());
                }
            }
        }
    }
    if remote_paths.len() > MAX_ARTIFACTS {
        bail!("artifact count exceeds {MAX_ARTIFACTS}");
    }
    let mut total = 0u64;
    let mut artifact_count = remote_paths.len();
    for remote in remote_paths {
        let relative = Path::new(&remote)
            .strip_prefix("/")
            .context("remote artifact path is not absolute")?;
        let destination = artifact_dir.join("pulled").join(relative);
        ensure_contained(&destination, artifact_dir)?;
        let parent = destination.parent().context("artifact has no parent")?;
        create_private_dir(parent)?;
        ensure_real_parent(parent, artifact_dir)?;
        let temporary = destination.with_extension("partial");
        let status = Command::new("adb")
            .args(["-s", serial, "pull", &remote])
            .arg(&temporary)
            .status()
            .context("running adb pull")?;
        if !status.success() {
            let _ = fs::remove_file(&temporary);
            bail!("adb pull failed for {remote}");
        }
        let size = fs::metadata(&temporary)?.len();
        total = total.checked_add(size).context("artifact size overflow")?;
        if size > MAX_ARTIFACT_BYTES || total > MAX_TOTAL_ARTIFACT_BYTES {
            let _ = fs::remove_file(&temporary);
            bail!("artifact pull limit exceeded");
        }
        let is_apk = destination.extension().and_then(|value| value.to_str()) == Some("apk");
        if !is_apk {
            let mut magic = [0u8; 4];
            let valid_elf = File::open(&temporary)
                .and_then(|mut file| file.read_exact(&mut magic))
                .is_ok()
                && magic == *b"\x7fELF";
            if !valid_elf {
                let _ = fs::remove_file(&temporary);
                bail!("pulled executable is not ELF: {remote}");
            }
        }
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
        fs::rename(&temporary, &destination)?;
        if is_apk {
            extract_apk_elfs(&destination, artifact_dir, &mut total, &mut artifact_count)?;
        }
    }
    Ok(())
}

fn remove_path(path: &Path) -> Result<()> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn verify_device_identity(serial: &str, values: &[Value]) -> Result<()> {
    let health = values
        .iter()
        .find(|value| value.get("type").and_then(Value::as_str) == Some("capture_health"))
        .context("capture has no device identity")?;
    let expected_fingerprint = health
        .get("fingerprint")
        .and_then(Value::as_str)
        .context("capture has no fingerprint")?;
    let expected_boot = health
        .get("boot_id")
        .and_then(Value::as_str)
        .context("capture has no boot_id")?;
    let fingerprint = adb_output(serial, &["shell", "getprop", "ro.build.fingerprint"])?;
    let boot = adb_output(serial, &["shell", "cat", "/proc/sys/kernel/random/boot_id"])?;
    if fingerprint.trim() != expected_fingerprint || boot.trim() != expected_boot {
        bail!("connected device fingerprint or boot ID does not match capture");
    }
    Ok(())
}

fn adb_output(serial: &str, args: &[&str]) -> Result<String> {
    let output = Command::new("adb")
        .args(["-s", serial])
        .args(args)
        .output()
        .context("running adb")?;
    if !output.status.success() {
        bail!(
            "adb command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn allowed_library_path(path: &str) -> bool {
    [
        "/system/",
        "/vendor/",
        "/product/",
        "/system_ext/",
        "/apex/",
        "/data/app/",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
        && !path.contains('\0')
        && !path.ends_with(" (deleted)")
        && !Path::new(path)
            .components()
            .any(|component| matches!(component, Component::ParentDir))
}

fn allowed_apk_path(path: &str) -> bool {
    path.starts_with("/data/app/")
        && path.ends_with(".apk")
        && !path.contains('\0')
        && !Path::new(path)
            .components()
            .any(|component| matches!(component, Component::ParentDir))
}

fn select_package(explicit: Option<&str>, values: &[Value]) -> Result<String> {
    if let Some(package) = explicit {
        if valid_package(package) {
            return Ok(package.into());
        }
        bail!("invalid --package");
    }
    let packages: BTreeSet<_> = values
        .iter()
        .filter_map(|value| value.get("root_package").and_then(Value::as_str))
        .collect();
    if packages.len() != 1 {
        bail!("--package is required when capture root_package is absent or ambiguous");
    }
    let package = *packages.first().unwrap();
    if !valid_package(package) {
        bail!("capture contains invalid root_package");
    }
    Ok(package.into())
}

fn valid_package(package: &str) -> bool {
    !package.is_empty()
        && package
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_'))
}

fn extract_apk_elfs(
    apk: &Path,
    artifact_dir: &Path,
    total: &mut u64,
    artifact_count: &mut usize,
) -> Result<()> {
    let file = File::open(apk)?;
    let mut archive = zip::ZipArchive::new(file).context("opening APK ZIP")?;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        let Some(path) = entry.enclosed_name() else {
            bail!("APK contains a traversal path");
        };
        if !path.starts_with("lib")
            || path.extension().and_then(|value| value.to_str()) != Some("so")
        {
            continue;
        }
        if entry.size() > MAX_ARTIFACT_BYTES {
            bail!("APK ELF entry exceeds per-file limit");
        }
        let destination = artifact_dir
            .join("apk")
            .join(
                apk.strip_prefix(artifact_dir)
                    .context("APK is outside artifact cache")?,
            )
            .join(&path);
        ensure_contained(&destination, artifact_dir)?;
        if let Some(parent) = destination.parent() {
            create_private_dir(parent)?;
            ensure_real_parent(parent, artifact_dir)?;
        }
        let mut bytes = Vec::with_capacity(entry.size() as usize);
        entry.take(MAX_ARTIFACT_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
            bail!("APK ELF entry exceeds per-file limit");
        }
        if !bytes.starts_with(b"\x7fELF") {
            continue;
        }
        *artifact_count += 1;
        if *artifact_count > MAX_ARTIFACTS {
            bail!("artifact count exceeds {MAX_ARTIFACTS}");
        }
        *total = total
            .checked_add(bytes.len() as u64)
            .context("artifact size overflow")?;
        if *total > MAX_TOTAL_ARTIFACT_BYTES {
            bail!("artifact total exceeds limit");
        }
        if fs::symlink_metadata(&destination)
            .ok()
            .is_some_and(|metadata| metadata.file_type().is_symlink())
        {
            bail!("artifact destination cannot be a symlink");
        }
        let mut output = File::create(&destination)?;
        output.write_all(&bytes)?;
        output.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn ensure_contained(path: &Path, root: &Path) -> Result<()> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
        || !path.starts_with(root)
    {
        bail!("artifact path escapes cache");
    }
    Ok(())
}

fn ensure_real_parent(parent: &Path, root: &Path) -> Result<()> {
    let root = fs::canonicalize(root)?;
    let parent = fs::canonicalize(parent)?;
    if !parent.starts_with(root) {
        bail!("artifact path escapes cache through a symlink");
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path)
        .ok()
        .is_some_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("artifact directory cannot be a symlink: {}", path.display());
    }
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn read_capture_values(path: &Path) -> Result<Vec<Value>> {
    Ok(BufReader::new(File::open(path)?)
        .lines()
        .filter_map(|line| serde_json::from_str(&line.ok()?).ok())
        .collect())
}

fn write_json_private(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    crate::private_output::write_json(path, value, true)
}

fn print_native_chains(document: &NativeMapDocument) {
    for event in &document.events {
        println!(
            "{} pid={} event={}:",
            event.context, event.pid, event.event_id
        );
        for frame in &event.frames {
            println!(
                "  {:>3} {:#018x} {}",
                frame.order, frame.runtime_ip, frame.symbol
            );
        }
    }
    for item in &document.unresolved {
        eprintln!("unresolved: {item}");
    }
}

fn timestamp(value: &Value) -> u64 {
    value
        .get("ts_ns")
        .or_else(|| value.get("timestamp_ns"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

fn event_context(value: &Value) -> String {
    value
        .get("syscall")
        .or_else(|| value.get("name"))
        .or_else(|| value.get("kind"))
        .and_then(Value::as_str)
        .unwrap_or("event")
        .into()
}

#[derive(Debug)]
struct CrashLink {
    id: String,
    pid: u32,
    timestamp_ns: u64,
    trace_id: Option<String>,
}

fn collect_crashes(values: &[Value]) -> Vec<CrashLink> {
    values
        .iter()
        .filter_map(|value| {
            let record_type = value.get("type")?.as_str()?;
            let (pid, is_crash) = match record_type {
                "process_exit" => (
                    value.get("pid")?.as_u64()? as u32,
                    value.get("classification").and_then(Value::as_str) == Some("crash"),
                ),
                "binder_call" => (
                    value.get("callee_pid")?.as_u64()? as u32,
                    value.get("status").and_then(Value::as_str) == Some("callee_crashed"),
                ),
                _ => return None,
            };
            is_crash.then(|| CrashLink {
                id: value
                    .get("event_id")
                    .map(value_id)
                    .unwrap_or_else(|| format!("{record_type}:{}", timestamp(value))),
                pid,
                timestamp_ns: timestamp(value),
                trace_id: value.get("trace_id").map(value_id),
            })
        })
        .collect()
}

fn related_crashes(event: &NativeEvent, crashes: &[CrashLink], window_ns: u64) -> Vec<String> {
    crashes
        .iter()
        .filter(|crash| {
            crash.pid == event.pid
                && crash.timestamp_ns.abs_diff(event.timestamp_ns) <= window_ns
                && match (&event.trace_id, &crash.trace_id) {
                    (Some(event_trace), Some(crash_trace)) => event_trace == crash_trace,
                    _ => true,
                }
        })
        .map(|crash| crash.id.clone())
        .take(MAX_EXEMPLARS)
        .collect()
}

fn value_id(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| value.to_string())
}

fn parse_duration_ns(value: &str) -> Result<u64> {
    crate::matcher::parse_latency_us(value)?
        .checked_mul(1_000)
        .context("duration is too large")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_keeps_only_executable_maps_and_bounds_paths() {
        let long = "a".repeat(MAX_PATH_BYTES + 20);
        let maps = parse_maps_text(&format!(
            "1000-2000 r-xp 00001000 fd:00 7 /{long}\n2000-3000 rw-p 0 00:00 0 [heap]"
        ));
        assert_eq!(maps.len(), 1);
        assert_eq!(maps[0].path.len(), MAX_PATH_BYTES);
        assert_eq!(maps[0].device, "fd:00");
        assert_eq!(maps[0].inode, 7);
    }

    #[test]
    fn pull_requires_explicit_serial() {
        let args = NativeMapArgs {
            capture: "x".into(),
            symbols: vec![],
            pull_apk: true,
            pull_libs: false,
            adb_serial: None,
            package: None,
            artifact_dir: None,
            json_output: None,
        };
        assert!(validate_pull_args(&args)
            .unwrap_err()
            .to_string()
            .contains("--adb-serial"));
    }

    #[test]
    fn only_allowlisted_device_library_paths_are_pullable() {
        assert!(allowed_library_path(
            "/apex/com.android.runtime/lib64/libc.so"
        ));
        assert!(!allowed_library_path("/data/local/tmp/evil.so"));
    }

    #[test]
    fn crash_linkage_obeys_pid_trace_and_window() {
        let event = NativeEvent {
            event_id: "event".into(),
            timestamp_ns: 10,
            pid: 7,
            context: "ioctl".into(),
            trace_id: Some("trace-a".into()),
            stack_trace_ref: "stack".into(),
            frames: Vec::new(),
        };
        let crashes = vec![
            CrashLink {
                id: "hit".into(),
                pid: 7,
                timestamp_ns: 12,
                trace_id: Some("trace-a".into()),
            },
            CrashLink {
                id: "wrong-trace".into(),
                pid: 7,
                timestamp_ns: 12,
                trace_id: Some("trace-b".into()),
            },
            CrashLink {
                id: "late".into(),
                pid: 7,
                timestamp_ns: 30,
                trace_id: Some("trace-a".into()),
            },
        ];
        assert_eq!(related_crashes(&event, &crashes, 5), vec!["hit"]);
    }

    #[test]
    fn capture_orders_maps_before_stack_and_deduplicates_reference() {
        let pid = std::process::id();
        let ip = capture_orders_maps_before_stack_and_deduplicates_reference as *const () as u64;
        let mut state = CaptureNativeState::default();
        let first = state
            .capture_stack(pid, 1, "user", 9, &[ip], &["fixture".into()])
            .unwrap();
        assert_eq!(first.records.len(), 2);
        assert!(first.records[0].contains(r#""type":"process_maps""#));
        assert!(first.records[1].contains(r#""type":"stack_trace""#));

        let duplicate = state
            .capture_stack(pid, 2, "user", 9, &[ip], &["fixture".into()])
            .unwrap();
        assert!(duplicate.records.is_empty());
        assert_eq!(duplicate.reference, first.reference);

        state.invalidate(pid);
        let refreshed = state
            .capture_stack(pid, 3, "user", 10, &[ip], &["fixture".into()])
            .unwrap();
        assert_eq!(refreshed.records.len(), 2);
        assert!(refreshed.reference.contains(":2:user:10"));
    }

    #[test]
    fn symbol_directories_take_precedence_over_artifact_cache() {
        let root =
            std::env::temp_dir().join(format!("neutron-symbol-index-{}", std::process::id()));
        let symbols = root.join("symbols");
        let artifacts = root.join("artifacts");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&symbols).unwrap();
        fs::create_dir_all(&artifacts).unwrap();
        let original = fs::read("/bin/true").unwrap();
        let mut changed = original.clone();
        changed.push(0);
        fs::write(symbols.join("fixture"), &original).unwrap();
        fs::write(artifacts.join("fixture"), &changed).unwrap();

        let elf = Elf::parse(&original).unwrap();
        let build_id = elf_build_id(&elf, &original).unwrap();
        let index = SymbolIndex::build(&[symbols], Some(&artifacts)).unwrap();
        assert_eq!(
            index.by_build_id[&build_id].sha256,
            hex(&Sha256::digest(&original))
        );
        let _ = fs::remove_dir_all(root);
    }
}
