//! Bounded SELinux AVC ingestion and evidence-safe offline explanation.

use std::collections::{hash_map::DefaultHasher, BTreeMap, BTreeSet, HashSet, VecDeque};
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{self, BufRead, BufReader, Read};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use neutron_common::ProcessTraceContext;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::causal::CausalRelation;

const MAX_AVC_LINE_BYTES: usize = 16 * 1024;
const MAX_CAPTURE_LINE_BYTES: usize = 1024 * 1024;
const MAX_CAPTURE_RECORDS: usize = 1_000_000;
const MAX_CONTEXT_BYTES: usize = 512;
const MAX_COMM_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 4096;
const MAX_CLASS_BYTES: usize = 64;
const MAX_PERMISSION_BYTES: usize = 64;
const MAX_PERMISSIONS: usize = 32;
const MAX_FIELDS: usize = 64;
const FALLBACK_DEDUP_WINDOW_NS: u64 = 2_000_000_000;
const MAX_DELEGATED_PATHS: usize = 256;

#[derive(Args, Debug)]
pub struct ExplainArgs {
    /// NDJSON capture (`-` for stdin).
    pub capture: String,

    /// Global capture event ID of a type:"selinux_denial" record.
    #[arg(long)]
    pub event_id: u64,

    /// Report format.
    #[arg(long, value_enum, default_value_t = ExplainFormat::Text)]
    pub format: ExplainFormat,

    /// Write the report to a file instead of stdout.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum ExplainFormat {
    #[default]
    Text,
    Json,
}

#[derive(Subcommand, Debug)]
pub enum SelinuxCommand {
    /// Explain one observed AVC decision and exact delegated evidence.
    Explain(ExplainArgs),
}

/// A process-wide follow context cannot prove which thread caused an AVC.
pub fn process_context_relation(context: ProcessTraceContext) -> CausalRelation {
    if context.depth == 0 {
        CausalRelation::Exact
    } else {
        CausalRelation::Inferred
    }
}

pub fn run(command: SelinuxCommand) -> Result<()> {
    match command {
        SelinuxCommand::Explain(args) => run_explain(args),
    }
}

fn run_explain(args: ExplainArgs) -> Result<()> {
    let explanation = if args.capture == "-" {
        explain_from_reader(io::stdin().lock(), args.event_id)?
    } else {
        let file = fs::File::open(&args.capture)
            .with_context(|| format!("opening capture {}", args.capture))?;
        explain_from_reader(BufReader::new(file), args.event_id)?
    };
    let report = match args.format {
        ExplainFormat::Text => render_explanation_text(&explanation),
        ExplainFormat::Json => serde_json::to_string_pretty(&explanation)?,
    };
    match args.output {
        Some(path) => fs::write(&path, format!("{report}\n"))
            .with_context(|| format!("writing {}", path.display())),
        None => {
            println!("{report}");
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SelinuxDenial {
    #[serde(rename = "type", default = "denial_type")]
    pub record_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<u64>,
    #[serde(default)]
    pub ts_ns: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_id: Option<String>,
    pub pid: u32,
    pub tid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    pub comm: String,
    pub scontext: String,
    pub source_domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_domain: Option<String>,
    pub tcontext: String,
    pub target_type: String,
    pub tclass: String,
    pub permissions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ioctlcmd: Option<String>,
    pub permissive: bool,
    pub result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_confidence: Option<String>,
}

fn denial_type() -> String {
    "selinux_denial".into()
}

pub fn parse_avc_line(line: &str) -> Result<Option<SelinuxDenial>> {
    if !line.contains("avc:") {
        return Ok(None);
    }
    if line.len() > MAX_AVC_LINE_BYTES {
        bail!("AVC line exceeds {MAX_AVC_LINE_BYTES} bytes");
    }
    let avc = line
        .split_once("avc:")
        .map(|(_, value)| value.trim_start())
        .context("malformed AVC prefix")?;
    let denied = avc
        .strip_prefix("denied")
        .context("unsupported AVC record (expected denied)")?
        .trim_start();
    let permissions_end = denied.find('}').context("AVC permissions missing '}'")?;
    let permissions_raw = denied
        .get(1..permissions_end)
        .filter(|_| denied.starts_with('{'))
        .context("AVC permissions missing '{'")?;
    let mut permissions: Vec<String> = permissions_raw
        .split_ascii_whitespace()
        .map(str::to_string)
        .collect();
    if permissions.is_empty() || permissions.len() > MAX_PERMISSIONS {
        bail!("AVC permission count is outside 1..={MAX_PERMISSIONS}");
    }
    if permissions
        .iter()
        .any(|permission| permission.len() > MAX_PERMISSION_BYTES)
    {
        bail!("AVC permission exceeds {MAX_PERMISSION_BYTES} bytes");
    }
    permissions.sort();
    permissions.dedup();

    let fields = parse_fields(&denied[permissions_end + 1..])?;
    let tid = required_field(&fields, "pid")?
        .parse::<u32>()
        .context("invalid AVC pid")?;
    if tid == 0 {
        bail!("AVC pid must be non-zero");
    }
    let comm = bounded_field(&fields, "comm", MAX_COMM_BYTES)?.unwrap_or_default();
    let scontext = required_bounded_field(&fields, "scontext", MAX_CONTEXT_BYTES)?;
    let tcontext = required_bounded_field(&fields, "tcontext", MAX_CONTEXT_BYTES)?;
    let source_domain = context_type(&scontext).context("invalid AVC scontext")?;
    let target_type = context_type(&tcontext).context("invalid AVC tcontext")?;
    let tclass = required_bounded_field(&fields, "tclass", MAX_CLASS_BYTES)?;
    let path = bounded_field(&fields, "path", MAX_PATH_BYTES)?.or(bounded_field(
        &fields,
        "name",
        MAX_PATH_BYTES,
    )?);
    let ioctlcmd = bounded_field(&fields, "ioctlcmd", MAX_CLASS_BYTES)?;
    let permissive = fields.get("permissive").is_some_and(|value| value == "1");
    let permission = (permissions.len() == 1).then(|| permissions[0].clone());

    Ok(Some(SelinuxDenial {
        record_type: denial_type(),
        event_id: None,
        ts_ns: 0,
        audit_id: parse_audit_id(line),
        pid: tid,
        tid,
        uid: None,
        comm,
        scontext,
        source_domain,
        current_context: None,
        current_domain: None,
        tcontext,
        target_type,
        tclass,
        permissions,
        permission,
        path,
        ioctlcmd,
        permissive,
        result: if permissive {
            "allowed_permissive".into()
        } else {
            "denied".into()
        },
        identity_confidence: Some("candidate".into()),
    }))
}

fn parse_fields(input: &str) -> Result<BTreeMap<String, String>> {
    let bytes = input.as_bytes();
    let mut fields = BTreeMap::new();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let key_start = index;
        while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
        {
            index += 1;
        }
        if key_start == index || bytes.get(index) != Some(&b'=') {
            while index < bytes.len() && !bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            continue;
        }
        let key = &input[key_start..index];
        index += 1;
        let mut value = String::new();
        if bytes.get(index) == Some(&b'"') {
            index += 1;
            let mut closed = false;
            while index < bytes.len() {
                match bytes[index] {
                    b'"' => {
                        index += 1;
                        closed = true;
                        break;
                    }
                    b'\\' if index + 1 < bytes.len() => {
                        index += 1;
                        value.push(bytes[index] as char);
                        index += 1;
                    }
                    byte => {
                        value.push(byte as char);
                        index += 1;
                    }
                }
            }
            if !closed {
                bail!("unterminated quoted AVC field {key}");
            }
        } else {
            let value_start = index;
            while index < bytes.len() && !bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            value.push_str(&input[value_start..index]);
        }
        if fields.len() >= MAX_FIELDS {
            bail!("AVC field count exceeds {MAX_FIELDS}");
        }
        fields.insert(key.to_string(), value);
    }
    Ok(fields)
}

fn required_field<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    fields
        .get(key)
        .map(String::as_str)
        .with_context(|| format!("AVC field {key} missing"))
}

fn bounded_field(
    fields: &BTreeMap<String, String>,
    key: &str,
    max: usize,
) -> Result<Option<String>> {
    let Some(value) = fields.get(key) else {
        return Ok(None);
    };
    if value.len() > max {
        bail!("AVC field {key} exceeds {max} bytes");
    }
    Ok(Some(value.clone()))
}

fn required_bounded_field(
    fields: &BTreeMap<String, String>,
    key: &str,
    max: usize,
) -> Result<String> {
    bounded_field(fields, key, max)?.with_context(|| format!("AVC field {key} missing"))
}

fn context_type(context: &str) -> Option<String> {
    let mut parts = context.split(':');
    let user = parts.next()?;
    let role = parts.next()?;
    let kind = parts.next()?;
    let level = parts.next()?;
    (!user.is_empty() && !role.is_empty() && !kind.is_empty() && !level.is_empty())
        .then(|| kind.to_string())
}

fn parse_audit_id(line: &str) -> Option<String> {
    let start = line.find("audit(")? + "audit(".len();
    let value = line.get(start..)?.split(')').next()?;
    (value.len() <= 64
        && !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'.' | b':')))
    .then(|| value.to_string())
}

#[derive(Debug)]
enum DedupKey {
    Audit(String),
    Fingerprint(u64, u64),
}

#[derive(Debug)]
pub struct DenialDeduper {
    capacity: usize,
    order: VecDeque<DedupKey>,
    audit_ids: HashSet<String>,
    fingerprints: BTreeMap<u64, u64>,
}

impl DenialDeduper {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::new(),
            audit_ids: HashSet::new(),
            fingerprints: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    pub fn is_duplicate(&mut self, denial: &SelinuxDenial, now_ns: u64) -> bool {
        let duplicate = if let Some(audit_id) = &denial.audit_id {
            if self.audit_ids.contains(audit_id) {
                true
            } else {
                self.audit_ids.insert(audit_id.clone());
                self.order.push_back(DedupKey::Audit(audit_id.clone()));
                false
            }
        } else {
            let fingerprint = denial_fingerprint(denial);
            if self.fingerprints.get(&fingerprint).is_some_and(|previous| {
                now_ns.saturating_sub(*previous) <= FALLBACK_DEDUP_WINDOW_NS
            }) {
                true
            } else {
                self.fingerprints.insert(fingerprint, now_ns);
                self.order
                    .push_back(DedupKey::Fingerprint(fingerprint, now_ns));
                false
            }
        };
        while self.order.len() > self.capacity {
            match self.order.pop_front() {
                Some(DedupKey::Audit(id)) => {
                    self.audit_ids.remove(&id);
                }
                Some(DedupKey::Fingerprint(fingerprint, timestamp)) => {
                    if self.fingerprints.get(&fingerprint) == Some(&timestamp) {
                        self.fingerprints.remove(&fingerprint);
                    }
                }
                None => break,
            }
        }
        duplicate
    }
}

fn denial_fingerprint(denial: &SelinuxDenial) -> u64 {
    let mut hasher = DefaultHasher::new();
    denial.pid.hash(&mut hasher);
    denial.comm.hash(&mut hasher);
    denial.scontext.hash(&mut hasher);
    denial.tcontext.hash(&mut hasher);
    denial.tclass.hash(&mut hasher);
    denial.permissions.hash(&mut hasher);
    denial.path.hash(&mut hasher);
    denial.ioctlcmd.hash(&mut hasher);
    denial.permissive.hash(&mut hasher);
    hasher.finish()
}

pub fn resolve_process_identity(denial: &mut SelinuxDenial) {
    let status_path = format!("/proc/{}/status", denial.tid);
    let Ok(status) = read_bounded_file(&status_path, 64 * 1024) else {
        return;
    };
    let Ok(status) = String::from_utf8(status) else {
        return;
    };
    let Some(tgid) = status_value(&status, "Tgid:").and_then(|value| value.parse().ok()) else {
        return;
    };
    denial.pid = tgid;
    denial.uid = status_value(&status, "Uid:").and_then(|value| value.parse().ok());
    denial.identity_confidence = None;

    let attr_path = format!("/proc/{tgid}/attr/current");
    let Ok(current) = read_bounded_file(&attr_path, MAX_CONTEXT_BYTES) else {
        return;
    };
    let current = String::from_utf8_lossy(&current).trim().to_string();
    if let Some(domain) = context_type(&current) {
        denial.current_context = Some(current);
        denial.current_domain = Some(domain);
    }
}

fn read_bounded_file(path: &str, limit: usize) -> io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(limit.min(4096));
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too large"));
    }
    Ok(bytes)
}

fn status_value<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key))?
        .split_ascii_whitespace()
        .next()
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SelinuxSourceStats {
    pub parsed: u64,
    pub malformed: u64,
    pub deduplicated: u64,
    pub out_of_scope: u64,
}

pub struct SelinuxLogcatReader {
    child: Option<Child>,
    reader: BufReader<std::process::ChildStdout>,
    pending_line: Vec<u8>,
    pending_overflow: bool,
    deduper: DenialDeduper,
    stats: SelinuxSourceStats,
}

fn selinux_logcat_args() -> &'static [&'static str] {
    &[
        "-v",
        "threadtime",
        "-T",
        "0",
        "-b",
        "kernel",
        "-b",
        "system",
        "-b",
        "main",
        "auditd:V",
        "kernel:V",
        "avc:V",
        "SELinux:V",
        "*:S",
    ]
}

impl SelinuxLogcatReader {
    pub fn spawn() -> io::Result<Self> {
        let mut child = Command::new("/system/bin/logcat")
            .args(selinux_logcat_args())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("SELinux logcat stdout missing"))?;
        crate::sources::logcat::set_nonblocking(stdout.as_raw_fd())?;
        Ok(Self {
            child: Some(child),
            reader: BufReader::new(stdout),
            pending_line: Vec::with_capacity(4096),
            pending_overflow: false,
            deduper: DenialDeduper::new(4096),
            stats: SelinuxSourceStats::default(),
        })
    }

    pub fn drain(&mut self, now_ns: u64) -> Vec<SelinuxDenial> {
        let mut denials = Vec::new();
        loop {
            let available = match self.reader.fill_buf() {
                Ok([]) => break,
                Ok(available) => available,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            };
            let newline = available.iter().position(|byte| *byte == b'\n');
            let consume = newline.map_or(available.len(), |index| index + 1);
            let content = newline.map_or(available, |index| &available[..index]);
            if self.pending_line.len() < MAX_AVC_LINE_BYTES + 1 {
                let remaining = MAX_AVC_LINE_BYTES + 1 - self.pending_line.len();
                self.pending_line
                    .extend_from_slice(&content[..content.len().min(remaining)]);
            }
            self.pending_overflow |= self.pending_line.len() > MAX_AVC_LINE_BYTES;
            self.reader.consume(consume);
            if newline.is_none() {
                continue;
            }
            if self.pending_overflow {
                self.stats.malformed = self.stats.malformed.saturating_add(1);
            } else {
                let line = String::from_utf8_lossy(&self.pending_line);
                match parse_avc_line(&line) {
                    Ok(Some(denial)) => {
                        self.stats.parsed = self.stats.parsed.saturating_add(1);
                        if self.deduper.is_duplicate(&denial, now_ns) {
                            self.stats.deduplicated = self.stats.deduplicated.saturating_add(1);
                        } else {
                            denials.push(denial);
                        }
                    }
                    Ok(None) => {}
                    Err(_) => self.stats.malformed = self.stats.malformed.saturating_add(1),
                }
            }
            self.pending_line.clear();
            self.pending_overflow = false;
        }
        denials
    }

    pub fn record_out_of_scope(&mut self) {
        self.stats.out_of_scope = self.stats.out_of_scope.saturating_add(1);
    }

    pub fn stats(&self) -> SelinuxSourceStats {
        self.stats
    }

    pub fn is_available(&mut self) -> bool {
        self.child
            .as_mut()
            .is_some_and(|child| child.try_wait().ok().flatten().is_none())
    }
}

impl Drop for SelinuxLogcatReader {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SelinuxExplanation {
    pub schema: &'static str,
    pub denial: Value,
    pub policy: PolicyExplanation,
    pub delegated_paths: Vec<DelegatedPath>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PolicyExplanation {
    pub source_type: String,
    pub target_type: String,
    pub tclass: String,
    pub permissions: Vec<String>,
    pub permissive: bool,
    pub result: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DelegatedPath {
    pub service: String,
    pub callee_pid: u64,
    pub binder_edges: Vec<BinderHop>,
    pub syscall: Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct BinderHop {
    pub caller_pid: u64,
    pub callee_pid: u64,
    pub service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
}

pub fn explain_from_reader<R: BufRead>(mut reader: R, event_id: u64) -> Result<SelinuxExplanation> {
    let mut records = Vec::new();
    let mut line = Vec::new();
    loop {
        match read_bounded_line(&mut reader, &mut line, MAX_CAPTURE_LINE_BYTES)? {
            false => break,
            true => {
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                if let Ok(value) = serde_json::from_slice::<Value>(&line) {
                    records.push(value);
                    if records.len() > MAX_CAPTURE_RECORDS {
                        bail!("capture exceeds {MAX_CAPTURE_RECORDS} records");
                    }
                }
            }
        }
    }

    let matching = records
        .iter()
        .find(|record| value_u64(record, "event_id") == Some(event_id));
    let denial = matching
        .with_context(|| format!("event {event_id} not found in capture"))?
        .clone();
    if value_str(&denial, "type") != Some("selinux_denial") {
        bail!("event {event_id} is not a SELinux denial");
    }
    let parsed: SelinuxDenial =
        serde_json::from_value(denial.clone()).context("SELinux denial record is malformed")?;
    let policy = PolicyExplanation {
        source_type: parsed.source_domain.clone(),
        target_type: parsed.target_type.clone(),
        tclass: parsed.tclass.clone(),
        permissions: parsed.permissions.clone(),
        permissive: parsed.permissive,
        result: parsed.result.clone(),
    };
    let (delegated_paths, warnings) = find_delegated_paths(&records, &denial);
    Ok(SelinuxExplanation {
        schema: "neutron.selinux-explanation/v1",
        denial,
        policy,
        delegated_paths,
        warnings,
    })
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    out: &mut Vec<u8>,
    limit: usize,
) -> io::Result<bool> {
    out.clear();
    let mut exceeded = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if exceeded {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "capture line too long",
                ));
            }
            return Ok(!out.is_empty());
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consume = newline.map_or(available.len(), |index| index + 1);
        let content = newline.map_or(available, |index| &available[..index]);
        if out.len() < limit + 1 {
            let remaining = limit + 1 - out.len();
            out.extend_from_slice(&content[..content.len().min(remaining)]);
        }
        exceeded |= out.len() > limit;
        reader.consume(consume);
        if newline.is_some() {
            if exceeded {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "capture line too long",
                ));
            }
            return Ok(true);
        }
    }
}

fn find_delegated_paths(records: &[Value], denial: &Value) -> (Vec<DelegatedPath>, Vec<String>) {
    let denial_id = value_u64(denial, "event_id").unwrap_or(0);
    let denial_pid = value_u64(denial, "pid").unwrap_or(0);
    let denial_trace = value_str(denial, "trace_id");
    let denial_path = value_str(denial, "path");
    if denial_path.is_none() {
        return (
            Vec::new(),
            vec!["pathless denial cannot establish exact delegated path matching".into()],
        );
    }
    let mut reachable: BTreeMap<u64, Vec<BinderHop>> = BTreeMap::new();
    reachable.insert(denial_pid, Vec::new());
    let mut paths = Vec::new();
    let mut warnings = BTreeSet::new();

    for record in records {
        if value_u64(record, "event_id").is_some_and(|id| id <= denial_id) {
            continue;
        }
        match value_str(record, "type") {
            Some("binder_call") => {
                let caller = value_u64(record, "caller_pid").unwrap_or(0);
                let Some(prefix) = reachable.get(&caller).cloned() else {
                    continue;
                };
                if value_str(record, "trace_id") != denial_trace {
                    warnings.insert("ignored Binder evidence from a different trace".into());
                    continue;
                }
                if value_str(record, "causal_relation") != Some("exact") {
                    warnings.insert("ignored inferred Binder edge".into());
                    continue;
                }
                if value_str(record, "status") != Some("completed") {
                    warnings.insert("ignored incomplete Binder edge".into());
                    continue;
                }
                let Some(service) = value_str(record, "service") else {
                    warnings.insert("ignored Binder edge without exact service attribution".into());
                    continue;
                };
                if value_str(record, "attribution_confidence") != Some("exact") {
                    warnings.insert("ignored candidate service attribution".into());
                    continue;
                }
                if let Some(previous) = prefix.last() {
                    if value_str(record, "parent_span_id") != previous.span_id.as_deref() {
                        warnings
                            .insert("ignored Binder edge outside the exact causal chain".into());
                        continue;
                    }
                }
                let callee = value_u64(record, "callee_pid").unwrap_or(0);
                if callee == 0 {
                    continue;
                }
                let mut chain = prefix;
                chain.push(BinderHop {
                    caller_pid: caller,
                    callee_pid: callee,
                    service: service.to_string(),
                    span_id: value_str(record, "span_id").map(str::to_string),
                });
                reachable.entry(callee).or_insert(chain);
            }
            Some("syscall") | Some("selinux_denial") => {
                let pid = value_u64(record, "pid").unwrap_or(0);
                let Some(chain) = reachable.get(&pid) else {
                    continue;
                };
                let Some(last) = chain.last() else {
                    continue;
                };
                if value_str(record, "trace_id") != denial_trace {
                    warnings.insert("ignored service evidence from a different trace".into());
                    continue;
                }
                if value_str(record, "path").or_else(|| value_str(record, "fd_path")) != denial_path
                {
                    warnings.insert("ignored service access to a different path".into());
                    continue;
                }
                if value_str(record, "causal_relation") != Some("exact") {
                    warnings.insert("ignored inferred service access".into());
                    continue;
                }
                if value_str(record, "parent_span_id") != last.span_id.as_deref() {
                    warnings.insert("ignored service access outside the exact Binder span".into());
                    continue;
                }
                if value_str(record, "type") == Some("selinux_denial") {
                    warnings.insert(
                        "observed service-side denial; it is not delegated reachability".into(),
                    );
                    continue;
                }
                if value_str(record, "phase") != Some("exit")
                    || !value_i64(record, "ret").is_some_and(|ret| ret >= 0)
                {
                    warnings.insert("ignored failed syscall from the delegated service".into());
                    continue;
                }
                if paths.len() >= MAX_DELEGATED_PATHS {
                    warnings.insert(format!(
                        "delegated path output truncated at {MAX_DELEGATED_PATHS} exemplars"
                    ));
                    continue;
                }
                paths.push(DelegatedPath {
                    service: last.service.clone(),
                    callee_pid: last.callee_pid,
                    binder_edges: chain.clone(),
                    syscall: json!({
                        "event_id": value_u64(record, "event_id"),
                        "pid": pid,
                        "tid": value_u64(record, "tid"),
                        "name": value_str(record, "name"),
                        "path": denial_path,
                        "ret": value_i64(record, "ret"),
                        "span_id": value_str(record, "span_id"),
                    }),
                });
            }
            _ => {}
        }
    }
    (paths, warnings.into_iter().collect())
}

fn value_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key)?.as_str()
}

fn value_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key)?.as_u64()
}

fn value_i64(value: &Value, key: &str) -> Option<i64> {
    value.get(key)?.as_i64()
}

pub fn render_explanation_text(explanation: &SelinuxExplanation) -> String {
    let denial = &explanation.denial;
    let comm = value_str(denial, "comm").unwrap_or("unknown");
    let pid = value_u64(denial, "pid").unwrap_or(0);
    let tid = value_u64(denial, "tid").unwrap_or(pid);
    let path = value_str(denial, "path").unwrap_or("<pathless target>");
    let permissions = explanation.policy.permissions.join(" ");
    let mut out = format!(
        "SELinux event {}\nAttempt: {comm} (pid {pid}, tid {tid}) tried {{ {permissions} }} on {path}.\n",
        value_u64(denial, "event_id").unwrap_or(0)
    );
    if explanation.policy.permissive {
        out.push_str("Decision: the AVC was logged, but the operation was allowed because the source domain was permissive.\n");
    } else {
        out.push_str("Decision: enforcing SELinux; the requested operation was denied.\n");
    }
    out.push_str(&format!(
        "Policy tuple: {} {}:{} {{ {} }}\n",
        explanation.policy.source_type,
        explanation.policy.target_type,
        explanation.policy.tclass,
        permissions
    ));
    if explanation.delegated_paths.is_empty() {
        out.push_str("Observed delegated paths: none.\n");
    } else {
        out.push_str("Observed delegated paths:\n");
        for delegated in &explanation.delegated_paths {
            out.push_str(&format!(
                "  - {} (callee pid {}) -> successful {} on {} (ret={})\n",
                delegated.service,
                delegated.callee_pid,
                value_str(&delegated.syscall, "name").unwrap_or("syscall"),
                value_str(&delegated.syscall, "path").unwrap_or(path),
                value_i64(&delegated.syscall, "ret").unwrap_or(0),
            ));
        }
    }
    if !explanation.warnings.is_empty() {
        out.push_str("Warnings:\n");
        for warning in &explanation.warnings {
            out.push_str(&format!("  - {warning}\n"));
        }
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::selinux_logcat_args;

    #[test]
    fn logcat_starts_at_the_capture_boundary() {
        assert!(selinux_logcat_args()
            .windows(2)
            .any(|args| args == ["-T", "0"]));
    }
}
