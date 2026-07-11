//! Causal IDs, live scenario state, and the local marker control socket.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::SyscallEvent;
use neutron_common::{
    decode_causal_depth, decode_causal_relation, encode_causal_relation_depth, ProcessTraceContext,
    CAUSAL_RELATION_EXACT, CAUSAL_RELATION_INFERRED, PROCESS_TRACE_CONTEXT_SIZE,
};

pub const DEFAULT_CONTROL_SOCKET: &str = "/data/local/tmp/neutron.control.sock";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CausalRelation {
    #[default]
    Exact,
    Inferred,
}

impl CausalRelation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Inferred => "inferred",
        }
    }

    const fn wire(self) -> u8 {
        match self {
            Self::Exact => CAUSAL_RELATION_EXACT,
            Self::Inferred => CAUSAL_RELATION_INFERRED,
        }
    }

    fn from_wire(value: u8) -> Self {
        if value == CAUSAL_RELATION_INFERRED {
            Self::Inferred
        } else {
            Self::Exact
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CausalWire {
    pub parent_debug_id: u32,
    pub relation: CausalRelation,
    pub depth: u8,
}

impl CausalWire {
    pub const fn new(parent_debug_id: u32, relation: CausalRelation, depth: u8) -> Self {
        Self {
            parent_debug_id,
            relation,
            depth,
        }
    }

    pub fn from_event(ev: &SyscallEvent) -> Self {
        let reserved = { ev._reserved };
        Self {
            parent_debug_id: u32::from_le_bytes([
                reserved[1],
                reserved[2],
                reserved[3],
                reserved[4],
            ]),
            relation: CausalRelation::from_wire(decode_causal_relation(reserved[5])),
            depth: decode_causal_depth(reserved[5]),
        }
    }

    pub fn write_to(self, ev: &mut SyscallEvent) {
        let mut reserved = { ev._reserved };
        reserved[1..5].copy_from_slice(&self.parent_debug_id.to_le_bytes());
        reserved[5] = encode_causal_relation_depth(self.relation.wire(), self.depth);
        ev._reserved = reserved;
    }
}

pub fn process_context_bytes(context: &ProcessTraceContext) -> [u8; PROCESS_TRACE_CONTEXT_SIZE] {
    let mut bytes = [0; PROCESS_TRACE_CONTEXT_SIZE];
    // SAFETY: ProcessTraceContext is packed, Copy, contains no padding, and the
    // destination has exactly the asserted wire size.
    unsafe {
        std::ptr::copy_nonoverlapping(
            context as *const ProcessTraceContext as *const u8,
            bytes.as_mut_ptr(),
            bytes.len(),
        );
    }
    bytes
}

pub fn process_context_from_bytes(bytes: [u8; PROCESS_TRACE_CONTEXT_SIZE]) -> ProcessTraceContext {
    let mut context = std::mem::MaybeUninit::<ProcessTraceContext>::uninit();
    // SAFETY: the byte array has the exact packed struct size. Map contents are
    // written only by neutron userspace/BPF with valid TraceReason values.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), context.as_mut_ptr() as *mut u8, bytes.len());
        context.assume_init()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScenarioInfo {
    pub scenario_id: String,
    pub trace_id: u64,
    pub generation: u16,
}

#[derive(Debug, Default)]
pub struct ScenarioState {
    active: Option<ScenarioInfo>,
    by_generation: BTreeMap<u16, ScenarioInfo>,
    used_names: BTreeSet<String>,
    next_generation: u16,
}

impl ScenarioState {
    pub fn active(&self) -> Option<&ScenarioInfo> {
        self.active.as_ref()
    }

    pub fn find(&self, generation: u16) -> Option<&ScenarioInfo> {
        self.by_generation.get(&generation)
    }

    pub fn start(&mut self, name: &str) -> Result<ScenarioInfo> {
        self.start_with_trace_id(name, random_nonzero_u64()?)
    }

    pub fn start_with_trace_id(&mut self, name: &str, trace_id: u64) -> Result<ScenarioInfo> {
        validate_marker_name(name)?;
        if self.active.is_some() {
            bail!("cannot start scenario '{name}': another scenario is active");
        }
        if self.used_names.contains(name) {
            bail!("scenario '{name}' was already used in this capture");
        }
        if trace_id == 0 {
            bail!("trace_id must be non-zero");
        }
        if self.next_generation == u16::MAX {
            bail!("scenario generation space exhausted for this capture");
        }
        self.next_generation += 1;
        let info = ScenarioInfo {
            scenario_id: name.to_string(),
            trace_id,
            generation: self.next_generation,
        };
        self.used_names.insert(name.to_string());
        self.by_generation.insert(info.generation, info.clone());
        self.active = Some(info.clone());
        Ok(info)
    }

    pub fn end(&mut self, name: &str) -> Result<ScenarioInfo> {
        validate_marker_name(name)?;
        let active = self
            .active
            .as_ref()
            .context("cannot end scenario: no scenario is active")?;
        if active.scenario_id != name {
            bail!(
                "cannot end scenario '{name}': active scenario is '{}'",
                active.scenario_id
            );
        }
        Ok(self.active.take().expect("active checked above"))
    }
}

#[derive(Clone, Debug)]
pub struct CausalMetadata {
    pub scenario_id: String,
    pub trace_id: u64,
    pub span_id: u64,
    pub parent_span_id: u64,
    pub depth: u8,
    pub relation: CausalRelation,
    pub root_package: Option<String>,
    pub root_uid: Option<u32>,
}

pub fn enrich_json(line: &str, metadata: &CausalMetadata) -> Result<String> {
    let mut value: Value =
        serde_json::from_str(line).context("parsing event JSON for causality")?;
    let object = value
        .as_object_mut()
        .context("causal event JSON must be an object")?;
    object.insert(
        "scenario_id".into(),
        Value::String(metadata.scenario_id.clone()),
    );
    object.insert(
        "trace_id".into(),
        Value::String(format_id(metadata.trace_id)),
    );
    object.insert("span_id".into(), Value::String(format_id(metadata.span_id)));
    object.insert(
        "parent_span_id".into(),
        Value::String(format_id(metadata.parent_span_id)),
    );
    object.insert("depth".into(), Value::from(metadata.depth));
    object.insert(
        "causal_relation".into(),
        Value::String(metadata.relation.as_str().into()),
    );
    if let Some(package) = &metadata.root_package {
        object.insert("root_package".into(), Value::String(package.clone()));
    }
    if let Some(uid) = metadata.root_uid {
        object.insert("root_uid".into(), Value::from(uid));
    }
    serde_json::to_string(&value).context("serializing causal event JSON")
}

pub fn format_id(id: u64) -> String {
    format!("{id:016x}")
}

pub fn root_process_span_id(trace_id: u64, pid: u32) -> u64 {
    stable_id(trace_id, b"process", &[pid as u64])
}

pub fn binder_span_id(trace_id: u64, debug_id: i32) -> u64 {
    stable_id(trace_id, b"binder", &[debug_id as u32 as u64])
}

pub fn syscall_span_id(trace_id: u64, pid: u32, tid: u32, enter_timestamp_ns: u64, nr: i32) -> u64 {
    stable_id(
        trace_id,
        b"syscall",
        &[pid as u64, tid as u64, enter_timestamp_ns, nr as u32 as u64],
    )
}

pub fn process_exit_span_id(trace_id: u64, pid: u32, timestamp_ns: u64) -> u64 {
    stable_id(trace_id, b"exit", &[pid as u64, timestamp_ns])
}

pub fn selinux_denial_span_id(trace_id: u64, pid: u32, tid: u32, timestamp_ns: u64) -> u64 {
    stable_id(
        trace_id,
        b"selinux_denial",
        &[pid as u64, tid as u64, timestamp_ns],
    )
}

fn stable_id(trace_id: u64, tag: &[u8], values: &[u64]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in trace_id
        .to_le_bytes()
        .into_iter()
        .chain(tag.iter().copied())
        .chain(values.iter().flat_map(|value| value.to_le_bytes()))
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    if hash == 0 {
        1
    } else {
        hash
    }
}

fn random_nonzero_u64() -> Result<u64> {
    let mut file = fs::File::open("/dev/urandom").context("opening /dev/urandom")?;
    loop {
        let mut bytes = [0; 8];
        file.read_exact(&mut bytes)
            .context("reading /dev/urandom")?;
        let value = u64::from_ne_bytes(bytes);
        if value != 0 {
            return Ok(value);
        }
    }
}

pub fn monotonic_timestamp_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime initializes the provided timespec.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } == 0 {
        (ts.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec as u64)
    } else {
        0
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MarkRequest {
    pub name: String,
    pub phase: String,
    #[serde(default)]
    pub meta: BTreeMap<String, String>,
}

impl MarkRequest {
    pub fn validate(&self) -> Result<()> {
        validate_marker_name(&self.name)?;
        if !matches!(self.phase.as_str(), "start" | "end") {
            bail!("invalid marker phase '{}' (expected start|end)", self.phase);
        }
        if self.meta.len() > 32 {
            bail!("marker metadata is limited to 32 entries");
        }
        for (key, value) in &self.meta {
            if key.trim().is_empty() || key.len() > 128 || value.len() > 1024 {
                bail!("invalid marker metadata entry");
            }
        }
        Ok(())
    }
}

fn validate_marker_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        bail!("marker name must be non-empty");
    }
    if name.len() > 128 || name.chars().any(char::is_control) {
        bail!("marker name must be at most 128 printable characters");
    }
    Ok(())
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MarkResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

pub struct PendingMark {
    pub request: MarkRequest,
    stream: UnixStream,
}

impl PendingMark {
    pub fn respond_ok(mut self, ts_ns: u64, generation: u16, trace_id: u64) -> Result<()> {
        write_response(
            &mut self.stream,
            &MarkResponse {
                ok: true,
                error: None,
                ts_ns: Some(ts_ns),
                generation: Some(generation),
                trace_id: Some(format_id(trace_id)),
            },
        )
    }

    pub fn respond_error(mut self, error: impl Into<String>) -> Result<()> {
        write_response(
            &mut self.stream,
            &MarkResponse {
                ok: false,
                error: Some(error.into()),
                ..MarkResponse::default()
            },
        )
    }
}

pub struct ControlServer {
    listener: UnixListener,
    path: PathBuf,
}

impl ControlServer {
    pub fn bind(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("creating control socket directory {}", parent.display())
            })?;
        }
        if path.exists() {
            fs::remove_file(path)
                .with_context(|| format!("removing stale control socket {}", path.display()))?;
        }
        let listener = UnixListener::bind(path)
            .with_context(|| format!("binding control socket {}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", path.display()))?;
        listener
            .set_nonblocking(true)
            .context("setting control socket nonblocking")?;
        Ok(Self {
            listener,
            path: path.to_path_buf(),
        })
    }

    pub fn try_recv(&self) -> Result<Option<PendingMark>> {
        let (mut stream, _) = match self.listener.accept() {
            Ok(pair) => pair,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error).context("accepting marker control request"),
        };
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .context("setting marker request timeout")?;
        let mut raw = Vec::new();
        if let Err(error) = (&mut stream).take(4097).read_to_end(&mut raw) {
            let _ = write_response(
                &mut stream,
                &MarkResponse {
                    ok: false,
                    error: Some(format!("incomplete marker request: {error}")),
                    ..MarkResponse::default()
                },
            );
            return Ok(None);
        }
        if raw.len() > 4096 {
            let _ = write_response(
                &mut stream,
                &MarkResponse {
                    ok: false,
                    error: Some("marker request exceeds 4096 bytes".into()),
                    ..MarkResponse::default()
                },
            );
            return Ok(None);
        }
        let request: MarkRequest = match serde_json::from_slice(&raw) {
            Ok(request) => request,
            Err(error) => {
                let _ = write_response(
                    &mut stream,
                    &MarkResponse {
                        ok: false,
                        error: Some(format!("invalid marker request: {error}")),
                        ..MarkResponse::default()
                    },
                );
                return Ok(None);
            }
        };
        if let Err(error) = request.validate() {
            let _ = write_response(
                &mut stream,
                &MarkResponse {
                    ok: false,
                    error: Some(error.to_string()),
                    ..MarkResponse::default()
                },
            );
            return Ok(None);
        }
        Ok(Some(PendingMark { request, stream }))
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn send_mark_request(path: impl AsRef<Path>, request: &MarkRequest) -> Result<MarkResponse> {
    request.validate()?;
    let path = path.as_ref();
    let mut stream = UnixStream::connect(path)
        .with_context(|| format!("connecting to control socket {}", path.display()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .context("setting marker response timeout")?;
    serde_json::to_writer(&mut stream, request).context("writing marker request")?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .context("finishing marker request")?;
    let response: MarkResponse =
        serde_json::from_reader(&mut stream).context("reading marker response")?;
    if !response.ok {
        bail!(
            "marker rejected: {}",
            response.error.as_deref().unwrap_or("unknown error")
        );
    }
    Ok(response)
}

fn write_response(stream: &mut UnixStream, response: &MarkResponse) -> Result<()> {
    serde_json::to_writer(&mut *stream, response).context("writing marker response")?;
    stream.flush().context("flushing marker response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutron_common::TraceReason;

    #[test]
    fn process_context_has_no_hidden_padding() {
        let context = ProcessTraceContext {
            root_trace_id: 1,
            parent_pid: 2,
            binder_debug_id: 3,
            depth: 4,
            reason: TraceReason::Binder,
            scenario_generation: 5,
        };
        let bytes = process_context_bytes(&context);
        assert_eq!(bytes.len(), 20);
        assert_eq!(&bytes[..8], &1u64.to_ne_bytes());
        assert_eq!(&bytes[8..12], &2u32.to_ne_bytes());
        assert_eq!(&bytes[12..16], &3u32.to_ne_bytes());
        assert_eq!(bytes[16], 4);
        assert_eq!(bytes[17], TraceReason::Binder as u8);
        assert_eq!(&bytes[18..20], &5u16.to_ne_bytes());
    }

    #[test]
    fn causal_json_includes_uid_root_metadata() {
        let metadata = CausalMetadata {
            scenario_id: "camera".into(),
            trace_id: 1,
            span_id: 2,
            parent_span_id: 3,
            depth: 0,
            relation: CausalRelation::Exact,
            root_package: None,
            root_uid: Some(10123),
        };
        let line = enrich_json(r#"{"type":"syscall"}"#, &metadata).unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["root_uid"], 10123);
        assert!(value.get("root_package").is_none());
    }
}
