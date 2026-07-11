//! Capture-to-regression artifact handling.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::ioctl_schema::{Field, PointerDirection, SchemaRegistry};
use neutron_common::SyscallEvent;

pub const HARNESS_SCHEMA: &str = "neutron.harness/v1";
pub const HARNESS_REF_SCHEMA: &str = "neutron.harness-ref/v1";
const MAX_CAPTURE_LINE: usize = 4 * 1024 * 1024;
const MAX_RESOURCE_BYTES: u64 = 1024 * 1024;
const MAX_EVENT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PARCEL_BYTES: u64 = 64 * 1024;
const MAX_REPLAY_BINARY_BYTES: u64 = 64 * 1024 * 1024;
const WARNING: &str =
    "AUTHORIZED USE ONLY: replay may crash or reboot the selected physical device.";

#[derive(Args, Debug, Clone)]
pub struct ExtractArgs {
    pub capture: PathBuf,
    #[arg(long)]
    pub event_id: u64,
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub struct ReplayArgs {
    pub directory: PathBuf,
    #[arg(long)]
    pub serial: String,
    #[arg(long)]
    pub package: String,
    #[arg(long)]
    pub runner: PathBuf,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub max_runs: u32,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub timeout: u64,
    #[arg(long)]
    pub authorized_use: bool,
}

#[derive(Args, Debug, Clone)]
pub struct MinimizeArgs {
    pub directory: PathBuf,
    #[arg(long)]
    pub serial: String,
    #[arg(long)]
    pub package: String,
    #[arg(long)]
    pub runner: PathBuf,
    #[arg(long, value_name = "EXEC")]
    pub oracle_command: PathBuf,
    #[arg(long, value_name = "ARG", allow_hyphen_values = true)]
    pub oracle_arg: Vec<String>,
    #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub max_runs: u32,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub timeout: u64,
    #[arg(long)]
    pub authorized_use: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceStatus {
    Complete,
    Blocked,
    Truncated,
    Error,
    Unresolved,
}

impl ResourceStatus {
    fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureIdentity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    pub uid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutableRegion {
    pub offset: u64,
    pub length: u64,
    #[serde(default)]
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessResource {
    pub id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub length: u64,
    pub status: ResourceStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer_offset: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointee_layout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessRef {
    pub schema: String,
    pub kind: String,
    pub status: ResourceStatus,
    pub sha256: String,
    pub length: u64,
    #[serde(default)]
    pub resources: Vec<HarnessResource>,
    pub identity: CaptureIdentity,
    #[serde(default)]
    pub mutable_regions: Vec<MutableRegion>,
    #[serde(default)]
    pub transactions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredIdentity {
    pub serial: String,
    pub fingerprint: String,
    pub boot_id: String,
    pub package: String,
    pub uid: u32,
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub event_id: u64,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    #[serde(default)]
    pub delay_ms: u64,
    pub selected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub schema: String,
    pub revision: u32,
    pub source_capture: String,
    pub selected_event_id: u64,
    pub input_sha256: String,
    pub required_identity: RequiredIdentity,
    pub steps: Vec<Step>,
    pub replay_status: String,
    pub blocked_reasons: Vec<String>,
    pub warning: String,
    #[serde(default)]
    pub mutable_regions: Vec<MutableRegion>,
    #[serde(default)]
    pub transactions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceCatalog {
    pub schema: String,
    pub device_paths: Vec<String>,
    pub binder_services: Vec<String>,
    pub resources: Vec<HarnessResource>,
    #[serde(default)]
    pub object_adapters: Vec<Value>,
    pub unresolved: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerContract {
    pub schema: String,
    #[serde(default)]
    pub transport: RunnerTransport,
    #[serde(default)]
    pub capabilities: Vec<RunnerCapability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepare: Option<Vec<String>>,
    pub execute: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recover: Option<Vec<String>>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunnerTransport {
    #[default]
    Host,
    Adb,
}

#[derive(Debug, Clone, Copy, Hash, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunnerCapability {
    CausalSteps,
    BinderTransactions,
    TimingDelays,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Completed,
    Crash,
    Reboot,
    TransportLoss,
    Timeout,
    HookFailure,
    IdentityDrift,
    RecoveryFailed,
    OracleError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunResult {
    pub schema: String,
    pub run: u32,
    pub status: RunStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub recovered: bool,
    pub warning: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdbDevice {
    serial: String,
    state: String,
    usb: bool,
}

#[derive(Debug)]
struct CommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timed_out: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct AdbStageAsset {
    local_path: PathBuf,
    remote_path: String,
}

#[derive(Debug, PartialEq, Eq)]
struct DdminResult<T> {
    value: Vec<T>,
    runs: u32,
}

fn default_timeout() -> u64 {
    30
}

#[derive(Debug)]
struct CaptureEvent {
    event_id: u64,
    value: Value,
    harness_ref: Option<HarnessRef>,
}

pub trait MemoryReader: Send + Sync {
    fn read_exact(&self, pid: u32, address: u64, length: usize) -> Result<Vec<u8>>;
}

struct ProcessMemory;

impl MemoryReader for ProcessMemory {
    fn read_exact(&self, pid: u32, address: u64, length: usize) -> Result<Vec<u8>> {
        if length > MAX_RESOURCE_BYTES as usize {
            bail!("remote memory read exceeds 1 MiB resource limit");
        }
        if length == 0 {
            return Ok(Vec::new());
        }
        if address == 0 {
            bail!("remote memory pointer is null");
        }
        let mut bytes = vec![0u8; length];
        let local = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: length,
        };
        let remote = libc::iovec {
            iov_base: address as *mut libc::c_void,
            iov_len: length,
        };
        // SAFETY: both iovecs describe valid buffers for this call. The remote
        // address is untrusted, but process_vm_readv reports EFAULT/short reads.
        let read = unsafe { libc::process_vm_readv(pid as i32, &local, 1, &remote, 1, 0) };
        if read < 0 {
            return Err(std::io::Error::last_os_error()).context("process_vm_readv");
        }
        if read as usize != length {
            bail!("process_vm_readv short read: expected {length}, got {read}");
        }
        Ok(bytes)
    }
}

pub struct CaptureWriter {
    registry: SchemaRegistry,
    blob_dir: PathBuf,
    identity: CaptureIdentity,
    memory: Box<dyn MemoryReader>,
}

impl CaptureWriter {
    pub fn new(
        capture_path: &Path,
        registry: SchemaRegistry,
        identity: CaptureIdentity,
    ) -> Result<Self> {
        Self::with_memory(capture_path, registry, identity, Box::new(ProcessMemory))
    }

    #[cfg(test)]
    fn new_for_test(
        capture_path: &Path,
        registry: SchemaRegistry,
        identity: CaptureIdentity,
        memory: impl MemoryReader + 'static,
    ) -> Result<Self> {
        Self::with_memory(capture_path, registry, identity, Box::new(memory))
    }

    fn with_memory(
        capture_path: &Path,
        registry: SchemaRegistry,
        identity: CaptureIdentity,
        memory: Box<dyn MemoryReader>,
    ) -> Result<Self> {
        let blob_dir = PathBuf::from(format!("{}.blobs", capture_path.display()));
        fs::create_dir(&blob_dir).with_context(|| {
            format!(
                "creating harness blob directory {} (it must not already exist)",
                blob_dir.display()
            )
        })?;
        secure_directory(&blob_dir)?;
        Ok(Self {
            registry,
            blob_dir,
            identity,
            memory,
        })
    }

    pub fn enrich_json(
        &self,
        event: &SyscallEvent,
        fd_path: Option<&str>,
        line: &str,
    ) -> Result<String> {
        let nr = { event.syscall_nr };
        if nr != 29 {
            return Ok(line.to_string());
        }
        let cmd = { event.args[1] } as u32;
        let reference = if cmd == 0xc030_6201 {
            self.capture_binder(event)?
        } else {
            self.capture_ioctl(event, fd_path)?
        };
        let mut value: Value =
            serde_json::from_str(line).context("parsing event for harness_ref")?;
        value
            .as_object_mut()
            .context("event JSON is not an object")?
            .insert("harness_ref".into(), serde_json::to_value(reference)?);
        serde_json::to_string(&value).context("serializing harness event")
    }

    fn capture_ioctl(&self, event: &SyscallEvent, fd_path: Option<&str>) -> Result<HarnessRef> {
        let pid = { event.pid };
        let uid = { event.uid };
        let args = { event.args };
        let cmd = args[1] as u32;
        let address = args[2];
        let size = ((cmd >> 16) & 0x3fff) as usize;
        let descriptor = self.registry.descriptor(cmd, fd_path, None);
        let flat = self.memory.read_exact(pid, address, size);
        let (flat, mut status, mut error) = match flat {
            Ok(bytes) => (bytes, ResourceStatus::Complete, None),
            Err(read_error) => (
                Vec::new(),
                ResourceStatus::Error,
                Some(format!("flat ioctl read failed: {read_error:#}")),
            ),
        };
        let sha256 = self.store_blob(&flat)?;
        let mut resources = Vec::new();
        let mut mutable_regions = Vec::new();
        if let Some(descriptor) = descriptor {
            for field in &descriptor.fields {
                if field.kind != "pointer" && !field.opaque {
                    mutable_regions.push(MutableRegion {
                        offset: field.offset.into(),
                        length: field.size.into(),
                        kind: if field.name.contains("flag") {
                            "flags".into()
                        } else {
                            "field".into()
                        },
                    });
                }
            }
            for field in descriptor
                .fields
                .iter()
                .filter(|field| field.kind == "pointer")
            {
                let pointer = descriptor
                    .pointers
                    .iter()
                    .find(|pointer| pointer.field == field.name);
                let Some(pointer) = pointer else {
                    status = ResourceStatus::Blocked;
                    resources.push(HarnessResource {
                        id: format!("pointer.{}", field.name),
                        kind: "ioctl_pointer".into(),
                        sha256: None,
                        length: 0,
                        status: ResourceStatus::Unresolved,
                        error: Some("pointer field has no capture descriptor".into()),
                        address: field_value(&flat, field),
                        pointer_offset: Some(field.offset.into()),
                        pointee_layout: None,
                        direction: None,
                        service: None,
                        object_type: None,
                        parent: None,
                        container: None,
                        parent_offset: None,
                    });
                    continue;
                };
                let pointer_address = field_value(&flat, field).unwrap_or(0);
                let length = pointer_length(pointer, descriptor.fields.as_slice(), &flat);
                let (bytes, resource_status, resource_error) = match length {
                    Ok(length) if length <= MAX_RESOURCE_BYTES => {
                        match self
                            .memory
                            .read_exact(pid, pointer_address, length as usize)
                        {
                            Ok(bytes) => (bytes, ResourceStatus::Complete, None),
                            Err(read_error) => (
                                Vec::new(),
                                ResourceStatus::Error,
                                Some(format!("pointer read failed: {read_error:#}")),
                            ),
                        }
                    }
                    Ok(_) => (
                        Vec::new(),
                        ResourceStatus::Truncated,
                        Some("pointer resource exceeds 1 MiB limit".into()),
                    ),
                    Err(length_error) => (
                        Vec::new(),
                        ResourceStatus::Unresolved,
                        Some(format!("pointer length unresolved: {length_error:#}")),
                    ),
                };
                if !resource_status.is_complete() {
                    status = ResourceStatus::Blocked;
                }
                let digest = self.store_blob(&bytes)?;
                resources.push(HarnessResource {
                    id: format!("pointer.{}", field.name),
                    kind: "ioctl_pointer".into(),
                    sha256: Some(digest),
                    length: bytes.len() as u64,
                    status: resource_status,
                    error: resource_error,
                    address: Some(pointer_address),
                    pointer_offset: Some(field.offset.into()),
                    pointee_layout: Some(pointer.pointee_layout.clone()),
                    direction: Some(pointer_direction(pointer.direction).into()),
                    service: None,
                    object_type: None,
                    parent: None,
                    container: None,
                    parent_offset: None,
                });
            }
        } else {
            status = ResourceStatus::Blocked;
            error = Some("no ioctl schema descriptor; pointer safety is unknown".into());
            resources.push(HarnessResource {
                id: "ioctl.schema".into(),
                kind: "schema".into(),
                sha256: None,
                length: 0,
                status: ResourceStatus::Unresolved,
                error: error.clone(),
                address: None,
                pointer_offset: None,
                pointee_layout: None,
                direction: None,
                service: None,
                object_type: None,
                parent: None,
                container: None,
                parent_offset: None,
            });
        }
        let total = flat.len() as u64
            + resources
                .iter()
                .map(|resource| resource.length)
                .sum::<u64>();
        if total > MAX_EVENT_BYTES {
            status = ResourceStatus::Truncated;
            error = Some("event resources exceed 4 MiB limit".into());
        }
        Ok(HarnessRef {
            schema: HARNESS_REF_SCHEMA.into(),
            kind: "ioctl".into(),
            status,
            sha256,
            length: flat.len() as u64,
            resources,
            identity: self.event_identity(pid, uid),
            mutable_regions,
            transactions: Vec::new(),
            error,
        })
    }

    fn capture_binder(&self, event: &SyscallEvent) -> Result<HarnessRef> {
        let pid = { event.pid };
        let uid = { event.uid };
        let args = { event.args };
        let outer = self.memory.read_exact(pid, args[2], 48);
        let (outer, mut status, mut error) = match outer {
            Ok(bytes) => (bytes, ResourceStatus::Complete, None),
            Err(read_error) => (
                Vec::new(),
                ResourceStatus::Error,
                Some(format!("BINDER_WRITE_READ read failed: {read_error:#}")),
            ),
        };
        let sha256 = self.store_blob(&outer)?;
        let mut resources = Vec::new();
        let mut transactions = Vec::new();
        if outer.len() == 48 {
            let write_size = read_u64(&outer, 0).unwrap_or(0);
            let write_buffer = read_u64(&outer, 16).unwrap_or(0);
            if write_size > MAX_RESOURCE_BYTES {
                status = ResourceStatus::Truncated;
                error = Some("Binder command stream exceeds 1 MiB limit".into());
            } else if write_size != 0 {
                match self
                    .memory
                    .read_exact(pid, write_buffer, write_size as usize)
                {
                    Ok(stream) => {
                        let stream_digest = self.store_blob(&stream)?;
                        resources.push(HarnessResource {
                            id: "binder.write_stream".into(),
                            kind: "binder_stream".into(),
                            sha256: Some(stream_digest),
                            length: stream.len() as u64,
                            status: ResourceStatus::Complete,
                            error: None,
                            address: Some(write_buffer),
                            pointer_offset: Some(16),
                            pointee_layout: None,
                            direction: Some("in".into()),
                            service: None,
                            object_type: None,
                            parent: None,
                            container: None,
                            parent_offset: None,
                        });
                        if let Err(parse_error) = self.capture_binder_transactions(
                            pid,
                            &stream,
                            &mut resources,
                            &mut transactions,
                        ) {
                            status = ResourceStatus::Blocked;
                            error = Some(format!("Binder reconstruction blocked: {parse_error:#}"));
                        }
                    }
                    Err(read_error) => {
                        status = ResourceStatus::Blocked;
                        error = Some(format!("Binder stream read failed: {read_error:#}"));
                    }
                }
            }
        }
        if resources
            .iter()
            .any(|resource| !resource.status.is_complete())
        {
            status = ResourceStatus::Blocked;
        }
        let total = outer.len() as u64
            + resources
                .iter()
                .filter(|resource| resource.sha256.is_some())
                .map(|resource| resource.length)
                .sum::<u64>();
        if total > MAX_EVENT_BYTES {
            status = ResourceStatus::Truncated;
            error = Some("event resources exceed 4 MiB limit".into());
        }
        Ok(HarnessRef {
            schema: HARNESS_REF_SCHEMA.into(),
            kind: "binder".into(),
            status,
            sha256,
            length: outer.len() as u64,
            resources,
            identity: self.event_identity(pid, uid),
            mutable_regions: Vec::new(),
            transactions,
            error,
        })
    }

    fn capture_binder_transactions(
        &self,
        pid: u32,
        stream: &[u8],
        resources: &mut Vec<HarnessResource>,
        transactions: &mut Vec<String>,
    ) -> Result<()> {
        let mut cursor = 0usize;
        let mut transaction_index = 0usize;
        while cursor + 4 <= stream.len() {
            let command = read_u32(stream, cursor).context("short Binder command")?;
            cursor += 4;
            let command_type = (command >> 8) & 0xff;
            let command_nr = command & 0xff;
            let command_size = ((command >> 16) & 0x3fff) as usize;
            if command_type != b'c' as u32 || !matches!(command_nr, 0 | 1 | 17) {
                if cursor.saturating_add(command_size) > stream.len() {
                    bail!("truncated Binder command {command:#x}");
                }
                cursor += command_size;
                continue;
            }
            if command_size < 64 || cursor + command_size > stream.len() {
                bail!("truncated Binder transaction command");
            }
            let transaction_offset = cursor;
            let transaction = &stream[cursor..cursor + command_size];
            cursor += command_size;
            let data_size = read_u64(transaction, 32).context("Binder data_size missing")?;
            let offsets_size = read_u64(transaction, 40).context("Binder offsets_size missing")?;
            let data_address = read_u64(transaction, 48).context("Binder data pointer missing")?;
            let offsets_address =
                read_u64(transaction, 56).context("Binder offsets pointer missing")?;
            let id = format!("binder.transaction.{transaction_index}");
            transaction_index += 1;
            transactions.push(id.clone());
            if data_size > MAX_PARCEL_BYTES {
                resources.push(blocked_resource(
                    &format!("{id}.parcel"),
                    "binder_parcel",
                    data_size,
                    "Parcel exceeds 64 KiB limit",
                ));
                continue;
            }
            if offsets_size > MAX_PARCEL_BYTES || offsets_size % 8 != 0 {
                resources.push(blocked_resource(
                    &format!("{id}.offsets"),
                    "binder_offsets",
                    offsets_size,
                    "invalid or oversized Binder offsets",
                ));
                continue;
            }
            let parcel = self
                .memory
                .read_exact(pid, data_address, data_size as usize)?;
            let offsets = self
                .memory
                .read_exact(pid, offsets_address, offsets_size as usize)?;
            let parcel_digest = self.store_blob(&parcel)?;
            let offsets_digest = self.store_blob(&offsets)?;
            resources.push(HarnessResource {
                id: format!("{id}.parcel"),
                kind: "binder_parcel".into(),
                sha256: Some(parcel_digest),
                length: parcel.len() as u64,
                status: ResourceStatus::Complete,
                error: None,
                address: Some(data_address),
                pointer_offset: Some((transaction_offset + 48) as u64),
                pointee_layout: None,
                direction: Some("in".into()),
                service: None,
                object_type: None,
                parent: None,
                container: Some("binder.write_stream".into()),
                parent_offset: None,
            });
            resources.push(HarnessResource {
                id: format!("{id}.offsets"),
                kind: "binder_offsets".into(),
                sha256: Some(offsets_digest),
                length: offsets.len() as u64,
                status: ResourceStatus::Complete,
                error: None,
                address: Some(offsets_address),
                pointer_offset: Some((transaction_offset + 56) as u64),
                pointee_layout: None,
                direction: Some("in".into()),
                service: None,
                object_type: None,
                parent: None,
                container: Some("binder.write_stream".into()),
                parent_offset: None,
            });
            self.capture_binder_objects(pid, &id, &parcel, &offsets, resources)?;
        }
        Ok(())
    }

    fn capture_binder_objects(
        &self,
        pid: u32,
        transaction: &str,
        parcel: &[u8],
        offsets: &[u8],
        resources: &mut Vec<HarnessResource>,
    ) -> Result<()> {
        let parcel_id = format!("{transaction}.parcel");
        let mut buffers = HashMap::<usize, (String, Vec<u8>)>::new();
        for (index, offset_bytes) in offsets.chunks_exact(8).enumerate() {
            let offset = u64::from_le_bytes(offset_bytes.try_into().expect("8-byte chunk"));
            let offset = usize::try_from(offset).context("Binder object offset overflow")?;
            let object_type =
                read_u32(parcel, offset).context("Binder object offset out of Parcel")?;
            let name = binder_object_name(object_type);
            let id = format!("{transaction}.object.{index}");
            match name {
                Some("buffer") => {
                    let address = read_u64(parcel, offset + 8).context("buffer pointer missing")?;
                    let length = read_u64(parcel, offset + 16).context("buffer length missing")?;
                    let parent = read_u64(parcel, offset + 24).context("buffer parent missing")?;
                    let parent_offset =
                        read_u64(parcel, offset + 32).context("buffer parent offset missing")?;
                    if length > MAX_RESOURCE_BYTES {
                        resources.push(blocked_resource(
                            &id,
                            "binder_buffer",
                            length,
                            "Binder buffer exceeds 1 MiB limit",
                        ));
                        continue;
                    }
                    let bytes = self.memory.read_exact(pid, address, length as usize)?;
                    let digest = self.store_blob(&bytes)?;
                    resources.push(HarnessResource {
                        id: id.clone(),
                        kind: "binder_buffer".into(),
                        sha256: Some(digest),
                        length,
                        status: ResourceStatus::Complete,
                        error: None,
                        address: Some(address),
                        pointer_offset: Some(offset as u64 + 8),
                        pointee_layout: None,
                        direction: Some("in_out".into()),
                        service: None,
                        object_type: Some("buffer".into()),
                        parent: Some(parent.to_string()),
                        container: Some(parcel_id.clone()),
                        parent_offset: Some(parent_offset),
                    });
                    buffers.insert(index, (id, bytes));
                }
                Some("fd") => {
                    let fd = read_u32(parcel, offset + 8).context("Binder fd missing")? as i32;
                    let path = fs::read_link(format!("/proc/{pid}/fd/{fd}"))
                        .ok()
                        .map(|path| path.display().to_string());
                    resources.push(HarnessResource {
                        id,
                        kind: "fd_recipe".into(),
                        sha256: None,
                        length: 0,
                        status: if path.is_some() {
                            ResourceStatus::Complete
                        } else {
                            ResourceStatus::Unresolved
                        },
                        error: path.is_none().then(|| "FD provenance unavailable".into()),
                        address: None,
                        pointer_offset: Some(offset as u64 + 8),
                        pointee_layout: None,
                        direction: None,
                        service: path,
                        object_type: Some("fd".into()),
                        parent: None,
                        container: Some(parcel_id.clone()),
                        parent_offset: None,
                    });
                }
                Some("fd_array") => {
                    let count = read_u64(parcel, offset + 8).context("FD-array count missing")?;
                    let parent =
                        read_u64(parcel, offset + 16).context("FD-array parent missing")?;
                    let parent_offset =
                        read_u64(parcel, offset + 24).context("FD-array offset missing")?;
                    if count > 256 {
                        resources.push(blocked_resource(
                            &id,
                            "fd_array_recipe",
                            count * 4,
                            "FD-array exceeds 256 descriptors",
                        ));
                        continue;
                    }
                    let Some((container, bytes)) = buffers.get(&(parent as usize)) else {
                        resources.push(blocked_resource(
                            &id,
                            "fd_array_recipe",
                            count * 4,
                            "FD-array parent buffer was not captured",
                        ));
                        continue;
                    };
                    for fd_index in 0..count {
                        let fd_offset = parent_offset
                            .checked_add(fd_index * 4)
                            .context("FD-array offset overflow")?;
                        let fd_offset = usize::try_from(fd_offset)?;
                        let fd = read_u32(bytes, fd_offset)
                            .context("FD-array entry is out of bounds")?
                            as i32;
                        let path = fs::read_link(format!("/proc/{pid}/fd/{fd}"))
                            .ok()
                            .map(|path| path.display().to_string());
                        resources.push(HarnessResource {
                            id: format!("{id}.fd.{fd_index}"),
                            kind: "fd_recipe".into(),
                            sha256: None,
                            length: 0,
                            status: if path.is_some() {
                                ResourceStatus::Complete
                            } else {
                                ResourceStatus::Unresolved
                            },
                            error: path.is_none().then(|| "FD provenance unavailable".into()),
                            address: None,
                            pointer_offset: Some(fd_offset as u64),
                            pointee_layout: None,
                            direction: None,
                            service: path,
                            object_type: Some("fd_array".into()),
                            parent: Some(parent.to_string()),
                            container: Some(container.clone()),
                            parent_offset: Some(parent_offset),
                        });
                    }
                }
                Some("handle") | Some("weak_handle") => resources.push(blocked_resource(
                    &id,
                    "binder_service",
                    0,
                    "recorded Binder handles are forbidden; configure service reacquisition",
                )),
                Some("binder") | Some("weak_binder") => resources.push(blocked_resource(
                    &id,
                    "binder_callback",
                    0,
                    "local/weak Binder object requires an explicit resource adapter",
                )),
                None => resources.push(blocked_resource(
                    &id,
                    "binder_object",
                    0,
                    &format!("unknown Binder object type {object_type:#x}"),
                )),
                _ => {}
            }
        }
        Ok(())
    }

    fn store_blob(&self, bytes: &[u8]) -> Result<String> {
        let digest = format!("{:x}", Sha256::digest(bytes));
        let path = self.blob_dir.join(&digest);
        if path.exists() {
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                bail!("content-addressed blob path is not a regular file");
            }
            let existing = fs::read(&path)?;
            if existing != bytes {
                bail!("content-addressed blob collision for {digest}");
            }
        } else {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            let mut file = options.open(&path)?;
            use std::io::Write as _;
            file.write_all(bytes)?;
            file.sync_data()?;
        }
        Ok(digest)
    }

    fn event_identity(&self, pid: u32, uid: u32) -> CaptureIdentity {
        let mut identity = self.identity.clone();
        identity.uid = uid;
        identity.domain = fs::read_to_string(format!("/proc/{pid}/attr/current"))
            .ok()
            .map(|value| value.trim_end_matches(['\n', '\0']).to_string())
            .filter(|value| !value.is_empty())
            .or(identity.domain);
        identity
    }
}

fn pointer_direction(direction: PointerDirection) -> &'static str {
    match direction {
        PointerDirection::In => "in",
        PointerDirection::Out => "out",
        PointerDirection::InOut => "in_out",
    }
}

fn field_value(bytes: &[u8], field: &Field) -> Option<u64> {
    let start = field.offset as usize;
    let end = start.checked_add(field.size as usize)?;
    let bytes = bytes.get(start..end)?;
    if !matches!(bytes.len(), 1 | 2 | 4 | 8) {
        return None;
    }
    let mut value = [0u8; 8];
    value[..bytes.len()].copy_from_slice(bytes);
    Some(u64::from_le_bytes(value))
}

fn pointer_length(
    pointer: &crate::ioctl_schema::PointerDescriptor,
    fields: &[Field],
    bytes: &[u8],
) -> Result<u64> {
    if let Some(field_name) = &pointer.length_field {
        let field = fields
            .iter()
            .find(|field| field.name == *field_name)
            .context("length field missing")?;
        return field_value(bytes, field).context("length field was not captured");
    }
    let values = fields
        .iter()
        .filter_map(|field| field_value(bytes, field).map(|value| (field.name.as_str(), value)))
        .collect::<HashMap<_, _>>();
    eval_length_expression(
        pointer
            .length_expression
            .as_deref()
            .context("length expression missing")?,
        &values,
    )
}

fn eval_length_expression(expression: &str, values: &HashMap<&str, u64>) -> Result<u64> {
    struct Parser<'a> {
        input: &'a [u8],
        cursor: usize,
        values: &'a HashMap<&'a str, u64>,
    }
    impl Parser<'_> {
        fn whitespace(&mut self) {
            while self
                .input
                .get(self.cursor)
                .is_some_and(u8::is_ascii_whitespace)
            {
                self.cursor += 1;
            }
        }
        fn expression(&mut self) -> Result<u64> {
            let mut value = self.term()?;
            loop {
                self.whitespace();
                match self.input.get(self.cursor).copied() {
                    Some(b'+') => {
                        self.cursor += 1;
                        value = value.checked_add(self.term()?).context("length overflow")?;
                    }
                    Some(b'-') => {
                        self.cursor += 1;
                        value = value.checked_sub(self.term()?).context("negative length")?;
                    }
                    _ => return Ok(value),
                }
            }
        }
        fn term(&mut self) -> Result<u64> {
            let mut value = self.factor()?;
            loop {
                self.whitespace();
                match self.input.get(self.cursor).copied() {
                    Some(b'*') => {
                        self.cursor += 1;
                        value = value
                            .checked_mul(self.factor()?)
                            .context("length overflow")?;
                    }
                    Some(b'/') => {
                        self.cursor += 1;
                        let divisor = self.factor()?;
                        value = value.checked_div(divisor).context("division by zero")?;
                    }
                    _ => return Ok(value),
                }
            }
        }
        fn factor(&mut self) -> Result<u64> {
            self.whitespace();
            if self.input.get(self.cursor) == Some(&b'(') {
                self.cursor += 1;
                let value = self.expression()?;
                self.whitespace();
                if self.input.get(self.cursor) != Some(&b')') {
                    bail!("unclosed length expression parenthesis");
                }
                self.cursor += 1;
                return Ok(value);
            }
            let start = self.cursor;
            while self.input.get(self.cursor).is_some_and(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'x')
            }) {
                self.cursor += 1;
            }
            if start == self.cursor {
                bail!("expected length value");
            }
            let token = std::str::from_utf8(&self.input[start..self.cursor])?;
            if let Some(hex) = token.strip_prefix("0x") {
                return u64::from_str_radix(hex, 16).context("invalid hex length literal");
            }
            if token.bytes().all(|byte| byte.is_ascii_digit()) {
                return token.parse().context("invalid length literal");
            }
            self.values
                .get(token)
                .copied()
                .with_context(|| format!("unknown length field '{token}'"))
        }
    }
    let mut parser = Parser {
        input: expression.as_bytes(),
        cursor: 0,
        values,
    };
    let value = parser.expression()?;
    parser.whitespace();
    if parser.cursor != parser.input.len() {
        bail!("unexpected length expression token");
    }
    Ok(value)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn blocked_resource(id: &str, kind: &str, length: u64, error: &str) -> HarnessResource {
    HarnessResource {
        id: id.into(),
        kind: kind.into(),
        sha256: None,
        length,
        status: ResourceStatus::Unresolved,
        error: Some(error.into()),
        address: None,
        pointer_offset: None,
        pointee_layout: None,
        direction: None,
        service: None,
        object_type: None,
        parent: None,
        container: None,
        parent_offset: None,
    }
}

fn binder_object_name(object_type: u32) -> Option<&'static str> {
    match object_type {
        0x7362_2a85 => Some("binder"),
        0x7762_2a85 => Some("weak_binder"),
        0x7368_2a85 => Some("handle"),
        0x7768_2a85 => Some("weak_handle"),
        0x6664_2a85 => Some("fd"),
        0x6664_6185 => Some("fd_array"),
        0x7074_2a85 => Some("buffer"),
        _ => None,
    }
}

pub fn extract(args: ExtractArgs) -> Result<()> {
    let capture = read_capture(&args.capture)?;
    let selected = capture
        .iter()
        .find(|event| event.event_id == args.event_id)
        .with_context(|| format!("event_id {} not found", args.event_id))?;
    let harness_ref = selected
        .harness_ref
        .as_ref()
        .context("selected event has no harness_ref")?;
    validate_ref(harness_ref)?;

    let blob_dir = PathBuf::from(format!("{}.blobs", args.capture.display()));
    let input = read_verified_blob(&blob_dir, &harness_ref.sha256, harness_ref.length)?;
    for resource in &harness_ref.resources {
        if let Some(digest) = &resource.sha256 {
            read_verified_blob(&blob_dir, digest, resource.length)
                .with_context(|| format!("validating resource '{}'", resource.id))?;
        }
    }

    let health = read_health(&args.capture)?;
    let required_identity = required_identity(selected, harness_ref, health.as_ref());
    let steps = dependency_steps(&capture, selected);
    let mut blocked_reasons = blocked_reasons(harness_ref);
    if required_identity.serial.is_empty() {
        blocked_reasons.push("capture is missing device serial".into());
    }
    if required_identity.fingerprint.is_empty() {
        blocked_reasons.push("capture is missing build fingerprint".into());
    }
    if required_identity.boot_id.is_empty() {
        blocked_reasons.push("capture is missing boot identity".into());
    }
    if required_identity.package.is_empty() {
        blocked_reasons.push("capture does not identify the required package".into());
    }
    if required_identity.domain.is_empty() {
        blocked_reasons.push("capture is missing SELinux domain".into());
    }
    let device_paths = selected
        .value
        .get("fd_path")
        .and_then(Value::as_str)
        .map(str::to_string)
        .into_iter()
        .collect::<Vec<_>>();
    let binder_services = steps
        .iter()
        .filter_map(|step| {
            capture
                .iter()
                .find(|event| event.event_id == step.event_id)
                .and_then(|event| event.value.get("service"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let unresolved = harness_ref
        .resources
        .iter()
        .filter(|resource| !resource.status.is_complete())
        .map(|resource| resource.id.clone())
        .collect::<Vec<_>>();
    let mut seen_reasons = HashSet::new();
    blocked_reasons.retain(|reason| seen_reasons.insert(reason.clone()));
    let metadata = Metadata {
        schema: HARNESS_SCHEMA.into(),
        revision: 0,
        source_capture: args.capture.display().to_string(),
        selected_event_id: args.event_id,
        input_sha256: format!("{:x}", Sha256::digest(&input)),
        required_identity,
        steps,
        replay_status: if blocked_reasons.is_empty() {
            "ready".into()
        } else {
            "blocked".into()
        },
        blocked_reasons,
        warning: WARNING.into(),
        mutable_regions: harness_ref.mutable_regions.clone(),
        transactions: harness_ref.transactions.clone(),
    };
    let resources = ResourceCatalog {
        schema: HARNESS_SCHEMA.into(),
        device_paths,
        binder_services,
        resources: harness_ref.resources.clone(),
        object_adapters: Vec::new(),
        unresolved,
    };
    write_artifact(
        &args.output,
        &blob_dir,
        &input,
        &metadata,
        &resources,
        selected,
    )
}

fn read_capture(path: &Path) -> Result<Vec<CaptureEvent>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut events = Vec::new();
    let mut ids = HashSet::new();
    let mut line = Vec::new();
    let mut line_number = 0usize;
    loop {
        line.clear();
        let read = read_limited_line(&mut reader, &mut line, MAX_CAPTURE_LINE)
            .map_err(|error| anyhow::anyhow!("reading {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        line_number += 1;
        let value: Value = serde_json::from_slice(&line)
            .with_context(|| format!("malformed NDJSON at line {line_number}"))?;
        let Some(event_id) = value.get("event_id").and_then(Value::as_u64) else {
            continue;
        };
        if !ids.insert(event_id) {
            bail!("duplicate event_id {event_id}");
        }
        let harness_ref = value
            .get("harness_ref")
            .cloned()
            .map(|value| {
                serde_json::from_value(value).map_err(|error| {
                    anyhow::anyhow!("invalid harness_ref at line {line_number}: {error}")
                })
            })
            .transpose()?;
        events.push(CaptureEvent {
            event_id,
            value,
            harness_ref,
        });
    }
    Ok(events)
}

fn read_health(path: &Path) -> Result<Option<Value>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut health = None;
    let mut bytes = Vec::new();
    let mut index = 0usize;
    loop {
        bytes.clear();
        if read_limited_line(&mut reader, &mut bytes, MAX_CAPTURE_LINE)? == 0 {
            break;
        }
        index += 1;
        let value: Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("malformed NDJSON at line {index}"))?;
        if value.get("type").and_then(Value::as_str) == Some("capture_health") {
            health = Some(value);
        }
    }
    Ok(health)
}

fn read_limited_line(
    reader: &mut impl BufRead,
    output: &mut Vec<u8>,
    limit: usize,
) -> Result<usize> {
    let mut total = 0usize;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(total);
        }
        let take = buffer
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(buffer.len(), |position| position + 1);
        total = total.checked_add(take).context("capture line overflow")?;
        if total > limit {
            bail!("capture line exceeds {limit} bytes");
        }
        output.extend_from_slice(&buffer[..take]);
        let done = buffer.get(take.wrapping_sub(1)) == Some(&b'\n');
        reader.consume(take);
        if done {
            return Ok(total);
        }
    }
}

fn validate_ref(reference: &HarnessRef) -> Result<()> {
    if reference.schema != HARNESS_REF_SCHEMA {
        bail!("unsupported harness_ref schema '{}'", reference.schema);
    }
    if reference.length > MAX_RESOURCE_BYTES {
        bail!("primary resource exceeds 1 MiB limit");
    }
    let mut total = reference.length;
    let mut ids = HashSet::new();
    for resource in &reference.resources {
        if resource.id.is_empty() || !ids.insert(&resource.id) {
            bail!("duplicate or empty harness resource id '{}'", resource.id);
        }
        if resource.status.is_complete() && resource.length > MAX_RESOURCE_BYTES {
            bail!("resource '{}' exceeds 1 MiB limit", resource.id);
        }
        if resource.status.is_complete()
            && resource.kind == "binder_parcel"
            && resource.length > MAX_PARCEL_BYTES
        {
            bail!("Binder Parcel '{}' exceeds 64 KiB limit", resource.id);
        }
        if resource.sha256.is_some() {
            total = total
                .checked_add(resource.length)
                .context("event resource length overflow")?;
        }
    }
    if total > MAX_EVENT_BYTES {
        bail!("event resources exceed 4 MiB limit");
    }
    Ok(())
}

fn normalize_digest(digest: &str) -> Result<&str> {
    let digest = digest.strip_prefix("sha256:").unwrap_or(digest);
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid SHA-256 digest '{digest}'");
    }
    Ok(digest)
}

fn read_verified_blob(directory: &Path, digest: &str, expected_len: u64) -> Result<Vec<u8>> {
    let digest = normalize_digest(digest)?;
    let path = directory.join(digest);
    let path_metadata =
        fs::symlink_metadata(&path).with_context(|| format!("missing blob {digest}"))?;
    if !path_metadata.file_type().is_file() || path_metadata.file_type().is_symlink() {
        bail!("blob {digest} is not a regular file");
    }
    let mut file = File::open(&path).with_context(|| format!("missing blob {digest}"))?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_RESOURCE_BYTES {
        bail!("blob {digest} exceeds resource limit");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    let actual = format!("{:x}", Sha256::digest(&bytes));
    if actual != digest.to_ascii_lowercase() {
        bail!("blob {digest} hash mismatch (got {actual})");
    }
    if metadata.len() != expected_len {
        bail!(
            "blob {digest} length mismatch: expected {expected_len}, got {}",
            metadata.len()
        );
    }
    Ok(bytes)
}

fn required_identity(
    selected: &CaptureEvent,
    reference: &HarnessRef,
    health: Option<&Value>,
) -> RequiredIdentity {
    let text = |value: Option<&Value>, key: &str| {
        value
            .and_then(|value| value.get(key))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let package = text(health, "root_package")
        .or_else(|| text(Some(&selected.value), "package"))
        .unwrap_or_default();
    RequiredIdentity {
        serial: reference.identity.serial.clone().unwrap_or_default(),
        fingerprint: reference
            .identity
            .fingerprint
            .clone()
            .or_else(|| text(health, "fingerprint"))
            .unwrap_or_default(),
        boot_id: reference
            .identity
            .boot_id
            .clone()
            .or_else(|| text(health, "boot_id"))
            .unwrap_or_default(),
        package,
        uid: reference.identity.uid,
        domain: reference.identity.domain.clone().unwrap_or_default(),
    }
}

fn dependency_steps(events: &[CaptureEvent], selected: &CaptureEvent) -> Vec<Step> {
    let by_span = events
        .iter()
        .filter_map(|event| {
            event
                .value
                .get("span_id")
                .and_then(Value::as_str)
                .map(|span| (span, event))
        })
        .collect::<HashMap<_, _>>();
    let mut chain = Vec::new();
    let mut parent = selected.value.get("parent_span_id").and_then(Value::as_str);
    let mut seen = HashSet::new();
    while let Some(span) = parent {
        if !seen.insert(span) {
            break;
        }
        let Some(event) = by_span.get(span).copied() else {
            break;
        };
        chain.push(event);
        parent = event.value.get("parent_span_id").and_then(Value::as_str);
    }
    chain.reverse();

    if let Some(fd) = selected
        .value
        .get("args")
        .and_then(Value::as_array)
        .and_then(|args| args.first())
        .and_then(Value::as_i64)
    {
        if let Some(fd_event) = events.iter().rev().find(|event| {
            event.event_id < selected.event_id
                && event.value.get("pid") == selected.value.get("pid")
                && event.value.get("ret").and_then(Value::as_i64) == Some(fd)
                && matches!(
                    event.value.get("name").and_then(Value::as_str),
                    Some("openat" | "dup" | "dup3")
                )
        }) {
            if !chain
                .iter()
                .any(|event| event.event_id == fd_event.event_id)
            {
                chain.push(fd_event);
                chain.sort_by_key(|event| event.event_id);
            }
        }
    }
    chain.push(selected);
    chain
        .into_iter()
        .map(|event| Step {
            event_id: event.event_id,
            kind: event
                .value
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            span_id: event
                .value
                .get("span_id")
                .and_then(Value::as_str)
                .map(str::to_string),
            parent_span_id: event
                .value
                .get("parent_span_id")
                .and_then(Value::as_str)
                .map(str::to_string),
            delay_ms: 0,
            selected: event.event_id == selected.event_id,
        })
        .collect()
}

fn blocked_reasons(reference: &HarnessRef) -> Vec<String> {
    let mut reasons = Vec::new();
    if !reference.status.is_complete() {
        reasons.push(format!("primary capture is {:?}", reference.status).to_lowercase());
    }
    for resource in &reference.resources {
        if !resource.status.is_complete() {
            reasons.push(format!(
                "resource '{}' is {:?}{}",
                resource.id,
                resource.status,
                resource
                    .error
                    .as_deref()
                    .map(|error| format!(": {error}"))
                    .unwrap_or_default()
            ));
        }
        if matches!(
            resource.object_type.as_deref(),
            Some("binder" | "weak_binder")
        ) && resource.service.is_none()
        {
            reasons.push(format!(
                "resource '{}' requires an explicit callback adapter",
                resource.id
            ));
        }
    }
    reasons
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
}

fn write_artifact(
    output: &Path,
    source_blobs: &Path,
    input: &[u8],
    metadata: &Metadata,
    resources: &ResourceCatalog,
    selected: &CaptureEvent,
) -> Result<()> {
    fs::create_dir(output).with_context(|| {
        format!(
            "creating testcase directory {} (it must not already exist)",
            output.display()
        )
    })?;
    secure_directory(output)?;
    let result = (|| {
        write_json(&output.join("metadata.json"), metadata)?;
        write_json(&output.join("resources.json"), resources)?;
        fs::write(output.join("input.bin"), input)?;
        let target_blobs = output.join("blobs");
        fs::create_dir(&target_blobs)?;
        for resource in &resources.resources {
            if let Some(digest) = &resource.sha256 {
                let digest = normalize_digest(digest)?;
                fs::copy(source_blobs.join(digest), target_blobs.join(digest))?;
            }
        }
        let runner = RunnerContract {
            schema: HARNESS_SCHEMA.into(),
            transport: RunnerTransport::Adb,
            capabilities: Vec::new(),
            prepare: None,
            execute: vec!["{artifact}/replay".into(), "{artifact}/input.bin".into()],
            recover: None,
            timeout_seconds: 30,
        };
        write_json(&output.join("runner.json"), &runner)?;
        fs::write(
            output.join("replay.rs"),
            replay_source(selected, resources)?,
        )?;
        fs::write(
            output.join("setup.sh"),
            "#!/system/bin/sh\n# Manual wrapper only; neutron never executes this file.\nexec ./replay input.bin\n",
        )?;
        fs::write(
            output.join("README.md"),
            format!(
                "# Neutron regression testcase\n\n{WARNING}\n\nBuild `replay.rs` for aarch64, review `runner.json`, and run through `neutron harness replay`.\n\nReplay status: **{}**.\n{}\n",
                metadata.replay_status,
                metadata
                    .blocked_reasons
                    .iter()
                    .map(|reason| format!("- {reason}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        )?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(output);
    }
    result
}

fn replay_source(selected: &CaptureEvent, resources: &ResourceCatalog) -> Result<String> {
    let cmd = selected
        .value
        .get("args")
        .and_then(Value::as_array)
        .and_then(|args| args.get(1))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let path = selected
        .value
        .get("fd_path")
        .and_then(Value::as_str)
        .unwrap_or("/dev/null");
    let blob_resources = resources
        .resources
        .iter()
        .filter(|resource| resource.sha256.is_some())
        .collect::<Vec<_>>();
    let indexes = blob_resources
        .iter()
        .enumerate()
        .map(|(index, resource)| (resource.id.as_str(), index))
        .collect::<HashMap<_, _>>();
    let mut loads = String::new();
    for resource in &blob_resources {
        let digest = normalize_digest(resource.sha256.as_deref().expect("filtered above"))?;
        loads.push_str(&format!(
            "    buffers.push(std::fs::read(artifact.join({:?}))?);\n",
            format!("blobs/{digest}")
        ));
    }
    let mut fixups = String::new();
    for (source_index, resource) in blob_resources.iter().enumerate() {
        let Some(offset) = resource.pointer_offset else {
            continue;
        };
        fixups.push_str(&format!(
            "    let pointer_{source_index} = buffers[{source_index}].as_mut_ptr() as u64;\n"
        ));
        match resource.container.as_deref() {
            Some(container) => {
                let target = indexes.get(container).with_context(|| {
                    format!(
                        "resource '{}' references missing container '{container}'",
                        resource.id
                    )
                })?;
                fixups.push_str(&format!(
                    "    put_u64(&mut buffers[{target}], {offset}, pointer_{source_index})?;\n"
                ));
            }
            None => fixups.push_str(&format!(
                "    put_u64(&mut input, {offset}, pointer_{source_index})?;\n"
            )),
        }
    }
    for resource in resources
        .resources
        .iter()
        .filter(|resource| resource.kind == "fd_recipe")
    {
        let path = resource
            .service
            .as_deref()
            .with_context(|| format!("FD recipe '{}' has no reopen path", resource.id))?;
        let offset = resource
            .pointer_offset
            .with_context(|| format!("FD recipe '{}' has no fixup offset", resource.id))?;
        let container = resource
            .container
            .as_deref()
            .with_context(|| format!("FD recipe '{}' has no container", resource.id))?;
        let target = indexes.get(container).with_context(|| {
            format!(
                "FD recipe '{}' references missing container '{container}'",
                resource.id
            )
        })?;
        fixups.push_str(&format!(
            "    opened.push(OpenOptions::new().read(true).write(true).open({path:?})?);\n    let fd = opened[opened.len() - 1].as_raw_fd();\n    put_i32(&mut buffers[{target}], {offset}, fd)?;\n"
        ));
    }
    Ok(format!(
        r#"// Generated by neutron; review before authorized use.
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

fn main() -> std::io::Result<()> {{
    let input_path = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "input.bin".into()));
    let artifact = input_path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut input = std::fs::read(&input_path)?;
    let mut buffers: Vec<Vec<u8>> = Vec::new();
    let mut opened: Vec<std::fs::File> = Vec::new();
{loads}{fixups}
    let device = OpenOptions::new().read(true).write(true).open({path:?})?;
    let rc = unsafe {{ ioctl(device.as_raw_fd(), {cmd}u64, input.as_mut_ptr()) }};
    if rc < 0 {{ return Err(std::io::Error::last_os_error()); }}
    Ok(())
}}

fn put_u64(target: &mut [u8], offset: u64, value: u64) -> std::io::Result<()> {{
    let offset = usize::try_from(offset).map_err(|_| std::io::ErrorKind::InvalidData)?;
    let end = offset.checked_add(8).ok_or(std::io::ErrorKind::InvalidData)?;
    target.get_mut(offset..end).ok_or(std::io::ErrorKind::InvalidData)?.copy_from_slice(&value.to_le_bytes());
    Ok(())
}}

fn put_i32(target: &mut [u8], offset: u64, value: i32) -> std::io::Result<()> {{
    let offset = usize::try_from(offset).map_err(|_| std::io::ErrorKind::InvalidData)?;
    let end = offset.checked_add(4).ok_or(std::io::ErrorKind::InvalidData)?;
    target.get_mut(offset..end).ok_or(std::io::ErrorKind::InvalidData)?.copy_from_slice(&value.to_le_bytes());
    Ok(())
}}

unsafe extern "C" {{ fn ioctl(fd: i32, request: u64, arg: *mut u8) -> i32; }}
"#
    ))
}

pub fn replay(args: ReplayArgs) -> Result<()> {
    require_authorized(args.authorized_use)?;
    validate_serial_syntax(&args.serial)?;
    eprintln!("neutron: WARNING: {WARNING}");
    let mut expected = validate_artifact(&args.directory)?.required_identity;
    if args.serial != expected.serial {
        bail!(
            "requested serial '{}' differs from captured serial '{}'",
            args.serial,
            expected.serial
        );
    }
    if args.package != expected.package {
        bail!(
            "requested package '{}' differs from captured package '{}'",
            args.package,
            expected.package
        );
    }
    let runner_path = resolve_runner_path(&args.directory, &args.runner);
    let runner = load_runner(&runner_path)?;
    let timeout = Duration::from_secs(args.timeout.min(runner.timeout_seconds));
    for run in 1..=args.max_runs.min(1000) {
        let result = replay_once(
            &args.directory,
            &args.serial,
            &args.package,
            &runner,
            timeout,
            run,
            &mut expected,
        );
        write_json(&args.directory.join("run-result.json"), &result)?;
        if !matches!(result.status, RunStatus::Completed | RunStatus::Crash) {
            bail!(
                "replay run {run} failed as {:?}: {}",
                result.status,
                result.error.as_deref().unwrap_or("no detail")
            );
        }
    }
    Ok(())
}

pub fn minimize(args: MinimizeArgs) -> Result<()> {
    require_authorized(args.authorized_use)?;
    validate_serial_syntax(&args.serial)?;
    eprintln!("neutron: WARNING: {WARNING}");
    let mut metadata = validate_artifact(&args.directory)?;
    let resources = load_resources(&args.directory)?;
    if !resources.unresolved.is_empty()
        || resources
            .resources
            .iter()
            .any(|resource| !resource.status.is_complete())
    {
        bail!("testcase contains unresolved or incomplete resources");
    }
    let runner_path = resolve_runner_path(&args.directory, &args.runner);
    let runner = load_runner(&runner_path)?;
    let original_input = fs::read(args.directory.join("input.bin"))?;
    let revisions = args.directory.join("revisions");
    fs::create_dir_all(&revisions)?;
    secure_directory(&revisions)?;
    let revision = next_revision(&revisions)?;
    let final_dir = revisions.join(format!("revision-{revision}"));
    let work_dir = revisions.join(format!(".candidate-{}", std::process::id()));
    let _ = fs::remove_dir_all(&work_dir);
    let mut state = MinimizeState {
        source: &args.directory,
        work: &work_dir,
        runner: &runner,
        serial: &args.serial,
        package: &args.package,
        oracle: &args.oracle_command,
        oracle_args: &args.oracle_arg,
        timeout: Duration::from_secs(args.timeout.min(runner.timeout_seconds)),
        max_runs: args.max_runs.min(1000),
        runs: 0,
        log: Vec::new(),
    };
    if !state.evaluate(&metadata, &original_input)? {
        let _ = fs::remove_dir_all(&work_dir);
        bail!("original testcase does not satisfy the oracle");
    }
    state.log.push(MinimizeLogEntry {
        run: state.runs,
        stage: "baseline".into(),
        accepted: true,
        candidate_items: metadata.steps.len(),
    });

    let original_steps = metadata.steps.clone();
    let selected = metadata.selected_event_id;
    let removable = original_steps
        .iter()
        .filter(|step| !step.selected)
        .cloned()
        .collect::<Vec<_>>();
    let fixed = original_steps
        .iter()
        .filter(|step| step.selected)
        .cloned()
        .collect::<Vec<_>>();
    let minimized_steps = state.ddmin_stage(
        "causal_steps",
        removable,
        |kept, candidate| {
            let mut steps = kept.to_vec();
            steps.extend(fixed.clone());
            steps.sort_by_key(|step| step.event_id);
            candidate.steps = steps;
        },
        &metadata,
        &original_input,
    )?;
    metadata.steps = minimized_steps.into_iter().chain(fixed).collect::<Vec<_>>();
    metadata.steps.sort_by_key(|step| step.event_id);

    let minimized_transactions = state.ddmin_stage(
        "binder_transactions",
        metadata.transactions.clone(),
        |kept, candidate| candidate.transactions = kept.to_vec(),
        &metadata,
        &original_input,
    )?;
    metadata.transactions = minimized_transactions;

    let all_regions = metadata.mutable_regions.clone();
    let retained_regions = state.ddmin_input_regions(&metadata, &original_input, &all_regions)?;
    let mut input = original_input.clone();
    zero_removed_regions(&mut input, &all_regions, &retained_regions);
    input = state.minimize_trailing(&metadata, input)?;

    let delays = metadata
        .steps
        .iter()
        .filter(|step| step.delay_ms != 0)
        .map(|step| step.event_id)
        .collect::<Vec<_>>();
    let kept_delays = state.ddmin_stage(
        "timing_delays",
        delays,
        |kept, candidate| {
            let kept = kept.iter().copied().collect::<HashSet<_>>();
            for step in &mut candidate.steps {
                if !kept.contains(&step.event_id) {
                    step.delay_ms = 0;
                }
            }
        },
        &metadata,
        &input,
    )?;
    let kept_delays = kept_delays.into_iter().collect::<HashSet<_>>();
    for step in &mut metadata.steps {
        if !kept_delays.contains(&step.event_id) {
            step.delay_ms = 0;
        }
    }

    copy_artifact(&args.directory, &final_dir)?;
    metadata.revision = revision;
    metadata.input_sha256 = format!("{:x}", Sha256::digest(&input));
    write_json(&final_dir.join("metadata.json"), &metadata)?;
    fs::write(final_dir.join("input.bin"), &input)?;
    write_json(&final_dir.join("runner.json"), &runner)?;
    write_json(&final_dir.join("minimize-log.json"), &state.log)?;
    write_json(
        &final_dir.join("revision-manifest.json"),
        &serde_json::json!({
            "schema": HARNESS_SCHEMA,
            "revision": revision,
            "parent_event_id": selected,
            "source_sha256": format!("{:x}", Sha256::digest(&original_input)),
            "input_sha256": format!("{:x}", Sha256::digest(&input)),
            "runs": state.runs,
            "warning": WARNING,
        }),
    )?;
    let _ = fs::remove_dir_all(&work_dir);
    println!("{}", final_dir.display());
    Ok(())
}

fn require_authorized(authorized: bool) -> Result<()> {
    if !authorized {
        bail!("--authorized-use is required");
    }
    Ok(())
}

fn parse_adb_devices(output: &str) -> Result<Vec<AdbDevice>> {
    let mut devices = Vec::new();
    for line in output
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
    {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 2 {
            bail!("malformed adb devices line '{line}'");
        }
        devices.push(AdbDevice {
            serial: fields[0].into(),
            state: fields[1].into(),
            usb: fields[2..].iter().any(|field| field.starts_with("usb:")),
        });
    }
    Ok(devices)
}

fn validate_usb_device(devices: &[AdbDevice], serial: &str) -> Result<()> {
    validate_serial_syntax(serial)?;
    let device = devices
        .iter()
        .find(|device| device.serial == serial)
        .with_context(|| format!("explicit ADB serial '{serial}' is not connected"))?;
    if device.state != "device" {
        bail!("ADB serial '{serial}' is in state '{}'", device.state);
    }
    if !device.usb {
        bail!("ADB serial '{serial}' is not a physical USB transport");
    }
    Ok(())
}

fn validate_serial_syntax(serial: &str) -> Result<()> {
    if serial.contains(':') {
        bail!("network ADB serials are forbidden");
    }
    if serial.starts_with("emulator-") {
        bail!("emulator transports are forbidden");
    }
    if serial.is_empty()
        || !serial
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("invalid ADB serial");
    }
    Ok(())
}

fn adb_inventory(timeout: Duration) -> Result<Vec<AdbDevice>> {
    let output = run_argv(
        &["adb".into(), "devices".into(), "-l".into()],
        None,
        timeout,
    )?;
    if output.timed_out || !output.status.success() {
        bail!("adb devices -l failed or timed out");
    }
    parse_adb_devices(&String::from_utf8_lossy(&output.stdout))
}

fn validate_argv(argv: &[String]) -> Result<()> {
    if argv.is_empty() || argv[0].is_empty() {
        bail!("runner argv must contain a non-empty program");
    }
    if argv.iter().any(|arg| arg.contains('\0')) {
        bail!("runner argv contains a NUL byte");
    }
    Ok(())
}

fn load_runner(path: &Path) -> Result<RunnerContract> {
    let bytes = fs::read(path).with_context(|| format!("reading runner {}", path.display()))?;
    let runner: RunnerContract = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing runner {}", path.display()))?;
    if runner.schema != HARNESS_SCHEMA {
        bail!("unsupported runner schema '{}'", runner.schema);
    }
    validate_argv(&runner.execute)?;
    for hook in [runner.prepare.as_deref(), runner.recover.as_deref()]
        .into_iter()
        .flatten()
    {
        validate_argv(hook)?;
    }
    if !(1..=3600).contains(&runner.timeout_seconds) {
        bail!("runner timeout_seconds must be in 1..=3600");
    }
    if runner.transport == RunnerTransport::Adb
        && (runner.prepare.is_some() || runner.recover.is_some())
    {
        bail!("ADB runners do not support prepare or recover hooks");
    }
    Ok(runner)
}

fn resolve_runner_path(directory: &Path, runner: &Path) -> PathBuf {
    if runner.is_absolute() || runner.exists() {
        runner.to_path_buf()
    } else {
        directory.join(runner)
    }
}

fn load_ready_metadata(directory: &Path) -> Result<Metadata> {
    let bytes = fs::read(directory.join("metadata.json"))?;
    let metadata: Metadata = serde_json::from_slice(&bytes)?;
    if metadata.schema != HARNESS_SCHEMA {
        bail!("unsupported testcase schema '{}'", metadata.schema);
    }
    if metadata.replay_status != "ready" || !metadata.blocked_reasons.is_empty() {
        bail!(
            "testcase is blocked: {}",
            metadata.blocked_reasons.join("; ")
        );
    }
    Ok(metadata)
}

fn load_resources(directory: &Path) -> Result<ResourceCatalog> {
    let value: ResourceCatalog =
        serde_json::from_slice(&fs::read(directory.join("resources.json"))?)?;
    if value.schema != HARNESS_SCHEMA {
        bail!("unsupported resources schema '{}'", value.schema);
    }
    Ok(value)
}

pub(crate) fn validate_artifact(directory: &Path) -> Result<Metadata> {
    let metadata = load_ready_metadata(directory)?;
    let input = fs::read(directory.join("input.bin"))?;
    let digest = format!("{:x}", Sha256::digest(&input));
    if digest != metadata.input_sha256 {
        bail!("input.bin hash mismatch");
    }
    let resources = load_resources(directory)?;
    if !resources.unresolved.is_empty() {
        bail!("testcase contains unresolved resources");
    }
    for resource in &resources.resources {
        if !resource.status.is_complete() {
            bail!("resource '{}' is not complete", resource.id);
        }
        if let Some(digest) = &resource.sha256 {
            read_verified_blob(&directory.join("blobs"), digest, resource.length)
                .with_context(|| format!("validating artifact resource '{}'", resource.id))?;
        }
    }
    Ok(metadata)
}

fn validate_identity(expected: &RequiredIdentity, actual: &RequiredIdentity) -> Result<()> {
    if expected.serial != actual.serial {
        bail!("device serial drift");
    }
    if expected.fingerprint != actual.fingerprint {
        bail!("build fingerprint drift");
    }
    if expected.boot_id != actual.boot_id {
        bail!("boot identity drift");
    }
    if expected.package != actual.package || expected.uid != actual.uid {
        bail!("package UID drift");
    }
    if expected.domain != actual.domain {
        bail!("SELinux domain drift");
    }
    Ok(())
}

fn query_identity(serial: &str, package: &str, timeout: Duration) -> Result<RequiredIdentity> {
    let mut identity = query_base_identity(serial, package, timeout)?;
    let pids = adb_text(serial, &["shell", "pidof", package], timeout)?;
    let pid = pids
        .split_whitespace()
        .next()
        .context("required package has no running process")?;
    if !pid.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("pidof returned an invalid PID");
    }
    let attr = format!("/proc/{pid}/attr/current");
    let domain = adb_text(serial, &["shell", "cat", &attr], timeout)?;
    identity.domain = domain.trim_end_matches('\0').into();
    Ok(identity)
}

fn validate_package(package: &str) -> Result<()> {
    if package.is_empty()
        || !package
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_'))
    {
        bail!("invalid Android package name");
    }
    Ok(())
}

fn adb_text(serial: &str, args: &[&str], timeout: Duration) -> Result<String> {
    let mut argv = vec!["adb".into(), "-s".into(), serial.into()];
    argv.extend(args.iter().map(|arg| (*arg).to_string()));
    let output = run_argv(&argv, None, timeout)?;
    if output.timed_out || !output.status.success() {
        bail!(
            "adb command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let value = String::from_utf8(output.stdout).context("adb output is not UTF-8")?;
    let value = value.trim().to_string();
    if value.is_empty() {
        bail!("adb command returned an empty value");
    }
    Ok(value)
}

fn expand_argv(argv: &[String], serial: &str, package: &str, directory: &Path) -> Vec<String> {
    expand_argv_at(argv, serial, package, &directory.display().to_string())
}

fn expand_argv_at(argv: &[String], serial: &str, package: &str, artifact: &str) -> Vec<String> {
    argv.iter()
        .map(|arg| {
            arg.replace("{serial}", serial)
                .replace("{package}", package)
                .replace("{artifact}", artifact)
        })
        .collect()
}

fn adb_execute_argv(
    execute: &[String],
    serial: &str,
    package: &str,
    remote_artifact: &str,
    timeout: Duration,
) -> Vec<String> {
    let mut argv = vec![
        "adb".into(),
        "-s".into(),
        serial.into(),
        "shell".into(),
        "timeout".into(),
        format!("{}s", timeout.as_secs().max(1)),
    ];
    argv.extend(expand_argv_at(
        execute,
        serial,
        package,
        remote_artifact,
    ));
    argv
}

fn adb_stage_files(
    directory: &Path,
    resources: &ResourceCatalog,
) -> Result<Vec<AdbStageAsset>> {
    let mut assets = Vec::new();
    for (name, limit) in [
        ("replay", MAX_REPLAY_BINARY_BYTES),
        ("input.bin", MAX_RESOURCE_BYTES),
        ("metadata.json", MAX_EVENT_BYTES),
        ("resources.json", MAX_EVENT_BYTES),
    ] {
        assets.push(checked_stage_asset(directory.join(name), name.into(), limit)?);
    }
    let mut digests = HashSet::new();
    for resource in &resources.resources {
        let Some(digest) = resource.sha256.as_deref() else {
            continue;
        };
        let digest = normalize_digest(digest)?.to_ascii_lowercase();
        if !digests.insert(digest.clone()) {
            continue;
        }
        assets.push(checked_stage_asset(
            directory.join("blobs").join(&digest),
            format!("blobs/{digest}"),
            MAX_RESOURCE_BYTES,
        )?);
    }
    assets.sort_by(|left, right| left.remote_path.cmp(&right.remote_path));
    Ok(assets)
}

fn remote_artifact_path(input_sha256: &str) -> Result<String> {
    let digest = normalize_digest(input_sha256)?.to_ascii_lowercase();
    Ok(format!(
        "/data/local/tmp/neutron-harness-{}-{}",
        std::process::id(),
        &digest[..16]
    ))
}

fn checked_stage_asset(path: PathBuf, remote_path: String, limit: u64) -> Result<AdbStageAsset> {
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("missing ADB replay asset {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!("ADB replay asset must be a regular file: {}", path.display());
    }
    if metadata.len() > limit {
        bail!("ADB replay asset exceeds its size limit: {}", path.display());
    }
    Ok(AdbStageAsset {
        local_path: path,
        remote_path,
    })
}

fn adb_argv(serial: &str, args: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut argv = vec!["adb".into(), "-s".into(), serial.into()];
    argv.extend(args);
    argv
}

fn run_checked_adb(argv: &[String], timeout: Duration, action: &str) -> Result<()> {
    let output = run_argv(argv, None, timeout)?;
    if output.timed_out || !output.status.success() {
        bail!(
            "adb {action} failed{}: {}",
            if output.timed_out { " (timeout)" } else { "" },
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn stage_adb_artifact(directory: &Path, serial: &str, timeout: Duration) -> Result<String> {
    let input = fs::read(directory.join("input.bin"))?;
    let remote = remote_artifact_path(&format!("{:x}", Sha256::digest(&input)))?;
    let resources = load_resources(directory)?;
    let assets = adb_stage_files(directory, &resources)?;
    let result = (|| {
        cleanup_adb_artifact(serial, &remote, timeout)?;
        run_checked_adb(
            &adb_argv(
                serial,
                [
                    "shell".into(),
                    "mkdir".into(),
                    "-p".into(),
                    format!("{remote}/blobs"),
                ],
            ),
            timeout,
            "staging directory creation",
        )?;
        for asset in assets {
            let local = asset
                .local_path
                .to_str()
                .context("ADB replay asset path is not UTF-8")?
                .to_string();
            run_checked_adb(
                &adb_argv(
                    serial,
                    ["push".into(), local, format!("{remote}/{}", asset.remote_path)],
                ),
                timeout,
                "asset push",
            )?;
        }
        run_checked_adb(
            &adb_argv(
                serial,
                [
                    "shell".into(),
                    "chmod".into(),
                    "0700".into(),
                    format!("{remote}/replay"),
                ],
            ),
            timeout,
            "replay chmod",
        )?;
        Ok(remote.clone())
    })();
    if result.is_err() {
        let _ = cleanup_adb_artifact(serial, &remote, timeout);
    }
    result
}

fn cleanup_adb_artifact(serial: &str, remote: &str, timeout: Duration) -> Result<()> {
    if !remote.starts_with("/data/local/tmp/neutron-harness-")
        || remote["/data/local/tmp/neutron-harness-".len()..]
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-')
    {
        bail!("refusing unsafe remote harness cleanup path");
    }
    run_checked_adb(
        &adb_argv(
            serial,
            [
                "shell".into(),
                "rm".into(),
                "-rf".into(),
                remote.into(),
            ],
        ),
        timeout,
        "staging cleanup",
    )
}

fn run_argv(argv: &[String], cwd: Option<&Path>, timeout: Duration) -> Result<CommandOutput> {
    validate_argv(argv)?;
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("spawning '{}'", argv[0]))?;
    let stdout = child.stdout.take().map(|mut pipe| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.read_to_end(&mut bytes)?;
            Ok::<_, std::io::Error>(bytes)
        })
    });
    let stderr = child.stderr.take().map(|mut pipe| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.read_to_end(&mut bytes)?;
            Ok::<_, std::io::Error>(bytes)
        })
    });
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(CommandOutput {
                status,
                stdout: join_output(stdout)?,
                stderr: join_output(stderr)?,
                timed_out: false,
            });
        }
        if started.elapsed() >= timeout {
            child.kill()?;
            let status = child.wait()?;
            return Ok(CommandOutput {
                status,
                stdout: join_output(stdout)?,
                stderr: join_output(stderr)?,
                timed_out: true,
            });
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn join_output(handle: Option<thread::JoinHandle<std::io::Result<Vec<u8>>>>) -> Result<Vec<u8>> {
    handle
        .map(|handle| {
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("command output reader panicked"))?
                .map_err(anyhow::Error::from)
        })
        .transpose()
        .map(|output| output.unwrap_or_default())
}

fn replay_once(
    directory: &Path,
    serial: &str,
    package: &str,
    runner: &RunnerContract,
    timeout: Duration,
    run: u32,
    expected: &mut RequiredIdentity,
) -> RunResult {
    match replay_once_inner(directory, serial, package, runner, timeout, expected) {
        Ok((status, exit_code, timed_out, recovered)) => RunResult {
            schema: HARNESS_SCHEMA.into(),
            run,
            status,
            exit_code,
            timed_out,
            recovered,
            warning: WARNING.into(),
            error: None,
        },
        Err(error) => RunResult {
            schema: HARNESS_SCHEMA.into(),
            run,
            status: if format!("{error:#}").contains("hook") {
                RunStatus::HookFailure
            } else if format!("{error:#}").contains("identity")
                || format!("{error:#}").contains("fingerprint")
                || format!("{error:#}").contains("SELinux")
                || format!("{error:#}").contains("package UID")
            {
                RunStatus::IdentityDrift
            } else if format!("{error:#}").contains("adb")
                || format!("{error:#}").contains("ADB")
                || format!("{error:#}").contains("USB")
            {
                RunStatus::TransportLoss
            } else {
                RunStatus::RecoveryFailed
            },
            exit_code: None,
            timed_out: false,
            recovered: false,
            warning: WARNING.into(),
            error: Some(format!("{error:#}")),
        },
    }
}

fn replay_once_inner(
    directory: &Path,
    serial: &str,
    package: &str,
    runner: &RunnerContract,
    timeout: Duration,
    expected: &mut RequiredIdentity,
) -> Result<(RunStatus, Option<i32>, bool, bool)> {
    let devices = adb_inventory(timeout)?;
    validate_usb_device(&devices, serial)?;
    let before = query_identity(serial, package, timeout)?;
    validate_identity(expected, &before)?;
    let remote = (runner.transport == RunnerTransport::Adb)
        .then(|| stage_adb_artifact(directory, serial, timeout))
        .transpose()?;
    let result = (|| {
        if let Some(prepare) = &runner.prepare {
            let output = run_argv(
                &expand_argv(prepare, serial, package, directory),
                Some(directory),
                timeout,
            )?;
            if output.timed_out || !output.status.success() {
                return Ok((
                    RunStatus::HookFailure,
                    output.status.code(),
                    output.timed_out,
                    false,
                ));
            }
        }
        let output = match remote.as_deref() {
            Some(remote) => run_argv(
                &adb_execute_argv(&runner.execute, serial, package, remote, timeout),
                None,
                timeout.saturating_add(Duration::from_secs(5)),
            )?,
            None => run_argv(
                &expand_argv(&runner.execute, serial, package, directory),
                Some(directory),
                timeout,
            )?,
        };
        let timed_out = output.timed_out
            || (runner.transport == RunnerTransport::Adb && output.status.code() == Some(124));
        let mut status = if timed_out {
            RunStatus::Timeout
        } else if output.status.success() {
            RunStatus::Completed
        } else {
            RunStatus::Crash
        };
        let mut recovered = false;
        let after = query_identity(serial, package, timeout);
        match after {
            Ok(actual) if actual.boot_id != before.boot_id => status = RunStatus::Reboot,
            Ok(actual) => validate_identity(expected, &actual)?,
            Err(_) => {
                status = if adb_inventory(timeout)
                    .and_then(|devices| validate_usb_device(&devices, serial))
                    .is_ok()
                {
                    RunStatus::Crash
                } else {
                    RunStatus::TransportLoss
                };
            }
        }
        if matches!(
            status,
            RunStatus::Crash | RunStatus::Reboot | RunStatus::TransportLoss | RunStatus::Timeout
        ) {
            let actual = recover_device(serial, package, runner, directory, timeout, expected)?;
            if actual.boot_id != expected.boot_id {
                expected.boot_id = actual.boot_id;
            }
            recovered = true;
        }
        Ok((status, output.status.code(), timed_out, recovered))
    })();
    let cleanup = remote
        .as_deref()
        .map(|remote| cleanup_adb_artifact(serial, remote, timeout))
        .unwrap_or(Ok(()));
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => {
            Err(error.context(format!("remote staging cleanup also failed: {cleanup:#}")))
        }
    }
}

fn recover_device(
    serial: &str,
    package: &str,
    runner: &RunnerContract,
    directory: &Path,
    timeout: Duration,
    expected: &RequiredIdentity,
) -> Result<RequiredIdentity> {
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            bail!("recovery timed out waiting for the same USB serial");
        }
        if adb_inventory(Duration::from_secs(5))
            .and_then(|devices| validate_usb_device(&devices, serial))
            .is_ok()
            && matches!(
                adb_text(
                    serial,
                    &["shell", "getprop", "sys.boot_completed"],
                    Duration::from_secs(5),
                )
                .as_deref(),
                Ok("1")
            )
        {
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }
    let base = query_base_identity(serial, package, timeout)?;
    if base.serial != expected.serial
        || base.fingerprint != expected.fingerprint
        || base.package != expected.package
        || base.uid != expected.uid
    {
        bail!("identity drift after recovery");
    }
    if let Some(recover) = &runner.recover {
        let output = run_argv(
            &expand_argv(recover, serial, package, directory),
            Some(directory),
            timeout,
        )?;
        if output.timed_out || !output.status.success() {
            bail!("recover hook failed");
        }
    }
    if let Some(prepare) = &runner.prepare {
        let output = run_argv(
            &expand_argv(prepare, serial, package, directory),
            Some(directory),
            timeout,
        )?;
        if output.timed_out || !output.status.success() {
            bail!("prepare hook failed after recovery");
        }
    }
    let actual = query_identity(serial, package, timeout)?;
    if actual.domain != expected.domain {
        bail!("SELinux identity drift after recovery");
    }
    Ok(actual)
}

fn query_base_identity(serial: &str, package: &str, timeout: Duration) -> Result<RequiredIdentity> {
    validate_package(package)?;
    let fingerprint = adb_text(
        serial,
        &["shell", "getprop", "ro.build.fingerprint"],
        timeout,
    )?;
    let boot_id = adb_text(
        serial,
        &["shell", "cat", "/proc/sys/kernel/random/boot_id"],
        timeout,
    )?;
    let packages = adb_text(
        serial,
        &["shell", "cmd", "package", "list", "packages", "-U", package],
        timeout,
    )?;
    let uid = crate::android::parse_package_uid_lines(&packages, package)?;
    Ok(RequiredIdentity {
        serial: serial.into(),
        fingerprint,
        boot_id,
        package: package.into(),
        uid,
        domain: String::new(),
    })
}

fn ddmin<T: Clone>(
    mut value: Vec<T>,
    max_runs: u32,
    mut reproduces: impl FnMut(&[T]) -> Result<bool>,
) -> Result<DdminResult<T>> {
    let mut runs = 0;
    let mut granularity = 2usize;
    while value.len() >= 2 && runs < max_runs {
        let chunk = value.len().div_ceil(granularity);
        let mut reduced = false;
        for start in (0..value.len()).step_by(chunk) {
            if runs >= max_runs {
                break;
            }
            let end = (start + chunk).min(value.len());
            let mut candidate = value[..start].to_vec();
            candidate.extend_from_slice(&value[end..]);
            runs += 1;
            if reproduces(&candidate)? {
                value = candidate;
                granularity = granularity.saturating_sub(1).max(2);
                reduced = true;
                break;
            }
        }
        if !reduced {
            if granularity >= value.len() {
                break;
            }
            granularity = (granularity * 2).min(value.len());
        }
    }
    Ok(DdminResult { value, runs })
}

#[cfg(test)]
fn byte_candidates(input: &[u8], regions: &[MutableRegion]) -> Vec<Vec<u8>> {
    let mut output = Vec::new();
    for region in regions {
        let mut candidate = input.to_vec();
        let start = (region.offset as usize).min(candidate.len());
        let end = start
            .saturating_add(region.length as usize)
            .min(candidate.len());
        candidate[start..end].fill(0);
        output.push(candidate);
    }
    let mut length = input.len() / 2;
    while length > 0 {
        output.push(input[..length].to_vec());
        length /= 2;
    }
    output
}

fn zero_removed_regions(input: &mut [u8], all: &[MutableRegion], retained: &[MutableRegion]) {
    for region in all {
        if retained.iter().any(|kept| {
            kept.offset == region.offset && kept.length == region.length && kept.kind == region.kind
        }) {
            continue;
        }
        let start = (region.offset as usize).min(input.len());
        let end = start
            .saturating_add(region.length as usize)
            .min(input.len());
        input[start..end].fill(0);
    }
}

#[derive(Serialize)]
struct MinimizeLogEntry {
    run: u32,
    stage: String,
    accepted: bool,
    candidate_items: usize,
}

struct MinimizeState<'a> {
    source: &'a Path,
    work: &'a Path,
    runner: &'a RunnerContract,
    serial: &'a str,
    package: &'a str,
    oracle: &'a Path,
    oracle_args: &'a [String],
    timeout: Duration,
    max_runs: u32,
    runs: u32,
    log: Vec<MinimizeLogEntry>,
}

impl MinimizeState<'_> {
    fn ddmin_stage<T: Clone>(
        &mut self,
        stage: &str,
        values: Vec<T>,
        mut apply: impl FnMut(&[T], &mut Metadata),
        metadata: &Metadata,
        input: &[u8],
    ) -> Result<Vec<T>> {
        let remaining = self.max_runs.saturating_sub(self.runs);
        let result = ddmin(values, remaining, |candidate| {
            let mut candidate_metadata = metadata.clone();
            apply(candidate, &mut candidate_metadata);
            let accepted = self.evaluate(&candidate_metadata, input)?;
            self.log.push(MinimizeLogEntry {
                run: self.runs,
                stage: stage.into(),
                accepted,
                candidate_items: candidate.len(),
            });
            Ok(accepted)
        })?;
        Ok(result.value)
    }

    fn ddmin_input_regions(
        &mut self,
        metadata: &Metadata,
        input: &[u8],
        regions: &[MutableRegion],
    ) -> Result<Vec<MutableRegion>> {
        let remaining = self.max_runs.saturating_sub(self.runs);
        let result = ddmin(regions.to_vec(), remaining, |retained| {
            let mut candidate = input.to_vec();
            zero_removed_regions(&mut candidate, regions, retained);
            let accepted = self.evaluate(metadata, &candidate)?;
            self.log.push(MinimizeLogEntry {
                run: self.runs,
                stage: "fields_and_flags".into(),
                accepted,
                candidate_items: retained.len(),
            });
            Ok(accepted)
        })?;
        Ok(result.value)
    }

    fn minimize_trailing(&mut self, metadata: &Metadata, mut input: Vec<u8>) -> Result<Vec<u8>> {
        let mut length = input.len() / 2;
        while length > 0 && self.runs < self.max_runs {
            let candidate = input[..length].to_vec();
            let accepted = self.evaluate(metadata, &candidate)?;
            self.log.push(MinimizeLogEntry {
                run: self.runs,
                stage: "trailing_buffer".into(),
                accepted,
                candidate_items: length,
            });
            if accepted {
                input = candidate;
            }
            length /= 2;
        }
        Ok(input)
    }

    fn evaluate(&mut self, metadata: &Metadata, input: &[u8]) -> Result<bool> {
        if self.runs >= self.max_runs {
            return Ok(false);
        }
        self.runs += 1;
        let _ = fs::remove_dir_all(self.work);
        copy_artifact(self.source, self.work)?;
        write_json(&self.work.join("metadata.json"), metadata)?;
        write_json(&self.work.join("runner.json"), self.runner)?;
        fs::write(self.work.join("input.bin"), input)?;
        let mut expected = metadata.required_identity.clone();
        let mut result = replay_once(
            self.work,
            self.serial,
            self.package,
            self.runner,
            self.timeout,
            self.runs,
            &mut expected,
        );
        let result_path = self.work.join("run-result.json");
        write_json(&result_path, &result)?;
        if matches!(
            result.status,
            RunStatus::TransportLoss
                | RunStatus::Timeout
                | RunStatus::HookFailure
                | RunStatus::IdentityDrift
                | RunStatus::RecoveryFailed
                | RunStatus::OracleError
        ) {
            bail!(
                "infrastructure failure during minimization: {:?}",
                result.status
            );
        }
        let mut argv = vec![self.oracle.display().to_string()];
        argv.extend(self.oracle_args.iter().cloned());
        argv.push(result_path.display().to_string());
        let oracle = match run_argv(&argv, Some(self.work), self.timeout) {
            Ok(output) => output,
            Err(error) => {
                result.status = RunStatus::OracleError;
                result.error = Some(format!("oracle execution failed: {error:#}"));
                write_json(&result_path, &result)?;
                return Err(error).context("oracle execution failed");
            }
        };
        if oracle.timed_out {
            result.status = RunStatus::OracleError;
            result.error = Some("oracle timed out".into());
            write_json(&result_path, &result)?;
            bail!("oracle timed out");
        }
        match oracle.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            code => {
                result.status = RunStatus::OracleError;
                result.error = Some(format!("oracle error (exit {code:?})"));
                write_json(&result_path, &result)?;
                bail!("oracle error (exit {:?})", code)
            }
        }
    }
}

fn next_revision(directory: &Path) -> Result<u32> {
    let mut maximum = 0;
    for entry in fs::read_dir(directory)? {
        let name = entry?.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(number) = name
            .strip_prefix("revision-")
            .and_then(|number| number.parse::<u32>().ok())
        {
            maximum = maximum.max(number);
        }
    }
    maximum.checked_add(1).context("revision number overflow")
}

fn copy_artifact(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir(target)?;
    secure_directory(target)?;
    for name in [
        "metadata.json",
        "resources.json",
        "input.bin",
        "replay.rs",
        "runner.json",
        "setup.sh",
        "README.md",
    ] {
        let source_path = source.join(name);
        if source_path.exists() {
            fs::copy(&source_path, target.join(name))?;
        }
    }
    let source_blobs = source.join("blobs");
    if source_blobs.is_dir() {
        let target_blobs = target.join("blobs");
        fs::create_dir(&target_blobs)?;
        for entry in fs::read_dir(source_blobs)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                fs::copy(entry.path(), target_blobs.join(entry.file_name()))?;
            }
        }
    }
    Ok(())
}

fn secure_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioctl_schema::{
        Descriptor, Field, Layout, PackMetadata, PointerDescriptor, PointerDirection, SchemaPack,
        SchemaRegistry, Selectors,
    };
    use neutron_common::SyscallEvent;

    struct FakeMemory(HashMap<(u32, u64), Vec<u8>>);

    impl MemoryReader for FakeMemory {
        fn read_exact(&self, pid: u32, address: u64, length: usize) -> Result<Vec<u8>> {
            let bytes = self.0.get(&(pid, address)).context("missing fake memory")?;
            if bytes.len() != length {
                bail!("fake memory length mismatch");
            }
            Ok(bytes.clone())
        }
    }

    fn pointer_registry(described: bool) -> SchemaRegistry {
        let cmd = 0xc018_7a01;
        let descriptor = Descriptor {
            id: "sample".into(),
            name: "SAMPLE".into(),
            cmd,
            magic: 0x7a,
            nr: 1,
            direction: 3,
            size: 24,
            type_name: "struct sample".into(),
            family: None,
            fd_paths: vec![],
            fields: vec![
                Field::scalar("len", 0, 8, "u64"),
                Field::scalar("ptr", 8, 8, "pointer"),
                Field::scalar("flags", 16, 4, "u32"),
            ],
            capture_eligible: true,
            provenance: vec![],
            replaces: vec![],
            pointers: described
                .then(|| PointerDescriptor {
                    field: "ptr".into(),
                    pointee_layout: "item".into(),
                    length_field: Some("len".into()),
                    length_expression: None,
                    direction: PointerDirection::InOut,
                })
                .into_iter()
                .collect(),
        };
        let mut pack = SchemaPack {
            schema: crate::ioctl_schema::SCHEMA_VERSION.into(),
            metadata: PackMetadata {
                name: "sample".into(),
                target_abi: "any".into(),
                selectors: Selectors::default(),
                source_revision: None,
                clang_invocation: vec![],
            },
            descriptors: vec![descriptor],
            layouts: vec![Layout {
                id: "item".into(),
                type_name: "u8[]".into(),
                size: 1,
                align: 1,
                fields: vec![Field::scalar("byte", 0, 1, "u8")],
            }],
            driver_evidence: vec![],
            content_hash: String::new(),
        };
        pack.seal().unwrap();
        SchemaRegistry::from_packs(vec![pack]).unwrap()
    }

    #[test]
    fn capture_stores_full_ioctl_and_declared_pointer_without_synthesis() {
        let root = std::env::temp_dir().join(format!("neutron-capture-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let capture = root.join("capture.ndjson");
        let mut flat = vec![0u8; 24];
        flat[0..8].copy_from_slice(&4u64.to_le_bytes());
        flat[8..16].copy_from_slice(&0x2000u64.to_le_bytes());
        flat[16..20].copy_from_slice(&7u32.to_le_bytes());
        let memory = FakeMemory(HashMap::from([
            ((42, 0x1000), flat.clone()),
            ((42, 0x2000), vec![1, 2, 3, 4]),
        ]));
        let writer = CaptureWriter::new_for_test(
            &capture,
            pointer_registry(true),
            CaptureIdentity {
                serial: Some("USB123".into()),
                fingerprint: Some("fp".into()),
                boot_id: Some("boot".into()),
                uid: 0,
                domain: None,
            },
            memory,
        )
        .unwrap();
        let event = SyscallEvent {
            pid: 42,
            uid: 10123,
            syscall_nr: 29,
            args: [7, 0xc018_7a01, 0x1000, 0, 0, 0],
            is_enter: 1,
            ..Default::default()
        };
        let line = writer
            .enrich_json(&event, Some("/dev/sample0"), r#"{"type":"syscall"}"#)
            .unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["harness_ref"]["status"], "complete");
        assert_eq!(value["harness_ref"]["length"], 24);
        assert_eq!(value["harness_ref"]["resources"][0]["length"], 4);
        assert_eq!(value["harness_ref"]["resources"][0]["pointer_offset"], 8);
        assert_eq!(value["harness_ref"]["mutable_regions"][0]["offset"], 0);
    }

    #[test]
    fn capture_blocks_schema_pointer_without_descriptor() {
        let root = std::env::temp_dir().join(format!("neutron-unresolved-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let capture = root.join("capture.ndjson");
        let mut flat = vec![0u8; 24];
        flat[8..16].copy_from_slice(&0x2000u64.to_le_bytes());
        let writer = CaptureWriter::new_for_test(
            &capture,
            pointer_registry(false),
            CaptureIdentity {
                serial: Some("USB123".into()),
                fingerprint: Some("fp".into()),
                boot_id: Some("boot".into()),
                uid: 0,
                domain: None,
            },
            FakeMemory(HashMap::from([((42, 0x1000), flat)])),
        )
        .unwrap();
        let event = SyscallEvent {
            pid: 42,
            uid: 10123,
            syscall_nr: 29,
            args: [7, 0xc018_7a01, 0x1000, 0, 0, 0],
            is_enter: 1,
            ..Default::default()
        };
        let line = writer.enrich_json(&event, None, "{}").unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["harness_ref"]["status"], "blocked");
        assert_eq!(value["harness_ref"]["resources"][0]["status"], "unresolved");
    }

    #[test]
    fn capture_reconstructs_binder_stream_parcel_offsets_and_buffer_fixup() {
        let root =
            std::env::temp_dir().join(format!("neutron-binder-capture-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let capture = root.join("capture.ndjson");

        let mut parcel = vec![0u8; 40];
        parcel[0..4].copy_from_slice(&0x7074_2a85u32.to_le_bytes());
        parcel[8..16].copy_from_slice(&0x4000u64.to_le_bytes());
        parcel[16..24].copy_from_slice(&4u64.to_le_bytes());
        let offsets = 0u64.to_le_bytes().to_vec();
        let command = (1u32 << 30) | (64 << 16) | ((b'c' as u32) << 8);
        let mut stream = command.to_le_bytes().to_vec();
        let mut transaction = vec![0u8; 64];
        transaction[32..40].copy_from_slice(&(parcel.len() as u64).to_le_bytes());
        transaction[40..48].copy_from_slice(&(offsets.len() as u64).to_le_bytes());
        transaction[48..56].copy_from_slice(&0x2000u64.to_le_bytes());
        transaction[56..64].copy_from_slice(&0x3000u64.to_le_bytes());
        stream.extend(transaction);
        let mut outer = vec![0u8; 48];
        outer[0..8].copy_from_slice(&(stream.len() as u64).to_le_bytes());
        outer[16..24].copy_from_slice(&0x1000u64.to_le_bytes());

        let writer = CaptureWriter::new_for_test(
            &capture,
            SchemaRegistry::default(),
            CaptureIdentity {
                serial: Some("USB123".into()),
                fingerprint: Some("fp".into()),
                boot_id: Some("boot".into()),
                uid: 0,
                domain: None,
            },
            FakeMemory(HashMap::from([
                ((42, 0x5000), outer),
                ((42, 0x1000), stream),
                ((42, 0x2000), parcel),
                ((42, 0x3000), offsets),
                ((42, 0x4000), vec![1, 2, 3, 4]),
            ])),
        )
        .unwrap();
        let event = SyscallEvent {
            pid: 42,
            uid: 10123,
            syscall_nr: 29,
            args: [7, 0xc030_6201, 0x5000, 0, 0, 0],
            is_enter: 1,
            ..Default::default()
        };
        let line = writer
            .enrich_json(&event, Some("/dev/binder"), "{}")
            .unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["harness_ref"]["status"], "complete");
        assert_eq!(
            value["harness_ref"]["transactions"][0],
            "binder.transaction.0"
        );
        let resources = value["harness_ref"]["resources"].as_array().unwrap();
        assert!(resources.iter().any(|resource| {
            resource["kind"] == "binder_buffer"
                && resource["container"] == "binder.transaction.0.parcel"
                && resource["pointer_offset"] == 8
        }));
    }

    #[test]
    fn adb_inventory_accepts_only_explicit_physical_usb_serial() {
        let inventory = parse_adb_devices(
            "List of devices attached\nUSB123 device usb:1-1 product:husky transport_id:1\n10.0.0.2:5555 device product:husky transport_id:2\nemulator-5554 device product:sdk transport_id:3\n",
        )
        .unwrap();
        validate_usb_device(&inventory, "USB123").unwrap();
        assert!(validate_usb_device(&inventory, "10.0.0.2:5555")
            .unwrap_err()
            .to_string()
            .contains("network"));
        assert!(validate_usb_device(&inventory, "emulator-5554")
            .unwrap_err()
            .to_string()
            .contains("emulator"));
        assert!(validate_usb_device(&inventory, "missing").is_err());
    }

    #[test]
    fn identity_check_rejects_every_drift_dimension() {
        let expected = RequiredIdentity {
            serial: "USB123".into(),
            fingerprint: "fp-a".into(),
            boot_id: "boot-a".into(),
            package: "com.example.app".into(),
            uid: 10123,
            domain: "u:r:untrusted_app:s0".into(),
        };
        validate_identity(&expected, &expected).unwrap();
        let mut actual = expected.clone();
        actual.domain = "u:r:platform_app:s0".into();
        assert!(validate_identity(&expected, &actual)
            .unwrap_err()
            .to_string()
            .contains("SELinux domain"));
    }

    #[test]
    fn argv_contract_rejects_shell_shaped_empty_or_nul_programs() {
        validate_argv(&["/bin/true".into(), "literal;not-shell".into()]).unwrap();
        assert!(validate_argv(&[]).is_err());
        assert!(validate_argv(&["bad\0program".into()]).is_err());
        let output = run_argv(
            &["/bin/echo".into(), "literal;not-shell".into()],
            None,
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "literal;not-shell\n"
        );
    }

    #[test]
    fn adb_runner_uses_remote_argv_without_a_shell() {
        let execute = vec![
            "{artifact}/replay".to_string(),
            "{artifact}/input.bin".to_string(),
        ];
        let remote = "/data/local/tmp/neutron-harness-123-abcdef";
        let argv = adb_execute_argv(
            &execute,
            "USB123",
            "com.example.app",
            remote,
            Duration::from_secs(30),
        );
        assert_eq!(
            argv,
            [
                "adb",
                "-s",
                "USB123",
                "shell",
                "timeout",
                "30s",
                "/data/local/tmp/neutron-harness-123-abcdef/replay",
                "/data/local/tmp/neutron-harness-123-abcdef/input.bin",
            ]
        );
        assert!(!argv.windows(2).any(|args| args == ["sh", "-c"]));
    }

    #[test]
    fn adb_staging_accepts_only_regular_replay_assets() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "neutron-adb-stage-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        for name in ["replay", "input.bin", "metadata.json", "resources.json"] {
            fs::write(root.join(name), name).unwrap();
        }
        let resources = ResourceCatalog {
            schema: HARNESS_SCHEMA.into(),
            device_paths: Vec::new(),
            binder_services: Vec::new(),
            resources: Vec::new(),
            object_adapters: Vec::new(),
            unresolved: Vec::new(),
        };

        let files = adb_stage_files(&root, &resources).unwrap();
        let remote: Vec<_> = files
            .iter()
            .map(|asset| asset.remote_path.as_str())
            .collect();
        assert_eq!(
            remote,
            ["input.bin", "metadata.json", "replay", "resources.json"]
        );

        fs::remove_file(root.join("replay")).unwrap();
        symlink(root.join("input.bin"), root.join("replay")).unwrap();
        assert!(adb_stage_files(&root, &resources)
            .unwrap_err()
            .to_string()
            .contains("regular file"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_staging_path_is_bounded_and_content_addressed() {
        let path = remote_artifact_path(&"ab".repeat(32)).unwrap();
        assert!(path.starts_with("/data/local/tmp/neutron-harness-"));
        assert!(path.ends_with("-abababababababab"));
        assert!(path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-')));
        assert!(remote_artifact_path("../unsafe").is_err());
    }

    #[test]
    fn binder_object_registry_covers_standard_reconstruction_types() {
        assert_eq!(binder_object_name(0x7362_2a85), Some("binder"));
        assert_eq!(binder_object_name(0x7762_2a85), Some("weak_binder"));
        assert_eq!(binder_object_name(0x7368_2a85), Some("handle"));
        assert_eq!(binder_object_name(0x7768_2a85), Some("weak_handle"));
        assert_eq!(binder_object_name(0x6664_2a85), Some("fd"));
        assert_eq!(binder_object_name(0x6664_6185), Some("fd_array"));
        assert_eq!(binder_object_name(0x7074_2a85), Some("buffer"));
        assert_eq!(binder_object_name(0), None);
    }

    #[test]
    fn deterministic_ddmin_removes_only_existing_elements() {
        let original = vec![1, 2, 3, 4, 5, 6];
        let first = ddmin(original.clone(), 64, |candidate| {
            Ok(candidate.contains(&2) && candidate.contains(&5))
        })
        .unwrap();
        let second = ddmin(original, 64, |candidate| {
            Ok(candidate.contains(&2) && candidate.contains(&5))
        })
        .unwrap();
        assert_eq!(first.value, vec![2, 5]);
        assert_eq!(first.value, second.value);
        assert_eq!(first.runs, second.runs);
    }

    #[test]
    fn minimization_candidates_only_delete_zero_or_shorten() {
        let input = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let variants = byte_candidates(
            &input,
            &[MutableRegion {
                offset: 2,
                length: 2,
                kind: "field".into(),
            }],
        );
        assert!(variants.iter().all(|candidate| {
            candidate.len() <= input.len()
                && candidate
                    .iter()
                    .enumerate()
                    .all(|(index, byte)| *byte == 0 || *byte == input[index])
        }));
    }
}
