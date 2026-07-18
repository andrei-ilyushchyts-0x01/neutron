//! `neutron doctor` — preflight environment checks.
//!
//! Verifies the prerequisites that have to hold for neutron to attach and run
//! on the current device:
//!
//!   - Sufficient privilege (euid 0 or `CAP_BPF` + `CAP_SYS_ADMIN`)
//!   - Kernel ≥ 6.1 with BTF, tracefs, bpffs
//!   - BPF ringbuf support (kernel 5.8+)
//!   - `raw_syscalls/sys_{enter,exit}` tracepoints
//!   - Real `BPF_MAP_TYPE_STACK_TRACE` creation capability (warn if missing)
//!   - `binder/binder_transaction` tracepoint (warn if missing)
//!   - `/proc/kallsyms` readable (kptr_restrict)
//!   - SELinux mode (warn if enforcing for an unprivileged caller)
//!   - Architecture is `aarch64`
//!
//! Each check produces a `CheckResult` with a status and a one-line reason.
//! `run()` prints the table and returns `0` when every check is `Pass` or
//! `Warn`, and `1` if any check is `Fail`.

use std::fs;
use std::io;
use std::path::Path;

use aya::maps::{Array, PerCpuArray, RingBuf};
use aya::programs::trace_point::TracePointLinkId;
use aya::programs::TracePoint;
use aya::{Ebpf, EbpfLoader};
use clap::Args;
use serde::Serialize;

use crate::bpf_abi::{
    inspect_bpf_object, read_bpf_object_path, validate_bpf_object_path, BpfAbiRequirements,
    BpfObjectError, BpfObjectIdentity,
};

#[derive(Args, Debug, Clone, Eq, PartialEq)]
pub struct DoctorArgs {
    /// Emit the versioned `neutron.doctor/v1` report to stdout.
    #[arg(long)]
    pub json: bool,

    /// Load the selected object and prove syscall attach, event delivery,
    /// per-CPU health reads, and cleanup with a bounded sentinel syscall.
    #[arg(long)]
    pub smoke: bool,

    /// BPF object to validate and, with `--smoke`, temporarily load.
    #[arg(long, default_value = "/data/local/share/neutron/neutron.bpf.elf")]
    pub object: String,
}

impl Default for DoctorArgs {
    fn default() -> Self {
        Self {
            json: false,
            smoke: false,
            object: "/data/local/share/neutron/neutron.bpf.elf".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

impl Status {
    fn glyph(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub name: &'static str,
    pub status: Status,
    pub reason: String,
}

impl CheckResult {
    pub fn pass(name: &'static str, reason: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Pass,
            reason: reason.into(),
        }
    }
    pub fn warn(name: &'static str, reason: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Warn,
            reason: reason.into(),
        }
    }
    pub fn fail(name: &'static str, reason: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Fail,
            reason: reason.into(),
        }
    }
}

// ── Tracepoint format compatibility ─────────────────────────────────────────

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TracepointKind {
    RawSysEnter,
    RawSysExit,
    BinderTransaction,
    BinderTransactionReceived,
    SchedProcessExit,
}

impl TracepointKind {
    pub const ALL: [Self; 5] = [
        Self::RawSysEnter,
        Self::RawSysExit,
        Self::BinderTransaction,
        Self::BinderTransactionReceived,
        Self::SchedProcessExit,
    ];

    pub const fn category(self) -> &'static str {
        match self {
            Self::RawSysEnter | Self::RawSysExit => "raw_syscalls",
            Self::BinderTransaction | Self::BinderTransactionReceived => "binder",
            Self::SchedProcessExit => "sched",
        }
    }

    pub const fn event(self) -> &'static str {
        match self {
            Self::RawSysEnter => "sys_enter",
            Self::RawSysExit => "sys_exit",
            Self::BinderTransaction => "binder_transaction",
            Self::BinderTransactionReceived => "binder_transaction_received",
            Self::SchedProcessExit => "sched_process_exit",
        }
    }

    const fn required_for_default_capture(self) -> bool {
        matches!(
            self,
            Self::RawSysEnter | Self::RawSysExit | Self::SchedProcessExit
        )
    }

    fn expected_fields(self) -> &'static [ExpectedTracepointField] {
        use neutron_common as common;

        const SYS_ENTER: &[ExpectedTracepointField] = &[
            ExpectedTracepointField::new(
                "id",
                "long",
                common::TRACEPOINT_SYS_ENTER_ID_OFFSET,
                8,
                true,
            ),
            ExpectedTracepointField::new(
                "args[6]",
                "unsigned long",
                common::TRACEPOINT_SYS_ENTER_ARGS_OFFSET,
                48,
                false,
            ),
        ];
        const SYS_EXIT: &[ExpectedTracepointField] = &[
            ExpectedTracepointField::new(
                "id",
                "long",
                common::TRACEPOINT_SYS_EXIT_ID_OFFSET,
                8,
                true,
            ),
            ExpectedTracepointField::new(
                "ret",
                "long",
                common::TRACEPOINT_SYS_EXIT_RET_OFFSET,
                8,
                true,
            ),
        ];
        const BINDER_TRANSACTION: &[ExpectedTracepointField] = &[
            ExpectedTracepointField::new(
                "debug_id",
                "int",
                common::TRACEPOINT_BINDER_DEBUG_ID_OFFSET,
                4,
                true,
            ),
            ExpectedTracepointField::new(
                "target_node",
                "int",
                common::TRACEPOINT_BINDER_TARGET_NODE_OFFSET,
                4,
                true,
            ),
            ExpectedTracepointField::new(
                "to_proc",
                "int",
                common::TRACEPOINT_BINDER_TO_PROC_OFFSET,
                4,
                true,
            ),
            ExpectedTracepointField::new(
                "to_thread",
                "int",
                common::TRACEPOINT_BINDER_TO_THREAD_OFFSET,
                4,
                true,
            ),
            ExpectedTracepointField::new(
                "reply",
                "int",
                common::TRACEPOINT_BINDER_REPLY_OFFSET,
                4,
                true,
            ),
            ExpectedTracepointField::new(
                "code",
                "unsigned int",
                common::TRACEPOINT_BINDER_CODE_OFFSET,
                4,
                false,
            ),
            ExpectedTracepointField::new(
                "flags",
                "unsigned int",
                common::TRACEPOINT_BINDER_FLAGS_OFFSET,
                4,
                false,
            ),
        ];
        const BINDER_RECEIVED: &[ExpectedTracepointField] = &[ExpectedTracepointField::new(
            "debug_id",
            "int",
            common::TRACEPOINT_BINDER_RECEIVED_DEBUG_ID_OFFSET,
            4,
            true,
        )];
        const SCHED_EXIT: &[ExpectedTracepointField] = &[
            ExpectedTracepointField::new(
                "comm[16]",
                "char",
                common::TRACEPOINT_SCHED_EXIT_COMM_OFFSET,
                16,
                false,
            ),
            ExpectedTracepointField::new(
                "pid",
                "pid_t",
                common::TRACEPOINT_SCHED_EXIT_PID_OFFSET,
                4,
                true,
            ),
        ];

        match self {
            Self::RawSysEnter => SYS_ENTER,
            Self::RawSysExit => SYS_EXIT,
            Self::BinderTransaction => BINDER_TRANSACTION,
            Self::BinderTransactionReceived => BINDER_RECEIVED,
            Self::SchedProcessExit => SCHED_EXIT,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ExpectedTracepointField {
    name: &'static str,
    field_type: &'static str,
    offset: usize,
    size: usize,
    signed: bool,
}

impl ExpectedTracepointField {
    const fn new(
        name: &'static str,
        field_type: &'static str,
        offset: usize,
        size: usize,
        signed: bool,
    ) -> Self {
        Self {
            name,
            field_type,
            offset,
            size,
            signed,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TracepointCompatibility {
    Compatible,
    Unsupported,
    Unknown,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct TracepointField {
    pub name: String,
    pub field_type: String,
    pub offset: usize,
    pub size: usize,
    pub signed: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct TracepointFormatReport {
    pub kind: TracepointKind,
    pub compatibility: TracepointCompatibility,
    pub normalized_sha256: String,
    pub fields: Vec<TracepointField>,
    pub mismatches: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TracepointFormatError {
    NoFields,
    InvalidFieldLine(String),
    InvalidNumber { field: String, value: String },
    InvalidSignedness { field: String, value: String },
}

impl std::fmt::Display for TracepointFormatError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoFields => formatter.write_str("tracepoint format contains no fields"),
            Self::InvalidFieldLine(line) => {
                write!(formatter, "invalid tracepoint field line: {line}")
            }
            Self::InvalidNumber { field, value } => {
                write!(formatter, "invalid numeric {field} value: {value}")
            }
            Self::InvalidSignedness { field, value } => {
                write!(formatter, "invalid signed value for {field}: {value}")
            }
        }
    }
}

impl std::error::Error for TracepointFormatError {}

/// Parse a tracefs `format` file, hash its normalized field layout, and
/// compare every field consumed by the corresponding BPF program.
pub fn validate_tracepoint_format(
    kind: TracepointKind,
    input: &str,
) -> Result<TracepointFormatReport, TracepointFormatError> {
    let fields = parse_tracepoint_fields(input)?;
    let mut normalized = String::new();
    for field in &fields {
        use std::fmt::Write as _;
        let _ = writeln!(
            normalized,
            "{}|{}|{}|{}|{}",
            field.name, field.field_type, field.offset, field.size, field.signed as u8
        );
    }

    let mut mismatches = Vec::new();
    for expected in kind.expected_fields() {
        let matches: Vec<&TracepointField> = fields
            .iter()
            .filter(|field| field.name == expected.name)
            .collect();
        if matches.is_empty() {
            mismatches.push(format!("missing field {}", expected.name));
            continue;
        }
        if matches.len() > 1 {
            mismatches.push(format!("duplicate field {}", expected.name));
            continue;
        }
        let actual = matches[0];
        if actual.field_type != expected.field_type {
            mismatches.push(format!(
                "{} type: expected {}, found {}",
                expected.name, expected.field_type, actual.field_type
            ));
        }
        if actual.offset != expected.offset {
            mismatches.push(format!(
                "{} offset: expected {}, found {}",
                expected.name, expected.offset, actual.offset
            ));
        }
        if actual.size != expected.size {
            mismatches.push(format!(
                "{} size: expected {}, found {}",
                expected.name, expected.size, actual.size
            ));
        }
        if actual.signed != expected.signed {
            mismatches.push(format!(
                "{} signed: expected {}, found {}",
                expected.name, expected.signed as u8, actual.signed as u8
            ));
        }
    }

    Ok(TracepointFormatReport {
        kind,
        compatibility: if mismatches.is_empty() {
            TracepointCompatibility::Compatible
        } else {
            TracepointCompatibility::Unsupported
        },
        normalized_sha256: crate::bpf_abi::sha256_hex(normalized.as_bytes()),
        fields,
        mismatches,
    })
}

fn parse_tracepoint_fields(input: &str) -> Result<Vec<TracepointField>, TracepointFormatError> {
    let mut fields = Vec::new();
    for raw_line in input.lines() {
        let line = raw_line.trim();
        let Some(body) = line.strip_prefix("field:") else {
            continue;
        };
        let mut parts = body.split(';');
        let declaration = parts
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| TracepointFormatError::InvalidFieldLine(line.to_string()))?;
        let mut declaration_parts: Vec<&str> = declaration.split_whitespace().collect();
        let name = declaration_parts
            .pop()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| TracepointFormatError::InvalidFieldLine(line.to_string()))?;
        if declaration_parts.is_empty() {
            return Err(TracepointFormatError::InvalidFieldLine(line.to_string()));
        }
        let field_type = declaration_parts.join(" ");
        let mut offset = None;
        let mut size = None;
        let mut signed = None;
        for part in parts {
            let part = part.trim();
            if let Some(value) = part.strip_prefix("offset:") {
                offset = Some(parse_tracepoint_number(name, "offset", value)?);
            } else if let Some(value) = part.strip_prefix("size:") {
                size = Some(parse_tracepoint_number(name, "size", value)?);
            } else if let Some(value) = part.strip_prefix("signed:") {
                signed = Some(match value.trim() {
                    "0" => false,
                    "1" => true,
                    other => {
                        return Err(TracepointFormatError::InvalidSignedness {
                            field: name.to_string(),
                            value: other.to_string(),
                        })
                    }
                });
            }
        }
        let (Some(offset), Some(size), Some(signed)) = (offset, size, signed) else {
            return Err(TracepointFormatError::InvalidFieldLine(line.to_string()));
        };
        fields.push(TracepointField {
            name: name.to_string(),
            field_type,
            offset,
            size,
            signed,
        });
    }
    if fields.is_empty() {
        return Err(TracepointFormatError::NoFields);
    }
    Ok(fields)
}

fn parse_tracepoint_number(
    field: &str,
    label: &str,
    value: &str,
) -> Result<usize, TracepointFormatError> {
    value
        .trim()
        .parse()
        .map_err(|_| TracepointFormatError::InvalidNumber {
            field: format!("{field}.{label}"),
            value: value.trim().to_string(),
        })
}

/// Filesystem reader injection point for tests. The real implementation
/// reads `/proc`, `/sys`, etc. directly.
pub trait Env {
    fn euid(&self) -> u32;
    fn read_to_string(&self, path: &str) -> std::io::Result<String>;
    fn path_exists(&self, path: &str) -> bool;
    fn arch(&self) -> &str;
    fn create_stack_trace_map(&self) -> io::Result<()>;
}

pub struct RealEnv;

impl Env for RealEnv {
    fn euid(&self) -> u32 {
        // SAFETY: geteuid is always safe; returns the calling thread's euid.
        unsafe { libc::geteuid() }
    }
    fn read_to_string(&self, path: &str) -> std::io::Result<String> {
        fs::read_to_string(path)
    }
    fn path_exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }
    fn arch(&self) -> &str {
        std::env::consts::ARCH
    }
    fn create_stack_trace_map(&self) -> io::Result<()> {
        try_create_stack_trace_map()
    }
}

// ── Individual checks ────────────────────────────────────────────────────────

const CAP_SYS_ADMIN: u8 = 21;
const CAP_BPF: u8 = 39;
const BPF_MAP_CREATE: libc::c_uint = 0;
const BPF_MAP_TYPE_STACK_TRACE: u32 = 7;
const STACK_TRACE_KEY_SIZE: u32 = 4;
const STACK_TRACE_VALUE_SIZE: u32 = 127 * 8;

#[repr(C)]
#[derive(Default)]
struct BpfMapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
    map_ifindex: u32,
    btf_fd: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    btf_vmlinux_value_type_id: u32,
    map_extra: u64,
}

fn try_create_stack_trace_map() -> io::Result<()> {
    let attr = BpfMapCreateAttr {
        map_type: BPF_MAP_TYPE_STACK_TRACE,
        key_size: STACK_TRACE_KEY_SIZE,
        value_size: STACK_TRACE_VALUE_SIZE,
        max_entries: 1,
        ..BpfMapCreateAttr::default()
    };
    // SAFETY: `attr` points to a stable, zero-initialized BPF_MAP_CREATE
    // attribute block for the duration of the syscall. The fd, when returned,
    // is closed immediately below.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_CREATE,
            &attr as *const BpfMapCreateAttr,
            std::mem::size_of::<BpfMapCreateAttr>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was returned by the kernel and is owned by this process.
    unsafe {
        libc::close(fd as libc::c_int);
    }
    Ok(())
}

fn parse_cap_eff(status: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        let rest = line.strip_prefix("CapEff:")?;
        u64::from_str_radix(rest.trim(), 16).ok()
    })
}

fn has_cap(mask: u64, bit: u8) -> bool {
    (mask & (1u64 << bit)) != 0
}

pub fn check_privilege<E: Env>(env: &E) -> CheckResult {
    let euid = env.euid();
    let cap_eff = env
        .read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| parse_cap_eff(&s));

    if let Some(caps) = cap_eff {
        let has_bpf = has_cap(caps, CAP_BPF);
        let has_sys_admin = has_cap(caps, CAP_SYS_ADMIN);
        if has_bpf && has_sys_admin {
            return CheckResult::pass(
                "privilege",
                format!("effective caps include CAP_BPF + CAP_SYS_ADMIN (euid={euid})"),
            );
        }
        if euid == 0 {
            return CheckResult::fail(
                "privilege",
                format!(
                    "euid=0 but CapEff={caps:#x} lacks required BPF capabilities \
                     (need CAP_BPF + CAP_SYS_ADMIN); BPF load will fail"
                ),
            );
        }
        return CheckResult::fail(
            "privilege",
            format!("non-root (euid={euid}) and CapEff={caps:#x} lacks CAP_BPF + CAP_SYS_ADMIN"),
        );
    }

    if euid == 0 {
        return CheckResult::warn(
            "privilege",
            "running as root (euid=0) but cannot read CapEff from /proc/self/status",
        );
    }
    CheckResult::warn(
        "privilege",
        format!(
            "non-root (euid={euid}) and cannot read CapEff; need CAP_BPF + CAP_SYS_ADMIN \
             — run via `adb shell su -c …` on a rooted device"
        ),
    )
}

pub fn check_arch<E: Env>(env: &E) -> CheckResult {
    let arch = env.arch();
    if arch == "aarch64" {
        CheckResult::pass("arch", "aarch64")
    } else {
        CheckResult::fail(
            "arch",
            format!("expected aarch64, got {arch} — neutron's syscall table is aarch64-specific"),
        )
    }
}

pub fn check_kernel_version<E: Env>(env: &E) -> CheckResult {
    let v = match env.read_to_string("/proc/version") {
        Ok(s) => s,
        Err(e) => {
            return CheckResult::fail("kernel version", format!("cannot read /proc/version: {e}"))
        }
    };
    // Lines look like "Linux version 6.1.145-android14-11-... ".
    let prefix = "Linux version ";
    let trimmed = v.trim_start_matches(prefix);
    let token = trimmed.split_whitespace().next().unwrap_or("");
    let mut nums = token.split('.').take(2);
    let major: u32 = nums.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = nums
        .next()
        .and_then(|s| {
            // strip trailing non-numeric suffix in patterns like "1-android14"
            let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
            s[..end].parse().ok()
        })
        .unwrap_or(0);
    if major > 6 || (major == 6 && minor >= 1) {
        CheckResult::pass("kernel version", format!("{major}.{minor} (≥ 6.1)"))
    } else if major >= 5 {
        CheckResult::warn(
            "kernel version",
            format!("{major}.{minor} — neutron targets 6.1+; tracepoint layouts may differ"),
        )
    } else {
        CheckResult::fail(
            "kernel version",
            format!("{major}.{minor} — too old; required ≥ 6.1"),
        )
    }
}

pub fn check_btf<E: Env>(env: &E) -> CheckResult {
    let path = "/sys/kernel/btf/vmlinux";
    if env.path_exists(path) {
        CheckResult::pass("BTF", "/sys/kernel/btf/vmlinux present")
    } else {
        CheckResult::fail(
            "BTF",
            format!("{path} missing — kernel must be built with CONFIG_DEBUG_INFO_BTF=y"),
        )
    }
}

pub fn check_tracefs<E: Env>(env: &E) -> CheckResult {
    if env.path_exists("/sys/kernel/tracing") {
        CheckResult::pass("tracefs", "/sys/kernel/tracing mounted")
    } else if env.path_exists("/sys/kernel/debug/tracing") {
        CheckResult::warn(
            "tracefs",
            "only /sys/kernel/debug/tracing exists; modern path /sys/kernel/tracing missing",
        )
    } else {
        CheckResult::fail(
            "tracefs",
            "no tracefs mount found at /sys/kernel/tracing or /sys/kernel/debug/tracing",
        )
    }
}

pub fn check_bpffs<E: Env>(env: &E) -> CheckResult {
    if env.path_exists("/sys/fs/bpf") {
        CheckResult::pass("bpffs", "/sys/fs/bpf present")
    } else {
        CheckResult::warn(
            "bpffs",
            "/sys/fs/bpf missing — pinning won't work but transient programs still load",
        )
    }
}

pub fn check_raw_syscalls<E: Env>(env: &E) -> CheckResult {
    let enter = "/sys/kernel/tracing/events/raw_syscalls/sys_enter";
    let exit = "/sys/kernel/tracing/events/raw_syscalls/sys_exit";
    let have_enter = env.path_exists(enter);
    let have_exit = env.path_exists(exit);
    match (have_enter, have_exit) {
        (true, true) => CheckResult::pass(
            "raw_syscalls tracepoints",
            "both sys_enter and sys_exit present",
        ),
        (true, false) => CheckResult::fail(
            "raw_syscalls tracepoints",
            "sys_enter present but sys_exit missing — neutron needs both",
        ),
        (false, true) => CheckResult::fail(
            "raw_syscalls tracepoints",
            "sys_exit present but sys_enter missing — neutron needs both",
        ),
        (false, false) => CheckResult::fail(
            "raw_syscalls tracepoints",
            "neither tracepoint present — kernel CONFIG_FTRACE_SYSCALLS may be off",
        ),
    }
}

fn errno_label(err: &io::Error) -> &'static str {
    match err.raw_os_error() {
        Some(libc::EPERM) => "EPERM",
        Some(libc::EACCES) => "EACCES",
        Some(libc::EINVAL) => "EINVAL",
        Some(libc::ENOSYS) => "ENOSYS",
        _ if err.kind() == io::ErrorKind::PermissionDenied => "EPERM",
        _ => "error",
    }
}

fn stack_trace_map_create_check_from_result(result: io::Result<()>) -> CheckResult {
    match result {
        Ok(()) => CheckResult::pass(
            "STACK_TRACES map",
            "BPF_MAP_TYPE_STACK_TRACE create succeeded",
        ),
        Err(err) => CheckResult::warn(
            "STACK_TRACES map",
            format!(
                "STACK_TRACES map create failed ({}: {err}); default stackless captures \
                 still work, but --stacks requires neutron-stacks.bpf.elf and a domain \
                 allowed to create BPF_MAP_TYPE_STACK_TRACE",
                errno_label(&err)
            ),
        ),
    }
}

pub fn check_stack_trace_map_create<E: Env>(env: &E) -> CheckResult {
    stack_trace_map_create_check_from_result(env.create_stack_trace_map())
}

pub fn check_binder_tracepoint<E: Env>(env: &E) -> CheckResult {
    let transaction = "/sys/kernel/tracing/events/binder/binder_transaction";
    let received = "/sys/kernel/tracing/events/binder/binder_transaction_received";
    match (env.path_exists(transaction), env.path_exists(received)) {
        (true, true) => CheckResult::pass(
            "binder tracepoints",
            "binder_transaction and binder_transaction_received present",
        ),
        (true, false) => CheckResult::warn(
            "binder tracepoints",
            "binder_transaction present but binder_transaction_received missing — \
             Binder causality is incomplete",
        ),
        (false, true) => CheckResult::warn(
            "binder tracepoints",
            "binder_transaction_received present but binder_transaction missing — \
             `--binder` mode will fail",
        ),
        (false, false) => CheckResult::warn(
            "binder tracepoints",
            "both Binder tracepoints are missing — `--binder` mode will fail; \
             syscall capture can still work",
        ),
    }
}

pub fn check_kallsyms<E: Env>(env: &E) -> CheckResult {
    match env.read_to_string("/proc/kallsyms") {
        Err(e) => CheckResult::fail("kallsyms", format!("cannot read /proc/kallsyms: {e}")),
        Ok(s) => {
            // Heuristic: if every line shows 0x0 addresses, kptr_restrict is on.
            let masked = s.lines().take(5).all(|l| {
                let addr = l.split_whitespace().next().unwrap_or("");
                addr.chars().all(|c| c == '0')
            });
            if masked {
                CheckResult::warn(
                    "kallsyms",
                    "addresses zeroed (kptr_restrict ≥ 1) — kernel stack frames stay hex",
                )
            } else {
                CheckResult::pass(
                    "kallsyms",
                    "/proc/kallsyms readable with non-zero addresses",
                )
            }
        }
    }
}

pub fn check_selinux<E: Env>(env: &E) -> CheckResult {
    let p = "/sys/fs/selinux/enforce";
    if !env.path_exists(p) {
        return CheckResult::pass("SELinux", "no SELinux interface present");
    }
    match env.read_to_string(p) {
        Ok(s) if s.trim() == "0" => CheckResult::pass("SELinux", "permissive"),
        Ok(s) if s.trim() == "1" => CheckResult::warn(
            "SELinux",
            "enforcing — neutron load needs the calling domain to permit `bpf` capability",
        ),
        Ok(other) => CheckResult::warn("SELinux", format!("unexpected value: {}", other.trim())),
        Err(e) => CheckResult::warn("SELinux", format!("cannot read {p}: {e}")),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InstalledTracepointReport {
    pub kind: TracepointKind,
    pub path: String,
    pub compatibility: TracepointCompatibility,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<TracepointField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mismatches: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

const TRACEFS_ROOTS: [&str; 2] = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];

/// Read and validate every tracepoint layout consumed by the shipped object.
pub fn inspect_installed_tracepoint_layouts<E: Env>(env: &E) -> Vec<InstalledTracepointReport> {
    TracepointKind::ALL
        .into_iter()
        .map(|kind| inspect_installed_tracepoint_layout(env, kind))
        .collect()
}

/// Fail closed before a live capture loads BPF when any offset-based layout
/// used by the selected mode is unavailable or incompatible.
pub fn validate_live_capture_layouts(
    binder: bool,
) -> Result<Vec<InstalledTracepointReport>, String> {
    let env = RealEnv;
    let mut kinds = vec![
        TracepointKind::RawSysEnter,
        TracepointKind::RawSysExit,
        TracepointKind::SchedProcessExit,
    ];
    if binder {
        kinds.extend([
            TracepointKind::BinderTransaction,
            TracepointKind::BinderTransactionReceived,
        ]);
    }
    let reports: Vec<_> = kinds
        .into_iter()
        .map(|kind| inspect_installed_tracepoint_layout(&env, kind))
        .collect();
    let failures: Vec<_> = reports
        .iter()
        .filter(|report| report.compatibility != TracepointCompatibility::Compatible)
        .map(|report| {
            let reason = report
                .error
                .as_deref()
                .map(str::to_owned)
                .unwrap_or_else(|| report.mismatches.join(", "));
            format!(
                "{}/{}={:?}: {reason}",
                report.kind.category(),
                report.kind.event(),
                report.compatibility
            )
        })
        .collect();
    if failures.is_empty() {
        Ok(reports)
    } else {
        Err(format!(
            "live capture tracepoint layout preflight failed: {}",
            failures.join("; ")
        ))
    }
}

fn inspect_installed_tracepoint_layout<E: Env>(
    env: &E,
    kind: TracepointKind,
) -> InstalledTracepointReport {
    let mut attempted = Vec::new();
    for root in TRACEFS_ROOTS {
        let path = format!("{root}/events/{}/{}/format", kind.category(), kind.event());
        attempted.push(path.clone());
        let input = match env.read_to_string(&path) {
            Ok(input) => input,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return InstalledTracepointReport {
                    kind,
                    path,
                    compatibility: TracepointCompatibility::Unknown,
                    normalized_sha256: None,
                    fields: Vec::new(),
                    mismatches: Vec::new(),
                    error: Some(format!("cannot read tracepoint format: {error}")),
                }
            }
        };
        return match validate_tracepoint_format(kind, &input) {
            Ok(report) => InstalledTracepointReport {
                kind,
                path,
                compatibility: report.compatibility,
                normalized_sha256: Some(report.normalized_sha256),
                fields: report.fields,
                mismatches: report.mismatches,
                error: None,
            },
            Err(error) => InstalledTracepointReport {
                kind,
                path,
                compatibility: TracepointCompatibility::Unknown,
                normalized_sha256: None,
                fields: Vec::new(),
                mismatches: Vec::new(),
                error: Some(error.to_string()),
            },
        };
    }

    InstalledTracepointReport {
        kind,
        path: attempted.join(" or "),
        compatibility: TracepointCompatibility::Unknown,
        normalized_sha256: None,
        fields: Vec::new(),
        mismatches: Vec::new(),
        error: Some("tracepoint format file not found".to_string()),
    }
}

fn tracepoint_layout_check(reports: &[InstalledTracepointReport]) -> CheckResult {
    let mut required_failures = Vec::new();
    let mut optional_failures = Vec::new();
    for report in reports {
        if report.compatibility == TracepointCompatibility::Compatible {
            continue;
        }
        let detail = format!(
            "{}/{}={:?}",
            report.kind.category(),
            report.kind.event(),
            report.compatibility
        );
        if report.kind.required_for_default_capture() {
            required_failures.push(detail);
        } else {
            optional_failures.push(detail);
        }
    }
    if !required_failures.is_empty() {
        CheckResult::fail(
            "tracepoint layouts",
            format!(
                "required layout validation failed: {}",
                required_failures.join(", ")
            ),
        )
    } else if !optional_failures.is_empty() {
        CheckResult::warn(
            "tracepoint layouts",
            format!(
                "default syscall capture compatible; optional layouts unavailable: {}",
                optional_failures.join(", ")
            ),
        )
    } else {
        CheckResult::pass(
            "tracepoint layouts",
            "all syscall, Binder, and process-exit field layouts are compatible",
        )
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ObjectCompatibility {
    Compatible,
    Unsupported,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorObjectReport {
    pub path: String,
    pub compatibility: ObjectCompatibility,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<BpfObjectIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl DoctorObjectReport {
    fn validate(path: &str) -> Self {
        let requirements = BpfAbiRequirements::default_capture()
            .with_features(neutron_common::BPF_FEATURE_PROCESS_EXIT);
        match validate_bpf_object_path(path, &requirements) {
            Ok(validated) => Self {
                path: path.to_string(),
                compatibility: ObjectCompatibility::Compatible,
                identity: Some(validated.identity),
                error: None,
            },
            Err(error) => {
                let compatibility = if matches!(&error, BpfObjectError::Io { .. }) {
                    ObjectCompatibility::Unknown
                } else {
                    ObjectCompatibility::Unsupported
                };
                Self {
                    path: path.to_string(),
                    compatibility,
                    identity: None,
                    error: Some(error.to_string()),
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SmokeReport {
    pub attempted: bool,
    pub tracepoint_layout_validated: bool,
    pub object_abi_validated: bool,
    pub bpf_load: bool,
    pub syscall_attach: bool,
    pub ringbuf_open: bool,
    pub sentinel_syscall: bool,
    pub exact_event: bool,
    pub event_size: u32,
    pub percpu_health_read: bool,
    pub health_totals: Vec<u64>,
    pub cleanup: bool,
    pub passed: bool,
    pub temporary_side_effects: Vec<&'static str>,
    pub pinned_resources_created: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<BpfObjectIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Default for SmokeReport {
    fn default() -> Self {
        Self {
            attempted: true,
            tracepoint_layout_validated: false,
            object_abi_validated: false,
            bpf_load: false,
            syscall_attach: false,
            ringbuf_open: false,
            sentinel_syscall: false,
            exact_event: false,
            event_size: core::mem::size_of::<neutron_common::SyscallEvent>() as u32,
            percpu_health_read: false,
            health_totals: Vec::new(),
            cleanup: false,
            passed: false,
            temporary_side_effects: vec![
                "un-pinned BPF maps",
                "raw_syscalls/sys_enter link",
                "raw_syscalls/sys_exit link",
            ],
            pinned_resources_created: false,
            object: None,
            error: None,
        }
    }
}

/// Prove the real stackless syscall capture path with one `getpid` sentinel.
/// ABI and tracepoint layouts are validated before any kernel BPF state is
/// created. Successful cleanup explicitly detaches both temporary links; Aya
/// drop guards remain the fallback on every error path.
pub fn run_syscall_smoke(object_path: &str) -> SmokeReport {
    let mut report = SmokeReport::default();
    let outcome = run_syscall_smoke_inner(object_path, &mut report);
    match outcome {
        Ok(()) => report.passed = true,
        Err(error) => report.error = Some(error),
    }
    report
}

fn run_syscall_smoke_inner(object_path: &str, report: &mut SmokeReport) -> Result<(), String> {
    let env = RealEnv;
    for kind in [TracepointKind::RawSysEnter, TracepointKind::RawSysExit] {
        let layout = inspect_installed_tracepoint_layout(&env, kind);
        if layout.compatibility != TracepointCompatibility::Compatible {
            return Err(format!(
                "{} layout is {:?}: {}",
                kind.event(),
                layout.compatibility,
                layout.error.unwrap_or_else(|| layout.mismatches.join(", "))
            ));
        }
    }
    report.tracepoint_layout_validated = true;

    let object_bytes = read_bpf_object_path(object_path)
        .map_err(|error| format!("cannot read BPF object {object_path}: {error}"))?;
    let requirements = BpfAbiRequirements::default_capture()
        .with_features(neutron_common::BPF_FEATURE_PROCESS_EXIT);
    let validated = inspect_bpf_object(&object_bytes, &requirements)
        .map_err(|error| format!("pre-attach ABI validation failed: {error}"))?;
    report.object_abi_validated = true;
    report.object = Some(validated.identity);
    let expected_pid = std::process::id();
    let expected_tid = unsafe { libc::syscall(libc::SYS_gettid) };
    if expected_tid < 0 {
        return Err(format!(
            "gettid before smoke attach failed: {}",
            io::Error::last_os_error()
        ));
    }
    let expected_tid = expected_tid as u32;

    let mut bpf = EbpfLoader::new()
        .load(&object_bytes)
        .map_err(|error| format!("BPF load failed: {error}"))?;
    report.bpf_load = true;
    configure_smoke_filter(&mut bpf, expected_pid)?;

    let enter_link =
        attach_smoke_tracepoint(&mut bpf, "trace_sys_enter", "raw_syscalls", "sys_enter")?;
    let exit_link =
        attach_smoke_tracepoint(&mut bpf, "trace_sys_exit", "raw_syscalls", "sys_exit")?;
    report.syscall_attach = true;

    let events_map = bpf
        .take_map("EVENTS")
        .ok_or_else(|| "EVENTS map missing from BPF object".to_string())?;
    let mut ring = RingBuf::try_from(events_map)
        .map_err(|error| format!("EVENTS is not a ring buffer: {error}"))?;
    report.ringbuf_open = true;

    while ring.next().is_some() {}
    let sentinel_result = unsafe { libc::syscall(libc::SYS_getpid) };
    if sentinel_result < 0 {
        return Err(format!(
            "sentinel getpid failed: {}",
            io::Error::last_os_error()
        ));
    }
    report.sentinel_syscall = true;

    let mut saw_enter = false;
    let mut saw_exit = false;
    let mut drained = 0usize;
    while let Some(item) = ring.next() {
        drained += 1;
        if drained > 4096 {
            return Err("smoke ring drain exceeded 4096 records".to_string());
        }
        let event = decode_exact_smoke_event(&item)?;
        let pid = packed_event_pid(&event);
        let tid = packed_event_tid(&event);
        let syscall_nr = packed_event_syscall_nr(&event);
        if pid != expected_pid || tid != expected_tid || syscall_nr != libc::SYS_getpid as i32 {
            continue;
        }
        let is_enter = packed_event_is_enter(&event);
        if is_enter == 1 {
            saw_enter = true;
        } else if is_enter == 0 && packed_event_ret(&event) == sentinel_result as i64 {
            saw_exit = true;
        }
    }
    if !(saw_enter && saw_exit) {
        return Err(format!(
            "sentinel event pair incomplete: enter={saw_enter} exit={saw_exit}"
        ));
    }
    report.exact_event = true;

    report.health_totals = read_percpu_health(&bpf)?;
    report.percpu_health_read = true;
    let submitted = report
        .health_totals
        .get(neutron_common::COUNTER_EVENTS_SUBMITTED as usize)
        .copied()
        .unwrap_or(0);
    if submitted < 2 {
        return Err(format!(
            "per-CPU health reported only {submitted} submitted events; expected at least 2"
        ));
    }

    let exit_detached = detach_smoke_tracepoint(&mut bpf, "trace_sys_exit", exit_link);
    let enter_detached = detach_smoke_tracepoint(&mut bpf, "trace_sys_enter", enter_link);
    match (exit_detached, enter_detached) {
        (Ok(()), Ok(())) => report.cleanup = true,
        (exit, enter) => {
            return Err(format!(
                "smoke cleanup failed: sys_exit={exit:?} sys_enter={enter:?}"
            ))
        }
    }
    Ok(())
}

fn configure_smoke_filter(bpf: &mut Ebpf, pid: u32) -> Result<(), String> {
    let map = bpf
        .map_mut("FILTER_MAP")
        .ok_or_else(|| "FILTER_MAP missing from BPF object".to_string())?;
    let mut filter: Array<_, u32> =
        Array::try_from(map).map_err(|error| format!("FILTER_MAP has wrong type: {error}"))?;
    filter
        .set(neutron_common::FILTER_KEY_PID, pid, 0)
        .map_err(|error| format!("setting smoke PID filter failed: {error}"))?;
    filter
        .set(neutron_common::FILTER_KEY_ACTIVE, 0, 0)
        .map_err(|error| format!("disabling smoke syscall filter failed: {error}"))?;
    Ok(())
}

fn attach_smoke_tracepoint(
    bpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    event: &str,
) -> Result<TracePointLinkId, String> {
    let program: &mut TracePoint = bpf
        .program_mut(program_name)
        .ok_or_else(|| format!("program {program_name} missing from BPF object"))?
        .try_into()
        .map_err(|error| format!("program {program_name} is not a tracepoint: {error}"))?;
    program
        .load()
        .map_err(|error| format!("loading {program_name} failed: {error}"))?;
    program
        .attach(category, event)
        .map_err(|error| format!("attaching {program_name} failed: {error}"))
}

fn detach_smoke_tracepoint(
    bpf: &mut Ebpf,
    program_name: &str,
    link: TracePointLinkId,
) -> Result<(), String> {
    let program: &mut TracePoint = bpf
        .program_mut(program_name)
        .ok_or_else(|| format!("program {program_name} disappeared before cleanup"))?
        .try_into()
        .map_err(|error| format!("program {program_name} changed type: {error}"))?;
    program
        .detach(link)
        .map_err(|error| format!("detaching {program_name} failed: {error}"))
}

fn decode_exact_smoke_event(bytes: &[u8]) -> Result<neutron_common::SyscallEvent, String> {
    let expected = core::mem::size_of::<neutron_common::SyscallEvent>();
    if bytes.len() != expected {
        return Err(format!(
            "ring event size mismatch after ABI validation: expected {expected}, found {}",
            bytes.len()
        ));
    }
    // SAFETY: the ABI handshake proved the exact packed event size; all event
    // fields are integers/byte arrays for which every bit pattern is valid.
    Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) })
}

fn packed_event_pid(event: &neutron_common::SyscallEvent) -> u32 {
    unsafe { std::ptr::addr_of!(event.pid).read_unaligned() }
}

fn packed_event_tid(event: &neutron_common::SyscallEvent) -> u32 {
    unsafe { std::ptr::addr_of!(event.tgid).read_unaligned() }
}

fn packed_event_syscall_nr(event: &neutron_common::SyscallEvent) -> i32 {
    unsafe { std::ptr::addr_of!(event.syscall_nr).read_unaligned() }
}

fn packed_event_is_enter(event: &neutron_common::SyscallEvent) -> u8 {
    unsafe { std::ptr::addr_of!(event.is_enter).read_unaligned() }
}

fn packed_event_ret(event: &neutron_common::SyscallEvent) -> i64 {
    unsafe { std::ptr::addr_of!(event.ret).read_unaligned() }
}

fn read_percpu_health(bpf: &Ebpf) -> Result<Vec<u64>, String> {
    let map = bpf
        .map("COUNTERS")
        .ok_or_else(|| "COUNTERS map missing from BPF object".to_string())?;
    let counters: PerCpuArray<_, u64> = PerCpuArray::try_from(map)
        .map_err(|error| format!("COUNTERS is not a PerCpuArray<u64>: {error}"))?;
    let mut totals = Vec::with_capacity(neutron_common::COUNTER_SLOT_COUNT as usize);
    for index in 0..neutron_common::COUNTER_SLOT_COUNT {
        let values = counters
            .get(&index, 0)
            .map_err(|error| format!("COUNTERS[{index}] read failed: {error}"))?;
        let total = values.iter().copied().fold(0u64, u64::saturating_add);
        totals.push(total);
    }
    Ok(totals)
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub schema: &'static str,
    pub tool: crate::build_info::SelfInfo,
    pub compatible: bool,
    pub checks: Vec<CheckResult>,
    pub tracepoint_layouts: Vec<InstalledTracepointReport>,
    pub object: DoctorObjectReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smoke: Option<SmokeReport>,
}

/// Run all checks in display order.
pub fn run_all<E: Env>(env: &E) -> Vec<CheckResult> {
    vec![
        check_privilege(env),
        check_arch(env),
        check_kernel_version(env),
        check_btf(env),
        check_tracefs(env),
        check_bpffs(env),
        check_raw_syscalls(env),
        check_stack_trace_map_create(env),
        check_binder_tracepoint(env),
        check_kallsyms(env),
        check_selinux(env),
    ]
}

/// Print results table to stderr; return process exit code.
pub fn print_and_exit_code(results: &[CheckResult]) -> i32 {
    eprintln!("neutron doctor — preflight checks");
    eprintln!();
    let name_w = results.iter().map(|r| r.name.len()).max().unwrap_or(0);
    for r in results {
        eprintln!(
            "  [{}] {:<width$}  {}",
            r.status.glyph(),
            r.name,
            r.reason,
            width = name_w
        );
    }
    eprintln!();
    let n_fail = results.iter().filter(|r| r.status == Status::Fail).count();
    let n_warn = results.iter().filter(|r| r.status == Status::Warn).count();
    if n_fail > 0 {
        eprintln!("doctor: {n_fail} FAIL, {n_warn} WARN — neutron will not run as-is");
        1
    } else if n_warn > 0 {
        eprintln!("doctor: {n_warn} WARN — neutron should run but check the warnings above");
        0
    } else {
        eprintln!("doctor: all checks passed");
        0
    }
}

/// Convenience entry point used by `main` when the `doctor` subcommand is
/// invoked. Runs all checks against the real environment, prints the table,
/// and returns the suggested process exit code.
pub fn run() -> i32 {
    run_with_args(&DoctorArgs::default())
}

/// Execute the evidence-grade doctor contract selected by the CLI.
pub fn run_with_args(args: &DoctorArgs) -> i32 {
    let env = RealEnv;
    let mut checks = run_all(&env);
    let tracepoint_layouts = inspect_installed_tracepoint_layouts(&env);
    checks.push(tracepoint_layout_check(&tracepoint_layouts));

    let object = DoctorObjectReport::validate(&args.object);
    match object.compatibility {
        ObjectCompatibility::Compatible => checks.push(CheckResult::pass(
            "BPF ABI",
            object
                .identity
                .as_ref()
                .map(|identity| {
                    format!(
                        "ABI {}.{} event_size={} object_sha256={}",
                        identity.abi_major,
                        identity.abi_minor,
                        identity.syscall_event_size,
                        identity.object_sha256
                    )
                })
                .unwrap_or_else(|| "compatible".to_string()),
        )),
        ObjectCompatibility::Unsupported | ObjectCompatibility::Unknown => {
            checks.push(CheckResult::fail(
                "BPF ABI",
                object
                    .error
                    .clone()
                    .unwrap_or_else(|| "object compatibility is unknown".to_string()),
            ));
        }
    }

    let smoke = args.smoke.then(|| run_syscall_smoke(&args.object));
    if let Some(smoke) = &smoke {
        if smoke.passed {
            checks.push(CheckResult::pass(
                "BPF smoke",
                "load, attach, exact sentinel event, per-CPU health read, and detach passed",
            ));
        } else {
            checks.push(CheckResult::fail(
                "BPF smoke",
                smoke
                    .error
                    .clone()
                    .unwrap_or_else(|| "smoke failed without a reason".to_string()),
            ));
        }
    }

    let compatible = checks.iter().all(|check| check.status != Status::Fail);
    let report = DoctorReport {
        schema: "neutron.doctor/v1",
        tool: crate::build_info::self_info(),
        compatible,
        checks,
        tracepoint_layouts,
        object,
        smoke,
    };

    if args.json {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("doctor: failed to serialize JSON report: {error}");
                return 1;
            }
        }
    } else {
        let _ = print_and_exit_code(&report.checks);
        eprintln!("tracepoint layout hashes:");
        for layout in &report.tracepoint_layouts {
            let hash = layout.normalized_sha256.as_deref().unwrap_or("unavailable");
            eprintln!(
                "  {}/{}: {:?} sha256={hash}",
                layout.kind.category(),
                layout.kind.event(),
                layout.compatibility
            );
        }
        if let Some(identity) = &report.object.identity {
            eprintln!(
                "BPF object: sha256={} ABI={}.{} event_size={} feature_bits={:#x}",
                identity.object_sha256,
                identity.abi_major,
                identity.abi_minor,
                identity.syscall_event_size,
                identity.feature_bits
            );
        }
        if let Some(smoke) = &report.smoke {
            eprintln!(
                "BPF smoke: {} cleanup={} per_cpu_health={}",
                if smoke.passed { "PASS" } else { "FAIL" },
                smoke.cleanup,
                smoke.percpu_health_read
            );
        }
    }

    if compatible {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    struct FakeEnv {
        euid: u32,
        files: RefCell<HashMap<String, String>>,
        existing: RefCell<Vec<String>>,
        arch: String,
    }

    impl FakeEnv {
        fn new() -> Self {
            Self {
                euid: 0,
                files: RefCell::new(HashMap::new()),
                existing: RefCell::new(vec![]),
                arch: "aarch64".to_string(),
            }
        }
        fn with_file(self, path: &str, contents: &str) -> Self {
            self.files.borrow_mut().insert(path.into(), contents.into());
            self.existing.borrow_mut().push(path.into());
            self
        }
        fn with_existing(self, path: &str) -> Self {
            self.existing.borrow_mut().push(path.into());
            self
        }
        fn with_arch(mut self, arch: &str) -> Self {
            self.arch = arch.into();
            self
        }
        fn with_euid(mut self, euid: u32) -> Self {
            self.euid = euid;
            self
        }
    }

    impl Env for FakeEnv {
        fn euid(&self) -> u32 {
            self.euid
        }
        fn read_to_string(&self, path: &str) -> std::io::Result<String> {
            self.files
                .borrow()
                .get(path)
                .cloned()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        }
        fn path_exists(&self, path: &str) -> bool {
            self.existing.borrow().iter().any(|p| p == path)
        }
        fn arch(&self) -> &str {
            &self.arch
        }
        fn create_stack_trace_map(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn privilege_pass_for_root_with_bpf_caps() {
        let env = FakeEnv::new().with_file("/proc/self/status", "CapEff:\t000001ffffffffff\n");
        assert_eq!(check_privilege(&env).status, Status::Pass);
    }

    #[test]
    fn privilege_warn_for_root_when_cap_eff_unreadable() {
        let env = FakeEnv::new();
        assert_eq!(check_privilege(&env).status, Status::Warn);
    }

    #[test]
    fn privilege_fails_for_root_without_effective_caps() {
        let env = FakeEnv::new().with_file("/proc/self/status", "CapEff:\t0000000000000000\n");
        let result = check_privilege(&env);
        assert_eq!(result.status, Status::Fail);
        assert!(result.reason.contains("CapEff=0x0"));
    }

    #[test]
    fn privilege_warn_for_unprivileged() {
        let env = FakeEnv::new().with_euid(2000);
        assert_eq!(check_privilege(&env).status, Status::Warn);
    }

    #[test]
    fn arch_fails_for_x86() {
        let env = FakeEnv::new().with_arch("x86_64");
        assert_eq!(check_arch(&env).status, Status::Fail);
    }

    #[test]
    fn kernel_version_pass_for_pixel_8_pro() {
        let env = FakeEnv::new().with_file(
            "/proc/version",
            "Linux version 6.1.145-android14-11 (build@host) ...",
        );
        assert_eq!(check_kernel_version(&env).status, Status::Pass);
    }

    #[test]
    fn kernel_version_fail_for_4_14() {
        let env = FakeEnv::new().with_file("/proc/version", "Linux version 4.14.180 (legacy)");
        assert_eq!(check_kernel_version(&env).status, Status::Fail);
    }

    #[test]
    fn kernel_version_warn_for_5_15() {
        let env = FakeEnv::new().with_file("/proc/version", "Linux version 5.15.0 ...");
        assert_eq!(check_kernel_version(&env).status, Status::Warn);
    }

    #[test]
    fn btf_pass_when_present() {
        let env = FakeEnv::new().with_existing("/sys/kernel/btf/vmlinux");
        assert_eq!(check_btf(&env).status, Status::Pass);
    }

    #[test]
    fn btf_fail_when_missing() {
        let env = FakeEnv::new();
        assert_eq!(check_btf(&env).status, Status::Fail);
    }

    #[test]
    fn raw_syscalls_pass_when_both_present() {
        let env = FakeEnv::new()
            .with_existing("/sys/kernel/tracing/events/raw_syscalls/sys_enter")
            .with_existing("/sys/kernel/tracing/events/raw_syscalls/sys_exit");
        assert_eq!(check_raw_syscalls(&env).status, Status::Pass);
    }

    #[test]
    fn raw_syscalls_fail_when_either_missing() {
        let env = FakeEnv::new().with_existing("/sys/kernel/tracing/events/raw_syscalls/sys_enter");
        assert_eq!(check_raw_syscalls(&env).status, Status::Fail);
    }

    #[test]
    fn binder_warn_when_missing() {
        let env = FakeEnv::new();
        assert_eq!(check_binder_tracepoint(&env).status, Status::Warn);
    }

    #[test]
    fn kallsyms_warn_when_addresses_masked() {
        let env = FakeEnv::new().with_file(
            "/proc/kallsyms",
            "0000000000000000 T do_syscall_64\n0000000000000000 T do_anything\n",
        );
        assert_eq!(check_kallsyms(&env).status, Status::Warn);
    }

    #[test]
    fn kallsyms_pass_when_real_addresses() {
        let env = FakeEnv::new().with_file("/proc/kallsyms", "ffffffc01023f000 T do_syscall_64\n");
        assert_eq!(check_kallsyms(&env).status, Status::Pass);
    }

    #[test]
    fn selinux_pass_when_permissive() {
        let env = FakeEnv::new().with_file("/sys/fs/selinux/enforce", "0");
        assert_eq!(check_selinux(&env).status, Status::Pass);
    }

    #[test]
    fn selinux_warn_when_enforcing() {
        let env = FakeEnv::new().with_file("/sys/fs/selinux/enforce", "1");
        assert_eq!(check_selinux(&env).status, Status::Warn);
    }

    #[test]
    fn print_and_exit_returns_one_on_any_fail() {
        let results = vec![
            CheckResult::pass("a", "ok"),
            CheckResult::fail("b", "broken"),
        ];
        assert_eq!(print_and_exit_code(&results), 1);
    }

    #[test]
    fn print_and_exit_returns_zero_on_only_warnings() {
        let results = vec![CheckResult::pass("a", "ok"), CheckResult::warn("b", "soft")];
        assert_eq!(print_and_exit_code(&results), 0);
    }

    #[test]
    fn stack_trace_map_create_warns_on_permission_denied() {
        let result = stack_trace_map_create_check_from_result(Err(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        )));

        assert_eq!(result.status, Status::Warn);
        assert!(result.reason.contains("STACK_TRACES"));
        assert!(result.reason.contains("EPERM"));
    }
}
