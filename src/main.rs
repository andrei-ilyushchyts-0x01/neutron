//! neutron — Android kernel-boundary and cross-service causal tracer for
//! authorized security assessment.
//!
//! This binary loads the BPF programs in `neutron-ebpf` via Aya, attaches them
//! to raw_syscalls/{sys_enter,sys_exit} (and optionally binder/binder_transaction),
//! polls per-CPU perf buffers, and emits either raw events or rule-engine
//! findings.
//!
//! Targets: kernel 6.1+ (Pixel 8 Pro). The legacy raw-`bpf()`-syscall loader
//! that targeted kernel 4.14 lives in git history before this commit.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{self, IsTerminal, Read, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use anyhow::{bail, Context, Result};
use aya::maps::{Array, HashMap as AyaHashMap, MapError, PerCpuArray, RingBuf, StackTraceMap};
use aya::programs::{KProbe, Program, TracePoint};
use aya::{Ebpf, EbpfLoader, VerifierLogLevel};
use clap::Parser;
use sha2::{Digest, Sha256};

use neutron::aidl::AidlCatalog;
use neutron::android;
use neutron::binder_services::{BinderCatalog, BinderMethodMap, BinderServiceMap};
use neutron::bpf_abi::{
    inspect_bpf_object, read_bpf_object_path, BpfAbiRequirements, BpfObjectIdentity,
    BPF_FEATURE_BINDER_TRACE, BPF_FEATURE_PROCESS_EXIT, BPF_FEATURE_STACKS,
};
use neutron::capture::{CaptureMode, ContextRing, DEFAULT_MAX_EVENTS};
#[cfg(test)]
use neutron::causal::selinux_denial_span_id;
use neutron::causal::{
    binder_span_id, enrich_json, expired_followed_pids, monotonic_timestamp_ns, parse_follow_ttl,
    process_context_bytes, process_context_from_bytes, process_exit_span_id, root_process_span_id,
    syscall_span_id, CausalMetadata, CausalRelation, CausalWire, ControlServer, FollowCandidate,
    FollowDecision, FollowPolicy, MarkRequest, PendingMark, ScenarioInfo, ScenarioState,
};
use neutron::cli::{
    AidlCommand, Args, Cli, Command, CommandMaturity, HarnessCommand, IoctlCommand,
};
use neutron::decode::{compute_latency_us, format_comm, format_data_field, resolve_path_from_fd};
use neutron::doctor;
use neutron::fdgraph::poller::{self as poller, PollerConfig, RealProcReader, ScopePolicy};
use neutron::fdgraph::FdGraph;
use neutron::format::{
    format_binder_call_json_with_attribution, format_event_json_full, format_event_text_with_stack,
    format_fd_snapshot_json, format_process_exit_json, FdHint,
};
use neutron::health::{
    format_capture_health_json_with_metadata, format_summary_with, CaptureContentIdentity,
    CaptureEnrichmentScope, CaptureFilterScope, CaptureFindingScope, CaptureHealth,
    CaptureInstrumentationScope, CaptureMetadata, CaptureObservationScope, CaptureOutputScope,
    CapturePackScope, CaptureProducerScope, CaptureSamplingScope, CaptureScope, CaptureSourceScope,
    KprobePackScope, UserspaceHealth,
};
use neutron::matcher::{self, MatchSpec, SyscallEventLens};
use neutron::predicate;
use neutron::rules::{build_rule_engine_from_yaml, emit_findings_with};
use neutron::sampler::SamplerChain;
use neutron::selinux::SelinuxLogcatReader;
use neutron::sources::binder_tracker::{BinderTracker, BinderTrackerStats};
use neutron::sources::logcat::{LogcatReader, RealLogcatReader};
use neutron::sources::lookback::RingBufferStore;
use neutron::sources::tombstone::{RealTombstoneWatcher, TombstoneWatcher};
use neutron::sources::ProcessExitEvent;
use neutron::symbolize::{is_kernel_addr, KernelResolver, ProcSymbolizer};
use neutron::SyscallEvent;
use neutron_common::{
    ExitSource, ProcessTraceContext, TraceReason, FILTER_KEY_ACTIVE, FILTER_KEY_ARG_U32_OFF,
    FILTER_KEY_CAUSAL_MODE, FILTER_KEY_FOLLOW_BINDER, FILTER_KEY_IOCTL_DIR,
    FILTER_KEY_LATENCY_MIN_US, FILTER_KEY_MATCH_BITS, FILTER_KEY_MAX_DEPTH, FILTER_KEY_PID,
    FILTER_KEY_RET_CLASS, FILTER_KEY_ROOT_UID, FILTER_KEY_ROOT_UID_ACTIVE,
    FILTER_KEY_ROOT_UID_ADMIT, FILTER_KEY_STATE_EMIT_REQUIRED, MATCH_BIT_ARG_U32,
    MATCH_BIT_IOCTL_CMD, MATCH_BIT_IOCTL_DIR, MATCH_BIT_IOCTL_NR, MATCH_BIT_IOCTL_TYPE,
    MATCH_BIT_LATENCY, MATCH_BIT_RET, MATCH_BIT_UID, PROCESS_TRACE_CONTEXT_SIZE,
    SYSCALL_NR_BINDER_RECEIVED, SYSCALL_NR_PROCESS_EXIT,
};

// ── Constants ────────────────────────────────────────────────────────────────

const SECURITY_PROFILE: &str = "security";
const STACKFUL_BPF_OBJECT: &str = "neutron-stacks.bpf.elf";

const SECURITY_EXCLUDE_COMM: &[&str] = &[
    "RenderThread",
    "FrameMetricsAgg",
    "PerfStat",
    "Profile Saver",
    "Jit thread pool",
];

const SYSCALL_CLONE: i32 = 220;
const CLONE_THREAD: u64 = 0x0001_0000;
const SYSCALL_OPENAT: i32 = 56;
const SYSCALL_CLOSE: i32 = 57;
const SYSCALL_MMAP: i32 = 222;
const SYSCALL_MPROTECT: i32 = 226;
const SYSCALL_MUNMAP: i32 = 215;
const SYSCALL_EXECVE: i32 = 221;
const SYSCALL_EXECVEAT: i32 = 281;

/// Maximum time `poll(2)` blocks waiting for the ring buffer to become
/// readable. Short enough to keep Ctrl-C latency bounded, long enough that
/// idle CPUs don't burn the cache.
const POLL_TIMEOUT_MS: i32 = 100;

// ── Signal handling ──────────────────────────────────────────────────────────

static RUNNING_PTR: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

extern "C" fn shutdown_signal_handler(_sig: libc::c_int) {
    let ptr = RUNNING_PTR.load(Ordering::SeqCst);
    if ptr != 0 {
        // SAFETY: pointer was set from a leaked Arc<AtomicBool> in
        // `install_shutdown_signals`.
        let running = unsafe { &*(ptr as *const Arc<AtomicBool>) };
        running.store(false, Ordering::SeqCst);
    }
}

/// Install graceful-shutdown signal handlers. Both SIGINT and SIGTERM
/// flip the `running` flag so the event loop can drain in-flight
/// findings, print the capture summary, and emit the `capture_health`
/// JSON line. Without the SIGTERM handler the kernel default kills the
/// process abruptly — which is what `timeout 3 neutron …` does by
/// default and why the 2026-05-06 device test reported a missing
/// health line (only `timeout -s INT 3` worked).
fn install_shutdown_signals(running: Arc<AtomicBool>) {
    let leaked = Box::into_raw(Box::new(running)) as usize;
    RUNNING_PTR.store(leaked, Ordering::SeqCst);
    unsafe {
        let h = shutdown_signal_handler as *const () as libc::sighandler_t;
        libc::signal(libc::SIGINT, h);
        libc::signal(libc::SIGTERM, h);
    }
}

fn ring_poll_failure(
    result: libc::c_int,
    revents: libc::c_short,
    errno: Option<i32>,
) -> Option<String> {
    if result < 0 {
        if errno == Some(libc::EINTR) {
            return None;
        }
        return Some(format!(
            "ring buffer poll failed{}",
            errno.map_or_else(String::new, |value| format!(" (errno {value})"))
        ));
    }
    let terminal = revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL);
    (terminal != 0).then(|| format!("ring buffer poll returned terminal revents=0x{terminal:x}"))
}

const RECENT_EXIT_CAUSAL_TTL_NS: u64 = 5_000_000_000;

#[derive(Clone, Debug)]
struct RecentExitCausal {
    metadata: CausalMetadata,
    exit_ts_ns: u64,
    comm: String,
}

fn correlate_recent_exit(
    recent: &mut HashMap<u32, RecentExitCausal>,
    event: &ProcessExitEvent,
) -> Option<CausalMetadata> {
    recent.retain(|_, value| {
        event.ts_ns >= value.exit_ts_ns
            && event.ts_ns.saturating_sub(value.exit_ts_ns) <= RECENT_EXIT_CAUSAL_TTL_NS
    });
    let candidate = recent.get(&event.pid)?;
    if candidate.comm.is_empty() || event.comm.is_empty() || candidate.comm != event.comm {
        return None;
    }
    let mut metadata = candidate.metadata.clone();
    metadata.relation = CausalRelation::Inferred;
    Some(metadata)
}

// ── Banner ───────────────────────────────────────────────────────────────────

fn print_banner() {
    eprintln!(
        "neutron {} — evidence-grade Android boundary mapping and causal tracing",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!("authorized security testing only — see SECURITY.md");
    eprintln!();
}

fn trimmed_nonempty(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn read_boot_id() -> Result<String> {
    const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
    const MAX_BOOT_ID_BYTES: u64 = 128;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(BOOT_ID_PATH)
        .with_context(|| format!("opening required boot identity at {BOOT_ID_PATH}"))?;
    let mut bytes = Vec::with_capacity(MAX_BOOT_ID_BYTES as usize);
    file.take(MAX_BOOT_ID_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading required boot identity from {BOOT_ID_PATH}"))?;
    if bytes.len() as u64 > MAX_BOOT_ID_BYTES {
        bail!("required boot identity exceeds {MAX_BOOT_ID_BYTES} bytes");
    }
    let value = std::str::from_utf8(&bytes).context("required boot identity is not UTF-8")?;
    let value = value.trim();
    let valid = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'),
        });
    if !valid {
        bail!("required boot identity is not a canonical lowercase UUID");
    }
    Ok(value.to_string())
}

fn read_android_property(name: &str) -> Option<String> {
    let output = android::run_platform_command("getprop", &[name]).ok()?;
    if !output.status.success() {
        return None;
    }
    let output = String::from_utf8(output.stdout).ok()?;
    trimmed_nonempty(&output)
}

fn required_android_property(name: &str) -> Result<String> {
    let value = read_android_property(name)
        .with_context(|| format!("reading required Android property {name}"))?;
    if value.len() > 4096 || value.chars().any(char::is_control) {
        bail!("Android property {name} is not a bounded printable value");
    }
    Ok(value)
}

fn read_kernel_release() -> Result<String> {
    const PATH: &str = "/proc/sys/kernel/osrelease";
    const MAX_BYTES: u64 = 4096;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(PATH)
        .with_context(|| format!("opening required kernel identity at {PATH}"))?;
    let mut bytes = Vec::with_capacity(256);
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading required kernel identity from {PATH}"))?;
    if bytes.len() as u64 > MAX_BYTES {
        bail!("kernel identity exceeds {MAX_BYTES} bytes");
    }
    let value = std::str::from_utf8(&bytes)
        .context("kernel identity is not UTF-8")?
        .trim();
    if value.is_empty() || value.chars().any(char::is_control) {
        bail!("kernel identity is empty or contains control characters");
    }
    Ok(value.to_string())
}

fn live_device_identity(
    boot_id: String,
    serial: &str,
) -> Result<neutron::run_manifest::DeviceIdentity> {
    let api = required_android_property("ro.build.version.sdk")?
        .parse::<u32>()
        .context("Android SDK property is not an unsigned integer")?;
    if api == 0 {
        bail!("Android SDK property must be non-zero");
    }
    Ok(neutron::run_manifest::DeviceIdentity {
        serial_hash: Some(neutron::run_manifest::serial_hash(serial)?),
        model: Some(required_android_property("ro.product.model")?),
        product: Some(required_android_property("ro.product.device")?),
        build_id: Some(required_android_property("ro.build.id")?),
        fingerprint: Some(required_android_property("ro.build.fingerprint")?),
        api: Some(api),
        spl: Some(required_android_property(
            "ro.build.version.security_patch",
        )?),
        kernel: Some(read_kernel_release()?),
        boot_id: Some(boot_id),
    })
}

fn observer_privilege_after_preflight() -> String {
    if unsafe { libc::geteuid() } == 0 {
        "root".into()
    } else {
        "cap_bpf+cap_sys_admin".into()
    }
}

// ── FD-poller config helpers (sprint-1 PR 3) ────────────────────────────────

/// Parse `--fdgraph-interval` (`1s`, `500ms`, `off`). `Ok(None)` means
/// the poller should not be spawned at all.
fn parse_fdgraph_interval(s: &str) -> Result<Option<Duration>> {
    let trimmed = s.trim();
    if trimmed.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    if let Some(rest) = trimmed.strip_suffix("ms") {
        let n: u64 = rest
            .parse()
            .with_context(|| format!("invalid --fdgraph-interval ms value: {trimmed}"))?;
        return Ok(Some(Duration::from_millis(n)));
    }
    if let Some(rest) = trimmed.strip_suffix('s') {
        let n: u64 = rest
            .parse()
            .with_context(|| format!("invalid --fdgraph-interval s value: {trimmed}"))?;
        return Ok(Some(Duration::from_secs(n)));
    }
    bail!("invalid --fdgraph-interval (expected '1s', '500ms', or 'off'): {trimmed}");
}

// ── Profile handling ─────────────────────────────────────────────────────────

fn apply_profile(args: &mut Args) -> Result<()> {
    let Some(profile) = args.profile.as_deref() else {
        return Ok(());
    };
    match profile {
        SECURITY_PROFILE => {
            if args.match_expr.is_none() {
                add_match_syscalls_if_empty(
                    args,
                    &[
                        29, 48, 56, 78, 79, 129, 167, 198, 200, 203, 206, 207, 220, 221, 222, 226,
                        281,
                    ],
                );
            }
            if args.exclude_comm.is_empty() {
                args.exclude_comm = SECURITY_EXCLUDE_COMM
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect();
            }
        }
        "kernel-lpe" => {
            add_match_syscalls_if_empty(
                args,
                &[
                    29, 56, 57, 23, 24, 98, 198, 199, 211, 212, 20, 21, 22, 220, 222, 226, 280,
                ],
            );
        }
        "driver-harness" => {
            add_match_syscalls_if_empty(args, &[29, 56, 57, 23, 24, 73, 20, 21, 22, 222, 226]);
        }
        _ => {
            bail!(
                "unknown profile '{profile}' (available: {SECURITY_PROFILE}, kernel-lpe, driver-harness)"
            );
        }
    }
    Ok(())
}

fn add_match_syscalls_if_empty(args: &mut Args, nrs: &[i32]) {
    if args.match_syscall.is_empty() {
        args.match_syscall = nrs.iter().map(|nr| nr.to_string()).collect();
    }
}

#[derive(Debug, Clone, Default)]
struct DriverPackConfig {
    names: Vec<String>,
    refresh_cmds: BTreeSet<u32>,
    refresh_types: BTreeSet<u32>,
}

fn normalize_pack_name(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

fn push_unique(v: &mut Vec<String>, value: impl Into<String>) {
    let value = value.into();
    if !v.iter().any(|x| x == &value) {
        v.push(value);
    }
}

fn push_unique_syscalls(args: &mut Args, nrs: &[i32]) {
    let mut existing = BTreeSet::new();
    for raw in &args.match_syscall {
        if let Ok(parsed) = matcher::parse_syscall_list(raw) {
            for nr in parsed {
                existing.insert(nr);
            }
        }
    }
    for nr in nrs {
        if existing.insert(*nr) {
            args.match_syscall.push(nr.to_string());
        }
    }
}

fn push_unique_ioctl_types(args: &mut Args, types: &[u32]) {
    let mut existing = BTreeSet::new();
    for raw in &args.match_ioctl_type {
        if let Ok(parsed) = matcher::parse_u32_list(raw) {
            for ty in parsed {
                existing.insert(ty);
            }
        }
    }
    for ty in types {
        if existing.insert(*ty) {
            args.match_ioctl_type.push(format!("{ty:#x}"));
        }
    }
}

#[cfg(test)]
fn apply_driver_packs(args: &mut Args) -> Result<DriverPackConfig> {
    let allow_defaults = !has_capture_predicate_flags(args);
    apply_driver_packs_with_defaults(args, allow_defaults)
}

fn apply_driver_packs_with_defaults(
    args: &mut Args,
    allow_defaults: bool,
) -> Result<DriverPackConfig> {
    let mut cfg = DriverPackConfig::default();
    for raw in args.driver_pack.clone() {
        let pack = normalize_pack_name(&raw);
        match pack.as_str() {
            "binder" => {
                args.binder = true;
                cfg.refresh_cmds.insert(0xC030_6201);
                cfg.refresh_types
                    .insert(neutron_common::IOCTL_TYPE_BINDER_OR_DMA_BUF);
                if allow_defaults {
                    push_unique_syscalls(args, &[29]);
                    push_unique_ioctl_types(args, &[neutron_common::IOCTL_TYPE_BINDER_OR_DMA_BUF]);
                    push_unique(&mut args.match_fd, "/dev/binder*");
                    push_unique(&mut args.match_fd, "/dev/vndbinder*");
                }
            }
            "kgsl" => {
                cfg.refresh_types.insert(neutron_common::IOCTL_TYPE_KGSL);
                if allow_defaults {
                    push_unique_syscalls(args, &[29, 56, 57, 23, 24, 73, 20, 21, 22, 222, 226]);
                    push_unique_ioctl_types(args, &[neutron_common::IOCTL_TYPE_KGSL]);
                    push_unique(&mut args.match_fd, "/dev/kgsl*");
                }
            }
            "mali" => {
                cfg.refresh_types
                    .insert(neutron_common::IOCTL_TYPE_MALI_KBASE);
                if allow_defaults {
                    push_unique_syscalls(args, &[29, 56, 57, 23, 24, 73, 20, 21, 22, 222, 226]);
                    push_unique_ioctl_types(args, &[neutron_common::IOCTL_TYPE_MALI_KBASE]);
                    push_unique(&mut args.match_fd, "/dev/mali*");
                }
            }
            "alsa" => {
                let types = [
                    neutron_common::IOCTL_TYPE_ALSA_PCM,
                    neutron_common::IOCTL_TYPE_ALSA_CTL,
                    neutron_common::IOCTL_TYPE_ALSA_HWDEP,
                    neutron_common::IOCTL_TYPE_ALSA_RAWMIDI,
                    neutron_common::IOCTL_TYPE_ALSA_TIMER,
                    neutron_common::IOCTL_TYPE_ALSA_SEQ,
                    neutron_common::IOCTL_TYPE_ALSA_COMPRESS,
                ];
                cfg.refresh_types.extend(types);
                if allow_defaults {
                    push_unique_syscalls(args, &[29, 56, 57, 23, 24, 73, 20, 21, 22]);
                    push_unique_ioctl_types(args, &types);
                    push_unique(&mut args.match_fd, "/dev/snd/*");
                }
            }
            "unix-socket" => {
                if allow_defaults {
                    push_unique_syscalls(args, &[57, 23, 24, 98, 198, 199, 202, 211, 212, 20, 21, 22]);
                }
            }
            "media-hal" => {
                let types = [
                    neutron_common::IOCTL_TYPE_LWIS,
                    neutron_common::IOCTL_TYPE_GXP_UPSTREAM,
                    neutron_common::IOCTL_TYPE_GXP_PIXEL,
                ];
                cfg.refresh_types.extend(types);
                if allow_defaults {
                    push_unique_syscalls(args, &[29, 56, 57, 23, 24, 73, 20, 21, 22, 222, 226]);
                    push_unique_ioctl_types(args, &types);
                    for glob in [
                        "/dev/lwis*",
                        "/dev/gxp*",
                        "/dev/media*",
                        "/dev/video*",
                        "/dev/v4l-subdev*",
                    ] {
                        push_unique(&mut args.match_fd, glob);
                    }
                }
            }
            _ => bail!(
                "unknown driver pack '{raw}' (available: binder, kgsl, mali, alsa, unix-socket, media-hal)"
            ),
        }
        push_unique(&mut cfg.names, pack);
    }
    Ok(cfg)
}

// ── BPF load + attach ────────────────────────────────────────────────────────

fn load_bpf(
    object_path: &str,
    max_processes: u32,
    verbose: bool,
    required_feature_bits: u64,
) -> Result<(Ebpf, BpfObjectIdentity)> {
    let bytes = read_bpf_object_path(object_path)
        .with_context(|| format!("cannot read BPF object {object_path}"))?;
    let requirements = BpfAbiRequirements::default_capture().with_features(required_feature_bits);
    let validated = inspect_bpf_object(&bytes, &requirements)
        .with_context(|| format!("validating userspace/BPF ABI for {object_path}"))?;
    let log_level = if verbose {
        VerifierLogLevel::DEBUG | VerifierLogLevel::STATS
    } else {
        VerifierLogLevel::STATS
    };
    let bpf = EbpfLoader::new()
        // DEBUG logs every verifier step and can itself exhaust the kernel's
        // log buffer on large programs before the useful rejection reason.
        .verifier_log_level(log_level)
        .set_max_entries("TRACED_PROCESSES", max_processes)
        .load(&bytes)
        .with_context(|| format!("Ebpf::load failed for {object_path}"))?;
    Ok((bpf, validated.identity))
}

fn attach_tracepoint(bpf: &mut Ebpf, name: &str, category: &str, event: &str) -> Result<()> {
    let prog: &mut TracePoint = bpf
        .program_mut(name)
        .with_context(|| format!("program {name} not found in BPF object"))?
        .try_into()
        .map_err(|e| anyhow::anyhow!("{name}: not a TracePoint: {e}"))?;
    prog.load()
        .with_context(|| format!("loading program {name}"))?;
    prog.attach(category, event)
        .with_context(|| format!("attaching {name} to {category}/{event}"))?;
    Ok(())
}

fn attach_kprobe_if_present(bpf: &mut Ebpf, program_name: &str, symbol: &str) -> Result<bool> {
    let Some(program) = bpf.program_mut(program_name) else {
        return Ok(false);
    };
    let prog: &mut KProbe = program
        .try_into()
        .map_err(|e| anyhow::anyhow!("{program_name}: not a KProbe: {e}"))?;
    prog.load()
        .with_context(|| format!("loading kprobe program {program_name}"))?;
    prog.attach(symbol, 0)
        .with_context(|| format!("attaching {program_name} to kprobe/{symbol}"))?;
    Ok(true)
}

/// Stop every producer before the final health snapshot. This creates an
/// explicit capture boundary: counters cannot change while userspace reads
/// them, and any records still queued after detach are accounted as
/// incomplete instead of silently disappearing.
fn detach_attached_programs(bpf: &mut Ebpf, attached: &[&str]) -> Vec<String> {
    let mut errors = Vec::new();
    for name in attached {
        let result = match bpf.program_mut(name) {
            Some(Program::TracePoint(program)) => program.unload(),
            Some(Program::KProbe(program)) => program.unload(),
            Some(_) => {
                errors.push(format!("program:{name}:unexpected_type"));
                continue;
            }
            None => {
                errors.push(format!("program:{name}:missing"));
                continue;
            }
        };
        if let Err(error) = result {
            errors.push(format!("program:{name}:{error}"));
        }
    }
    errors
}

fn attach_kprobe_packs(
    bpf: &mut Ebpf,
    packs: &[String],
    attached: &mut Vec<&'static str>,
) -> Result<Vec<KprobePackScope>> {
    let mut statuses = Vec::new();
    for raw in packs {
        let pack = normalize_pack_name(raw);
        let candidates: &[(&str, &str)] = match pack.as_str() {
            "binder" => &[("kprobe_binder_ioctl", "binder_ioctl")],
            "kgsl" => &[("kprobe_kgsl_ioctl", "kgsl_ioctl")],
            "mali" => &[("kprobe_mali_ioctl", "kbase_ioctl")],
            "alsa" => &[("kprobe_alsa_ioctl", "snd_ctl_ioctl")],
            "unix-socket" => &[
                ("kprobe_unix_stream_sendmsg", "unix_stream_sendmsg"),
                ("kprobe_unix_stream_recvmsg", "unix_stream_recvmsg"),
            ],
            _ => bail!(
                "unknown kprobe pack '{raw}' (available: binder, kgsl, mali, alsa, unix-socket)"
            ),
        };
        let mut any = false;
        let mut status = KprobePackScope {
            name: pack.clone(),
            ..KprobePackScope::default()
        };
        for (program, symbol) in candidates {
            let source = format!("{program}@{symbol}");
            status.requested_sources.push(source.clone());
            match attach_kprobe_if_present(bpf, program, symbol) {
                Ok(true) => {
                    any = true;
                    attached.push(*program);
                    status.attached_sources.push(source);
                }
                Ok(false) => {
                    status.failures.push(format!("{source}:program_missing"));
                    eprintln!(
                        "neutron: warn: kprobe pack {pack}: BPF program {program} not present; skipping {symbol}"
                    );
                }
                Err(e) => {
                    status.failures.push(format!("{source}:attach_failed:{e}"));
                    eprintln!(
                        "neutron: warn: kprobe pack {pack}: {program}/{symbol} attach failed: {e}; continuing"
                    );
                }
            }
        }
        if !any {
            eprintln!(
                "neutron: warn: kprobe pack {pack}: no kprobes attached; syscall tracepoints remain active"
            );
        }
        statuses.push(status);
    }
    Ok(statuses)
}

// ── Filter map population ────────────────────────────────────────────────────

fn populate_filter_map(
    bpf: &mut Ebpf,
    pid: u32,
    causal_mode: bool,
    follow_binder: bool,
    max_depth: u8,
    root_uid: Option<u32>,
    admit_root_uid: bool,
) -> Result<()> {
    let map = bpf
        .map_mut("FILTER_MAP")
        .context("FILTER_MAP missing from BPF object")?;
    let mut filter: Array<_, u32> =
        Array::try_from(map).context("FILTER_MAP is not an Array<u32>")?;
    filter
        .set(FILTER_KEY_PID, pid, 0)
        .context("setting FILTER_MAP[PID]")?;
    filter
        .set(FILTER_KEY_ACTIVE, 0u32, 0)
        .context("setting FILTER_MAP[ACTIVE]")?;
    filter
        .set(FILTER_KEY_CAUSAL_MODE, u32::from(causal_mode), 0)
        .context("setting FILTER_MAP[CAUSAL_MODE]")?;
    filter
        .set(FILTER_KEY_FOLLOW_BINDER, u32::from(follow_binder), 0)
        .context("setting FILTER_MAP[FOLLOW_BINDER]")?;
    filter
        .set(FILTER_KEY_MAX_DEPTH, u32::from(max_depth), 0)
        .context("setting FILTER_MAP[MAX_DEPTH]")?;
    filter
        .set(FILTER_KEY_ROOT_UID, root_uid.unwrap_or_default(), 0)
        .context("setting FILTER_MAP[ROOT_UID]")?;
    filter
        .set(FILTER_KEY_ROOT_UID_ACTIVE, u32::from(root_uid.is_some()), 0)
        .context("setting FILTER_MAP[ROOT_UID_ACTIVE]")?;
    filter
        .set(FILTER_KEY_ROOT_UID_ADMIT, u32::from(admit_root_uid), 0)
        .context("setting FILTER_MAP[ROOT_UID_ADMIT]")?;
    Ok(())
}

/// Unified capture-predicate carrier. Phase 1a populates this from
/// individual `--match-*` flags; Phase 1b populates it from a parsed
/// `--match '<expr>'` AST. The runtime hot-path consults the same
/// `evaluate` method either way, so the post-filter loop stays unchanged.
enum CapturePredicate {
    Empty,
    Spec(MatchSpec),
    Expr {
        ast: predicate::Expr,
        bpf_spec: MatchSpec,
        ast_mentions_fd_path: bool,
    },
}

impl CapturePredicate {
    fn bpf_spec(&self) -> Option<&MatchSpec> {
        match self {
            CapturePredicate::Empty => None,
            CapturePredicate::Spec(s) => Some(s),
            CapturePredicate::Expr { bpf_spec, .. } => Some(bpf_spec),
        }
    }

    fn evaluate(&self, lens: &dyn matcher::EventLens) -> bool {
        match self {
            CapturePredicate::Empty => true,
            CapturePredicate::Spec(s) => matcher::evaluate(s, lens),
            CapturePredicate::Expr { ast, .. } => predicate::evaluate(ast, lens),
        }
    }

    fn audit_lines(&self) -> Vec<String> {
        match self {
            CapturePredicate::Empty => Vec::new(),
            CapturePredicate::Spec(s) => s.audit_lines(),
            CapturePredicate::Expr { ast, .. } => predicate::audit_lines(ast),
        }
    }

    fn is_empty(&self) -> bool {
        matches!(self, CapturePredicate::Empty)
    }

    fn needs_state_events_via_ast(&self) -> bool {
        match self {
            CapturePredicate::Expr {
                ast_mentions_fd_path,
                bpf_spec,
                ..
            } => *ast_mentions_fd_path && !bpf_spec.needs_state_events(),
            _ => false,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn effective_capture_scope(
    args: &Args,
    predicate: &CapturePredicate,
    capture_mode: CaptureMode,
    suppress_raw: bool,
    findings_enabled: bool,
    max_output_bytes: Option<u64>,
    rotate_output_bytes: Option<u64>,
    effective_root_uid: Option<u32>,
    follow_ttl_ns: u64,
    driver_packs: &[String],
    kprobe_packs: &[KprobePackScope],
    schema_packs: &[String],
    schema_pack_identities: &[CaptureContentIdentity],
    rules_sha256: Option<&str>,
    binder_services_sha256: Option<&str>,
    binder_methods_sha256: Option<&str>,
    aidl_catalog_sha256: Option<&str>,
    dynamic_service_inventory_sha256: Option<&str>,
    dynamic_hal_inventory_sha256: Option<&str>,
    bpf_identity: &BpfObjectIdentity,
    tool_identity: &neutron::run_manifest::ToolIdentity,
    fdgraph_available: bool,
    logcat_available: bool,
    selinux_logcat_available: bool,
    tombstone_available: bool,
) -> CaptureScope {
    let mut bpf_filters = Vec::new();
    let mut userspace_filters = Vec::new();
    for line in predicate.audit_lines() {
        let line = line.trim();
        if let Some((_, value)) = line.split_once("[bpf]") {
            bpf_filters.push(value.trim().to_string());
        } else if let Some((_, value)) = line.split_once("[user]") {
            userspace_filters.push(value.trim().to_string());
        }
    }
    let (capture_mode, context_duration_ns) = match capture_mode {
        CaptureMode::Default => ("matched", None),
        CaptureMode::MatchedWithContext { duration_ns } => {
            ("matched_with_context", Some(duration_ns))
        }
    };
    let event_mode = if suppress_raw {
        "findings_only"
    } else if findings_enabled {
        "raw_and_findings"
    } else {
        "raw_only"
    };
    CaptureScope {
        schema: neutron::health::CAPTURE_SCOPE_SCHEMA.into(),
        output: CaptureOutputScope {
            event_mode: event_mode.into(),
            serialization: if args.json { "ndjson" } else { "text" }.into(),
            capture_mode: capture_mode.into(),
            context_duration_ns,
            destination: if args.output.is_some() {
                "file"
            } else {
                "stdout"
            }
            .into(),
            max_output_bytes,
            rotate_output_bytes,
        },
        observation: CaptureObservationScope {
            target_pid: args.pid,
            root_package: args.package.clone(),
            root_uid: effective_root_uid,
            follow_children: args.follow_children,
        },
        filters: CaptureFilterScope {
            bpf: bpf_filters,
            userspace: userspace_filters,
            exclude_comm: args.exclude_comm.clone(),
            match_expression: args.match_expr.clone(),
            match_packages: args.match_package.clone(),
            match_android_providers: args.match_android_provider.clone(),
            alert_rwx_only: args.alert_rwx,
        },
        sampling: CaptureSamplingScope {
            probability: args.sample.unwrap_or(1.0).clamp(0.0, 1.0),
            rate_limit_per_second: args.rate_limit,
        },
        instrumentation: CaptureInstrumentationScope {
            binder_tracepoints: args.binder,
            binder_correlation: args.binder_inflight > 0,
            causal_follow: args.follow_binder,
            follow_services: args.follow_services,
            follow_hal: args.follow_hal,
            stacks: args.stacks,
            capture_reads: args.capture_reads,
            resolve_paths: args.resolve_paths,
            max_depth: args.max_depth,
            max_processes: args.max_processes,
            follow_ttl_ns,
            follow_allow_domains: args.follow_allow_domain.clone(),
            follow_deny_domains: args.follow_deny_domain.clone(),
        },
        packs: CapturePackScope {
            driver: driver_packs.to_vec(),
            kprobe: kprobe_packs.to_vec(),
            schema: schema_packs.to_vec(),
            schema_identities: schema_pack_identities.to_vec(),
        },
        sources: CaptureSourceScope {
            fdgraph_enabled: fdgraph_available,
            fdgraph_interval: args.fdgraph_interval.clone(),
            fdgraph_pid_scope: args.fdgraph_pids.clone(),
            fdgraph_thresholds: args.fdgraph_thresholds.clone(),
            fdgraph_top_paths_n: args.fdgraph_top_paths_n,
            logcat_requested: !args.no_logcat,
            logcat_available,
            selinux_logcat_requested: !args.no_logcat,
            selinux_logcat_available,
            tombstone_requested: !args.tombstone_dir.is_empty(),
            tombstone_available,
            tombstone_dir: (!args.tombstone_dir.is_empty()).then(|| args.tombstone_dir.clone()),
            lookback_events: args.lookback_events,
            binder_inflight_capacity: args.binder_inflight,
        },
        findings: CaptureFindingScope {
            enabled: findings_enabled,
            rules_sha256: rules_sha256.map(str::to_string),
            drain_interval: args.findings_drain_interval.max(1),
            raw_window: args.finding_raw_window,
            fd_snapshot_on_finding: args.fd_snapshot_on_finding,
        },
        enrichment: CaptureEnrichmentScope {
            binder_services_sha256: binder_services_sha256.map(str::to_string),
            binder_methods_sha256: binder_methods_sha256.map(str::to_string),
            aidl_catalog_sha256: aidl_catalog_sha256.map(str::to_string),
            dynamic_service_inventory_sha256: dynamic_service_inventory_sha256.map(str::to_string),
            dynamic_hal_inventory_sha256: dynamic_hal_inventory_sha256.map(str::to_string),
        },
        producer: CaptureProducerScope {
            bpf_object_sha256: bpf_identity.object_sha256.clone(),
            bpf_build_id: bpf_identity.build_id.clone(),
            bpf_feature_bits: bpf_identity.feature_bits,
            userspace_binary_sha256: tool_identity.binary_sha256.clone(),
            userspace_version: tool_identity.version.clone(),
            userspace_git_commit: tool_identity.git_commit.clone(),
            userspace_git_dirty: tool_identity.git_dirty,
        },
        claim_scope_complete: false,
        claim_scope_reasons: Vec::new(),
    }
    .recompute_claim_scope()
}

/// Print a one-shot stderr warning when a `--match-fd` / `--match-comm`
/// flag arrived as a list of literal entries with a strong common
/// prefix and no glob characters — almost always the result of an
/// outer shell having expanded the wildcard before neutron saw it.
/// The 2026-05-06 device-test report flagged this as the loudest
/// remaining UX rough edge: `--match-fd '/dev/lwis*'` over `adb shell
/// su -c "..."` got expanded against the host's `/dev` and arrived
/// as a noisy literal list. See man page `GLOB QUOTING WITH ADB`
/// for the working escape pattern.
fn warn_likely_shell_expansion(label: &str, globs: &[String]) {
    if let Some(prefix) = matcher::detect_likely_shell_expansion(globs) {
        eprintln!(
            "neutron: WARNING: {label} arrived as {} literal values sharing prefix \
             {prefix:?} with no glob characters — looks like the outer shell expanded \
             a wildcard. If you intended a glob, escape the asterisk so the device \
             shell sees it (see `GLOB QUOTING WITH ADB` in the man page):",
            globs.len()
        );
        eprintln!(
            r#"    adb shell su -c "...{label}={}\\*""#,
            prefix.trim_end_matches('-')
        );
    }
}

/// True iff any individual `--match-*` flag was provided. Used by
/// `build_capture_predicate` to enforce mutual exclusivity with
/// `--match <expr>`.
fn any_individual_match_flag(args: &Args) -> bool {
    !args.match_pid.is_empty()
        || !args.match_uid.is_empty()
        || !args.match_package.is_empty()
        || !args.match_android_provider.is_empty()
        || !args.match_syscall.is_empty()
        || !args.match_fd.is_empty()
        || !args.match_comm.is_empty()
        || !args.match_ioctl_cmd.is_empty()
        || !args.match_ioctl_type.is_empty()
        || !args.match_ioctl_nr.is_empty()
        || args.match_ioctl_dir.is_some()
        || args.match_ret.is_some()
        || args.match_latency_min.is_some()
        || args.match_prot_rwx
        || args.match_prot_wx
        || !args.match_arg_u8.is_empty()
        || !args.match_arg_u16.is_empty()
        || !args.match_arg_u32.is_empty()
        || !args.match_arg_u64.is_empty()
        || !args.match_binder_code.is_empty()
        || !args.match_binder_flags.is_empty()
        || !args.match_binder_to_proc.is_empty()
        || !args.match_binder_to_thread.is_empty()
        || !args.match_binder_target_node.is_empty()
        || args.match_binder_reply.is_some()
}

fn has_capture_predicate_flags(args: &Args) -> bool {
    any_individual_match_flag(args) || args.match_expr.is_some()
}

fn capture_guardrail_warnings(args: &Args) -> Vec<String> {
    let mut warnings = Vec::new();
    if args.pid == 0 && args.binder && args.raw && args.rate_limit.is_none() {
        warnings.push(
            "broad capture: --pid 0 with --binder and --raw can produce very large traces; \
             consider --match-* filters, --rate-limit, --sample, or a narrower --pid"
                .to_string(),
        );
    }
    if args.output.is_some()
        && args.max_output_size.is_none()
        && args.rotate_output_size.is_none()
        && args.raw
        && args.pid == 0
    {
        warnings.push(
            "uncapped output: --output with --pid 0 and --raw can grow quickly; set \
             --max-output-size or --rotate-output-size (for example 250mb), add \
             --rate-limit/--sample, or narrow the capture with --match-* filters"
                .to_string(),
        );
    }
    if args.pid == 0
        && args
            .capture
            .as_deref()
            .is_some_and(|c| c.trim().starts_with("matched+context="))
    {
        warnings.push(
            "broad context capture: --capture matched+context=<DUR> under --pid 0 buffers \
             rejected system-wide events; keep DUR small and prefer UID/PID/syscall filters"
                .to_string(),
        );
    }
    if args.binder && has_capture_predicate_flags(args) && args.binder_inflight > 0 {
        warnings.push(
            "binder context: synthesized type:\"binder_call\" lines come from the global \
             Binder correlator and may include caller/callee pairs outside strict \
             --match-* filters; use --binder-inflight 0 to suppress correlation context"
                .to_string(),
        );
    }
    warnings
}

fn build_capture_predicate(args: &Args) -> Result<CapturePredicate> {
    let has_individual = any_individual_match_flag(args);
    let has_expr = args.match_expr.is_some();
    if has_individual && has_expr {
        bail!(
            "--match <expr> is mutually exclusive with --match-* individual flags; \
             pick one form"
        );
    }
    if let Some(s) = &args.match_expr {
        let ast = predicate::parse(s).with_context(|| format!("--match {s:?}"))?;
        let bpf_spec = predicate::extract_bpf_spec(&ast);
        let ast_mentions_fd_path = predicate::mentions_fd_path(&ast);
        return Ok(CapturePredicate::Expr {
            ast,
            bpf_spec,
            ast_mentions_fd_path,
        });
    }
    let spec = matcher::build_from_args(args)?;
    if spec.is_empty() {
        Ok(CapturePredicate::Empty)
    } else {
        Ok(CapturePredicate::Spec(spec))
    }
}

fn resolve_match_packages(args: &mut Args) -> Result<()> {
    for package in args.match_package.clone() {
        let uid = android::resolve_package_uid(&package)
            .with_context(|| format!("resolving --match-package {package}"))?;
        eprintln!("  match package: {package} -> uid {uid}");
        if let Some(warning) = android::match_package_uid_warning(&package, uid) {
            eprintln!("neutron: WARNING: {warning}");
        }
        args.match_uid.push(uid.to_string());
    }
    Ok(())
}

fn resolve_match_android_providers(args: &mut Args) -> Result<()> {
    for authority in args.match_android_provider.clone() {
        let provider = android::resolve_provider_authority(&authority)
            .with_context(|| format!("resolving --match-android-provider {authority}"))?;
        let uid = android::resolve_package_uid(&provider.package)
            .with_context(|| format!("resolving provider package {}", provider.package))?;
        match provider.component.as_deref() {
            Some(component) => eprintln!(
                "  match android provider: {} -> {} ({component}) uid {uid}",
                provider.authority, provider.package
            ),
            None => eprintln!(
                "  match android provider: {} -> {} uid {uid}",
                provider.authority, provider.package
            ),
        }
        args.match_uid.push(uid.to_string());
    }
    Ok(())
}

/// Phase 1a — push every BPF-evaluable clause of `spec` into its kernel
/// map, compute the `MATCH_BITS` mask, and toggle
/// `STATE_EMIT_REQUIRED` when a clause contains an fd-path predicate.
///
/// Idempotent: setting a slot to its default zero value is the
/// authoritative "off" signal. Userspace clauses (fd globs, comm globs,
/// non-u32 arg widths, binder fields) leave no kernel residue.
fn populate_match_maps(bpf: &mut Ebpf, spec: &MatchSpec) -> Result<()> {
    let mut bits: u32 = 0;

    // Multi-PID via existing PID_WHITELIST. The single --pid case is still
    // handled by FILTER_KEY_PID and stays the fast path; --match-pid only
    // populates the whitelist when there are extra PIDs.
    if !spec.pids.is_empty() {
        let map = bpf
            .map_mut("PID_WHITELIST")
            .context("PID_WHITELIST missing")?;
        let mut wl: AyaHashMap<_, u32, u8> =
            AyaHashMap::try_from(map).context("PID_WHITELIST is not HashMap<u32,u8>")?;
        for pid in &spec.pids {
            wl.insert(pid, 1u8, 0)
                .with_context(|| format!("PID_WHITELIST.insert({pid})"))?;
        }
    }

    // UID set.
    if !spec.uids.is_empty() {
        let map = bpf
            .map_mut("MATCH_UID_SET")
            .context("MATCH_UID_SET missing from BPF object")?;
        let mut uids: AyaHashMap<_, u32, u8> =
            AyaHashMap::try_from(map).context("MATCH_UID_SET is not HashMap<u32,u8>")?;
        for u in &spec.uids {
            uids.insert(u, 1u8, 0)
                .with_context(|| format!("MATCH_UID_SET.insert({u})"))?;
        }
        bits |= MATCH_BIT_UID;
    }

    // Syscall whitelist via existing SYSCALL_FILTER. Toggling
    // FILTER_KEY_ACTIVE is what the BPF-side `syscall_allowed` consults.
    if !spec.syscalls.is_empty() {
        let map = bpf
            .map_mut("SYSCALL_FILTER")
            .context("SYSCALL_FILTER missing")?;
        let mut sf: AyaHashMap<_, u32, u8> =
            AyaHashMap::try_from(map).context("SYSCALL_FILTER is not HashMap<u32,u8>")?;
        for nr in &spec.syscalls {
            sf.insert(*nr as u32, 1u8, 0)
                .with_context(|| format!("SYSCALL_FILTER.insert({nr})"))?;
        }
        // Toggle the legacy active flag.
        let map = bpf.map_mut("FILTER_MAP").context("FILTER_MAP missing")?;
        let mut filter: Array<_, u32> =
            Array::try_from(map).context("FILTER_MAP is not Array<u32>")?;
        filter
            .set(FILTER_KEY_ACTIVE, 1u32, 0)
            .context("FILTER_MAP[ACTIVE]=1")?;
    }

    if !spec.ioctl_cmds.is_empty() {
        let map = bpf
            .map_mut("MATCH_IOCTL_CMD_SET")
            .context("MATCH_IOCTL_CMD_SET missing")?;
        let mut m: AyaHashMap<_, u32, u8> =
            AyaHashMap::try_from(map).context("MATCH_IOCTL_CMD_SET is not HashMap<u32,u8>")?;
        for v in &spec.ioctl_cmds {
            m.insert(v, 1u8, 0)
                .with_context(|| format!("MATCH_IOCTL_CMD_SET.insert({v:#x})"))?;
        }
        bits |= MATCH_BIT_IOCTL_CMD;
    }
    if !spec.ioctl_types.is_empty() {
        let map = bpf
            .map_mut("MATCH_IOCTL_TYPE_SET")
            .context("MATCH_IOCTL_TYPE_SET missing")?;
        let mut m: AyaHashMap<_, u32, u8> =
            AyaHashMap::try_from(map).context("MATCH_IOCTL_TYPE_SET is not HashMap<u32,u8>")?;
        for v in &spec.ioctl_types {
            m.insert(v, 1u8, 0)
                .with_context(|| format!("MATCH_IOCTL_TYPE_SET.insert({v:#x})"))?;
        }
        bits |= MATCH_BIT_IOCTL_TYPE;
    }
    if !spec.ioctl_nrs.is_empty() {
        let map = bpf
            .map_mut("MATCH_IOCTL_NR_SET")
            .context("MATCH_IOCTL_NR_SET missing")?;
        let mut m: AyaHashMap<_, u32, u8> =
            AyaHashMap::try_from(map).context("MATCH_IOCTL_NR_SET is not HashMap<u32,u8>")?;
        for v in &spec.ioctl_nrs {
            m.insert(v, 1u8, 0)
                .with_context(|| format!("MATCH_IOCTL_NR_SET.insert({v:#x})"))?;
        }
        bits |= MATCH_BIT_IOCTL_NR;
    }
    if let Some(dir) = spec.ioctl_dir {
        let map = bpf.map_mut("FILTER_MAP").context("FILTER_MAP missing")?;
        let mut filter: Array<_, u32> =
            Array::try_from(map).context("FILTER_MAP is not Array<u32>")?;
        filter
            .set(FILTER_KEY_IOCTL_DIR, dir.as_u32(), 0)
            .context("FILTER_MAP[IOCTL_DIR]")?;
        bits |= MATCH_BIT_IOCTL_DIR;
    }

    if spec.ret_class != matcher::RetClass::Any {
        let map = bpf.map_mut("FILTER_MAP").context("FILTER_MAP missing")?;
        let mut filter: Array<_, u32> =
            Array::try_from(map).context("FILTER_MAP is not Array<u32>")?;
        filter
            .set(FILTER_KEY_RET_CLASS, spec.ret_class.as_u32(), 0)
            .context("FILTER_MAP[RET_CLASS]")?;
        bits |= MATCH_BIT_RET;
    }
    if let Some(min_us) = spec.latency_min_us {
        // Clamp into u32 — values above u32::MAX µs are pathological
        // (>71 minutes per syscall) and certainly user error.
        let v: u32 = min_us.try_into().unwrap_or(u32::MAX);
        let map = bpf.map_mut("FILTER_MAP").context("FILTER_MAP missing")?;
        let mut filter: Array<_, u32> =
            Array::try_from(map).context("FILTER_MAP is not Array<u32>")?;
        filter
            .set(FILTER_KEY_LATENCY_MIN_US, v, 0)
            .context("FILTER_MAP[LATENCY_MIN_US]")?;
        bits |= MATCH_BIT_LATENCY;
    }

    // Single BPF-evaluable u32 arg clause. Multi-offset stays userspace-only.
    if let Some(c) = spec.bpf_arg_u32() {
        let map = bpf
            .map_mut("MATCH_ARG_U32_VALS")
            .context("MATCH_ARG_U32_VALS missing")?;
        let mut m: AyaHashMap<_, u32, u8> =
            AyaHashMap::try_from(map).context("MATCH_ARG_U32_VALS is not HashMap<u32,u8>")?;
        for v in &c.values {
            let v32: u32 = (*v).try_into().context("arg.u32 value exceeds u32::MAX")?;
            m.insert(v32, 1u8, 0)
                .with_context(|| format!("MATCH_ARG_U32_VALS.insert({v32:#x})"))?;
        }
        let map = bpf.map_mut("FILTER_MAP").context("FILTER_MAP missing")?;
        let mut filter: Array<_, u32> =
            Array::try_from(map).context("FILTER_MAP is not Array<u32>")?;
        filter
            .set(FILTER_KEY_ARG_U32_OFF, c.offset, 0)
            .context("FILTER_MAP[ARG_U32_OFF]")?;
        bits |= MATCH_BIT_ARG_U32;
    }

    // Only fd-path predicates drive `STATE_EMIT_REQUIRED`; without that fd-path exemption,
    // active BPF predicates can suppress required lifecycle events. An active syscall
    // whitelist remains the earlier gate even when the exemption is enabled.
    let state_required = if spec.needs_state_events() {
        1u32
    } else {
        0u32
    };
    let map = bpf.map_mut("FILTER_MAP").context("FILTER_MAP missing")?;
    let mut filter: Array<_, u32> = Array::try_from(map).context("FILTER_MAP is not Array<u32>")?;
    filter
        .set(FILTER_KEY_STATE_EMIT_REQUIRED, state_required, 0)
        .context("FILTER_MAP[STATE_EMIT_REQUIRED]")?;

    // Authoritative MATCH_BITS write last so a partial population can
    // never accidentally activate a half-configured predicate.
    filter
        .set(FILTER_KEY_MATCH_BITS, bits, 0)
        .context("FILTER_MAP[MATCH_BITS]")?;

    Ok(())
}

fn populate_ioctl_refresh_maps(bpf: &mut Ebpf, cfg: &DriverPackConfig) -> Result<()> {
    if !cfg.refresh_cmds.is_empty() {
        let map = bpf
            .map_mut("IOCTL_REFRESH_CMD_SET")
            .context("IOCTL_REFRESH_CMD_SET missing")?;
        let mut m: AyaHashMap<_, u32, u8> =
            AyaHashMap::try_from(map).context("IOCTL_REFRESH_CMD_SET is not HashMap<u32,u8>")?;
        for cmd in &cfg.refresh_cmds {
            m.insert(*cmd, 1u8, 0)
                .with_context(|| format!("IOCTL_REFRESH_CMD_SET.insert({cmd:#x})"))?;
        }
    }
    if !cfg.refresh_types.is_empty() {
        let map = bpf
            .map_mut("IOCTL_REFRESH_TYPE_SET")
            .context("IOCTL_REFRESH_TYPE_SET missing")?;
        let mut m: AyaHashMap<_, u32, u8> =
            AyaHashMap::try_from(map).context("IOCTL_REFRESH_TYPE_SET is not HashMap<u32,u8>")?;
        for ty in &cfg.refresh_types {
            m.insert(*ty, 1u8, 0)
                .with_context(|| format!("IOCTL_REFRESH_TYPE_SET.insert({ty:#x})"))?;
        }
    }
    Ok(())
}

// ── Runtime preflight + capture lock ─────────────────────────────────────────

fn capture_privilege_preflight(check: &doctor::CheckResult) -> Result<()> {
    match check.status {
        doctor::Status::Pass => Ok(()),
        doctor::Status::Warn => {
            eprintln!("neutron: WARNING: privilege preflight: {}", check.reason);
            Ok(())
        }
        doctor::Status::Fail => bail!(
            "privilege preflight failed: {}. Run `neutron doctor` for the full \
             environment check. On rooted Android use adb shell \"su -c '...'\" \
             so neutron runs in the privileged domain, not as shell.",
            check.reason
        ),
    }
}

fn default_capture_lock_path() -> Result<PathBuf> {
    let android_runtime = Path::new("/data/local/share/neutron/runtime");
    let runtime = if Path::new("/data/local").is_dir() {
        android_runtime.to_path_buf()
    } else {
        std::env::temp_dir().join(format!("neutron-runtime-{}", unsafe { libc::geteuid() }))
    };
    match fs::symlink_metadata(&runtime) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            neutron::private_output::create_private_directory(&runtime).with_context(|| {
                format!(
                    "creating default private capture runtime {}",
                    runtime.display()
                )
            })?;
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspecting capture runtime {}", runtime.display()));
        }
    }
    Ok(runtime.join("neutron.capture.lock"))
}

fn resolve_capture_lock_path(raw: &str) -> Result<Option<PathBuf>> {
    let raw = raw.trim();
    if raw.is_empty() || raw.eq_ignore_ascii_case("auto") {
        return Ok(Some(default_capture_lock_path()?));
    }
    if raw.eq_ignore_ascii_case("off") || raw.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(raw)))
}

#[derive(Debug)]
struct CaptureLock {
    _file: fs::File,
}

impl CaptureLock {
    fn acquire(path: &Path) -> Result<Self> {
        let file = neutron::private_output::open_private_file(
            path,
            neutron::private_output::PrivateFileMode::Lock,
        )
        .with_context(|| format!("opening capture lock {}", path.display()))?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(Self { _file: file });
        }
        let err = io::Error::last_os_error();
        let raw = err.raw_os_error();
        if err.kind() == io::ErrorKind::WouldBlock
            || raw == Some(libc::EWOULDBLOCK)
            || raw == Some(libc::EAGAIN)
        {
            bail!(
                "another neutron capture appears active (lock {}); run one capture at a time \
                 or pass --capture-lock off for advanced debugging",
                path.display()
            );
        }
        Err(err).with_context(|| format!("locking capture lock {}", path.display()))
    }
}

fn acquire_capture_lock(raw: &str) -> Result<Option<CaptureLock>> {
    let Some(path) = resolve_capture_lock_path(raw)? else {
        eprintln!("neutron: WARNING: capture lock disabled by --capture-lock off");
        return Ok(None);
    };
    Ok(Some(CaptureLock::acquire(&path)?))
}

// ── Output sink ──────────────────────────────────────────────────────────────

fn parse_size_bytes(raw: Option<&str>, flag_name: &str) -> Result<Option<u64>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() || s == "off" || s == "none" {
        return Ok(None);
    }
    let (num, mult) = if let Some(n) = s.strip_suffix("kb") {
        (n, 1024u64)
    } else if let Some(n) = s.strip_suffix('k') {
        (n, 1024u64)
    } else if let Some(n) = s.strip_suffix("mb") {
        (n, 1024u64 * 1024)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 1024u64 * 1024)
    } else if let Some(n) = s.strip_suffix("gb") {
        (n, 1024u64 * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix('g') {
        (n, 1024u64 * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix('b') {
        (n, 1)
    } else {
        (s.as_str(), 1)
    };
    let n: u64 = num
        .trim()
        .parse()
        .with_context(|| format!("invalid {flag_name} value: {raw}"))?;
    if n == 0 {
        bail!("{flag_name} must be > 0 when set");
    }
    n.checked_mul(mult)
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!("{flag_name} overflows u64: {raw}"))
}

fn parse_output_size_bytes(raw: Option<&str>) -> Result<Option<u64>> {
    parse_size_bytes(raw, "--max-output-size")
}

fn parse_rotate_output_size_bytes(raw: Option<&str>) -> Result<Option<u64>> {
    parse_size_bytes(raw, "--rotate-output-size")
}

struct CappedWriter {
    inner: Box<dyn IoWrite>,
    written: u64,
    max_bytes: u64,
    hit: Arc<AtomicBool>,
}

impl CappedWriter {
    fn new(inner: Box<dyn IoWrite>, max_bytes: u64, hit: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            written: 0,
            max_bytes,
            hit,
        }
    }
}

impl IoWrite for CappedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.hit.load(Ordering::Relaxed)
            || self.written.saturating_add(buf.len() as u64) > self.max_bytes
        {
            self.hit.store(true, Ordering::Relaxed);
            return Err(io::Error::other(format!(
                "max output size {} bytes reached",
                self.max_bytes
            )));
        }
        self.inner.write_all(buf)?;
        let n = buf.len();
        self.written = self.written.saturating_add(n as u64);
        if self.written >= self.max_bytes {
            self.hit.store(true, Ordering::Relaxed);
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct RotatingWriter {
    base_path: String,
    segment_idx: u64,
    segment_bytes: u64,
    max_segment_bytes: u64,
    inner: std::io::LineWriter<fs::File>,
}

impl RotatingWriter {
    fn new(path: &str, max_segment_bytes: u64) -> Result<Self> {
        if max_segment_bytes == 0 {
            bail!("--rotate-output-size must be > 0 when set");
        }
        let file = open_private_capture_file(Path::new(path), true, false)
            .with_context(|| format!("cannot create {path}"))?;
        Ok(Self {
            base_path: path.to_string(),
            segment_idx: 0,
            segment_bytes: 0,
            max_segment_bytes,
            inner: std::io::LineWriter::new(file),
        })
    }

    fn segment_path(&self) -> String {
        if self.segment_idx == 0 {
            self.base_path.clone()
        } else {
            format!("{}.{}", self.base_path, self.segment_idx)
        }
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.inner.flush()?;
        self.segment_idx = self.segment_idx.saturating_add(1);
        self.segment_bytes = 0;
        let path = self.segment_path();
        let file =
            open_private_capture_file(Path::new(&path), false, false).map_err(io::Error::other)?;
        self.inner = std::io::LineWriter::new(file);
        eprintln!("neutron: rotated output to {path}");
        Ok(())
    }
}

/// Count newline-terminated records that the primary capture sink actually
/// accepted. This sits outside cap/rotation writers, so rejected writes are
/// never reported as emitted and every record kind shares one accounting path.
struct RecordCountingWriter {
    inner: Box<dyn IoWrite>,
    records: Arc<AtomicU64>,
    pending: Vec<u8>,
}

impl RecordCountingWriter {
    fn new(inner: Box<dyn IoWrite>, records: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            records,
            pending: Vec::with_capacity(4096),
        }
    }
}

impl IoWrite for RecordCountingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        const MAX_OUTPUT_RECORD_BYTES: usize = 16 * 1024 * 1024;
        for byte in buf {
            self.pending.push(*byte);
            if self.pending.len() > MAX_OUTPUT_RECORD_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "capture record exceeds 16 MiB",
                ));
            }
            if *byte == b'\n' {
                let result = self.inner.write_all(&self.pending);
                self.pending.clear();
                result?;
                self.records.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.pending.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "capture output ended with a partial record",
            ));
        }
        self.inner.flush()
    }
}

fn open_private_capture_file(path: &Path, overwrite: bool, append: bool) -> Result<fs::File> {
    let mode = if append {
        neutron::private_output::PrivateFileMode::Append
    } else if overwrite {
        neutron::private_output::PrivateFileMode::Overwrite
    } else {
        neutron::private_output::PrivateFileMode::CreateNew
    };
    neutron::private_output::open_private_file(path, mode)
        .with_context(|| format!("opening private capture output {}", path.display()))
}

impl IoWrite for RotatingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.segment_bytes > 0
            && self.segment_bytes.saturating_add(buf.len() as u64) > self.max_segment_bytes
        {
            self.rotate()?;
        }
        self.inner.write_all(buf)?;
        let n = buf.len();
        self.segment_bytes = self.segment_bytes.saturating_add(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn stop_if_output_cap_hit(cap_hit: &AtomicBool, reported: &mut bool, running: &AtomicBool) -> bool {
    if !cap_hit.load(Ordering::Relaxed) {
        return false;
    }
    if !*reported {
        eprintln!("neutron: WARNING: --max-output-size reached; stopping capture");
        *reported = true;
    }
    running.store(false, Ordering::Relaxed);
    true
}

fn write_or_output_cap(result: io::Result<()>, cap_hit: &AtomicBool) -> Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(_) if cap_hit.load(Ordering::Relaxed) => Ok(()),
        Err(error) => Err(error).context("writing capture output"),
    }
}

fn open_output(
    path: Option<&String>,
    max_bytes: Option<u64>,
    rotate_bytes: Option<u64>,
    cap_hit: Arc<AtomicBool>,
) -> Result<Box<dyn IoWrite>> {
    if max_bytes.is_some() && rotate_bytes.is_some() {
        bail!("--max-output-size and --rotate-output-size are mutually exclusive");
    }
    if rotate_bytes.is_some() && path.is_none() {
        bail!("--rotate-output-size requires --output");
    }
    if let (Some(p), Some(max)) = (path, rotate_bytes) {
        return Ok(Box::new(RotatingWriter::new(p, max)?));
    }

    let base: Box<dyn IoWrite> = match path {
        Some(p) => {
            // Start each trace with a fresh file, then reopen in O_APPEND
            // mode so `neutron mark --output <same-file>` cannot be
            // overwritten by this long-lived writer's file offset.
            let f = open_private_capture_file(Path::new(p), true, true)?;
            Box::new(std::io::LineWriter::new(f))
        }
        None => Box::new(std::io::BufWriter::new(std::io::stdout())),
    };
    if let Some(max) = max_bytes {
        Ok(Box::new(CappedWriter::new(base, max, cap_hit)))
    } else {
        Ok(base)
    }
}

fn write_health_sidecar<P: AsRef<Path>>(path: Option<P>, line: &str) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let path = path.as_ref();
    let mut body = String::with_capacity(line.len() + 1);
    body.push_str(line);
    body.push('\n');
    let mut file = open_private_capture_file(path, true, false)?;
    file.write_all(body.as_bytes())
        .with_context(|| format!("writing capture health sidecar {}", path.to_string_lossy()))?;
    file.flush()
        .with_context(|| format!("flushing capture health sidecar {}", path.to_string_lossy()))
}

// ── Stack symbolization helper ───────────────────────────────────────────────

/// Render one stack-trace map entry. Picks the right symbolizer per frame
/// based on the canonical aarch64 user/kernel split.
struct RenderedStack {
    ips: Vec<u64>,
    rendered: Vec<String>,
}

fn format_stack(
    stack_traces: &StackTraceMap<aya::maps::MapData>,
    stackid: i32,
    proc_sym: Option<&mut ProcSymbolizer>,
    kernel_resolver: Option<&KernelResolver>,
) -> Result<Option<RenderedStack>, MapError> {
    if stackid < 0 {
        return Ok(None);
    }
    let trace = stack_traces.get(&(stackid as u32), 0)?;
    let frames = trace.frames();
    if frames.is_empty() {
        return Ok(None);
    }
    // We can't borrow `proc_sym` mutably from inside the closure once we've
    // taken &mut to it, so collect into Strings via an explicit loop.
    let mut rendered: Vec<String> = Vec::with_capacity(frames.len());
    let mut ips = Vec::with_capacity(frames.len());
    let mut proc_sym = proc_sym;
    for f in frames.iter() {
        let ip = f.ip;
        ips.push(ip);
        let s = if is_kernel_addr(ip) {
            // KernelResolver bundles kallsyms + /proc/modules. When
            // kallsyms is masked by kptr_restrict, modules still gives
            // a `[<ko>]+0x<offset>` label for IPs inside loaded
            // modules. Both layers absent → bare hex.
            match kernel_resolver {
                Some(r) => r.resolve(ip),
                None => format!("{:#x}", ip),
            }
        } else {
            match proc_sym.as_deref_mut() {
                Some(ps) => ps.symbolize(ip),
                None => format!("{:#x}", ip),
            }
        };
        rendered.push(s);
    }
    Ok(Some(RenderedStack { ips, rendered }))
}

// ── Event filtering ──────────────────────────────────────────────────────────

fn should_skip_for_exclude_comm(ev: &SyscallEvent, exclude_comm: &[String]) -> bool {
    if exclude_comm.is_empty() {
        return false;
    }
    let comm = format_comm(&{ ev.comm });
    exclude_comm.iter().any(|x| comm.contains(x.as_str()))
}

fn should_skip_for_alert_rwx(ev: &SyscallEvent) -> bool {
    let nr = { ev.syscall_nr };
    if nr != SYSCALL_MMAP && nr != SYSCALL_MPROTECT {
        return false;
    }
    let d = { ev.data };
    !(d[0] == 1 || d[0] == 2)
}

// ── Side-effect handlers (--follow-children, --capture-reads) ────────────────

fn handle_follow_children(
    ev: &SyscallEvent,
    pid_whitelist: &mut AyaHashMap<&mut aya::maps::MapData, u32, u8>,
    verbose: bool,
) -> Option<String> {
    let child_pid = followed_child_pid(ev)?;
    match pid_whitelist.insert(child_pid, 1u8, 0) {
        Ok(()) => {
            if verbose {
                eprintln!("  [follow] now tracking child pid {child_pid}");
            }
        }
        Err(error) => {
            return Some(format!(
                "PID_WHITELIST update failed for child {child_pid}: {error}"
            ));
        }
    }
    None
}

fn followed_child_pid(ev: &SyscallEvent) -> Option<u32> {
    let nr = { ev.syscall_nr };
    let is_enter = { ev.is_enter };
    if nr != SYSCALL_CLONE || is_enter == 1 {
        return None;
    }
    let ret = { ev.ret };
    if ret <= 0 {
        return None;
    }
    let args = { ev.args };
    if args[0] & CLONE_THREAD != 0 {
        return None;
    }
    Some(ret as u32)
}

fn handle_capture_reads(
    ev: &SyscallEvent,
    watch_fds: &mut AyaHashMap<&mut aya::maps::MapData, u64, u8>,
    watched_fds: &mut HashSet<u64>,
    verbose: bool,
) -> Option<String> {
    let nr = { ev.syscall_nr };
    let is_enter = { ev.is_enter };
    let pid = { ev.pid };

    // openat() exit: watch any /proc/* or /sys/* fd
    if nr == SYSCALL_OPENAT && is_enter == 0 {
        let fd = { ev.ret };
        if fd >= 0 {
            if let Some(p) = resolve_path_from_fd(pid, fd) {
                if p.starts_with("/proc/") || p.starts_with("/sys/") {
                    let key = ((pid as u64) << 32) | (fd as u64 & 0xffffffff);
                    if let Err(error) = watch_fds.insert(key, 1u8, 0) {
                        return Some(format!("WATCH_FDS insert failed for {pid}/{fd}: {error}"));
                    }
                    watched_fds.insert(key);
                    if verbose {
                        eprintln!("  [capture] watching fd={fd} path={p}");
                    }
                }
            }
        }
    }

    // close() enter: stop watching the fd
    if nr == SYSCALL_CLOSE && is_enter == 1 {
        let fd = { ev.args[0] } as i64;
        if fd >= 0 {
            let key = ((pid as u64) << 32) | (fd as u64 & 0xffffffff);
            if watched_fds.remove(&key) {
                if let Err(error) = watch_fds.remove(&key) {
                    return Some(format!("WATCH_FDS remove failed for {pid}/{fd}: {error}"));
                }
            }
        }
    }

    // read()/write() exit on watched fd: content peek removed alongside the
    // process_vm_readv PAN workaround. The BPF programs only stash the user
    // pointer in `ptr_hint`; future work could capture buffer bytes directly
    // via `bpf_probe_read_user_buf` into `data[..]` if needed.
    None
}

fn cleanup_watched_fds_for_pid(
    pid: u32,
    watch_fds: &mut AyaHashMap<&mut aya::maps::MapData, u64, u8>,
    watched_fds: &mut HashSet<u64>,
) -> Vec<String> {
    let prefix = u64::from(pid) << 32;
    let keys: Vec<u64> = watched_fds
        .iter()
        .copied()
        .filter(|key| *key >> 32 == u64::from(pid))
        .collect();
    let mut errors = Vec::new();
    for key in keys {
        match watch_fds.remove(&key) {
            Ok(()) | Err(MapError::KeyNotFound) => {
                watched_fds.remove(&key);
            }
            Err(error) => errors.push(format!(
                "WATCH_FDS cleanup failed for {pid}/{}: {error}",
                key.saturating_sub(prefix)
            )),
        }
    }
    errors
}

// ── Causal process/scenario helpers (1.3) ──────────────────────────────────

fn replace_causal_roots(
    bpf: &mut Ebpf,
    roots: &[u32],
    trace_id: u64,
    generation: u16,
) -> Result<()> {
    let map = bpf
        .map_mut("TRACED_PROCESSES")
        .context("TRACED_PROCESSES missing")?;
    let mut traced: AyaHashMap<_, u32, [u8; PROCESS_TRACE_CONTEXT_SIZE]> =
        AyaHashMap::try_from(map).context("TRACED_PROCESSES has unexpected layout")?;
    let keys: Vec<u32> = traced
        .keys()
        .collect::<Result<_, _>>()
        .context("enumerating causal process roots")?;
    for pid in keys {
        match traced.remove(&pid) {
            Ok(()) => {}
            Err(error) if map_delete_already_absent(&error) => {}
            Err(error) => return Err(error).with_context(|| format!("removing causal PID {pid}")),
        }
    }
    for pid in roots.iter().copied() {
        let context = root_process_context(trace_id, generation);
        traced
            .insert(pid, process_context_bytes(&context), 0)
            .with_context(|| format!("adding root PID {pid} to TRACED_PROCESSES"))?;
    }
    Ok(())
}

fn map_delete_already_absent(error: &MapError) -> bool {
    match error {
        MapError::KeyNotFound | MapError::ElementNotFound => true,
        MapError::SyscallError(error) => {
            error.call == "bpf_map_delete_elem"
                && error.io_error.raw_os_error() == Some(libc::ENOENT)
        }
        _ => false,
    }
}

fn set_root_uid_context(bpf: &mut Ebpf, trace_id: u64, generation: u16) -> Result<()> {
    let map = bpf
        .map_mut("ROOT_UID_CONTEXT")
        .context("ROOT_UID_CONTEXT missing")?;
    let mut root: Array<_, [u8; PROCESS_TRACE_CONTEXT_SIZE]> =
        Array::try_from(map).context("ROOT_UID_CONTEXT has unexpected layout")?;
    root.set(
        0,
        process_context_bytes(&root_process_context(trace_id, generation)),
        0,
    )
    .context("updating ROOT_UID_CONTEXT")
}

fn clear_causal_transients(bpf: &mut Ebpf) -> Result<()> {
    // These are internal packed BPF-map wire sizes:
    // ProcessTraceContext(20) + flags(4) + parent_debug_id(4) + relation(1)
    // + admission_boundary(1), debug_id(4) + scenario_generation(2)
    // + depth(1) + admission_boundary(1), and per-thread u8 enter markers.
    {
        let map = bpf
            .map_mut("BINDER_TRANSACTION_CONTEXT")
            .context("BINDER_TRANSACTION_CONTEXT missing")?;
        let mut transactions: AyaHashMap<_, u32, [u8; 30]> = AyaHashMap::try_from(map)
            .context("BINDER_TRANSACTION_CONTEXT has unexpected layout")?;
        let keys: Vec<u32> = transactions
            .keys()
            .collect::<Result<_, _>>()
            .context("enumerating Binder transaction contexts")?;
        for key in keys {
            match transactions.remove(&key) {
                Ok(()) => {}
                Err(error) if map_delete_already_absent(&error) => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("removing Binder transaction context {key}"))
                }
            }
        }
    }
    {
        let map = bpf
            .map_mut("THREAD_BINDER_CONTEXT")
            .context("THREAD_BINDER_CONTEXT missing")?;
        let mut threads: AyaHashMap<_, u64, [u8; 8]> =
            AyaHashMap::try_from(map).context("THREAD_BINDER_CONTEXT has unexpected layout")?;
        let keys: Vec<u64> = threads
            .keys()
            .collect::<Result<_, _>>()
            .context("enumerating Binder thread contexts")?;
        for key in keys {
            match threads.remove(&key) {
                Ok(()) => {}
                Err(error) if map_delete_already_absent(&error) => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("removing Binder thread context {key}"))
                }
            }
        }
    }
    {
        let map = bpf
            .map_mut("ADMITTED_THREAD_ENTERS")
            .context("ADMITTED_THREAD_ENTERS missing")?;
        let mut threads: AyaHashMap<_, u64, u8> =
            AyaHashMap::try_from(map).context("ADMITTED_THREAD_ENTERS has unexpected layout")?;
        let keys: Vec<u64> = threads
            .keys()
            .collect::<Result<_, _>>()
            .context("enumerating admitted thread enter markers")?;
        for key in keys {
            match threads.remove(&key) {
                Ok(()) => {}
                Err(error) if map_delete_already_absent(&error) => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("removing admitted thread enter marker {key}"))
                }
            }
        }
    }
    Ok(())
}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct RawSyscallEvent([u8; core::mem::size_of::<SyscallEvent>()]);

// SAFETY: this is an exact-size byte representation used only to remove
// entries from the INFLIGHT map; every bit pattern is valid.
unsafe impl aya::Pod for RawSyscallEvent {}

/// Stop carrying pre-boundary syscall state across a scenario end. The BPF
/// causal context is disabled before this runs, so newly admitted entries
/// have generation zero. Removed entries are explicit evidence loss.
fn discard_inflight_at_scenario_end(bpf: &mut Ebpf) -> Result<u64> {
    let map = bpf.map_mut("INFLIGHT").context("INFLIGHT missing")?;
    let mut inflight: AyaHashMap<_, u64, RawSyscallEvent> =
        AyaHashMap::try_from(map).context("INFLIGHT has unexpected layout")?;
    let keys: Vec<u64> = inflight
        .keys()
        .collect::<Result<_, _>>()
        .context("enumerating INFLIGHT at scenario end")?;
    let mut discarded = 0_u64;
    for key in keys {
        match inflight.remove(&key) {
            Ok(()) => discarded = discarded.saturating_add(1),
            Err(error) if map_delete_already_absent(&error) => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("removing INFLIGHT entry {key} at scenario end"))
            }
        }
    }
    Ok(discarded)
}

fn reconcile_causal_roots(
    bpf: &mut Ebpf,
    roots: &[u32],
    trace_id: u64,
    generation: u16,
) -> Result<()> {
    let map = bpf
        .map_mut("TRACED_PROCESSES")
        .context("TRACED_PROCESSES missing")?;
    let mut traced: AyaHashMap<_, u32, [u8; PROCESS_TRACE_CONTEXT_SIZE]> =
        AyaHashMap::try_from(map).context("TRACED_PROCESSES has unexpected layout")?;
    let roots: HashSet<u32> = roots.iter().copied().collect();
    let keys: Vec<u32> = traced
        .keys()
        .collect::<Result<_, _>>()
        .context("enumerating causal roots for reconciliation")?;
    for pid in keys {
        let remove = match traced.get(&pid, 0) {
            Ok(context) => {
                let context = process_context_from_bytes(context);
                context.reason == TraceReason::Root && !roots.contains(&pid)
            }
            Err(MapError::KeyNotFound | MapError::ElementNotFound) => false,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("reading causal PID {pid} during reconciliation"))
            }
        };
        if remove {
            match traced.remove(&pid) {
                Ok(()) => {}
                Err(error) if map_delete_already_absent(&error) => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("removing stale causal root PID {pid}"))
                }
            }
        }
    }
    let context = root_process_context(trace_id, generation);
    for pid in roots {
        traced
            .insert(pid, process_context_bytes(&context), 0)
            .with_context(|| format!("adding refreshed causal root PID {pid}"))?;
    }
    Ok(())
}

fn root_process_context(trace_id: u64, generation: u16) -> ProcessTraceContext {
    ProcessTraceContext {
        root_trace_id: trace_id,
        parent_pid: 0,
        binder_debug_id: 0,
        depth: 0,
        reason: TraceReason::Root,
        scenario_generation: generation,
    }
}

fn discover_dynamic_roots(args: &Args, package_uid: Option<u32>) -> Result<Option<Vec<u32>>> {
    if let Some(package) = args.package.as_deref() {
        let uid = package_uid.context("package UID missing for causal root refresh")?;
        return android::find_package_processes(package, uid)
            .with_context(|| format!("finding processes for --package {package}"))
            .map(Some);
    }
    args.root_uid
        .map(android::find_uid_processes)
        .transpose()
        .context("finding processes for --root-uid")
}

fn process_context_lookup(
    pid: u32,
    result: std::result::Result<[u8; PROCESS_TRACE_CONTEXT_SIZE], MapError>,
) -> Result<Option<ProcessTraceContext>> {
    match result {
        Ok(bytes) => Ok(Some(process_context_from_bytes(bytes))),
        Err(MapError::KeyNotFound) => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading traced process PID {pid}")),
    }
}

fn read_process_context(bpf: &Ebpf, pid: u32) -> Result<Option<ProcessTraceContext>> {
    let map = bpf
        .map("TRACED_PROCESSES")
        .context("TRACED_PROCESSES missing")?;
    let traced: AyaHashMap<_, u32, [u8; PROCESS_TRACE_CONTEXT_SIZE]> =
        AyaHashMap::try_from(map).context("TRACED_PROCESSES has unexpected layout")?;
    process_context_lookup(pid, traced.get(&pid, 0))
}

fn process_thread_keys(
    keys: impl Iterator<Item = std::result::Result<u64, MapError>>,
    pid: u32,
    map_name: &str,
) -> Result<Vec<u64>> {
    let keys = keys
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("iterating {map_name} keys"))?;
    Ok(keys
        .into_iter()
        .filter(|pid_tgid| (*pid_tgid >> 32) as u32 == pid)
        .collect())
}

fn remove_followed_process(bpf: &mut Ebpf, pid: u32) -> Result<Option<ProcessTraceContext>> {
    let context = {
        let map = bpf
            .map_mut("TRACED_PROCESSES")
            .context("TRACED_PROCESSES missing")?;
        let mut traced: AyaHashMap<_, u32, [u8; PROCESS_TRACE_CONTEXT_SIZE]> =
            AyaHashMap::try_from(map).context("TRACED_PROCESSES has unexpected layout")?;
        let context = match traced.get(&pid, 0) {
            Ok(bytes) => process_context_from_bytes(bytes),
            Err(MapError::KeyNotFound | MapError::ElementNotFound) => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("reading followed PID {pid}")),
        };
        if context.reason == TraceReason::Root {
            return Ok(None);
        }
        match traced.remove(&pid) {
            Ok(()) => {}
            Err(error) if map_delete_already_absent(&error) => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("removing followed PID {pid}"))
            }
        }
        context
    };

    let binder_debug_id = { context.binder_debug_id };
    if binder_debug_id != 0 {
        let map = bpf
            .map_mut("BINDER_TRANSACTION_CONTEXT")
            .context("BINDER_TRANSACTION_CONTEXT missing")?;
        let mut transactions: AyaHashMap<_, u32, [u8; 30]> = AyaHashMap::try_from(map)
            .context("BINDER_TRANSACTION_CONTEXT has unexpected layout")?;
        match transactions.remove(&binder_debug_id) {
            Ok(()) => {}
            Err(error) if map_delete_already_absent(&error) => {}
            Err(error) => return Err(error).context("removing blocked Binder transaction context"),
        }
    }

    let map = bpf
        .map_mut("THREAD_BINDER_CONTEXT")
        .context("THREAD_BINDER_CONTEXT missing")?;
    let mut threads: AyaHashMap<_, u64, [u8; 8]> =
        AyaHashMap::try_from(map).context("THREAD_BINDER_CONTEXT has unexpected layout")?;
    let keys = process_thread_keys(threads.keys(), pid, "THREAD_BINDER_CONTEXT")?;
    for key in keys {
        match threads.remove(&key) {
            Ok(()) => {}
            Err(error) if map_delete_already_absent(&error) => {}
            Err(error) => return Err(error).context("removing blocked Binder thread context"),
        }
    }

    let map = bpf
        .map_mut("ADMITTED_THREAD_ENTERS")
        .context("ADMITTED_THREAD_ENTERS missing")?;
    let mut enters: AyaHashMap<_, u64, u8> =
        AyaHashMap::try_from(map).context("ADMITTED_THREAD_ENTERS has unexpected layout")?;
    let keys = process_thread_keys(enters.keys(), pid, "ADMITTED_THREAD_ENTERS")?;
    for key in keys {
        match enters.remove(&key) {
            Ok(()) => {}
            Err(error) if map_delete_already_absent(&error) => {}
            Err(error) => return Err(error).context("removing admitted thread enter marker"),
        }
    }
    Ok(Some(context))
}

fn follow_process_identity(pid: u32) -> (Option<String>, Option<String>) {
    fn bounded(path: String, limit: usize) -> Option<String> {
        let bytes = fs::read(path).ok()?;
        if bytes.len() > limit {
            return None;
        }
        let value = String::from_utf8(bytes).ok()?;
        let value = value.trim_end_matches(['\n', '\0']).trim();
        (!value.is_empty()).then(|| value.to_string())
    }

    let comm = bounded(format!("/proc/{pid}/comm"), 256);
    let domain = bounded(format!("/proc/{pid}/attr/current"), 512)
        .and_then(|context| neutron::causal::normalize_domain(&context).ok());
    (comm, domain)
}

fn pre_admission_follow_deny_domains(args: &Args) -> Result<BTreeSet<String>> {
    if !args.follow_binder {
        return Ok(BTreeSet::new());
    }
    args.follow_deny_domain
        .iter()
        .map(|domain| neutron::causal::normalize_domain(domain))
        .collect()
}

fn seed_pre_admission_follow_denies(
    bpf: &mut Ebpf,
    deny_domains: &BTreeSet<String>,
) -> Result<usize> {
    if deny_domains.is_empty() {
        return Ok(0);
    }
    let map = bpf
        .map_mut("BINDER_FOLLOW_DENY_PIDS")
        .context("BINDER_FOLLOW_DENY_PIDS missing")?;
    let mut denied: AyaHashMap<_, u32, u8> =
        AyaHashMap::try_from(map).context("BINDER_FOLLOW_DENY_PIDS has unexpected layout")?;
    let mut seeded = 0;
    for entry in fs::read_dir("/proc").context("enumerating /proc for follow deny domains")? {
        let Ok(entry) = entry else { continue };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let (_, domain) = follow_process_identity(pid);
        if !domain.is_some_and(|domain| deny_domains.contains(&domain)) {
            continue;
        }
        denied
            .insert(pid, 1, 0)
            .with_context(|| format!("pre-admission follow deny for PID {pid}"))?;
        seeded += 1;
    }
    Ok(seeded)
}

#[allow(clippy::too_many_arguments)]
fn emit_follow_guardrail(
    out: &mut dyn IoWrite,
    json: bool,
    event_id_counter: &mut u64,
    status: &str,
    reason: &str,
    caller_pid: u32,
    callee_pid: u32,
    debug_id: u32,
    depth: u8,
    metadata: Option<&CausalMetadata>,
    process_context: Option<ProcessTraceContext>,
    scenarios: &ScenarioState,
) -> io::Result<()> {
    if !json {
        return writeln!(
            out,
            "[follow] {status} pid={callee_pid} parent={caller_pid} depth={depth} reason={reason}"
        );
    }
    *event_id_counter = event_id_counter.wrapping_add(1);
    let mut value = serde_json::json!({
        "type": "follow_guardrail",
        "event_id": *event_id_counter,
        "status": status,
        "reason": reason,
        "caller_pid": caller_pid,
        "callee_pid": callee_pid,
        "binder_debug_id": debug_id,
        "depth": depth,
        "causal_branch_complete": false,
    });
    if let Some(context) = process_context {
        let trace_id = { context.root_trace_id };
        value["trace_id"] = serde_json::Value::String(format!("{trace_id:016x}"));
        if let Some(scenario) = scenarios.find(context.scenario_generation) {
            value["scenario_id"] = serde_json::Value::String(scenario.scenario_id.clone());
        }
    }
    let mut line = serde_json::to_string(&value).map_err(io::Error::other)?;
    if let Some(metadata) = metadata {
        line = enrich_json(&line, metadata).map_err(io::Error::other)?;
    }
    writeln!(out, "{line}")
}

fn causal_metadata_for_event(
    ev: &SyscallEvent,
    scenarios: &ScenarioState,
    root_package: Option<&str>,
    root_uid: Option<u32>,
) -> Option<CausalMetadata> {
    let generation = { ev.maps_generation };
    if generation == 0 {
        return None;
    }
    let scenario = scenarios.find(generation)?;
    let wire = CausalWire::from_event(ev);
    let pid = { ev.pid };
    let tid = { ev.tgid };
    let nr = { ev.syscall_nr };
    let timestamp = { ev.timestamp_ns };
    let debug_id = { ev.ptr_hint } as u32 as i32;
    let span_id = if nr == -1 || nr == SYSCALL_NR_BINDER_RECEIVED {
        binder_span_id(scenario.trace_id, debug_id)
    } else if nr == SYSCALL_NR_PROCESS_EXIT {
        process_exit_span_id(scenario.trace_id, pid, timestamp)
    } else {
        let enter = { ev.enter_timestamp_ns };
        syscall_span_id(
            scenario.trace_id,
            pid,
            tid,
            if enter == 0 { timestamp } else { enter },
            nr,
        )
    };
    let parent_span_id = if wire.parent_debug_id == 0 {
        root_process_span_id(scenario.trace_id, pid)
    } else {
        binder_span_id(scenario.trace_id, wire.parent_debug_id as i32)
    };
    Some(CausalMetadata {
        scenario_id: scenario.scenario_id.clone(),
        trace_id: scenario.trace_id,
        span_id,
        parent_span_id,
        depth: wire.depth,
        relation: wire.relation,
        root_package: root_package.map(str::to_string),
        root_uid,
    })
}

#[cfg(test)]
fn causal_metadata_for_selinux_denial(
    denial: &neutron::selinux::SelinuxDenial,
    context: ProcessTraceContext,
    scenario: &ScenarioInfo,
    root_package: Option<&str>,
    root_uid: Option<u32>,
) -> CausalMetadata {
    let binder_debug_id = context.binder_debug_id;
    let depth = context.depth;
    let parent_span_id = if binder_debug_id == 0 {
        root_process_span_id(scenario.trace_id, denial.pid)
    } else {
        binder_span_id(scenario.trace_id, binder_debug_id as i32)
    };
    CausalMetadata {
        scenario_id: scenario.scenario_id.clone(),
        trace_id: scenario.trace_id,
        span_id: selinux_denial_span_id(scenario.trace_id, denial.pid, denial.tid, denial.ts_ns),
        parent_span_id,
        depth,
        relation: neutron::selinux::process_context_relation(context),
        root_package: root_package.map(str::to_string),
        root_uid,
    }
}

fn selinux_denial_in_scope(
    denial: &neutron::selinux::SelinuxDenial,
    args: &Args,
    root_pids: &[u32],
    scope_pids: &BTreeSet<u32>,
    scope_uids: &BTreeSet<u32>,
    causal_context: Option<ProcessTraceContext>,
) -> bool {
    if args
        .exclude_comm
        .iter()
        .any(|excluded| denial.comm.contains(excluded))
    {
        return false;
    }
    if args.package.is_some() || args.root_uid.is_some() {
        return causal_context.is_some() || root_pids.contains(&denial.pid);
    }
    if args.pid != 0 && denial.pid != args.pid {
        return false;
    }
    if !scope_pids.is_empty() && !scope_pids.contains(&denial.pid) {
        return false;
    }
    if !scope_uids.is_empty() && !denial.uid.is_some_and(|uid| scope_uids.contains(&uid)) {
        return false;
    }
    true
}

fn emit_selinux_denial(
    denial: &mut neutron::selinux::SelinuxDenial,
    causal: Option<&CausalMetadata>,
    lookback: Option<&mut RingBufferStore>,
    out: &mut dyn IoWrite,
    json_mode: bool,
    event_id_counter: &mut u64,
) -> io::Result<()> {
    *event_id_counter = event_id_counter.wrapping_add(1);
    denial.event_id = Some(*event_id_counter);
    let mut line = serde_json::to_string(denial).expect("serializing SELinux denial cannot fail");
    if let Some(metadata) = causal {
        line = enrich_json(&line, metadata).map_err(io::Error::other)?;
    }
    if json_mode {
        writeln!(out, "{line}")?;
    } else {
        writeln!(
            out,
            "[selinux] {} pid={} {} {}:{} {{ {} }}{}",
            denial.result,
            denial.pid,
            denial.source_domain,
            denial.target_type,
            denial.tclass,
            denial.permissions.join(" "),
            denial
                .path
                .as_deref()
                .map(|path| format!(" path={path}"))
                .unwrap_or_default(),
        )?;
    }
    if let Some(lookback) = lookback {
        lookback.record(denial.pid, &line);
    }
    Ok(())
}

fn live_marker_line(
    request: &neutron::causal::MarkRequest,
    scenario: &ScenarioInfo,
    ts_ns: u64,
    root_package: Option<&str>,
    root_uid: Option<u32>,
    root_pid: Option<u32>,
) -> String {
    let mut value = serde_json::json!({
        "type": "marker",
        "ts_ns": ts_ns,
        "name": request.name,
        "phase": request.phase,
        "scenario_id": scenario.scenario_id,
        "trace_id": neutron::causal::format_id(scenario.trace_id),
        "generation": scenario.generation,
        "meta": request.meta,
    });
    if let (Some(package), Some(object)) = (root_package, value.as_object_mut()) {
        object.insert(
            "root_package".into(),
            serde_json::Value::String(package.into()),
        );
    }
    if let (Some(uid), Some(object)) = (root_uid, value.as_object_mut()) {
        object.insert("root_uid".into(), serde_json::Value::from(uid));
    }
    if let (Some(pid), Some(object)) = (root_pid, value.as_object_mut()) {
        object.insert("root_pid".into(), serde_json::Value::from(pid));
    }
    serde_json::to_string(&value).expect("serializing marker JSON cannot fail")
}

struct PendingScenarioEnd {
    pending: PendingMark,
    request: MarkRequest,
    scenario: ScenarioInfo,
    settle_until: std::time::Instant,
    cleanup_complete: bool,
}

// ── Crash-correlation emit helper (sprint-2 PR 1) ────────────────────────────

/// Emit a single `ProcessExitEvent` through the same pipeline that handles
/// raw events: stamp event_id, dump lookback into `crash_context`, feed the
/// rule engine, write the formatted line. Used by all three crash sources.
#[allow(clippy::too_many_arguments)]
fn emit_process_exit(
    ev: &ProcessExitEvent,
    lookback: Option<&mut RingBufferStore>,
    engine: &mut Option<neutron_rules::RuleEngine>,
    out: &mut dyn IoWrite,
    suppress_raw: bool,
    json_mode: bool,
    event_id_counter: &mut u64,
    causal: Option<&CausalMetadata>,
) -> io::Result<()> {
    let ctx = lookback.map(|lb| lb.take(ev.pid)).unwrap_or_default();
    *event_id_counter = event_id_counter.wrapping_add(1);
    let mut line = format_process_exit_json(ev, &ctx, Some(*event_id_counter));
    if let Some(metadata) = causal {
        line = enrich_json(&line, metadata).map_err(io::Error::other)?;
    }
    if let Some(eng) = engine.as_mut() {
        if let Some(owned) = neutron_rules::Event::parse_line(&line) {
            if let Some(view) = owned.view() {
                eng.feed(&view);
            }
        }
    }
    if !suppress_raw {
        // process_exit lines are always JSON-shaped; in text mode print a
        // one-line summary so non-JSON consumers still see crashes.
        let printed = if json_mode {
            line
        } else {
            format!(
                "[exit] pid={} comm={} class={} signal={} source={}",
                ev.pid,
                ev.comm,
                ev.classify().as_str(),
                ev.exit_signal,
                ev.source.as_str(),
            )
        };
        writeln!(out, "{printed}")?;
    }
    Ok(())
}

// ── Binder-causality emit helper (sprint-2 PR 2) ─────────────────────────────

/// Emit a synthesised `binder_call` event through the same pipeline as raw
/// events: stamp event_id, feed the rule engine, write the formatted line,
/// and (optionally) push it into the lookback ring buffer for the caller's
/// PID so subsequent crash events surface the binder activity in their
/// `crash_context`.
#[allow(clippy::too_many_arguments)]
fn emit_binder_call(
    pair: &neutron::sources::binder_tracker::BinderCallEvent,
    lookback: Option<&mut RingBufferStore>,
    engine: &mut Option<neutron_rules::RuleEngine>,
    out: &mut dyn IoWrite,
    suppress_raw: bool,
    json_mode: bool,
    event_id_counter: &mut u64,
    services: &BinderServiceMap,
    catalog: &BinderCatalog,
    methods: &BinderMethodMap,
    aidl: Option<&AidlCatalog>,
    causal: Option<&CausalMetadata>,
) -> io::Result<()> {
    *event_id_counter = event_id_counter.wrapping_add(1);
    let attribution = catalog
        .resolve_with_aidl(
            services,
            methods,
            aidl,
            pair.callee_pid,
            pair.target_node,
            pair.code,
        )
        .expect("legacy method conflicts are validated before tracing");
    let mut line =
        format_binder_call_json_with_attribution(pair, Some(*event_id_counter), &attribution);
    if let Some(metadata) = causal {
        line = enrich_json(&line, metadata).map_err(io::Error::other)?;
    }
    if let Some(eng) = engine.as_mut() {
        if let Some(owned) = neutron_rules::Event::parse_line(&line) {
            if let Some(view) = owned.view() {
                eng.feed(&view);
            }
        }
    }
    if !suppress_raw {
        let printed = if json_mode {
            line.clone()
        } else {
            format!(
                "[binder] {}->{} code={} status={}{}",
                pair.caller_pid,
                pair.callee_pid,
                pair.code,
                pair.status.as_str(),
                pair.latency_us()
                    .map(|l| format!(" lat_us={l}"))
                    .unwrap_or_default(),
            )
        };
        writeln!(out, "{printed}")?;
    }
    if let Some(lb) = lookback {
        // Record the pair against the *caller* PID so a later caller-side
        // crash carries the binder activity in its lookback. Callee-side
        // crashes already trigger the on_callee_crash drain.
        lb.record(pair.caller_pid, &line);
    }
    Ok(())
}

// ── Main ─────────────────────────────────────────────────────────────────────

fn maturity_warning_for(
    command: Option<&Command>,
    legacy_trace_json: bool,
    stderr_is_terminal: bool,
) -> Option<&'static str> {
    let machine_readable_stream = match command {
        Some(Command::Trace(args)) => args.json,
        Some(Command::Doctor(args)) => args.json,
        None => legacy_trace_json,
        _ => false,
    };
    if machine_readable_stream || !stderr_is_terminal {
        return None;
    }
    match command {
        Some(command) => command.maturity().warning(),
        None => CommandMaturity::Preview.warning(),
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.version {
        if cli.args.verbose {
            println!("{}", neutron::build_info::verbose_version());
        } else {
            println!("neutron {}", env!("CARGO_PKG_VERSION"));
        }
        return Ok(());
    }
    let maturity_warning = maturity_warning_for(
        cli.command.as_ref(),
        cli.args.json,
        io::stderr().is_terminal(),
    );
    if let Some(warning) = maturity_warning {
        eprintln!("warning: {warning}");
    }
    match cli.command {
        Some(Command::Trace(args)) => run_trace(*args),
        Some(Command::Doctor(args)) => {
            std::process::exit(doctor::run_with_args(&args));
        }
        Some(Command::SelfInfo(args)) => {
            if args.json {
                println!(
                    "{}",
                    neutron::build_info::self_info_json_with_bpf_objects(&args.bpf_objects)?
                );
            } else {
                println!("{}", neutron::build_info::verbose_version());
            }
            Ok(())
        }
        Some(Command::Evidence(command)) => neutron::evidence::run(command),
        Some(Command::Window(args)) => neutron::window::run(args),
        Some(Command::Summarize(args)) => neutron::summarize::run(args),
        Some(Command::Diff(args)) => neutron::diff::run(args),
        Some(Command::Report(args)) => neutron::report::run_report(args),
        Some(Command::BinderMap(command)) => neutron::report::run_binder_map(command),
        Some(Command::Mark(args)) => neutron::mark::run(args),
        Some(Command::Graph(args)) => neutron::graph::run(args),
        Some(Command::Surface(command)) => neutron::surface::run(command),
        Some(Command::Recipes(command)) => neutron::recipes::run(command),
        Some(Command::Ioctl(IoctlCommand::Generate(args))) => {
            neutron::ioctl_schema::generate(&args)
        }
        Some(Command::Harness(HarnessCommand::Extract(args))) => neutron::harness::extract(args),
        Some(Command::Harness(HarnessCommand::Build(args))) => neutron::harness::build(args),
        Some(Command::Harness(HarnessCommand::Minimize(args))) => neutron::harness::minimize(args),
        Some(Command::Harness(HarnessCommand::Replay(args))) => neutron::harness::replay(args),
        Some(Command::Aidl(AidlCommand::Index(args))) => neutron::aidl::run_index(args),
        Some(Command::Aidl(AidlCommand::Decode(args))) => neutron::aidl::run_decode(args),
        Some(Command::Research(args)) => std::process::exit(neutron::research::run(args)),
        Some(Command::NativeMap(args)) => neutron::native::run_native_map(args),
        Some(Command::GhidraExport(args)) => neutron::native::run_ghidra_export(args),
        Some(Command::Selinux(command)) => neutron::selinux::run(command),
        None => run_trace(cli.args),
    }
}

fn validate_harness_capture_args(args: &Args) -> Result<()> {
    if !args.harness_capture {
        return Ok(());
    }
    if args.package.is_none() && args.pid == 0 {
        bail!("--harness-capture requires --package or a non-zero --pid");
    }
    if args.output.is_none() {
        bail!("--harness-capture requires --output");
    }
    if args.sample.is_some_and(|sample| sample != 1.0) || args.rate_limit.is_some() {
        bail!("--harness-capture cannot be combined with sampling or rate limiting");
    }
    Ok(())
}

fn validate_distinct_output_paths(
    output: Option<&str>,
    health_output: Option<&str>,
    rotation_enabled: bool,
) -> Result<()> {
    let (Some(output), Some(health_output)) = (output, health_output) else {
        return Ok(());
    };
    let output = resolved_output_path(output)?;
    let health_output = resolved_output_path(health_output)?;
    if output == health_output {
        bail!("--output and --health-output must name different files");
    }
    if rotation_enabled && is_rotation_segment(&output, &health_output) {
        bail!("--health-output must be outside the --output rotation namespace");
    }
    Ok(())
}

fn is_rotation_segment(base: &Path, candidate: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;

    if base.parent() != candidate.parent() {
        return false;
    }
    let (Some(base), Some(candidate)) = (base.file_name(), candidate.file_name()) else {
        return false;
    };
    let base = base.as_bytes();
    let candidate = candidate.as_bytes();
    candidate.len() > base.len() + 1
        && candidate.starts_with(base)
        && candidate[base.len()] == b'.'
        && candidate[base.len() + 1..].iter().all(u8::is_ascii_digit)
}

fn resolved_output_path(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if path.exists() {
        return fs::canonicalize(path)
            .with_context(|| format!("resolving output path {}", path.display()));
    }
    let file_name = path
        .file_name()
        .context("output path must end in a file name")?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(fs::canonicalize(parent)
        .with_context(|| format!("resolving output parent {}", parent.display()))?
        .join(file_name))
}

#[derive(Debug)]
struct PinnedConfiguration {
    content: String,
    sha256: String,
}

fn read_pinned_configuration(path: &str, label: &str) -> Result<PinnedConfiguration> {
    const MAX_CONFIGURATION_BYTES: u64 = 16 * 1024 * 1024;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening {label} for content identity: {path}"))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting {label} for content identity: {path}"))?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        bail!("{label} must be a single-link regular file: {path}");
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!("{label} must be owned by the effective user: {path}");
    }
    if metadata.mode() & 0o022 != 0 {
        bail!("{label} must not be group- or world-writable: {path}");
    }
    if metadata.len() > MAX_CONFIGURATION_BYTES {
        bail!("{label} exceeds the {MAX_CONFIGURATION_BYTES}-byte identity limit");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_CONFIGURATION_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {label} for content identity: {path}"))?;
    if bytes.len() as u64 > MAX_CONFIGURATION_BYTES {
        bail!("{label} exceeds the {MAX_CONFIGURATION_BYTES}-byte identity limit");
    }
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    let content =
        String::from_utf8(bytes).with_context(|| format!("{label} is not valid UTF-8: {path}"))?;
    Ok(PinnedConfiguration { content, sha256 })
}

#[derive(Debug)]
struct TraceRunBundle {
    run_dir: PathBuf,
    run_id: String,
    started_at: String,
}

fn configure_trace_run_bundle(args: &mut Args) -> Result<Option<TraceRunBundle>> {
    let Some(run_dir) = args.run_dir.clone() else {
        return Ok(None);
    };
    if args.output.is_some() || args.health_output.is_some() || args.rotate_output_size.is_some() {
        bail!(
            "--run-dir owns capture.ndjson and capture.health.json and cannot be combined with --output, --health-output, or --rotate-output-size"
        );
    }
    if args.attacker_capability.is_empty()
        || args.attacker_capability.len() > 4096
        || args.attacker_capability.chars().any(char::is_control)
    {
        bail!("--attacker-capability must be a bounded printable string");
    }
    neutron::run_manifest::create_private_run_directory(&run_dir)?;
    let output = run_dir.join("capture.ndjson");
    let health = run_dir.join("capture.health.json");
    args.output = Some(
        output
            .to_str()
            .context("--run-dir must be valid UTF-8")?
            .to_string(),
    );
    args.health_output = Some(
        health
            .to_str()
            .context("--run-dir must be valid UTF-8")?
            .to_string(),
    );
    args.json = true;
    if args.max_output_size.is_none() {
        args.max_output_size = Some("1gb".into());
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    Ok(Some(TraceRunBundle {
        run_dir,
        run_id: format!("trace-{nonce:x}-{}", std::process::id()),
        started_at: neutron::run_manifest::utc_timestamp(),
    }))
}

fn run_trace(mut args: Args) -> Result<()> {
    let trace_bundle = configure_trace_run_bundle(&mut args)?;
    validate_harness_capture_args(&args)?;
    validate_distinct_output_paths(
        args.output.as_deref(),
        args.health_output.as_deref(),
        args.rotate_output_size.is_some(),
    )?;
    if args.harness_capture {
        args.json = true;
        args.raw = true;
    }
    if args.follow_services || args.follow_hal {
        args.follow_binder = true;
    }
    if args.follow_binder {
        args.binder = true;
    }
    if args.package.is_some() || args.root_uid.is_some() {
        // Causal captures are NDJSON evidence streams even when the explicit
        // example omits the legacy output-mode flags.
        args.json = true;
        args.raw = true;
    }
    let follow_ttl = parse_follow_ttl(&args.follow_ttl)?;
    let follow_ttl_ns = u64::try_from(follow_ttl.as_nanos()).context("follow TTL is too large")?;
    if !args.follow_allow_domain.is_empty() || !args.follow_deny_domain.is_empty() {
        bail!(
            "--follow-allow-domain/--follow-deny-domain are not enforceable before first-event BPF admission in 1.5; refusing a privacy-unsafe capture"
        );
    }
    let follow_policy = FollowPolicy::new(
        args.follow_allow_domain.iter(),
        args.follow_deny_domain.iter(),
    )?;
    let user_supplied_match = has_capture_predicate_flags(&args);
    apply_profile(&mut args)?;
    let mut driver_packs = apply_driver_packs_with_defaults(&mut args, !user_supplied_match)?;
    let schema_identity = neutron::ioctl_schema::RuntimeIdentity::current();
    let schema_packs = neutron::ioctl_schema::load_selected_packs(
        &args.schema_pack,
        args.no_schema_auto,
        &schema_identity,
    )?;
    let schema_names: Vec<String> = schema_packs
        .iter()
        .map(|pack| pack.metadata.name.clone())
        .collect();
    let schema_pack_identities: Vec<CaptureContentIdentity> = schema_packs
        .iter()
        .map(|pack| {
            let sha256 = pack
                .content_hash
                .strip_prefix("sha256:")
                .context("verified schema pack content_hash lacks sha256: prefix")?;
            if sha256.len() != 64
                || !sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                bail!("verified schema pack content_hash is not lowercase SHA-256");
            }
            Ok(CaptureContentIdentity {
                name: pack.metadata.name.clone(),
                sha256: sha256.into(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let schema_registry = neutron::ioctl_schema::SchemaRegistry::from_packs(schema_packs)?;
    driver_packs
        .refresh_cmds
        .extend(schema_registry.refresh_cmds());
    if driver_packs.refresh_cmds.len() > 64 {
        bail!(
            "ioctl refresh policy requires {} commands; BPF capacity is 64",
            driver_packs.refresh_cmds.len()
        );
    }
    let harness_schema_registry = args.harness_capture.then(|| schema_registry.clone());
    neutron::ioctl_schema::install_registry(schema_registry);
    let max_output_bytes = parse_output_size_bytes(args.max_output_size.as_deref())?;
    let rotate_output_bytes = parse_rotate_output_size_bytes(args.rotate_output_size.as_deref())?;
    if trace_bundle.is_some()
        && !matches!(
            max_output_bytes,
            Some(bytes) if bytes <= neutron::run_manifest::MAX_LIVE_CAPTURE_BYTES
        )
    {
        bail!("--run-dir requires --max-output-size at or below 1gb");
    }
    if max_output_bytes.is_some() && rotate_output_bytes.is_some() {
        bail!("--max-output-size and --rotate-output-size are mutually exclusive");
    }
    if rotate_output_bytes.is_some() && args.output.is_none() {
        bail!("--rotate-output-size requires --output");
    }

    print_banner();
    let privilege = doctor::check_privilege(&doctor::RealEnv);
    capture_privilege_preflight(&privilege)?;
    doctor::validate_live_capture_layouts(args.binder).map_err(anyhow::Error::msg)?;
    let _capture_lock = acquire_capture_lock(&args.capture_lock)?;
    let capture_boot_id = read_boot_id()?;
    let capture_serial = required_android_property("ro.serialno")?;
    let capture_device_identity = live_device_identity(capture_boot_id.clone(), &capture_serial)?;
    let capture_fingerprint = capture_device_identity.fingerprint.clone();
    let harness_serial = args.harness_capture.then(|| capture_serial.clone());
    let package_uid = args
        .package
        .as_deref()
        .map(|package| {
            android::resolve_package_uid(package)
                .with_context(|| format!("resolving --package {package}"))
        })
        .transpose()?;
    let mut root_pids = if let Some(pids) = discover_dynamic_roots(&args, package_uid)? {
        pids
    } else if args.pid != 0 {
        vec![args.pid]
    } else {
        Vec::new()
    };
    if let (Some(package), Some(uid)) = (args.package.as_deref(), package_uid) {
        if root_pids.is_empty() {
            bail!("no running process matches package {package} (uid {uid})");
        }
    }
    if root_pids.len() > args.max_processes as usize {
        bail!(
            "causal root has {} processes, exceeding --max-processes {}",
            root_pids.len(),
            args.max_processes
        );
    }
    eprintln!("  loading {}", args.object);
    if let Some(package) = args.package.as_deref() {
        eprintln!("  root package: {package}");
    } else if let Some(uid) = args.root_uid {
        eprintln!("  root uid: {uid} ({} current processes)", root_pids.len());
    } else {
        eprintln!(
            "  target pid: {}",
            if args.pid == 0 {
                "all".to_string()
            } else {
                args.pid.to_string()
            }
        );
    }
    if args.pid == 0 && args.package.is_none() && args.root_uid.is_none() {
        eprintln!("  note: tracing all processes; inflight map may overflow under heavy load");
    }
    if !driver_packs.names.is_empty() {
        eprintln!("  driver packs: {}", driver_packs.names.join(", "));
    }
    if !schema_names.is_empty() {
        eprintln!("  ioctl schema packs: {}", schema_names.join(", "));
    }
    resolve_match_android_providers(&mut args)?;
    resolve_match_packages(&mut args)?;
    for warning in capture_guardrail_warnings(&args) {
        eprintln!("neutron: WARNING: {warning}");
    }
    // `--pages` is deprecated as of CORE V1 (RingBuf size is fixed in the BPF
    // object). Silently ignored — kept only for CLI backward compatibility.
    let _ = args.pages;

    // 1. Load BPF and attach tracepoints.
    let mut required_bpf_features = BPF_FEATURE_PROCESS_EXIT;
    if args.binder {
        required_bpf_features |= BPF_FEATURE_BINDER_TRACE;
    }
    if args.stacks {
        required_bpf_features |= BPF_FEATURE_STACKS;
    }
    let (mut bpf, bpf_identity) = load_bpf(
        &args.object,
        args.max_processes,
        args.verbose,
        required_bpf_features,
    )?;
    eprintln!(
        "  BPF ABI: v{}.{} event_size={} object_sha256={}",
        bpf_identity.abi_major,
        bpf_identity.abi_minor,
        bpf_identity.syscall_event_size,
        bpf_identity.object_sha256,
    );
    if !bpf_identity.build_id_present {
        eprintln!("neutron: WARNING: BPF object build ID is unavailable");
    }
    let tool_identity = neutron::run_manifest::ToolIdentity::current()
        .context("identifying the running userspace binary")?;
    let stack_traces = if args.stacks {
        let stack_map = bpf.take_map("STACK_TRACES").with_context(|| {
            format!(
                "--stacks requires a STACK_TRACES map; use {STACKFUL_BPF_OBJECT} or rebuild with `cargo xtask build-ebpf --stacks`"
            )
        })?;
        Some(
            StackTraceMap::try_from(stack_map)
                .context("STACK_TRACES has an incompatible map layout")?,
        )
    } else {
        None
    };

    // Configure PID/causal gates before any global tracepoint is attached so
    // the short loader setup window cannot capture unrelated processes.
    populate_filter_map(
        &mut bpf,
        args.pid,
        args.package.is_some() || args.root_uid.is_some(),
        args.follow_binder,
        args.max_depth,
        args.root_uid.or(package_uid),
        args.root_uid.is_some(),
    )?;
    let pre_admission_follow_denies = pre_admission_follow_deny_domains(&args)?;
    let seeded_follow_denies =
        seed_pre_admission_follow_denies(&mut bpf, &pre_admission_follow_denies)?;
    if seeded_follow_denies > 0 {
        eprintln!(
            "  pre-admission Binder follow denies: {seeded_follow_denies} PID(s) in {}",
            pre_admission_follow_denies
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    set_root_uid_context(&mut bpf, 0, 0)?;
    replace_causal_roots(&mut bpf, &root_pids, 0, 0)?;
    populate_ioctl_refresh_maps(&mut bpf, &driver_packs)?;
    let capture_predicate = build_capture_predicate(&args)?;
    let (selinux_scope_pids, selinux_scope_uids) = capture_predicate
        .bpf_spec()
        .map(|spec| (spec.pids.clone(), spec.uids.clone()))
        .unwrap_or_default();
    if let Some(bpf_spec) = capture_predicate.bpf_spec() {
        populate_match_maps(&mut bpf, bpf_spec)?;
    }
    if capture_predicate.needs_state_events_via_ast() {
        let map = bpf.map_mut("FILTER_MAP").context("FILTER_MAP missing")?;
        let mut filter: Array<_, u32> =
            Array::try_from(map).context("FILTER_MAP is not Array<u32>")?;
        filter
            .set(FILTER_KEY_STATE_EMIT_REQUIRED, 1u32, 0)
            .context("FILTER_MAP[STATE_EMIT_REQUIRED]=1")?;
    }

    attach_tracepoint(&mut bpf, "trace_sys_enter", "raw_syscalls", "sys_enter")?;
    attach_tracepoint(&mut bpf, "trace_sys_exit", "raw_syscalls", "sys_exit")?;
    attach_tracepoint(
        &mut bpf,
        "trace_sched_process_exit",
        "sched",
        "sched_process_exit",
    )?;
    let mut attached = vec![
        "trace_sys_enter",
        "trace_sys_exit",
        "trace_sched_process_exit",
    ];
    if args.binder {
        attach_tracepoint(
            &mut bpf,
            "trace_binder_transaction",
            "binder",
            "binder_transaction",
        )?;
        attached.push("trace_binder_transaction");
        attach_tracepoint(
            &mut bpf,
            "trace_binder_transaction_received",
            "binder",
            "binder_transaction_received",
        )?;
        attached.push("trace_binder_transaction_received");
    }
    let kprobe_packs = attach_kprobe_packs(&mut bpf, &args.kprobe_pack, &mut attached)?;

    // 2. Phase 1a/1b — the capture predicate was pushed before attach. Print
    // its split BPF/userspace audit now that setup succeeded.
    let audit = capture_predicate.audit_lines();
    if !audit.is_empty() {
        eprintln!("  match predicate (Phase 1):");
        for line in audit {
            eprintln!("    {line}");
        }
        if capture_predicate
            .bpf_spec()
            .is_some_and(|s| s.needs_state_events())
            || capture_predicate.needs_state_events_via_ast()
        {
            eprintln!(
                "    [bpf]  state-tracking syscalls bypass later match gates \
                 only after syscall-whitelist admission; lifecycle state may be incomplete"
            );
        }
        if let Some(spec) = capture_predicate.bpf_spec() {
            warn_likely_shell_expansion("--match-fd", &spec.fd_globs);
            warn_likely_shell_expansion("--match-comm", &spec.comm_globs);
        }
    }

    // 2c. Phase 1c — capture mode (`--capture matched+context=<DUR>`).
    let capture_mode = CaptureMode::from_cli(args.capture.as_deref())?;
    let mut context_ring: Option<ContextRing> = match capture_mode {
        CaptureMode::Default => None,
        CaptureMode::MatchedWithContext { duration_ns } => {
            eprintln!(
                "  capture mode: matched+context={}ms (forward+backward)",
                duration_ns / 1_000_000
            );
            Some(ContextRing::new(duration_ns, DEFAULT_MAX_EVENTS))
        }
    };

    // 2d. Phase 1d — sampling and rate limiting. Admitted state-tracking
    // syscalls bypass both inside `SamplerChain`; an earlier active syscall
    // whitelist can still make fdgraph state incomplete.
    let mut sampler = SamplerChain::from_args(args.sample, args.rate_limit)?;

    // 2e. Phase 4b — optional binder service descriptor map for
    // `binder_call` enrichment.
    let binder_services_config = args
        .binder_services
        .as_deref()
        .map(|path| read_pinned_configuration(path, "Binder service map"))
        .transpose()?;
    let binder_services: BinderServiceMap = match (&args.binder_services, &binder_services_config) {
        (Some(path), Some(config)) => {
            let m = BinderServiceMap::from_json(&config.content)
                .with_context(|| format!("parsing Binder service map: {path}"))?;
            eprintln!("  binder service map: {} entries from {path}", m.len());
            m
        }
        (None, None) => BinderServiceMap::default(),
        _ => unreachable!("Binder service configuration presence is derived from its path"),
    };
    let binder_methods_config = args
        .binder_methods
        .as_deref()
        .map(|path| read_pinned_configuration(path, "Binder method map"))
        .transpose()?;
    let binder_methods = match (&args.binder_methods, &binder_methods_config) {
        (Some(path), Some(config)) => {
            let methods = BinderMethodMap::from_json(&config.content)
                .with_context(|| format!("parsing Binder method map: {path}"))?;
            eprintln!("  binder method map: {} entries from {path}", methods.len());
            methods
        }
        (None, None) => BinderMethodMap::default(),
        _ => unreachable!("Binder method configuration presence is derived from its path"),
    };
    let aidl_catalog_config = args
        .aidl_catalog
        .as_deref()
        .map(|path| read_pinned_configuration(path, "AIDL catalog"))
        .transpose()?;
    let aidl_catalog = match (&args.aidl_catalog, &aidl_catalog_config) {
        (Some(path), Some(config)) => Some(
            AidlCatalog::from_json(&config.content)
                .with_context(|| format!("validating AIDL catalog: {path}"))?,
        ),
        (None, None) => None,
        _ => unreachable!("AIDL configuration presence is derived from its path"),
    };
    if let Some(catalog) = &aidl_catalog {
        binder_methods.validate_catalog(catalog)?;
        eprintln!(
            "  AIDL catalog: {} interfaces from {}",
            catalog.interfaces.len(),
            args.aidl_catalog.as_deref().expect("catalog path present")
        );
    }
    let mut binder_catalog = BinderCatalog::discover(args.follow_services, args.follow_hal)
        .context("discovering initial Binder service/HAL inventory")?;
    let initial_service_inventory_sha256 = binder_catalog
        .service_inventory_sha256()
        .map(str::to_string);
    let initial_hal_inventory_sha256 = binder_catalog.hal_inventory_sha256().map(str::to_string);
    let mut binder_discovery_failures = 0_u64;
    let mut binder_discovery_drift = 0_u64;
    let mut discovery_seen_pids = HashSet::<u32>::new();
    let mut discovery_refresh_pending = false;
    let mut last_discovery_refresh = std::time::Instant::now();
    if !sampler.is_passthrough() {
        if let Some(p) = args.sample {
            eprintln!("  sample: p={p:.3} (state-tracking syscalls exempt)");
        }
        if let Some(n) = args.rate_limit {
            eprintln!("  rate-limit: {n} events/sec (state-tracking syscalls exempt)");
        }
    }

    // 3. Build rule engine.
    let rules_config = if args.no_findings {
        None
    } else {
        args.rules
            .as_deref()
            .map(|path| read_pinned_configuration(path, "ruleset"))
            .transpose()?
    };
    let rules_sha256 = if args.no_findings {
        None
    } else if let Some(config) = &rules_config {
        Some(config.sha256.clone())
    } else {
        Some(format!(
            "{:x}",
            Sha256::digest(neutron_rules::builtin::DEFAULT_RULES_YAML.as_bytes())
        ))
    };
    let mut engine = build_rule_engine_from_yaml(
        &args,
        args.rules
            .as_deref()
            .zip(rules_config.as_ref())
            .map(|(path, config)| (path, config.content.as_str())),
    )?;
    let suppress_raw = engine.is_some() && !args.raw;
    let drain_interval = args.findings_drain_interval.max(1);
    let mut events_since_drain: u64 = 0;

    eprintln!("  attached: {}", attached.join(", "));

    // 4. Set up the ring buffer consumer (must happen after attach).
    let events_map = bpf
        .take_map("EVENTS")
        .context("EVENTS map missing from BPF object")?;
    let mut ring: RingBuf<_> = RingBuf::try_from(events_map).context("EVENTS is not a RingBuf")?;
    let ring_fd = ring.as_raw_fd();
    if args.verbose {
        eprintln!("  ring buffer: 1 producer (kernel) → 1 consumer (this loop)");
    }

    // 5. Stack-trace map (immutable read borrow used per event).
    //    We borrow this immutably from `bpf` later when needed. For the event
    //    loop we keep a re-acquired binding per drain to avoid holding `bpf`.

    // 6. Output sink.
    let output_cap_hit = Arc::new(AtomicBool::new(false));
    let mut output_cap_reported = false;
    let harness_capture = match (harness_schema_registry, args.output.as_deref()) {
        (Some(registry), Some(path)) => Some(neutron::harness::CaptureWriter::new(
            Path::new(path),
            registry,
            neutron::harness::CaptureIdentity {
                serial: harness_serial,
                fingerprint: capture_fingerprint.clone(),
                boot_id: Some(capture_boot_id.clone()),
                uid: package_uid.or(args.root_uid).unwrap_or(0),
                domain: None,
            },
        )?),
        (Some(_), None) => bail!("--harness-capture requires --output"),
        (None, _) => None,
    };
    let output_records = Arc::new(AtomicU64::new(0));
    let output = open_output(
        args.output.as_ref(),
        max_output_bytes,
        rotate_output_bytes,
        output_cap_hit.clone(),
    )?;
    let mut out: Box<dyn IoWrite> =
        Box::new(RecordCountingWriter::new(output, output_records.clone()));

    // 7. Ctrl-C handler.
    let running = Arc::new(AtomicBool::new(true));
    install_shutdown_signals(running.clone());

    let control_server = if args.control_socket.eq_ignore_ascii_case("off") {
        None
    } else {
        let server = ControlServer::bind(&args.control_socket)?;
        eprintln!("  control socket: {} (0600)", args.control_socket);
        Some(server)
    };
    let mut scenarios = ScenarioState::default();
    // The sched tracepoint cannot expose the fatal signal. Preserve its
    // causal span briefly so the later logcat/tombstone observation can
    // enrich the same graph node with SIGSEGV/SIGABRT classification even
    // though BPF has already removed the dying PID from its dynamic map.
    let mut recent_exit_causal = HashMap::<u32, RecentExitCausal>::new();
    let mut followed_last_hop_ns = BTreeMap::<u32, u64>::new();
    let mut policy_blocked_pids = HashSet::<u32>::new();
    let mut follow_policy_filtered = 0_u64;
    let mut follow_ttl_expired = 0_u64;
    let mut marker_transition_error = None;
    let mut last_root_refresh = std::time::Instant::now();

    eprintln!("  tracing… Ctrl-C to stop\n");

    // 8. Event loop.
    //
    // Single multi-producer ring buffer — `RingBuf::next()` returns one record
    // at a time. We drain the ring greedily, then `poll(2)` for readability
    // when it goes empty (kernel signals via POLLIN).
    let ev_size = std::mem::size_of::<SyscallEvent>();
    // Per-PID symbolizer cache. `None` means we tried and failed to read
    // `/proc/<pid>/maps` (process exited, or insufficient permissions).
    let mut proc_sym_cache: HashMap<u32, Option<ProcSymbolizer>> = HashMap::new();
    let mut native_capture = neutron::native::CaptureNativeState::default();
    // Build the kernel-side resolver once. Two layers: kallsyms gives
    // `name+0x<offset>` when readable; /proc/modules still gives
    // `[<ko>]+0x<offset>` when kptr_restrict masks kallsyms. Phase 5b.
    let kernel_resolver: Option<KernelResolver> = if args.stacks {
        let r = KernelResolver::load();
        if r.is_blind() {
            None
        } else {
            Some(r)
        }
    } else {
        None
    };
    if args.verbose {
        match kernel_resolver.as_ref() {
            Some(r) => {
                let k = r.kallsyms.as_ref().map(|k| k.len()).unwrap_or(0);
                let m = r.modules.as_ref().map(|m| m.len()).unwrap_or(0);
                eprintln!(
                    "  kernel resolver: {k} kallsyms + {m} module ranges{}",
                    if k == 0 {
                        " (kallsyms masked; modules-only fallback)"
                    } else {
                        ""
                    }
                );
            }
            None if args.stacks => {
                eprintln!(
                    "  kernel resolver: unavailable (kptr_restrict + no modules) — \
                     kernel frames stay hex"
                );
            }
            _ => {}
        }
    }
    let mut total_events: u64 = 0;
    let mut invalid_ring_records: u64 = 0;
    let mut stack_read_failures: u64 = 0;
    // Phase-1 pipeline counters surfaced in the final capture summary
    // and the `capture_health` JSON line. The 2026-05-06 device test
    // asked for matched / sampled-out / emitted as separate buckets so
    // an operator can see how a `--match-*` configuration shaped the
    // trace.
    let mut events_matched: u64 = 0;
    let mut events_sampled_out: u64 = 0;
    let mut logcat_untrusted_native_exits: u64 = 0;
    let mut tombstone_unmatched_in_scope: u64 = 0;
    let mut tombstone_out_of_scope: u64 = 0;
    let mut fd_poller_samples_consumed: u64 = 0;
    let mut ring_poll_error = None;
    // Session-scoped monotonic correlation token stamped onto every emitted
    // JSON line as `"event_id":N`. Resets on neutron restart — consumers must
    // not assume cross-session uniqueness. Used by the rule engine and (in
    // upcoming sprints) the binder-causality and raw-on-finding correlators.
    let mut event_id_counter: u64 = 0;
    // Userspace FD graph: tracks (pid, fd) → resource so ioctl/read/write/mmap
    // events can be enriched with `fd_kind`, `fd_path`. Updated every event;
    // miss/backfill counts are surfaced in the capture summary on exit.
    let mut fd_graph = FdGraph::new();

    // ── FD poller (sprint-1 PR 3) ────────────────────────────────────────
    //
    // Spawn a separate thread that periodically reads /proc/<pid>/fd and
    // /proc/<pid>/limits for in-scope PIDs and forwards FdSampleEvent
    // values through an mpsc::sync_channel. Each sample becomes a
    // `type:"fd_snapshot"` JSON line and feeds the rule engine.
    //
    // The "active" set (PIDs that have produced any traced event since
    // startup) is the default scope — keeping the poller off broad /proc
    // scans under `--pid 0`. We send a fresh copy of the set whenever it
    // grows; the poller drains updates non-blockingly.
    let scope = ScopePolicy::from_str(&args.fdgraph_pids).map_err(anyhow::Error::msg)?;
    let interval = parse_fdgraph_interval(&args.fdgraph_interval)?;
    let mut active_pids: HashSet<u32> = root_pids.iter().copied().collect();
    let mut watched_sensitive_fds = HashSet::<u64>::new();
    let mut follow_children_map_failures = 0_u64;
    let mut watch_fds_map_failures = 0_u64;
    let poller_state: Option<(_, _, _, _)> = match interval {
        Some(dt) => {
            let cfg = PollerConfig {
                interval: dt,
                scope,
                target_pid: args.pid,
                top_paths_n: args.fdgraph_top_paths_n,
            };
            if args.verbose {
                eprintln!(
                    "  fdgraph poller: interval={:?}, scope={:?}, top_paths_n={}",
                    cfg.interval, cfg.scope, cfg.top_paths_n
                );
            }
            let (samples_rx, active_tx, stop_tx, handle) =
                poller::spawn(cfg, Box::new(RealProcReader))?;
            // Seed the poller's view with the initial active set so the
            // explicit --pid target is sampled on the very first tick.
            let _ = active_tx.try_send(active_pids.clone());
            Some((samples_rx, active_tx, stop_tx, handle))
        }
        None => None,
    };

    // ── Crash correlation (sprint-2 PR 1) ────────────────────────────────
    //
    // Lookback ring buffer captures every emitted JSON line per PID. On a
    // process_exit event (from any source) the buffer is dumped into the
    // crash_context field of the emitted JSON. Bounded — see lookback.rs.
    let mut lookback: Option<RingBufferStore> = if args.lookback_events == 0 {
        None
    } else {
        Some(RingBufferStore::new(200, args.lookback_events))
    };
    if let Some(lb) = lookback.as_ref() {
        if args.verbose {
            eprintln!(
                "  lookback: max_pids={}, max_lines_per_pid={}",
                lb.max_pids(),
                lb.max_lines_per_pid()
            );
        }
    }

    // Tombstone watcher — only spawned when the configured directory exists
    // and is readable. On hosts without `/data/tombstones/` we silently skip
    // (the watcher would otherwise log "ENOENT" every poll).
    let tombstone_source_enabled = !args.tombstone_dir.is_empty();
    let mut tombstone_watcher: Option<RealTombstoneWatcher> = if !tombstone_source_enabled {
        None
    } else {
        let w = RealTombstoneWatcher::with_dir(&args.tombstone_dir);
        if w.dir_available() {
            let mut w = w;
            if let Err(error) = w.prime() {
                eprintln!(
                    "neutron: WARNING: tombstone baseline failed for {} ({error}); capture health will be unknown",
                    args.tombstone_dir
                );
            }
            if args.verbose {
                eprintln!("  tombstone watcher: polling {}", args.tombstone_dir);
            }
            Some(w)
        } else {
            if args.verbose {
                eprintln!(
                    "  tombstone watcher: {} not present — skipped",
                    args.tombstone_dir
                );
            }
            None
        }
    };

    // ── Binder causality (sprint-2 PR 2) ─────────────────────────────────
    //
    // Userspace correlator pairs caller-side `binder_transaction` events
    // (BPF nr=-1) with callee-side `binder_transaction_received` (BPF
    // nr=-4) by the `debug_id` carried in `ptr_hint`. On match the loop
    // emits a synthetic `type:"binder_call"` line; on callee crash
    // (process_exit with classification=crash) any in-flight transactions
    // for that PID are emitted with `status:"callee_crashed"`.
    let mut binder_tracker: Option<BinderTracker> = if args.binder_inflight == 0 {
        None
    } else {
        Some(BinderTracker::new(args.binder_inflight))
    };
    if let Some(t) = binder_tracker.as_ref() {
        if args.verbose {
            eprintln!("  binder tracker: max_inflight={}", t.max_inflight());
        }
    }

    // Logcat tail — Android-only. On hosts the spawn fails with ENOENT
    // (`logcat` not in PATH); we degrade gracefully.
    let logcat_source_enabled = !args.no_logcat;
    let mut logcat_reader: Option<RealLogcatReader> = if !logcat_source_enabled {
        None
    } else {
        match RealLogcatReader::spawn() {
            Ok(mut r) => {
                if let Err(error) = r.prime(monotonic_timestamp_ns()) {
                    eprintln!(
                        "neutron: WARNING: logcat baseline failed ({error}); capture health will be unknown"
                    );
                }
                if args.verbose {
                    eprintln!("  logcat tail: spawned");
                }
                Some(r)
            }
            Err(e) => {
                if args.verbose {
                    eprintln!("  logcat tail: spawn failed ({e}) — skipped");
                }
                None
            }
        }
    };
    let selinux_source_enabled = !args.no_logcat;
    let mut selinux_reader: Option<SelinuxLogcatReader> = if args.no_logcat {
        None
    } else {
        match SelinuxLogcatReader::spawn() {
            Ok(mut reader) => {
                if let Err(error) = reader.prime(monotonic_timestamp_ns()) {
                    eprintln!(
                        "neutron: WARNING: SELinux logcat baseline failed ({error}); capture health will be unknown"
                    );
                }
                if args.verbose {
                    eprintln!("  SELinux AVC logcat tail: spawned");
                }
                Some(reader)
            }
            Err(error) => {
                eprintln!(
                    "neutron: WARNING: SELinux AVC logcat source unavailable ({error}); capture health will be degraded"
                );
                None
            }
        }
    };

    let initial_logcat_available = logcat_reader
        .as_mut()
        .is_some_and(RealLogcatReader::is_available);
    let initial_selinux_available = selinux_reader
        .as_mut()
        .is_some_and(SelinuxLogcatReader::is_available);
    let initial_tombstone_available = tombstone_watcher
        .as_ref()
        .is_some_and(|watcher| watcher.runtime_state().primed && watcher.runtime_state().available);
    let mut capture_scope = effective_capture_scope(
        &args,
        &capture_predicate,
        capture_mode,
        suppress_raw,
        engine.is_some(),
        max_output_bytes,
        rotate_output_bytes,
        args.root_uid.or(package_uid),
        follow_ttl_ns,
        &driver_packs.names,
        &kprobe_packs,
        &schema_names,
        &schema_pack_identities,
        rules_sha256.as_deref(),
        binder_services_config
            .as_ref()
            .map(|config| config.sha256.as_str()),
        binder_methods_config
            .as_ref()
            .map(|config| config.sha256.as_str()),
        aidl_catalog_config
            .as_ref()
            .map(|config| config.sha256.as_str()),
        initial_service_inventory_sha256.as_deref(),
        initial_hal_inventory_sha256.as_deref(),
        &bpf_identity,
        &tool_identity,
        poller_state.is_some(),
        initial_logcat_available,
        initial_selinux_available,
        initial_tombstone_available,
    );

    let mut pending_scenario_end: Option<PendingScenarioEnd> = None;
    let mut scenario_inflight_discarded = 0_u64;
    let mut scenario_context_discarded = 0_u64;
    let mut scenario_context_baseline_discarded = 0_u64;
    while running.load(Ordering::Relaxed) {
        if pending_scenario_end.is_none() {
            if let Some(server) = control_server.as_ref() {
                while let Some(pending) = server.try_recv()? {
                    let request = pending.request.clone();
                    if request.phase == "end" {
                        let scenario = match scenarios.validate_end(&request.name) {
                            Ok(scenario) => scenario,
                            Err(error) => {
                                if let Err(response_error) =
                                    pending.respond_error(format!("{error:#}"))
                                {
                                    eprintln!(
                                    "neutron: warn: marker client disconnected: {response_error:#}"
                                );
                                }
                                continue;
                            }
                        };
                        let transition = (|| -> Result<u64> {
                            set_root_uid_context(&mut bpf, 0, 0)?;
                            replace_causal_roots(&mut bpf, &root_pids, 0, 0)?;
                            clear_causal_transients(&mut bpf)?;
                            discard_inflight_at_scenario_end(&mut bpf)
                        })();
                        match transition {
                            Ok(discarded) => {
                                scenario_inflight_discarded =
                                    scenario_inflight_discarded.saturating_add(discarded);
                                pending_scenario_end = Some(PendingScenarioEnd {
                                    pending,
                                    request,
                                    scenario,
                                    settle_until: std::time::Instant::now()
                                        + Duration::from_millis(100),
                                    cleanup_complete: false,
                                });
                            }
                            Err(error) => {
                                marker_transition_error = Some(format!(
                                    "scenario end kernel transition failed: {error:#}"
                                ));
                                if let Err(response_error) =
                                    pending.respond_error(format!("{error:#}"))
                                {
                                    eprintln!(
                                    "neutron: warn: marker client disconnected: {response_error:#}"
                                );
                                }
                                running.store(false, Ordering::Relaxed);
                            }
                        }
                        break;
                    }
                    let result: Result<(ScenarioInfo, u64, String)> = (|| {
                        scenarios.validate_start(&request.name)?;
                        if let Some(discovered) = discover_dynamic_roots(&args, package_uid)? {
                            root_pids = discovered;
                        }
                        if root_pids.is_empty() && args.root_uid.is_none() {
                            bail!(
                                "live scenarios require --root-uid, a running --package root, or a non-zero --pid root"
                            );
                        }
                        if root_pids.len() > args.max_processes as usize {
                            bail!(
                                "{} root processes exceed --max-processes {}",
                                root_pids.len(),
                                args.max_processes
                            );
                        }
                        // Validate the transition before these baseline drains:
                        // a rejected nested/duplicate marker must not discard
                        // evidence from the active scenario.
                        if let Some(watcher) = tombstone_watcher.as_mut() {
                            watcher
                                .prime()
                                .context("establishing tombstone baseline before scenario start")?;
                        }
                        if let Some(reader) = logcat_reader.as_mut() {
                            reader
                                .prime(monotonic_timestamp_ns())
                                .context("establishing logcat baseline before scenario start")?;
                        }
                        if let Some(reader) = selinux_reader.as_mut() {
                            reader.prime(monotonic_timestamp_ns()).context(
                                "establishing SELinux logcat baseline before scenario start",
                            )?;
                        }
                        if let Some(ring) = context_ring.as_mut() {
                            scenario_context_baseline_discarded =
                                scenario_context_baseline_discarded
                                    .saturating_add(ring.reset_boundary() as u64);
                        }
                        // The boundary timestamp precedes BPF activation, so
                        // every event stamped with this generation is
                        // monotonically at or after the start marker.
                        let ts_ns = monotonic_timestamp_ns();
                        let scenario = scenarios.start(&request.name)?;
                        if let Err(error) = (|| -> Result<()> {
                            set_root_uid_context(&mut bpf, scenario.trace_id, scenario.generation)?;
                            replace_causal_roots(
                                &mut bpf,
                                &root_pids,
                                scenario.trace_id,
                                scenario.generation,
                            )?;
                            clear_causal_transients(&mut bpf)
                        })() {
                            marker_transition_error = Some(format!(
                                "scenario start kernel transition failed: {error:#}"
                            ));
                            return Err(error);
                        }
                        if let Some(tracker) = binder_tracker.as_mut() {
                            tracker.reset_baseline();
                        }
                        recent_exit_causal.clear();
                        followed_last_hop_ns.clear();
                        policy_blocked_pids.clear();
                        active_pids = root_pids.iter().copied().collect();
                        if let Some((_, active_tx, _, _)) = poller_state.as_ref() {
                            let _ = active_tx.try_send(active_pids.clone());
                        }
                        let line = live_marker_line(
                            &request,
                            &scenario,
                            ts_ns,
                            args.package.as_deref(),
                            args.root_uid.or(package_uid),
                            (args.pid != 0).then_some(args.pid),
                        );
                        Ok((scenario, ts_ns, line))
                    })();
                    let response = match result {
                        Ok((scenario, ts_ns, line)) => match writeln!(out, "{line}") {
                            Ok(()) => {
                                pending.respond_ok(ts_ns, scenario.generation, scenario.trace_id)
                            }
                            Err(error) => {
                                marker_transition_error =
                                    Some(format!("scenario start marker write failed: {error}"));
                                running.store(false, Ordering::Relaxed);
                                pending.respond_error(format!(
                                    "scenario start marker write failed: {error}"
                                ))
                            }
                        },
                        Err(error) => pending.respond_error(format!("{error:#}")),
                    };
                    if let Err(error) = response {
                        eprintln!("neutron: warn: marker client disconnected: {error:#}");
                    }
                    if marker_transition_error.is_some() {
                        running.store(false, Ordering::Relaxed);
                        break;
                    }
                }
            }
        }

        // A camera burst can reveal dozens of new Binder PIDs in one ring
        // drain. Coalesce those observations into one catalog refresh and
        // always service marker requests first; running `service` + `lshal`
        // once per PID can otherwise starve the control socket for minutes.
        if discovery_refresh_pending && last_discovery_refresh.elapsed() >= Duration::from_secs(1) {
            match BinderCatalog::discover(args.follow_services, args.follow_hal) {
                Ok(discovered) => {
                    if discovered.service_inventory_sha256()
                        != initial_service_inventory_sha256.as_deref()
                        || discovered.hal_inventory_sha256()
                            != initial_hal_inventory_sha256.as_deref()
                    {
                        binder_discovery_drift = binder_discovery_drift.saturating_add(1);
                    }
                    binder_catalog = discovered;
                }
                Err(error) => {
                    binder_discovery_failures = binder_discovery_failures.saturating_add(1);
                    if binder_discovery_failures == 1 {
                        eprintln!("neutron: WARNING: Binder inventory refresh failed: {error:#}");
                    }
                }
            }
            discovery_refresh_pending = false;
            last_discovery_refresh = std::time::Instant::now();
        }

        if last_root_refresh.elapsed() >= Duration::from_secs(1) {
            last_root_refresh = std::time::Instant::now();
            if args.package.is_some() || args.root_uid.is_some() {
                match discover_dynamic_roots(&args, package_uid) {
                    Ok(None) => {}
                    Ok(Some(discovered)) if discovered.len() <= args.max_processes as usize => {
                        let previous_roots = root_pids.iter().copied().collect::<BTreeSet<_>>();
                        let (trace_id, generation) = if pending_scenario_end.is_some() {
                            (0, 0)
                        } else {
                            scenarios
                                .active()
                                .map(|scenario| (scenario.trace_id, scenario.generation))
                                .unwrap_or((0, 0))
                        };
                        reconcile_causal_roots(&mut bpf, &discovered, trace_id, generation)?;
                        root_pids = discovered;
                        let current_roots = root_pids.iter().copied().collect::<BTreeSet<_>>();
                        let mut changed = false;
                        for exited_root in previous_roots.difference(&current_roots) {
                            changed |= active_pids.remove(exited_root);
                        }
                        if changed {
                            if let Some((_, active_tx, _, _)) = poller_state.as_ref() {
                                let _ = active_tx.try_send(active_pids.clone());
                            }
                        }
                    }
                    Ok(Some(discovered)) => bail!(
                        "causal root now has {} processes, above --max-processes {}",
                        discovered.len(),
                        args.max_processes
                    ),
                    Err(error) => return Err(error).context("refreshing causal root process set"),
                }
            }
            if args.follow_binder && pending_scenario_end.is_none() && scenarios.active().is_some()
            {
                let roots = root_pids.iter().copied().collect::<BTreeSet<_>>();
                let now_ns = monotonic_timestamp_ns();
                for pid in
                    expired_followed_pids(&followed_last_hop_ns, &roots, now_ns, follow_ttl_ns)
                {
                    followed_last_hop_ns.remove(&pid);
                    policy_blocked_pids.remove(&pid);
                    if active_pids.remove(&pid) {
                        if let Some((_, active_tx, _, _)) = poller_state.as_ref() {
                            let _ = active_tx.try_send(active_pids.clone());
                        }
                    }
                    let Some(context) = remove_followed_process(&mut bpf, pid)? else {
                        continue;
                    };
                    follow_ttl_expired = follow_ttl_expired.saturating_add(1);
                    write_or_output_cap(
                        emit_follow_guardrail(
                            &mut *out,
                            args.json,
                            &mut event_id_counter,
                            "expired",
                            "pid_ttl",
                            context.parent_pid,
                            pid,
                            context.binder_debug_id,
                            context.depth,
                            None,
                            Some(context),
                            &scenarios,
                        ),
                        &output_cap_hit,
                    )?;
                }
            }
        }

        let mut saw_any = false;
        loop {
            let bytes_owned: Vec<u8> = match ring.next() {
                Some(item) => {
                    let slice: &[u8] = &item;
                    if slice.len() != ev_size {
                        invalid_ring_records = invalid_ring_records.saturating_add(1);
                        continue;
                    }
                    slice.to_vec()
                }
                None => break,
            };
            saw_any = true;
            let bytes = bytes_owned;
            {
                // SAFETY: SyscallEvent is #[repr(C, packed)] of plain integers and
                // byte arrays; every 257-byte payload is a valid bit-pattern.
                let ev: SyscallEvent =
                    unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const _) };
                total_events += 1;

                let event_pid = { ev.pid };
                let event_nr = { ev.syscall_nr };
                if event_nr != SYSCALL_NR_PROCESS_EXIT
                    && should_skip_for_exclude_comm(&ev, &args.exclude_comm)
                {
                    continue;
                }
                if event_nr != SYSCALL_NR_PROCESS_EXIT
                    && args.alert_rwx
                    && should_skip_for_alert_rwx(&ev)
                {
                    continue;
                }
                let causal_event = causal_metadata_for_event(
                    &ev,
                    &scenarios,
                    args.package.as_deref(),
                    args.root_uid.or(package_uid),
                );
                if event_nr != SYSCALL_NR_PROCESS_EXIT {
                    // Any post-exit activity proves that this PID has been
                    // reused; stale crash attribution must be discarded.
                    recent_exit_causal.remove(&event_pid);
                }
                if policy_blocked_pids.contains(&event_pid)
                    && event_nr != SYSCALL_NR_BINDER_RECEIVED
                    && event_nr != SYSCALL_NR_PROCESS_EXIT
                    && !root_pids.contains(&event_pid)
                {
                    continue;
                }

                // ── Sprint-2 PR 1: BPF sched_process_exit handoff ────
                //
                // The tracepoint emits a synthetic SyscallEvent with
                // syscall_nr == -3. Convert to a ProcessExitEvent and route
                // through the shared emit path; do NOT format it as a normal
                // syscall JSON line.
                if { ev.syscall_nr } == SYSCALL_NR_PROCESS_EXIT {
                    let args_arr = { ev.args };
                    let pe = ProcessExitEvent {
                        ts_ns: { ev.timestamp_ns },
                        pid: { ev.pid },
                        uid: Some(ev.uid),
                        comm: format_comm(&{ ev.comm }),
                        exit_code: (args_arr[0] & 0xff) as u8,
                        exit_signal: (args_arr[1] & 0xffffffff) as u32,
                        source: ExitSource::from_u8((args_arr[2] & 0xff) as u8)
                            .unwrap_or(ExitSource::Tracepoint),
                    };
                    if active_pids.remove(&pe.pid) {
                        if let Some((_, active_tx, _, _)) = poller_state.as_ref() {
                            let _ = active_tx.try_send(active_pids.clone());
                        }
                    }
                    if args.capture_reads {
                        let map = bpf.map_mut("WATCH_FDS").context("WATCH_FDS missing")?;
                        let mut watch_fds: AyaHashMap<_, u64, u8> = AyaHashMap::try_from(map)
                            .context("WATCH_FDS is not HashMap<u64,u8>")?;
                        for error in cleanup_watched_fds_for_pid(
                            pe.pid,
                            &mut watch_fds,
                            &mut watched_sensitive_fds,
                        ) {
                            watch_fds_map_failures = watch_fds_map_failures.saturating_add(1);
                            if watch_fds_map_failures == 1 {
                                eprintln!("neutron: WARNING: {error}");
                            }
                        }
                    }
                    if let Some(metadata) = causal_event.as_ref() {
                        recent_exit_causal.insert(
                            pe.pid,
                            RecentExitCausal {
                                metadata: metadata.clone(),
                                exit_ts_ns: pe.ts_ns,
                                comm: pe.comm.clone(),
                            },
                        );
                    }
                    // Sprint-2 PR 2: drain in-flight binder transactions
                    // for the dying PID before emitting the exit. Each
                    // drained entry becomes a `binder_call` line with
                    // status=callee_crashed, feeding R004.
                    if pe.classify() == neutron::sources::ExitClassification::Crash {
                        if let Some(t) = binder_tracker.as_mut() {
                            for pair in t.on_callee_crash(pe.pid) {
                                write_or_output_cap(
                                    emit_binder_call(
                                        &pair,
                                        lookback.as_mut(),
                                        &mut engine,
                                        &mut *out,
                                        suppress_raw,
                                        args.json,
                                        &mut event_id_counter,
                                        &binder_services,
                                        &binder_catalog,
                                        &binder_methods,
                                        aidl_catalog.as_ref(),
                                        pair.causal_metadata.as_ref(),
                                    ),
                                    &output_cap_hit,
                                )?;
                            }
                        }
                    }
                    write_or_output_cap(
                        emit_process_exit(
                            &pe,
                            lookback.as_mut(),
                            &mut engine,
                            &mut *out,
                            suppress_raw,
                            args.json,
                            &mut event_id_counter,
                            causal_event.as_ref(),
                        ),
                        &output_cap_hit,
                    )?;
                    if args.pid != 0
                        && args.package.is_none()
                        && args.root_uid.is_none()
                        && pe.pid == args.pid
                    {
                        running.store(false, Ordering::Relaxed);
                        break;
                    }
                    continue;
                }

                // ── Sprint-2 PR 2: binder caller / received tracker ────
                //
                // Caller side (nr=-1) goes into the in-flight map. Callee
                // side (nr=-4) tries to match and emits a binder_call on
                // success. The raw binder / binder_received JSON line is
                // still emitted below so operators can grep low-level
                // detail.
                let nr_now = { ev.syscall_nr };
                if nr_now == -1 {
                    let args_arr = { ev.args };
                    let debug_id = { ev.ptr_hint } as u32 as i32;
                    let callee_pid = args_arr[0] as u32;
                    if callee_pid != 0
                        && (args.follow_services || args.follow_hal)
                        && discovery_seen_pids.insert(callee_pid)
                    {
                        discovery_refresh_pending = true;
                    }
                    if args.follow_binder
                        && pending_scenario_end.is_none()
                        && callee_pid != 0
                        && !root_pids.contains(&callee_pid)
                    {
                        if let Some(metadata) = causal_event.as_ref() {
                            let caller_pid = { ev.pid };
                            let caller_comm = format_comm(&{ ev.comm });
                            let (_, caller_domain) = follow_process_identity(caller_pid);
                            let (callee_comm, callee_domain) = follow_process_identity(callee_pid);
                            let decision = follow_policy.decide(FollowCandidate {
                                caller_comm: Some(&caller_comm),
                                caller_domain: caller_domain.as_deref(),
                                callee_comm: callee_comm.as_deref(),
                                callee_domain: callee_domain.as_deref(),
                                caller_relation: metadata.relation,
                                caller_depth: metadata.depth.saturating_sub(1),
                            });
                            match decision {
                                FollowDecision::Allow => {
                                    policy_blocked_pids.remove(&callee_pid);
                                    let ts_ns = { ev.timestamp_ns };
                                    if !root_pids.contains(&caller_pid) {
                                        followed_last_hop_ns.insert(caller_pid, ts_ns);
                                    }
                                    followed_last_hop_ns.insert(callee_pid, ts_ns);
                                }
                                FollowDecision::Block(reason) => {
                                    let _ = remove_followed_process(&mut bpf, callee_pid)?;
                                    followed_last_hop_ns.remove(&callee_pid);
                                    if active_pids.remove(&callee_pid) {
                                        if let Some((_, active_tx, _, _)) = poller_state.as_ref() {
                                            let _ = active_tx.try_send(active_pids.clone());
                                        }
                                    }
                                    policy_blocked_pids.insert(callee_pid);
                                    follow_policy_filtered =
                                        follow_policy_filtered.saturating_add(1);
                                    write_or_output_cap(
                                        emit_follow_guardrail(
                                            &mut *out,
                                            args.json,
                                            &mut event_id_counter,
                                            "blocked",
                                            reason,
                                            caller_pid,
                                            callee_pid,
                                            debug_id as u32,
                                            metadata.depth,
                                            Some(metadata),
                                            None,
                                            &scenarios,
                                        ),
                                        &output_cap_hit,
                                    )?;
                                }
                            }
                        }
                    }
                    if let Some(t) = binder_tracker.as_mut() {
                        let pid = { ev.pid };
                        let uid = { ev.uid };
                        let ts = { ev.timestamp_ns };
                        t.record_caller(
                            debug_id,
                            pid,
                            uid,
                            format_comm(&{ ev.comm }),
                            args_arr[0] as u32,
                            args_arr[1] as u32,
                            args_arr[2] as u32,
                            args_arr[4] != 0,
                            args_arr[5] as i32,
                            ts,
                            causal_event.clone(),
                        );
                    }
                } else if nr_now == SYSCALL_NR_BINDER_RECEIVED {
                    if let Some(t) = binder_tracker.as_mut() {
                        let debug_id = { ev.ptr_hint } as u32 as i32;
                        let ts = { ev.timestamp_ns };
                        if let Some(pair) = t.record_received(debug_id, ts) {
                            write_or_output_cap(
                                emit_binder_call(
                                    &pair,
                                    lookback.as_mut(),
                                    &mut engine,
                                    &mut *out,
                                    suppress_raw,
                                    args.json,
                                    &mut event_id_counter,
                                    &binder_services,
                                    &binder_catalog,
                                    &binder_methods,
                                    aidl_catalog.as_ref(),
                                    pair.causal_metadata.as_ref(),
                                ),
                                &output_cap_hit,
                            )?;
                        }
                    }
                }

                // Resolve the stack BEFORE building the JSON line so the
                // rule engine can pattern-match against `stack_contains`.
                // This must happen before `format_event_json_with_stack`.
                let mapping_changed = { ev.is_enter } == 0
                    && { ev.ret } >= 0
                    && matches!(
                        { ev.syscall_nr },
                        SYSCALL_MMAP | SYSCALL_MUNMAP | SYSCALL_MPROTECT
                    );
                if mapping_changed {
                    native_capture.invalidate(ev.pid);
                    proc_sym_cache.remove(&{ ev.pid });
                }
                let exec_event = matches!({ ev.syscall_nr }, SYSCALL_EXECVE | SYSCALL_EXECVEAT);
                if exec_event && { ev.is_enter } == 0 && { ev.ret } < 0 {
                    native_capture.clear_invalidation(ev.pid);
                }

                let (stack_str, stack_refs): (Option<String>, Vec<String>) = if args.stacks {
                    let kstk = { ev.kernel_stackid };
                    let ustk = { ev.user_stackid };
                    if kstk >= 0 || ustk >= 0 {
                        let pid = { ev.pid };
                        let proc_sym_opt = proc_sym_cache
                            .entry(pid)
                            .or_insert_with(|| ProcSymbolizer::new(pid));
                        if let Some(stack_traces) = stack_traces.as_ref() {
                            let proc_sym_mut = proc_sym_opt.as_mut();
                            let kernel_stack = match format_stack(
                                stack_traces,
                                kstk,
                                None,
                                kernel_resolver.as_ref(),
                            ) {
                                Ok(stack) => stack,
                                Err(_) => {
                                    stack_read_failures = stack_read_failures.saturating_add(1);
                                    None
                                }
                            };
                            let user_stack =
                                match format_stack(stack_traces, ustk, proc_sym_mut, None) {
                                    Ok(stack) => stack,
                                    Err(_) => {
                                        stack_read_failures = stack_read_failures.saturating_add(1);
                                        None
                                    }
                                };
                            let mut references = Vec::new();
                            for (kind, id, stack) in [
                                ("user", ustk, user_stack.as_ref()),
                                ("kernel", kstk, kernel_stack.as_ref()),
                            ] {
                                let Some(stack) = stack else { continue };
                                let Some(captured) = native_capture.capture_stack(
                                    pid,
                                    ev.timestamp_ns,
                                    kind,
                                    id,
                                    &stack.ips,
                                    &stack.rendered,
                                ) else {
                                    continue;
                                };
                                if args.json && !suppress_raw {
                                    for record in captured.records {
                                        write_or_output_cap(
                                            writeln!(out, "{record}"),
                                            &output_cap_hit,
                                        )?;
                                    }
                                }
                                references.push(captured.reference);
                            }
                            let kernel_str = kernel_stack.map(|stack| stack.rendered.join(" <- "));
                            let user_str = user_stack.map(|stack| stack.rendered.join(" <- "));
                            let rendered = match (kernel_str, user_str) {
                                (Some(k), Some(u)) => Some(format!("{k} ;; {u}")),
                                (Some(k), None) => Some(k),
                                (None, Some(u)) => Some(u),
                                (None, None) => None,
                            };
                            (rendered, references)
                        } else {
                            (None, Vec::new())
                        }
                    } else {
                        (None, Vec::new())
                    }
                } else {
                    (None, Vec::new())
                };
                if exec_event && { ev.is_enter } == 1 {
                    native_capture.invalidate(ev.pid);
                    proc_sym_cache.remove(&{ ev.pid });
                }

                // Update the FD graph from this event (open/close/dup/socket/
                // memfd_create/etc. drive state transitions). Pass the
                // already-decoded path so we don't re-decode in the graph.
                let decoded_path = format_data_field(&ev);
                fd_graph.update(&ev, decoded_path.as_deref());

                // If the event references a fd we know about, build an FdHint
                // for JSON enrichment. mmap with MAP_ANONYMOUS (fd == -1) is
                // skipped by `fd_arg_for_event`.
                let fd_hint = FdGraph::fd_arg_for_event(&ev).and_then(|(fd, _idx)| {
                    let pid = { ev.pid };
                    let ts = { ev.timestamp_ns };
                    let opt = if args.resolve_paths {
                        fd_graph.lookup_or_resolve(pid, fd, ts)
                    } else {
                        fd_graph.lookup(pid, fd).cloned()
                    };
                    opt.map(|e| FdHint {
                        kind: e.kind,
                        path: e.path,
                    })
                });

                // Phase 1a/1b — userspace post-filter. The BPF prefilter is a
                // safe over-approximation; here we apply the full predicate
                // (including userspace-only clauses, OR / NOT branches, and
                // `--match <expr>` AST nodes) to decide whether to emit the
                // event line, feed the rule engine, and record into the
                // crash-context lookback.
                //
                // fdgraph state has already been updated above so we can
                // reject state-tracking events without losing fd→path
                // information; a later ioctl whose match depends on the
                // resolved path then sees the up-to-date entry.
                let post_filter_ok = if capture_predicate.is_empty() {
                    true
                } else {
                    let lens = SyscallEventLens::new(
                        &ev,
                        format_comm(&{ ev.comm }),
                        fd_hint.as_ref().map(|h| h.path.as_str()),
                        compute_latency_us(&ev),
                    );
                    capture_predicate.evaluate(&lens)
                };
                if post_filter_ok {
                    events_matched = events_matched.saturating_add(1);
                }

                // Always compute the JSON form: cheap and fed to the rule engine.
                event_id_counter = event_id_counter.wrapping_add(1);
                let mut json_line = format_event_json_full(
                    &ev,
                    args.resolve_paths,
                    stack_str.as_deref(),
                    fd_hint.as_ref(),
                    Some(event_id_counter),
                );
                json_line = neutron::native::add_stack_references(&json_line, &stack_refs);
                if let Some(metadata) = causal_event.as_ref() {
                    json_line = enrich_json(&json_line, metadata)?;
                }
                if let Some(capture) = harness_capture.as_ref() {
                    json_line = capture.enrich_json(
                        &ev,
                        fd_hint.as_ref().map(|hint| hint.path.as_str()),
                        &json_line,
                    )?;
                }

                // Phase 1d — sampling decision. State-tracking syscalls
                // (open/close/dup/socket/...) and synthetic sentinels
                // bypass the chain so fdgraph and crash correlation stay
                // intact even at p=0.0 / rate=1.
                let nr_for_sampler = { ev.syscall_nr };
                let ts_ns = { ev.timestamp_ns };
                let sampler_keep = sampler.keep(ts_ns, nr_for_sampler);
                if !sampler_keep {
                    events_sampled_out = events_sampled_out.saturating_add(1);
                }

                // Phase 1c — context-window dispatch. The post-filter +
                // sampler verdicts feed the ring (or the simple emit
                // path) together. State-tracking events that the sampler
                // exempts will reach the ring as `matched=false` if the
                // predicate also rejected them — so they sit in the
                // backward window without firing it themselves.
                let lines: Vec<String> = if !sampler_keep {
                    Vec::new()
                } else {
                    match context_ring.as_mut() {
                        None => {
                            if post_filter_ok {
                                vec![json_line.clone()]
                            } else {
                                Vec::new()
                            }
                        }
                        Some(_ring) if pending_scenario_end.is_some() && causal_event.is_none() => {
                            if post_filter_ok {
                                vec![json_line.clone()]
                            } else {
                                Vec::new()
                            }
                        }
                        Some(ring) => ring.observe(ts_ns, post_filter_ok, &json_line),
                    }
                };

                if !lines.is_empty() {
                    // Always feed the rule engine the *currently observed*
                    // event when the post-filter agrees — flushing context
                    // into the engine as if it were live would re-fire
                    // rules on stale events. Backward-context lines from the
                    // ring are write-only (they go to the output and the
                    // lookback, but not the engine).
                    if post_filter_ok {
                        if let Some(eng) = engine.as_mut() {
                            if let Some(owned) = neutron_rules::Event::parse_line(&json_line) {
                                if let Some(view) = owned.view() {
                                    eng.feed(&view);
                                }
                            }
                        }
                    }

                    if !suppress_raw {
                        for line in &lines {
                            // For text mode we still render the live event
                            // via the existing text formatter; backward-flush
                            // lines from the ring stay in JSON to preserve
                            // their original shape (mixing modes inside one
                            // capture is unavoidable when the ring buffers
                            // JSON).
                            if args.json || line != &json_line {
                                write_or_output_cap(writeln!(out, "{line}"), &output_cap_hit)?;
                            } else {
                                let text = format_event_text_with_stack(
                                    &ev,
                                    args.resolve_paths,
                                    stack_str.as_deref(),
                                );
                                write_or_output_cap(writeln!(out, "{text}"), &output_cap_hit)?;
                            }
                        }
                    }

                    // Lookback: record the JSON form (not the text form — JSON
                    // round-trips losslessly into the crash_context array).
                    if let Some(lb) = lookback.as_mut() {
                        let pid = { ev.pid };
                        lb.record(pid, &json_line);
                    }
                }

                events_since_drain += 1;
                if events_since_drain >= drain_interval {
                    events_since_drain = 0;
                    if let Some(eng) = engine.as_mut() {
                        let findings = eng.drain_ready();
                        if !findings.is_empty() {
                            write_or_output_cap(
                                emit_findings_with(
                                    &findings,
                                    &mut *out,
                                    args.json,
                                    args.fd_snapshot_on_finding,
                                ),
                                &output_cap_hit,
                            )?;
                        }
                    }
                }

                // Active-set bookkeeping for the FD poller's "active" scope.
                // We add every PID that produced an event the userspace
                // pipeline saw — strictly broader than "fd-bearing" but
                // ensures the target process is sampled even if it does
                // nothing fd-related. Send updated set to poller only when
                // it grew; sending is non-blocking so we never stall the
                // event loop.
                if let Some((_, active_tx, _, _)) = poller_state.as_ref() {
                    let pid = { ev.pid };
                    if pid != 0 && active_pids.insert(pid) {
                        let _ = active_tx.try_send(active_pids.clone());
                    }
                }

                // Side effects that need to happen AFTER the event is consumed.
                if args.follow_children {
                    let map = bpf
                        .map_mut("PID_WHITELIST")
                        .context("PID_WHITELIST missing")?;
                    let mut pid_whitelist: AyaHashMap<_, u32, u8> = AyaHashMap::try_from(map)
                        .context("PID_WHITELIST is not HashMap<u32,u8>")?;
                    if let Some(error) =
                        handle_follow_children(&ev, &mut pid_whitelist, args.verbose)
                    {
                        follow_children_map_failures =
                            follow_children_map_failures.saturating_add(1);
                        if follow_children_map_failures == 1 {
                            eprintln!("neutron: WARNING: {error}");
                        }
                    }
                }
                if args.capture_reads {
                    let map = bpf.map_mut("WATCH_FDS").context("WATCH_FDS missing")?;
                    let mut watch_fds: AyaHashMap<_, u64, u8> =
                        AyaHashMap::try_from(map).context("WATCH_FDS is not HashMap<u64,u8>")?;
                    if let Some(error) = handle_capture_reads(
                        &ev,
                        &mut watch_fds,
                        &mut watched_sensitive_fds,
                        args.verbose,
                    ) {
                        watch_fds_map_failures = watch_fds_map_failures.saturating_add(1);
                        if watch_fds_map_failures == 1 {
                            eprintln!("neutron: WARNING: {error}");
                        }
                    }
                }

                if stop_if_output_cap_hit(
                    &output_cap_hit,
                    &mut output_cap_reported,
                    running.as_ref(),
                ) {
                    break;
                }

                if !running.load(Ordering::Relaxed) {
                    break;
                }
            }
        }
        // Drain any FD-poller samples produced since the last iteration.
        // Each sample becomes a `type:"fd_snapshot"` JSON line; the engine
        // sees it as `EventKind::FdSnapshot` and matches `R001`-class rules.
        if let Some((samples_rx, _, _, _)) = poller_state.as_ref() {
            while let Ok(sample) = samples_rx.try_recv() {
                fd_poller_samples_consumed = fd_poller_samples_consumed.saturating_add(1);
                fd_graph.record_sample(
                    sample.pid,
                    sample.fd_count,
                    sample.rlimit_nofile,
                    sample.ts_ns,
                );
                let stats_snapshot = fd_graph.stats(sample.pid).copied().unwrap_or_default();
                event_id_counter = event_id_counter.wrapping_add(1);
                let line = format_fd_snapshot_json(
                    &sample,
                    stats_snapshot.high_water_mark,
                    stats_snapshot.growth_rate_per_sec,
                    Some(event_id_counter),
                );
                if let Some(eng) = engine.as_mut() {
                    if let Some(owned) = neutron_rules::Event::parse_line(&line) {
                        if let Some(view) = owned.view() {
                            eng.feed(&view);
                        }
                    }
                }
                if !suppress_raw {
                    write_or_output_cap(writeln!(out, "{line}"), &output_cap_hit)?;
                }
                if let Some(lb) = lookback.as_mut() {
                    lb.record(sample.pid, &line);
                }
                if stop_if_output_cap_hit(
                    &output_cap_hit,
                    &mut output_cap_reported,
                    running.as_ref(),
                ) {
                    break;
                }
            }
        }

        // ── Crash-correlation watcher drain (sprint-2 PR 1) ──────────
        //
        // Pull any new ProcessExitEvent values from the tombstone watcher
        // and the logcat tail. Each drains independently; per_process
        // aggregation in the rule engine collapses dups when both sources
        // describe the same crash.
        let now_ns = monotonic_timestamp_ns();
        if let Some(w) = tombstone_watcher.as_mut() {
            for pe in w.poll(now_ns) {
                let Some(pe_causal) = correlate_recent_exit(&mut recent_exit_causal, &pe) else {
                    let root_uid = args.root_uid.or(package_uid);
                    if root_pids.contains(&pe.pid)
                        || active_pids.contains(&pe.pid)
                        || pe.uid.is_some_and(|uid| root_uid == Some(uid))
                    {
                        tombstone_unmatched_in_scope =
                            tombstone_unmatched_in_scope.saturating_add(1);
                    } else {
                        tombstone_out_of_scope = tombstone_out_of_scope.saturating_add(1);
                    }
                    continue;
                };
                if pe.classify() == neutron::sources::ExitClassification::Crash {
                    if let Some(t) = binder_tracker.as_mut() {
                        for pair in t.on_callee_crash(pe.pid) {
                            write_or_output_cap(
                                emit_binder_call(
                                    &pair,
                                    lookback.as_mut(),
                                    &mut engine,
                                    &mut *out,
                                    suppress_raw,
                                    args.json,
                                    &mut event_id_counter,
                                    &binder_services,
                                    &binder_catalog,
                                    &binder_methods,
                                    aidl_catalog.as_ref(),
                                    pair.causal_metadata.as_ref(),
                                ),
                                &output_cap_hit,
                            )?;
                        }
                    }
                }
                write_or_output_cap(
                    emit_process_exit(
                        &pe,
                        lookback.as_mut(),
                        &mut engine,
                        &mut *out,
                        suppress_raw,
                        args.json,
                        &mut event_id_counter,
                        Some(&pe_causal),
                    ),
                    &output_cap_hit,
                )?;
                if stop_if_output_cap_hit(
                    &output_cap_hit,
                    &mut output_cap_reported,
                    running.as_ref(),
                ) {
                    break;
                }
            }
        }
        if let Some(r) = logcat_reader.as_mut() {
            for pe in r.drain(now_ns) {
                let Some(pe_causal) = correlate_recent_exit(&mut recent_exit_causal, &pe) else {
                    logcat_untrusted_native_exits = logcat_untrusted_native_exits.saturating_add(1);
                    if args.verbose && logcat_untrusted_native_exits == 1 {
                        eprintln!(
                            "neutron: WARNING: ignored native-fatal logcat text without a matching BPF process-exit event"
                        );
                    }
                    continue;
                };
                if pe.classify() == neutron::sources::ExitClassification::Crash {
                    if let Some(t) = binder_tracker.as_mut() {
                        for pair in t.on_callee_crash(pe.pid) {
                            write_or_output_cap(
                                emit_binder_call(
                                    &pair,
                                    lookback.as_mut(),
                                    &mut engine,
                                    &mut *out,
                                    suppress_raw,
                                    args.json,
                                    &mut event_id_counter,
                                    &binder_services,
                                    &binder_catalog,
                                    &binder_methods,
                                    aidl_catalog.as_ref(),
                                    pair.causal_metadata.as_ref(),
                                ),
                                &output_cap_hit,
                            )?;
                        }
                    }
                }
                write_or_output_cap(
                    emit_process_exit(
                        &pe,
                        lookback.as_mut(),
                        &mut engine,
                        &mut *out,
                        suppress_raw,
                        args.json,
                        &mut event_id_counter,
                        Some(&pe_causal),
                    ),
                    &output_cap_hit,
                )?;
                if stop_if_output_cap_hit(
                    &output_cap_hit,
                    &mut output_cap_reported,
                    running.as_ref(),
                ) {
                    break;
                }
            }
        }

        if let Some(reader) = selinux_reader.as_mut() {
            for mut denial in reader.drain(monotonic_timestamp_ns()) {
                neutron::selinux::resolve_process_identity(&mut denial);
                denial.ts_ns = monotonic_timestamp_ns();
                let process_context = read_process_context(&bpf, denial.pid)?;
                if !selinux_denial_in_scope(
                    &denial,
                    &args,
                    &root_pids,
                    &selinux_scope_pids,
                    &selinux_scope_uids,
                    process_context,
                ) {
                    reader.record_out_of_scope();
                    continue;
                }
                // Logcat does not provide gap-free delivery or a timestamp
                // that is atomically comparable to the live scenario marker.
                // Preserve the positive AVC record, but do not synthesize a
                // scenario edge from the process's *current* BPF context: a
                // queued pre-marker line or PID reuse could otherwise be
                // mislabeled as causal evidence.
                let causal = None;
                write_or_output_cap(
                    emit_selinux_denial(
                        &mut denial,
                        causal.as_ref(),
                        lookback.as_mut(),
                        &mut *out,
                        args.json,
                        &mut event_id_counter,
                    ),
                    &output_cap_hit,
                )?;
                if stop_if_output_cap_hit(
                    &output_cap_hit,
                    &mut output_cap_reported,
                    running.as_ref(),
                ) {
                    break;
                }
            }
        }

        if !saw_any {
            // Block on `poll(2)` until the ring becomes readable (or timeout).
            // SAFETY: `pollfd` is a POD; we initialise all fields before the call.
            let mut pfd = libc::pollfd {
                fd: ring_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let poll_result = unsafe { libc::poll(&mut pfd, 1, POLL_TIMEOUT_MS) };
            let errno = (poll_result < 0)
                .then(|| std::io::Error::last_os_error().raw_os_error())
                .flatten();
            if let Some(error) = ring_poll_failure(poll_result, pfd.revents, errno) {
                ring_poll_error = Some(error);
                break;
            }
        }

        let should_finish_cleanup = pending_scenario_end.as_ref().is_some_and(|pending| {
            !pending.cleanup_complete && std::time::Instant::now() >= pending.settle_until
        });
        if should_finish_cleanup {
            let cleanup = (|| -> Result<u64> {
                set_root_uid_context(&mut bpf, 0, 0)?;
                replace_causal_roots(&mut bpf, &root_pids, 0, 0)?;
                clear_causal_transients(&mut bpf)?;
                discard_inflight_at_scenario_end(&mut bpf)
            })();
            match cleanup {
                Ok(discarded) => {
                    scenario_inflight_discarded =
                        scenario_inflight_discarded.saturating_add(discarded);
                    if let Some(tracker) = binder_tracker.as_mut() {
                        tracker.discard_inflight();
                    }
                    if let Some(ring) = context_ring.as_mut() {
                        scenario_context_discarded =
                            scenario_context_discarded.saturating_add(ring.reset_boundary() as u64);
                    }
                    if let Some(pending) = pending_scenario_end.as_mut() {
                        pending.cleanup_complete = true;
                    }
                    // Run one complete ring/source drain after the final map
                    // cleanup before committing the end marker.
                    continue;
                }
                Err(error) => {
                    marker_transition_error =
                        Some(format!("scenario end final cleanup failed: {error:#}"));
                    if let Some(pending) = pending_scenario_end.take() {
                        if let Err(response_error) =
                            pending.pending.respond_error(format!("{error:#}"))
                        {
                            eprintln!(
                                "neutron: warn: marker client disconnected: {response_error:#}"
                            );
                        }
                    }
                    running.store(false, Ordering::Relaxed);
                    continue;
                }
            }
        }

        if pending_scenario_end
            .as_ref()
            .is_some_and(|pending| pending.cleanup_complete)
        {
            let pending = pending_scenario_end
                .take()
                .expect("pending scenario end checked above");
            if let Some(tracker) = binder_tracker.as_mut() {
                tracker.discard_inflight();
            }
            if let Some(ring) = context_ring.as_mut() {
                scenario_context_discarded =
                    scenario_context_discarded.saturating_add(ring.reset_boundary() as u64);
            }
            let ts_ns = monotonic_timestamp_ns();
            let line = live_marker_line(
                &pending.request,
                &pending.scenario,
                ts_ns,
                args.package.as_deref(),
                args.root_uid.or(package_uid),
                (args.pid != 0).then_some(args.pid),
            );
            match writeln!(out, "{line}") {
                Ok(()) => match scenarios.end(&pending.request.name) {
                    Ok(committed) if committed == pending.scenario => {
                        recent_exit_causal.clear();
                        followed_last_hop_ns.clear();
                        policy_blocked_pids.clear();
                        active_pids = root_pids.iter().copied().collect();
                        if let Some((_, active_tx, _, _)) = poller_state.as_ref() {
                            let _ = active_tx.try_send(active_pids.clone());
                        }
                        if let Err(error) = pending.pending.respond_ok(
                            ts_ns,
                            committed.generation,
                            committed.trace_id,
                        ) {
                            eprintln!("neutron: warn: marker client disconnected: {error:#}");
                        }
                    }
                    Ok(_) | Err(_) => {
                        marker_transition_error =
                            Some("scenario end state commit diverged after marker write".into());
                        let _ = pending
                            .pending
                            .respond_error("scenario end state commit diverged");
                        running.store(false, Ordering::Relaxed);
                    }
                },
                Err(error) => {
                    marker_transition_error =
                        Some(format!("scenario end marker write failed: {error}"));
                    let _ = pending
                        .pending
                        .respond_error(format!("scenario end marker write failed: {error}"));
                    running.store(false, Ordering::Relaxed);
                }
            }
        }
    }

    // Stop kernel producers before taking the final health snapshot. Any
    // records that were queued but not processed at the shutdown boundary are
    // counted explicitly, so a clean-looking counter map cannot hide them.
    let detach_errors = detach_attached_programs(&mut bpf, &attached);
    let mut shutdown_events_discarded = 0_u64;
    while ring.next().is_some() {
        shutdown_events_discarded = shutdown_events_discarded.saturating_add(1);
    }
    let binder_tracker_stats = if let Some(tracker) = binder_tracker.as_mut() {
        tracker.discard_inflight();
        tracker.stats()
    } else {
        BinderTrackerStats::default()
    };

    // Signal the FD poller to stop, join it, and retain its bounded-channel
    // telemetry. A thread panic or a sample/update that never reached the
    // consumer must not disappear behind a clean capture-health record.
    let mut poller_join_failed = false;
    let mut fd_poller_shutdown_samples_discarded = 0_u64;
    let fd_poller_stats = if let Some((samples_rx, active_tx, stop_tx, handle)) = poller_state {
        if stop_tx.send(()).is_err() {
            poller_join_failed = true;
        }
        if handle.join().is_err() {
            poller_join_failed = true;
        }
        while samples_rx.try_recv().is_ok() {
            // These records were produced before shutdown but were not
            // incorporated into the evidence stream.
            fd_poller_shutdown_samples_discarded =
                fd_poller_shutdown_samples_discarded.saturating_add(1);
        }
        active_tx.stats()
    } else {
        poller::FdPollerStats::default()
    };

    // 9. Flush rule engine.
    if let Some(eng) = engine.take() {
        let pending = eng.flush_all();
        if !pending.is_empty() {
            write_or_output_cap(
                emit_findings_with(&pending, &mut *out, args.json, args.fd_snapshot_on_finding),
                &output_cap_hit,
            )?;
        }
    }

    // 10. Capture summary. Read the COUNTERS map and print the slot values
    // plus a warning if any drop or degradation counter is non-zero.
    // RingBuf is *not* lossless: `reserve()` returns None when the ring is
    // full, and the BPF programs increment COUNTER_RINGBUF_RESERVE_FAILED in
    // that case. The summary surfaces this so operators can judge whether
    // absence of a finding is conclusive.
    let logcat_source_available = logcat_reader
        .as_mut()
        .is_some_and(RealLogcatReader::is_available);
    let logcat_stats = logcat_reader
        .as_ref()
        .map(RealLogcatReader::stats)
        .unwrap_or_default();
    let logcat_terminal = logcat_reader
        .as_ref()
        .and_then(RealLogcatReader::terminal_state)
        .map(|state| format!("{state:?}"));
    let selinux_source_available = selinux_reader
        .as_mut()
        .is_some_and(SelinuxLogcatReader::is_available);
    let selinux_stats = selinux_reader
        .as_ref()
        .map(SelinuxLogcatReader::stats)
        .unwrap_or_default();
    let selinux_terminal = selinux_reader
        .as_ref()
        .and_then(SelinuxLogcatReader::terminal_state)
        .map(|state| format!("{state:?}"));
    let tombstone_stats = tombstone_watcher
        .as_ref()
        .map(RealTombstoneWatcher::stats)
        .unwrap_or_default();
    let tombstone_source_available = tombstone_watcher
        .as_ref()
        .is_some_and(|watcher| watcher.runtime_state().primed && watcher.runtime_state().available);
    let tombstone_last_error = tombstone_watcher
        .as_ref()
        .and_then(|watcher| watcher.runtime_state().last_error.as_ref())
        .map(|error| format!("{} {}: {}", error.operation, error.path, error.message));
    capture_scope.sources.logcat_available = logcat_source_available;
    capture_scope.sources.selinux_logcat_available = selinux_source_available;
    capture_scope.sources.tombstone_available = tombstone_source_available;
    capture_scope = capture_scope.recompute_claim_scope();
    let health = match bpf.map("COUNTERS") {
        Some(map) => match PerCpuArray::<_, u64>::try_from(map) {
            Ok(counters) => CaptureHealth::read(&counters),
            Err(error) => CaptureHealth::unknown(format!("map:COUNTERS:{error}")),
        },
        None => CaptureHealth::unknown("map:COUNTERS:missing"),
    };
    let mut unknown_reasons = detach_errors;
    match read_boot_id() {
        Ok(final_boot_id) if final_boot_id == capture_boot_id => {}
        Ok(final_boot_id) => unknown_reasons.push(format!(
            "device boot identity changed during capture: {} -> {}",
            capture_boot_id, final_boot_id
        )),
        Err(error) => unknown_reasons.push(format!(
            "final device boot identity could not be read: {error:#}"
        )),
    }
    if let Some(error) = marker_transition_error {
        unknown_reasons.push(error);
    }
    if let Some(error) = ring_poll_error {
        unknown_reasons.push(error);
    }
    if poller_join_failed || fd_poller_stats.running {
        unknown_reasons.push("FD poller did not terminate cleanly".into());
    }
    let fd_poller_unconsumed = fd_poller_stats
        .samples_sent
        .saturating_sub(fd_poller_samples_consumed);
    if fd_poller_unconsumed != fd_poller_shutdown_samples_discarded {
        unknown_reasons.push(format!(
            "FD poller sample reconciliation mismatch: sent={} consumed={} shutdown_discarded={}",
            fd_poller_stats.samples_sent,
            fd_poller_samples_consumed,
            fd_poller_shutdown_samples_discarded
        ));
    }
    if let Some(terminal) = logcat_terminal {
        unknown_reasons.push(format!("logcat source terminated: {terminal}"));
    }
    if let Some(terminal) = selinux_terminal {
        unknown_reasons.push(format!("SELinux logcat source terminated: {terminal}"));
    }
    if let Some(error) = tombstone_last_error {
        unknown_reasons.push(format!("tombstone source error: {error}"));
    }
    if stack_read_failures > 0 {
        unknown_reasons.push(format!(
            "STACK_TRACES lookup failed {stack_read_failures} time(s)"
        ));
    }
    if invalid_ring_records > 0 {
        unknown_reasons.push(format!(
            "ring buffer yielded {invalid_ring_records} record(s) whose size did not match the validated event ABI"
        ));
    }
    let mut incomplete_reasons = Vec::new();
    if let Some(active) = scenarios.active() {
        incomplete_reasons.push(format!(
            "scenario '{}' ended without a closing marker",
            active.scenario_id
        ));
    }
    if logcat_source_enabled && logcat_reader.is_none() {
        incomplete_reasons.push("requested logcat source could not be started".into());
    }
    if selinux_source_enabled && selinux_reader.is_none() {
        incomplete_reasons.push("requested SELinux logcat source could not be started".into());
    }
    if tombstone_source_enabled && tombstone_watcher.is_none() {
        incomplete_reasons.push("requested tombstone source was unavailable at startup".into());
    }
    if follow_children_map_failures > 0 {
        incomplete_reasons.push(format!(
            "PID_WHITELIST update failed {follow_children_map_failures} time(s); child observation is incomplete"
        ));
    }
    if watch_fds_map_failures > 0 {
        incomplete_reasons.push(format!(
            "WATCH_FDS update failed {watch_fds_map_failures} time(s); watched-FD instrumentation is incomplete"
        ));
    }
    if binder_discovery_failures > 0 {
        incomplete_reasons.push(format!(
            "Binder service/HAL inventory refresh failed {binder_discovery_failures} time(s)"
        ));
    }
    if binder_discovery_drift > 0 {
        incomplete_reasons.push(format!(
            "Binder service/HAL inventory changed during capture ({binder_discovery_drift} refresh(es)); candidate attribution is not stable"
        ));
    }
    if scenario_inflight_discarded > 0 {
        incomplete_reasons.push(format!(
            "{scenario_inflight_discarded} syscall(s) were still in flight at a scenario end boundary"
        ));
    }
    if scenario_context_discarded > 0 {
        incomplete_reasons.push(format!(
            "{scenario_context_discarded} buffered context record(s) were cleared at a scenario boundary"
        ));
    }
    if tombstone_unmatched_in_scope > 0 {
        incomplete_reasons.push(format!(
            "{tombstone_unmatched_in_scope} in-scope tombstone crash record(s) lacked a matching BPF process-exit"
        ));
    }
    if health.is_readable(neutron_common::COUNTER_EVENTS_SUBMITTED) {
        let submitted = health.get(neutron_common::COUNTER_EVENTS_SUBMITTED);
        let received = total_events
            .saturating_add(invalid_ring_records)
            .saturating_add(shutdown_events_discarded);
        if submitted != received {
            incomplete_reasons.push(format!(
                "BPF/userspace event reconciliation mismatch: submitted={submitted} received={received}"
            ));
        }
    }
    let user_health = UserspaceHealth {
        fd_graph_miss: fd_graph.miss_count(),
        fd_graph_backfilled: fd_graph.backfill_count(),
        fd_poller_samples_dropped: fd_poller_stats.samples_dropped_full,
        fd_poller_shutdown_samples_discarded,
        fd_poller_sample_channel_errors: fd_poller_stats.sample_receiver_disconnected,
        fd_poller_active_updates_dropped: fd_poller_stats
            .active_updates_dropped_full
            .saturating_add(
                fd_poller_stats
                    .active_updates_sent
                    .saturating_sub(fd_poller_stats.active_updates_applied),
            ),
        fd_poller_active_channel_errors: fd_poller_stats.active_receiver_disconnected,
        fd_poller_proc_disappeared: fd_poller_stats.proc_disappeared,
        fd_poller_proc_permission_errors: fd_poller_stats.proc_permission_errors,
        fd_poller_proc_io_errors: fd_poller_stats.proc_io_errors,
        fd_poller_proc_parse_errors: fd_poller_stats.proc_parse_errors,
        fd_poller_proc_truncations: fd_poller_stats.proc_truncations,
        fd_poller_proc_races: fd_poller_stats.proc_races,
        fd_poller_pid_reuse: fd_poller_stats.pid_reuse,
        fd_poller_samples_suppressed_read_errors: fd_poller_stats.samples_suppressed_read_errors,
        fd_poller_target_unreadable_polls: fd_poller_stats.target_unreadable_polls,
        fd_poller_scope_read_errors: fd_poller_stats.scope_read_errors,
        scenario_inflight_discarded,
        scenario_context_discarded,
        scenario_context_baseline_discarded,
        events_matched,
        events_sampled_out,
        events_emitted: output_records.load(Ordering::Relaxed),
        output_cap_hit: output_cap_hit.load(Ordering::Relaxed),
        follow_policy_filtered,
        follow_ttl_expired,
        binder_tracker_evictions: binder_tracker_stats.tracker_evictions,
        binder_unmatched_receives: binder_tracker_stats.unmatched_receives,
        binder_causal_metadata_discarded: binder_tracker_stats.causal_metadata_discarded,
        binder_invalid_callers: binder_tracker_stats.invalid_callers,
        binder_baseline_discarded: binder_tracker_stats.baseline_discarded,
        binder_tracker_disabled: binder_tracker.is_none(),
        kprobe_attach_failures: kprobe_packs
            .iter()
            .flat_map(|pack| {
                pack.failures
                    .iter()
                    .map(|failure| format!("{}:{failure}", pack.name))
            })
            .collect(),
        native_capture_degraded: native_capture.degraded(),
        native_maps_truncated: native_capture.maps_truncated,
        native_stacks_truncated: native_capture.stacks_truncated,
        native_refresh_failed: native_capture.refresh_failed,
        logcat_source_enabled,
        logcat_source_available,
        logcat_baseline_drains: logcat_stats.baseline_drains,
        logcat_baseline_lines_discarded: logcat_stats.baseline_lines_discarded,
        logcat_baseline_events_discarded: logcat_stats.baseline_events_discarded,
        logcat_baseline_pending_discarded: logcat_stats.baseline_pending_discarded,
        logcat_baseline_errors: logcat_stats.baseline_errors,
        logcat_unprimed_drains: logcat_stats.unprimed_drains,
        logcat_lines_read: logcat_stats.lines_read,
        logcat_oversized_lines: logcat_stats.oversized_lines,
        logcat_eof: logcat_stats.eof,
        logcat_read_errors: logcat_stats.read_errors,
        logcat_incomplete_correlations: logcat_stats.incomplete_correlations,
        logcat_malformed_correlations: logcat_stats.malformed_correlations,
        logcat_unsupported_java_fatal: logcat_stats.unsupported_java_fatal,
        logcat_unsupported_anr: logcat_stats.unsupported_anr,
        logcat_untrusted_native_exits,
        selinux_source_enabled,
        selinux_source_available,
        selinux_baseline_drains: selinux_stats.baseline_drains,
        selinux_baseline_records_discarded: selinux_stats.baseline_records_discarded,
        selinux_baseline_pending_discarded: selinux_stats.baseline_pending_discarded,
        selinux_baseline_errors: selinux_stats.baseline_errors,
        selinux_unprimed_drains: selinux_stats.unprimed_drains,
        selinux_parsed: selinux_stats.parsed,
        selinux_malformed: selinux_stats.malformed,
        selinux_deduplicated: selinux_stats.deduplicated,
        selinux_out_of_scope: selinux_stats.out_of_scope,
        selinux_eof: selinux_stats.eof,
        selinux_read_errors: selinux_stats.read_errors,
        tombstone_source_enabled,
        tombstone_source_available,
        tombstone_baseline_primes: tombstone_stats.baseline_primes,
        tombstone_baseline_errors: tombstone_stats.baseline_errors,
        tombstone_baseline_files: tombstone_stats.baseline_files,
        tombstone_unprimed_polls: tombstone_stats.unprimed_polls,
        tombstone_directory_errors: tombstone_stats.directory_errors,
        tombstone_directory_entry_errors: tombstone_stats.directory_entry_errors,
        tombstone_directory_overflows: tombstone_stats.directory_overflows,
        tombstone_file_read_errors: tombstone_stats.file_read_errors,
        tombstone_oversized_files: tombstone_stats.oversized_files,
        tombstone_file_identity_races: tombstone_stats.file_identity_races,
        tombstone_malformed_files: tombstone_stats.malformed_files,
        tombstone_unmatched_in_scope,
        tombstone_out_of_scope,
        incomplete_reasons,
        unknown_reasons,
        shutdown_events_discarded,
    };
    eprint!(
        "{}",
        format_summary_with(&health, &user_health, total_events)
    );

    // Machine-readable counterpart on the NDJSON stream and, optionally, a
    // sidecar independent of the primary output cap. Unknown health is still
    // emitted; it must never collapse to an innocent-looking zero snapshot.
    let mut final_health_line = None;
    if args.json || args.health_output.is_some() {
        let mut match_pids = args.match_pid.clone();
        if args.pid != 0 {
            push_unique(&mut match_pids, args.pid.to_string());
        }
        let capture_meta = CaptureMetadata {
            capture_scope: Some(capture_scope),
            driver_packs: driver_packs.names.clone(),
            kprobe_packs: args
                .kprobe_pack
                .iter()
                .map(|s| normalize_pack_name(s))
                .collect(),
            attached_programs: attached.iter().map(|s| (*s).to_string()).collect(),
            ioctl_refresh_cmds: driver_packs.refresh_cmds.iter().copied().collect(),
            ioctl_refresh_types: driver_packs.refresh_types.iter().copied().collect(),
            match_packages: args.match_package.clone(),
            match_uids: args.match_uid.clone(),
            match_pids,
            root_package: args.package.clone(),
            root_uid: args.root_uid.or(package_uid),
            boot_id: Some(capture_boot_id.clone()),
            fingerprint: capture_fingerprint.clone(),
            max_depth: args.max_depth,
            max_processes: args.max_processes,
            bpf_object_sha256: Some(bpf_identity.object_sha256.clone()),
            bpf_build_id: Some(bpf_identity.build_id.clone()),
            bpf_abi_major: Some(bpf_identity.abi_major),
            bpf_abi_minor: Some(bpf_identity.abi_minor),
            bpf_event_size: Some(bpf_identity.syscall_event_size),
            bpf_feature_bits: Some(bpf_identity.feature_bits),
            ring_size_bytes: Some(1 << 20),
        };
        let line = format_capture_health_json_with_metadata(
            &health,
            &user_health,
            total_events,
            &capture_meta,
        );
        write_health_sidecar(args.health_output.as_deref(), &line)?;
        if args.json {
            write_or_output_cap(writeln!(out, "{line}"), &output_cap_hit)?;
        }
        final_health_line = Some(line);
    }
    out.flush().context("flushing final capture output")?;
    drop(out);

    if let Some(bundle) = trace_bundle {
        let line = final_health_line.context("trace run bundle has no final capture health")?;
        let capture_health: serde_json::Value =
            serde_json::from_str(&line).context("parsing final capture health for manifest")?;
        let capture = neutron::run_manifest::identify_artifact(&bundle.run_dir, "capture.ndjson")?;
        let health =
            neutron::run_manifest::identify_artifact(&bundle.run_dir, "capture.health.json")?;
        let manifest = neutron::run_manifest::RunManifest::live_capture(
            neutron::run_manifest::LiveCaptureManifest {
                run_id: bundle.run_id,
                started_at: bundle.started_at,
                completed_at: neutron::run_manifest::utc_timestamp(),
                device: capture_device_identity,
                research_model: neutron::run_manifest::ResearchModel {
                    observer_privilege: observer_privilege_after_preflight(),
                    attacker_capability: args.attacker_capability.clone(),
                },
                bpf: neutron::run_manifest::BpfIdentity::from_loaded(&bpf_identity),
                capture_health,
                artifacts: vec![capture, health],
            },
        )?;
        neutron::run_manifest::finalize_bundle(&bundle.run_dir, &manifest)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutron::mark::{self, MarkArgs};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn maturity_warning_never_contaminates_machine_readable_streams() {
        let doctor_json = Cli::try_parse_from(["neutron", "doctor", "--json"])
            .expect("doctor JSON command should parse");
        let doctor_text =
            Cli::try_parse_from(["neutron", "doctor"]).expect("doctor command should parse");
        let trace_json = Cli::try_parse_from(["neutron", "trace", "--json"])
            .expect("trace JSON command should parse");

        assert_eq!(
            maturity_warning_for(doctor_json.command.as_ref(), false, true),
            None
        );
        assert_eq!(
            maturity_warning_for(trace_json.command.as_ref(), false, true),
            None
        );
        assert_eq!(maturity_warning_for(None, true, true), None);
        assert_eq!(
            maturity_warning_for(doctor_text.command.as_ref(), false, true),
            CommandMaturity::Preview.warning()
        );
        assert_eq!(maturity_warning_for(None, false, false), None);
    }

    fn private_test_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("neutron-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn ring_poll_errors_are_fail_closed_but_eintr_is_retryable() {
        assert_eq!(ring_poll_failure(-1, 0, Some(libc::EINTR)), None);
        assert!(ring_poll_failure(-1, 0, Some(libc::EBADF))
            .is_some_and(|error| error.contains("errno")));
        assert!(ring_poll_failure(1, libc::POLLNVAL, None)
            .is_some_and(|error| error.contains("terminal revents")));
        assert_eq!(ring_poll_failure(0, 0, None), None);
    }

    #[test]
    fn external_crash_attribution_requires_recent_matching_bpf_exit_and_is_inferred() {
        let metadata = CausalMetadata {
            scenario_id: "camera".into(),
            trace_id: 7,
            span_id: 11,
            parent_span_id: 12,
            depth: 1,
            relation: CausalRelation::Exact,
            root_package: Some("com.example".into()),
            root_uid: Some(10123),
        };
        let mut recent = HashMap::from([(
            42,
            RecentExitCausal {
                metadata: metadata.clone(),
                exit_ts_ns: 1_000,
                comm: "vendor.hal".into(),
            },
        )]);
        let mut event = ProcessExitEvent {
            ts_ns: 2_000,
            pid: 42,
            uid: Some(1000),
            comm: "vendor.hal".into(),
            exit_code: 0,
            exit_signal: 11,
            source: ExitSource::Logcat,
        };

        let mut expected = metadata.clone();
        expected.relation = CausalRelation::Inferred;
        assert_eq!(correlate_recent_exit(&mut recent, &event), Some(expected));
        event.comm = "reused.pid".into();
        assert!(correlate_recent_exit(&mut recent, &event).is_none());
        event.comm = "vendor.hal".into();
        event.ts_ns = 1_000 + RECENT_EXIT_CAUSAL_TTL_NS + 1;
        assert!(correlate_recent_exit(&mut recent, &event).is_none());
        assert!(recent.is_empty());
    }

    #[test]
    fn follow_children_never_promotes_thread_ids_to_process_pids() {
        let process_child = SyscallEvent {
            syscall_nr: SYSCALL_CLONE,
            is_enter: 0,
            ret: 4242,
            args: [0; 6],
            ..SyscallEvent::default()
        };
        assert_eq!(followed_child_pid(&process_child), Some(4242));

        let thread_child = SyscallEvent {
            args: [CLONE_THREAD, 0, 0, 0, 0, 0],
            ..process_child
        };
        assert_eq!(followed_child_pid(&thread_child), None);
    }

    #[test]
    fn process_context_lookup_only_treats_absent_keys_as_no_context() {
        assert!(process_context_lookup(42, Err(MapError::KeyNotFound))
            .unwrap()
            .is_none());
        let error = process_context_lookup(42, Err(MapError::ElementNotFound)).unwrap_err();
        assert!(format!("{error:#}").contains("reading traced process PID 42"));
        assert!(format!("{error:#}").contains("element not found"));
    }

    #[test]
    fn followed_process_key_iteration_is_fail_closed() {
        let pid = 42_u32;
        let matching = (u64::from(pid) << 32) | 7;
        let other = (43_u64 << 32) | 8;
        assert_eq!(
            process_thread_keys(
                vec![Ok(matching), Ok(other)].into_iter(),
                pid,
                "THREAD_BINDER_CONTEXT",
            )
            .unwrap(),
            [matching]
        );

        let error = process_thread_keys(
            vec![Ok(matching), Err(MapError::KeyNotFound)].into_iter(),
            pid,
            "THREAD_BINDER_CONTEXT",
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("iterating THREAD_BINDER_CONTEXT keys"));
    }

    #[test]
    fn pinned_configuration_hashes_the_same_bounded_bytes_that_are_parsed() {
        let directory = private_test_dir("pinned-config");
        let path = directory.join("config.json");
        std::fs::write(&path, b"{\"value\":1}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let pinned = read_pinned_configuration(path.to_str().unwrap(), "test config").unwrap();
        std::fs::write(&path, b"{\"value\":2}").unwrap();

        assert_eq!(pinned.content, "{\"value\":1}");
        assert_eq!(
            pinned.sha256,
            format!("{:x}", Sha256::digest(b"{\"value\":1}"))
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o622)).unwrap();
        assert!(read_pinned_configuration(path.to_str().unwrap(), "test config").is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pinned_configuration_rejects_symlinks() {
        let directory = private_test_dir("pinned-config-link");
        let target = directory.join("target.json");
        let link = directory.join("link.json");
        std::fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_pinned_configuration(link.to_str().unwrap(), "test config").is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn live_marker_includes_uid_root_metadata() {
        let request = neutron::causal::MarkRequest {
            name: "surface-observe".into(),
            phase: "start".into(),
            meta: Default::default(),
        };
        let scenario = ScenarioInfo {
            scenario_id: "surface-observe".into(),
            trace_id: 1,
            generation: 1,
        };
        let line = live_marker_line(&request, &scenario, 42, None, Some(10123), None);
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["root_uid"], 10123);
        assert!(value.get("root_package").is_none());
    }

    #[test]
    fn harness_capture_requires_narrow_scope_file_output_and_no_sampling() {
        let mut args = Args {
            harness_capture: true,
            ..Default::default()
        };
        assert!(validate_harness_capture_args(&args)
            .unwrap_err()
            .to_string()
            .contains("--package"));
        args.pid = 42;
        assert!(validate_harness_capture_args(&args)
            .unwrap_err()
            .to_string()
            .contains("--output"));
        args.output = Some("capture.ndjson".into());
        validate_harness_capture_args(&args).unwrap();
        args.sample = Some(0.5);
        assert!(validate_harness_capture_args(&args).is_err());
    }

    #[test]
    fn output_sink_preserves_marker_appends_while_tracer_is_running() {
        let dir =
            std::env::temp_dir().join(format!("neutron-output-append-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("capture.ndjson");
        let path_s = path.to_string_lossy().into_owned();

        {
            let mut out = open_output(Some(&path_s), None, None, Arc::new(AtomicBool::new(false)))
                .expect("open trace output");
            writeln!(out, r#"{{"type":"syscall","event_id":1}}"#).unwrap();

            mark::run(MarkArgs {
                name: "scenario".into(),
                phase: Some("start".into()),
                meta: vec![],
                output: Some(path_s.clone()),
                control_socket: "off".into(),
                ts_ns: Some(42),
            })
            .expect("append marker while trace output is open");

            writeln!(out, r#"{{"type":"syscall","event_id":2}}"#).unwrap();
        }

        let content = std::fs::read_to_string(&path).expect("read output");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            content.contains(r#""type":"marker""#),
            "marker append must survive tracer writes; got:\n{content}"
        );
        assert!(
            content.contains(r#""name":"scenario""#),
            "marker name should remain readable; got:\n{content}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn capture_output_rejects_symlinks_without_truncating_target() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!(
            "neutron-output-symlink-test-{}",
            std::process::id()
        ));
        let victim = base.with_extension("victim");
        let link = base.with_extension("link");
        let _ = std::fs::remove_file(&victim);
        let _ = std::fs::remove_file(&link);
        std::fs::write(&victim, b"preserve\n").unwrap();
        symlink(&victim, &link).unwrap();

        let link_s = link.to_string_lossy().into_owned();
        assert!(open_output(Some(&link_s), None, None, Arc::new(AtomicBool::new(false))).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"preserve\n");

        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&victim);
    }

    #[test]
    fn parse_output_size_accepts_binary_suffixes() {
        assert_eq!(parse_output_size_bytes(None).unwrap(), None);
        assert_eq!(parse_output_size_bytes(Some("off")).unwrap(), None);
        assert_eq!(parse_output_size_bytes(Some("512")).unwrap(), Some(512));
        assert_eq!(parse_output_size_bytes(Some("2kb")).unwrap(), Some(2048));
        assert_eq!(
            parse_output_size_bytes(Some("3mb")).unwrap(),
            Some(3 * 1024 * 1024)
        );
    }

    #[test]
    fn cli_accepts_health_output_sidecar_path() {
        let cli = Cli::try_parse_from(["neutron", "--health-output", "/tmp/neutron.health.ndjson"])
            .expect("parse --health-output");

        assert_eq!(
            cli.args.health_output.as_deref(),
            Some("/tmp/neutron.health.ndjson")
        );
    }

    #[test]
    fn trace_run_bundle_privately_routes_capture_and_health_outputs() {
        let parent = private_test_dir("trace-run-bundle");
        let run_dir = parent.join("run");
        let mut args = Args {
            run_dir: Some(run_dir.clone()),
            attacker_capability: "not_tested".into(),
            ..Args::default()
        };

        let bundle = configure_trace_run_bundle(&mut args)
            .expect("configure trace run bundle")
            .expect("bundle enabled");
        assert_eq!(bundle.run_dir, run_dir);
        assert_eq!(
            args.output.as_deref(),
            Some(run_dir.join("capture.ndjson").to_str().unwrap())
        );
        assert_eq!(
            args.health_output.as_deref(),
            Some(run_dir.join("capture.health.json").to_str().unwrap())
        );
        assert!(args.json);
        assert_eq!(args.max_output_size.as_deref(), Some("1gb"));
        let metadata = std::fs::metadata(&run_dir).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o077, 0);
        let _ = std::fs::remove_dir_all(parent);
    }

    #[test]
    fn trace_run_bundle_runtime_validation_fails_closed_on_conflicts() {
        for mut args in [
            Args {
                run_dir: Some("run".into()),
                output: Some("capture.ndjson".into()),
                ..Args::default()
            },
            Args {
                run_dir: Some("run".into()),
                health_output: Some("capture.health.json".into()),
                ..Args::default()
            },
            Args {
                run_dir: Some("run".into()),
                rotate_output_size: Some("1mb".into()),
                ..Args::default()
            },
        ] {
            assert!(configure_trace_run_bundle(&mut args).is_err());
        }
    }

    #[test]
    fn primary_and_health_outputs_must_be_distinct_after_parent_resolution() {
        let temporary = std::env::temp_dir();
        let primary = temporary.join("neutron-output-collision.ndjson");
        let equivalent = temporary.join(".").join("neutron-output-collision.ndjson");

        let error = validate_distinct_output_paths(primary.to_str(), equivalent.to_str(), false)
            .unwrap_err();
        assert!(error.to_string().contains("must name different files"));
    }

    #[test]
    fn health_output_cannot_overwrite_a_rotated_segment() {
        let temporary = std::env::temp_dir();
        let primary = temporary.join("neutron-rotating.ndjson");
        let health = temporary.join("neutron-rotating.ndjson.1");

        let error =
            validate_distinct_output_paths(primary.to_str(), health.to_str(), true).unwrap_err();
        assert!(error.to_string().contains("rotation namespace"));
    }

    #[test]
    fn cli_accepts_capture_lock_auto_and_off_modes() {
        let cli = Cli::try_parse_from(["neutron"]).expect("parse default capture lock");
        assert_eq!(cli.args.capture_lock, "auto");

        let cli = Cli::try_parse_from(["neutron", "--capture-lock", "off"])
            .expect("parse disabled capture lock");
        assert_eq!(cli.args.capture_lock, "off");
    }

    #[test]
    fn capture_privilege_preflight_rejects_doctor_failures() {
        let check = doctor::CheckResult::fail(
            "privilege",
            "non-root (euid=2000) and CapEff=0x0 lacks CAP_BPF + CAP_SYS_ADMIN",
        );

        let err = capture_privilege_preflight(&check).expect_err("privilege failure should stop");
        let msg = format!("{err:#}");
        assert!(msg.contains("privilege preflight failed"));
        assert!(msg.contains("neutron doctor"));
        assert!(msg.contains("adb shell"));
    }

    #[test]
    fn match_package_shared_uid_warning_flags_system_aids() {
        let warning = android::match_package_uid_warning("com.android.settings", 1000)
            .expect("system UID should warn");

        assert!(warning.contains("shared/system UID"));
        assert!(warning.contains("com.android.settings"));
        assert!(warning.contains("uid 1000"));
    }

    #[test]
    fn match_package_shared_uid_warning_is_silent_for_app_uid() {
        assert!(
            android::match_package_uid_warning("com.google.android.GoogleCamera", 10145).is_none()
        );
    }

    #[test]
    fn capture_lock_rejects_second_owner_until_first_drops() {
        let directory = private_test_dir("capture-lock");
        let path = directory.join("capture.lock");

        let first = CaptureLock::acquire(&path).expect("first lock owner");
        let err = CaptureLock::acquire(&path).expect_err("second owner should fail");
        assert!(format!("{err:#}").contains("another neutron capture appears active"));

        drop(first);
        let _second = CaptureLock::acquire(&path).expect("lock released after drop");
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn automatic_capture_lock_uses_a_private_runtime_directory() {
        let path = resolve_capture_lock_path("auto")
            .expect("resolve automatic lock")
            .expect("automatic lock enabled");
        let parent = path.parent().expect("lock parent");
        let metadata = std::fs::metadata(parent).expect("private runtime metadata");
        use std::os::unix::fs::MetadataExt as _;
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.mode() & 0o077, 0);

        let lock = acquire_capture_lock("auto")
            .expect("acquire automatic lock")
            .expect("automatic lock enabled");
        drop(lock);
        std::fs::remove_file(&path).expect("remove test lock");
    }

    #[test]
    fn capture_lock_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = private_test_dir("capture-lock-symlink");
        let target = directory.join("target");
        let link = directory.join("link");
        std::fs::write(&target, b"do-not-lock").unwrap();
        symlink(&target, &link).unwrap();

        assert!(CaptureLock::acquire(&link).is_err());

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn health_sidecar_writes_even_when_primary_output_cap_is_hit() {
        let dir = private_test_dir("health-sidecar");
        let out_path = dir.join("capture.ndjson");
        let health_path = dir.join("capture.health.ndjson");
        let out_s = out_path.to_string_lossy().into_owned();
        let health_s = health_path.to_string_lossy().into_owned();

        let hit = Arc::new(AtomicBool::new(false));
        let mut out = open_output(Some(&out_s), Some(4), None, hit.clone()).expect("open output");
        let _ = out.write_all(b"abcd");
        assert!(hit.load(Ordering::Relaxed));

        write_health_sidecar(
            Some(&health_s),
            r#"{"type":"capture_health","output_cap_hit":true}"#,
        )
        .expect("write sidecar");

        let health = std::fs::read_to_string(&health_path).expect("read sidecar");
        assert!(health.contains(r#""type":"capture_health""#));
        assert!(health.ends_with('\n'));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn capture_write_errors_are_fatal_unless_the_configured_cap_was_hit() {
        let cap_hit = AtomicBool::new(false);
        let error = write_or_output_cap(
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed")),
            &cap_hit,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("writing capture output"));

        cap_hit.store(true, Ordering::Relaxed);
        write_or_output_cap(
            Err(io::Error::new(io::ErrorKind::WriteZero, "capped")),
            &cap_hit,
        )
        .unwrap();
    }

    #[test]
    fn capture_health_sidecar_write_errors_are_returned() {
        let directory = std::env::temp_dir();
        assert!(write_health_sidecar(Some(&directory), r#"{"type":"capture_health"}"#,).is_err());
    }

    #[test]
    fn capped_writer_sets_flag_without_exceeding_limit() {
        let hit = Arc::new(AtomicBool::new(false));
        let inner: Box<dyn IoWrite> = Box::new(Vec::<u8>::new());
        let mut writer = CappedWriter::new(inner, 4, hit.clone());

        writer.write_all(b"abcd").unwrap();
        assert!(hit.load(Ordering::Relaxed));
        assert!(writer.write_all(b"e").is_err());
    }

    #[test]
    fn streamed_record_rejected_by_cap_is_atomic_and_not_counted() {
        let dir = private_test_dir("record-cap-atomic");
        let path = dir.join("capture.ndjson");
        let path_s = path.to_string_lossy().into_owned();
        let hit = Arc::new(AtomicBool::new(false));
        let records = Arc::new(AtomicU64::new(0));

        {
            let sink = open_output(Some(&path_s), Some(5), None, hit.clone()).unwrap();
            let mut writer = RecordCountingWriter::new(sink, records.clone());
            writer.write_all(b"abc").unwrap();
            assert!(writer.write_all(b"def\n").is_err());
            assert!(hit.load(Ordering::Relaxed));
            assert_eq!(records.load(Ordering::Relaxed), 0);
            writer.flush().unwrap();
        }

        assert_eq!(std::fs::read(&path).unwrap(), b"");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn streamed_records_are_counted_only_after_complete_sink_writes() {
        let dir = private_test_dir("record-counting");
        let path = dir.join("capture.ndjson");
        let path_s = path.to_string_lossy().into_owned();
        let records = Arc::new(AtomicU64::new(0));

        {
            let sink =
                open_output(Some(&path_s), None, None, Arc::new(AtomicBool::new(false))).unwrap();
            let mut writer = RecordCountingWriter::new(sink, records.clone());
            writer.write_all(b"one").unwrap();
            assert_eq!(records.load(Ordering::Relaxed), 0);
            writer.write_all(b"\ntw").unwrap();
            assert_eq!(records.load(Ordering::Relaxed), 1);
            writer.write_all(b"o\n").unwrap();
            writer.flush().unwrap();
        }

        assert_eq!(records.load(Ordering::Relaxed), 2);
        assert_eq!(std::fs::read(&path).unwrap(), b"one\ntwo\n");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rotating_writer_rolls_to_numbered_segments() {
        let dir = private_test_dir("rotate-test");
        let base = dir.join("capture.ndjson");
        let base_s = base.to_string_lossy().into_owned();
        let rotated_s = format!("{base_s}.1");

        {
            let mut writer = RotatingWriter::new(&base_s, 6).expect("open rotating writer");
            writer.write_all(b"aaaa\n").unwrap();
            writer.write_all(b"bbbb\n").unwrap();
            writer.flush().unwrap();
        }

        let first = std::fs::read_to_string(&base_s).expect("read base segment");
        let second = std::fs::read_to_string(&rotated_s).expect("read rotated segment");
        let _ = std::fs::remove_dir_all(dir);

        assert_eq!(first, "aaaa\n");
        assert_eq!(second, "bbbb\n");
    }

    #[test]
    fn rotation_never_splits_a_streamed_record() {
        let dir = private_test_dir("rotate-record-atomic");
        let base = dir.join("capture.ndjson");
        let base_s = base.to_string_lossy().into_owned();
        let rotated_s = format!("{base_s}.1");
        let records = Arc::new(AtomicU64::new(0));

        {
            let sink: Box<dyn IoWrite> =
                Box::new(RotatingWriter::new(&base_s, 6).expect("open rotating writer"));
            let mut writer = RecordCountingWriter::new(sink, records.clone());
            writer.write_all(b"aa").unwrap();
            writer.write_all(b"aa\nbb").unwrap();
            writer.write_all(b"bb\n").unwrap();
            writer.flush().unwrap();
        }

        let first = std::fs::read_to_string(&base_s).expect("read base segment");
        let second = std::fs::read_to_string(&rotated_s).expect("read rotated segment");
        let _ = std::fs::remove_dir_all(dir);

        assert_eq!(records.load(Ordering::Relaxed), 2);
        assert_eq!(first, "aaaa\n");
        assert_eq!(second, "bbbb\n");
    }

    #[test]
    fn open_output_rejects_rotation_without_file_output() {
        let err = match open_output(None, None, Some(1024), Arc::new(AtomicBool::new(false))) {
            Ok(_) => panic!("rotation without --output should fail"),
            Err(err) => err,
        };
        assert!(format!("{err:#}").contains("--rotate-output-size requires --output"));
    }

    #[test]
    fn open_output_rejects_cap_and_rotation_together() {
        let path =
            std::env::temp_dir().join(format!("neutron-rotate-conflict-{}", std::process::id()));
        let path_s = path.to_string_lossy().into_owned();
        let err = match open_output(
            Some(&path_s),
            Some(1024),
            Some(1024),
            Arc::new(AtomicBool::new(false)),
        ) {
            Ok(_) => panic!("cap and rotation together should fail"),
            Err(err) => err,
        };
        assert!(format!("{err:#}").contains("mutually exclusive"));
    }

    #[test]
    fn guardrails_warn_on_broad_raw_binder_capture_without_rate_limit() {
        let args = Args {
            pid: 0,
            binder: true,
            raw: true,
            no_findings: true,
            ..Args::default()
        };

        let warnings = capture_guardrail_warnings(&args);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("--pid 0") && w.contains("--binder") && w.contains("--raw")),
            "expected broad raw binder warning, got {warnings:?}"
        );
    }

    #[test]
    fn guardrails_explain_binder_context_with_match_filters() {
        let args = Args {
            binder: true,
            binder_inflight: 1024,
            match_uid: vec!["10341".into()],
            ..Args::default()
        };

        let warnings = capture_guardrail_warnings(&args);
        assert!(
            warnings.iter().any(|w| w.contains("binder_call")),
            "expected binder_call context warning, got {warnings:?}"
        );
    }

    #[test]
    fn effective_capture_scope_records_output_filters_instrumentation_and_packs() {
        let args = Args {
            json: true,
            raw: false,
            match_syscall: vec!["29".into()],
            match_fd: vec!["/dev/kgsl*".into()],
            match_comm: vec!["vendor-hal*".into()],
            match_binder_code: vec!["2".into()],
            exclude_comm: vec!["traced".into()],
            binder: true,
            follow_binder: true,
            stacks: true,
            driver_pack: vec!["kgsl".into()],
            kprobe_pack: vec!["kgsl".into()],
            ..Args::default()
        };
        let predicate = build_capture_predicate(&args).unwrap();
        let kprobe = KprobePackScope {
            name: "kgsl".into(),
            requested_sources: vec!["kprobe_kgsl_ioctl@kgsl_ioctl".into()],
            attached_sources: vec!["kprobe_kgsl_ioctl@kgsl_ioctl".into()],
            failures: Vec::new(),
        };
        let bpf_identity = BpfObjectIdentity {
            object_sha256: "1".repeat(64),
            section: neutron_common::BPF_ABI_SECTION_NAME,
            magic: "NEUTRON".into(),
            abi_major: neutron_common::BPF_ABI_MAJOR,
            abi_minor: neutron_common::BPF_ABI_MINOR,
            syscall_event_size: core::mem::size_of::<SyscallEvent>() as u32,
            feature_bits: neutron_common::BPF_FEATURE_SYSCALL_TRACE,
            build_id: "2".repeat(40),
            build_id_present: true,
        };
        let schema_identity = CaptureContentIdentity {
            name: "pixel-gpu".into(),
            sha256: "4".repeat(64),
        };
        let tool_identity = neutron::run_manifest::ToolIdentity {
            version: "1.5.0-rc.1".into(),
            git_commit: "6".repeat(40),
            git_dirty: false,
            binary_sha256: "7".repeat(64),
            build_timestamp: "2026-07-17T00:00:00Z".into(),
            rustc: "rustc test".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            feature_set: Vec::new(),
        };
        let scope = effective_capture_scope(
            &args,
            &predicate,
            CaptureMode::MatchedWithContext { duration_ns: 1_000 },
            true,
            true,
            Some(4096),
            None,
            Some(10123),
            30_000_000_000,
            &["kgsl".into()],
            &[kprobe],
            &["pixel-gpu".into()],
            &[schema_identity],
            Some(&"3".repeat(64)),
            Some(&"5".repeat(64)),
            None,
            None,
            None,
            None,
            &bpf_identity,
            &tool_identity,
            true,
            true,
            true,
            true,
        );

        assert_eq!(scope.output.event_mode, "findings_only");
        assert_eq!(scope.output.capture_mode, "matched_with_context");
        assert_eq!(scope.output.context_duration_ns, Some(1_000));
        assert!(scope
            .filters
            .bpf
            .iter()
            .any(|value| value.contains("syscall")));
        assert!(scope
            .filters
            .userspace
            .iter()
            .any(|value| value.contains("fd_path")));
        assert!(scope
            .filters
            .userspace
            .iter()
            .any(|value| value.contains("comm")));
        assert!(scope
            .filters
            .userspace
            .iter()
            .any(|value| value.contains("binder.code")));
        assert_eq!(scope.filters.exclude_comm, ["traced"]);
        assert!(scope.instrumentation.binder_tracepoints);
        assert!(scope.instrumentation.causal_follow);
        assert!(scope.instrumentation.stacks);
        assert_eq!(scope.packs.driver, ["kgsl"]);
        assert_eq!(scope.packs.kprobe[0].name, "kgsl");
        assert_eq!(scope.packs.schema, ["pixel-gpu"]);
        assert_eq!(scope.packs.schema_identities[0].sha256, "4".repeat(64));
        assert_eq!(scope.findings.rules_sha256, Some("3".repeat(64)));
        assert_eq!(
            scope.enrichment.binder_services_sha256,
            Some("5".repeat(64))
        );
        assert_eq!(scope.producer.bpf_object_sha256, "1".repeat(64));
        assert_eq!(scope.producer.userspace_binary_sha256, "7".repeat(64));
        assert!(!scope.claim_scope_complete);
    }

    #[test]
    fn kernel_lpe_profile_populates_syscall_whitelist_defaults() {
        let mut args = Args {
            profile: Some("kernel-lpe".into()),
            ..Args::default()
        };
        apply_profile(&mut args).expect("profile applies");
        let spec = matcher::build_from_args(&args).expect("profile match spec");
        for nr in [29, 98, 198, 211, 212, 220, 222, 226, 280] {
            assert!(
                spec.syscalls.contains(&nr),
                "kernel-lpe should include syscall {nr}; got {:?}",
                spec.syscalls
            );
        }
    }

    #[test]
    fn security_profile_populates_documented_syscall_whitelist_and_exclusions() {
        let mut args = Args {
            profile: Some(SECURITY_PROFILE.into()),
            ..Args::default()
        };

        apply_profile(&mut args).expect("security profile applies");
        let spec = matcher::build_from_args(&args).expect("security profile match spec");

        assert_eq!(
            spec.syscalls,
            BTreeSet::from([
                29, 48, 56, 78, 79, 129, 167, 198, 200, 203, 206, 207, 220, 221, 222, 226, 281,
            ])
        );
        assert_eq!(
            args.exclude_comm,
            SECURITY_EXCLUDE_COMM
                .iter()
                .map(|value| (*value).to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn security_profile_preserves_explicit_syscall_whitelist() {
        let mut args = Args {
            profile: Some(SECURITY_PROFILE.into()),
            match_syscall: vec!["172".into()],
            ..Args::default()
        };

        apply_profile(&mut args).expect("security profile applies");

        assert_eq!(args.match_syscall, ["172"]);
        assert_eq!(
            args.exclude_comm,
            SECURITY_EXCLUDE_COMM
                .iter()
                .map(|value| (*value).to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn security_profile_preserves_explicit_match_expression() {
        let expression = "uid = 10361 AND syscall = ioctl";
        let mut args = Args {
            profile: Some(SECURITY_PROFILE.into()),
            match_expr: Some(expression.into()),
            ..Args::default()
        };

        apply_profile(&mut args).expect("security profile applies");

        assert_eq!(args.match_expr.as_deref(), Some(expression));
        assert!(args.match_syscall.is_empty());
        assert!(matches!(
            build_capture_predicate(&args).expect("expression remains usable"),
            CapturePredicate::Expr { .. }
        ));
    }

    #[test]
    fn driver_pack_defaults_scope_to_fd_and_ioctl_type_when_no_user_match() {
        let mut args = Args {
            driver_pack: vec!["kgsl".into()],
            ..Args::default()
        };
        let packs = apply_driver_packs(&mut args).expect("driver pack applies");
        let spec = matcher::build_from_args(&args).expect("driver pack match spec");
        assert!(spec.syscalls.contains(&29));
        assert!(spec.ioctl_types.contains(&neutron_common::IOCTL_TYPE_KGSL));
        assert_eq!(spec.fd_globs, vec!["/dev/kgsl*"]);
        assert!(packs
            .refresh_types
            .contains(&neutron_common::IOCTL_TYPE_KGSL));
    }

    #[test]
    fn guardrails_warn_on_uncapped_broad_file_output() {
        let args = Args {
            pid: 0,
            raw: true,
            output: Some("/data/local/tmp/trace.ndjson".into()),
            ..Args::default()
        };

        let warnings = capture_guardrail_warnings(&args);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("--max-output-size") && w.contains("--output")),
            "expected uncapped output warning, got {warnings:?}"
        );
    }

    #[test]
    fn guardrails_treat_rotation_as_output_bound() {
        let args = Args {
            pid: 0,
            raw: true,
            output: Some("/data/local/tmp/trace.ndjson".into()),
            rotate_output_size: Some("250mb".into()),
            ..Args::default()
        };

        let warnings = capture_guardrail_warnings(&args);
        assert!(
            warnings.iter().all(|w| !w.contains("uncapped output")),
            "rotation should suppress uncapped output warning, got {warnings:?}"
        );
    }

    #[test]
    fn pre_admission_follow_denies_normalize_requested_domains() {
        let args = Args {
            follow_binder: true,
            follow_deny_domain: vec!["u:r:system_server:s0".into(), "servicemanager".into()],
            ..Args::default()
        };

        assert_eq!(
            pre_admission_follow_deny_domains(&args).unwrap(),
            BTreeSet::from(["servicemanager".to_string(), "system_server".to_string()])
        );
    }

    #[test]
    fn android_provider_match_counts_as_capture_predicate_flag() {
        let args = Args {
            match_android_provider: vec!["com.android.contacts".into()],
            ..Args::default()
        };

        assert!(any_individual_match_flag(&args));
    }

    fn test_denial() -> neutron::selinux::SelinuxDenial {
        neutron::selinux::parse_avc_line(
            r#"audit(1.0:2): avc: denied { ioctl } for pid=42 comm="app" path="/dev/test" scontext=u:r:app:s0 tcontext=u:object_r:test_device:s0 tclass=chr_file permissive=0"#,
        )
        .unwrap()
        .unwrap()
    }

    #[test]
    fn selinux_scope_applies_pid_uid_and_exclusion() {
        let mut denial = test_denial();
        denial.uid = Some(10123);
        let pids = BTreeSet::from([42]);
        let uids = BTreeSet::from([10123]);
        assert!(selinux_denial_in_scope(
            &denial,
            &Args::default(),
            &[],
            &pids,
            &uids,
            None,
        ));

        let args = Args {
            exclude_comm: vec!["app".into()],
            ..Args::default()
        };
        assert!(!selinux_denial_in_scope(
            &denial,
            &args,
            &[],
            &pids,
            &uids,
            None,
        ));
    }

    #[test]
    fn selinux_denials_share_the_global_event_counter() {
        let mut counter = 40;
        let mut output = Vec::new();
        for _ in 0..2 {
            let mut denial = test_denial();
            denial.ts_ns = 10;
            emit_selinux_denial(&mut denial, None, None, &mut output, true, &mut counter).unwrap();
        }
        let ids: Vec<u64> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["event_id"]
                    .as_u64()
                    .unwrap()
            })
            .collect();
        assert_eq!(ids, [41, 42]);
    }

    #[test]
    fn selinux_denial_marks_binder_process_context_inferred() {
        let mut denial = test_denial();
        denial.ts_ns = 99;
        let scenario = ScenarioInfo {
            scenario_id: "test".into(),
            trace_id: 7,
            generation: 1,
        };
        let context = ProcessTraceContext {
            root_trace_id: 7,
            parent_pid: 10,
            binder_debug_id: 5,
            depth: 1,
            reason: TraceReason::Binder,
            scenario_generation: 1,
        };
        let metadata = causal_metadata_for_selinux_denial(
            &denial,
            context,
            &scenario,
            Some("com.example.app"),
            Some(10123),
        );
        assert_eq!(metadata.relation, CausalRelation::Inferred);
        assert_eq!(metadata.parent_span_id, binder_span_id(7, 5));
        assert_eq!(metadata.root_package.as_deref(), Some("com.example.app"));
        assert_eq!(metadata.root_uid, Some(10123));
    }
}
