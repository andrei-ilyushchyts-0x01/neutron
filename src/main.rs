//! neutron — Aya-based syscall tracer for authorized Android security
//! assessment.
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
use std::io::{self, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use std::os::fd::AsRawFd;

use anyhow::{bail, Context, Result};
use aya::maps::{Array, HashMap as AyaHashMap, MapError, RingBuf, StackTraceMap};
use aya::programs::{KProbe, TracePoint};
use aya::{Ebpf, EbpfLoader, VerifierLogLevel};
use clap::Parser;

use neutron::aidl::AidlCatalog;
use neutron::android;
use neutron::binder_services::{BinderCatalog, BinderMethodMap, BinderServiceMap};
use neutron::capture::{CaptureMode, ContextRing, DEFAULT_MAX_EVENTS};
use neutron::causal::{
    binder_span_id, enrich_json, expired_followed_pids, monotonic_timestamp_ns, parse_follow_ttl,
    process_context_bytes, process_context_from_bytes, process_exit_span_id, root_process_span_id,
    selinux_denial_span_id, syscall_span_id, CausalMetadata, CausalRelation, CausalWire,
    ControlServer, FollowCandidate, FollowDecision, FollowPolicy, ScenarioInfo, ScenarioState,
};
use neutron::cli::{AidlCommand, Args, Cli, Command, HarnessCommand, IoctlCommand};
use neutron::decode::{compute_latency_us, format_comm, format_data_field, resolve_path_from_fd};
use neutron::doctor;
use neutron::fdgraph::poller::{self as poller, PollerConfig, RealProcReader, ScopePolicy};
use neutron::fdgraph::FdGraph;
use neutron::format::{
    format_binder_call_json_with_attribution, format_event_json_full, format_event_text_with_stack,
    format_fd_snapshot_json, format_process_exit_json, FdHint,
};
use neutron::health::{
    format_capture_health_json_with_metadata, format_summary_with, CaptureHealth, CaptureMetadata,
    UserspaceHealth,
};
use neutron::matcher::{self, MatchSpec, SyscallEventLens};
use neutron::predicate;
use neutron::rules::{build_rule_engine, emit_findings_with};
use neutron::sampler::SamplerChain;
use neutron::selinux::SelinuxLogcatReader;
use neutron::sources::binder_tracker::BinderTracker;
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
const SYSCALL_OPENAT: i32 = 56;
const SYSCALL_CLOSE: i32 = 57;
const SYSCALL_MMAP: i32 = 222;
const SYSCALL_MPROTECT: i32 = 226;

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

// ── Banner ───────────────────────────────────────────────────────────────────

fn print_banner() {
    eprintln!(
        "neutron {} — Aya, kernel 6.1+ (Pixel 8 Pro)",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!("authorized security testing only — see SECURITY.md");
    eprintln!();
}

fn trimmed_nonempty(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn read_boot_id() -> Option<String> {
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    trimmed_nonempty(&value)
}

fn read_build_fingerprint() -> Option<String> {
    let output = std::process::Command::new("/system/bin/getprop")
        .arg("ro.build.fingerprint")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    trimmed_nonempty(&String::from_utf8_lossy(&output.stdout))
}

fn read_device_serial() -> Option<String> {
    let output = std::process::Command::new("/system/bin/getprop")
        .arg("ro.serialno")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    trimmed_nonempty(&String::from_utf8_lossy(&output.stdout))
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

fn load_bpf(object_path: &str, max_processes: u32, verbose: bool) -> Result<Ebpf> {
    let bytes =
        fs::read(object_path).with_context(|| format!("cannot read BPF object {object_path}"))?;
    let log_level = if verbose {
        VerifierLogLevel::DEBUG | VerifierLogLevel::STATS
    } else {
        VerifierLogLevel::STATS
    };
    EbpfLoader::new()
        // DEBUG logs every verifier step and can itself exhaust the kernel's
        // log buffer on large programs before the useful rejection reason.
        .verifier_log_level(log_level)
        .set_max_entries("TRACED_PROCESSES", max_processes)
        .load(&bytes)
        .with_context(|| format!("Ebpf::load failed for {object_path}"))
}

fn missing_stack_map_warning(stacks_requested: bool, stack_map_present: bool) -> Option<String> {
    if stacks_requested && !stack_map_present {
        Some(format!(
            "--stacks requested but this BPF object has no STACK_TRACES map; \
             use {STACKFUL_BPF_OBJECT} or rebuild with `cargo xtask build-ebpf --stacks`"
        ))
    } else {
        None
    }
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

fn attach_kprobe_packs(
    bpf: &mut Ebpf,
    packs: &[String],
    attached: &mut Vec<&'static str>,
) -> Result<()> {
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
        for (program, symbol) in candidates {
            match attach_kprobe_if_present(bpf, program, symbol) {
                Ok(true) => {
                    any = true;
                    attached.push(*program);
                }
                Ok(false) => {
                    eprintln!(
                        "neutron: warn: kprobe pack {pack}: BPF program {program} not present; skipping {symbol}"
                    );
                }
                Err(e) => {
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
    }
    Ok(())
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
/// `STATE_EMIT_REQUIRED` if any clause depends on userspace fdgraph state.
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

    // STATE_EMIT_REQUIRED bit — flip on whenever userspace will need state
    // events to keep fdgraph consistent.
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

fn default_capture_lock_path() -> PathBuf {
    let android_tmp = Path::new("/data/local/tmp");
    if android_tmp.is_dir() {
        android_tmp.join("neutron.capture.lock")
    } else {
        std::env::temp_dir().join("neutron.capture.lock")
    }
}

fn resolve_capture_lock_path(raw: &str) -> Result<Option<PathBuf>> {
    let raw = raw.trim();
    if raw.is_empty() || raw.eq_ignore_ascii_case("auto") {
        return Ok(Some(default_capture_lock_path()));
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
    fn acquire(path: &str) -> Result<Self> {
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("opening capture lock {path}"))?;
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
                "another neutron capture appears active (lock {path}); run one capture at a time \
                 or pass --capture-lock off for advanced debugging"
            );
        }
        Err(err).with_context(|| format!("locking capture lock {path}"))
    }
}

fn acquire_capture_lock(raw: &str) -> Result<Option<CaptureLock>> {
    let Some(path) = resolve_capture_lock_path(raw)? else {
        eprintln!("neutron: WARNING: capture lock disabled by --capture-lock off");
        return Ok(None);
    };
    let path_s = path.to_string_lossy().into_owned();
    Ok(Some(CaptureLock::acquire(&path_s)?))
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
        let n = self.inner.write(buf)?;
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
        let file = fs::File::create(path).with_context(|| format!("cannot create {path}"))?;
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
        let file = fs::File::create(&path)?;
        self.inner = std::io::LineWriter::new(file);
        eprintln!("neutron: rotated output to {path}");
        Ok(())
    }
}

impl IoWrite for RotatingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.segment_bytes > 0
            && self.segment_bytes.saturating_add(buf.len() as u64) > self.max_segment_bytes
        {
            self.rotate()?;
        }
        let n = self.inner.write(buf)?;
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
            fs::File::create(p).with_context(|| format!("cannot create {p}"))?;
            let f = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .with_context(|| format!("cannot open {p} for append"))?;
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
    fs::write(path, body)
        .with_context(|| format!("writing capture health sidecar {}", path.to_string_lossy()))
}

// ── Stack symbolization helper ───────────────────────────────────────────────

/// Render one stack-trace map entry. Picks the right symbolizer per frame
/// based on the canonical aarch64 user/kernel split.
fn format_stack(
    stack_traces: &StackTraceMap<&aya::maps::MapData>,
    stackid: i32,
    proc_sym: Option<&mut ProcSymbolizer>,
    kernel_resolver: Option<&KernelResolver>,
) -> Option<String> {
    if stackid < 0 {
        return None;
    }
    let trace = stack_traces.get(&(stackid as u32), 0).ok()?;
    let frames = trace.frames();
    if frames.is_empty() {
        return None;
    }
    // We can't borrow `proc_sym` mutably from inside the closure once we've
    // taken &mut to it, so collect into Strings via an explicit loop.
    let mut rendered: Vec<String> = Vec::with_capacity(frames.len());
    let mut proc_sym = proc_sym;
    for f in frames.iter() {
        let ip = f.ip;
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
    Some(rendered.join(" <- "))
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
) -> Result<()> {
    let nr = { ev.syscall_nr };
    let is_enter = { ev.is_enter };
    if nr != SYSCALL_CLONE || is_enter == 1 {
        return Ok(());
    }
    let ret = { ev.ret };
    if ret <= 0 {
        return Ok(());
    }
    let child_pid = ret as u32;
    match pid_whitelist.insert(child_pid, 1u8, 0) {
        Ok(()) => {
            if verbose {
                eprintln!("  [follow] now tracking child pid {child_pid}");
            }
        }
        Err(e) => {
            if verbose {
                eprintln!("  [follow] pid_whitelist update failed for {child_pid}: {e}");
            }
        }
    }
    Ok(())
}

fn handle_capture_reads(
    ev: &SyscallEvent,
    watch_fds: &mut AyaHashMap<&mut aya::maps::MapData, u64, u8>,
    out: &mut dyn IoWrite,
    verbose: bool,
) -> Result<()> {
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
                    let _ = watch_fds.insert(key, 1u8, 0);
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
            let _ = watch_fds.remove(&key);
        }
    }

    // read()/write() exit on watched fd: content peek removed alongside the
    // process_vm_readv PAN workaround. The BPF programs only stash the user
    // pointer in `ptr_hint`; future work could capture buffer bytes directly
    // via `bpf_probe_read_user_buf` into `data[..]` if needed.
    let _ = out;

    Ok(())
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
    // ProcessTraceContext(20) + flags(4) + parent_debug_id(4) + relation(1),
    // and debug_id(4) + scenario_generation(2) + depth(1).
    {
        let map = bpf
            .map_mut("BINDER_TRANSACTION_CONTEXT")
            .context("BINDER_TRANSACTION_CONTEXT missing")?;
        let mut transactions: AyaHashMap<_, u32, [u8; 29]> = AyaHashMap::try_from(map)
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
        let mut threads: AyaHashMap<_, u64, [u8; 7]> =
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
    Ok(())
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

fn read_process_context(bpf: &Ebpf, pid: u32) -> Option<ProcessTraceContext> {
    let map = bpf.map("TRACED_PROCESSES")?;
    let traced: AyaHashMap<_, u32, [u8; PROCESS_TRACE_CONTEXT_SIZE]> =
        AyaHashMap::try_from(map).ok()?;
    traced.get(&pid, 0).ok().map(process_context_from_bytes)
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
        let mut transactions: AyaHashMap<_, u32, [u8; 29]> = AyaHashMap::try_from(map)
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
    let mut threads: AyaHashMap<_, u64, [u8; 7]> =
        AyaHashMap::try_from(map).context("THREAD_BINDER_CONTEXT has unexpected layout")?;
    let keys: Vec<u64> = threads
        .keys()
        .filter_map(|key| key.ok())
        .filter(|pid_tgid| (*pid_tgid >> 32) as u32 == pid)
        .collect();
    for key in keys {
        match threads.remove(&key) {
            Ok(()) => {}
            Err(error) if map_delete_already_absent(&error) => {}
            Err(error) => return Err(error).context("removing blocked Binder thread context"),
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

fn causal_metadata_for_process_exit(
    ev: &ProcessExitEvent,
    context: ProcessTraceContext,
    scenario: &ScenarioInfo,
    root_package: Option<&str>,
    root_uid: Option<u32>,
) -> CausalMetadata {
    let parent_span_id = if context.binder_debug_id == 0 {
        root_process_span_id(scenario.trace_id, ev.pid)
    } else {
        binder_span_id(scenario.trace_id, context.binder_debug_id as i32)
    };
    CausalMetadata {
        scenario_id: scenario.scenario_id.clone(),
        trace_id: scenario.trace_id,
        span_id: process_exit_span_id(scenario.trace_id, ev.pid, ev.ts_ns),
        parent_span_id,
        depth: context.depth,
        relation: if context.depth == 0 {
            CausalRelation::Exact
        } else {
            CausalRelation::Inferred
        },
        root_package: root_package.map(str::to_string),
        root_uid,
    }
}

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
        if let Ok(enriched) = enrich_json(&line, metadata) {
            line = enriched;
        }
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
    serde_json::to_string(&value).expect("serializing marker JSON cannot fail")
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
        if let Ok(enriched) = enrich_json(&line, metadata) {
            line = enriched;
        }
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
        if let Ok(enriched) = enrich_json(&line, metadata) {
            line = enriched;
        }
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Trace(args)) => run_trace(*args),
        Some(Command::Doctor) => {
            std::process::exit(doctor::run());
        }
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
        Some(Command::Harness(HarnessCommand::Minimize(args))) => neutron::harness::minimize(args),
        Some(Command::Harness(HarnessCommand::Replay(args))) => neutron::harness::replay(args),
        Some(Command::Aidl(AidlCommand::Index(args))) => neutron::aidl::run_index(args),
        Some(Command::Aidl(AidlCommand::Decode(args))) => neutron::aidl::run_decode(args),
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

fn run_trace(mut args: Args) -> Result<()> {
    validate_harness_capture_args(&args)?;
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
    if max_output_bytes.is_some() && rotate_output_bytes.is_some() {
        bail!("--max-output-size and --rotate-output-size are mutually exclusive");
    }
    if rotate_output_bytes.is_some() && args.output.is_none() {
        bail!("--rotate-output-size requires --output");
    }

    print_banner();
    let privilege = doctor::check_privilege(&doctor::RealEnv);
    capture_privilege_preflight(&privilege)?;
    let _capture_lock = acquire_capture_lock(&args.capture_lock)?;
    let capture_boot_id = read_boot_id();
    let capture_fingerprint = read_build_fingerprint();
    let capture_serial = args.harness_capture.then(read_device_serial).flatten();
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

    // Best-effort: relax perf_event_paranoid (kernel 6.x is usually fine without).
    let _ = fs::write("/proc/sys/kernel/perf_event_paranoid", "-1\n");

    // 1. Load BPF and attach tracepoints.
    let mut bpf = load_bpf(&args.object, args.max_processes, args.verbose)?;
    let has_stack_map = bpf.map("STACK_TRACES").is_some();
    if let Some(warning) = missing_stack_map_warning(args.stacks, has_stack_map) {
        eprintln!("neutron: WARNING: {warning}");
    }

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
        // Sprint-2 PR 2: callee-side companion. Best-effort — older kernels
        // before the tracepoint was upstreamed will fail attach. Continue
        // without it (the userspace correlator simply never matches).
        match attach_tracepoint(
            &mut bpf,
            "trace_binder_transaction_received",
            "binder",
            "binder_transaction_received",
        ) {
            Ok(()) => attached.push("trace_binder_transaction_received"),
            Err(e) => {
                eprintln!(
                    "neutron: warn: binder_transaction_received attach failed: {e}; \
                     binder causality (R004) will be silent"
                );
            }
        }
    }
    attach_kprobe_packs(&mut bpf, &args.kprobe_pack, &mut attached)?;

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
                "    [bpf]  state-tracking syscalls always-emit (fd_path \
                 enrichment requires fdgraph state)"
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

    // 2d. Phase 1d — sampling and rate limiting. State-tracking syscalls
    // bypass both inside `SamplerChain`, so fdgraph stays consistent
    // regardless of the configured probability or QPS cap.
    let mut sampler = SamplerChain::from_args(args.sample, args.rate_limit)?;

    // 2e. Phase 4b — optional binder service descriptor map for
    // `binder_call` enrichment.
    let binder_services: BinderServiceMap = match &args.binder_services {
        Some(path) => {
            let m = BinderServiceMap::load_file(path)?;
            eprintln!("  binder service map: {} entries from {path}", m.len());
            m
        }
        None => BinderServiceMap::default(),
    };
    let binder_methods = match &args.binder_methods {
        Some(path) => {
            let methods = BinderMethodMap::load_file(path)?;
            eprintln!("  binder method map: {} entries from {path}", methods.len());
            methods
        }
        None => BinderMethodMap::default(),
    };
    let aidl_catalog = args
        .aidl_catalog
        .as_deref()
        .map(AidlCatalog::load_file)
        .transpose()?;
    if let Some(catalog) = &aidl_catalog {
        binder_methods.validate_catalog(catalog)?;
        eprintln!(
            "  AIDL catalog: {} interfaces from {}",
            catalog.interfaces.len(),
            args.aidl_catalog.as_deref().expect("catalog path present")
        );
    }
    let mut binder_catalog = BinderCatalog::discover(args.follow_services, args.follow_hal);
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
    let mut engine = build_rule_engine(&args)?;
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
                serial: capture_serial,
                fingerprint: capture_fingerprint.clone(),
                boot_id: capture_boot_id.clone(),
                uid: package_uid.or(args.root_uid).unwrap_or(0),
                domain: None,
            },
        )?),
        (Some(_), None) => bail!("--harness-capture requires --output"),
        (None, _) => None,
    };
    let mut out = open_output(
        args.output.as_ref(),
        max_output_bytes,
        rotate_output_bytes,
        output_cap_hit.clone(),
    )?;

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
    let mut binder_causal = HashMap::<i32, CausalMetadata>::new();
    // The sched tracepoint cannot expose the fatal signal. Preserve its
    // causal span briefly so the later logcat/tombstone observation can
    // enrich the same graph node with SIGSEGV/SIGABRT classification even
    // though BPF has already removed the dying PID from its dynamic map.
    let mut recent_exit_causal = HashMap::<u32, CausalMetadata>::new();
    let mut followed_last_hop_ns = BTreeMap::<u32, u64>::new();
    let mut policy_blocked_pids = HashSet::<u32>::new();
    let mut follow_policy_filtered = 0_u64;
    let mut follow_ttl_expired = 0_u64;
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
    // Phase-1 pipeline counters surfaced in the final capture summary
    // and the `capture_health` JSON line. The 2026-05-06 device test
    // asked for matched / sampled-out / emitted as separate buckets so
    // an operator can see how a `--match-*` configuration shaped the
    // trace.
    let mut events_matched: u64 = 0;
    let mut events_sampled_out: u64 = 0;
    let mut events_emitted: u64 = 0;
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
                poller::spawn(cfg, Box::new(RealProcReader));
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
    let mut tombstone_watcher: Option<RealTombstoneWatcher> = if args.tombstone_dir.is_empty() {
        None
    } else {
        let w = RealTombstoneWatcher::with_dir(&args.tombstone_dir);
        if w.dir_available() {
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
    let mut logcat_reader: Option<RealLogcatReader> = if args.no_logcat {
        None
    } else {
        match RealLogcatReader::spawn() {
            Ok(r) => {
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
            Ok(reader) => {
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

    while running.load(Ordering::Relaxed) {
        if let Some(server) = control_server.as_ref() {
            while let Some(pending) = server.try_recv()? {
                let request = pending.request.clone();
                let result: Result<(ScenarioInfo, u64, String)> = (|| {
                    if request.phase == "start" {
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
                        let scenario = scenarios.start(&request.name)?;
                        set_root_uid_context(&mut bpf, scenario.trace_id, scenario.generation)?;
                        replace_causal_roots(
                            &mut bpf,
                            &root_pids,
                            scenario.trace_id,
                            scenario.generation,
                        )?;
                        clear_causal_transients(&mut bpf)?;
                        binder_causal.clear();
                        recent_exit_causal.clear();
                        followed_last_hop_ns.clear();
                        policy_blocked_pids.clear();
                        let ts_ns = monotonic_timestamp_ns();
                        let line = live_marker_line(
                            &request,
                            &scenario,
                            ts_ns,
                            args.package.as_deref(),
                            args.root_uid.or(package_uid),
                        );
                        Ok((scenario, ts_ns, line))
                    } else {
                        let scenario = scenarios.end(&request.name)?;
                        set_root_uid_context(&mut bpf, 0, 0)?;
                        replace_causal_roots(&mut bpf, &root_pids, 0, 0)?;
                        clear_causal_transients(&mut bpf)?;
                        recent_exit_causal.clear();
                        followed_last_hop_ns.clear();
                        policy_blocked_pids.clear();
                        let ts_ns = monotonic_timestamp_ns();
                        let line = live_marker_line(
                            &request,
                            &scenario,
                            ts_ns,
                            args.package.as_deref(),
                            args.root_uid.or(package_uid),
                        );
                        Ok((scenario, ts_ns, line))
                    }
                })();
                let response = match result {
                    Ok((scenario, ts_ns, line)) => {
                        write_or_output_cap(writeln!(out, "{line}"), &output_cap_hit)?;
                        events_emitted = events_emitted.saturating_add(1);
                        pending.respond_ok(ts_ns, scenario.generation, scenario.trace_id)
                    }
                    Err(error) => pending.respond_error(format!("{error:#}")),
                };
                if let Err(error) = response {
                    eprintln!("neutron: warn: marker client disconnected: {error:#}");
                }
            }
        }

        // A camera burst can reveal dozens of new Binder PIDs in one ring
        // drain. Coalesce those observations into one catalog refresh and
        // always service marker requests first; running `service` + `lshal`
        // once per PID can otherwise starve the control socket for minutes.
        if discovery_refresh_pending && last_discovery_refresh.elapsed() >= Duration::from_secs(1) {
            binder_catalog = BinderCatalog::discover(args.follow_services, args.follow_hal);
            discovery_refresh_pending = false;
            last_discovery_refresh = std::time::Instant::now();
        }

        if last_root_refresh.elapsed() >= Duration::from_secs(1) {
            last_root_refresh = std::time::Instant::now();
            if args.package.is_some() || args.root_uid.is_some() {
                match discover_dynamic_roots(&args, package_uid) {
                    Ok(None) => {}
                    Ok(Some(discovered)) if discovered.len() <= args.max_processes as usize => {
                        let (trace_id, generation) = scenarios
                            .active()
                            .map(|scenario| (scenario.trace_id, scenario.generation))
                            .unwrap_or((0, 0));
                        reconcile_causal_roots(&mut bpf, &discovered, trace_id, generation)?;
                        root_pids = discovered;
                    }
                    Ok(Some(discovered)) => bail!(
                        "causal root now has {} processes, above --max-processes {}",
                        discovered.len(),
                        args.max_processes
                    ),
                    Err(error) => return Err(error).context("refreshing causal root process set"),
                }
            }
            if args.follow_binder && scenarios.active().is_some() {
                let roots = root_pids.iter().copied().collect::<BTreeSet<_>>();
                let now_ns = monotonic_timestamp_ns();
                for pid in
                    expired_followed_pids(&followed_last_hop_ns, &roots, now_ns, follow_ttl_ns)
                {
                    followed_last_hop_ns.remove(&pid);
                    policy_blocked_pids.remove(&pid);
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
                    events_emitted = events_emitted.saturating_add(1);
                }
            }
        }

        let mut saw_any = false;
        loop {
            let bytes_owned: Vec<u8> = match ring.next() {
                Some(item) => {
                    let slice: &[u8] = &item;
                    if slice.len() < ev_size {
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
                // byte arrays; any 241-byte payload is a valid bit-pattern.
                let ev: SyscallEvent =
                    unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const _) };
                total_events += 1;

                if should_skip_for_exclude_comm(&ev, &args.exclude_comm) {
                    continue;
                }
                if args.alert_rwx && should_skip_for_alert_rwx(&ev) {
                    continue;
                }
                let causal_event = causal_metadata_for_event(
                    &ev,
                    &scenarios,
                    args.package.as_deref(),
                    args.root_uid.or(package_uid),
                );
                let event_pid = { ev.pid };
                let event_nr = { ev.syscall_nr };
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
                        uid: { ev.uid },
                        comm: format_comm(&{ ev.comm }),
                        exit_code: (args_arr[0] & 0xff) as u8,
                        exit_signal: (args_arr[1] & 0xffffffff) as u32,
                        source: ExitSource::from_u8((args_arr[2] & 0xff) as u8)
                            .unwrap_or(ExitSource::Tracepoint),
                    };
                    if let Some(metadata) = causal_event.as_ref() {
                        recent_exit_causal.insert(pe.pid, metadata.clone());
                    }
                    // Sprint-2 PR 2: drain in-flight binder transactions
                    // for the dying PID before emitting the exit. Each
                    // drained entry becomes a `binder_call` line with
                    // status=callee_crashed, feeding R004.
                    if pe.classify() == neutron::sources::ExitClassification::Crash {
                        if let Some(t) = binder_tracker.as_mut() {
                            for pair in t.on_callee_crash(pe.pid) {
                                let pair_causal = binder_causal.remove(&pair.debug_id);
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
                                        pair_causal.as_ref(),
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
                    if let Some(metadata) = causal_event.clone() {
                        binder_causal.insert(debug_id, metadata);
                    }
                    let callee_pid = args_arr[0] as u32;
                    if callee_pid != 0
                        && (args.follow_services || args.follow_hal)
                        && discovery_seen_pids.insert(callee_pid)
                    {
                        discovery_refresh_pending = true;
                    }
                    if args.follow_binder && callee_pid != 0 && !root_pids.contains(&callee_pid) {
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
                                    events_emitted = events_emitted.saturating_add(1);
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
                        );
                    }
                } else if nr_now == SYSCALL_NR_BINDER_RECEIVED {
                    if let Some(t) = binder_tracker.as_mut() {
                        let debug_id = { ev.ptr_hint } as u32 as i32;
                        let ts = { ev.timestamp_ns };
                        if let Some(pair) = t.record_received(debug_id, ts) {
                            let pair_causal = binder_causal.remove(&pair.debug_id);
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
                                    pair_causal.as_ref(),
                                ),
                                &output_cap_hit,
                            )?;
                        }
                    }
                }

                // Resolve the stack BEFORE building the JSON line so the
                // rule engine can pattern-match against `stack_contains`.
                // This must happen before `format_event_json_with_stack`.
                let stack_str: Option<String> = if args.stacks {
                    let kstk = { ev.kernel_stackid };
                    let ustk = { ev.user_stackid };
                    if kstk >= 0 || ustk >= 0 {
                        let pid = { ev.pid };
                        let proc_sym_opt = proc_sym_cache
                            .entry(pid)
                            .or_insert_with(|| ProcSymbolizer::new(pid));
                        if let Some(stmap) = bpf.map("STACK_TRACES") {
                            if let Ok(stack_traces) = StackTraceMap::try_from(stmap) {
                                let proc_sym_mut = proc_sym_opt.as_mut();
                                let kernel_str = format_stack(
                                    &stack_traces,
                                    kstk,
                                    None,
                                    kernel_resolver.as_ref(),
                                );
                                let user_str =
                                    format_stack(&stack_traces, ustk, proc_sym_mut, None);
                                match (kernel_str, user_str) {
                                    (Some(k), Some(u)) => Some(format!("{k} ;; {u}")),
                                    (Some(k), None) => Some(k),
                                    (None, Some(u)) => Some(u),
                                    (None, None) => None,
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

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
                if let Some(metadata) = causal_event.as_ref() {
                    if let Ok(enriched) = enrich_json(&json_line, metadata) {
                        json_line = enriched;
                    }
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
                        events_emitted = events_emitted.saturating_add(lines.len() as u64);
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
                    handle_follow_children(&ev, &mut pid_whitelist, args.verbose)?;
                }
                if args.capture_reads {
                    let map = bpf.map_mut("WATCH_FDS").context("WATCH_FDS missing")?;
                    let mut watch_fds: AyaHashMap<_, u64, u8> =
                        AyaHashMap::try_from(map).context("WATCH_FDS is not HashMap<u64,u8>")?;
                    handle_capture_reads(&ev, &mut watch_fds, &mut *out, args.verbose)?;
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
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        if let Some(w) = tombstone_watcher.as_mut() {
            for pe in w.poll(now_ns) {
                let pe_causal = recent_exit_causal.get(&pe.pid).cloned().or_else(|| {
                    read_process_context(&bpf, pe.pid).and_then(|context| {
                        scenarios.find(context.scenario_generation).map(|scenario| {
                            causal_metadata_for_process_exit(
                                &pe,
                                context,
                                scenario,
                                args.package.as_deref(),
                                args.root_uid.or(package_uid),
                            )
                        })
                    })
                });
                if pe.classify() == neutron::sources::ExitClassification::Crash {
                    if let Some(t) = binder_tracker.as_mut() {
                        for pair in t.on_callee_crash(pe.pid) {
                            let pair_causal = binder_causal.remove(&pair.debug_id);
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
                                    pair_causal.as_ref(),
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
                        pe_causal.as_ref(),
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
                let pe_causal = recent_exit_causal.get(&pe.pid).cloned().or_else(|| {
                    read_process_context(&bpf, pe.pid).and_then(|context| {
                        scenarios.find(context.scenario_generation).map(|scenario| {
                            causal_metadata_for_process_exit(
                                &pe,
                                context,
                                scenario,
                                args.package.as_deref(),
                                args.root_uid.or(package_uid),
                            )
                        })
                    })
                });
                if pe.classify() == neutron::sources::ExitClassification::Crash {
                    if let Some(t) = binder_tracker.as_mut() {
                        for pair in t.on_callee_crash(pe.pid) {
                            let pair_causal = binder_causal.remove(&pair.debug_id);
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
                                    pair_causal.as_ref(),
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
                        pe_causal.as_ref(),
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
                let process_context = read_process_context(&bpf, denial.pid);
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
                let causal = process_context.and_then(|context| {
                    scenarios.find(context.scenario_generation).map(|scenario| {
                        causal_metadata_for_selinux_denial(
                            &denial,
                            context,
                            scenario,
                            args.package.as_deref(),
                            args.root_uid.or(package_uid),
                        )
                    })
                });
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
                events_emitted = events_emitted.saturating_add(1);
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
            // Non-zero return is fine; -1 with EINTR is fine. Errors are
            // ignored — the outer loop re-checks `running`.
            unsafe {
                libc::poll(&mut pfd, 1, POLL_TIMEOUT_MS);
            }
        }
    }

    // Signal the FD poller to stop; the thread exits within one tick.
    if let Some((_, _, stop_tx, handle)) = poller_state {
        let _ = stop_tx.send(());
        let _ = handle.join();
    }

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
    let selinux_stats = selinux_reader
        .as_ref()
        .map(SelinuxLogcatReader::stats)
        .unwrap_or_default();
    let selinux_source_available = selinux_reader
        .as_mut()
        .is_some_and(SelinuxLogcatReader::is_available);
    let user_health = UserspaceHealth {
        fd_graph_miss: fd_graph.miss_count(),
        fd_graph_backfilled: fd_graph.backfill_count(),
        events_matched,
        events_sampled_out,
        events_emitted,
        output_cap_hit: output_cap_hit.load(Ordering::Relaxed),
        follow_policy_filtered,
        follow_ttl_expired,
        selinux_source_enabled,
        selinux_source_available,
        selinux_parsed: selinux_stats.parsed,
        selinux_malformed: selinux_stats.malformed,
        selinux_deduplicated: selinux_stats.deduplicated,
        selinux_out_of_scope: selinux_stats.out_of_scope,
    };
    if let Some(map) = bpf.map("COUNTERS") {
        match Array::<_, u64>::try_from(map) {
            Ok(arr) => {
                let health = CaptureHealth::read(&arr);
                eprint!(
                    "{}",
                    format_summary_with(&health, &user_health, total_events)
                );
                // Phase 5c — machine-readable counterpart on the NDJSON
                // stream and, optionally, a sidecar independent of the
                // primary output cap. Stderr block stays intact for humans.
                if args.json || args.health_output.is_some() {
                    let mut match_pids = args.match_pid.clone();
                    if args.pid != 0 {
                        push_unique(&mut match_pids, args.pid.to_string());
                    }
                    let capture_meta = CaptureMetadata {
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
                        boot_id: capture_boot_id.clone(),
                        fingerprint: capture_fingerprint.clone(),
                        max_depth: args.max_depth,
                        max_processes: args.max_processes,
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
                }
            }
            Err(e) => {
                eprintln!("\nneutron: COUNTERS map present but unreadable: {e}");
                eprintln!("neutron: exiting (events={total_events})");
            }
        }
    } else {
        eprintln!("\nneutron: exiting (events={total_events})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutron::mark::{self, MarkArgs};
    use std::io::Write;

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
        let line = live_marker_line(&request, &scenario, 42, None, Some(10123));
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
        let path =
            std::env::temp_dir().join(format!("neutron-output-append-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
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
        let _ = std::fs::remove_file(&path);
        assert!(
            content.contains(r#""type":"marker""#),
            "marker append must survive tracer writes; got:\n{content}"
        );
        assert!(
            content.contains(r#""name":"scenario""#),
            "marker name should remain readable; got:\n{content}"
        );
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
        let path = std::env::temp_dir().join(format!("neutron-lock-test-{}", std::process::id()));
        let path_s = path.to_string_lossy().into_owned();
        let _ = std::fs::remove_file(&path);

        let first = CaptureLock::acquire(&path_s).expect("first lock owner");
        let err = CaptureLock::acquire(&path_s).expect_err("second owner should fail");
        assert!(format!("{err:#}").contains("another neutron capture appears active"));

        drop(first);
        let _second = CaptureLock::acquire(&path_s).expect("lock released after drop");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn health_sidecar_writes_even_when_primary_output_cap_is_hit() {
        let base =
            std::env::temp_dir().join(format!("neutron-health-sidecar-{}", std::process::id()));
        let out_path = base.with_extension("ndjson");
        let health_path = base.with_extension("health.ndjson");
        let out_s = out_path.to_string_lossy().into_owned();
        let health_s = health_path.to_string_lossy().into_owned();
        let _ = std::fs::remove_file(&out_path);
        let _ = std::fs::remove_file(&health_path);

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

        let _ = std::fs::remove_file(&out_path);
        let _ = std::fs::remove_file(&health_path);
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
    fn rotating_writer_rolls_to_numbered_segments() {
        let base = std::env::temp_dir().join(format!("neutron-rotate-test-{}", std::process::id()));
        let base_s = base.to_string_lossy().into_owned();
        let rotated_s = format!("{base_s}.1");
        let _ = std::fs::remove_file(&base_s);
        let _ = std::fs::remove_file(&rotated_s);

        {
            let mut writer = RotatingWriter::new(&base_s, 6).expect("open rotating writer");
            writer.write_all(b"aaaa\n").unwrap();
            writer.write_all(b"bbbb\n").unwrap();
            writer.flush().unwrap();
        }

        let first = std::fs::read_to_string(&base_s).expect("read base segment");
        let second = std::fs::read_to_string(&rotated_s).expect("read rotated segment");
        let _ = std::fs::remove_file(&base_s);
        let _ = std::fs::remove_file(&rotated_s);

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
    fn android_provider_match_counts_as_capture_predicate_flag() {
        let args = Args {
            match_android_provider: vec!["com.android.contacts".into()],
            ..Args::default()
        };

        assert!(any_individual_match_flag(&args));
    }

    #[test]
    fn stack_map_warning_is_silent_when_stacks_are_not_requested() {
        assert!(missing_stack_map_warning(false, false).is_none());
    }

    #[test]
    fn stack_map_warning_explains_stackful_object_when_stacks_are_requested() {
        let warning = missing_stack_map_warning(true, false)
            .expect("stackless object with --stacks should warn");

        assert!(warning.contains("--stacks"));
        assert!(warning.contains("neutron-stacks.bpf.elf"));
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
