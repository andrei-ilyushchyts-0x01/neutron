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

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write as IoWrite};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use std::os::fd::AsRawFd;

use anyhow::{bail, Context, Result};
use aya::maps::{Array, HashMap as AyaHashMap, RingBuf, StackTraceMap};
use aya::programs::TracePoint;
use aya::Ebpf;
use clap::Parser;

use neutron::android;
use neutron::binder_services::BinderServiceMap;
use neutron::capture::{CaptureMode, ContextRing, DEFAULT_MAX_EVENTS};
use neutron::cli::{Args, Cli, Command};
use neutron::decode::{compute_latency_us, format_comm, format_data_field, resolve_path_from_fd};
use neutron::doctor;
use neutron::fdgraph::poller::{self as poller, PollerConfig, RealProcReader, ScopePolicy};
use neutron::fdgraph::FdGraph;
use neutron::format::{
    format_binder_call_json_with_service, format_event_json_full, format_event_text_with_stack,
    format_fd_snapshot_json, format_process_exit_json, FdHint,
};
use neutron::health::{
    format_capture_health_json, format_summary_with, CaptureHealth, UserspaceHealth,
};
use neutron::matcher::{self, MatchSpec, SyscallEventLens};
use neutron::predicate;
use neutron::rules::{build_rule_engine, emit_findings_with};
use neutron::sampler::SamplerChain;
use neutron::sources::binder_tracker::BinderTracker;
use neutron::sources::logcat::{LogcatReader, RealLogcatReader};
use neutron::sources::lookback::RingBufferStore;
use neutron::sources::tombstone::{RealTombstoneWatcher, TombstoneWatcher};
use neutron::sources::ProcessExitEvent;
use neutron::symbolize::{is_kernel_addr, KernelResolver, ProcSymbolizer};
use neutron::SyscallEvent;
use neutron_common::{
    ExitSource, FILTER_KEY_ACTIVE, FILTER_KEY_ARG_U32_OFF, FILTER_KEY_IOCTL_DIR,
    FILTER_KEY_LATENCY_MIN_US, FILTER_KEY_MATCH_BITS, FILTER_KEY_PID, FILTER_KEY_RET_CLASS,
    FILTER_KEY_STATE_EMIT_REQUIRED, MATCH_BIT_ARG_U32, MATCH_BIT_IOCTL_CMD, MATCH_BIT_IOCTL_DIR,
    MATCH_BIT_IOCTL_NR, MATCH_BIT_IOCTL_TYPE, MATCH_BIT_LATENCY, MATCH_BIT_RET, MATCH_BIT_UID,
    SYSCALL_NR_BINDER_RECEIVED, SYSCALL_NR_PROCESS_EXIT,
};

// ── Constants ────────────────────────────────────────────────────────────────

const SECURITY_PROFILE: &str = "security";

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
    if profile != SECURITY_PROFILE {
        bail!("unknown profile '{profile}' (available: {SECURITY_PROFILE})");
    }
    if args.exclude_comm.is_empty() {
        args.exclude_comm = SECURITY_EXCLUDE_COMM
            .iter()
            .map(|s| (*s).to_string())
            .collect();
    }
    Ok(())
}

// ── BPF load + attach ────────────────────────────────────────────────────────

fn load_bpf(object_path: &str) -> Result<Ebpf> {
    let bytes =
        fs::read(object_path).with_context(|| format!("cannot read BPF object {object_path}"))?;
    Ebpf::load(&bytes).with_context(|| format!("Ebpf::load failed for {object_path}"))
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

// ── Filter map population ────────────────────────────────────────────────────

fn populate_filter_map(bpf: &mut Ebpf, pid: u32) -> Result<()> {
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
) {
    let ctx = lookback.map(|lb| lb.take(ev.pid)).unwrap_or_default();
    *event_id_counter = event_id_counter.wrapping_add(1);
    let line = format_process_exit_json(ev, &ctx, Some(*event_id_counter));
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
        let _ = writeln!(out, "{printed}");
    }
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
    services: Option<&BinderServiceMap>,
) {
    *event_id_counter = event_id_counter.wrapping_add(1);
    let service = services.and_then(|m| m.lookup(pair.callee_pid, pair.target_node));
    let line = format_binder_call_json_with_service(pair, Some(*event_id_counter), service);
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
        let _ = writeln!(out, "{printed}");
    }
    if let Some(lb) = lookback {
        // Record the pair against the *caller* PID so a later caller-side
        // crash carries the binder activity in its lookback. Callee-side
        // crashes already trigger the on_callee_crash drain.
        lb.record(pair.caller_pid, &line);
    }
}

// ── Main ─────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Doctor) => {
            std::process::exit(doctor::run());
        }
        Some(Command::Window(args)) => neutron::window::run(args),
        Some(Command::Summarize(args)) => neutron::summarize::run(args),
        Some(Command::Diff(args)) => neutron::diff::run(args),
        Some(Command::Mark(args)) => neutron::mark::run(args),
        Some(Command::Recipes(command)) => neutron::recipes::run(command),
        None => run_trace(cli.args),
    }
}

fn run_trace(mut args: Args) -> Result<()> {
    apply_profile(&mut args)?;
    let max_output_bytes = parse_output_size_bytes(args.max_output_size.as_deref())?;
    let rotate_output_bytes = parse_rotate_output_size_bytes(args.rotate_output_size.as_deref())?;
    if max_output_bytes.is_some() && rotate_output_bytes.is_some() {
        bail!("--max-output-size and --rotate-output-size are mutually exclusive");
    }
    if rotate_output_bytes.is_some() && args.output.is_none() {
        bail!("--rotate-output-size requires --output");
    }

    print_banner();
    eprintln!("  loading {}", args.object);
    eprintln!(
        "  target pid: {}",
        if args.pid == 0 {
            "all".to_string()
        } else {
            args.pid.to_string()
        }
    );
    if args.pid == 0 {
        eprintln!("  note: tracing all processes; inflight map may overflow under heavy load");
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
    let mut bpf = load_bpf(&args.object)?;

    attach_tracepoint(&mut bpf, "trace_sys_enter", "raw_syscalls", "sys_enter")?;
    attach_tracepoint(&mut bpf, "trace_sys_exit", "raw_syscalls", "sys_exit")?;
    let mut attached = vec!["trace_sys_enter", "trace_sys_exit"];
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

    // 2. Populate filter map.
    populate_filter_map(&mut bpf, args.pid)?;

    // 2b. Phase 1a/1b — build the capture predicate. `--match <expr>`
    // takes precedence over the individual `--match-*` flags; the two
    // forms are mutually exclusive (using both at once is rejected).
    let capture_predicate = build_capture_predicate(&args)?;
    if let Some(bpf_spec) = capture_predicate.bpf_spec() {
        populate_match_maps(&mut bpf, bpf_spec)?;
    }
    if capture_predicate.needs_state_events_via_ast() {
        // Fallback path: the AST mentions fd_path even though the BPF
        // lowering couldn't capture it (e.g. inside an OR). Toggle
        // STATE_EMIT_REQUIRED so kernel-side fd-state syscalls still
        // bypass the prefilter and userspace fdgraph stays consistent.
        let map = bpf.map_mut("FILTER_MAP").context("FILTER_MAP missing")?;
        let mut filter: Array<_, u32> =
            Array::try_from(map).context("FILTER_MAP is not Array<u32>")?;
        filter
            .set(FILTER_KEY_STATE_EMIT_REQUIRED, 1u32, 0)
            .context("FILTER_MAP[STATE_EMIT_REQUIRED]=1")?;
    }
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
    let binder_services: Option<BinderServiceMap> = match &args.binder_services {
        Some(path) => {
            let m = BinderServiceMap::load_file(path)?;
            eprintln!("  binder service map: {} entries from {path}", m.len());
            Some(m)
        }
        None => None,
    };
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
    let mut out = open_output(
        args.output.as_ref(),
        max_output_bytes,
        rotate_output_bytes,
        output_cap_hit.clone(),
    )?;

    // 7. Ctrl-C handler.
    let running = Arc::new(AtomicBool::new(true));
    install_shutdown_signals(running.clone());

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
    let mut active_pids: HashSet<u32> = HashSet::new();
    if args.pid != 0 {
        active_pids.insert(args.pid);
    }
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

    while running.load(Ordering::Relaxed) {
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
                    // Sprint-2 PR 2: drain in-flight binder transactions
                    // for the dying PID before emitting the exit. Each
                    // drained entry becomes a `binder_call` line with
                    // status=callee_crashed, feeding R004.
                    if pe.classify() == neutron::sources::ExitClassification::Crash {
                        if let Some(t) = binder_tracker.as_mut() {
                            for pair in t.on_callee_crash(pe.pid) {
                                emit_binder_call(
                                    &pair,
                                    lookback.as_mut(),
                                    &mut engine,
                                    &mut *out,
                                    suppress_raw,
                                    args.json,
                                    &mut event_id_counter,
                                    binder_services.as_ref(),
                                );
                            }
                        }
                    }
                    emit_process_exit(
                        &pe,
                        lookback.as_mut(),
                        &mut engine,
                        &mut *out,
                        suppress_raw,
                        args.json,
                        &mut event_id_counter,
                    );
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
                    if let Some(t) = binder_tracker.as_mut() {
                        let args_arr = { ev.args };
                        let debug_id = { ev.ptr_hint } as u32 as i32;
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
                            emit_binder_call(
                                &pair,
                                lookback.as_mut(),
                                &mut engine,
                                &mut *out,
                                suppress_raw,
                                args.json,
                                &mut event_id_counter,
                                binder_services.as_ref(),
                            );
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
                let json_line = format_event_json_full(
                    &ev,
                    args.resolve_paths,
                    stack_str.as_deref(),
                    fd_hint.as_ref(),
                    Some(event_id_counter),
                );

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
                                let _ = writeln!(out, "{line}");
                            } else {
                                let text = format_event_text_with_stack(
                                    &ev,
                                    args.resolve_paths,
                                    stack_str.as_deref(),
                                );
                                let _ = writeln!(out, "{text}");
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
                            emit_findings_with(
                                &findings,
                                &mut *out,
                                args.json,
                                args.fd_snapshot_on_finding,
                            );
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
                    let _ = writeln!(out, "{line}");
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
                if pe.classify() == neutron::sources::ExitClassification::Crash {
                    if let Some(t) = binder_tracker.as_mut() {
                        for pair in t.on_callee_crash(pe.pid) {
                            emit_binder_call(
                                &pair,
                                lookback.as_mut(),
                                &mut engine,
                                &mut *out,
                                suppress_raw,
                                args.json,
                                &mut event_id_counter,
                                binder_services.as_ref(),
                            );
                        }
                    }
                }
                emit_process_exit(
                    &pe,
                    lookback.as_mut(),
                    &mut engine,
                    &mut *out,
                    suppress_raw,
                    args.json,
                    &mut event_id_counter,
                );
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
                if pe.classify() == neutron::sources::ExitClassification::Crash {
                    if let Some(t) = binder_tracker.as_mut() {
                        for pair in t.on_callee_crash(pe.pid) {
                            emit_binder_call(
                                &pair,
                                lookback.as_mut(),
                                &mut engine,
                                &mut *out,
                                suppress_raw,
                                args.json,
                                &mut event_id_counter,
                                binder_services.as_ref(),
                            );
                        }
                    }
                }
                emit_process_exit(
                    &pe,
                    lookback.as_mut(),
                    &mut engine,
                    &mut *out,
                    suppress_raw,
                    args.json,
                    &mut event_id_counter,
                );
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
            emit_findings_with(&pending, &mut *out, args.json, args.fd_snapshot_on_finding);
        }
    }

    // 10. Capture summary. Read the COUNTERS map and print the slot values
    // plus a warning if any drop or degradation counter is non-zero.
    // RingBuf is *not* lossless: `reserve()` returns None when the ring is
    // full, and the BPF programs increment COUNTER_RINGBUF_RESERVE_FAILED in
    // that case. The summary surfaces this so operators can judge whether
    // absence of a finding is conclusive.
    let user_health = UserspaceHealth {
        fd_graph_miss: fd_graph.miss_count(),
        fd_graph_backfilled: fd_graph.backfill_count(),
        events_matched,
        events_sampled_out,
        events_emitted,
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
                // stream. Lets downstream tools see the same counters
                // without scraping stderr prose. Stderr block stays
                // intact for human readers.
                if args.json {
                    let line = format_capture_health_json(&health, &user_health, total_events);
                    let _ = writeln!(out, "{line}");
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
        assert!(packs.refresh_types.contains(&neutron_common::IOCTL_TYPE_KGSL));
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
}
