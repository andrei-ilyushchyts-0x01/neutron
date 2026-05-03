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

use std::collections::HashMap;
use std::fs;
use std::io::Write as IoWrite;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use std::os::fd::AsRawFd;

use anyhow::{bail, Context, Result};
use aya::maps::{Array, HashMap as AyaHashMap, RingBuf, StackTraceMap};
use aya::programs::TracePoint;
use aya::Ebpf;
use clap::Parser;

use neutron::cli::{Args, Cli, Command};
use neutron::decode::{format_comm, format_data_field, resolve_path_from_fd};
use neutron::doctor;
use neutron::fdgraph::FdGraph;
use neutron::format::{format_event_json_full, format_event_text_with_stack, FdHint};
use neutron::health::{format_summary_with, CaptureHealth, UserspaceHealth};
use neutron::rules::{build_rule_engine, emit_findings};
use neutron::symbolize::{is_kernel_addr, KernelSymbolizer, ProcSymbolizer};
use neutron::SyscallEvent;
use neutron_common::{FILTER_KEY_ACTIVE, FILTER_KEY_PID};

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

extern "C" fn sigint_handler(_sig: libc::c_int) {
    let ptr = RUNNING_PTR.load(Ordering::SeqCst);
    if ptr != 0 {
        // SAFETY: pointer was set from a leaked Arc<AtomicBool> in install_sigint.
        let running = unsafe { &*(ptr as *const Arc<AtomicBool>) };
        running.store(false, Ordering::SeqCst);
    }
}

fn install_sigint(running: Arc<AtomicBool>) {
    let leaked = Box::into_raw(Box::new(running)) as usize;
    RUNNING_PTR.store(leaked, Ordering::SeqCst);
    unsafe {
        libc::signal(
            libc::SIGINT,
            sigint_handler as *const () as libc::sighandler_t,
        );
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

// ── Output sink ──────────────────────────────────────────────────────────────

fn open_output(path: Option<&String>) -> Result<Box<dyn IoWrite>> {
    match path {
        Some(p) => {
            let f = fs::File::create(p).with_context(|| format!("cannot create {p}"))?;
            Ok(Box::new(std::io::BufWriter::new(f)))
        }
        None => Ok(Box::new(std::io::BufWriter::new(std::io::stdout()))),
    }
}

// ── Stack symbolization helper ───────────────────────────────────────────────

/// Render one stack-trace map entry. Picks the right symbolizer per frame
/// based on the canonical aarch64 user/kernel split.
fn format_stack(
    stack_traces: &StackTraceMap<&aya::maps::MapData>,
    stackid: i32,
    proc_sym: Option<&mut ProcSymbolizer>,
    kernel_sym: Option<&KernelSymbolizer>,
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
            match kernel_sym {
                Some(k) => k.symbolize(ip),
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

// ── Main ─────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Doctor) => {
            std::process::exit(doctor::run());
        }
        None => run_trace(cli.args),
    }
}

fn run_trace(mut args: Args) -> Result<()> {
    apply_profile(&mut args)?;

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
    }

    // 2. Populate filter map.
    populate_filter_map(&mut bpf, args.pid)?;

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
    let mut out = open_output(args.output.as_ref())?;

    // 7. Ctrl-C handler.
    let running = Arc::new(AtomicBool::new(true));
    install_sigint(running.clone());

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
    // Build the kernel symbolizer once. None when kallsyms is masked.
    let kernel_sym: Option<KernelSymbolizer> = if args.stacks {
        KernelSymbolizer::from_kallsyms()
    } else {
        None
    };
    if args.verbose {
        if let Some(k) = kernel_sym.as_ref() {
            eprintln!("  kallsyms: {} symbols loaded", k.len());
        } else if args.stacks {
            eprintln!("  kallsyms: unavailable (kptr_restrict?) — kernel frames stay hex");
        }
    }
    let mut total_events: u64 = 0;
    // Userspace FD graph: tracks (pid, fd) → resource so ioctl/read/write/mmap
    // events can be enriched with `fd_kind`, `fd_path`. Updated every event;
    // miss/backfill counts are surfaced in the capture summary on exit.
    let mut fd_graph = FdGraph::new();

    while running.load(Ordering::Relaxed) {
        let mut saw_any = false;
        loop {
            let bytes_owned: Vec<u8> = match ring.next() {
                Some(item) => {
                    let slice: &[u8] = &*item;
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
                                let kernel_str =
                                    format_stack(&stack_traces, kstk, None, kernel_sym.as_ref());
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

                // Always compute the JSON form: cheap and fed to the rule engine.
                let json_line = format_event_json_full(
                    &ev,
                    args.resolve_paths,
                    stack_str.as_deref(),
                    fd_hint.as_ref(),
                );

                if let Some(eng) = engine.as_mut() {
                    if let Some(owned) = neutron_rules::Event::parse_line(&json_line) {
                        if let Some(view) = owned.view() {
                            eng.feed(&view);
                        }
                    }
                }

                if !suppress_raw {
                    let line = if args.json {
                        json_line.clone()
                    } else {
                        format_event_text_with_stack(&ev, args.resolve_paths, stack_str.as_deref())
                    };
                    let _ = writeln!(out, "{line}");
                }

                events_since_drain += 1;
                if events_since_drain >= drain_interval {
                    events_since_drain = 0;
                    if let Some(eng) = engine.as_mut() {
                        let findings = eng.drain_ready();
                        if !findings.is_empty() {
                            emit_findings(&findings, &mut *out, args.json);
                        }
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

                if !running.load(Ordering::Relaxed) {
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

    // 9. Flush rule engine.
    if let Some(eng) = engine.take() {
        let pending = eng.flush_all();
        if !pending.is_empty() {
            emit_findings(&pending, &mut *out, args.json);
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
    };
    if let Some(map) = bpf.map("COUNTERS") {
        match Array::<_, u64>::try_from(map) {
            Ok(arr) => {
                let health = CaptureHealth::read(&arr);
                eprint!(
                    "{}",
                    format_summary_with(&health, &user_health, total_events)
                );
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
