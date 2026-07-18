//! neutron BPF programs (aya-ebpf, kernel 6.1+ target)
//!
//! Build:  cargo xtask build-ebpf
//! Target: bpfel-unknown-none (Pixel 8 Pro / Android 14 GKI / kernel 6.1.145)
//!
//! Modern-kernel assumptions (no kernel-4.14 workarounds):
//! - BPF-to-BPF calls are accepted, but fixed-size event zero/copy operations
//!   stay explicitly expanded: generic LLVM memory loops exhaust the Pixel
//!   Android 6.1 verifier's instruction budget.
//! - Helpers 112/113/114 (`bpf_probe_read_kernel_*`, `bpf_probe_read_user_*`,
//!   `bpf_probe_read_user_str_*`) are available — used in preference to the
//!   address-space-agnostic helpers 4 / 45.
//! - BTF + CO-RE compatible (Aya performs runtime BTF relocation).
//! - Optional stack traces via the `stacks` feature, `bpf_get_stackid`, and
//!   `BPF_MAP_TYPE_STACK_TRACE`.
//! - Output via a bounded BPF ring buffer (`BPF_MAP_TYPE_RINGBUF`, kernel
//!   5.8+) with explicit reserve-failure accounting.
//!
//! `SyscallEvent` is `#[repr(C, packed)]`, so all field accesses go through
//! `addr_of!` / `addr_of_mut!` and `write_unaligned` / `read_unaligned`.
#![no_std]
#![no_main]

use core::mem::{size_of, MaybeUninit};
use core::ptr::{addr_of, addr_of_mut};

#[cfg(feature = "stacks")]
use aya_ebpf::{bindings::BPF_F_USER_STACK, maps::StackTrace};
use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel_buf, bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes, gen,
    },
    macros::{map, tracepoint},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use neutron_common::{
    bpf_build_id_from_git_hex, causal_admission_boundary_exit, causal_pid_action,
    encode_causal_relation_depth, is_state_tracking_nr, ret_matches_class, BpfAbiMetadata,
    ExitSource, ProcessTraceContext, SyscallEvent, TraceReason, BPF_ABI_MAGIC, BPF_ABI_MAJOR,
    BPF_ABI_MINOR, BPF_FEATURE_BINDER_TRACE, BPF_FEATURE_PER_CPU_HEALTH, BPF_FEATURE_PROCESS_EXIT,
    BPF_FEATURE_SYSCALL_TRACE, CAUSAL_PID_ADMIT_ROOT, CAUSAL_PID_FALLTHROUGH, CAUSAL_PID_MATCH,
    CAUSAL_RELATION_EXACT, CAUSAL_RELATION_INFERRED, COUNTER_BINDER_DEPTH_LIMIT,
    COUNTER_BINDER_FOLLOW_FAILED, COUNTER_CAUSAL_ADMISSION_BOUNDARY_EXIT, COUNTER_EVENTS_SUBMITTED,
    COUNTER_INFLIGHT_LOOKUP_MISSED, COUNTER_INFLIGHT_UPDATE_FAILED,
    COUNTER_IOCTL_PAYLOAD_TRUNCATED, COUNTER_IOCTL_REFRESH_MISSED, COUNTER_PATH_READ_FAILED,
    COUNTER_PATH_TRUNCATED, COUNTER_PAYLOAD_READ_FAILED, COUNTER_RINGBUF_RESERVE_FAILED,
    COUNTER_SLOT_COUNT, COUNTER_THREAD_CONTEXT_UPDATE_FAILED, COUNTER_TRACED_PROCESS_LIMIT,
    COUNTER_TRACEPOINT_READ_FAILED, COUNTER_UNIX_MSG_CONTROL_NESTED,
    COUNTER_UNIX_MSG_CONTROL_TRUNCATED, EVENT_FLAG_IOCTL_EXIT_REFRESHED,
    EVENT_FLAG_PAYLOAD_READ_FAILED, EVENT_FLAG_PAYLOAD_UNAVAILABLE, FILTER_KEY_ACTIVE,
    FILTER_KEY_ARG_U32_OFF, FILTER_KEY_CAUSAL_MODE, FILTER_KEY_FOLLOW_BINDER, FILTER_KEY_IOCTL_DIR,
    FILTER_KEY_LATENCY_MIN_US, FILTER_KEY_MATCH_BITS, FILTER_KEY_MAX_DEPTH, FILTER_KEY_PID,
    FILTER_KEY_RET_CLASS, FILTER_KEY_ROOT_UID, FILTER_KEY_ROOT_UID_ACTIVE,
    FILTER_KEY_ROOT_UID_ADMIT, FILTER_KEY_STATE_EMIT_REQUIRED, FILTER_MAP_SLOT_COUNT,
    MATCH_BIT_ARG_U32, MATCH_BIT_IOCTL_CMD, MATCH_BIT_IOCTL_DIR, MATCH_BIT_IOCTL_NR,
    MATCH_BIT_IOCTL_TYPE, MATCH_BIT_LATENCY, MATCH_BIT_RET, MATCH_BIT_UID,
    SYSCALL_NR_BINDER_RECEIVED, SYSCALL_NR_PROCESS_EXIT, TRACEPOINT_BINDER_CODE_OFFSET as BT_CODE,
    TRACEPOINT_BINDER_DEBUG_ID_OFFSET as BT_DEBUG_ID, TRACEPOINT_BINDER_FLAGS_OFFSET as BT_FLAGS,
    TRACEPOINT_BINDER_RECEIVED_DEBUG_ID_OFFSET as BTR_DEBUG_ID,
    TRACEPOINT_BINDER_REPLY_OFFSET as BT_REPLY,
    TRACEPOINT_BINDER_TARGET_NODE_OFFSET as BT_TARGET_NODE,
    TRACEPOINT_BINDER_TO_PROC_OFFSET as BT_TO_PROC,
    TRACEPOINT_BINDER_TO_THREAD_OFFSET as BT_TO_THREAD,
    TRACEPOINT_SCHED_EXIT_COMM_OFFSET as SCHED_EXIT_COMM,
    TRACEPOINT_SCHED_EXIT_PID_OFFSET as SCHED_EXIT_PID,
    TRACEPOINT_SYS_ENTER_ARGS_OFFSET as SYS_ENTER_ARGS,
    TRACEPOINT_SYS_ENTER_ID_OFFSET as SYS_ENTER_ID, TRACEPOINT_SYS_EXIT_ID_OFFSET as SYS_EXIT_ID,
    TRACEPOINT_SYS_EXIT_RET_OFFSET as SYS_EXIT_RET,
};
#[cfg(feature = "stacks")]
use neutron_common::{BPF_FEATURE_STACKS, COUNTER_STACK_KERNEL_FAILED, COUNTER_STACK_USER_FAILED};

const BASE_BPF_FEATURES: u64 = BPF_FEATURE_SYSCALL_TRACE
    | BPF_FEATURE_BINDER_TRACE
    | BPF_FEATURE_PER_CPU_HEALTH
    | BPF_FEATURE_PROCESS_EXIT;
#[cfg(feature = "stacks")]
const BPF_FEATURES: u64 = BASE_BPF_FEATURES | BPF_FEATURE_STACKS;
#[cfg(not(feature = "stacks"))]
const BPF_FEATURES: u64 = BASE_BPF_FEATURES;

/// Kept in an Aya-ignored custom ELF section so userspace can reject a stale
/// or mismatched object before any map is created or program is attached.
#[used]
#[link_section = ".neutron_abi"]
static NEUTRON_BPF_ABI: [u8; neutron_common::BPF_ABI_ENCODED_SIZE] = BpfAbiMetadata {
    magic: BPF_ABI_MAGIC,
    abi_major: BPF_ABI_MAJOR,
    abi_minor: BPF_ABI_MINOR,
    syscall_event_size: size_of::<SyscallEvent>() as u32,
    feature_bits: BPF_FEATURES,
    build_id: bpf_build_id_from_git_hex(option_env!("NEUTRON_GIT_COMMIT")),
}
.encode();

// ── Maps ─────────────────────────────────────────────────────────────────────

/// `filter_map[FILTER_KEY_PID]`    = target PID (0 = all)
/// `filter_map[FILTER_KEY_ACTIVE]` = syscall filter active (0 = off, 1 = on)
///
/// Phase 1a extends the array with predicate-driven slots — see the
/// `FILTER_KEY_*` constants in `neutron-common`. The size matches
/// `FILTER_MAP_SLOT_COUNT` so future Phase-1 slots can be added without a
/// wire bump.
#[map]
static FILTER_MAP: Array<u32> = Array::with_max_entries(FILTER_MAP_SLOT_COUNT, 0);

/// Single multi-producer ring buffer for syscall events.
/// Size: 1 MiB — must be a power of two and at least one page. At 257 bytes
/// per event (plus an 8-byte record header), this fits ~3950 events of burst
/// capacity, comfortably absorbing observed 100k-events/s peaks on Pixel 8 Pro.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[repr(C, align(8))]
struct AlignedEvent {
    event: SyscallEvent,
}

/// Per-CPU scratch used by the syscall-exit path, whose live locals plus a
/// full event exceed BPF's 512-byte stack limit. Tracepoint programs run with
/// migration disabled, so a single value per CPU is sufficient.
#[map]
static EVENT_SCRATCH: PerCpuArray<AlignedEvent> = PerCpuArray::with_max_entries(1, 0);

/// Enter/exit correlation: `pid_tgid` → `SyscallEvent` captured on sys_enter.
#[map]
static INFLIGHT: HashMap<u64, SyscallEvent> = HashMap::with_max_entries(4096, 0);

/// Syscall whitelist. Active only when `FILTER_MAP[FILTER_KEY_ACTIVE] == 1`.
#[map]
static SYSCALL_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

/// Additional PIDs to trace (child processes after clone()).
#[map]
static PID_WHITELIST: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

/// Explicit target PIDs that have exited during this capture. The static
/// CONFIG target is intentionally immutable, so this guard prevents a later
/// PID reuse from being accepted even if the process-exit ring record itself
/// cannot reach userspace.
#[map]
static EXITED_TARGET_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

/// Dynamic causal set. Userspace overrides max_entries at load time from
/// `--max-processes`; Binder propagation updates it before publishing events.
#[map]
static TRACED_PROCESSES: HashMap<u32, ProcessTraceContext> = HashMap::with_max_entries(64, 0);

/// Reserved pre-attachment follower deny set. The 1.5 CLI leaves this empty
/// and rejects domain-policy flags because it cannot enforce them safely at
/// first-event admission.
#[map]
static BINDER_FOLLOW_DENY_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

/// Context assigned when explicit `--root-uid` admits a process on its first
/// event. Userspace swaps this singleton at causal scenario boundaries.
#[map]
static ROOT_UID_CONTEXT: Array<ProcessTraceContext> = Array::with_max_entries(1, 0);

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct BinderTransactionContext {
    process: ProcessTraceContext,
    flags: u32,
    parent_debug_id: u32,
    relation: u8,
    admission_boundary: u8,
}

#[map]
static BINDER_TRANSACTION_CONTEXT: HashMap<u32, BinderTransactionContext> =
    HashMap::with_max_entries(4096, 0);

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct BinderThreadContext {
    debug_id: u32,
    scenario_generation: u16,
    depth: u8,
    admission_boundary: u8,
}

#[map]
static THREAD_BINDER_CONTEXT: HashMap<u64, BinderThreadContext> =
    HashMap::with_max_entries(4096, 0);

/// Threads in dynamically Binder-admitted processes that have executed at
/// least one post-admission syscall enter. A sibling Binder thread can still
/// be exiting a syscall that began before its process was admitted; the first
/// such exit is a causal boundary, not an INFLIGHT loss.
#[map]
static ADMITTED_THREAD_ENTERS: HashMap<u64, u8> = HashMap::with_max_entries(4096, 0);

/// Watched fds for selective read/write capture.
/// Key: `(pid << 32) | fd`. Value: tag (1 = procfs/sysfs).
#[map]
static WATCH_FDS: HashMap<u64, u8> = HashMap::with_max_entries(256, 0);

/// Stack trace map. 127 frames * 8 bytes = 1016 bytes per slot.
#[cfg(feature = "stacks")]
#[map]
static STACK_TRACES: StackTrace = StackTrace::with_max_entries(16384, 0);

// ── Phase 1a — predicate-set maps ────────────────────────────────────────────
//
// These maps materialise the BPF-evaluable subset of `--match-*` flags. A
// map being non-empty is meaningless on its own; the corresponding bit in
// `FILTER_MAP[FILTER_KEY_MATCH_BITS]` is the authoritative "active"
// indicator. Userspace populates one or both atomically when configuring.

/// UID values matching `--match-uid`. Active when `MATCH_BIT_UID` is set.
#[map]
static MATCH_UID_SET: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

/// ioctl `cmd` values matching `--match-ioctl-cmd`. Compared against the
/// 32-bit cmd word as the kernel sees it. Gated by `MATCH_BIT_IOCTL_CMD`.
#[map]
static MATCH_IOCTL_CMD_SET: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

/// `_IOC_TYPE` byte values matching `--match-ioctl-type`. Gated by
/// `MATCH_BIT_IOCTL_TYPE`. Stored as u32 because BPF HashMap keys must be
/// at least 4 bytes.
#[map]
static MATCH_IOCTL_TYPE_SET: HashMap<u32, u8> = HashMap::with_max_entries(16, 0);

/// `_IOC_NR` byte values matching `--match-ioctl-nr`. Gated by
/// `MATCH_BIT_IOCTL_NR`.
#[map]
static MATCH_IOCTL_NR_SET: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

/// u32 LE values matching `--match-arg-u32-vals`. The BPF programs read a
/// u32 from the captured ioctl payload at offset
/// `FILTER_MAP[FILTER_KEY_ARG_U32_OFF]` (relative to `data[4..]`) and look
/// up the value here. Gated by `MATCH_BIT_ARG_U32`.
#[map]
static MATCH_ARG_U32_VALS: HashMap<u32, u8> = HashMap::with_max_entries(32, 0);

/// Runtime ioctl post-exit refresh allowlist keyed by full cmd word.
/// Populated by userspace when `--driver-pack` enables a decoder whose
/// meaningful scalar fields are written back on exit.
#[map]
static IOCTL_REFRESH_CMD_SET: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

/// Runtime ioctl post-exit refresh allowlist keyed by `_IOC_TYPE` byte.
/// Lets decoder packs opt in a family without rebuilding the BPF object.
#[map]
static IOCTL_REFRESH_TYPE_SET: HashMap<u32, u8> = HashMap::with_max_entries(32, 0);

/// Capture-health counters. Each CPU owns its own monotonic `u64` slot, so the
/// loss-accounting path cannot itself lose cross-CPU read/add/write updates.
/// Userspace must aggregate every CPU for each `COUNTER_*` index.
#[map]
static COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(COUNTER_SLOT_COUNT, 0);

#[inline(always)]
fn bump_counter(idx: u32) {
    if let Some(slot) = COUNTERS.get_ptr_mut(idx) {
        // SAFETY: `slot` points to this CPU's u64 in the per-CPU array. A
        // tracepoint program does not migrate CPUs while executing, so no
        // cross-CPU writer aliases this value.
        unsafe {
            let cur = core::ptr::read_unaligned(slot);
            core::ptr::write_unaligned(slot, cur.wrapping_add(1));
        }
    }
}

/// Read one required field from a tracepoint context. Doctor validates the
/// static layout before attach, but a runtime helper failure still invalidates
/// the affected event and must be represented in capture health.
macro_rules! required_tracepoint_field {
    ($ctx:expr, $ty:ty, $offset:expr) => {
        match unsafe { $ctx.read_at::<$ty>($offset) } {
            Ok(value) => value,
            Err(_) => {
                bump_counter(COUNTER_TRACEPOINT_READ_FAILED);
                return Err(());
            }
        }
    };
}

#[inline(always)]
fn ioctl_refresh_enabled(cmd: u32) -> bool {
    if neutron_common::ioctl_post_exit_refresh(cmd) {
        return true;
    }
    if unsafe { IOCTL_REFRESH_CMD_SET.get(&cmd) }.is_some() {
        return true;
    }
    let ty = neutron_common::ioctl_type(cmd);
    if unsafe { IOCTL_REFRESH_TYPE_SET.get(&ty) }.is_some() {
        return true;
    }
    false
}

// ── Common filter helpers ────────────────────────────────────────────────────

/// Returns the configured target PID (0 means "all"), or `None` if the filter
/// map is unreachable (treat as "drop event" to fail closed).
#[inline(always)]
fn target_pid() -> Option<u32> {
    FILTER_MAP.get(FILTER_KEY_PID).copied()
}

#[inline(always)]
fn syscall_filter_active() -> bool {
    matches!(FILTER_MAP.get(FILTER_KEY_ACTIVE).copied(), Some(v) if v != 0)
}

#[inline(always)]
fn causal_mode() -> bool {
    matches!(FILTER_MAP.get(FILTER_KEY_CAUSAL_MODE).copied(), Some(v) if v != 0)
}

#[inline(always)]
fn follow_binder_enabled() -> bool {
    matches!(FILTER_MAP.get(FILTER_KEY_FOLLOW_BINDER).copied(), Some(v) if v != 0)
}

#[inline(always)]
fn max_causal_depth() -> u8 {
    FILTER_MAP
        .get(FILTER_KEY_MAX_DEPTH)
        .copied()
        .unwrap_or(0)
        .min(u8::MAX as u32) as u8
}

#[inline(always)]
fn root_uid_matches() -> bool {
    if !matches!(FILTER_MAP.get(FILTER_KEY_ROOT_UID_ACTIVE).copied(), Some(1)) {
        return true;
    }
    let Some(expected) = FILTER_MAP.get(FILTER_KEY_ROOT_UID).copied() else {
        return false;
    };
    bpf_get_current_uid_gid() as u32 == expected
}

#[inline(always)]
fn root_uid_admission_enabled() -> bool {
    matches!(FILTER_MAP.get(FILTER_KEY_ROOT_UID_ADMIT).copied(), Some(1))
}

#[inline(always)]
fn active_causal_context_matches(context: ProcessTraceContext) -> bool {
    let Some(active) = ROOT_UID_CONTEXT.get(0).copied() else {
        return false;
    };
    context.root_trace_id != 0
        && context.root_trace_id == active.root_trace_id
        && context.scenario_generation == active.scenario_generation
}

/// Returns `true` if the given userspace process ID matches the configured
/// target. `userspace_pid` corresponds to kernel `task_struct->tgid` and is
/// stable across all threads of the process — that is precisely the property
/// we want for app-wide tracing (binder pool threads, JIT helpers, native
/// workers, WebView/Chromium threads all share it).
#[inline(always)]
fn pid_matches(userspace_pid: u32) -> bool {
    let context = unsafe { TRACED_PROCESSES.get(&userspace_pid) }.copied();
    let action = causal_pid_action(
        causal_mode(),
        context.map_or(0, |value| value.reason as u8),
        root_uid_admission_enabled(),
        root_uid_matches(),
    );
    if action == CAUSAL_PID_MATCH {
        return context.is_some_and(|existing| {
            (existing.reason == TraceReason::Root && existing.root_trace_id == 0)
                || active_causal_context_matches(existing)
        });
    }
    if action == CAUSAL_PID_ADMIT_ROOT {
        let Some(root) = ROOT_UID_CONTEXT.get(0).copied() else {
            return false;
        };
        if root.reason != TraceReason::Root {
            return false;
        }
        if context.is_some_and(|existing| {
            existing.root_trace_id == root.root_trace_id
                && existing.scenario_generation == root.scenario_generation
        }) {
            return true;
        }
        if TRACED_PROCESSES.insert(&userspace_pid, &root, 0).is_err() {
            bump_counter(COUNTER_TRACED_PROCESS_LIMIT);
            return false;
        }
        return true;
    }
    if action != CAUSAL_PID_FALLTHROUGH {
        return false;
    }
    let target = match target_pid() {
        Some(t) => t,
        None => return false,
    };
    if target != 0 && target == userspace_pid {
        return unsafe { EXITED_TARGET_PIDS.get(&userspace_pid).is_none() };
    }
    // SAFETY: `HashMap::get` borrows into kernel map memory; we discard the
    // borrow immediately, so no aliasing concern.
    if unsafe { PID_WHITELIST.get(&userspace_pid).is_some() } {
        return true;
    }
    target == 0 && !causal_mode()
}

const EMPTY_PROCESS_CONTEXT: ProcessTraceContext = ProcessTraceContext {
    root_trace_id: 0,
    parent_pid: 0,
    binder_debug_id: 0,
    depth: 0,
    reason: TraceReason::Root,
    scenario_generation: 0,
};

/// The zero `root_trace_id` tuple means "no causal context". Live trace IDs
/// are always non-zero. Returning a fully initialized tuple instead of an
/// `Option` prevents LLVM from spilling an uninitialized enum payload that
/// the BPF verifier cannot prove is read only after its discriminant.
#[inline(always)]
fn causal_context(pid_tgid: u64, userspace_pid: u32) -> (ProcessTraceContext, u32, u8) {
    let Some(process) = unsafe { TRACED_PROCESSES.get(&userspace_pid) }.copied() else {
        return (EMPTY_PROCESS_CONTEXT, 0, 0);
    };
    if process.root_trace_id != 0 && !active_causal_context_matches(process) {
        return (EMPTY_PROCESS_CONTEXT, 0, 0);
    }
    if let Some(thread) = unsafe { THREAD_BINDER_CONTEXT.get(&pid_tgid) }.copied() {
        if thread.scenario_generation == process.scenario_generation {
            let mut context = process;
            context.depth = thread.depth;
            context.binder_debug_id = thread.debug_id;
            return (context, thread.debug_id, CAUSAL_RELATION_EXACT);
        }
    }
    let relation = if process.depth == 0 {
        CAUSAL_RELATION_EXACT
    } else {
        CAUSAL_RELATION_INFERRED
    };
    (process, process.binder_debug_id, relation)
}

#[inline(always)]
fn syscall_allowed(nr: i32) -> bool {
    if !syscall_filter_active() {
        return true;
    }
    let key = nr as u32;
    // SAFETY: see `pid_matches`.
    unsafe { SYSCALL_FILTER.get(&key).is_some() }
}

// ── Phase 1a — predicate evaluators ──────────────────────────────────────────

/// Read a `MATCH_BITS` flag. Defaults to "no predicate active" if the
/// FILTER_MAP slot is unreadable — fail-open keeps existing flows working.
#[inline(always)]
fn match_bits() -> u32 {
    FILTER_MAP.get(FILTER_KEY_MATCH_BITS).copied().unwrap_or(0)
}

#[inline(always)]
fn match_active(bit: u32) -> bool {
    (match_bits() & bit) != 0
}

#[inline(always)]
fn state_emit_required() -> bool {
    matches!(
        FILTER_MAP.get(FILTER_KEY_STATE_EMIT_REQUIRED).copied(),
        Some(v) if v != 0
    )
}

#[inline(always)]
fn uid_matches_predicate(uid: u32) -> bool {
    if !match_active(MATCH_BIT_UID) {
        return true;
    }
    // SAFETY: same map-borrow rules as `pid_matches`.
    unsafe { MATCH_UID_SET.get(&uid).is_some() }
}

/// ioctl-shape predicates. `cmd` is the 32-bit cmd word from `args[1]`,
/// `payload_ptr` is the captured arg snapshot starting at `data[4..]`.
/// Returns `true` when every active ioctl predicate matches; vacuously
/// `true` when no ioctl predicate is configured.
#[inline(always)]
fn ioctl_matches_predicate(cmd: u32, payload_ptr: *const u8) -> bool {
    if match_active(MATCH_BIT_IOCTL_CMD) && unsafe { MATCH_IOCTL_CMD_SET.get(&cmd) }.is_none() {
        return false;
    }
    if match_active(MATCH_BIT_IOCTL_TYPE) {
        let ty = (cmd >> 8) & 0xff;
        if unsafe { MATCH_IOCTL_TYPE_SET.get(&ty) }.is_none() {
            return false;
        }
    }
    if match_active(MATCH_BIT_IOCTL_NR) {
        let nr = cmd & 0xff;
        if unsafe { MATCH_IOCTL_NR_SET.get(&nr) }.is_none() {
            return false;
        }
    }
    if match_active(MATCH_BIT_IOCTL_DIR) {
        let dir = (cmd >> 30) & 0x3;
        let want = FILTER_MAP.get(FILTER_KEY_IOCTL_DIR).copied().unwrap_or(0);
        if dir != want {
            return false;
        }
    }
    if match_active(MATCH_BIT_ARG_U32) {
        let off = FILTER_MAP.get(FILTER_KEY_ARG_U32_OFF).copied().unwrap_or(0);
        // `data[4..128]` holds 124 bytes. We need 4 bytes at `off`, so the
        // valid range for `off` is `0..=120`. Userspace bounds-checks at
        // configuration time but we re-check defensively — a verifier-friendly
        // bound here also satisfies the "constant max-offset" pattern the
        // BPF verifier wants.
        if off > 120 {
            return false;
        }
        if off.saturating_add(4) > bounded_ioctl_payload_len(cmd) as u32 {
            return false;
        }
        let mut buf = [0u8; 4];
        // SAFETY: `payload_ptr` is the address of the captured `data[4..]`
        // window inside the on-stack `SyscallEvent`. `off + 4 <= 124` is
        // bounded above. We use the kernel-buf helper because the data lives
        // in BPF stack memory by the time we read it back during enter. See
        // `try_sys_enter` for the population path.
        let src = unsafe { payload_ptr.add(off as usize) };
        if unsafe { bpf_probe_read_kernel_buf(src, &mut buf) }.is_err() {
            bump_counter(COUNTER_PAYLOAD_READ_FAILED);
            return false;
        }
        let v = u32::from_le_bytes(buf);
        if unsafe { MATCH_ARG_U32_VALS.get(&v) }.is_none() {
            return false;
        }
    }
    true
}

/// Combined enter-side predicate. Evaluates the BPF-evaluable AND-conjunction
/// of `--match-*` flags. Returns `true` when all configured predicates
/// match — or when the syscall is in the state-tracking set and userspace
/// requested state events. The userspace post-filter still applies the
/// remaining (non-BPF-evaluable) clauses on its side.
#[inline(always)]
fn enter_predicate_match(nr: i32, uid: u32, ev: *const SyscallEvent) -> bool {
    if !uid_matches_predicate(uid) {
        return false;
    }
    if nr == 29 {
        // SAFETY: `ev` points to the on-stack `SyscallEvent` populated by
        // `capture_syscall_data`. `data` is a `[u8; 128]` inside that struct;
        // `data[4..]` is the captured arg snapshot.
        let cmd = unsafe { core::ptr::addr_of!((*ev).args).read_unaligned() }[1] as u32;
        let reserved = unsafe { core::ptr::addr_of!((*ev)._reserved).read_unaligned() };
        if match_active(MATCH_BIT_ARG_U32)
            && reserved[0] & (EVENT_FLAG_PAYLOAD_READ_FAILED | EVENT_FLAG_PAYLOAD_UNAVAILABLE) != 0
        {
            return false;
        }
        let payload_ptr = unsafe { (core::ptr::addr_of!((*ev).data) as *const u8).add(4) };
        if !ioctl_matches_predicate(cmd, payload_ptr) {
            return false;
        }
    } else {
        // Non-ioctl events: ioctl-shape predicates are inapplicable. If the
        // user configured them, they implicitly restrict to ioctl events.
        // `arg.u32@N` is also ioctl-only because the offset is relative to
        // the ioctl arg snapshot.
        if match_active(MATCH_BIT_IOCTL_CMD)
            || match_active(MATCH_BIT_IOCTL_TYPE)
            || match_active(MATCH_BIT_IOCTL_NR)
            || match_active(MATCH_BIT_IOCTL_DIR)
            || match_active(MATCH_BIT_ARG_U32)
        {
            return false;
        }
    }
    true
}

/// Combined exit-side predicate. Layers ret-class and latency thresholds on
/// top of the enter-side predicate; reuses [`enter_predicate_match`] via
/// the saved INFLIGHT entry. `saved` must be non-null (callers handle the
/// null case before getting here).
#[inline(always)]
fn exit_predicate_match(nr: i32, uid: u32, saved: *const SyscallEvent, ret: i64, now: u64) -> bool {
    if !enter_predicate_match(nr, uid, saved) {
        return false;
    }
    if match_active(MATCH_BIT_RET) {
        let class = FILTER_MAP.get(FILTER_KEY_RET_CLASS).copied().unwrap_or(0);
        if !ret_matches_class(ret, class) {
            return false;
        }
    }
    if match_active(MATCH_BIT_LATENCY) {
        let min_us = FILTER_MAP
            .get(FILTER_KEY_LATENCY_MIN_US)
            .copied()
            .unwrap_or(0) as u64;
        let enter_ts = unsafe { core::ptr::addr_of!((*saved).enter_timestamp_ns).read_unaligned() };
        if enter_ts == 0 || now < enter_ts {
            return false;
        }
        let lat_us = (now - enter_ts) / 1_000;
        if lat_us < min_us {
            return false;
        }
    }
    true
}

/// Phase 1 emit gate for `sys_enter`. Returns true when the event should be
/// submitted to the ringbuf. Independent of INFLIGHT update — by the time
/// this is checked, an allowlisted syscall has already populated INFLIGHT so
/// exit-time predicates (ret/latency) keep working.
///
/// Composition (safe over-approximation):
/// 1. Legacy `syscall_allowed` whitelist (gated by `FILTER_KEY_ACTIVE`).
/// 2. Predicate AND-conjunction across configured `MATCH_*` clauses.
/// 3. Always-pass for state-tracking syscalls when userspace requested it.
/// 4. When an exit-only predicate (`MATCH_BIT_RET` / `MATCH_BIT_LATENCY`)
///    is configured, drop enter events outright before ringbuf
///    reservation. The matching exit will still emit if it satisfies
///    the predicate; INFLIGHT was populated for the allowlisted syscall so the
///    exit retains args/data/stack. Saves the ringbuf bandwidth that
///    the 2026-05-06 device test surfaced as 321k unwanted enter
///    events under `--match-ret negative`.
#[inline(always)]
fn should_submit_enter(nr: i32, uid: u32, ev: *const SyscallEvent) -> bool {
    if !syscall_allowed(nr) {
        return false;
    }
    let bits = match_bits();
    let exit_only = (bits & (MATCH_BIT_RET | MATCH_BIT_LATENCY)) != 0;
    if exit_only && !(state_emit_required() && is_state_tracking_nr(nr)) {
        return false;
    }
    if enter_predicate_match(nr, uid, ev) {
        return true;
    }
    if state_emit_required() && is_state_tracking_nr(nr) {
        return true;
    }
    // No predicate active and no state-tracking opt-in: legacy fast path.
    bits == 0
}

/// Phase 1 emit gate for `sys_exit`. Same composition as the enter gate but
/// also evaluates `MATCH_BIT_RET` / `MATCH_BIT_LATENCY` against the saved
/// INFLIGHT entry. `saved` may be null when the matching enter was lost
/// (capture started after enter, INFLIGHT cap evicted the entry, etc.); in
/// that case ioctl-shape and ret/latency predicates cannot be evaluated and
/// we fall back to the same composition as the enter gate sans predicate.
#[inline(always)]
fn should_submit_exit(nr: i32, uid: u32, saved: *const SyscallEvent, ret: i64, now: u64) -> bool {
    if !syscall_allowed(nr) {
        return false;
    }
    if !saved.is_null() && exit_predicate_match(nr, uid, saved, ret, now) {
        return true;
    }
    if state_emit_required() && is_state_tracking_nr(nr) {
        return true;
    }
    match_bits() == 0
}

// ── Raw event helpers ────────────────────────────────────────────────────────
//
// All field writes go through raw pointers because `SyscallEvent` is
// `#[repr(C, packed)]` (alignment 1) — forming `&packed.field` is UB.

/// Zero one wire event without asking LLVM to emit a generic `memset` loop.
/// Android's 6.1 verifier explores such compiler-builtins until the one
/// million instruction limit. Callers provide 8-byte-aligned stack, map, or
/// ring memory via [`AlignedEvent`] or Aya's ring buffer.
#[inline(always)]
unsafe fn zero_event(ev: *mut SyscallEvent) {
    let base = ev.cast::<u8>();
    macro_rules! zero_u64 {
        ($($offset:expr),+ $(,)?) => {
            $(core::ptr::write_volatile(base.add($offset).cast::<u64>(), 0);)+
        };
    }
    zero_u64!(
        0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 136, 144, 152, 160,
        168, 176, 184, 192, 200, 208, 216, 224, 232, 240, 248,
    );
    core::ptr::write_volatile(base.add(256), 0);
}

/// Copy one aligned wire event without a generic `memcpy`/`memmove`
/// subprogram. Volatile fixed-width accesses keep LLVM from folding the
/// bounded stores back into a verifier-hostile loop.
#[inline(always)]
unsafe fn copy_event(dst: *mut SyscallEvent, src: *const SyscallEvent) {
    let dst = dst.cast::<u8>();
    let src = src.cast::<u8>();
    macro_rules! copy_u64 {
        ($($offset:expr),+ $(,)?) => {
            $(
                core::ptr::write_volatile(
                    dst.add($offset).cast::<u64>(),
                    core::ptr::read_volatile(src.add($offset).cast::<u64>()),
                );
            )+
        };
    }
    copy_u64!(
        0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 136, 144, 152, 160,
        168, 176, 184, 192, 200, 208, 216, 224, 232, 240, 248,
    );
    core::ptr::write_volatile(dst.add(256), core::ptr::read_volatile(src.add(256)));
}

#[inline(always)]
unsafe fn write_current_comm(ev: *mut SyscallEvent) {
    let _ = gen::bpf_get_current_comm(addr_of_mut!((*ev).comm).cast(), 16);
}

#[inline(always)]
fn event_scratch() -> Option<*mut SyscallEvent> {
    EVENT_SCRATCH
        .get_ptr_mut(0)
        .map(|storage| unsafe { addr_of_mut!((*storage).event) })
}

/// Single-pointer-into-`data[..]` writes. `off` must be in `0..128`.
#[inline(always)]
unsafe fn data_ptr(ev: *mut SyscallEvent, off: usize) -> *mut u8 {
    (addr_of_mut!((*ev).data) as *mut u8).add(off)
}

#[inline(always)]
unsafe fn reserved_ptr(ev: *mut SyscallEvent, off: usize) -> *mut u8 {
    (addr_of_mut!((*ev)._reserved) as *mut u8).add(off)
}

#[inline(always)]
unsafe fn data_write_u8(ev: *mut SyscallEvent, off: usize, v: u8) {
    *data_ptr(ev, off) = v;
}

#[inline(always)]
unsafe fn reserved_write_u8(ev: *mut SyscallEvent, off: usize, v: u8) {
    *reserved_ptr(ev, off) = v;
}

#[inline(always)]
unsafe fn mark_payload_read_failed(ev: *mut SyscallEvent) {
    let flags = reserved_ptr(ev, 0);
    *flags |= EVENT_FLAG_PAYLOAD_READ_FAILED;
}

#[inline(always)]
unsafe fn mark_payload_unavailable(ev: *mut SyscallEvent) {
    let flags = reserved_ptr(ev, 0);
    *flags |= EVENT_FLAG_PAYLOAD_UNAVAILABLE;
}

#[inline(always)]
unsafe fn reserved_write_u32(ev: *mut SyscallEvent, off: usize, value: u32) {
    let bytes = value.to_le_bytes();
    reserved_write_u8(ev, off, bytes[0]);
    reserved_write_u8(ev, off + 1, bytes[1]);
    reserved_write_u8(ev, off + 2, bytes[2]);
    reserved_write_u8(ev, off + 3, bytes[3]);
}

#[inline(always)]
unsafe fn stamp_causal(
    ev: *mut SyscallEvent,
    context: ProcessTraceContext,
    parent_debug_id: u32,
    relation: u8,
) {
    addr_of_mut!((*ev).maps_generation).write_unaligned(context.scenario_generation);
    reserved_write_u32(ev, 1, parent_debug_id);
    reserved_write_u8(ev, 5, encode_causal_relation_depth(relation, context.depth));
}

#[inline(always)]
fn follow_binder_callee(
    caller: ProcessTraceContext,
    caller_pid: u32,
    callee_pid: i32,
    debug_id: i32,
    flags: u32,
    parent_debug_id: u32,
    relation: u8,
) {
    if !follow_binder_enabled() || !active_causal_context_matches(caller) {
        return;
    }
    if callee_pid <= 0 || debug_id == 0 {
        bump_counter(COUNTER_BINDER_FOLLOW_FAILED);
        return;
    }
    let depth = caller.depth.saturating_add(1);
    if depth > max_causal_depth() {
        bump_counter(COUNTER_BINDER_DEPTH_LIMIT);
        return;
    }
    let pid = callee_pid as u32;
    if unsafe { BINDER_FOLLOW_DENY_PIDS.get(&pid) }.is_some() {
        return;
    }
    let existing = unsafe { TRACED_PROCESSES.get(&pid) }.copied();
    let preserve_root = existing.is_some_and(|context| context.reason == TraceReason::Root);
    let process = ProcessTraceContext {
        root_trace_id: caller.root_trace_id,
        parent_pid: caller_pid,
        binder_debug_id: debug_id as u32,
        depth,
        reason: TraceReason::Binder,
        scenario_generation: caller.scenario_generation,
    };
    let transaction = BinderTransactionContext {
        process,
        flags,
        parent_debug_id,
        relation,
        admission_boundary: u8::from(existing.is_none()),
    };
    if BINDER_TRANSACTION_CONTEXT
        .insert(&(debug_id as u32), &transaction, 0)
        .is_err()
    {
        bump_counter(COUNTER_BINDER_FOLLOW_FAILED);
        return;
    }
    if !preserve_root && TRACED_PROCESSES.insert(&pid, &process, 0).is_err() {
        let _ = BINDER_TRANSACTION_CONTEXT.remove(&(debug_id as u32));
        bump_counter(COUNTER_TRACED_PROCESS_LIMIT);
        bump_counter(COUNTER_BINDER_FOLLOW_FAILED);
    }
}

#[inline(always)]
fn consume_admission_boundary_exit(pid_tgid: u64) -> bool {
    let Some(context) = unsafe { THREAD_BINDER_CONTEXT.get(&pid_tgid) }.copied() else {
        return false;
    };
    if context.admission_boundary == 0 {
        return false;
    }
    let consumed = BinderThreadContext {
        debug_id: context.debug_id,
        scenario_generation: context.scenario_generation,
        depth: context.depth,
        admission_boundary: 0,
    };
    THREAD_BINDER_CONTEXT
        .insert(&pid_tgid, &consumed, 0)
        .is_ok()
}

#[inline(always)]
fn mark_admitted_thread_enter(pid_tgid: u64, userspace_pid: u32) {
    let Some(context) = unsafe { TRACED_PROCESSES.get(&userspace_pid) }.copied() else {
        return;
    };
    if context.reason != TraceReason::Binder || !active_causal_context_matches(context) {
        return;
    }
    let _ = ADMITTED_THREAD_ENTERS.insert(&pid_tgid, &1, 0);
}

#[inline(always)]
fn consume_sibling_admission_boundary_exit(pid_tgid: u64, userspace_pid: u32) -> bool {
    let Some(context) = unsafe { TRACED_PROCESSES.get(&userspace_pid) }.copied() else {
        return false;
    };
    if !active_causal_context_matches(context) {
        return false;
    }
    let seen_enter = unsafe { ADMITTED_THREAD_ENTERS.get(&pid_tgid) }.is_some();
    if !causal_admission_boundary_exit(context.reason, seen_enter, false) {
        return false;
    }
    ADMITTED_THREAD_ENTERS.insert(&pid_tgid, &1, 0).is_ok()
}

#[inline(always)]
unsafe fn data_write_u32(ev: *mut SyscallEvent, off: usize, v: u32) {
    let b = v.to_le_bytes();
    data_write_u8(ev, off, b[0]);
    data_write_u8(ev, off + 1, b[1]);
    data_write_u8(ev, off + 2, b[2]);
    data_write_u8(ev, off + 3, b[3]);
}

#[inline(always)]
unsafe fn data_write_u64(ev: *mut SyscallEvent, off: usize, v: u64) {
    let b = v.to_le_bytes();
    data_write_u8(ev, off, b[0]);
    data_write_u8(ev, off + 1, b[1]);
    data_write_u8(ev, off + 2, b[2]);
    data_write_u8(ev, off + 3, b[3]);
    data_write_u8(ev, off + 4, b[4]);
    data_write_u8(ev, off + 5, b[5]);
    data_write_u8(ev, off + 6, b[6]);
    data_write_u8(ev, off + 7, b[7]);
}

/// View `data[off..off+len]` as a mutable slice for use with the buf-style
/// helpers. Caller must guarantee `off + len <= 128`.
#[inline(always)]
unsafe fn data_slice(ev: *mut SyscallEvent, off: usize, len: usize) -> &'static mut [u8] {
    core::slice::from_raw_parts_mut(data_ptr(ev, off), len)
}

/// Capture a bounded user string and account for both unreadable and truncated
/// values. Aya excludes the NUL from the returned slice, so a 127-byte result
/// means the 128-byte destination was filled.
#[inline(always)]
unsafe fn capture_user_path(ev: *mut SyscallEvent, ptr: u64, dst: &mut [u8]) {
    match bpf_probe_read_user_str_bytes(ptr as *const u8, dst) {
        Ok(bytes) => {
            if bytes.len().saturating_add(1) >= dst.len() {
                bump_counter(COUNTER_PATH_TRUNCATED);
            }
        }
        Err(_) => {
            mark_payload_read_failed(ev);
            bump_counter(COUNTER_PATH_READ_FAILED);
        }
    }
}

/// Read a bounded user payload and make any failure visible in final capture
/// health. Callers must derive `dst.len()` from an ABI-declared bound rather
/// than from Neutron's destination capacity alone.
#[inline(always)]
unsafe fn capture_user_bytes(ev: *mut SyscallEvent, ptr: u64, dst: &mut [u8]) -> bool {
    if bpf_probe_read_user_buf(ptr as *const u8, dst).is_ok() {
        true
    } else {
        mark_payload_read_failed(ev);
        bump_counter(COUNTER_PAYLOAD_READ_FAILED);
        false
    }
}

#[inline(always)]
fn bounded_ioctl_payload_len(cmd: u32) -> usize {
    (neutron_common::ioctl_size(cmd) as usize).min(124)
}

// ── Per-syscall data capture ────────────────────────────────────────────────
//
// Mirrors `capture_syscall_data` in `bpf/syscall_tracer.bpf.c`. Operates on
// the supplied `SyscallEvent` directly so no large stack copy is needed.
// User-space pointers go through helper 114 (`bpf_probe_read_user_*`); the
// kernel-space helper 113 is used for memory we know is in kernel space.
#[inline(always)]
unsafe fn capture_syscall_data(ev: *mut SyscallEvent, nr: i32, args: &[u64; 6]) {
    // The producer and userspace decoder share this aarch64 path table.
    if let Some(arg_index) = neutron_common::syscall_path_arg_index(nr) {
        let ptr = args[arg_index];
        addr_of_mut!((*ev).ptr_hint).write_unaligned(ptr);
        if ptr != 0 {
            let dst = data_slice(ev, 0, 128);
            capture_user_path(ev, ptr, dst);
        } else {
            mark_payload_unavailable(ev);
        }
        return;
    }

    // ioctl(29): args[1] = cmd, args[2] = data pointer.
    // Pack: data[0..4] = cmd (u32 LE), data[4..128] = first 124 bytes of arg.
    if nr == 29 {
        let cmd = args[1] as u32;
        if neutron_common::ioctl_size(cmd) > 124 {
            bump_counter(COUNTER_IOCTL_PAYLOAD_TRUNCATED);
        }
        let bytes = cmd.to_le_bytes();
        data_write_u8(ev, 0, bytes[0]);
        data_write_u8(ev, 1, bytes[1]);
        data_write_u8(ev, 2, bytes[2]);
        data_write_u8(ev, 3, bytes[3]);
        let ptr = args[2];
        let len = bounded_ioctl_payload_len(cmd);
        if len != 0 {
            if ptr != 0 {
                let dst = data_slice(ev, 4, len);
                capture_user_bytes(ev, ptr, dst);
            } else {
                mark_payload_unavailable(ev);
            }
        }
        return;
    }

    // connect(203), bind(200): args[1] = sockaddr*, args[2] = addrlen.
    if matches!(nr, 203 | 200) {
        let ptr = args[1];
        addr_of_mut!((*ev).ptr_hint).write_unaligned(ptr);
        let len = neutron_common::bounded_sockaddr_len(args[2]) as usize;
        if len != 0 {
            if ptr != 0 {
                let dst = data_slice(ev, 0, len);
                capture_user_bytes(ev, ptr, dst);
            } else {
                mark_payload_unavailable(ev);
            }
        }
        return;
    }

    // sendto(206): args[4] = dest_addr, args[5] = addrlen.
    if nr == 206 {
        let ptr = args[4];
        addr_of_mut!((*ev).ptr_hint).write_unaligned(ptr);
        let len = neutron_common::bounded_sockaddr_len(args[5]) as usize;
        if len != 0 {
            if ptr != 0 {
                let dst = data_slice(ev, 0, len);
                capture_user_bytes(ev, ptr, dst);
            } else {
                mark_payload_unavailable(ev);
            }
        }
        return;
    }

    // sendmsg(211), recvmsg(212): args[1] = msghdr*. Read only the fields
    // we need. msghdr layout (aarch64):
    //   void*    msg_name        @ +0  (8)
    //   socklen  msg_namelen     @ +8  (4)
    //   void*    msg_control     @ +32 (8)
    //   size_t   msg_controllen  @ +40 (8)
    //
    // `data` layout for these syscalls:
    //   [0..28]   optional sockaddr from msg_name
    //   [64..72]  msg_controllen
    //   [80..88]  first cmsghdr.cmsg_len
    //   [88..92]  first cmsghdr.cmsg_level
    //   [92..96]  first cmsghdr.cmsg_type
    //   [96..100] bounded SCM_RIGHTS fd count
    if matches!(nr, 211 | 212) {
        let ptr = args[1];
        addr_of_mut!((*ev).ptr_hint).write_unaligned(ptr);
        if ptr == 0 {
            mark_payload_unavailable(ev);
            return;
        }
        // Read msg_name (8B pointer) + msg_namelen (4B) + 4B pad in one shot
        // into a stack scratch.
        let mut hdr_head_buf = MaybeUninit::<[u8; 16]>::uninit();
        let hdr_head = &mut *hdr_head_buf.as_mut_ptr();
        if !capture_user_bytes(ev, ptr, hdr_head) {
            return;
        }
        let name_ptr = u64::from_le_bytes([
            hdr_head[0],
            hdr_head[1],
            hdr_head[2],
            hdr_head[3],
            hdr_head[4],
            hdr_head[5],
            hdr_head[6],
            hdr_head[7],
        ]);
        let namelen = u32::from_le_bytes([hdr_head[8], hdr_head[9], hdr_head[10], hdr_head[11]]);
        data_write_u32(ev, 72, namelen);
        if name_ptr != 0 && namelen >= 2 {
            // Constant 28 = max sockaddr_in6.
            let len = (namelen as usize).min(28);
            let dst = data_slice(ev, 0, len);
            capture_user_bytes(ev, name_ptr, dst);
        } else if name_ptr == 0 && namelen != 0 {
            mark_payload_unavailable(ev);
        }
        // Read msg_control pointer + msg_controllen into stack scratch.
        let mut hdr_ctl_buf = MaybeUninit::<[u8; 16]>::uninit();
        let hdr_ctl = &mut *hdr_ctl_buf.as_mut_ptr();
        if !capture_user_bytes(ev, ptr.saturating_add(32), hdr_ctl) {
            bump_counter(COUNTER_UNIX_MSG_CONTROL_TRUNCATED);
            return;
        }
        let control_ptr = u64::from_le_bytes([
            hdr_ctl[0], hdr_ctl[1], hdr_ctl[2], hdr_ctl[3], hdr_ctl[4], hdr_ctl[5], hdr_ctl[6],
            hdr_ctl[7],
        ]);
        let controllen = u64::from_le_bytes([
            hdr_ctl[8],
            hdr_ctl[9],
            hdr_ctl[10],
            hdr_ctl[11],
            hdr_ctl[12],
            hdr_ctl[13],
            hdr_ctl[14],
            hdr_ctl[15],
        ]);
        data_write_u64(ev, 64, controllen);
        if controllen == 0 {
            return;
        }
        if control_ptr == 0 || controllen < 16 {
            mark_payload_unavailable(ev);
            bump_counter(COUNTER_UNIX_MSG_CONTROL_TRUNCATED);
            return;
        }
        let mut cmsg_buf = MaybeUninit::<[u8; 16]>::uninit();
        let cmsg = &mut *cmsg_buf.as_mut_ptr();
        if !capture_user_bytes(ev, control_ptr, cmsg) {
            bump_counter(COUNTER_UNIX_MSG_CONTROL_TRUNCATED);
            return;
        }
        let cmsg_len = u64::from_le_bytes([
            cmsg[0], cmsg[1], cmsg[2], cmsg[3], cmsg[4], cmsg[5], cmsg[6], cmsg[7],
        ]);
        let cmsg_level = u32::from_le_bytes([cmsg[8], cmsg[9], cmsg[10], cmsg[11]]);
        let cmsg_type = u32::from_le_bytes([cmsg[12], cmsg[13], cmsg[14], cmsg[15]]);
        data_write_u64(ev, 80, cmsg_len);
        data_write_u32(ev, 88, cmsg_level);
        data_write_u32(ev, 92, cmsg_type);
        if cmsg_len < 16 || cmsg_len > controllen {
            bump_counter(COUNTER_UNIX_MSG_CONTROL_TRUNCATED);
            return;
        }
        // CMSG_ALIGN(len) for 64-bit ABI: (len + 7) & !7. If there is more
        // control data after the first aligned header, record the loss.
        let aligned = (cmsg_len + 7) & !7;
        if controllen > aligned {
            bump_counter(COUNTER_UNIX_MSG_CONTROL_NESTED);
        }
        // SOL_SOCKET=1, SCM_RIGHTS=1. Count fds in the first control record,
        // bounded to avoid implying we captured an arbitrary-length list.
        if cmsg_level == 1 && cmsg_type == 1 && cmsg_len >= 16 {
            let bytes = cmsg_len - 16;
            let count = (bytes / 4).min(16) as u32;
            data_write_u32(ev, 96, count);
        }
        return;
    }

    // read(63), write(64): if fd is in WATCH_FDS, stash buf pointer in
    // `ptr_hint` and record tag at data[8]. Buffer-content capture is not
    // implemented yet; the userspace `process_vm_readv` peek was removed
    // along with the PAN workaround.
    if matches!(nr, 63 | 64) {
        let pid = addr_of!((*ev).pid).read_unaligned();
        let fd_nr = args[0] as u32;
        let watch_key = ((pid as u64) << 32) | fd_nr as u64;
        if let Some(tag_ptr) = WATCH_FDS.get_ptr(&watch_key) {
            // SAFETY: `tag_ptr` points to map memory; `u8` has alignment 1.
            let tag = core::ptr::read(tag_ptr);
            addr_of_mut!((*ev).ptr_hint).write_unaligned(args[1]);
            data_write_u8(ev, 8, tag);
        }
        return;
    }

    // mmap(222), mprotect(226): record RWX/WX prot marker at data[0].
    if matches!(nr, 222 | 226) {
        let prot = args[2];
        if (prot & 7) == 7 {
            data_write_u8(ev, 0, 1); // RWX
        } else if (prot & 6) == 6 {
            data_write_u8(ev, 0, 2); // WX without R
        }
    }
}

#[inline(always)]
fn capture_stack_ids(ctx: &TracePointContext) -> (i32, i32) {
    #[cfg(feature = "stacks")]
    unsafe {
        // Negative return is fine; the legacy wire format stores it as-is.
        // `get_stackid` invokes helper 27 and requires STACK_TRACES to exist
        // in the object, so keep the whole path behind the `stacks` feature.
        let kernel = match STACK_TRACES.get_stackid(ctx, 0) {
            Ok(id) => id as i32,
            Err(e) => {
                bump_counter(COUNTER_STACK_KERNEL_FAILED);
                e as i32
            }
        };
        let user = match STACK_TRACES.get_stackid(ctx, BPF_F_USER_STACK as u64) {
            Ok(id) => id as i32,
            Err(e) => {
                bump_counter(COUNTER_STACK_USER_FAILED);
                e as i32
            }
        };
        (kernel, user)
    }

    #[cfg(not(feature = "stacks"))]
    {
        let _ = ctx;
        (-1, -1)
    }
}

// ── Programs ─────────────────────────────────────────────────────────────────

#[tracepoint]
pub fn trace_sys_enter(ctx: TracePointContext) -> i32 {
    let _ = try_sys_enter(&ctx);
    0
}

#[inline(always)]
fn try_sys_enter(ctx: &TracePointContext) -> Result<(), ()> {
    // bpf_get_current_pid_tgid() = (kernel_tgid << 32) | kernel_pid, where
    // kernel_tgid = userspace process ID and kernel_pid = userspace thread ID.
    // The wire field naming is historically inverted (see SyscallEvent doc):
    // `ev.pid` carries the userspace PID (kernel TGID) so it matches `--pid`,
    // and `ev.tgid` carries the userspace TID. We keep that wire convention
    // but use accurate local names so the filter and event population are
    // self-documenting.
    let pid_tgid = bpf_get_current_pid_tgid();
    let userspace_pid = (pid_tgid >> 32) as u32; // kernel tgid
    let userspace_tid = pid_tgid as u32; // kernel pid

    if !pid_matches(userspace_pid) {
        return Err(());
    }
    mark_admitted_thread_enter(pid_tgid, userspace_pid);

    let nr = required_tracepoint_field!(ctx, i64, SYS_ENTER_ID) as i32;
    // A syscall rejected by the active whitelist can never pass the exit-side
    // emit gate either. Do not retain invisible state for it: a long-blocking
    // filtered syscall would otherwise be counted as lost evidence when a
    // scenario boundary drains INFLIGHT. Causal admission bookkeeping stays
    // above this gate so boundary-exit classification remains intact.
    if !syscall_allowed(nr) {
        return Err(());
    }
    let args = required_tracepoint_field!(ctx, [u64; 6], SYS_ENTER_ARGS);

    // Build the event on stack first — we need to (a) insert it into INFLIGHT
    // for sys_exit correlation, and (b) submit a copy through the ring buffer.
    // The redundant 257-byte copy into the ring entry is bounded and explicit.
    let mut ev_buf: MaybeUninit<AlignedEvent> = MaybeUninit::uninit();
    let ev = unsafe { addr_of_mut!((*ev_buf.as_mut_ptr()).event) };

    unsafe {
        zero_event(ev);
        let now = bpf_ktime_get_ns();
        addr_of_mut!((*ev).timestamp_ns).write_unaligned(now);
        addr_of_mut!((*ev).enter_timestamp_ns).write_unaligned(now);
        // Wire convention: ev.pid = userspace process ID; ev.tgid = userspace TID.
        addr_of_mut!((*ev).pid).write_unaligned(userspace_pid);
        addr_of_mut!((*ev).tgid).write_unaligned(userspace_tid);
        addr_of_mut!((*ev).uid).write_unaligned(bpf_get_current_uid_gid() as u32);
        addr_of_mut!((*ev).syscall_nr).write_unaligned(nr);
        addr_of_mut!((*ev).is_enter).write_unaligned(1);
        // ret, ptr_hint, maps_generation, and _reserved were zeroed by
        // `zero_event` above.

        // Read the six syscall args from the tracepoint context and stamp
        // them into the event in one packed write.
        addr_of_mut!((*ev).args).write_unaligned(args);

        // comm[16] — direct write from the helper-returned array.
        write_current_comm(ev);

        capture_syscall_data(ev, nr, &args);

        let (context, parent_debug_id, relation) = causal_context(pid_tgid, userspace_pid);
        if context.root_trace_id != 0 {
            stamp_causal(ev, context, parent_debug_id, relation);
        }

        let (kid, uid_stack) = capture_stack_ids(ctx);
        addr_of_mut!((*ev).kernel_stackid).write_unaligned(kid);
        addr_of_mut!((*ev).user_stackid).write_unaligned(uid_stack);

        // Insert into INFLIGHT keyed by the raw kernel pid_tgid (so per-thread
        // correlation works for binder/JIT/worker threads, not just the main
        // thread). sys_exit looks up the same key.
        //
        // Every allowlisted syscall gets INFLIGHT state: exit-time predicates
        // need it even when the ringbuf submission below is filtered. See
        // `should_submit_enter` for the predicate emit gate.
        if INFLIGHT.insert(&pid_tgid, &*ev, 0).is_err() {
            bump_counter(COUNTER_INFLIGHT_UPDATE_FAILED);
        }

        // Emit gate. Independent of INFLIGHT update: when this returns false,
        // the ringbuf submission is skipped but the INFLIGHT entry survives
        // for the matching sys_exit.
        let uid_field = addr_of!((*ev).uid).read_unaligned();
        if !should_submit_enter(nr, uid_field, ev) {
            return Ok(());
        }

        // Try to publish through the ring. If the ring is full, drop and
        // count it — the inflight entry survives so the exit event still
        // carries args/stack.
        if let Some(mut entry) = EVENTS.reserve::<SyscallEvent>(0) {
            // SAFETY: `as_mut_ptr` returns an 8-byte-aligned pointer to
            // uninitialized memory the kernel reserved for us. `SyscallEvent`
            // is `#[repr(C, packed)]` so we use `write_unaligned`.
            let dst: *mut SyscallEvent = entry.as_mut_ptr();
            copy_event(dst, ev);
            entry.submit(0);
            bump_counter(COUNTER_EVENTS_SUBMITTED);
        } else {
            bump_counter(COUNTER_RINGBUF_RESERVE_FAILED);
        }
    }
    Ok(())
}

#[tracepoint]
pub fn trace_sys_exit(ctx: TracePointContext) -> i32 {
    let _ = try_sys_exit(&ctx);
    0
}

#[inline(always)]
fn try_sys_exit(ctx: &TracePointContext) -> Result<(), ()> {
    // See `try_sys_enter` for the kernel/userspace pid/tgid naming inversion.
    let pid_tgid = bpf_get_current_pid_tgid();
    let userspace_pid = (pid_tgid >> 32) as u32; // kernel tgid
    let userspace_tid = pid_tgid as u32; // kernel pid

    if !pid_matches(userspace_pid) {
        return Err(());
    }

    let nr = match unsafe { ctx.read_at::<i64>(SYS_EXIT_ID) } {
        Ok(value) => value as i32,
        Err(_) => {
            bump_counter(COUNTER_TRACEPOINT_READ_FAILED);
            let _ = INFLIGHT.remove(&pid_tgid);
            return Err(());
        }
    };
    let ret = match unsafe { ctx.read_at::<i64>(SYS_EXIT_RET) } {
        Ok(value) => value,
        Err(_) => {
            bump_counter(COUNTER_TRACEPOINT_READ_FAILED);
            let _ = INFLIGHT.remove(&pid_tgid);
            return Err(());
        }
    };
    let now = unsafe { bpf_ktime_get_ns() };
    let uid_now = bpf_get_current_uid_gid() as u32;

    // Peek the saved INFLIGHT entry without removing it — the predicate
    // evaluator needs to read saved args (for ioctl-shape) and the saved
    // enter timestamp (for latency). The borrow is released before the
    // ringbuf reservation.
    let saved_ptr: *const SyscallEvent = INFLIGHT.get_ptr(&pid_tgid).unwrap_or_default();
    let direct_admission_boundary = consume_admission_boundary_exit(pid_tgid);
    let admission_boundary_exit = saved_ptr.is_null()
        && (direct_admission_boundary
            || consume_sibling_admission_boundary_exit(pid_tgid, userspace_pid));

    if !should_submit_exit(nr, uid_now, saved_ptr, ret, now) {
        // Reclaim the allowlisted INFLIGHT entry that enter-side predicates
        // retained for possible exit matching. Without this, predicate-
        // filtered syscalls would gradually exhaust map capacity and cause
        // update failures that hurt correlation.
        let _ = INFLIGHT.remove(&pid_tgid);
        return Err(());
    }

    // This path has enough other live locals that a full event would exceed
    // BPF's 512-byte stack. Use per-CPU map scratch, then copy into the ring.
    // In particular, do not memset a reserved ring entry directly: recent
    // LLVM BPF backends lower that to a BPF-to-BPF call carrying a ringbuf
    // reference, which Android 6.1 rejects.
    let ev = event_scratch().ok_or(())?;
    unsafe {
        zero_event(ev);
        addr_of_mut!((*ev).timestamp_ns).write_unaligned(now);
        addr_of_mut!((*ev).pid).write_unaligned(userspace_pid);
        addr_of_mut!((*ev).tgid).write_unaligned(userspace_tid);
        addr_of_mut!((*ev).uid).write_unaligned(bpf_get_current_uid_gid() as u32);
        addr_of_mut!((*ev).is_enter).write_unaligned(0);
        addr_of_mut!((*ev).ret).write_unaligned(ret);
        write_current_comm(ev);

        // Try to recover args + data + stack ids from the inflight entry.
        if let Some(saved) = INFLIGHT.get_ptr(&pid_tgid) {
            let saved_ts = addr_of!((*saved).timestamp_ns).read_unaligned();
            let saved_nr = addr_of!((*saved).syscall_nr).read_unaligned();
            let saved_kstack = addr_of!((*saved).kernel_stackid).read_unaligned();
            let saved_ustack = addr_of!((*saved).user_stackid).read_unaligned();
            let saved_ptr_hint = addr_of!((*saved).ptr_hint).read_unaligned();
            let saved_generation = addr_of!((*saved).maps_generation).read_unaligned();
            let saved_reserved = addr_of!((*saved)._reserved).read_unaligned();
            // Preserve all six syscall args verbatim — the previous wire
            // format hijacked args[5] for the enter timestamp, which clobbered
            // the legitimate 6th arg of mmap (offset), clone3, etc. The enter
            // timestamp now lives in its own `enter_timestamp_ns` field.
            let saved_args: [u64; 6] = addr_of!((*saved).args).read_unaligned();
            addr_of_mut!((*ev).args).write_unaligned(saved_args);
            addr_of_mut!((*ev).enter_timestamp_ns).write_unaligned(saved_ts);

            addr_of_mut!((*ev).syscall_nr).write_unaligned(saved_nr);
            addr_of_mut!((*ev).kernel_stackid).write_unaligned(saved_kstack);
            addr_of_mut!((*ev).user_stackid).write_unaligned(saved_ustack);
            addr_of_mut!((*ev).ptr_hint).write_unaligned(saved_ptr_hint);
            addr_of_mut!((*ev).maps_generation).write_unaligned(saved_generation);
            addr_of_mut!((*ev)._reserved).write_unaligned(saved_reserved);

            // Copy the 128-byte data buffer from inflight map memory via the
            // kernel-space helper for a guaranteed bounded copy with EFAULT
            // handling.
            let dst = data_slice(ev, 0, 128);
            if bpf_probe_read_kernel_buf(addr_of!((*saved).data) as *const u8, dst).is_err() {
                mark_payload_read_failed(ev);
                bump_counter(COUNTER_PAYLOAD_READ_FAILED);
            }

            let _ = INFLIGHT.remove(&pid_tgid);

            // ── Sprint-1 PR 2: post-exit refresh for whitelisted R/RW ioctls ──
            //
            // For ioctl families where the kernel writes back into the user
            // buffer (`DMA_HEAP_*`, `BINDER_*`, `DMA_BUF_*`, `ASHMEM_*` with
            // `_IOC_DIR ∈ {R,RW}`) the meaningful payload is post-call. The
            // enter capture above gave us pre-call bytes; we now overwrite
            // `data[4..128]` with the post-call user buffer so userspace
            // decoders see kernel-written fields like
            // `dma_heap_allocation_data.fd`.
            //
            // `data[0..4]` keeps the cmd word from enter — the userspace
            // formatter uses it to flip `"data_phase":"exit"` via the same
            // [`neutron_common::ioctl_post_exit_refresh`] predicate. The
            // user pointer was stashed on enter as `ptr_hint` and survived
            // through INFLIGHT.
            if saved_nr == 29 && saved_ptr_hint != 0 {
                // ioctl(2) ABI: args[1] = cmd. Use the saved value rather
                // than re-reading data[0..4] so we avoid additional pointer
                // arithmetic the verifier would have to track.
                let cmd = saved_args[1] as u32;
                let cmd_bytes = cmd.to_le_bytes();
                data_write_u8(ev, 0, cmd_bytes[0]);
                data_write_u8(ev, 1, cmd_bytes[1]);
                data_write_u8(ev, 2, cmd_bytes[2]);
                data_write_u8(ev, 3, cmd_bytes[3]);
                if ioctl_refresh_enabled(cmd) {
                    let len = bounded_ioctl_payload_len(cmd);
                    if len != 0 {
                        let dst = data_slice(ev, 4, len);
                        if capture_user_bytes(ev, saved_ptr_hint, dst) {
                            // Only advertise post-exit data after a successful
                            // bounded re-read. Failed reads leave the enter
                            // snapshot and globally degrade capture health.
                            reserved_write_u8(ev, 0, EVENT_FLAG_IOCTL_EXIT_REFRESHED);
                        }
                    }
                } else if neutron_common::ioctl_runtime_refresh_candidate(cmd) {
                    bump_counter(COUNTER_IOCTL_REFRESH_MISSED);
                }
            }
        } else {
            if admission_boundary_exit {
                bump_counter(COUNTER_CAUSAL_ADMISSION_BOUNDARY_EXIT);
            } else {
                bump_counter(COUNTER_INFLIGHT_LOOKUP_MISSED);
            }
            addr_of_mut!((*ev).syscall_nr).write_unaligned(nr);
            addr_of_mut!((*ev).kernel_stackid).write_unaligned(-1);
            addr_of_mut!((*ev).user_stackid).write_unaligned(-1);
            let (context, parent_debug_id, relation) = causal_context(pid_tgid, userspace_pid);
            if context.root_trace_id != 0 {
                stamp_causal(ev, context, parent_debug_id, relation);
            }
            // args / data / ptr_hint / enter_timestamp_ns are already zero.
            // Latency will resolve to None userspace-side.
        }

        if let Some(mut entry) = EVENTS.reserve::<SyscallEvent>(0) {
            let dst: *mut SyscallEvent = entry.as_mut_ptr();
            copy_event(dst, ev);
            entry.submit(0);
            bump_counter(COUNTER_EVENTS_SUBMITTED);
        } else {
            bump_counter(COUNTER_RINGBUF_RESERVE_FAILED);
        }
    }
    Ok(())
}

#[tracepoint]
pub fn trace_binder_transaction(ctx: TracePointContext) -> i32 {
    let _ = try_binder(&ctx);
    0
}

#[inline(always)]
fn try_binder(ctx: &TracePointContext) -> Result<(), ()> {
    // See `try_sys_enter` for the kernel/userspace pid/tgid naming inversion.
    let pid_tgid = bpf_get_current_pid_tgid();
    let userspace_pid = (pid_tgid >> 32) as u32; // kernel tgid
    let userspace_tid = pid_tgid as u32; // kernel pid

    if !pid_matches(userspace_pid) {
        return Err(());
    }

    // SAFETY: doctor validates these offsets against tracefs `format` before
    // attach. Runtime read failures discard the event and degrade health.
    let debug_id = required_tracepoint_field!(ctx, i32, BT_DEBUG_ID);
    let to_proc = required_tracepoint_field!(ctx, i32, BT_TO_PROC);
    let to_thread = required_tracepoint_field!(ctx, i32, BT_TO_THREAD);
    let reply = required_tracepoint_field!(ctx, i32, BT_REPLY);
    let code = required_tracepoint_field!(ctx, u32, BT_CODE);
    let flags = required_tracepoint_field!(ctx, u32, BT_FLAGS);
    let target_node = required_tracepoint_field!(ctx, i32, BT_TARGET_NODE);
    let now = unsafe { bpf_ktime_get_ns() };

    let (context, parent_debug_id, relation) = causal_context(pid_tgid, userspace_pid);
    let has_causal = context.root_trace_id != 0;
    let mut event_context = context;
    if reply == 0 {
        event_context.depth = event_context.depth.saturating_add(1);
        if has_causal {
            // This update intentionally precedes EVENTS.reserve/submit: the
            // callee can run immediately on another CPU after Binder wakes it.
            follow_binder_callee(
                context,
                userspace_pid,
                to_proc,
                debug_id,
                flags,
                parent_debug_id,
                relation,
            );
        }
    } else {
        // A synchronous reply is the reliable end boundary for the receiving
        // Binder thread's exact context.
        let _ = THREAD_BINDER_CONTEXT.remove(&pid_tgid);
    }

    let mut ev_buf: MaybeUninit<AlignedEvent> = MaybeUninit::uninit();
    let ev = unsafe { addr_of_mut!((*ev_buf.as_mut_ptr()).event) };
    unsafe {
        zero_event(ev);
        addr_of_mut!((*ev).timestamp_ns).write_unaligned(now);
        addr_of_mut!((*ev).pid).write_unaligned(userspace_pid);
        addr_of_mut!((*ev).tgid).write_unaligned(userspace_tid);
        addr_of_mut!((*ev).uid).write_unaligned(bpf_get_current_uid_gid() as u32);
        addr_of_mut!((*ev).syscall_nr).write_unaligned(-1); // sentinel
        addr_of_mut!((*ev).is_enter).write_unaligned(1);
        write_current_comm(ev);

        let args: [u64; 6] = [
            to_proc as u32 as u64,
            code as u64,
            flags as u64,
            to_thread as u32 as u64,
            reply as u32 as u64,
            target_node as u32 as u64,
        ];
        addr_of_mut!((*ev).args).write_unaligned(args);
        // Stash the binder transaction id in `ptr_hint` so the userspace
        // correlator can pair this caller event with the callee-side
        // `binder_transaction_received` (sprint-2 PR 2). Cast preserves bits;
        // userspace casts back to i32.
        addr_of_mut!((*ev).ptr_hint).write_unaligned(debug_id as u32 as u64);

        if has_causal {
            stamp_causal(ev, event_context, parent_debug_id, relation);
        }

        let (kid, uid_stack) = capture_stack_ids(ctx);
        addr_of_mut!((*ev).kernel_stackid).write_unaligned(kid);
        addr_of_mut!((*ev).user_stackid).write_unaligned(uid_stack);

        if let Some(mut entry) = EVENTS.reserve::<SyscallEvent>(0) {
            let dst: *mut SyscallEvent = entry.as_mut_ptr();
            copy_event(dst, ev);
            entry.submit(0);
            bump_counter(COUNTER_EVENTS_SUBMITTED);
        } else {
            bump_counter(COUNTER_RINGBUF_RESERVE_FAILED);
        }
    }
    Ok(())
}

// ── binder/binder_transaction_received (sprint-2 PR 2: causality) ────────────
//
// Callee-side companion of `binder_transaction`. Fires when the binder
// thread dequeues an inbound transaction. We stash the same `debug_id` in
// `ptr_hint` so the userspace correlator can match it to the caller-side
// event by ID. Comm/uid come from `bpf_get_current_*` (the receiving
// thread is a worker thread of the callee process).

#[tracepoint]
pub fn trace_binder_transaction_received(ctx: TracePointContext) -> i32 {
    let _ = try_binder_received(&ctx);
    0
}

#[inline(always)]
fn try_binder_received(ctx: &TracePointContext) -> Result<(), ()> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let userspace_pid = (pid_tgid >> 32) as u32;
    let userspace_tid = pid_tgid as u32;

    if !pid_matches(userspace_pid) {
        return Err(());
    }

    let debug_id = required_tracepoint_field!(ctx, i32, BTR_DEBUG_ID);
    let now = unsafe { bpf_ktime_get_ns() };
    let transaction = if debug_id == 0 {
        None
    } else {
        unsafe { BINDER_TRANSACTION_CONTEXT.get(&(debug_id as u32)) }.copied()
    };
    if debug_id != 0 {
        let _ = BINDER_TRANSACTION_CONTEXT.remove(&(debug_id as u32));
    }
    let transaction = transaction.filter(|context| active_causal_context_matches(context.process));
    if let Some(context) = transaction {
        if context.flags & 1 == 0 {
            let thread = BinderThreadContext {
                debug_id: debug_id as u32,
                scenario_generation: context.process.scenario_generation,
                depth: context.process.depth,
                admission_boundary: context.admission_boundary,
            };
            if THREAD_BINDER_CONTEXT.insert(&pid_tgid, &thread, 0).is_err() {
                bump_counter(COUNTER_THREAD_CONTEXT_UPDATE_FAILED);
            }
        } else {
            // One-way calls have no reply tracepoint to delimit execution.
            // Keep process-level context only, which syscalls label inferred.
            let _ = THREAD_BINDER_CONTEXT.remove(&pid_tgid);
        }
    }

    let mut ev_buf: MaybeUninit<AlignedEvent> = MaybeUninit::uninit();
    let ev = unsafe { addr_of_mut!((*ev_buf.as_mut_ptr()).event) };
    unsafe {
        zero_event(ev);
        addr_of_mut!((*ev).timestamp_ns).write_unaligned(now);
        addr_of_mut!((*ev).pid).write_unaligned(userspace_pid);
        addr_of_mut!((*ev).tgid).write_unaligned(userspace_tid);
        addr_of_mut!((*ev).uid).write_unaligned(bpf_get_current_uid_gid() as u32);
        addr_of_mut!((*ev).syscall_nr).write_unaligned(SYSCALL_NR_BINDER_RECEIVED);
        addr_of_mut!((*ev).is_enter).write_unaligned(1);
        write_current_comm(ev);
        addr_of_mut!((*ev).ptr_hint).write_unaligned(debug_id as u32 as u64);
        if let Some(context) = transaction {
            stamp_causal(
                ev,
                context.process,
                context.parent_debug_id,
                context.relation,
            );
        } else {
            let (context, parent_debug_id, relation) = causal_context(pid_tgid, userspace_pid);
            if context.root_trace_id != 0 {
                stamp_causal(ev, context, parent_debug_id, relation);
            }
        }
        // No useful args / stacks here — debug_id alone is the matching key.
        // Stack capture is skipped to keep this tracepoint cheap.
        addr_of_mut!((*ev).kernel_stackid).write_unaligned(-1);
        addr_of_mut!((*ev).user_stackid).write_unaligned(-1);

        if let Some(mut entry) = EVENTS.reserve::<SyscallEvent>(0) {
            let dst: *mut SyscallEvent = entry.as_mut_ptr();
            copy_event(dst, ev);
            entry.submit(0);
            bump_counter(COUNTER_EVENTS_SUBMITTED);
        } else {
            bump_counter(COUNTER_RINGBUF_RESERVE_FAILED);
        }
    }
    Ok(())
}

// ── sched/sched_process_exit (sprint-2 PR 1: crash correlation) ──────────────
//
// Tracepoint fires once per task termination — covers normal exit, fatal
// signals (SIGSEGV/SIGABRT/...), OOM kill, and SIGKILL. We emit a synthetic
// SyscallEvent with `syscall_nr == SYSCALL_NR_PROCESS_EXIT (-3)` so the
// existing wire/format pipeline carries it without a layout bump.
//
// Tracepoint format (kernel >= 4.x, stable):
//   common_header @ 0..8
//   field:char    comm[16];   offset:8;   size:16;
//   field:pid_t   pid;        offset:24;  size:4;   (kernel pid == userspace TID)
//   field:int     prio;       offset:28;  size:4;
//
// The tracepoint payload does NOT carry exit_code or signal — those live
// on `task_struct` and require BTF to read safely. We deliberately leave
// args[0..2] zero here; userspace logcat / tombstone watchers (sources
// 1 / 2) supply the signal info when they observe the same crash. The
// tracepoint event is the lookback synchronisation point: when userspace
// sees `nr == -3` it knows to dump the per-PID ring buffer.

#[tracepoint]
pub fn trace_sched_process_exit(ctx: TracePointContext) -> i32 {
    let _ = try_sched_process_exit(&ctx);
    0
}

#[inline(always)]
fn try_sched_process_exit(ctx: &TracePointContext) -> Result<(), ()> {
    // Use the tracepoint's own pid field rather than bpf_get_current_pid_tgid:
    // by the time the tracepoint fires the current task may already be in the
    // do_exit() teardown path and the helper's behaviour is well-defined but
    // returns the dying task — what we actually want for "who exited".
    let pid_tgid = bpf_get_current_pid_tgid();
    let userspace_pid = (pid_tgid >> 32) as u32;
    let userspace_tid = required_tracepoint_field!(ctx, i32, SCHED_EXIT_PID) as u32;

    // Same filter rules as the syscall path: respect `--pid` / whitelist so
    // we don't flood userspace with unrelated exits.
    if !pid_matches(userspace_pid) {
        return Err(());
    }

    let now = unsafe { bpf_ktime_get_ns() };
    let causal = causal_context(pid_tgid, userspace_pid);
    let _ = INFLIGHT.remove(&pid_tgid);
    let _ = THREAD_BINDER_CONTEXT.remove(&pid_tgid);
    let _ = ADMITTED_THREAD_ENTERS.remove(&pid_tgid);
    if userspace_tid != userspace_pid {
        return Ok(());
    }
    if target_pid() == Some(userspace_pid)
        && EXITED_TARGET_PIDS.insert(&userspace_pid, &1, 0).is_err()
    {
        bump_counter(COUNTER_INFLIGHT_UPDATE_FAILED);
    }
    let _ = TRACED_PROCESSES.remove(&userspace_pid);
    let _ = PID_WHITELIST.remove(&userspace_pid);

    let mut ev_buf: MaybeUninit<AlignedEvent> = MaybeUninit::uninit();
    let ev = unsafe { addr_of_mut!((*ev_buf.as_mut_ptr()).event) };
    unsafe {
        zero_event(ev);
        addr_of_mut!((*ev).timestamp_ns).write_unaligned(now);
        addr_of_mut!((*ev).pid).write_unaligned(userspace_pid);
        addr_of_mut!((*ev).tgid).write_unaligned(userspace_tid);
        addr_of_mut!((*ev).uid).write_unaligned(bpf_get_current_uid_gid() as u32);
        addr_of_mut!((*ev).syscall_nr).write_unaligned(SYSCALL_NR_PROCESS_EXIT);
        addr_of_mut!((*ev).is_enter).write_unaligned(1);

        // Prefer the tracepoint's comm field — it is captured at the moment
        // of exit and survives the dying-task race that bpf_get_current_comm
        // can lose. Fall back if the read fails.
        if let Ok(comm) = ctx.read_at::<[u8; 16]>(SCHED_EXIT_COMM) {
            addr_of_mut!((*ev).comm).write_unaligned(comm);
        } else {
            bump_counter(COUNTER_TRACEPOINT_READ_FAILED);
            write_current_comm(ev);
        }

        // args[0] = exit_code (TBD via task_struct BTF), args[1] = signal,
        // args[2] = ExitSource::Tracepoint discriminant. Userspace decoders
        // key off args[2] to attribute the source on the JSON line.
        // The event is already zeroed, so only the non-zero source slot needs
        // a write. Building a mostly-zero `[u64; 6]` makes LLVM emit memset.
        (addr_of_mut!((*ev).args) as *mut u64)
            .add(2)
            .write_unaligned(ExitSource::Tracepoint as u64);

        if causal.0.root_trace_id != 0 {
            stamp_causal(ev, causal.0, causal.1, causal.2);
        }

        let (kid, uid_stack) = capture_stack_ids(ctx);
        addr_of_mut!((*ev).kernel_stackid).write_unaligned(kid);
        addr_of_mut!((*ev).user_stackid).write_unaligned(uid_stack);

        if let Some(mut entry) = EVENTS.reserve::<SyscallEvent>(0) {
            let dst: *mut SyscallEvent = entry.as_mut_ptr();
            copy_event(dst, ev);
            entry.submit(0);
            bump_counter(COUNTER_EVENTS_SUBMITTED);
        } else {
            bump_counter(COUNTER_RINGBUF_RESERVE_FAILED);
        }
    }
    Ok(())
}

// Compile-time assertion duplicating the one in `neutron-common`, so a
// mismatch surfaces immediately when building the BPF crate too. Bump in
// lockstep when the wire format changes.
const _: () = assert!(size_of::<SyscallEvent>() == 257);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
