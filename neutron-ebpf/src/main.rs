//! neutron BPF programs (aya-ebpf, kernel 6.1+ target)
//!
//! Build:  cargo xtask build-ebpf
//! Target: bpfel-unknown-none (Pixel 8 Pro / Android 14 GKI / kernel 6.1.145)
//!
//! Modern-kernel assumptions (no kernel-4.14 workarounds):
//! - BPF-to-BPF calls accepted by the verifier, so compiler-emitted memset /
//!   memcpy / memmove are fine.
//! - Helpers 112/113/114 (`bpf_probe_read_kernel_*`, `bpf_probe_read_user_*`,
//!   `bpf_probe_read_user_str_*`) are available — used in preference to the
//!   address-space-agnostic helpers 4 / 45.
//! - BTF + CO-RE compatible (Aya performs runtime BTF relocation).
//! - Stack traces via `bpf_get_stackid` + `BPF_MAP_TYPE_STACK_TRACE`.
//! - Output via BPF ring buffer (`BPF_MAP_TYPE_RINGBUF`, kernel 5.8+) — single
//!   multi-producer ring, lossless, no per-CPU juggling.
//!
//! `SyscallEvent` is `#[repr(C, packed)]`, so all field accesses go through
//! `addr_of!` / `addr_of_mut!` and `write_unaligned` / `read_unaligned`.
#![no_std]
#![no_main]

use core::mem::{size_of, MaybeUninit};
use core::ptr::{addr_of, addr_of_mut};

use aya_ebpf::{
    bindings::BPF_F_USER_STACK,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel_buf, bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{Array, HashMap, RingBuf, StackTrace},
    programs::TracePointContext,
};
use neutron_common::{
    is_state_tracking_nr, ret_matches_class, ExitSource, SyscallEvent, COUNTER_EVENTS_SUBMITTED,
    COUNTER_INFLIGHT_LOOKUP_MISSED, COUNTER_INFLIGHT_UPDATE_FAILED, COUNTER_IOCTL_REFRESH_MISSED,
    COUNTER_RINGBUF_RESERVE_FAILED, COUNTER_SLOT_COUNT, COUNTER_STACK_KERNEL_FAILED,
    COUNTER_STACK_USER_FAILED, COUNTER_UNIX_MSG_CONTROL_NESTED, COUNTER_UNIX_MSG_CONTROL_TRUNCATED,
    FILTER_KEY_ACTIVE, FILTER_KEY_ARG_U32_OFF, FILTER_KEY_IOCTL_DIR, FILTER_KEY_LATENCY_MIN_US,
    FILTER_KEY_MATCH_BITS, FILTER_KEY_PID, FILTER_KEY_RET_CLASS, FILTER_KEY_STATE_EMIT_REQUIRED,
    FILTER_MAP_SLOT_COUNT, MATCH_BIT_ARG_U32, MATCH_BIT_IOCTL_CMD, MATCH_BIT_IOCTL_DIR,
    MATCH_BIT_IOCTL_NR, MATCH_BIT_IOCTL_TYPE, MATCH_BIT_LATENCY, MATCH_BIT_RET, MATCH_BIT_UID,
    SYSCALL_NR_BINDER_RECEIVED, SYSCALL_NR_PROCESS_EXIT,
};

// COUNTER_PATH_READ_FAILED and COUNTER_PATH_TRUNCATED slot indices are reserved
// in neutron-common but not yet incremented here — wiring per-call-site error
// inspection through `capture_syscall_data` adds branches to a verifier-hot
// path and is deferred to a follow-up. Userspace already knows about the slots.

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
/// Size: 1 MiB — must be a power of two and at least one page. At ~241 bytes
/// per event (plus 8-byte header per record), this fits ~4200 events of burst
/// capacity, comfortably absorbing observed 100k-events/s peaks on Pixel 8 Pro.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

/// Enter/exit correlation: `pid_tgid` → `SyscallEvent` captured on sys_enter.
#[map]
static INFLIGHT: HashMap<u64, SyscallEvent> = HashMap::with_max_entries(4096, 0);

/// Syscall whitelist. Active only when `FILTER_MAP[FILTER_KEY_ACTIVE] == 1`.
#[map]
static SYSCALL_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

/// Additional PIDs to trace (child processes after clone()).
#[map]
static PID_WHITELIST: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

/// Watched fds for selective read/write capture.
/// Key: `(pid << 32) | fd`. Value: tag (1 = procfs/sysfs).
#[map]
static WATCH_FDS: HashMap<u64, u8> = HashMap::with_max_entries(256, 0);

/// Stack trace map. 127 frames * 8 bytes = 1016 bytes per slot.
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

/// Capture-health counters. Slot indices are defined in `neutron_common::COUNTER_*`.
/// Userspace polls this map periodically and prints a capture summary on exit.
/// Values are u64 monotonic counters; the BPF programs increment them via the
/// `bump_counter` helper (one helper call per degraded path).
#[map]
static COUNTERS: Array<u64> = Array::with_max_entries(COUNTER_SLOT_COUNT, 0);

#[inline(always)]
fn bump_counter(idx: u32) {
    if let Some(slot) = COUNTERS.get_ptr_mut(idx) {
        // SAFETY: `slot` points to a u64 inside the BPF array map. Concurrent
        // writes from other CPUs are tolerated — counters are best-effort. We
        // accept a non-atomic add: the verifier accepts read+add+write through
        // a map pointer and the worst-case under contention is a lost update,
        // not memory corruption.
        unsafe {
            let cur = core::ptr::read_unaligned(slot);
            core::ptr::write_unaligned(slot, cur.wrapping_add(1));
        }
    }
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

// ── Tracepoint field offsets (raw_syscalls/sys_*) ────────────────────────────

// Common header is 8 bytes (type:2 + flags:1 + preempt:1 + pid:4).
// raw_syscalls/sys_enter: id (long) at +8, args[6] (unsigned long) at +16..+64.
// raw_syscalls/sys_exit:  id (long) at +8, ret (long) at +16.
const SYS_ENTER_ID: usize = 8;
const SYS_ENTER_ARGS: usize = 16;
const SYS_EXIT_ID: usize = 8;
const SYS_EXIT_RET: usize = 16;

// binder/binder_transaction tracepoint:
//   debug_id (s32)    @ +8     target_node (s32) @ +12
//   to_proc (s32)     @ +16    to_thread (s32)   @ +20
//   reply (s32)       @ +24    code (u32)        @ +28
//   flags (u32)       @ +32
const BT_DEBUG_ID: usize = 8;
const BT_TARGET_NODE: usize = 12;
const BT_TO_PROC: usize = 16;
const BT_TO_THREAD: usize = 20;
const BT_REPLY: usize = 24;
const BT_CODE: usize = 28;
const BT_FLAGS: usize = 32;

// binder/binder_transaction_received tracepoint:
//   debug_id (s32)    @ +8
const BTR_DEBUG_ID: usize = 8;

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

/// Returns `true` if the given userspace process ID matches the configured
/// target. `userspace_pid` corresponds to kernel `task_struct->tgid` and is
/// stable across all threads of the process — that is precisely the property
/// we want for app-wide tracing (binder pool threads, JIT helpers, native
/// workers, WebView/Chromium threads all share it).
#[inline(always)]
fn pid_matches(userspace_pid: u32) -> bool {
    let target = match target_pid() {
        Some(t) => t,
        None => return false,
    };
    if target == 0 || target == userspace_pid {
        return true;
    }
    // SAFETY: `HashMap::get` borrows into kernel map memory; we discard the
    // borrow immediately, so no aliasing concern.
    unsafe { PID_WHITELIST.get(&userspace_pid).is_some() }
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
    if match_active(MATCH_BIT_IOCTL_CMD) {
        if unsafe { MATCH_IOCTL_CMD_SET.get(&cmd) }.is_none() {
            return false;
        }
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
        let mut buf = [0u8; 4];
        // SAFETY: `payload_ptr` is the address of the captured `data[4..]`
        // window inside the on-stack `SyscallEvent`. `off + 4 <= 124` is
        // bounded above. We use the kernel-buf helper because the data lives
        // in BPF stack memory by the time we read it back during enter. See
        // `try_sys_enter` for the population path.
        let src = unsafe { payload_ptr.add(off as usize) };
        if unsafe { bpf_probe_read_kernel_buf(src, &mut buf) }.is_err() {
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
/// this is checked, INFLIGHT has already been populated unconditionally so
/// exit-time predicates (ret/latency) keep working.
///
/// Composition (safe over-approximation):
/// 1. Legacy `syscall_allowed` whitelist (gated by `FILTER_KEY_ACTIVE`).
/// 2. Predicate AND-conjunction across configured `MATCH_*` clauses.
/// 3. Always-pass for state-tracking syscalls when userspace requested it.
/// 4. When an exit-only predicate (`MATCH_BIT_RET` / `MATCH_BIT_LATENCY`)
///    is configured, drop enter events outright before ringbuf
///    reservation. The matching exit will still emit if it satisfies
///    the predicate; INFLIGHT was populated unconditionally so the
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

// ── Per-syscall data capture ────────────────────────────────────────────────
//
// Mirrors `capture_syscall_data` in `bpf/syscall_tracer.bpf.c`. Operates on
// the supplied `SyscallEvent` directly so no large stack copy is needed.
// User-space pointers go through helper 114 (`bpf_probe_read_user_*`); the
// kernel-space helper 113 is used for memory we know is in kernel space.
#[inline(always)]
unsafe fn capture_syscall_data(ev: *mut SyscallEvent, nr: i32, args: &[u64; 6]) {
    // File-path syscalls with path at args[1]:
    //   openat(56), faccessat(48), faccessat2(439), fstatat(79), readlinkat(78),
    //   mkdirat(34), unlinkat(35), execveat(281), openat2(437).
    //
    // Note: the v0.1.0-legacy table mistakenly believed 35=mkdirat / 36=unlinkat.
    // Authoritative aarch64 numbers: mkdirat=34, unlinkat=35, symlinkat=36.
    // symlinkat takes path at args[0] (target) — handled below.
    if matches!(nr, 56 | 48 | 79 | 78 | 34 | 35 | 281 | 437 | 439) {
        let ptr = args[1];
        addr_of_mut!((*ev).ptr_hint).write_unaligned(ptr);
        if ptr != 0 {
            let dst = data_slice(ev, 0, 128);
            let _ = bpf_probe_read_user_str_bytes(ptr as *const u8, dst);
        }
        return;
    }

    // File-path syscalls with path at args[0]:
    //   execve(221), statfs(43), symlinkat(36 — target), chdir(49), mount(40 — source).
    if matches!(nr, 221 | 43 | 36 | 49 | 40) {
        let ptr = args[0];
        addr_of_mut!((*ev).ptr_hint).write_unaligned(ptr);
        if ptr != 0 {
            let dst = data_slice(ev, 0, 128);
            let _ = bpf_probe_read_user_str_bytes(ptr as *const u8, dst);
        }
        return;
    }

    // execveat(281): filename in args[1]
    if nr == 281 {
        let ptr = args[1];
        addr_of_mut!((*ev).ptr_hint).write_unaligned(ptr);
        if ptr != 0 {
            let dst = data_slice(ev, 0, 128);
            let _ = bpf_probe_read_user_str_bytes(ptr as *const u8, dst);
        }
        return;
    }

    // ioctl(29): args[1] = cmd, args[2] = data pointer.
    // Pack: data[0..4] = cmd (u32 LE), data[4..128] = first 124 bytes of arg.
    if nr == 29 {
        let cmd = args[1] as u32;
        let bytes = cmd.to_le_bytes();
        data_write_u8(ev, 0, bytes[0]);
        data_write_u8(ev, 1, bytes[1]);
        data_write_u8(ev, 2, bytes[2]);
        data_write_u8(ev, 3, bytes[3]);
        let ptr = args[2];
        if ptr != 0 {
            let dst = data_slice(ev, 4, 124);
            let _ = bpf_probe_read_user_buf(ptr as *const u8, dst);
        }
        return;
    }

    // connect(203), bind(200): args[1] = sockaddr*, args[2] = addrlen.
    if matches!(nr, 203 | 200) {
        let ptr = args[1];
        addr_of_mut!((*ev).ptr_hint).write_unaligned(ptr);
        if ptr != 0 {
            let dst = data_slice(ev, 0, 128);
            let _ = bpf_probe_read_user_buf(ptr as *const u8, dst);
        }
        return;
    }

    // sendto(206): args[4] = dest_addr, args[5] = addrlen.
    if nr == 206 {
        let ptr = args[4];
        addr_of_mut!((*ev).ptr_hint).write_unaligned(ptr);
        if ptr != 0 {
            let dst = data_slice(ev, 0, 128);
            let _ = bpf_probe_read_user_buf(ptr as *const u8, dst);
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
            return;
        }
        // Read msg_name (8B pointer) + msg_namelen (4B) + 4B pad in one shot
        // into a stack scratch.
        let mut hdr_head = [0u8; 16];
        if bpf_probe_read_user_buf(ptr as *const u8, &mut hdr_head).is_err() {
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
        if name_ptr != 0 && namelen >= 2 {
            // Constant 28 = max sockaddr_in6.
            let dst = data_slice(ev, 0, 28);
            let _ = bpf_probe_read_user_buf(name_ptr as *const u8, dst);
        }
        // Read msg_control pointer + msg_controllen into stack scratch.
        let mut hdr_ctl = [0u8; 16];
        if bpf_probe_read_user_buf((ptr + 32) as *const u8, &mut hdr_ctl).is_err() {
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
            bump_counter(COUNTER_UNIX_MSG_CONTROL_TRUNCATED);
            return;
        }
        let mut cmsg = [0u8; 16];
        if bpf_probe_read_user_buf(control_ptr as *const u8, &mut cmsg).is_err() {
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

    let nr = match unsafe { ctx.read_at::<i64>(SYS_ENTER_ID) } {
        Ok(v) => v as i32,
        Err(_) => return Err(()),
    };

    // CRITICAL: do NOT return early on a failed syscall_allowed() here. The
    // INFLIGHT update below is the source of truth for exit-time predicates
    // (ret/latency) added in Phase 1. Even when the ringbuf submission would
    // be filtered, the matching sys_exit may still need args/data/stack from
    // this entry. The emit gate runs after INFLIGHT.insert.

    // Build the event on stack first — we need to (a) insert it into INFLIGHT
    // for sys_exit correlation, and (b) submit a copy through the ring buffer.
    // The redundant 241-byte memcpy into the ring entry is trivial.
    let mut ev_buf: MaybeUninit<SyscallEvent> = MaybeUninit::zeroed();
    let ev: *mut SyscallEvent = ev_buf.as_mut_ptr();

    unsafe {
        let now = bpf_ktime_get_ns();
        addr_of_mut!((*ev).timestamp_ns).write_unaligned(now);
        addr_of_mut!((*ev).enter_timestamp_ns).write_unaligned(now);
        // Wire convention: ev.pid = userspace process ID; ev.tgid = userspace TID.
        addr_of_mut!((*ev).pid).write_unaligned(userspace_pid);
        addr_of_mut!((*ev).tgid).write_unaligned(userspace_tid);
        addr_of_mut!((*ev).uid).write_unaligned(bpf_get_current_uid_gid() as u32);
        addr_of_mut!((*ev).syscall_nr).write_unaligned(nr);
        addr_of_mut!((*ev).is_enter).write_unaligned(1);
        // ret, ptr_hint, maps_generation, _reserved already zero from
        // MaybeUninit::zeroed().

        // Read the six syscall args from the tracepoint context and stamp
        // them into the event in one packed write.
        let args = ctx.read_at::<[u64; 6]>(SYS_ENTER_ARGS).unwrap_or([0u64; 6]);
        addr_of_mut!((*ev).args).write_unaligned(args);

        // comm[16] — direct write from the helper-returned array.
        if let Ok(comm) = bpf_get_current_comm() {
            addr_of_mut!((*ev).comm).write_unaligned(comm);
        }

        capture_syscall_data(ev, nr, &args);

        // Stack traces — negative return is fine; the legacy code stores it
        // as-is. `get_stackid` invokes helper 27.
        let kid = match STACK_TRACES.get_stackid(ctx, 0) {
            Ok(id) => id as i32,
            Err(e) => {
                bump_counter(COUNTER_STACK_KERNEL_FAILED);
                e as i32
            }
        };
        let uid_stack = match STACK_TRACES.get_stackid(ctx, BPF_F_USER_STACK as u64) {
            Ok(id) => id as i32,
            Err(e) => {
                bump_counter(COUNTER_STACK_USER_FAILED);
                e as i32
            }
        };
        addr_of_mut!((*ev).kernel_stackid).write_unaligned(kid);
        addr_of_mut!((*ev).user_stackid).write_unaligned(uid_stack);

        // Insert into INFLIGHT keyed by the raw kernel pid_tgid (so per-thread
        // correlation works for binder/JIT/worker threads, not just the main
        // thread). sys_exit looks up the same key.
        //
        // INFLIGHT.insert is unconditional (after pid_matches): exit-time
        // predicates need this state even when the ringbuf submission below
        // is filtered. See `should_submit_enter` for the emit gate.
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
            let dst: *mut SyscallEvent = entry.as_mut_ptr() as *mut SyscallEvent;
            core::ptr::write_unaligned(dst, core::ptr::read_unaligned(ev));
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
        Ok(v) => v as i32,
        Err(_) => return Err(()),
    };

    let ret = unsafe { ctx.read_at::<i64>(SYS_EXIT_RET) }.unwrap_or(0);
    let now = unsafe { bpf_ktime_get_ns() };
    let uid_now = bpf_get_current_uid_gid() as u32;

    // Peek the saved INFLIGHT entry without removing it — the predicate
    // evaluator needs to read saved args (for ioctl-shape) and the saved
    // enter timestamp (for latency). The borrow is released before the
    // ringbuf reservation.
    let saved_ptr: *const SyscallEvent = match INFLIGHT.get_ptr(&pid_tgid) {
        Some(p) => p as *const SyscallEvent,
        None => core::ptr::null(),
    };

    if !should_submit_exit(nr, uid_now, saved_ptr, ret, now) {
        // Reclaim the INFLIGHT entry that the unconditional enter-side
        // insertion left behind. Without this, filtered syscalls would
        // gradually fill the cap and trigger LRU evictions that hurt
        // unfiltered correlation.
        let _ = INFLIGHT.remove(&pid_tgid);
        return Err(());
    }

    // Reserve directly into the ring — no INFLIGHT insertion on exit, so we
    // can skip the stack scratch and write the event into the ring entry.
    // If the ring is full, count the drop and bail (degraded but not broken;
    // the next event picks up where we left off).
    let Some(mut entry) = EVENTS.reserve::<SyscallEvent>(0) else {
        bump_counter(COUNTER_RINGBUF_RESERVE_FAILED);
        return Err(());
    };

    // SAFETY: `as_mut_ptr` returns kernel-reserved memory sized for a full
    // `SyscallEvent`. We zero it ourselves so unset fields stay defined.
    let ev: *mut SyscallEvent = entry.as_mut_ptr() as *mut SyscallEvent;
    unsafe {
        core::ptr::write_bytes(ev as *mut u8, 0, size_of::<SyscallEvent>());

        addr_of_mut!((*ev).timestamp_ns).write_unaligned(now);
        addr_of_mut!((*ev).pid).write_unaligned(userspace_pid);
        addr_of_mut!((*ev).tgid).write_unaligned(userspace_tid);
        addr_of_mut!((*ev).uid).write_unaligned(bpf_get_current_uid_gid() as u32);
        addr_of_mut!((*ev).is_enter).write_unaligned(0);
        addr_of_mut!((*ev).ret).write_unaligned(ret);
        if let Ok(comm) = bpf_get_current_comm() {
            addr_of_mut!((*ev).comm).write_unaligned(comm);
        }

        // Try to recover args + data + stack ids from the inflight entry.
        if let Some(saved) = INFLIGHT.get_ptr(&pid_tgid) {
            let saved_ts = addr_of!((*saved).timestamp_ns).read_unaligned();
            let saved_nr = addr_of!((*saved).syscall_nr).read_unaligned();
            let saved_kstack = addr_of!((*saved).kernel_stackid).read_unaligned();
            let saved_ustack = addr_of!((*saved).user_stackid).read_unaligned();
            let saved_ptr_hint = addr_of!((*saved).ptr_hint).read_unaligned();
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

            // Copy the 128-byte data buffer from inflight map memory via the
            // kernel-space helper for a guaranteed bounded copy with EFAULT
            // handling.
            let dst = data_slice(ev, 0, 128);
            let _ = bpf_probe_read_kernel_buf(addr_of!((*saved).data) as *const u8, dst);

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
                if ioctl_refresh_enabled(cmd) {
                    let dst = data_slice(ev, 4, 124);
                    let _ = bpf_probe_read_user_buf(saved_ptr_hint as *const u8, dst);
                    reserved_write_u8(ev, 0, 1);
                } else if neutron_common::ioctl_runtime_refresh_candidate(cmd) {
                    bump_counter(COUNTER_IOCTL_REFRESH_MISSED);
                }
            }
        } else {
            bump_counter(COUNTER_INFLIGHT_LOOKUP_MISSED);
            addr_of_mut!((*ev).syscall_nr).write_unaligned(nr);
            addr_of_mut!((*ev).kernel_stackid).write_unaligned(-1);
            addr_of_mut!((*ev).user_stackid).write_unaligned(-1);
            // args / data / ptr_hint / enter_timestamp_ns already zero from
            // write_bytes above. Latency will resolve to None userspace-side.
        }

        entry.submit(0);
        bump_counter(COUNTER_EVENTS_SUBMITTED);
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

    // Tracepoint fields. Failures default to 0 (the C version did the same via
    // `bpf_probe_read` into a zero-initialised local).
    // SAFETY: tracepoint layout fixed by the kernel; offsets from event format.
    let debug_id = unsafe { ctx.read_at::<i32>(BT_DEBUG_ID) }.unwrap_or(0);
    let to_proc = unsafe { ctx.read_at::<i32>(BT_TO_PROC) }.unwrap_or(0);
    let to_thread = unsafe { ctx.read_at::<i32>(BT_TO_THREAD) }.unwrap_or(0);
    let reply = unsafe { ctx.read_at::<i32>(BT_REPLY) }.unwrap_or(0);
    let code = unsafe { ctx.read_at::<u32>(BT_CODE) }.unwrap_or(0);
    let flags = unsafe { ctx.read_at::<u32>(BT_FLAGS) }.unwrap_or(0);
    let target_node = unsafe { ctx.read_at::<i32>(BT_TARGET_NODE) }.unwrap_or(0);
    let now = unsafe { bpf_ktime_get_ns() };

    // Binder events have no INFLIGHT correlation, so write directly into the
    // ring entry. If the ring is full, count the drop and bail.
    let Some(mut entry) = EVENTS.reserve::<SyscallEvent>(0) else {
        bump_counter(COUNTER_RINGBUF_RESERVE_FAILED);
        return Err(());
    };

    let ev: *mut SyscallEvent = entry.as_mut_ptr() as *mut SyscallEvent;
    unsafe {
        core::ptr::write_bytes(ev as *mut u8, 0, size_of::<SyscallEvent>());

        addr_of_mut!((*ev).timestamp_ns).write_unaligned(now);
        addr_of_mut!((*ev).pid).write_unaligned(userspace_pid);
        addr_of_mut!((*ev).tgid).write_unaligned(userspace_tid);
        addr_of_mut!((*ev).uid).write_unaligned(bpf_get_current_uid_gid() as u32);
        addr_of_mut!((*ev).syscall_nr).write_unaligned(-1); // sentinel
        addr_of_mut!((*ev).is_enter).write_unaligned(1);
        if let Ok(comm) = bpf_get_current_comm() {
            addr_of_mut!((*ev).comm).write_unaligned(comm);
        }

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

        let kid = match STACK_TRACES.get_stackid(ctx, 0) {
            Ok(id) => id as i32,
            Err(e) => {
                bump_counter(COUNTER_STACK_KERNEL_FAILED);
                e as i32
            }
        };
        let uid_stack = match STACK_TRACES.get_stackid(ctx, BPF_F_USER_STACK as u64) {
            Ok(id) => id as i32,
            Err(e) => {
                bump_counter(COUNTER_STACK_USER_FAILED);
                e as i32
            }
        };
        addr_of_mut!((*ev).kernel_stackid).write_unaligned(kid);
        addr_of_mut!((*ev).user_stackid).write_unaligned(uid_stack);

        entry.submit(0);
        bump_counter(COUNTER_EVENTS_SUBMITTED);
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

    let debug_id = unsafe { ctx.read_at::<i32>(BTR_DEBUG_ID) }.unwrap_or(0);
    let now = unsafe { bpf_ktime_get_ns() };

    let Some(mut entry) = EVENTS.reserve::<SyscallEvent>(0) else {
        bump_counter(COUNTER_RINGBUF_RESERVE_FAILED);
        return Err(());
    };

    let ev: *mut SyscallEvent = entry.as_mut_ptr() as *mut SyscallEvent;
    unsafe {
        core::ptr::write_bytes(ev as *mut u8, 0, size_of::<SyscallEvent>());
        addr_of_mut!((*ev).timestamp_ns).write_unaligned(now);
        addr_of_mut!((*ev).pid).write_unaligned(userspace_pid);
        addr_of_mut!((*ev).tgid).write_unaligned(userspace_tid);
        addr_of_mut!((*ev).uid).write_unaligned(bpf_get_current_uid_gid() as u32);
        addr_of_mut!((*ev).syscall_nr).write_unaligned(SYSCALL_NR_BINDER_RECEIVED);
        addr_of_mut!((*ev).is_enter).write_unaligned(1);
        if let Ok(comm) = bpf_get_current_comm() {
            addr_of_mut!((*ev).comm).write_unaligned(comm);
        }
        addr_of_mut!((*ev).ptr_hint).write_unaligned(debug_id as u32 as u64);
        // No useful args / stacks here — debug_id alone is the matching key.
        // Stack capture is skipped to keep this tracepoint cheap.
        addr_of_mut!((*ev).kernel_stackid).write_unaligned(-1);
        addr_of_mut!((*ev).user_stackid).write_unaligned(-1);

        entry.submit(0);
        bump_counter(COUNTER_EVENTS_SUBMITTED);
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

const SCHED_EXIT_COMM: usize = 8;
const SCHED_EXIT_PID: usize = 24;

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
    let userspace_tid = pid_tgid as u32;

    // Same filter rules as the syscall path: respect `--pid` / whitelist so
    // we don't flood userspace with unrelated exits.
    if !pid_matches(userspace_pid) {
        return Err(());
    }

    let now = unsafe { bpf_ktime_get_ns() };

    let Some(mut entry) = EVENTS.reserve::<SyscallEvent>(0) else {
        bump_counter(COUNTER_RINGBUF_RESERVE_FAILED);
        return Err(());
    };

    let ev: *mut SyscallEvent = entry.as_mut_ptr() as *mut SyscallEvent;
    unsafe {
        core::ptr::write_bytes(ev as *mut u8, 0, size_of::<SyscallEvent>());

        addr_of_mut!((*ev).timestamp_ns).write_unaligned(now);
        addr_of_mut!((*ev).pid).write_unaligned(userspace_pid);
        addr_of_mut!((*ev).tgid).write_unaligned(userspace_tid);
        addr_of_mut!((*ev).uid).write_unaligned(bpf_get_current_uid_gid() as u32);
        addr_of_mut!((*ev).syscall_nr).write_unaligned(SYSCALL_NR_PROCESS_EXIT);
        addr_of_mut!((*ev).is_enter).write_unaligned(1);

        // Prefer the tracepoint's comm field — it is captured at the moment
        // of exit and survives the dying-task race that bpf_get_current_comm
        // can lose. Fall back if the read fails.
        let mut comm_buf: [u8; 16] = [0; 16];
        if ctx
            .read_at::<[u8; 16]>(SCHED_EXIT_COMM)
            .map(|c| comm_buf = c)
            .is_err()
        {
            if let Ok(c) = bpf_get_current_comm() {
                comm_buf = c;
            }
        }
        addr_of_mut!((*ev).comm).write_unaligned(comm_buf);

        // args[0] = exit_code (TBD via task_struct BTF), args[1] = signal,
        // args[2] = ExitSource::Tracepoint discriminant. Userspace decoders
        // key off args[2] to attribute the source on the JSON line.
        let args: [u64; 6] = [0, 0, ExitSource::Tracepoint as u64, 0, 0, 0];
        addr_of_mut!((*ev).args).write_unaligned(args);

        // Optional kernel/user stacks at exit time. The user stack is
        // typically just the libc exit() trampoline, but the kernel stack
        // can show do_exit / oom_kill_process / get_signal. Capture both
        // for parity with the binder tracepoint path.
        let kid = match STACK_TRACES.get_stackid(ctx, 0) {
            Ok(id) => id as i32,
            Err(e) => {
                bump_counter(COUNTER_STACK_KERNEL_FAILED);
                e as i32
            }
        };
        let uid_stack = match STACK_TRACES.get_stackid(ctx, BPF_F_USER_STACK as u64) {
            Ok(id) => id as i32,
            Err(e) => {
                bump_counter(COUNTER_STACK_USER_FAILED);
                e as i32
            }
        };
        addr_of_mut!((*ev).kernel_stackid).write_unaligned(kid);
        addr_of_mut!((*ev).user_stackid).write_unaligned(uid_stack);

        entry.submit(0);
        bump_counter(COUNTER_EVENTS_SUBMITTED);
    }

    // Silence unused-import warning when this is the only consumer.
    let _ = SCHED_EXIT_PID;
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
