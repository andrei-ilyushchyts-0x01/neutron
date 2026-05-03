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
    SyscallEvent, COUNTER_EVENTS_SUBMITTED, COUNTER_INFLIGHT_LOOKUP_MISSED,
    COUNTER_INFLIGHT_UPDATE_FAILED, COUNTER_RINGBUF_RESERVE_FAILED, COUNTER_SLOT_COUNT,
    COUNTER_STACK_KERNEL_FAILED, COUNTER_STACK_USER_FAILED, FILTER_KEY_ACTIVE, FILTER_KEY_PID,
};

// COUNTER_PATH_READ_FAILED and COUNTER_PATH_TRUNCATED slot indices are reserved
// in neutron-common but not yet incremented here — wiring per-call-site error
// inspection through `capture_syscall_data` adds branches to a verifier-hot
// path and is deferred to a follow-up. Userspace already knows about the slots.

// ── Maps ─────────────────────────────────────────────────────────────────────

/// `filter_map[FILTER_KEY_PID]`    = target PID (0 = all)
/// `filter_map[FILTER_KEY_ACTIVE]` = syscall filter active (0 = off, 1 = on)
#[map]
static FILTER_MAP: Array<u32> = Array::with_max_entries(2, 0);

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
const BT_TARGET_NODE: usize = 12;
const BT_TO_PROC: usize = 16;
const BT_TO_THREAD: usize = 20;
const BT_REPLY: usize = 24;
const BT_CODE: usize = 28;
const BT_FLAGS: usize = 32;

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
unsafe fn data_write_u8(ev: *mut SyscallEvent, off: usize, v: u8) {
    *data_ptr(ev, off) = v;
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
    //   size_t   msg_controllen  @ +40 (8)
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
            hdr_head[0], hdr_head[1], hdr_head[2], hdr_head[3],
            hdr_head[4], hdr_head[5], hdr_head[6], hdr_head[7],
        ]);
        let namelen = u32::from_le_bytes([hdr_head[8], hdr_head[9], hdr_head[10], hdr_head[11]]);
        if name_ptr != 0 && namelen >= 2 {
            // Constant 28 = max sockaddr_in6.
            let dst = data_slice(ev, 0, 28);
            let _ = bpf_probe_read_user_buf(name_ptr as *const u8, dst);
        }
        // Read msg_controllen (8B) into data[64..72].
        let dst_ctl = data_slice(ev, 64, 8);
        let _ = bpf_probe_read_user_buf((ptr + 40) as *const u8, dst_ctl);
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
    let userspace_tid = pid_tgid as u32;          // kernel pid

    if !pid_matches(userspace_pid) {
        return Err(());
    }

    let nr = match unsafe { ctx.read_at::<i64>(SYS_ENTER_ID) } {
        Ok(v) => v as i32,
        Err(_) => return Err(()),
    };

    if !syscall_allowed(nr) {
        return Err(());
    }

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
        if INFLIGHT.insert(&pid_tgid, &*ev, 0).is_err() {
            bump_counter(COUNTER_INFLIGHT_UPDATE_FAILED);
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
    let userspace_tid = pid_tgid as u32;          // kernel pid

    if !pid_matches(userspace_pid) {
        return Err(());
    }

    let nr = match unsafe { ctx.read_at::<i64>(SYS_EXIT_ID) } {
        Ok(v) => v as i32,
        Err(_) => return Err(()),
    };

    if !syscall_allowed(nr) {
        return Err(());
    }

    let ret = unsafe { ctx.read_at::<i64>(SYS_EXIT_RET) }.unwrap_or(0);
    let now = unsafe { bpf_ktime_get_ns() };

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
    let userspace_tid = pid_tgid as u32;          // kernel pid

    if !pid_matches(userspace_pid) {
        return Err(());
    }

    // Tracepoint fields. Failures default to 0 (the C version did the same via
    // `bpf_probe_read` into a zero-initialised local).
    // SAFETY: tracepoint layout fixed by the kernel; offsets from event format.
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

// Compile-time assertion duplicating the one in `neutron-common`, so a
// mismatch surfaces immediately when building the BPF crate too. Bump in
// lockstep when the wire format changes.
const _: () = assert!(size_of::<SyscallEvent>() == 257);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
