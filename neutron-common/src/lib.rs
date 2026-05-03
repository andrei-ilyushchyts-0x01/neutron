//! Shared types between the BPF kernel programs and the userspace loader.
//!
//! This crate is `no_std` so it compiles for both `bpfel-unknown-none` (BPF)
//! and `aarch64-unknown-linux-musl` (userspace).
#![no_std]

/// Syscall event emitted by the BPF programs into the perf ring buffer.
///
/// CRITICAL: layout must stay in sync with the map definitions in
/// `neutron-ebpf/src/main.rs` (inflight map value_size).
///
/// Naming convention (kernel vs userspace terminology):
/// - `pid` field holds the **userspace process ID** (kernel `tgid`). This is
///   the value `pidof <package>` returns and what the user passes via `--pid`.
/// - `tgid` field holds the **userspace thread ID** (kernel `pid`). Distinct
///   for every thread in a process. The naming is inverted from kernel
///   terminology for historical compatibility with the legacy v0.1.0 wire
///   format; do not flip without a coordinated wire bump.
///
/// `data[128]` is a union field interpreted by `syscall_nr`:
/// - File syscalls (56, 48, 79, 78, 43, 36, 35, 221, 281): NUL-terminated path
/// - ioctl (29): [0..4] = cmd (u32 LE), [4..128] = first 124 bytes of arg
/// - connect/bind/sendto (203, 200, 206): sockaddr struct
/// - mmap/mprotect (222, 226): [0] = RWX marker (1=RWX, 2=WX)
/// - binder tracepoint (syscall_nr == -1): not used
///
/// `enter_timestamp_ns` is set on every enter event and copied through the
/// `INFLIGHT` map onto exit events. Userspace computes latency as
/// `timestamp_ns - enter_timestamp_ns` for exit events. Binder events
/// (`syscall_nr == -1`) leave it zero.
///
/// `maps_generation` is reserved for the userspace symbolizer to stamp the
/// `/proc/<pid>/maps` snapshot generation that an event was resolved against.
/// The BPF programs leave it zero.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct SyscallEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub syscall_nr: i32,
    pub args: [u64; 6],
    pub ret: i64,
    pub is_enter: u8,
    pub comm: [u8; 16],
    pub data: [u8; 128],
    pub kernel_stackid: i32,
    pub user_stackid: i32,
    pub ptr_hint: u64,
    pub enter_timestamp_ns: u64,
    pub maps_generation: u16,
    pub _reserved: [u8; 6],
}

// Compile-time layout check. v1.0 wire format is 257 bytes:
// 241 (legacy v0.1.0 layout) + 8 (enter_timestamp_ns) + 2 (maps_generation)
// + 6 (reserved padding for the next single-field bump). Bumping requires
// updating `_SIZE_CHECK` here AND the duplicate assertion in
// `neutron-ebpf/src/main.rs`.
const _SIZE_CHECK: () = assert!(core::mem::size_of::<SyscallEvent>() == 257);

impl Default for SyscallEvent {
    fn default() -> Self {
        // SAFETY: all-zeros is valid for this packed struct of integers and byte arrays
        unsafe { core::mem::zeroed() }
    }
}

/// Keys for filter_map (BPF_MAP_TYPE_ARRAY, 2 entries)
pub const FILTER_KEY_PID: u32 = 0;
pub const FILTER_KEY_ACTIVE: u32 = 1;

/// Maximum number of stack frames stored per stack trace
pub const STACK_FRAMES: u32 = 127;

// ── Counter indices (COUNTERS BPF_MAP_TYPE_ARRAY, 16 slots) ──────────────────
//
// The loader and the BPF programs share these indices to surface degraded
// paths to the user via the capture summary at exit. Slot indices are stable
// — they may be added at the end but never reordered.

/// Number of events successfully submitted to the ring buffer.
pub const COUNTER_EVENTS_SUBMITTED: u32 = 0;
/// `EVENTS.reserve()` returned `None` (ring full). Event was dropped.
pub const COUNTER_RINGBUF_RESERVE_FAILED: u32 = 1;
/// `INFLIGHT.insert()` failed on enter — exit event will lack args/stack ids.
pub const COUNTER_INFLIGHT_UPDATE_FAILED: u32 = 2;
/// `INFLIGHT.get_ptr()` returned `None` on exit — args/data/stack lost.
pub const COUNTER_INFLIGHT_LOOKUP_MISSED: u32 = 3;
/// `bpf_get_stackid(BPF_F_USER_STACK)` returned an error.
pub const COUNTER_STACK_USER_FAILED: u32 = 4;
/// `bpf_get_stackid(0)` (kernel stack) returned an error.
pub const COUNTER_STACK_KERNEL_FAILED: u32 = 5;
/// `bpf_probe_read_user_str_bytes` returned an error — path/string capture lost.
pub const COUNTER_PATH_READ_FAILED: u32 = 6;
/// Path capture filled the whole `data[128]` buffer (no NUL seen).
pub const COUNTER_PATH_TRUNCATED: u32 = 7;
/// Userspace fd graph lookup miss (resolving via `/proc/<pid>/fd/<fd>`).
pub const COUNTER_FD_LOOKUP_MISSED: u32 = 8;
/// Userspace symbolizer failed to resolve a non-zero IP to a symbol.
pub const COUNTER_SYMBOLIZATION_FAILED: u32 = 9;

/// Number of slots in the COUNTERS map. New counters extend the tail; bumping
/// requires updating the `Array::with_max_entries(...)` size in BPF and the
/// label table in userspace.
pub const COUNTER_SLOT_COUNT: u32 = 16;
