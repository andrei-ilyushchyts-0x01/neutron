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

// ── ioctl post-exit refresh policy ───────────────────────────────────────────
//
// For ioctls in the "R" or "RW" direction (kernel writes back into the user
// buffer), the meaningful payload is post-call. The BPF programs always
// capture the enter-time bytes; for whitelisted families they ALSO re-read
// `args[2]` on `sys_exit`, overwriting `data[4..128]` with the post-call
// contents. Userspace mirrors the same predicate to set
// `"data_phase":"exit"` on the JSON line.
//
// CRITICAL: this policy is shared between the BPF programs and the userspace
// loader. A change must update both consumers atomically — that's exactly
// why it lives here in `neutron-common`.

/// `_IOC` direction value: kernel writes (Read from userspace's perspective).
pub const IOCTL_DIR_R: u32 = 2;
/// `_IOC` direction value: bidirectional. Kernel both reads and writes.
pub const IOCTL_DIR_RW: u32 = 3;

/// `_IOC_TYPE` byte for `/dev/dma_heap/*` ioctls (`'H'`). The dma-heap
/// allocator writes the new fd back into `dma_heap_allocation_data.fd`,
/// which only becomes meaningful post-call.
pub const IOCTL_TYPE_DMA_HEAP: u32 = 0x48;
/// `_IOC_TYPE` byte for both `binder` and `dma-buf` ioctls (`'b'`). The
/// kernel headers reuse the same magic; the userspace decoder disambiguates
/// via the FD-graph kind. The post-exit refresh fires for either, since
/// `BINDER_WRITE_READ` and several `dma-buf` commands write back state.
pub const IOCTL_TYPE_BINDER_OR_DMA_BUF: u32 = 0x62;
/// `_IOC_TYPE` byte for `/dev/ashmem` ioctls (`'w'`).
pub const IOCTL_TYPE_ASHMEM: u32 = 0x77;

/// Extracts the `_IOC_DIR` field (top two bits) from an ioctl `cmd`.
#[inline]
pub const fn ioctl_dir(cmd: u32) -> u32 {
    (cmd >> 30) & 0x3
}

/// Extracts the `_IOC_TYPE` byte (bits 8..16) from an ioctl `cmd`.
#[inline]
pub const fn ioctl_type(cmd: u32) -> u32 {
    (cmd >> 8) & 0xff
}

/// Returns `true` when a `sys_exit` event for this ioctl should overwrite
/// `data[4..128]` with the post-call user buffer. Both the BPF re-read and
/// the userspace `"data_phase":"exit"` flag key off this single predicate.
///
/// Whitelist:
/// - direction must be `R` or `RW` (kernel writes back to the user buffer);
/// - type must be one of the families the userspace decoder understands
///   (`dma_heap`, `binder`/`dma_buf`, `ashmem`).
#[inline]
pub const fn ioctl_post_exit_refresh(cmd: u32) -> bool {
    let dir = ioctl_dir(cmd);
    let ty = ioctl_type(cmd);
    (dir == IOCTL_DIR_R || dir == IOCTL_DIR_RW)
        && (ty == IOCTL_TYPE_DMA_HEAP
            || ty == IOCTL_TYPE_BINDER_OR_DMA_BUF
            || ty == IOCTL_TYPE_ASHMEM)
}

#[cfg(test)]
mod ioctl_policy_tests {
    use super::*;

    /// Encodes a `_IOC(dir, type, nr, size)` command word the way the kernel
    /// macros do (dir = top 2 bits, size = bits 16..30, type = bits 8..16,
    /// nr = bits 0..8). Test-only helper — production code receives `cmd`
    /// from the kernel already encoded.
    fn ioc(dir: u32, ty: u32, nr: u32, size: u32) -> u32 {
        ((dir & 0x3) << 30) | ((size & 0x3fff) << 16) | ((ty & 0xff) << 8) | (nr & 0xff)
    }

    #[test]
    fn ioctl_dir_extracts_top_two_bits() {
        assert_eq!(ioctl_dir(ioc(IOCTL_DIR_R, 0x48, 0, 24)), IOCTL_DIR_R);
        assert_eq!(ioctl_dir(ioc(IOCTL_DIR_RW, 0x48, 0, 24)), IOCTL_DIR_RW);
        assert_eq!(ioctl_dir(ioc(0, 0x48, 0, 24)), 0);
        assert_eq!(ioctl_dir(ioc(1, 0x48, 0, 24)), 1);
    }

    #[test]
    fn ioctl_type_extracts_byte_one() {
        assert_eq!(
            ioctl_type(ioc(IOCTL_DIR_RW, IOCTL_TYPE_DMA_HEAP, 0, 24)),
            IOCTL_TYPE_DMA_HEAP
        );
        assert_eq!(
            ioctl_type(ioc(IOCTL_DIR_RW, IOCTL_TYPE_BINDER_OR_DMA_BUF, 1, 48)),
            IOCTL_TYPE_BINDER_OR_DMA_BUF
        );
    }

    #[test]
    fn dma_heap_alloc_is_a_refresh_target() {
        // DMA_HEAP_IOCTL_ALLOC = _IOWR('H', 0x0, struct dma_heap_allocation_data) (24 bytes)
        let cmd = ioc(IOCTL_DIR_RW, IOCTL_TYPE_DMA_HEAP, 0, 24);
        assert!(ioctl_post_exit_refresh(cmd));
    }

    #[test]
    fn binder_write_read_is_a_refresh_target() {
        // BINDER_WRITE_READ = _IOWR('b', 1, struct binder_write_read) (48 bytes on aarch64)
        let cmd = ioc(IOCTL_DIR_RW, IOCTL_TYPE_BINDER_OR_DMA_BUF, 1, 48);
        assert!(ioctl_post_exit_refresh(cmd));
    }

    #[test]
    fn write_only_command_is_not_refreshed() {
        // _IOW means the kernel only reads the user buffer — no post-call data.
        let cmd = ioc(1, IOCTL_TYPE_BINDER_OR_DMA_BUF, 1, 32);
        assert!(!ioctl_post_exit_refresh(cmd));
    }

    #[test]
    fn unknown_type_is_not_refreshed() {
        let cmd = ioc(IOCTL_DIR_RW, 0xab, 5, 8);
        assert!(!ioctl_post_exit_refresh(cmd));
    }
}
