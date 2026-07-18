//! Shared types between the BPF kernel programs and the userspace loader.
//!
//! This crate is `no_std` so it compiles for both `bpfel-unknown-none` (BPF)
//! and `aarch64-unknown-linux-musl` (userspace).
#![no_std]

/// Syscall event emitted by the BPF programs into the BPF ring buffer.
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
/// `maps_generation` carries the live causal scenario generation in 1.3 and
/// is copied from syscall enter to exit. Zero means no active scenario.
/// `_reserved[0]` is a bit field: bit 0 marks a successful ioctl exit refresh
/// and bit 1 marks an event whose bounded payload read failed. Bytes 1..4
/// carry the causal parent Binder debug ID and byte 5 carries relation/depth.
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

pub const EVENT_FLAG_IOCTL_EXIT_REFRESHED: u8 = 1 << 0;
pub const EVENT_FLAG_PAYLOAD_READ_FAILED: u8 = 1 << 1;
pub const EVENT_FLAG_PAYLOAD_UNAVAILABLE: u8 = 1 << 2;

/// Return the syscall argument index containing a pathname captured in
/// [`SyscallEvent::data`]. Shared by the BPF producer and userspace decoder so
/// positive path evidence cannot be captured and then silently discarded.
pub const fn syscall_path_arg_index(syscall_nr: i32) -> Option<usize> {
    match syscall_nr {
        // aarch64: path in args[1]
        34 | 35 | 48 | 56 | 78 | 79 | 281 | 437 | 439 => Some(1),
        // aarch64: path in args[0]
        36 | 40 | 43 | 49 | 221 => Some(0),
        _ => None,
    }
}

#[inline]
pub fn event_ioctl_exit_refreshed(event: &SyscallEvent) -> bool {
    let reserved = event._reserved;
    reserved[0] & EVENT_FLAG_IOCTL_EXIT_REFRESHED != 0
}

#[inline]
pub fn event_payload_read_failed(event: &SyscallEvent) -> bool {
    let reserved = event._reserved;
    reserved[0] & EVENT_FLAG_PAYLOAD_READ_FAILED != 0
}

#[inline]
pub fn event_payload_unavailable(event: &SyscallEvent) -> bool {
    let reserved = event._reserved;
    reserved[0] & EVENT_FLAG_PAYLOAD_UNAVAILABLE != 0
}

#[inline]
pub fn event_payload_is_valid(event: &SyscallEvent) -> bool {
    !event_payload_read_failed(event) && !event_payload_unavailable(event)
}

// ── Causal tracing (1.3) ───────────────────────────────────────────────────

/// Why a process entered the dynamic causal trace set.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TraceReason {
    #[default]
    Root = 1,
    Binder = 2,
    Service = 3,
    Hal = 4,
}

/// BPF-side context for a process in the dynamic causal trace set.
///
/// Packed layout avoids implicit padding so userspace can populate the Aya map
/// as a `[u8; PROCESS_TRACE_CONTEXT_SIZE]` without adding a shared dependency.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessTraceContext {
    pub root_trace_id: u64,
    pub parent_pid: u32,
    pub binder_debug_id: u32,
    pub depth: u8,
    pub reason: TraceReason,
    pub scenario_generation: u16,
}

pub const PROCESS_TRACE_CONTEXT_SIZE: usize = core::mem::size_of::<ProcessTraceContext>();
const _: () = assert!(PROCESS_TRACE_CONTEXT_SIZE == 20);

/// `_reserved[5]` low bits. Zero means the event has no causal relation.
pub const CAUSAL_RELATION_EXACT: u8 = 1;
pub const CAUSAL_RELATION_INFERRED: u8 = 2;

/// Keep relation in the documented low bits and use the otherwise-unused high
/// bits for depth. This preserves the 257-byte event wire layout.
#[inline]
pub const fn encode_causal_relation_depth(relation: u8, depth: u8) -> u8 {
    let depth = if depth > 63 { 63 } else { depth };
    (relation & 0x03) | (depth << 2)
}

#[inline]
pub const fn decode_causal_relation(value: u8) -> u8 {
    value & 0x03
}

#[inline]
pub const fn decode_causal_depth(value: u8) -> u8 {
    value >> 2
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

// ── Userspace/eBPF ABI metadata ─────────────────────────────────────────────

/// ELF section containing the fixed-width [`BpfAbiMetadata`] encoding.
pub const BPF_ABI_SECTION_NAME: &str = ".neutron_abi";

/// Little-endian `NEUTRON\0`, used to reject unrelated or corrupt sections.
pub const BPF_ABI_MAGIC: u64 = u64::from_le_bytes(*b"NEUTRON\0");
/// Breaking ABI generation. A mismatch must be rejected before BPF load or
/// tracepoint attachment.
pub const BPF_ABI_MAJOR: u16 = 2;
/// Backward-compatible ABI revision within [`BPF_ABI_MAJOR`].
pub const BPF_ABI_MINOR: u16 = 0;

/// The object contains the raw syscall enter/exit programs and event stream.
pub const BPF_FEATURE_SYSCALL_TRACE: u64 = 1 << 0;
/// The object contains both Binder transaction tracepoint programs.
pub const BPF_FEATURE_BINDER_TRACE: u64 = 1 << 1;
/// Capture-health counters use a per-CPU array and require aggregation.
pub const BPF_FEATURE_PER_CPU_HEALTH: u64 = 1 << 2;
/// The object contains the optional kernel/user stack trace map and helpers.
pub const BPF_FEATURE_STACKS: u64 = 1 << 3;
/// The object contains the sched_process_exit causal sentinel program.
pub const BPF_FEATURE_PROCESS_EXIT: u64 = 1 << 4;

/// Fixed wire size of the custom ELF metadata section. The encoding is
/// deliberately independent of Rust struct padding and always little-endian.
pub const BPF_ABI_ENCODED_SIZE: usize = 44;

/// Metadata compiled into every supported Neutron BPF object.
///
/// The Rust representation is never copied directly into the object. Use
/// [`BpfAbiMetadata::encode`] and [`BpfAbiMetadata::decode`] at object
/// boundaries so compiler padding cannot become part of the wire contract.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfAbiMetadata {
    pub magic: u64,
    pub abi_major: u16,
    pub abi_minor: u16,
    pub syscall_event_size: u32,
    pub feature_bits: u64,
    pub build_id: [u8; 20],
}

impl BpfAbiMetadata {
    /// Encode metadata for the `.neutron_abi` ELF section.
    pub const fn encode(self) -> [u8; BPF_ABI_ENCODED_SIZE] {
        let mut out = [0u8; BPF_ABI_ENCODED_SIZE];
        copy_abi_bytes(&mut out, 0, self.magic.to_le_bytes());
        copy_abi_bytes(&mut out, 8, self.abi_major.to_le_bytes());
        copy_abi_bytes(&mut out, 10, self.abi_minor.to_le_bytes());
        copy_abi_bytes(&mut out, 12, self.syscall_event_size.to_le_bytes());
        copy_abi_bytes(&mut out, 16, self.feature_bits.to_le_bytes());
        copy_abi_bytes(&mut out, 24, self.build_id);
        out
    }

    /// Decode and authenticate the fixed-width little-endian metadata block.
    pub fn decode(bytes: &[u8]) -> Result<Self, BpfAbiError> {
        if bytes.is_empty() {
            return Err(BpfAbiError::MissingMetadata);
        }
        if bytes.len() < BPF_ABI_ENCODED_SIZE {
            return Err(BpfAbiError::TruncatedMetadata {
                expected: BPF_ABI_ENCODED_SIZE,
                actual: bytes.len(),
            });
        }

        let magic = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        if magic != BPF_ABI_MAGIC {
            return Err(BpfAbiError::InvalidMagic {
                expected: BPF_ABI_MAGIC,
                actual: magic,
            });
        }
        let abi_major = u16::from_le_bytes([bytes[8], bytes[9]]);
        let abi_minor = u16::from_le_bytes([bytes[10], bytes[11]]);
        let syscall_event_size = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let feature_bits = u64::from_le_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        let mut build_id = [0u8; 20];
        build_id.copy_from_slice(&bytes[24..44]);
        Ok(Self {
            magic,
            abi_major,
            abi_minor,
            syscall_event_size,
            feature_bits,
            build_id,
        })
    }
}

const fn copy_abi_bytes<const N: usize>(
    output: &mut [u8; BPF_ABI_ENCODED_SIZE],
    offset: usize,
    input: [u8; N],
) {
    let mut index = 0;
    while index < N {
        output[offset + index] = input[index];
        index += 1;
    }
}

impl PartialEq for BpfAbiMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.magic == other.magic
            && self.abi_major == other.abi_major
            && self.abi_minor == other.abi_minor
            && self.syscall_event_size == other.syscall_event_size
            && self.feature_bits == other.feature_bits
            && self.build_id == other.build_id
    }
}

impl Eq for BpfAbiMetadata {}

impl core::fmt::Debug for BpfAbiMetadata {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let magic = self.magic;
        let abi_major = self.abi_major;
        let abi_minor = self.abi_minor;
        let syscall_event_size = self.syscall_event_size;
        let feature_bits = self.feature_bits;
        let build_id = self.build_id;
        formatter
            .debug_struct("BpfAbiMetadata")
            .field("magic", &magic)
            .field("abi_major", &abi_major)
            .field("abi_minor", &abi_minor)
            .field("syscall_event_size", &syscall_event_size)
            .field("feature_bits", &feature_bits)
            .field("build_id", &build_id)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BpfAbiError {
    MissingMetadata,
    TruncatedMetadata {
        expected: usize,
        actual: usize,
    },
    InvalidMagic {
        expected: u64,
        actual: u64,
    },
    MajorMismatch {
        expected: u16,
        actual: u16,
    },
    EventSizeMismatch {
        expected: u32,
        actual: u32,
    },
    MissingBuildId,
    BuildIdMismatch {
        expected: [u8; 20],
        actual: [u8; 20],
    },
    MissingFeatures {
        required: u64,
        available: u64,
        missing: u64,
    },
}

impl core::fmt::Display for BpfAbiError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingMetadata => formatter.write_str("BPF ABI metadata is missing"),
            Self::TruncatedMetadata { expected, actual } => write!(
                formatter,
                "BPF ABI metadata is truncated: expected at least {expected} bytes, found {actual}"
            ),
            Self::InvalidMagic { expected, actual } => write!(
                formatter,
                "BPF ABI magic mismatch: expected {expected:#018x}, found {actual:#018x}"
            ),
            Self::MajorMismatch { expected, actual } => write!(
                formatter,
                "BPF ABI major mismatch: userspace requires {expected}, object provides {actual}"
            ),
            Self::EventSizeMismatch { expected, actual } => write!(
                formatter,
                "SyscallEvent size mismatch: userspace requires {expected}, object provides {actual}"
            ),
            Self::MissingBuildId => formatter.write_str(
                "BPF build ID is missing; rebuild the object through cargo xtask build-ebpf",
            ),
            Self::BuildIdMismatch { expected, actual } => {
                formatter.write_str("BPF source commit mismatch: userspace=")?;
                write_hex(formatter, expected)?;
                formatter.write_str(" object=")?;
                write_hex(formatter, actual)
            }
            Self::MissingFeatures {
                required,
                available,
                missing,
            } => write!(
                formatter,
                "BPF feature mismatch: required={required:#x} available={available:#x} missing={missing:#x}"
            ),
        }
    }
}

fn write_hex(formatter: &mut core::fmt::Formatter<'_>, bytes: &[u8]) -> core::fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

/// Convert a 40-character Git object ID exposed by the build environment into
/// the 20-byte ABI build ID. Invalid or absent values produce all zeroes; the
/// userspace object inspector still reports the full object SHA-256.
pub const fn bpf_build_id_from_git_hex(value: Option<&str>) -> [u8; 20] {
    let Some(value) = value else {
        return [0u8; 20];
    };
    let bytes = value.as_bytes();
    if bytes.len() < 40 {
        return [0u8; 20];
    }
    let mut output = [0u8; 20];
    let mut index = 0;
    while index < 20 {
        let high = hex_nibble(bytes[index * 2]);
        let low = hex_nibble(bytes[index * 2 + 1]);
        if high > 15 || low > 15 {
            return [0u8; 20];
        }
        output[index] = (high << 4) | low;
        index += 1;
    }
    output
}

const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => u8::MAX,
    }
}

// ── Tracepoint field offsets covered by doctor compatibility checks ─────────

pub const TRACEPOINT_SYS_ENTER_ID_OFFSET: usize = 8;
pub const TRACEPOINT_SYS_ENTER_ARGS_OFFSET: usize = 16;
pub const TRACEPOINT_SYS_EXIT_ID_OFFSET: usize = 8;
pub const TRACEPOINT_SYS_EXIT_RET_OFFSET: usize = 16;
pub const TRACEPOINT_BINDER_DEBUG_ID_OFFSET: usize = 8;
pub const TRACEPOINT_BINDER_TARGET_NODE_OFFSET: usize = 12;
pub const TRACEPOINT_BINDER_TO_PROC_OFFSET: usize = 16;
pub const TRACEPOINT_BINDER_TO_THREAD_OFFSET: usize = 20;
pub const TRACEPOINT_BINDER_REPLY_OFFSET: usize = 24;
pub const TRACEPOINT_BINDER_CODE_OFFSET: usize = 28;
pub const TRACEPOINT_BINDER_FLAGS_OFFSET: usize = 32;
pub const TRACEPOINT_BINDER_RECEIVED_DEBUG_ID_OFFSET: usize = 8;
pub const TRACEPOINT_SCHED_EXIT_COMM_OFFSET: usize = 8;
pub const TRACEPOINT_SCHED_EXIT_PID_OFFSET: usize = 24;

// ── filter_map (BPF_MAP_TYPE_ARRAY) ──────────────────────────────────────────
//
// Slot indices are stable — they may be added at the end but never reordered.
// The BPF object must declare `Array::with_max_entries(FILTER_MAP_SLOT_COUNT,
// ..)`; userspace must keep `populate_filter_map` aligned with this list.

/// Target PID. `0` means "match all PIDs". Phase 1a additionally consults
/// `PID_WHITELIST` for multi-PID matches.
pub const FILTER_KEY_PID: u32 = 0;
/// Legacy syscall-filter active flag (gates the `SYSCALL_FILTER` HashMap).
/// Kept for backward compatibility with existing `--profile` entry points.
pub const FILTER_KEY_ACTIVE: u32 = 1;
/// Phase 1a — bitmask of which `MATCH_*` predicates are configured. See
/// the `MATCH_BIT_*` constants below.
pub const FILTER_KEY_MATCH_BITS: u32 = 2;
/// Phase 1a — `RetClass` discriminant. Only consulted when `MATCH_BIT_RET`
/// is set on `MATCH_BITS`.
pub const FILTER_KEY_RET_CLASS: u32 = 3;
/// Phase 1a — minimum `latency_us` for an exit event to match. `0` disables
/// the check; gated by `MATCH_BIT_LATENCY`.
pub const FILTER_KEY_LATENCY_MIN_US: u32 = 4;
/// Phase 1a — byte offset (within the post-cmd `arg` snapshot, i.e.
/// `data[4..]`) at which the BPF programs read a u32 LE value to compare
/// against `MATCH_ARG_U32_VALS`. Gated by `MATCH_BIT_ARG_U32`.
pub const FILTER_KEY_ARG_U32_OFF: u32 = 5;
/// Phase 1a — required `_IOC_DIR` value (`0..=3`). Gated by
/// `MATCH_BIT_IOCTL_DIR`.
pub const FILTER_KEY_IOCTL_DIR: u32 = 6;
/// Phase 1a — when set to `1`, BPF programs let
/// state-tracking syscalls (see [`is_state_tracking_nr`]) bypass the
/// predicate filter. Userspace flips this on whenever a feature relies on
/// `FdGraph` state (e.g. `--match-fd`, `--resolve-paths`,
/// `--follow-children`).
pub const FILTER_KEY_STATE_EMIT_REQUIRED: u32 = 7;
/// Enable matching through `TRACED_PROCESSES` instead of broad PID 0 mode.
pub const FILTER_KEY_CAUSAL_MODE: u32 = 8;
/// Allow Binder sends to add their callee to `TRACED_PROCESSES`.
pub const FILTER_KEY_FOLLOW_BINDER: u32 = 9;
/// Maximum Binder expansion depth.
pub const FILTER_KEY_MAX_DEPTH: u32 = 10;
/// Enable the root-process UID guard used by package/UID causal roots.
pub const FILTER_KEY_ROOT_UID_ACTIVE: u32 = 11;
/// Expected UID for depth-zero roots. Binder-followed processes are exempt.
pub const FILTER_KEY_ROOT_UID: u32 = 12;
/// Admit previously unseen matching-UID roots on their first kernel event.
/// Enabled only for explicit `--root-uid`, never package/shared-UID roots.
pub const FILTER_KEY_ROOT_UID_ADMIT: u32 = 13;
/// Allocate generously so future Phase-1 extensions don't require a wire
/// bump. Existing slots stay at their current indices.
pub const FILTER_MAP_SLOT_COUNT: u32 = 16;

pub const CAUSAL_PID_REJECT: u8 = 0;
pub const CAUSAL_PID_MATCH: u8 = 1;
pub const CAUSAL_PID_ADMIT_ROOT: u8 = 2;
pub const CAUSAL_PID_FALLTHROUGH: u8 = 3;

/// Decide whether a process is already in causal scope, may become an
/// explicit UID root, or must continue through the legacy non-causal filters.
#[inline(always)]
pub const fn causal_pid_action(
    causal_mode: bool,
    context_reason: u8,
    root_uid_admit: bool,
    root_uid_matches: bool,
) -> u8 {
    if context_reason != 0 {
        if context_reason == TraceReason::Root as u8 {
            if !root_uid_matches {
                CAUSAL_PID_REJECT
            } else if root_uid_admit {
                CAUSAL_PID_ADMIT_ROOT
            } else {
                CAUSAL_PID_MATCH
            }
        } else {
            CAUSAL_PID_MATCH
        }
    } else if !causal_mode {
        CAUSAL_PID_FALLTHROUGH
    } else if root_uid_admit && root_uid_matches {
        CAUSAL_PID_ADMIT_ROOT
    } else {
        CAUSAL_PID_REJECT
    }
}

/// Classify a missing syscall exit at a dynamic Binder-follow boundary.
///
/// A process can be admitted while one of its sibling Binder threads is
/// already blocked in a syscall that started before the trace set contained
/// the process. That thread's first observed exit has no matching enter. It
/// is a causal-boundary observation only when no post-admission enter was
/// seen for that thread; later misses remain capture degradation.
#[inline(always)]
pub const fn causal_admission_boundary_exit(
    reason: TraceReason,
    thread_seen_enter: bool,
    direct_binder_boundary: bool,
) -> bool {
    direct_binder_boundary || (reason as u8 == TraceReason::Binder as u8 && !thread_seen_enter)
}

// ── MATCH_BITS — bitfield in FILTER_MAP[FILTER_KEY_MATCH_BITS] ───────────────
//
// Each bit gates one predicate evaluator BPF-side. Userspace sets the bit
// when it populates the corresponding map / scalar slot, and clears it
// otherwise. PID and SYSCALL predicates ride on the legacy
// `FILTER_KEY_PID` / `FILTER_KEY_ACTIVE` toggles, so they have no bit.

pub const MATCH_BIT_UID: u32 = 1 << 0;
pub const MATCH_BIT_IOCTL_CMD: u32 = 1 << 1;
pub const MATCH_BIT_IOCTL_TYPE: u32 = 1 << 2;
pub const MATCH_BIT_IOCTL_NR: u32 = 1 << 3;
pub const MATCH_BIT_IOCTL_DIR: u32 = 1 << 4;
pub const MATCH_BIT_RET: u32 = 1 << 5;
pub const MATCH_BIT_LATENCY: u32 = 1 << 6;
pub const MATCH_BIT_ARG_U32: u32 = 1 << 7;

// ── ret-class discriminant (FILTER_KEY_RET_CLASS) ────────────────────────────

pub const RET_CLASS_ANY: u32 = 0;
pub const RET_CLASS_NONZERO: u32 = 1;
pub const RET_CLASS_NEGATIVE: u32 = 2;
pub const RET_CLASS_ZERO: u32 = 3;

/// Returns `true` if the given ret value matches the configured class.
/// Pure function; safe to use from both BPF and userspace.
#[inline]
pub const fn ret_matches_class(ret: i64, class: u32) -> bool {
    match class {
        RET_CLASS_NONZERO => ret != 0,
        RET_CLASS_NEGATIVE => ret < 0,
        RET_CLASS_ZERO => ret == 0,
        _ => true, // RET_CLASS_ANY and unknown values pass through.
    }
}

// ── State-tracking syscalls (Phase 1a) ───────────────────────────────────────
//
// These syscalls drive the userspace `FdGraph`: openat, dup, close, socket,
// pipe, eventfd, memfd_create, accept, clone (for follow-children). When a
// `--match-fd` / `--resolve-paths` / `--follow-children` feature is active,
// `FILTER_KEY_STATE_EMIT_REQUIRED` is set and BPF lets these syscalls
// bypass the predicate filter so userspace fdgraph stays consistent. The
// matching userspace post-filter still decides whether the event is
// written to NDJSON or only consumed for state.
//
// Numbers are aarch64 generic (kernel/uapi/asm-generic/unistd.h). They
// must stay in sync with `src/decode/syscalls.rs`.

/// Authoritative list of state-tracking syscall numbers. Userspace iterates
/// this slice to populate `SYSCALL_FILTER` when `--match-syscall` is in use
/// alongside fd-aware features. BPF uses [`is_state_tracking_nr`] for the
/// same predicate via a `match` expression that compiles to a jump table.
pub const STATE_TRACKING_NRS: &[i32] = &[
    19,  // eventfd2
    23,  // dup
    24,  // dup3
    56,  // openat
    57,  // close
    59,  // pipe2
    198, // socket
    199, // socketpair
    202, // accept
    220, // clone
    242, // accept4
    279, // memfd_create
    437, // openat2
];

/// `true` when the syscall number drives userspace fdgraph state. Kept as a
/// `match` expression so the BPF compiler emits a jump table instead of an
/// O(N) slice scan. Must enumerate the same numbers as `STATE_TRACKING_NRS`.
#[inline]
pub const fn is_state_tracking_nr(nr: i32) -> bool {
    matches!(
        nr,
        19 | 23 | 24 | 56 | 57 | 59 | 198 | 199 | 202 | 220 | 242 | 279 | 437
    )
}

/// Maximum number of stack frames stored per stack trace
pub const STACK_FRAMES: u32 = 127;

// ── Counter indices (COUNTERS BPF_MAP_TYPE_PERCPU_ARRAY) ─────────────────────
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
/// R/RW ioctl was a plausible driver-pack refresh candidate but neither
/// the static whitelist nor runtime refresh maps selected it.
pub const COUNTER_IOCTL_REFRESH_MISSED: u32 = 10;
/// sendmsg/recvmsg control metadata was present but could not be read
/// completely into the bounded `data[128]` summary.
pub const COUNTER_UNIX_MSG_CONTROL_TRUNCATED: u32 = 11;
/// sendmsg/recvmsg carried more than one control message; neutron records
/// only the first cmsghdr and counts the rest as nested metadata.
pub const COUNTER_UNIX_MSG_CONTROL_NESTED: u32 = 12;
/// Dynamic traced-process map had no room for a new callee/root.
pub const COUNTER_TRACED_PROCESS_LIMIT: u32 = 13;
/// Binder propagation stopped at the configured maximum depth.
pub const COUNTER_BINDER_DEPTH_LIMIT: u32 = 14;
/// A Binder follow update failed (map update or unusable callee PID).
pub const COUNTER_BINDER_FOLLOW_FAILED: u32 = 15;
/// Per-thread exact Binder context could not be recorded.
pub const COUNTER_THREAD_CONTEXT_UPDATE_FAILED: u32 = 16;
/// A dynamic Binder callee exited its first causally scoped syscall after the
/// process was admitted, so no enter-side arguments were available yet.
/// This is an explicit causal-boundary observation, not ring-buffer loss.
pub const COUNTER_CAUSAL_ADMISSION_BOUNDARY_EXIT: u32 = 17;
/// A bounded user/kernel payload read failed. The event may still be emitted,
/// but its payload must not be treated as complete evidence.
pub const COUNTER_PAYLOAD_READ_FAILED: u32 = 18;
/// A required tracepoint context field could not be read at its validated
/// offset. The affected event is discarded and capture health is degraded.
pub const COUNTER_TRACEPOINT_READ_FAILED: u32 = 19;
/// An ioctl declared more payload bytes than fit in the 124-byte bounded
/// capture region. The event is emitted, but its argument evidence is partial.
pub const COUNTER_IOCTL_PAYLOAD_TRUNCATED: u32 = 20;

/// Number of slots in the COUNTERS map. New counters extend the tail; bumping
/// requires updating the `PerCpuArray::with_max_entries(...)` size in BPF and the
/// label table in userspace.
pub const COUNTER_SLOT_COUNT: u32 = 21;

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
/// `_IOC_TYPE` byte used by the Qualcomm KGSL GPU driver.
pub const IOCTL_TYPE_KGSL: u32 = 0x09;
/// `_IOC_TYPE` byte used by the ARM Mali kbase driver.
pub const IOCTL_TYPE_MALI_KBASE: u32 = 0x80;
/// `_IOC_TYPE` byte for ALSA PCM ioctls used by Android audio HALs.
pub const IOCTL_TYPE_ALSA_PCM: u32 = 0x50;
/// `_IOC_TYPE` byte for ALSA control ioctls (`'U'`).
pub const IOCTL_TYPE_ALSA_CTL: u32 = 0x55;
/// `_IOC_TYPE` byte for ALSA hwdep ioctls (`'H'`), shared with dma-heap.
pub const IOCTL_TYPE_ALSA_HWDEP: u32 = 0x48;
/// `_IOC_TYPE` byte for ALSA rawmidi ioctls (`'W'`).
pub const IOCTL_TYPE_ALSA_RAWMIDI: u32 = 0x57;
/// `_IOC_TYPE` byte for ALSA timer ioctls (`'T'`).
pub const IOCTL_TYPE_ALSA_TIMER: u32 = 0x54;
/// `_IOC_TYPE` byte for ALSA sequencer ioctls (`'S'`).
pub const IOCTL_TYPE_ALSA_SEQ: u32 = 0x53;
/// `_IOC_TYPE` byte for ALSA compress-offload ioctls (`'C'`).
pub const IOCTL_TYPE_ALSA_COMPRESS: u32 = 0x43;
/// `_IOC_TYPE` byte for Pixel LWIS camera HAL ioctls (`'L'`).
pub const IOCTL_TYPE_LWIS: u32 = 0x4c;
/// Upstream GXP accelerator `_IOC_TYPE` byte (`'G'`).
pub const IOCTL_TYPE_GXP_UPSTREAM: u32 = 0x47;
/// Pixel out-of-tree GXP accelerator `_IOC_TYPE` byte.
pub const IOCTL_TYPE_GXP_PIXEL: u32 = 0xee;

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

/// Extracts the `_IOC_SIZE` field (bits 16..30) from an ioctl `cmd`.
///
/// Neutron uses this as the privacy and safety bound for user-buffer reads;
/// zero-sized commands are never treated as carrying a generic pointer-sized
/// payload.
#[inline]
pub const fn ioctl_size(cmd: u32) -> u32 {
    (cmd >> 16) & 0x3fff
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

/// Returns `true` for R/RW ioctl families that decoder packs can safely ask
/// BPF to refresh at runtime via the `IOCTL_REFRESH_*` maps. The maps provide
/// the active policy; this helper is the userspace/BPF shared coarse filter
/// and documentation of supported driver-pack families.
#[inline]
pub const fn ioctl_runtime_refresh_candidate(cmd: u32) -> bool {
    let dir = ioctl_dir(cmd);
    if !(dir == IOCTL_DIR_R || dir == IOCTL_DIR_RW) {
        return false;
    }
    let ty = ioctl_type(cmd);
    matches!(
        ty,
        IOCTL_TYPE_KGSL
            | IOCTL_TYPE_MALI_KBASE
            | IOCTL_TYPE_ALSA_PCM
            | IOCTL_TYPE_ALSA_CTL
            | IOCTL_TYPE_ALSA_HWDEP
            | IOCTL_TYPE_ALSA_RAWMIDI
            | IOCTL_TYPE_ALSA_TIMER
            | IOCTL_TYPE_ALSA_SEQ
            | IOCTL_TYPE_ALSA_COMPRESS
            | IOCTL_TYPE_LWIS
            | IOCTL_TYPE_GXP_UPSTREAM
            | IOCTL_TYPE_GXP_PIXEL
    )
}

/// Synthetic event IDs reserved for optional explicit kprobe research packs.
/// They are encoded as negative `syscall_nr` values in the existing
/// `SyscallEvent` wire layout when a future BPF object provides the matching
/// programs.
pub const SYSCALL_NR_KPROBE_BINDER: i32 = -10;
pub const SYSCALL_NR_KPROBE_KGSL: i32 = -11;
pub const SYSCALL_NR_KPROBE_MALI: i32 = -12;
pub const SYSCALL_NR_KPROBE_ALSA: i32 = -13;
pub const SYSCALL_NR_KPROBE_UNIX_SOCKET: i32 = -14;

// ── Process exit (sprint-2 PR 1) ─────────────────────────────────────────────
//
// Synthetic syscall_nr sentinel for `type:"process_exit"` events. Encoded
// into the existing `SyscallEvent` wire layout so no bump is required:
// - syscall_nr = -3 (sentinel; -1 = binder, -2 = fd_snapshot)
// - args[0]   = exit_code (0..=255 from exit(2), or 0 when killed by signal)
// - args[1]   = exit_signal (0 = no signal, otherwise SIG* value)
// - args[2]   = exit_source (ExitSource discriminant)
// - args[3..] = reserved
//
// The BPF sched_process_exit handler emits with source=0 (Tracepoint) and
// args[0]/args[1] = 0 (the task_struct->exit_code BTF read is deferred).
// Userspace sources (logcat, tombstone watchers) emit with source=1/2 and
// fill in signal info parsed from their respective stream formats.

/// Sentinel `syscall_nr` for `type:"process_exit"` events.
pub const SYSCALL_NR_PROCESS_EXIT: i32 = -3;

/// Sentinel `syscall_nr` for `binder/binder_transaction_received` events
/// emitted by the BPF callee-side tracepoint (sprint-2 PR 2). Paired with
/// `-1` (binder caller) by debug_id stored in `ptr_hint`.
pub const SYSCALL_NR_BINDER_RECEIVED: i32 = -4;

/// Discriminant for the source that detected an exit. Stored in
/// `SyscallEvent.args[2]` when `syscall_nr == SYSCALL_NR_PROCESS_EXIT`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ExitSource {
    #[default]
    Tracepoint = 0,
    Logcat = 1,
    Tombstone = 2,
}

impl ExitSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            ExitSource::Tracepoint => "tracepoint",
            ExitSource::Logcat => "logcat",
            ExitSource::Tombstone => "tombstone",
        }
    }

    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(ExitSource::Tracepoint),
            1 => Some(ExitSource::Logcat),
            2 => Some(ExitSource::Tombstone),
            _ => None,
        }
    }
}

/// Fatal POSIX signal numbers that classify an exit as `"crash"`. Aarch64
/// Linux numbering — matches `<bits/signum-generic.h>` and is identical to
/// the values logcat / tombstoned print.
pub const SIGILL: u32 = 4;
pub const SIGABRT: u32 = 6;
pub const SIGBUS: u32 = 7;
pub const SIGFPE: u32 = 8;
pub const SIGSEGV: u32 = 11;
pub const SIGSYS: u32 = 31;

/// Returns the symbolic name (`"SIGSEGV"` etc.) for a signal number, or
/// `None` for values neutron does not classify. Used by userspace formatters.
pub const fn signal_name(sig: u32) -> Option<&'static str> {
    match sig {
        SIGILL => Some("SIGILL"),
        SIGABRT => Some("SIGABRT"),
        SIGBUS => Some("SIGBUS"),
        SIGFPE => Some("SIGFPE"),
        SIGSEGV => Some("SIGSEGV"),
        SIGSYS => Some("SIGSYS"),
        // Common non-fatal that a watcher may still surface.
        9 => Some("SIGKILL"),
        15 => Some("SIGTERM"),
        2 => Some("SIGINT"),
        _ => None,
    }
}

/// `true` when a signal terminates a process and warrants the `"crash"`
/// classification. R003_process_crash matches exactly this set.
pub const fn is_fatal_signal(sig: u32) -> bool {
    matches!(sig, SIGILL | SIGABRT | SIGBUS | SIGFPE | SIGSEGV | SIGSYS)
}

// ── Binder causality (sprint-2 PR 2) ─────────────────────────────────────────
//
// Userspace synthesises `type:"binder_call"` events by pairing caller-side
// `binder_transaction` (nr=-1) with callee-side `binder_transaction_received`
// (nr=-4) via `debug_id` carried in `ptr_hint`. The status enum is the
// rule-engine-facing label; `as_str` round-trips through JSON.

/// Lifecycle status of a binder transaction observed by the userspace
/// correlator.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BinderCallStatus {
    /// Pair matched: callee dequeued the transaction. The default state
    /// emitted at receive time.
    #[default]
    Completed,
    /// Callee process emitted `process_exit` with `classification == "crash"`
    /// while the transaction was in flight.
    CalleeCrashed,
    /// Tracker's bounded LRU evicted the entry without ever observing a
    /// receive event. Reserved for follow-up rules; the default emit path
    /// does not currently surface these.
    Unmatched,
}

impl BinderCallStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            BinderCallStatus::Completed => "completed",
            BinderCallStatus::CalleeCrashed => "callee_crashed",
            BinderCallStatus::Unmatched => "unmatched",
        }
    }
}

#[cfg(test)]
mod binder_call_tests {
    use super::*;

    #[test]
    fn status_strings_are_stable() {
        assert_eq!(BinderCallStatus::Completed.as_str(), "completed");
        assert_eq!(BinderCallStatus::CalleeCrashed.as_str(), "callee_crashed");
        assert_eq!(BinderCallStatus::Unmatched.as_str(), "unmatched");
    }
}

#[cfg(test)]
mod exit_classification_tests {
    use super::*;

    #[test]
    fn fatal_signals_match_documented_set() {
        for sig in [SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE, SIGSYS] {
            assert!(is_fatal_signal(sig), "{sig} should be fatal");
        }
        assert!(!is_fatal_signal(0));
        assert!(!is_fatal_signal(9), "SIGKILL deliberately excluded");
        assert!(!is_fatal_signal(15));
    }

    #[test]
    fn signal_name_round_trips_for_known_signals() {
        assert_eq!(signal_name(SIGSEGV), Some("SIGSEGV"));
        assert_eq!(signal_name(SIGABRT), Some("SIGABRT"));
        assert_eq!(signal_name(9), Some("SIGKILL"));
        assert_eq!(signal_name(0xff), None);
    }

    #[test]
    fn exit_source_round_trips() {
        for src in [
            ExitSource::Tracepoint,
            ExitSource::Logcat,
            ExitSource::Tombstone,
        ] {
            assert_eq!(ExitSource::from_u8(src as u8), Some(src));
        }
        assert_eq!(ExitSource::from_u8(99), None);
    }
}

#[cfg(test)]
mod state_tracking_tests {
    use super::*;

    #[test]
    fn is_state_tracking_nr_matches_listed_set() {
        for &nr in STATE_TRACKING_NRS {
            assert!(
                is_state_tracking_nr(nr),
                "STATE_TRACKING_NRS slice contains nr={nr} but predicate disagrees"
            );
        }
    }

    #[test]
    fn is_state_tracking_nr_rejects_arbitrary_syscalls() {
        // ioctl=29, mmap=222, futex=98 — none should appear in the list.
        assert!(!is_state_tracking_nr(29));
        assert!(!is_state_tracking_nr(222));
        assert!(!is_state_tracking_nr(98));
        assert!(!is_state_tracking_nr(-1)); // binder sentinel
    }

    #[test]
    fn ret_matches_class_covers_known_values() {
        assert!(ret_matches_class(0, RET_CLASS_ANY));
        assert!(ret_matches_class(-1, RET_CLASS_ANY));

        assert!(!ret_matches_class(0, RET_CLASS_NONZERO));
        assert!(ret_matches_class(1, RET_CLASS_NONZERO));
        assert!(ret_matches_class(-1, RET_CLASS_NONZERO));

        assert!(!ret_matches_class(0, RET_CLASS_NEGATIVE));
        assert!(!ret_matches_class(1, RET_CLASS_NEGATIVE));
        assert!(ret_matches_class(-22, RET_CLASS_NEGATIVE));

        assert!(ret_matches_class(0, RET_CLASS_ZERO));
        assert!(!ret_matches_class(1, RET_CLASS_ZERO));
    }

    #[test]
    fn ret_matches_class_treats_unknown_class_as_any() {
        assert!(ret_matches_class(0, 99));
        assert!(ret_matches_class(-1, 99));
    }

    #[test]
    fn match_bits_are_distinct_powers_of_two() {
        let bits = [
            MATCH_BIT_UID,
            MATCH_BIT_IOCTL_CMD,
            MATCH_BIT_IOCTL_TYPE,
            MATCH_BIT_IOCTL_NR,
            MATCH_BIT_IOCTL_DIR,
            MATCH_BIT_RET,
            MATCH_BIT_LATENCY,
            MATCH_BIT_ARG_U32,
        ];
        let mut seen: u32 = 0;
        for b in bits {
            assert!(b.is_power_of_two(), "{b:#x} is not a single bit");
            assert_eq!(seen & b, 0, "{b:#x} collides with already-seen bits");
            seen |= b;
        }
    }
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
    fn runtime_refresh_policy_accepts_driver_pack_types() {
        let kgsl = ioc(IOCTL_DIR_RW, IOCTL_TYPE_KGSL, 0x2f, 32);
        let mali = ioc(IOCTL_DIR_R, IOCTL_TYPE_MALI_KBASE, 0, 16);
        let alsa_pcm = ioc(IOCTL_DIR_RW, IOCTL_TYPE_ALSA_PCM, 0x10, 32);
        assert!(ioctl_runtime_refresh_candidate(kgsl));
        assert!(ioctl_runtime_refresh_candidate(mali));
        assert!(ioctl_runtime_refresh_candidate(alsa_pcm));
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

#[cfg(test)]
mod causal_pid_policy_tests {
    use super::*;

    #[test]
    fn explicit_uid_admits_an_unlisted_matching_process() {
        assert_eq!(
            causal_pid_action(true, 0, true, true),
            CAUSAL_PID_ADMIT_ROOT
        );
    }

    #[test]
    fn package_or_match_predicates_cannot_broaden_causal_scope() {
        assert_eq!(causal_pid_action(true, 0, false, true), CAUSAL_PID_REJECT);
    }

    #[test]
    fn uid_guard_rejects_wrong_uid_roots_but_not_binder_followers() {
        assert_eq!(
            causal_pid_action(true, TraceReason::Root as u8, true, false),
            CAUSAL_PID_REJECT
        );
        assert_eq!(
            causal_pid_action(true, TraceReason::Binder as u8, true, false),
            CAUSAL_PID_MATCH
        );
        assert_eq!(causal_pid_action(true, 0, true, false), CAUSAL_PID_REJECT);
    }

    #[test]
    fn explicit_uid_refreshes_a_root_admitted_before_the_active_marker() {
        assert_eq!(
            causal_pid_action(true, TraceReason::Root as u8, true, true),
            CAUSAL_PID_ADMIT_ROOT
        );
    }

    #[test]
    fn noncausal_absent_processes_continue_to_legacy_filters() {
        assert_eq!(
            causal_pid_action(false, 0, false, false),
            CAUSAL_PID_FALLTHROUGH
        );
    }

    #[test]
    fn binder_admission_covers_a_sibling_thread_that_started_before_follow() {
        assert!(causal_admission_boundary_exit(
            TraceReason::Binder,
            false,
            false,
        ));
        assert!(causal_admission_boundary_exit(
            TraceReason::Binder,
            true,
            true,
        ));
        assert!(!causal_admission_boundary_exit(
            TraceReason::Binder,
            true,
            false,
        ));
        assert!(!causal_admission_boundary_exit(
            TraceReason::Root,
            false,
            false,
        ));
    }
}
