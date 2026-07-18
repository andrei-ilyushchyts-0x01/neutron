//! ioctl() argument decoding (cmd + payload).
//!
//! Two layers:
//!
//! - [`format_ioctl_deep`] — the original device-agnostic `_IOC` decomposition
//!   used by the human-readable text formatter. Stable since v1.0.
//! - [`decode_ioctl`] — decoder registry that returns a typed
//!   [`DecodedIoctl`] for known commands. Built-ins cover DMA-heap and Binder
//!   scalar layouts plus bounded driver-family views; runtime schema packs add
//!   more data-only layouts. [`render_decoded_ioctl_json`] emits the matching
//!   JSON fragment that the NDJSON formatter splices into the line.
//!
//! The whitelist of which `cmd` values trigger a `sys_exit` re-read of the
//! user buffer is shared with the BPF programs via
//! [`neutron_common::ioctl_post_exit_refresh`] so the two sides cannot drift.

use crate::fdgraph::FdKind;

/// Decode ioctl deep data: `data[0..4]` = cmd, `data[4..128]` = payload.
pub fn format_ioctl_deep(raw: &[u8; 128]) -> String {
    let cmd = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    // _IOC decomposition: dir(2) | size(14) | type(8) | nr(8)
    let nr = cmd & 0xff;
    let ioc_type = (cmd >> 8) & 0xff;
    let size = (cmd >> 16) & 0x3fff;
    let dir = (cmd >> 30) & 0x3;
    let dir_s = match dir {
        0 => "NONE",
        1 => "W",
        2 => "R",
        3 => "RW",
        _ => "?",
    };

    // Known device types
    let device = match ioc_type {
        // Binder and dma-buf deliberately share the 'b' magic. This legacy
        // formatter has no FD context, so keep that ambiguity visible.
        0x62 => "binder_or_dma_buf", // 'b'
        0x77 => "ashmem",            // 'w' (0x77)
        _ => "",
    };

    let has_payload = raw[4..20].iter().any(|&b| b != 0);
    if device.is_empty() {
        if has_payload {
            let hex: String = raw[4..20].iter().map(|b| format!("{:02x}", b)).collect();
            format!(
                "_IOC({},{:#04x},{},{}) payload={}...",
                dir_s, ioc_type, nr, size, hex
            )
        } else {
            format!("_IOC({},{:#04x},{},{})", dir_s, ioc_type, nr, size)
        }
    } else if has_payload {
        let hex: String = raw[4..20].iter().map(|b| format!("{:02x}", b)).collect();
        format!(
            "{}:_IOC({},{},{}) payload={}...",
            device, dir_s, nr, size, hex
        )
    } else {
        format!("{}:_IOC({},{},{})", device, dir_s, nr, size)
    }
}

// ── Decoder registry (sprint 1, PR 2) ────────────────────────────────────────

/// Family of an ioctl, classified by `_IOC_TYPE` and (for the `'b'` collision
/// between binder and dma-buf) the FD-graph kind of the target fd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoctlFamily {
    DmaHeap,
    DmaBuf,
    /// The shared `'b'` magic was observed without enough FD context to
    /// distinguish Binder from dma-buf. Evidence consumers must not collapse
    /// this into either concrete family.
    BinderOrDmaBuf,
    Binder,
    Kgsl,
    Mali,
    Alsa,
    Ashmem,
    /// Pixel's LWIS camera HAL surface — type byte `'L'` (0x4c). The
    /// command-packet ioctl (`_IOWR('L', 100, lwis_cmd_pkt)`) carries an
    /// opaque `cmd_id` in `data[4..8]`; the decoder maps known IDs to
    /// human names. Phase 3.
    Lwis,
    /// Pixel Tensor's GXP accelerator driver — type byte `'G'` (0x47 in
    /// upstream; the Pixel out-of-tree driver uses 0xee but we accept
    /// either since the decoded family is the same logical attack
    /// surface). Phase 3.
    Gxp,
    /// Trusty IPC character-device UAPI (`TIPC_IOC_*`, magic `'r'`).
    TrustyTipc,
    /// Video4Linux2 UAPI (`VIDIOC_*`, magic `'V'`).
    V4l2,
    Unknown,
}

impl IoctlFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            IoctlFamily::DmaHeap => "dma_heap",
            IoctlFamily::DmaBuf => "dma_buf",
            IoctlFamily::BinderOrDmaBuf => "binder_or_dma_buf",
            IoctlFamily::Binder => "binder",
            IoctlFamily::Kgsl => "kgsl",
            IoctlFamily::Mali => "mali",
            IoctlFamily::Alsa => "alsa",
            IoctlFamily::Ashmem => "ashmem",
            IoctlFamily::Lwis => "lwis",
            IoctlFamily::Gxp => "gxp",
            IoctlFamily::TrustyTipc => "trusty_tipc",
            IoctlFamily::V4l2 => "v4l2",
            IoctlFamily::Unknown => "unknown",
        }
    }

    /// Classify by `_IOC_TYPE` byte. The `'b'` (0x62) magic is reused by
    /// both binder and dma-buf in the kernel headers — they only diverge by
    /// the file_operations of the target fd. We use the FD-graph kind as the
    /// disambiguator: `Binder` fd → binder, a known non-Binder fd → dma-buf,
    /// and absent/unknown context → an explicit ambiguous family.
    pub fn from_cmd(cmd: u32, fd_kind: Option<FdKind>) -> Self {
        Self::from_cmd_with_path(cmd, fd_kind, None)
    }

    /// Classify with optional fd path context. Driver packs intentionally
    /// avoid arbitrary pointer walking; the fd graph path is the safest way
    /// to disambiguate ioctl magic collisions (`'H'` dma-heap vs ALSA hwdep,
    /// `'b'` binder vs dma-buf) when it is available.
    pub fn from_cmd_with_path(cmd: u32, fd_kind: Option<FdKind>, fd_path: Option<&str>) -> Self {
        if let Some(path) = fd_path {
            if path.starts_with("/dev/snd/") || path == "/dev/snd" {
                return IoctlFamily::Alsa;
            }
            if path.starts_with("/dev/kgsl") {
                return IoctlFamily::Kgsl;
            }
            if path.starts_with("/dev/mali") {
                return IoctlFamily::Mali;
            }
            if path.starts_with("/dev/binder") || path.starts_with("/dev/vndbinder") {
                return IoctlFamily::Binder;
            }
            if path.starts_with("/dev/trusty-ipc") {
                return IoctlFamily::TrustyTipc;
            }
            if path.starts_with("/dev/video")
                || path.starts_with("/dev/v4l-subdev")
                || path.starts_with("/dev/media")
            {
                return IoctlFamily::V4l2;
            }
        }
        let ty = neutron_common::ioctl_type(cmd);
        match ty {
            t if t == neutron_common::IOCTL_TYPE_DMA_HEAP => IoctlFamily::DmaHeap,
            t if t == neutron_common::IOCTL_TYPE_BINDER_OR_DMA_BUF => match fd_kind {
                Some(FdKind::Binder) => IoctlFamily::Binder,
                None | Some(FdKind::Unknown) => IoctlFamily::BinderOrDmaBuf,
                _ => IoctlFamily::DmaBuf,
            },
            t if t == neutron_common::IOCTL_TYPE_ASHMEM => IoctlFamily::Ashmem,
            t if t == neutron_common::IOCTL_TYPE_KGSL => IoctlFamily::Kgsl,
            t if t == neutron_common::IOCTL_TYPE_MALI_KBASE => IoctlFamily::Mali,
            t if is_alsa_type(t) => IoctlFamily::Alsa,
            t if t == neutron_common::IOCTL_TYPE_LWIS => IoctlFamily::Lwis,
            t if t == neutron_common::IOCTL_TYPE_GXP_UPSTREAM
                || t == neutron_common::IOCTL_TYPE_GXP_PIXEL =>
            {
                IoctlFamily::Gxp
            }
            IOCTL_TYPE_TRUSTY_TIPC => IoctlFamily::TrustyTipc,
            IOCTL_TYPE_V4L2 => IoctlFamily::V4l2,
            _ => IoctlFamily::Unknown,
        }
    }
}

fn is_alsa_type(ty: u32) -> bool {
    matches!(
        ty,
        neutron_common::IOCTL_TYPE_ALSA_PCM
            | neutron_common::IOCTL_TYPE_ALSA_CTL
            | neutron_common::IOCTL_TYPE_ALSA_HWDEP
            | neutron_common::IOCTL_TYPE_ALSA_RAWMIDI
            | neutron_common::IOCTL_TYPE_ALSA_TIMER
            | neutron_common::IOCTL_TYPE_ALSA_SEQ
            | neutron_common::IOCTL_TYPE_ALSA_COMPRESS
    )
}

/// Output of [`decode_ioctl`]. `family` is always set; `name` is the
/// human-readable command identifier when recognised; `fields` is the
/// typed payload view (only `DmaHeapAlloc` is decoded today).
#[derive(Debug, Clone)]
pub struct DecodedIoctl {
    pub family: IoctlFamily,
    pub name: Option<String>,
    pub fields: IoctlFields,
    pub generated: Option<crate::ioctl_schema::GenericDecodedIoctl>,
}

/// Typed view of the ioctl `arg` buffer for known commands.
///
/// `None` is the default — the family is identified but the payload is left
/// raw. As more decoders land they extend this enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoctlFields {
    /// `struct dma_heap_allocation_data` from `include/uapi/linux/dma-heap.h`:
    /// `{ __u64 len; __u32 fd; __u32 fd_flags; __u64 heap_flags; }` — 24
    /// bytes packed.
    ///
    /// CRITICAL: `returned_fd` is written by the kernel post-call. Pre-PR-2
    /// the BPF program only captured the enter-time bytes, so `returned_fd`
    /// would always be the caller's pre-call placeholder (typically 0). PR 2
    /// refreshes the user buffer on `sys_exit` for whitelisted families,
    /// so the value is meaningful when the event carries `data_phase:"exit"`.
    DmaHeapAlloc {
        len: u64,
        returned_fd: i32,
        fd_flags: u32,
        heap_flags: u64,
    },
    /// `struct binder_write_read` scalar header. Nested `write_buffer` /
    /// `read_buffer` command streams are deliberately not dereferenced by
    /// default; the sizes and consumed offsets are enough to detect bursts
    /// and stalled reads without parsing arbitrary AIDL Parcels.
    BinderWriteRead {
        write_size: u64,
        write_consumed: u64,
        read_size: u64,
        read_consumed: u64,
    },
    /// Generic scalar snapshot for driver ioctl packs where the first
    /// words carry stable enough metadata to support timeline/rule matching
    /// but the nested pointers remain out of scope.
    DriverScalars {
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
    },
    /// ALSA ioctl scalar marker. `compat_candidate` is intentionally broad:
    /// negative returns on ALSA family ioctls are useful when looking for
    /// 32/64-bit compat races and control-path confusion.
    Alsa {
        compat_candidate: bool,
        arg0: u64,
        arg1: u64,
    },
    /// LWIS command-packet (`_IOWR('L', 100, lwis_cmd_pkt)`). The first
    /// `u32` of the arg buffer is the LWIS-internal command ID; userspace
    /// resolves it to a human name when known. `cmd_id_name` is `None`
    /// for IDs we don't have a label for (rather than a placeholder
    /// string, so downstream filters can still target them by hex value).
    LwisCmdPkt {
        cmd_id: u32,
        cmd_id_name: Option<&'static str>,
    },
    None,
}

/// `_IOC` command for `DMA_HEAP_IOCTL_ALLOC = _IOWR('H', 0x0, struct dma_heap_allocation_data)`.
/// `dir = 3 (RW), size = 24, type = 0x48 ('H'), nr = 0`.
const DMA_HEAP_IOCTL_ALLOC: u32 = 0xC018_4800;

/// `_IOC` command for `BINDER_WRITE_READ = _IOWR('b', 1, struct binder_write_read)`.
const BINDER_WRITE_READ: u32 = 0xC030_6201;

/// `_IOC` for `LWIS_CMD_PACKET = _IOWR('L', 100, struct lwis_cmd_pkt)`:
/// `dir = 3 (RW), size = 16, type = 0x4c ('L'), nr = 100 (0x64)`.
const LWIS_CMD_PACKET: u32 = 0xC010_4C64;

const IOCTL_TYPE_TRUSTY_TIPC: u32 = b'r' as u32;
const IOCTL_TYPE_V4L2: u32 = b'V' as u32;

/// Decode a captured ioctl `cmd`/`arg` pair into a typed [`DecodedIoctl`].
///
/// `payload` is the buffer captured by BPF as `data[4..128]` (124 bytes
/// max). `_ret` is currently unused; held for forward-compat with decoders
/// that surface kernel return codes.
///
/// Defensive: returns [`IoctlFamily::Unknown`] + [`IoctlFields::None`] for
/// any unrecognised cmd, and [`IoctlFields::None`] when the payload is
/// shorter than the decoder's expected struct size (truncated capture).
pub fn decode_ioctl(cmd: u32, payload: &[u8], _ret: i64, fd_kind: Option<FdKind>) -> DecodedIoctl {
    decode_ioctl_with_context(cmd, payload, _ret, fd_kind, None)
}

/// Decode with optional fd path context from the userspace fd graph.
pub fn decode_ioctl_with_context(
    cmd: u32,
    payload: &[u8],
    ret: i64,
    fd_kind: Option<FdKind>,
    fd_path: Option<&str>,
) -> DecodedIoctl {
    let family = IoctlFamily::from_cmd_with_path(cmd, fd_kind, fd_path);
    let (name, fields) = match cmd {
        DMA_HEAP_IOCTL_ALLOC if family == IoctlFamily::DmaHeap => {
            (Some("DMA_HEAP_IOCTL_ALLOC"), decode_dma_heap_alloc(payload))
        }
        BINDER_WRITE_READ if family == IoctlFamily::Binder => {
            (Some("BINDER_WRITE_READ"), decode_binder_write_read(payload))
        }
        LWIS_CMD_PACKET if family == IoctlFamily::Lwis => {
            (Some("LWIS_CMD_PACKET"), decode_lwis_cmd_pkt(payload))
        }
        _ => match family {
            IoctlFamily::Kgsl => (kgsl_ioctl_name(cmd), decode_driver_scalars(payload)),
            IoctlFamily::Mali => (mali_ioctl_name(cmd), decode_driver_scalars(payload)),
            IoctlFamily::Alsa => (alsa_ioctl_name(cmd), decode_alsa(payload, ret)),
            IoctlFamily::TrustyTipc => (trusty_tipc_ioctl_name(cmd), IoctlFields::None),
            IoctlFamily::V4l2 => (v4l2_ioctl_name(cmd), IoctlFields::None),
            _ => (None, IoctlFields::None),
        },
    };
    let generated = crate::ioctl_schema::decode_active(
        cmd,
        payload,
        fd_path,
        (family != IoctlFamily::Unknown).then(|| family.as_str()),
    );
    DecodedIoctl {
        family,
        name: name
            .map(str::to_string)
            .or_else(|| generated.as_ref().map(|d| d.name.clone())),
        fields,
        generated,
    }
}

/// LWIS command-packet ID → human name. Built from the assessment's own
/// observed-id set plus the explicitly-named flows the LWIS userspace
/// HAL uses on Pixel 8 Pro. IDs we haven't pinned to a documented name
/// (e.g. `0x20200`, `0x40200`, `0x50006`) come back as `None` so they
/// stay searchable by hex value without a misleading label.
const LWIS_CMD_NAMES: &[(u32, &str)] = &[
    (0x10100, "DEVICE_ENABLE"),
    (0x10200, "DEVICE_DISABLE"),
    (0x20100, "DMA_BUFFER_ENROLL"),
    (0x20300, "DMA_BUFFER_ALLOC"),
    (0x20400, "DMA_BUFFER_FREE"),
    (0x30100, "REG_IO"),
    (0x40100, "TRANSACTION_SUBMIT"),
    (0x40300, "TRANSACTION_CANCEL"),
];

fn lwis_cmd_id_name(cmd_id: u32) -> Option<&'static str> {
    LWIS_CMD_NAMES
        .iter()
        .find_map(|(id, name)| (*id == cmd_id).then_some(*name))
}

fn decode_lwis_cmd_pkt(payload: &[u8]) -> IoctlFields {
    if payload.len() < 4 {
        return IoctlFields::None;
    }
    let cmd_id = u32::from_le_bytes(payload[0..4].try_into().unwrap());
    IoctlFields::LwisCmdPkt {
        cmd_id,
        cmd_id_name: lwis_cmd_id_name(cmd_id),
    }
}

fn trusty_tipc_ioctl_name(cmd: u32) -> Option<&'static str> {
    if neutron_common::ioctl_type(cmd) != IOCTL_TYPE_TRUSTY_TIPC {
        return None;
    }
    match ((cmd >> 30) & 0x3, cmd & 0xff) {
        (1, 0x80) => Some("TIPC_IOC_CONNECT"),
        (1, 0x81) => Some("TIPC_IOC_SEND_MSG"),
        _ => None,
    }
}

fn v4l2_ioctl_name(cmd: u32) -> Option<&'static str> {
    if neutron_common::ioctl_type(cmd) != IOCTL_TYPE_V4L2 {
        return None;
    }
    match ((cmd >> 30) & 0x3, cmd & 0xff) {
        (2, 0) => Some("VIDIOC_QUERYCAP"),
        (3, 2) => Some("VIDIOC_ENUM_FMT"),
        (3, 4) => Some("VIDIOC_G_FMT"),
        (3, 5) => Some("VIDIOC_S_FMT"),
        (3, 8) => Some("VIDIOC_REQBUFS"),
        (3, 9) => Some("VIDIOC_QUERYBUF"),
        (3, 15) => Some("VIDIOC_QBUF"),
        (3, 17) => Some("VIDIOC_DQBUF"),
        (1, 18) => Some("VIDIOC_STREAMON"),
        (1, 19) => Some("VIDIOC_STREAMOFF"),
        _ => None,
    }
}

fn kgsl_ioctl_name(cmd: u32) -> Option<&'static str> {
    match cmd & 0xff {
        0x02 => Some("IOCTL_KGSL_DEVICE_GETPROPERTY"),
        0x07 => Some("IOCTL_KGSL_DEVICE_WAITTIMESTAMP_CTXTID"),
        0x10 => Some("IOCTL_KGSL_RINGBUFFER_ISSUEIBCMDS"),
        0x13 => Some("IOCTL_KGSL_DRAWCTXT_CREATE"),
        0x2f => Some("IOCTL_KGSL_GPUMEM_ALLOC"),
        0x33 => Some("IOCTL_KGSL_GPUOBJ_ALLOC"),
        0x34 => Some("IOCTL_KGSL_GPUOBJ_FREE"),
        0x35 => Some("IOCTL_KGSL_GPU_COMMAND"),
        _ => None,
    }
}

fn mali_ioctl_name(cmd: u32) -> Option<&'static str> {
    match cmd & 0xff {
        0x00 => Some("KBASE_IOCTL_VERSION_CHECK"),
        0x01 => Some("KBASE_IOCTL_SET_FLAGS"),
        0x02 => Some("KBASE_IOCTL_MEM_ALLOC"),
        0x03 => Some("KBASE_IOCTL_MEM_QUERY"),
        0x04 => Some("KBASE_IOCTL_MEM_FREE"),
        0x05 => Some("KBASE_IOCTL_HWCNT_READER_SETUP"),
        0x06 => Some("KBASE_IOCTL_TLSTREAM_ACQUIRE"),
        0x07 => Some("KBASE_IOCTL_TLSTREAM_FLUSH"),
        0x08 => Some("KBASE_IOCTL_JIT_INIT"),
        0x09 => Some("KBASE_IOCTL_MEM_JIT_INIT"),
        _ => None,
    }
}

fn alsa_ioctl_name(cmd: u32) -> Option<&'static str> {
    let nr = cmd & 0xff;
    match neutron_common::ioctl_type(cmd) {
        neutron_common::IOCTL_TYPE_ALSA_PCM => match nr {
            0x00 => Some("SNDRV_PCM_IOCTL_PVERSION"),
            0x10 => Some("SNDRV_PCM_IOCTL_INFO"),
            0x11 => Some("SNDRV_PCM_IOCTL_TSTAMP"),
            0x20 => Some("SNDRV_PCM_IOCTL_HW_REFINE"),
            0x21 => Some("SNDRV_PCM_IOCTL_HW_PARAMS"),
            0x22 => Some("SNDRV_PCM_IOCTL_HW_FREE"),
            _ => Some("SNDRV_PCM_IOCTL"),
        },
        neutron_common::IOCTL_TYPE_ALSA_CTL => Some("SNDRV_CTL_IOCTL"),
        neutron_common::IOCTL_TYPE_ALSA_HWDEP => Some("SNDRV_HWDEP_IOCTL"),
        neutron_common::IOCTL_TYPE_ALSA_RAWMIDI => Some("SNDRV_RAWMIDI_IOCTL"),
        neutron_common::IOCTL_TYPE_ALSA_TIMER => Some("SNDRV_TIMER_IOCTL"),
        neutron_common::IOCTL_TYPE_ALSA_SEQ => Some("SNDRV_SEQ_IOCTL"),
        neutron_common::IOCTL_TYPE_ALSA_COMPRESS => Some("SNDRV_COMPRESS_IOCTL"),
        _ => None,
    }
}

fn read_u64_at(payload: &[u8], off: usize) -> u64 {
    if payload.len() < off + 8 {
        return 0;
    }
    u64::from_le_bytes(payload[off..off + 8].try_into().unwrap())
}

fn decode_binder_write_read(payload: &[u8]) -> IoctlFields {
    if payload.len() < 40 {
        return IoctlFields::None;
    }
    IoctlFields::BinderWriteRead {
        write_size: read_u64_at(payload, 0),
        write_consumed: read_u64_at(payload, 8),
        read_size: read_u64_at(payload, 24),
        read_consumed: read_u64_at(payload, 32),
    }
}

fn decode_driver_scalars(payload: &[u8]) -> IoctlFields {
    if payload.len() < 32 {
        return IoctlFields::None;
    }
    IoctlFields::DriverScalars {
        arg0: read_u64_at(payload, 0),
        arg1: read_u64_at(payload, 8),
        arg2: read_u64_at(payload, 16),
        arg3: read_u64_at(payload, 24),
    }
}

fn decode_alsa(payload: &[u8], ret: i64) -> IoctlFields {
    if payload.len() < 16 {
        return IoctlFields::None;
    }
    IoctlFields::Alsa {
        compat_candidate: ret < 0,
        arg0: read_u64_at(payload, 0),
        arg1: read_u64_at(payload, 8),
    }
}

/// Decode a `struct dma_heap_allocation_data` from a captured payload.
fn decode_dma_heap_alloc(payload: &[u8]) -> IoctlFields {
    if payload.len() < 24 {
        return IoctlFields::None;
    }
    let len = u64::from_le_bytes(payload[0..8].try_into().unwrap());
    let fd = i32::from_le_bytes(payload[8..12].try_into().unwrap());
    let fd_flags = u32::from_le_bytes(payload[12..16].try_into().unwrap());
    let heap_flags = u64::from_le_bytes(payload[16..24].try_into().unwrap());
    IoctlFields::DmaHeapAlloc {
        len,
        returned_fd: fd,
        fd_flags,
        heap_flags,
    }
}

/// Render the optional `O_RDONLY|O_RDWR|...|O_CLOEXEC` string for a
/// `dma_heap_allocation_data.fd_flags` value. The dma-heap allocator only
/// honours `O_ACCMODE | O_CLOEXEC`, so a tiny lookup is sufficient.
fn fd_flags_as_str(flags: u32) -> String {
    let mut parts: Vec<&'static str> = Vec::with_capacity(2);
    parts.push(match flags & 0x3 {
        0 => "O_RDONLY",
        1 => "O_WRONLY",
        2 => "O_RDWR",
        _ => "O_ACCMODE3",
    });
    // O_CLOEXEC = 0o2000000 = 0x80000 on aarch64 Linux.
    if flags & 0x80000 != 0 {
        parts.push("O_CLOEXEC");
    }
    parts.join("|")
}

/// Render the JSON suffix for a [`DecodedIoctl`] to be spliced into an
/// NDJSON line — the leading commas and field names are included so the
/// caller can concatenate without further glue. Returns an empty string
/// when the family is `Unknown` AND no name/fields are populated.
pub fn render_decoded_ioctl_json(d: &DecodedIoctl) -> String {
    let mut out = render_decoded_ioctl_identity_json(d);
    render_decoded_ioctl_fields_json(d, &mut out);
    out
}

/// Render only command-derived ioctl identity. This is safe when the BPF
/// payload read failed: family and name come from the command/fd context,
/// while all payload-derived scalar objects remain suppressed.
pub fn render_decoded_ioctl_identity_json(d: &DecodedIoctl) -> String {
    let mut out = String::new();
    if d.family != IoctlFamily::Unknown {
        out.push_str(r#","ioctl_family":""#);
        out.push_str(d.family.as_str());
        out.push('"');
    } else if let Some(family) = d.generated.as_ref().and_then(|d| d.family.as_deref()) {
        out.push_str(r#","ioctl_family":"#);
        out.push_str(&serde_json::to_string(family).expect("serializing ioctl family"));
    }
    if let Some(name) = &d.name {
        out.push_str(r#","ioctl_name":"#);
        out.push_str(&serde_json::to_string(name).expect("serializing ioctl name"));
    }
    out
}

fn render_decoded_ioctl_fields_json(d: &DecodedIoctl, out: &mut String) {
    match &d.fields {
        IoctlFields::DmaHeapAlloc {
            len,
            returned_fd,
            fd_flags,
            heap_flags,
        } => {
            out.push_str(&format!(
                r#","dma_heap":{{"len":{},"returned_fd":{},"fd_flags":{},"fd_flags_str":"{}","heap_flags":{}}}"#,
                len,
                returned_fd,
                fd_flags,
                fd_flags_as_str(*fd_flags),
                heap_flags,
            ));
        }
        IoctlFields::BinderWriteRead {
            write_size,
            write_consumed,
            read_size,
            read_consumed,
        } => {
            out.push_str(&format!(
                r#","binder_write_read":{{"write_size":{},"write_consumed":{},"read_size":{},"read_consumed":{}}}"#,
                write_size, write_consumed, read_size, read_consumed,
            ));
        }
        IoctlFields::DriverScalars {
            arg0,
            arg1,
            arg2,
            arg3,
        } => {
            let key = match d.family {
                IoctlFamily::Kgsl => "kgsl",
                IoctlFamily::Mali => "mali",
                _ => "driver_ioctl",
            };
            out.push_str(&format!(
                r#","{}":{{"arg0":{},"arg1":{},"arg2":{},"arg3":{}}}"#,
                key, arg0, arg1, arg2, arg3,
            ));
        }
        IoctlFields::Alsa {
            compat_candidate,
            arg0,
            arg1,
        } => {
            out.push_str(&format!(
                r#","alsa":{{"compat_candidate":{},"arg0":{},"arg1":{}}}"#,
                compat_candidate, arg0, arg1,
            ));
        }
        IoctlFields::LwisCmdPkt {
            cmd_id,
            cmd_id_name,
        } => {
            out.push_str(&format!(r#","lwis":{{"cmd_id":{cmd_id}"#));
            if let Some(name) = cmd_id_name {
                out.push_str(&format!(r#","cmd_id_name":"{name}""#));
            }
            out.push('}');
        }
        IoctlFields::None => {}
    }
    if let Some(generated) = &d.generated {
        out.push_str(r#","ioctl_fields":"#);
        out.push_str(
            &serde_json::to_string(&generated.fields).expect("serializing generated ioctl fields"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buf_with_cmd(cmd: u32) -> [u8; 128] {
        let mut buf = [0u8; 128];
        buf[..4].copy_from_slice(&cmd.to_le_bytes());
        buf
    }

    #[test]
    fn format_ioctl_deep_preserves_binder_dma_buf_ambiguity_without_fd_context() {
        // type='b' (0x62), nr=0, size=4, dir=W(1)
        // dir is the top 2 bits in 32-bit cmd: 1 << 30 = 0x40000000
        // size in bits 16..30 (14 bits): 4 << 16 = 0x00040000
        // nr (low byte) is 0; clippy::identity_op flags `| 0`, so we omit it.
        let cmd: u32 = (1 << 30) | (4 << 16) | (0x62 << 8);
        let buf = buf_with_cmd(cmd);
        let s = format_ioctl_deep(&buf);
        assert_eq!(s, "binder_or_dma_buf:_IOC(W,0,4)");
    }

    #[test]
    fn format_ioctl_deep_recognizes_ashmem_device() {
        // type='w' (0x77), no size/dir, no payload
        let cmd: u32 = (0x77u32) << 8;
        let buf = buf_with_cmd(cmd);
        let s = format_ioctl_deep(&buf);
        assert!(s.starts_with("ashmem:"), "got {}", s);
    }

    #[test]
    fn format_ioctl_deep_unknown_device_falls_back_to_ioc_form() {
        // type=0xab (unknown), nr=5, size=8, dir=R(2)
        let cmd: u32 = (2u32 << 30) | (8u32 << 16) | (0xabu32 << 8) | 5;
        let buf = buf_with_cmd(cmd);
        let s = format_ioctl_deep(&buf);
        assert!(s.starts_with("_IOC("), "got {}", s);
        assert!(s.contains("0xab"), "got {}", s);
    }

    #[test]
    fn format_ioctl_deep_includes_payload_when_nonzero() {
        // type='b' Binder/dma-buf collision + payload bytes after byte 4
        let cmd: u32 = (0x62u32) << 8;
        let mut buf = buf_with_cmd(cmd);
        buf[4] = 0xde;
        buf[5] = 0xad;
        buf[6] = 0xbe;
        buf[7] = 0xef;
        let s = format_ioctl_deep(&buf);
        assert!(s.contains("payload="), "got {}", s);
        assert!(s.contains("deadbeef"), "got {}", s);
    }

    #[test]
    fn format_ioctl_deep_unknown_with_payload() {
        let cmd: u32 = (0xabu32) << 8;
        let mut buf = buf_with_cmd(cmd);
        buf[4] = 0x11;
        let s = format_ioctl_deep(&buf);
        assert!(s.contains("payload="), "got {}", s);
    }

    // ── Decoder registry tests (sprint 1, PR 2) ──────────────────────────────

    /// Build a 24-byte `dma_heap_allocation_data` payload with the supplied
    /// fields. Mirrors the exact wire layout the kernel populates.
    fn dma_heap_payload(len: u64, fd: i32, fd_flags: u32, heap_flags: u64) -> Vec<u8> {
        let mut p = Vec::with_capacity(24);
        p.extend_from_slice(&len.to_le_bytes());
        p.extend_from_slice(&fd.to_le_bytes());
        p.extend_from_slice(&fd_flags.to_le_bytes());
        p.extend_from_slice(&heap_flags.to_le_bytes());
        p
    }

    #[test]
    fn ioctl_family_classifies_dma_heap_by_type_byte() {
        // Any cmd with type=0x48 must classify as DmaHeap regardless of fd_kind.
        let cmd = 0xC018_4800; // DMA_HEAP_IOCTL_ALLOC
        assert_eq!(IoctlFamily::from_cmd(cmd, None), IoctlFamily::DmaHeap);
        assert_eq!(
            IoctlFamily::from_cmd(cmd, Some(FdKind::Device)),
            IoctlFamily::DmaHeap
        );
    }

    #[test]
    fn ioctl_family_disambiguates_b_magic_via_fd_kind() {
        // type=0x62 collides between binder and dma-buf. With a Binder fd it
        // resolves to Binder; an absent hint must preserve the ambiguity.
        let cmd = (3u32 << 30) | (48u32 << 16) | (0x62u32 << 8) | 1; // BINDER_WRITE_READ
        assert_eq!(
            IoctlFamily::from_cmd(cmd, Some(FdKind::Binder)),
            IoctlFamily::Binder
        );
        assert_eq!(
            IoctlFamily::from_cmd(cmd, Some(FdKind::File)),
            IoctlFamily::DmaBuf
        );
        assert_eq!(
            IoctlFamily::from_cmd(cmd, None).as_str(),
            "binder_or_dma_buf"
        );
    }

    #[test]
    fn ioctl_family_unknown_for_unrecognised_type() {
        let cmd = (3u32 << 30) | (8u32 << 16) | (0xabu32 << 8) | 5;
        assert_eq!(IoctlFamily::from_cmd(cmd, None), IoctlFamily::Unknown);
    }

    #[test]
    fn decode_dma_heap_alloc_returns_typed_fields() {
        let payload = dma_heap_payload(4096, 32, 0x80002, 0);
        let decoded = decode_ioctl(0xC018_4800, &payload, 0, None);
        assert_eq!(decoded.family, IoctlFamily::DmaHeap);
        assert_eq!(decoded.name.as_deref(), Some("DMA_HEAP_IOCTL_ALLOC"));
        match decoded.fields {
            IoctlFields::DmaHeapAlloc {
                len,
                returned_fd,
                fd_flags,
                heap_flags,
            } => {
                assert_eq!(len, 4096);
                assert_eq!(returned_fd, 32);
                assert_eq!(fd_flags, 0x80002);
                assert_eq!(heap_flags, 0);
            }
            other => panic!("expected DmaHeapAlloc fields, got {other:?}"),
        }
    }

    #[test]
    fn decode_dma_heap_alloc_handles_truncated_payload() {
        // BPF capture of less than 24 bytes (legitimate when the ring is
        // under pressure) must not panic — the decoder returns IoctlFields::None.
        let short = [0u8; 16];
        let decoded = decode_ioctl(0xC018_4800, &short, 0, None);
        assert_eq!(decoded.family, IoctlFamily::DmaHeap);
        assert_eq!(decoded.name.as_deref(), Some("DMA_HEAP_IOCTL_ALLOC"));
        assert_eq!(decoded.fields, IoctlFields::None);
    }

    #[test]
    fn decode_unrecognised_cmd_yields_unknown_family_no_fields() {
        let decoded = decode_ioctl(0xDEAD_BEEF, &[0u8; 32], 0, None);
        assert_eq!(decoded.family, IoctlFamily::Unknown);
        assert_eq!(decoded.name, None);
        assert_eq!(decoded.fields, IoctlFields::None);
    }

    #[test]
    fn render_decoded_dma_heap_alloc_emits_nested_object() {
        let payload = dma_heap_payload(8192, 42, 0x80002, 1);
        let decoded = decode_ioctl(0xC018_4800, &payload, 0, None);
        let json_suffix = render_decoded_ioctl_json(&decoded);
        // Wrap into a complete object so we can parse-and-assert by key.
        let line = format!("{{\"x\":1{}}}", json_suffix);
        let v: serde_json::Value = serde_json::from_str(&line).expect("valid json");
        assert_eq!(
            v.get("ioctl_family").and_then(|x| x.as_str()),
            Some("dma_heap")
        );
        assert_eq!(
            v.get("ioctl_name").and_then(|x| x.as_str()),
            Some("DMA_HEAP_IOCTL_ALLOC")
        );
        let dh = v
            .get("dma_heap")
            .and_then(|x| x.as_object())
            .expect("dma_heap object");
        assert_eq!(dh.get("len").and_then(|x| x.as_u64()), Some(8192));
        assert_eq!(dh.get("returned_fd").and_then(|x| x.as_i64()), Some(42));
        assert_eq!(dh.get("fd_flags").and_then(|x| x.as_u64()), Some(0x80002));
        assert_eq!(
            dh.get("fd_flags_str").and_then(|x| x.as_str()),
            Some("O_RDWR|O_CLOEXEC")
        );
        assert_eq!(dh.get("heap_flags").and_then(|x| x.as_u64()), Some(1));
    }

    #[test]
    fn render_decoded_unknown_emits_nothing() {
        let decoded = DecodedIoctl {
            family: IoctlFamily::Unknown,
            name: None,
            fields: IoctlFields::None,
            generated: None,
        };
        assert_eq!(render_decoded_ioctl_json(&decoded), "");
    }

    #[test]
    fn render_decoded_family_only_emits_just_family() {
        // A non-BWR binder ioctl still renders as family-only.
        let cmd = (3u32 << 30) | (48u32 << 16) | (0x62u32 << 8) | 1;
        let decoded = decode_ioctl(cmd + 1, &[0u8; 48], 0, Some(FdKind::Binder));
        let json = render_decoded_ioctl_json(&decoded);
        assert_eq!(json, r#","ioctl_family":"binder""#);
    }

    #[test]
    fn fd_flags_as_str_decodes_common_combinations() {
        assert_eq!(fd_flags_as_str(0), "O_RDONLY");
        assert_eq!(fd_flags_as_str(2), "O_RDWR");
        assert_eq!(fd_flags_as_str(0x80002), "O_RDWR|O_CLOEXEC");
        assert_eq!(fd_flags_as_str(0x80000), "O_RDONLY|O_CLOEXEC");
        assert_eq!(fd_flags_as_str(1), "O_WRONLY");
    }

    // ── Decoder pack expansion (Phase 3) ─────────────────────────────────────

    fn lwis_payload(cmd_id: u32) -> Vec<u8> {
        let mut p = vec![0u8; 16];
        p[..4].copy_from_slice(&cmd_id.to_le_bytes());
        p
    }

    #[test]
    fn ioctl_family_classifies_lwis_by_type_byte() {
        // Any cmd with type=0x4c classifies as Lwis regardless of fd_kind.
        let cmd = LWIS_CMD_PACKET;
        assert_eq!(IoctlFamily::from_cmd(cmd, None), IoctlFamily::Lwis);
        assert_eq!(
            IoctlFamily::from_cmd(cmd, Some(FdKind::Binder)),
            IoctlFamily::Lwis,
        );
    }

    #[test]
    fn ioctl_family_classifies_gxp_for_both_type_bytes() {
        // Upstream 'G' (0x47) and Pixel 0xee both surface as Gxp.
        let cmd_upstream = (3u32 << 30) | (16u32 << 16) | (0x47u32 << 8) | 1;
        let cmd_pixel = (3u32 << 30) | (16u32 << 16) | (0xeeu32 << 8) | 1;
        assert_eq!(IoctlFamily::from_cmd(cmd_upstream, None), IoctlFamily::Gxp);
        assert_eq!(IoctlFamily::from_cmd(cmd_pixel, None), IoctlFamily::Gxp);
    }

    #[test]
    fn decode_lwis_cmd_packet_resolves_known_id() {
        let payload = lwis_payload(0x10100);
        let decoded = decode_ioctl(LWIS_CMD_PACKET, &payload, 0, None);
        assert_eq!(decoded.family, IoctlFamily::Lwis);
        assert_eq!(decoded.name.as_deref(), Some("LWIS_CMD_PACKET"));
        match decoded.fields {
            IoctlFields::LwisCmdPkt {
                cmd_id,
                cmd_id_name,
            } => {
                assert_eq!(cmd_id, 0x10100);
                assert_eq!(cmd_id_name, Some("DEVICE_ENABLE"));
            }
            other => panic!("expected LwisCmdPkt, got {other:?}"),
        }
    }

    #[test]
    fn decode_lwis_cmd_packet_keeps_unknown_id_as_none_name() {
        // 0x20200 was observed in the assessment but isn't on the
        // documented-name list — we keep the raw id, name=None.
        let payload = lwis_payload(0x20200);
        let decoded = decode_ioctl(LWIS_CMD_PACKET, &payload, 0, None);
        match decoded.fields {
            IoctlFields::LwisCmdPkt {
                cmd_id,
                cmd_id_name,
            } => {
                assert_eq!(cmd_id, 0x20200);
                assert_eq!(cmd_id_name, None);
            }
            other => panic!("expected LwisCmdPkt, got {other:?}"),
        }
    }

    #[test]
    fn decode_lwis_handles_truncated_payload() {
        let decoded = decode_ioctl(LWIS_CMD_PACKET, &[0u8; 2], 0, None);
        assert_eq!(decoded.family, IoctlFamily::Lwis);
        assert_eq!(decoded.name.as_deref(), Some("LWIS_CMD_PACKET"));
        assert_eq!(decoded.fields, IoctlFields::None);
    }

    #[test]
    fn render_decoded_lwis_emits_nested_object_with_known_name() {
        let payload = lwis_payload(0x10200);
        let decoded = decode_ioctl(LWIS_CMD_PACKET, &payload, 0, None);
        let json_suffix = render_decoded_ioctl_json(&decoded);
        let line = format!("{{\"x\":1{}}}", json_suffix);
        let v: serde_json::Value = serde_json::from_str(&line).expect("valid json");
        assert_eq!(v.get("ioctl_family").and_then(|x| x.as_str()), Some("lwis"));
        assert_eq!(
            v.get("ioctl_name").and_then(|x| x.as_str()),
            Some("LWIS_CMD_PACKET"),
        );
        let lwis = v
            .get("lwis")
            .and_then(|x| x.as_object())
            .expect("lwis object");
        assert_eq!(lwis.get("cmd_id").and_then(|x| x.as_u64()), Some(0x10200));
        assert_eq!(
            lwis.get("cmd_id_name").and_then(|x| x.as_str()),
            Some("DEVICE_DISABLE"),
        );
    }

    #[test]
    fn render_decoded_lwis_omits_name_when_unknown() {
        let payload = lwis_payload(0x40200);
        let decoded = decode_ioctl(LWIS_CMD_PACKET, &payload, 0, None);
        let json_suffix = render_decoded_ioctl_json(&decoded);
        let line = format!("{{\"x\":1{}}}", json_suffix);
        let v: serde_json::Value = serde_json::from_str(&line).expect("valid json");
        let lwis = v.get("lwis").and_then(|x| x.as_object()).unwrap();
        assert_eq!(lwis.get("cmd_id").and_then(|x| x.as_u64()), Some(0x40200));
        assert!(
            lwis.get("cmd_id_name").is_none(),
            "unknown id must not synthesise a placeholder name"
        );
    }

    #[test]
    fn lwis_cmd_id_name_covers_documented_set() {
        // Names lifted directly from the assessment / Pixel LWIS userspace HAL.
        for (id, expected) in [
            (0x10100, "DEVICE_ENABLE"),
            (0x10200, "DEVICE_DISABLE"),
            (0x20300, "DMA_BUFFER_ALLOC"),
            (0x20400, "DMA_BUFFER_FREE"),
        ] {
            assert_eq!(lwis_cmd_id_name(id), Some(expected));
        }
        assert_eq!(lwis_cmd_id_name(0xdead_beef), None);
    }

    // ── BPF driver-pack decoders ────────────────────────────────────────────

    fn binder_write_read_payload(
        write_size: u64,
        write_consumed: u64,
        read_size: u64,
        read_consumed: u64,
    ) -> Vec<u8> {
        let mut p = vec![0u8; 48];
        p[0..8].copy_from_slice(&write_size.to_le_bytes());
        p[8..16].copy_from_slice(&write_consumed.to_le_bytes());
        p[24..32].copy_from_slice(&read_size.to_le_bytes());
        p[32..40].copy_from_slice(&read_consumed.to_le_bytes());
        p
    }

    #[test]
    fn decode_binder_write_read_returns_scalar_summary() {
        let cmd = (3u32 << 30) | (48u32 << 16) | (0x62u32 << 8) | 1;
        let decoded = decode_ioctl(
            cmd,
            &binder_write_read_payload(16, 8, 32, 4),
            0,
            Some(FdKind::Binder),
        );
        assert_eq!(decoded.family, IoctlFamily::Binder);
        assert_eq!(decoded.name.as_deref(), Some("BINDER_WRITE_READ"));
        match decoded.fields {
            IoctlFields::BinderWriteRead {
                write_size,
                write_consumed,
                read_size,
                read_consumed,
            } => {
                assert_eq!(write_size, 16);
                assert_eq!(write_consumed, 8);
                assert_eq!(read_size, 32);
                assert_eq!(read_consumed, 4);
            }
            other => panic!("expected BinderWriteRead fields, got {other:?}"),
        }
        let json = render_decoded_ioctl_json(&decoded);
        let v: serde_json::Value = serde_json::from_str(&format!("{{\"x\":1{json}}}")).unwrap();
        assert_eq!(v["binder_write_read"]["write_size"], 16);
        assert_eq!(v["binder_write_read"]["read_consumed"], 4);
    }

    #[test]
    fn decode_kgsl_mali_and_alsa_driver_families_with_scalar_fields() {
        let kgsl_cmd = (3u32 << 30) | (32u32 << 16) | (0x09u32 << 8) | 0x2f;
        let mut kgsl_payload = vec![0u8; 32];
        kgsl_payload[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        kgsl_payload[8..16].copy_from_slice(&0x2000u64.to_le_bytes());
        let kgsl = decode_ioctl_with_context(
            kgsl_cmd,
            &kgsl_payload,
            -22,
            Some(FdKind::Device),
            Some("/dev/kgsl-3d0"),
        );
        assert_eq!(kgsl.family, IoctlFamily::Kgsl);
        assert_eq!(kgsl.name.as_deref(), Some("IOCTL_KGSL_GPUMEM_ALLOC"));
        assert!(matches!(kgsl.fields, IoctlFields::DriverScalars { .. }));

        let mali_cmd = (3u32 << 30) | (16u32 << 16) | (0x80u32 << 8);
        let mali = decode_ioctl_with_context(
            mali_cmd,
            &[0u8; 16],
            0,
            Some(FdKind::Device),
            Some("/dev/mali0"),
        );
        assert_eq!(mali.family, IoctlFamily::Mali);
        assert_eq!(mali.name.as_deref(), Some("KBASE_IOCTL_VERSION_CHECK"));

        let alsa_cmd = (3u32 << 30) | (32u32 << 16) | (0x50u32 << 8) | 0x10;
        let alsa = decode_ioctl_with_context(
            alsa_cmd,
            &[0u8; 32],
            -25,
            Some(FdKind::Device),
            Some("/dev/snd/pcmC0D0p"),
        );
        assert_eq!(alsa.family, IoctlFamily::Alsa);
        assert!(alsa.name.is_some());
        let json = render_decoded_ioctl_json(&alsa);
        let v: serde_json::Value = serde_json::from_str(&format!("{{\"x\":1{json}}}")).unwrap();
        assert_eq!(v["alsa"]["compat_candidate"], true);
    }

    #[test]
    fn fixed_scalar_schemas_do_not_fabricate_fields_from_short_payloads() {
        let kgsl_cmd = (3u32 << 30) | (16u32 << 16) | (0x09u32 << 8) | 0x2f;
        let kgsl = decode_ioctl_with_context(
            kgsl_cmd,
            &[0u8; 16],
            -22,
            Some(FdKind::Device),
            Some("/dev/kgsl-3d0"),
        );
        assert_eq!(kgsl.family, IoctlFamily::Kgsl);
        assert_eq!(kgsl.fields, IoctlFields::None);
        let rendered = render_decoded_ioctl_json(&kgsl);
        assert!(!rendered.contains("arg0"));

        let alsa_cmd = (3u32 << 30) | (8u32 << 16) | (0x50u32 << 8) | 0x10;
        let alsa = decode_ioctl_with_context(
            alsa_cmd,
            &[0u8; 8],
            -25,
            Some(FdKind::Device),
            Some("/dev/snd/pcmC0D0p"),
        );
        assert_eq!(alsa.family, IoctlFamily::Alsa);
        assert_eq!(alsa.fields, IoctlFields::None);
        let rendered = render_decoded_ioctl_json(&alsa);
        assert!(!rendered.contains("compat_candidate"));
        assert!(!rendered.contains("arg0"));
    }
}
