//! ioctl() argument decoding (cmd + payload).
//!
//! Two layers:
//!
//! - [`format_ioctl_deep`] — the original device-agnostic `_IOC` decomposition
//!   used by the human-readable text formatter. Stable since v1.0.
//! - [`decode_ioctl`] — sprint-1 PR 2 decoder registry that returns a typed
//!   [`DecodedIoctl`] for known commands (today only `DMA_HEAP_IOCTL_ALLOC`
//!   carries field-level decoding; binder / dma-buf / ashmem are classified
//!   to [`IoctlFamily`] only). [`render_decoded_ioctl_json`] emits the
//!   matching JSON fragment that the NDJSON formatter splices into the line.
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
        0x62 => "binder", // 'b'
        0x77 => "ashmem", // 'w' (0x77)
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
    Binder,
    Ashmem,
    Unknown,
}

impl IoctlFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            IoctlFamily::DmaHeap => "dma_heap",
            IoctlFamily::DmaBuf => "dma_buf",
            IoctlFamily::Binder => "binder",
            IoctlFamily::Ashmem => "ashmem",
            IoctlFamily::Unknown => "unknown",
        }
    }

    /// Classify by `_IOC_TYPE` byte. The `'b'` (0x62) magic is reused by
    /// both binder and dma-buf in the kernel headers — they only diverge by
    /// the file_operations of the target fd. We use the FD-graph kind as the
    /// disambiguator: `Binder` fd → binder, anything else → dma-buf.
    pub fn from_cmd(cmd: u32, fd_kind: Option<FdKind>) -> Self {
        let ty = neutron_common::ioctl_type(cmd);
        match ty {
            t if t == neutron_common::IOCTL_TYPE_DMA_HEAP => IoctlFamily::DmaHeap,
            t if t == neutron_common::IOCTL_TYPE_BINDER_OR_DMA_BUF => match fd_kind {
                Some(FdKind::Binder) => IoctlFamily::Binder,
                _ => IoctlFamily::DmaBuf,
            },
            t if t == neutron_common::IOCTL_TYPE_ASHMEM => IoctlFamily::Ashmem,
            _ => IoctlFamily::Unknown,
        }
    }
}

/// Output of [`decode_ioctl`]. `family` is always set; `name` is the
/// human-readable command identifier when recognised; `fields` is the
/// typed payload view (only `DmaHeapAlloc` is decoded today).
#[derive(Debug, Clone)]
pub struct DecodedIoctl {
    pub family: IoctlFamily,
    pub name: Option<&'static str>,
    pub fields: IoctlFields,
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
    None,
}

/// `_IOC` command for `DMA_HEAP_IOCTL_ALLOC = _IOWR('H', 0x0, struct dma_heap_allocation_data)`.
/// `dir = 3 (RW), size = 24, type = 0x48 ('H'), nr = 0`.
const DMA_HEAP_IOCTL_ALLOC: u32 = 0xC018_4800;

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
    let family = IoctlFamily::from_cmd(cmd, fd_kind);
    let (name, fields) = match cmd {
        DMA_HEAP_IOCTL_ALLOC => (Some("DMA_HEAP_IOCTL_ALLOC"), decode_dma_heap_alloc(payload)),
        _ => (None, IoctlFields::None),
    };
    DecodedIoctl {
        family,
        name,
        fields,
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
    let mut out = String::new();
    if d.family != IoctlFamily::Unknown {
        out.push_str(r#","ioctl_family":""#);
        out.push_str(d.family.as_str());
        out.push('"');
    }
    if let Some(name) = d.name {
        out.push_str(r#","ioctl_name":""#);
        out.push_str(name);
        out.push('"');
    }
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
        IoctlFields::None => {}
    }
    out
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
    fn format_ioctl_deep_recognizes_binder_device() {
        // type='b' (0x62), nr=0, size=4, dir=W(1)
        // dir is the top 2 bits in 32-bit cmd: 1 << 30 = 0x40000000
        // size in bits 16..30 (14 bits): 4 << 16 = 0x00040000
        // nr (low byte) is 0; clippy::identity_op flags `| 0`, so we omit it.
        let cmd: u32 = (1 << 30) | (4 << 16) | (0x62 << 8);
        let buf = buf_with_cmd(cmd);
        let s = format_ioctl_deep(&buf);
        assert_eq!(s, "binder:_IOC(W,0,4)");
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
        // type='b' binder + payload bytes after byte 4
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
        // resolves to Binder; with anything else it falls back to DmaBuf.
        let cmd = (3u32 << 30) | (48u32 << 16) | (0x62u32 << 8) | 1; // BINDER_WRITE_READ
        assert_eq!(
            IoctlFamily::from_cmd(cmd, Some(FdKind::Binder)),
            IoctlFamily::Binder
        );
        assert_eq!(
            IoctlFamily::from_cmd(cmd, Some(FdKind::File)),
            IoctlFamily::DmaBuf
        );
        assert_eq!(IoctlFamily::from_cmd(cmd, None), IoctlFamily::DmaBuf);
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
        assert_eq!(decoded.name, Some("DMA_HEAP_IOCTL_ALLOC"));
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
        assert_eq!(decoded.name, Some("DMA_HEAP_IOCTL_ALLOC"));
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
        };
        assert_eq!(render_decoded_ioctl_json(&decoded), "");
    }

    #[test]
    fn render_decoded_family_only_emits_just_family() {
        // BINDER_WRITE_READ classified via fd_kind=Binder, no payload decoder yet.
        let cmd = (3u32 << 30) | (48u32 << 16) | (0x62u32 << 8) | 1;
        let decoded = decode_ioctl(cmd, &[0u8; 48], 0, Some(FdKind::Binder));
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
}
