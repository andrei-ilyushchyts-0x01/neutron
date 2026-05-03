//! ioctl() argument decoding (cmd + payload).

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
        let cmd: u32 = (1 << 30) | (4 << 16) | (0x62 << 8) | 0;
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
}
