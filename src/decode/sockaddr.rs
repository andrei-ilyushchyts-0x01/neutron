//! sockaddr decoding (in-event payload + /proc/net inode lookup).

use std::fs;

/// Decode a sockaddr from `data[128]`. Returns "AF_INET 1.2.3.4:80" etc.
pub fn format_sockaddr(raw: &[u8; 128]) -> Option<String> {
    if raw[0] == 0 && raw[1] == 0 {
        return None;
    }
    let family = u16::from_le_bytes([raw[0], raw[1]]);
    match family {
        2 => {
            // AF_INET: port(2 bytes BE) + addr(4 bytes)
            if raw.len() < 8 {
                return None;
            }
            let port = u16::from_be_bytes([raw[2], raw[3]]);
            let addr = format!("{}.{}.{}.{}", raw[4], raw[5], raw[6], raw[7]);
            Some(format!("AF_INET {}:{}", addr, port))
        }
        10 => {
            // AF_INET6: port(2 BE) + flowinfo(4) + addr(16)
            if raw.len() < 28 {
                return None;
            }
            let port = u16::from_be_bytes([raw[2], raw[3]]);
            let mut segs = [0u16; 8];
            for i in 0..8 {
                segs[i] = u16::from_be_bytes([raw[8 + i * 2], raw[9 + i * 2]]);
            }
            let addr = segs
                .iter()
                .map(|s| format!("{:x}", s))
                .collect::<Vec<_>>()
                .join(":");
            Some(format!("AF_INET6 [{}]:{}", addr, port))
        }
        1 => {
            // AF_UNIX: path starts at offset 2
            let path_bytes = &raw[2..];
            let end = path_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(path_bytes.len());
            if end == 0 {
                // Abstract socket: first byte is 0, name follows
                if raw.len() > 3 && raw[3] != 0 {
                    let aend = raw[3..]
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(raw.len() - 3);
                    let name = String::from_utf8_lossy(&raw[3..3 + aend]);
                    return Some(format!("AF_UNIX @{}", name));
                }
                return Some("AF_UNIX (abstract)".to_string());
            }
            let path = String::from_utf8_lossy(&path_bytes[..end]);
            Some(format!("AF_UNIX {}", path))
        }
        _ => Some(format!(
            "AF_?({}) {:02x}{:02x}{:02x}{:02x}...",
            family, raw[2], raw[3], raw[4], raw[5]
        )),
    }
}

/// Decode only fields covered by the syscall-declared sockaddr length. This
/// prevents zero-filled bytes beyond a short user buffer from becoming
/// fabricated address/port evidence.
pub fn format_sockaddr_bounded(raw: &[u8; 128], declared_len: usize) -> Option<String> {
    let captured_len = declared_len.min(raw.len());
    if captured_len < 2 {
        return None;
    }
    let family = u16::from_le_bytes([raw[0], raw[1]]);
    let required = match family {
        1 => 2,   // AF_UNIX has a variable-length name after sa_family.
        2 => 8,   // family + port + IPv4 address are the rendered fields.
        10 => 28, // canonical sockaddr_in6, including scope-id boundary.
        _ => 6,   // unknown-family preview renders four bytes after family.
    };
    if captured_len < required {
        return None;
    }
    let mut bounded = *raw;
    bounded[captured_len..].fill(0);
    format_sockaddr(&bounded)
}

/// Read the socket inode from `/proc/<pid>/fd/<fd>`. Symlink target format:
/// `socket:[<inode>]`.
pub fn read_socket_inode(pid: u32, fd: i64) -> Option<u64> {
    if fd < 0 {
        return None;
    }
    let target = fs::read_link(format!("/proc/{}/fd/{}", pid, fd)).ok()?;
    let s = target.to_string_lossy();
    let s = s.strip_prefix("socket:[")?;
    let s = s.strip_suffix(']')?;
    s.parse::<u64>().ok()
}

/// Parse an address string from `/proc/net/tcp` (`tcp6`).
/// IPv4: `HHHHHHHH:PPPP` (8 hex chars = LE u32, colon, 4 hex = port).
/// IPv6: 32 hex chars + colon + 4 hex.
pub fn parse_net_addr(addr_str: &str, is_v6: bool) -> Option<String> {
    let (addr_hex, port_hex) = addr_str.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if !is_v6 {
        if addr_hex.len() != 8 {
            return None;
        }
        let v = u32::from_str_radix(addr_hex, 16).ok()?;
        // /proc/net/tcp stores IPv4 in host byte order (little-endian on ARM64)
        Some(format!(
            "AF_INET {}.{}.{}.{}:{}",
            v & 0xff,
            (v >> 8) & 0xff,
            (v >> 16) & 0xff,
            v >> 24,
            port
        ))
    } else {
        if addr_hex.len() != 32 {
            return None;
        }
        let mut segs = [0u16; 8];
        for i in 0..4 {
            let w = u32::from_str_radix(&addr_hex[i * 8..(i + 1) * 8], 16).ok()?;
            segs[i * 2] = ((w & 0xff) << 8 | (w >> 8) & 0xff) as u16;
            segs[i * 2 + 1] = ((w >> 16 & 0xff) << 8 | (w >> 24) & 0xff) as u16;
        }
        let addr = segs
            .iter()
            .map(|s| format!("{:x}", s))
            .collect::<Vec<_>>()
            .join(":");
        Some(format!("AF_INET6 [{}]:{}", addr, port))
    }
}

/// Look up a socket by inode in `/proc/<pid>/net/{tcp,tcp6}`.
/// Column layout (whitespace-separated, 0-indexed): 0=sl, 1=local_addr,
/// 2=rem_addr, 9=inode.
pub fn lookup_socket_by_inode(pid: u32, inode: u64) -> Option<String> {
    for (suffix, is_v6) in &[("tcp", false), ("tcp6", true)] {
        let path = format!("/proc/{}/net/{}", pid, suffix);
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 {
                continue;
            }
            if cols[9].parse::<u64>().unwrap_or(0) == inode {
                return parse_net_addr(cols[2], *is_v6);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buf_from(prefix: &[u8]) -> [u8; 128] {
        let mut buf = [0u8; 128];
        let n = prefix.len().min(buf.len());
        buf[..n].copy_from_slice(&prefix[..n]);
        buf
    }

    #[test]
    fn format_sockaddr_decodes_af_inet() {
        // family=2 LE, port=80 BE, addr=8.8.8.8
        let buf = buf_from(&[0x02, 0x00, 0x00, 0x50, 8, 8, 8, 8]);
        assert_eq!(
            format_sockaddr(&buf),
            Some("AF_INET 8.8.8.8:80".to_string())
        );
    }

    #[test]
    fn format_sockaddr_decodes_af_inet6_loopback() {
        // family=10 LE, port=443 BE, flowinfo=0, addr=::1 (last 16 bytes)
        let mut buf = [0u8; 128];
        buf[0] = 0x0a;
        buf[1] = 0x00;
        buf[2] = 0x01;
        buf[3] = 0xbb; // 0x01bb = 443
                       // bytes [8..24] is the 16-byte address. ::1 = 15 zeros + 0x01
        buf[23] = 0x01;
        assert_eq!(
            format_sockaddr(&buf),
            Some("AF_INET6 [0:0:0:0:0:0:0:1]:443".to_string())
        );
    }

    #[test]
    fn format_sockaddr_decodes_af_unix_pathname() {
        // family=1 LE, then "/run/socket\0"
        let mut bytes = vec![0x01, 0x00];
        bytes.extend_from_slice(b"/run/socket\0");
        let buf = buf_from(&bytes);
        assert_eq!(
            format_sockaddr(&buf),
            Some("AF_UNIX /run/socket".to_string())
        );
    }

    #[test]
    fn format_sockaddr_decodes_af_unix_abstract() {
        // family=1 LE, raw[2]=0, raw[3..] = "myabstract\0"
        let mut bytes = vec![0x01, 0x00, 0x00];
        bytes.extend_from_slice(b"myabstract\0");
        let buf = buf_from(&bytes);
        assert_eq!(
            format_sockaddr(&buf),
            Some("AF_UNIX @myabstract".to_string())
        );
    }

    #[test]
    fn format_sockaddr_returns_none_for_all_zero_buffer() {
        assert_eq!(format_sockaddr(&[0u8; 128]), None);
    }

    #[test]
    fn format_sockaddr_returns_unknown_family_marker() {
        // family=99 LE, some payload bytes
        let buf = buf_from(&[99, 0, 0xde, 0xad, 0xbe, 0xef]);
        let out = format_sockaddr(&buf).expect("some output for unknown family");
        assert!(out.starts_with("AF_?(99)"), "got {}", out);
    }

    #[test]
    fn bounded_sockaddr_rejects_zero_filled_fields_past_declared_length() {
        let buf = buf_from(&[2, 0, 0x01, 0xbb, 127, 0, 0, 1]);
        assert_eq!(format_sockaddr_bounded(&buf, 2), None);
        assert_eq!(
            format_sockaddr_bounded(&buf, 8),
            Some("AF_INET 127.0.0.1:443".into())
        );
    }

    #[test]
    fn parse_net_addr_decodes_ipv4_loopback() {
        // /proc/net/tcp stores IPv4 in host LE. 127.0.0.1 → 0x0100007F
        let out = parse_net_addr("0100007F:1F90", false);
        assert_eq!(out, Some("AF_INET 127.0.0.1:8080".to_string()));
    }

    #[test]
    fn parse_net_addr_rejects_invalid_ipv4_length() {
        assert_eq!(parse_net_addr("ABCD:0050", false), None);
    }

    #[test]
    fn parse_net_addr_decodes_ipv6() {
        // 32 hex chars (16 bytes) of address + colon + port hex
        let out = parse_net_addr("00000000000000000000000000000000:0050", true);
        let s = out.expect("parsed v6");
        assert!(s.starts_with("AF_INET6 ["), "got {s}");
        assert!(s.ends_with("]:80"), "got {s}");
    }

    #[test]
    fn parse_net_addr_rejects_invalid_ipv6_length() {
        assert_eq!(parse_net_addr("ABCD:0050", true), None);
    }

    #[test]
    fn parse_net_addr_rejects_missing_colon() {
        assert_eq!(parse_net_addr("0100007F", false), None);
    }

    #[test]
    fn read_socket_inode_returns_none_for_negative_fd() {
        assert_eq!(read_socket_inode(std::process::id(), -1), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_socket_inode_resolves_real_socket() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixDatagram;

        let (a, _b) = UnixDatagram::pair().expect("pair");
        let fd = a.as_raw_fd() as i64;
        let inode = read_socket_inode(std::process::id(), fd);
        assert!(inode.is_some(), "expected inode for live socket");
        assert!(inode.unwrap() > 0);
    }
}
