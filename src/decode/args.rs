//! Per-syscall argument decoders for the enter-event display path.

pub fn af_name(v: u64) -> &'static str {
    match v as i32 {
        0 => "AF_UNSPEC",
        1 => "AF_LOCAL",
        2 => "AF_INET",
        10 => "AF_INET6",
        16 => "AF_NETLINK",
        17 => "AF_PACKET",
        _ => "",
    }
}

pub fn sock_type_name(v: u64) -> String {
    let base = (v & 0xff) as i32;
    let name = match base {
        1 => "SOCK_STREAM",
        2 => "SOCK_DGRAM",
        3 => "SOCK_RAW",
        5 => "SOCK_SEQPACKET",
        _ => return format!("{:#x}", v),
    };
    let mut flags = String::from(name);
    if v & 0x800 != 0 {
        flags.push_str("|NONBLOCK");
    }
    if v & 0x80000 != 0 {
        flags.push_str("|CLOEXEC");
    }
    flags
}

pub fn format_socket_args(args: &[u64; 6]) -> String {
    let domain = af_name(args[0]);
    let stype = sock_type_name(args[1]);
    if domain.is_empty() {
        format!("{}, {}, {}", args[0], stype, args[2])
    } else {
        format!("{}, {}, {}", domain, stype, args[2])
    }
}

pub fn format_openat_args(args: &[u64; 6]) -> String {
    let dirfd = args[0] as i64;
    let dirfd_s = if dirfd == -100 {
        "AT_FDCWD".to_string()
    } else {
        format!("{}", dirfd)
    };
    let flags = args[2] as u32;
    let mut fstr = Vec::new();
    match flags & 3 {
        0 => fstr.push("O_RDONLY"),
        1 => fstr.push("O_WRONLY"),
        2 => fstr.push("O_RDWR"),
        _ => {}
    }
    if flags & 0x40 != 0 {
        fstr.push("O_CREAT");
    }
    if flags & 0x200 != 0 {
        fstr.push("O_TRUNC");
    }
    if flags & 0x400 != 0 {
        fstr.push("O_APPEND");
    }
    if flags & 0x80000 != 0 {
        fstr.push("O_CLOEXEC");
    }
    let flags_s = if fstr.is_empty() {
        format!("{:#x}", flags)
    } else {
        fstr.join("|")
    };
    format!("{}, {:#x}, {}", dirfd_s, args[1], flags_s)
}

pub fn format_ioctl_args(args: &[u64; 6]) -> String {
    format!("{}, {:#x}, {:#x}", args[0], args[1], args[2])
}

pub fn format_rw_args(args: &[u64; 6]) -> String {
    format!("{}, {:#x}, {}", args[0], args[1], args[2])
}

pub fn prot_name(v: u64) -> String {
    let v = v as u32;
    if v == 0 {
        return "PROT_NONE".to_string();
    }
    let mut parts = Vec::new();
    if v & 1 != 0 {
        parts.push("PROT_READ");
    }
    if v & 2 != 0 {
        parts.push("PROT_WRITE");
    }
    if v & 4 != 0 {
        parts.push("PROT_EXEC");
    }
    if parts.is_empty() {
        format!("{:#x}", v)
    } else {
        parts.join("|")
    }
}

pub fn format_mmap_args(args: &[u64; 6]) -> String {
    let prot = prot_name(args[2]);
    let flags = args[3] as u32;
    let mut fparts = Vec::new();
    if flags & 1 != 0 {
        fparts.push("MAP_SHARED");
    }
    if flags & 2 != 0 {
        fparts.push("MAP_PRIVATE");
    }
    if flags & 0x10 != 0 {
        fparts.push("MAP_FIXED");
    }
    if flags & 0x20 != 0 {
        fparts.push("MAP_ANONYMOUS");
    }
    let flags_s = if fparts.is_empty() {
        format!("{:#x}", flags)
    } else {
        fparts.join("|")
    };
    let fd = args[4] as i64;
    format!(
        "{:#x}, {}, {}, {}, {}, {:#x}",
        args[0], args[1], prot, flags_s, fd, args[5]
    )
}

pub fn format_mprotect_args(args: &[u64; 6]) -> String {
    format!("{:#x}, {}, {}", args[0], args[1], prot_name(args[2]))
}

pub fn format_enter_args(syscall_nr: i32, args: &[u64; 6]) -> String {
    match syscall_nr {
        198 | 293 => format_socket_args(args),
        56 => format_openat_args(args),
        29 => format_ioctl_args(args),
        63 | 64 | 67 | 68 => format_rw_args(args),
        65 | 66 => format_rw_args(args), // readv/writev: fd, iov, iovcnt
        222 => format_mmap_args(args),
        226 => format_mprotect_args(args),
        211 | 212 => format!("{}, <msghdr>, {:#x}", args[0], args[2]),
        _ => format!("{:#x}, {:#x}, {:#x}", args[0], args[1], args[2]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn af_name_known_and_unknown() {
        assert_eq!(af_name(2), "AF_INET");
        assert_eq!(af_name(10), "AF_INET6");
        assert_eq!(af_name(1), "AF_LOCAL");
        assert_eq!(af_name(99), "");
    }

    #[test]
    fn sock_type_name_basic_stream() {
        assert_eq!(sock_type_name(1), "SOCK_STREAM");
    }

    #[test]
    fn sock_type_name_with_nonblock_flag() {
        assert_eq!(sock_type_name(1 | 0x800), "SOCK_STREAM|NONBLOCK");
    }

    #[test]
    fn sock_type_name_with_cloexec_flag() {
        assert_eq!(sock_type_name(1 | 0x80000), "SOCK_STREAM|CLOEXEC");
    }

    #[test]
    fn sock_type_name_with_both_flags() {
        let s = sock_type_name(2 | 0x800 | 0x80000);
        assert!(s.starts_with("SOCK_DGRAM"), "got {s}");
        assert!(s.contains("NONBLOCK"), "got {s}");
        assert!(s.contains("CLOEXEC"), "got {s}");
    }

    #[test]
    fn sock_type_name_unknown_renders_hex() {
        let s = sock_type_name(0xff);
        assert!(s.starts_with("0x"), "got {s}");
    }

    #[test]
    fn prot_name_none_when_zero() {
        assert_eq!(prot_name(0), "PROT_NONE");
    }

    #[test]
    fn prot_name_rwx_combined() {
        assert_eq!(prot_name(7), "PROT_READ|PROT_WRITE|PROT_EXEC");
    }

    #[test]
    fn prot_name_read_only() {
        assert_eq!(prot_name(1), "PROT_READ");
    }

    #[test]
    fn format_openat_args_at_fdcwd_and_flags() {
        // AT_FDCWD=-100, flags = O_RDONLY|O_CLOEXEC = 0|0x80000
        let args: [u64; 6] = [(-100i64) as u64, 0xdeadbeef, 0x80000, 0, 0, 0];
        let s = format_openat_args(&args);
        assert!(s.contains("AT_FDCWD"), "got {s}");
        assert!(s.contains("O_RDONLY"), "got {s}");
        assert!(s.contains("O_CLOEXEC"), "got {s}");
    }

    #[test]
    fn format_openat_args_creates_with_trunc() {
        // O_WRONLY|O_CREAT|O_TRUNC = 1 | 0x40 | 0x200 = 0x241
        let args: [u64; 6] = [(-100i64) as u64, 0, 0x241, 0, 0, 0];
        let s = format_openat_args(&args);
        assert!(s.contains("O_WRONLY"), "got {s}");
        assert!(s.contains("O_CREAT"), "got {s}");
        assert!(s.contains("O_TRUNC"), "got {s}");
    }

    #[test]
    fn format_socket_args_inet_stream() {
        let args: [u64; 6] = [2, 1, 0, 0, 0, 0];
        assert_eq!(format_socket_args(&args), "AF_INET, SOCK_STREAM, 0");
    }

    #[test]
    fn format_socket_args_unknown_family_emits_number() {
        let args: [u64; 6] = [42, 1, 0, 0, 0, 0];
        let s = format_socket_args(&args);
        assert!(s.starts_with("42, "), "got {s}");
    }

    #[test]
    fn format_mmap_args_rwx_anonymous_private() {
        // prot=7 (RWX), flags = MAP_PRIVATE | MAP_ANONYMOUS = 2 | 0x20 = 0x22
        let args: [u64; 6] = [0, 4096, 7, 0x22, (-1i64) as u64, 0];
        let s = format_mmap_args(&args);
        assert!(s.contains("PROT_READ|PROT_WRITE|PROT_EXEC"), "got {s}");
        assert!(s.contains("MAP_PRIVATE|MAP_ANONYMOUS"), "got {s}");
    }

    #[test]
    fn format_mmap_args_unknown_flags_render_hex() {
        let args: [u64; 6] = [0, 4096, 0, 0x100, 0, 0];
        let s = format_mmap_args(&args);
        assert!(s.contains("0x100"), "got {s}");
    }

    #[test]
    fn format_mprotect_args_rwx() {
        let args: [u64; 6] = [0x1000, 4096, 7, 0, 0, 0];
        let s = format_mprotect_args(&args);
        assert!(s.contains("PROT_READ|PROT_WRITE|PROT_EXEC"), "got {s}");
    }

    #[test]
    fn format_ioctl_args_renders_hex() {
        let args: [u64; 6] = [3, 0xdeadbeef, 0x4242, 0, 0, 0];
        let s = format_ioctl_args(&args);
        assert!(s.contains("0xdeadbeef"));
        assert!(s.contains("0x4242"));
    }

    #[test]
    fn format_rw_args_renders_fd_buf_count() {
        let args: [u64; 6] = [4, 0xcafe, 128, 0, 0, 0];
        let s = format_rw_args(&args);
        assert!(s.starts_with("4, "));
        assert!(s.contains("0xcafe"));
        assert!(s.contains("128"));
    }

    #[test]
    fn format_enter_args_dispatches_openat() {
        let args: [u64; 6] = [(-100i64) as u64, 0, 0x80000, 0, 0, 0];
        let s = format_enter_args(56, &args);
        assert!(s.contains("AT_FDCWD"), "got {s}");
    }

    #[test]
    fn format_enter_args_dispatches_mmap() {
        let args: [u64; 6] = [0, 4096, 7, 0x22, (-1i64) as u64, 0];
        let s = format_enter_args(222, &args);
        assert!(s.contains("PROT_READ|PROT_WRITE|PROT_EXEC"));
        assert!(s.contains("MAP_PRIVATE|MAP_ANONYMOUS"));
    }

    #[test]
    fn format_enter_args_dispatches_ioctl() {
        let args: [u64; 6] = [3, 0xdeadbeef, 0x4242, 0, 0, 0];
        let s = format_enter_args(29, &args);
        assert!(s.contains("0xdeadbeef"));
    }

    #[test]
    fn format_enter_args_dispatches_socket() {
        let args: [u64; 6] = [2, 1, 0, 0, 0, 0];
        let s = format_enter_args(198, &args);
        assert_eq!(s, "AF_INET, SOCK_STREAM, 0");
    }

    #[test]
    fn format_enter_args_default_renders_three_hex() {
        let args: [u64; 6] = [0xa, 0xb, 0xc, 0, 0, 0];
        let s = format_enter_args(99999, &args);
        assert_eq!(s, "0xa, 0xb, 0xc");
    }

    #[test]
    fn format_enter_args_dispatches_sendmsg() {
        let args: [u64; 6] = [5, 0, 0x1000, 0, 0, 0];
        let s = format_enter_args(211, &args);
        assert!(s.contains("<msghdr>"), "got {s}");
        assert!(s.contains("0x1000"), "got {s}");
    }
}
