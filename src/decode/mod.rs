pub mod args;
pub mod binder;
pub mod ioctl;
pub mod sockaddr;
pub mod syscalls;

use neutron_common::SyscallEvent;
use std::fs;

pub use args::{
    af_name, format_enter_args, format_ioctl_args, format_mmap_args, format_mprotect_args,
    format_openat_args, format_rw_args, format_socket_args, prot_name, sock_type_name,
};
pub use binder::{format_binder_event, format_binder_event_json, format_binder_received_json};
pub use ioctl::{
    decode_ioctl, format_ioctl_deep, render_decoded_ioctl_json, DecodedIoctl, IoctlFamily,
    IoctlFields,
};
pub use sockaddr::{format_sockaddr, lookup_socket_by_inode, parse_net_addr, read_socket_inode};
pub use syscalls::syscall_name;

/// True if `nr` carries a NUL-terminated path in `data[128]`.
///
/// Must stay in sync with `capture_syscall_data` in `neutron-ebpf/src/main.rs`.
/// Path at args[1]: openat(56), faccessat(48), faccessat2(439), fstatat(79),
///                  readlinkat(78), mkdirat(34), unlinkat(35), execveat(281),
///                  openat2(437).
/// Path at args[0]: execve(221), statfs(43), symlinkat(36 — target),
///                  chdir(49), mount(40 — source).
pub fn is_path_syscall(nr: i32) -> bool {
    matches!(
        nr,
        56 | 48 | 439 | 79 | 78 | 34 | 35 | 281 | 437 | 221 | 43 | 36 | 49 | 40
    )
}

/// Resolve a path via `/proc/<pid>/fd/<fd>` readlink. Used as a userspace
/// fallback for openat-exit events when the in-kernel path capture failed.
pub fn resolve_path_from_fd(pid: u32, fd: i64) -> Option<String> {
    if fd < 0 {
        return None;
    }

    let link = format!("/proc/{pid}/fd/{fd}");
    fs::read_link(link)
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

/// Extract a NUL-terminated string from the data field. Returns `None` if the
/// first byte is `0` (BPF helper failure under PAN, etc.).
pub fn format_data_as_path(raw: &[u8; 128]) -> Option<String> {
    if raw[0] == 0 {
        return None;
    }
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Some(String::from_utf8_lossy(&raw[..end]).into_owned())
}

/// Format the `comm[16]` field of a `SyscallEvent` as a `String`.
pub fn format_comm(raw: &[u8; 16]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(16);
    String::from_utf8_lossy(&raw[..end]).to_string()
}

/// Interpret `data[128]` based on `syscall_nr` and return a display string.
///
/// Dispatches:
/// - file path syscalls → NUL-terminated path
/// - bind/connect/sendto (+ device alias 294) → sockaddr
/// - sendmsg/recvmsg → sockaddr from `msg_name` + `controllen`
/// - ioctl(29) → `format_ioctl_deep`
/// - mmap(222)/mprotect(226) → RWX/WX marker tag
pub fn format_data_field(ev: &SyscallEvent) -> Option<String> {
    let nr = { ev.syscall_nr };
    let data = { ev.data };

    match nr {
        // File path syscalls
        56 | 48 | 79 | 78 | 43 | 36 | 35 | 221 | 281 => format_data_as_path(&data),
        // Network sockaddr (including device alias 294 for connect)
        200 | 203 | 206 | 294 => format_sockaddr(&data),
        // sendmsg/recvmsg: sockaddr from msg_name + controllen at data[64..72]
        211 | 212 => {
            let addr = format_sockaddr(&data);
            let controllen = u64::from_le_bytes(data[64..72].try_into().unwrap_or([0u8; 8]));
            match (addr, controllen) {
                (Some(a), 0) => Some(a),
                (Some(a), n) => Some(format!("{} ctrl_len={}", a, n)),
                (None, n) if n > 0 => Some(format!("ctrl_len={}", n)),
                _ => None,
            }
        }
        // ioctl deep
        29 => {
            if data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0 {
                None
            } else {
                Some(format_ioctl_deep(&data))
            }
        }
        // mmap/mprotect RWX marker
        222 | 226 => match data[0] {
            1 => Some("[!RWX]".to_string()),
            2 => Some("[!WX]".to_string()),
            _ => None,
        },
        _ => None,
    }
}

/// Try to recover a path string for `ev`, optionally falling back to
/// `/proc/<pid>/fd/<fd>` readlink for openat-exit events.
pub fn resolve_path(ev: &SyscallEvent, resolve_paths: bool) -> Option<String> {
    let nr = { ev.syscall_nr };
    let decoded = format_data_field(ev);
    if decoded.is_some() || !resolve_paths || !is_path_syscall(nr) {
        return decoded;
    }
    // BPF capture failed — try /proc/<pid>/fd/<fd> readlink for openat-exit.
    let pid = { ev.pid };
    let is_enter = { ev.is_enter };
    let ret = { ev.ret };
    if is_enter == 0 && nr == 56 && ret >= 0 {
        return resolve_path_from_fd(pid, ret);
    }
    None
}

/// For exit events, returns latency in microseconds derived from the
/// dedicated `enter_timestamp_ns` wire field. Returns `None` for enter events
/// or when the enter timestamp was not captured (INFLIGHT miss in BPF).
pub fn compute_latency_us(ev: &SyscallEvent) -> Option<u64> {
    if { ev.is_enter } != 0 {
        return None;
    }
    let enter_ts = { ev.enter_timestamp_ns };
    let exit_ts = { ev.timestamp_ns };
    if enter_ts == 0 || exit_ts < enter_ts {
        return None;
    }
    Some((exit_ts - enter_ts) / 1_000)
}

#[cfg(test)]
mod tests {
    use super::{format_data_as_path, format_data_field, resolve_path};
    use neutron_common::SyscallEvent;
    use std::fs::File;
    use std::os::fd::AsRawFd;

    fn path_bytes(path: &[u8]) -> [u8; 128] {
        let mut data = [0u8; 128];
        let len = path.len().min(data.len());
        data[..len].copy_from_slice(&path[..len]);
        data
    }

    fn path_event(nr: i32, path: &[u8]) -> SyscallEvent {
        SyscallEvent {
            syscall_nr: nr,
            data: path_bytes(path),
            ..SyscallEvent::default()
        }
    }

    #[test]
    fn format_data_as_path_reads_nul_terminated_string() {
        let data = path_bytes(b"/proc/self/maps\0ignored");
        assert_eq!(
            format_data_as_path(&data),
            Some("/proc/self/maps".to_string())
        );
    }

    #[test]
    fn format_data_as_path_uses_full_buffer_without_nul() {
        let data = [b'a'; 128];
        let path = format_data_as_path(&data).expect("path");
        assert_eq!(path.len(), 128);
        assert!(path.chars().all(|ch| ch == 'a'));
    }

    #[test]
    fn format_data_as_path_returns_none_for_empty_payload() {
        assert_eq!(format_data_as_path(&[0u8; 128]), None);
    }

    #[test]
    fn format_data_as_path_lossily_decodes_invalid_utf8() {
        let data = path_bytes(&[0xff, 0xfe, 0x00]);
        let path = format_data_as_path(&data).expect("path");
        assert!(path.contains('\u{fffd}'));
    }

    #[test]
    fn format_data_field_decodes_all_file_path_syscalls() {
        for nr in [56, 48, 79, 78, 43, 36, 35, 221, 281] {
            let ev = path_event(nr, b"/system/lib/libc.so\0");
            assert_eq!(
                format_data_field(&ev),
                Some("/system/lib/libc.so".to_string())
            );
        }
    }

    #[test]
    fn resolve_path_uses_fd_fallback_for_openat_exit() {
        let file = File::open("Cargo.toml").expect("open Cargo.toml");
        let ev = SyscallEvent {
            pid: std::process::id(),
            syscall_nr: 56,
            ret: file.as_raw_fd() as i64,
            is_enter: 0,
            ..SyscallEvent::default()
        };

        let path = resolve_path(&ev, true).expect("resolved path");
        assert!(path.ends_with("/Cargo.toml"), "resolved path was {path}");
    }
}
