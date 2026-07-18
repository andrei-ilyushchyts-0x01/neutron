//! Human-readable text rendering of `SyscallEvent`s.

use crate::decode::{
    compute_latency_us, escape_text, format_binder_event, format_comm, format_data_field,
    format_enter_args, lookup_socket_by_inode, read_socket_inode, resolve_path_from_fd,
    syscall_name,
};
use neutron_common::SyscallEvent;

/// Render a `SyscallEvent` as a single human-readable line.
///
/// Equivalent to `format_event_text_with_stack(ev, resolve_paths, None)`.
pub fn format_event_text(ev: &SyscallEvent, resolve_paths: bool) -> String {
    format_event_text_with_stack(ev, resolve_paths, None)
}

/// Render a `SyscallEvent` as a single human-readable line with an optional
/// pre-rendered stack suffix.
///
/// `resolve_paths` enables userspace fallbacks (`/proc/<pid>/fd/<fd>` readlink,
/// `/proc/<pid>/net/tcp*`) when the in-event payload is empty.
pub fn format_event_text_with_stack(
    ev: &SyscallEvent,
    resolve_paths: bool,
    stack: Option<&str>,
) -> String {
    let mut line = format_event_text_inner(ev, resolve_paths);
    if let Some(s) = stack {
        line.push_str(" stack=<");
        line.push_str(&escape_text(s));
        line.push('>');
    }
    line
}

fn format_event_text_inner(ev: &SyscallEvent, resolve_paths: bool) -> String {
    let syscall_nr = { ev.syscall_nr };

    // Binder events have their own formatter
    if syscall_nr == -1 {
        return format_binder_event(ev);
    }

    let ts_ms = { ev.timestamp_ns } / 1_000_000;
    let pid = { ev.pid };
    let tid = { ev.tgid }; // kernel tgid field actually holds Linux TID
    let is_enter = { ev.is_enter };
    let ret = { ev.ret };
    let args = { ev.args };
    let comm = escape_text(&format_comm(&{ ev.comm }));
    let name = syscall_name(syscall_nr);
    let data_info = format_data_field(ev);
    let payload_note = if neutron_common::event_payload_read_failed(ev) {
        " [payload-read-failed]"
    } else if neutron_common::event_payload_unavailable(ev) {
        " [payload-unavailable]"
    } else {
        ""
    };

    // RWX alert prefix
    let rwx_prefix = {
        let d = { ev.data };
        match (syscall_nr, d[0]) {
            (222 | 226, 1) => "[!RWX] ",
            (222 | 226, 2) => "[!WX] ",
            _ => "",
        }
    };

    if is_enter == 1 {
        let args_str = format_enter_args(syscall_nr, &args);
        let base = format!(
            "[{:>10}] {:>6}/{:<6} {:<16} {}-> {}({}){}",
            ts_ms, pid, tid, comm, rwx_prefix, name, args_str, payload_note,
        );
        // Append data field info (path, sockaddr, ioctl, etc.)
        match data_info {
            Some(ref d) if !d.starts_with("[!") => {
                format!("{} \"{}\"", base, escape_text(d))
            }
            _ => base,
        }
    } else {
        let latency_str = match compute_latency_us(ev) {
            Some(us) if us < 1_000 => format!(" [+{}us]", us),
            Some(us) => format!(" [+{:.1}ms]", us as f64 / 1_000.0),
            None => String::new(),
        };
        let base = format!(
            "[{:>10}] {:>6}/{:<6} {:<16} {}<- {} = {}{}{}",
            ts_ms, pid, tid, comm, rwx_prefix, name, ret, latency_str, payload_note,
        );
        // Resolve paths on exit: openat readlink fallback, then /proc/net for connect
        if resolve_paths && data_info.is_none() {
            // Tertiary: readlink for openat
            if syscall_nr == 56 && ret >= 0 {
                if let Some(resolved) = resolve_path_from_fd(pid, ret) {
                    return format!("{} \"{}\"", base, escape_text(&resolved));
                }
            }
            // Quaternary: /proc/net for connect()
            if (syscall_nr == 203 || syscall_nr == 294) && ret >= 0 {
                let sock_fd = args[0] as i64;
                if let Some(resolved) = read_socket_inode(pid, sock_fd)
                    .and_then(|inode| lookup_socket_by_inode(pid, inode))
                {
                    return format!("{} \"{}\"", base, escape_text(&resolved));
                }
            }
        }
        match data_info {
            Some(ref d) if !d.starts_with("[!") => {
                format!("{} \"{}\"", base, escape_text(d))
            }
            _ => base,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comm_bytes(name: &str) -> [u8; 16] {
        let mut c = [0u8; 16];
        let n = name.len().min(16);
        c[..n].copy_from_slice(&name.as_bytes()[..n]);
        c
    }

    fn data_path(path: &[u8]) -> [u8; 128] {
        let mut data = [0u8; 128];
        let n = path.len().min(data.len());
        data[..n].copy_from_slice(&path[..n]);
        data
    }

    #[test]
    fn format_event_text_openat_enter_includes_path_and_header() {
        let ev = SyscallEvent {
            timestamp_ns: 1_500_000, // 1.5ms → ts_ms=1
            pid: 42,
            tgid: 42,
            uid: 1000,
            syscall_nr: 56,
            args: [(-100i64) as u64, 0xdead, 0x80000, 0, 0, 0],
            is_enter: 1,
            comm: comm_bytes("probe"),
            data: data_path(b"/proc/self/maps\0"),
            ..SyscallEvent::default()
        };
        let s = format_event_text(&ev, false);
        // Header `[ts_ms] pid/tid comm` then `-> openat(...)` and embedded path.
        assert!(s.contains("42/42"), "missing pid/tid in {s}");
        assert!(s.contains("probe"), "missing comm in {s}");
        assert!(s.contains("openat("), "missing openat in {s}");
        assert!(s.contains("AT_FDCWD"), "missing AT_FDCWD in {s}");
        assert!(s.contains("\"/proc/self/maps\""), "missing path in {s}");
    }

    #[test]
    fn format_event_text_exit_appends_microsecond_latency() {
        // enter_timestamp_ns = 1_500_000; exit ts = 2_000_000 → 500us latency
        let ev = SyscallEvent {
            timestamp_ns: 2_000_000,
            enter_timestamp_ns: 1_500_000,
            pid: 7,
            tgid: 7,
            syscall_nr: 56,
            ret: 4,
            is_enter: 0,
            comm: comm_bytes("p"),
            ..SyscallEvent::default()
        };
        let s = format_event_text(&ev, false);
        assert!(s.contains(" [+500us]"), "missing latency in {s}");
        assert!(s.contains("<- openat"), "missing exit form in {s}");
    }

    #[test]
    fn format_event_text_exit_appends_millisecond_latency() {
        // 2_500_000ns latency → 2500us → "[+2.5ms]"
        let ev = SyscallEvent {
            timestamp_ns: 3_000_000,
            enter_timestamp_ns: 500_000,
            syscall_nr: 56,
            ret: 4,
            is_enter: 0,
            comm: comm_bytes("p"),
            ..SyscallEvent::default()
        };
        let s = format_event_text(&ev, false);
        assert!(s.contains("[+2.5ms]"), "missing ms latency in {s}");
    }

    #[test]
    fn format_event_text_mmap_rwx_marks_alert_prefix() {
        let mut data = [0u8; 128];
        data[0] = 1; // RWX marker
        let ev = SyscallEvent {
            timestamp_ns: 0,
            syscall_nr: 222,
            args: [0, 4096, 7, 0x22, (-1i64) as u64, 0],
            is_enter: 1,
            comm: comm_bytes("p"),
            data,
            ..SyscallEvent::default()
        };
        let s = format_event_text(&ev, false);
        assert!(s.contains("[!RWX]"), "missing RWX prefix in {s}");
    }

    #[test]
    fn format_event_text_routes_binder_event() {
        let ev = SyscallEvent {
            syscall_nr: -1,
            timestamp_ns: 1_000_000,
            pid: 99,
            tgid: 99,
            args: [42, 1, 0, 0, 0, 0],
            comm: comm_bytes("svc"),
            ..SyscallEvent::default()
        };
        let s = format_event_text(&ev, false);
        assert!(s.contains("BINDER"), "missing BINDER in {s}");
    }

    #[test]
    fn text_output_escapes_control_characters_from_comm_path_and_stack() {
        let ev = SyscallEvent {
            syscall_nr: 56,
            is_enter: 1,
            pid: 42,
            tgid: 42,
            comm: comm_bytes("bad\n\x1bcomm"),
            data: data_path(b"/proc/bad\n\x1b[31m\0"),
            ..SyscallEvent::default()
        };
        let rendered = format_event_text_with_stack(&ev, false, Some("sym\n\x1b[2J"));

        assert_eq!(
            rendered.lines().count(),
            1,
            "text record split: {rendered:?}"
        );
        assert!(!rendered.contains('\u{1b}'), "terminal escape leaked");
        assert!(rendered.contains("\\n"), "newline should be visible");
        assert!(rendered.contains("\\u{1b}"), "ESC should be visible");
    }

    #[test]
    fn format_event_text_includes_sockaddr_for_connect() {
        let mut data = [0u8; 128];
        data[..8].copy_from_slice(&[0x02, 0x00, 0x00, 0x50, 8, 8, 8, 8]);
        let ev = SyscallEvent {
            timestamp_ns: 0,
            syscall_nr: 203, // connect
            is_enter: 1,
            args: [3, 0, 8, 0, 0, 0],
            comm: comm_bytes("net"),
            data,
            ..SyscallEvent::default()
        };
        let s = format_event_text(&ev, false);
        assert!(
            s.contains("\"AF_INET 8.8.8.8:80\""),
            "missing sockaddr in {s}"
        );
    }

    #[test]
    fn format_comm_strips_trailing_nuls() {
        let mut buf = [0u8; 16];
        buf[..5].copy_from_slice(b"hello");
        assert_eq!(crate::decode::format_comm(&buf), "hello");
    }

    #[test]
    fn format_comm_truncates_when_no_nul() {
        let buf = [b'a'; 16];
        let s = crate::decode::format_comm(&buf);
        assert_eq!(s.len(), 16);
    }

    #[test]
    fn compute_latency_returns_none_for_enter() {
        let ev = SyscallEvent {
            is_enter: 1,
            ..SyscallEvent::default()
        };
        assert!(crate::decode::compute_latency_us(&ev).is_none());
    }

    #[test]
    fn compute_latency_returns_us_for_exit() {
        let ev = SyscallEvent {
            timestamp_ns: 2_000_000,
            enter_timestamp_ns: 1_500_000,
            is_enter: 0,
            ..SyscallEvent::default()
        };
        assert_eq!(crate::decode::compute_latency_us(&ev), Some(500));
    }

    #[test]
    fn compute_latency_returns_none_when_enter_ts_missing() {
        let ev = SyscallEvent {
            timestamp_ns: 1_000_000,
            is_enter: 0,
            ..SyscallEvent::default()
        };
        assert!(crate::decode::compute_latency_us(&ev).is_none());
    }
}
