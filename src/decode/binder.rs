//! Binder transaction event formatters (synthetic `syscall_nr == -1`).

use crate::decode::format_comm;
use neutron_common::SyscallEvent;

/// Format a binder transaction event for human-readable text output.
pub fn format_binder_event(ev: &SyscallEvent) -> String {
    let args = { ev.args };
    let to_proc = args[0] as u32;
    let code = args[1] as u32;
    let flags = args[2] as u32;
    let to_thread = args[3] as u32;
    let reply = args[4] != 0;
    let target_node = args[5] as u32;
    let comm = format_comm(&{ ev.comm });
    let ts_ms = { ev.timestamp_ns } / 1_000_000;
    let pid = { ev.pid };
    let tid = { ev.tgid };

    format!(
        "[{:>10}] {:>6}/{:<6} {:<16} {} BINDER to_proc={} to_thread={} node={} code={:#x} flags={:#x}",
        ts_ms,
        pid,
        tid,
        comm,
        if reply { "<-" } else { "->" },
        to_proc,
        to_thread,
        target_node,
        code,
        flags,
    )
}

/// Format a binder transaction event as JSON.
///
/// `event_id` is the caller-supplied monotonic correlation token; omitted
/// from the line when `None`. Binder transactions are point-in-time so the
/// emitted `phase` is always `"enter"` — there is no symmetric exit event
/// to pair with.
pub fn format_binder_event_json(ev: &SyscallEvent, event_id: Option<u64>) -> String {
    let args = { ev.args };
    let comm = format_comm(&{ ev.comm });
    let event_id_json = match event_id {
        Some(id) => format!(r#","event_id":{}"#, id),
        None => String::new(),
    };
    format!(
        r#"{{"ts_ns":{},"pid":{},"tgid":{},"uid":{},"type":"binder","phase":"enter","comm":"{}","reply":{},"to_proc":{},"to_thread":{},"target_node":{},"code":{},"flags":{}{}}}"#,
        { ev.timestamp_ns },
        { ev.pid },
        { ev.tgid },
        { ev.uid },
        comm,
        args[4] != 0,
        args[0] as u32,
        args[3] as u32,
        args[5] as u32,
        args[1] as u32,
        args[2],
        event_id_json,
    )
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

    fn binder_event(args: [u64; 6]) -> SyscallEvent {
        SyscallEvent {
            syscall_nr: -1,
            timestamp_ns: 1_000_000,
            pid: 1234,
            tgid: 1234,
            uid: 10001,
            args,
            comm: comm_bytes("binder-test"),
            ..SyscallEvent::default()
        }
    }

    #[test]
    fn format_binder_event_contains_expected_tokens() {
        let ev = binder_event([42, 0x1, 0x10, 99, 0, 7]);
        let s = format_binder_event(&ev);
        assert!(s.contains("BINDER"), "missing BINDER in {s}");
        assert!(s.contains("to_proc=42"), "missing to_proc in {s}");
        assert!(s.contains("code=0x1"), "missing code= in {s}");
        assert!(s.contains("node=7"), "missing node= in {s}");
        assert!(s.contains("binder-test"), "missing comm in {s}");
    }

    #[test]
    fn format_binder_event_uses_forward_arrow_for_request() {
        let ev = binder_event([1, 0, 0, 0, 0, 0]); // reply=0 → ->
        let s = format_binder_event(&ev);
        assert!(s.contains(" -> "), "missing forward arrow in {s}");
        assert!(!s.contains(" <- "));
    }

    #[test]
    fn format_binder_event_uses_back_arrow_for_reply() {
        let ev = binder_event([1, 0, 0, 0, 1, 0]); // reply=1 → <-
        let s = format_binder_event(&ev);
        assert!(s.contains(" <- "), "missing back arrow in {s}");
        assert!(!s.contains(" -> "));
    }

    #[test]
    fn format_binder_event_json_is_valid_json_with_expected_keys() {
        let ev = binder_event([42, 0x5, 0x10, 99, 1, 7]);
        let s = format_binder_event_json(&ev, None);
        let v: serde_json::Value =
            serde_json::from_str(&s).unwrap_or_else(|e| panic!("bad json: {e} for {s}"));
        let obj = v.as_object().expect("object");
        for k in [
            "ts_ns",
            "pid",
            "tgid",
            "uid",
            "type",
            "phase",
            "reply",
            "to_proc",
            "to_thread",
            "target_node",
            "code",
            "flags",
        ] {
            assert!(obj.contains_key(k), "missing key {k} in {s}");
        }
        assert_eq!(obj.get("type").and_then(|v| v.as_str()), Some("binder"));
        assert_eq!(obj.get("phase").and_then(|v| v.as_str()), Some("enter"));
        assert_eq!(obj.get("reply").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(obj.get("to_proc").and_then(|v| v.as_u64()), Some(42));
        assert_eq!(obj.get("target_node").and_then(|v| v.as_u64()), Some(7));
        // event_id omitted when caller doesn't supply one.
        assert!(!obj.contains_key("event_id"));
    }

    #[test]
    fn format_binder_event_json_includes_event_id_when_provided() {
        let ev = binder_event([1, 0, 0, 0, 0, 0]);
        let s = format_binder_event_json(&ev, Some(99));
        let v: serde_json::Value =
            serde_json::from_str(&s).unwrap_or_else(|e| panic!("bad json: {e} for {s}"));
        assert_eq!(v.get("event_id").and_then(|x| x.as_u64()), Some(99));
    }
}
