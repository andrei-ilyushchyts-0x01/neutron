//! Binder transaction event formatters (synthetic `syscall_nr == -1`).

use crate::decode::{escape_text, format_comm};
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
    let comm = escape_text(&format_comm(&{ ev.comm }));
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
///
/// Sprint-2 PR 2 added `debug_id` (the binder transaction id stashed in
/// `ptr_hint` by the BPF programs) so the userspace correlator can pair
/// caller-side events with `binder_transaction_received` (`type:"binder_received"`).
pub fn format_binder_event_json(ev: &SyscallEvent, event_id: Option<u64>) -> String {
    let args = { ev.args };
    let comm = format_comm(&{ ev.comm });
    let comm_json = serde_json::to_string(&comm).expect("serializing binder comm cannot fail");
    let event_id_json = match event_id {
        Some(id) => format!(r#","event_id":{}"#, id),
        None => String::new(),
    };
    let debug_id = { ev.ptr_hint } as u32 as i32;
    format!(
        r#"{{"ts_ns":{},"pid":{},"tgid":{},"process_id":{},"thread_id":{},"uid":{},"type":"binder","phase":"enter","comm":{},"reply":{},"to_proc":{},"to_thread":{},"target_node":{},"code":{},"flags":{},"debug_id":{}{}}}"#,
        { ev.timestamp_ns },
        { ev.pid },
        { ev.tgid },
        { ev.pid },
        { ev.tgid },
        { ev.uid },
        comm_json,
        args[4] != 0,
        args[0] as u32,
        args[3] as u32,
        args[5] as u32,
        args[1] as u32,
        args[2],
        debug_id,
        event_id_json,
    )
}

/// Format a callee-side `binder/binder_transaction_received` event
/// (synthetic `syscall_nr == SYSCALL_NR_BINDER_RECEIVED`). Carries the
/// matching `debug_id` so the userspace correlator can find the caller.
/// Sprint-2 PR 2.
pub fn format_binder_received_json(ev: &SyscallEvent, event_id: Option<u64>) -> String {
    let comm = format_comm(&{ ev.comm });
    let comm_json = serde_json::to_string(&comm).expect("serializing binder comm cannot fail");
    let debug_id = { ev.ptr_hint } as u32 as i32;
    let event_id_json = match event_id {
        Some(id) => format!(r#","event_id":{}"#, id),
        None => String::new(),
    };
    format!(
        r#"{{"ts_ns":{},"pid":{},"tgid":{},"process_id":{},"thread_id":{},"uid":{},"type":"binder_received","comm":{},"debug_id":{}{}}}"#,
        { ev.timestamp_ns },
        { ev.pid },
        { ev.tgid },
        { ev.pid },
        { ev.tgid },
        { ev.uid },
        comm_json,
        debug_id,
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
    fn format_binder_event_json_preserves_zero_identity_fields() {
        let ev = binder_event([0, 0, 0, 0, 0, 0]);
        let value: serde_json::Value =
            serde_json::from_str(&format_binder_event_json(&ev, None)).unwrap();

        assert_eq!(
            value.get("debug_id").and_then(|value| value.as_i64()),
            Some(0)
        );
        assert_eq!(
            value.get("to_proc").and_then(|value| value.as_u64()),
            Some(0)
        );
    }

    #[test]
    fn binder_comm_control_characters_cannot_split_ndjson() {
        let mut ev = binder_event([42, 1, 0, 0, 0, 7]);
        ev.comm = comm_bytes("evil\n\tcomm");

        for line in [
            format_binder_event_json(&ev, Some(1)),
            format_binder_received_json(&ev, Some(2)),
        ] {
            assert_eq!(line.lines().count(), 1, "binder record was split: {line:?}");
            let value: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
            assert_eq!(value["comm"], "evil\n\tcomm");
        }
    }

    #[test]
    fn binder_text_comm_cannot_split_or_escape_the_terminal() {
        let mut ev = binder_event([42, 1, 0, 0, 0, 7]);
        ev.comm = comm_bytes("evil\n\x1b[2J");

        let text = format_binder_event(&ev);
        assert_eq!(text.lines().count(), 1, "binder text split: {text:?}");
        assert!(!text.contains('\u{1b}'), "terminal escape leaked");
        assert!(text.contains("\\n"));
        assert!(text.contains("\\u{1b}"));
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
