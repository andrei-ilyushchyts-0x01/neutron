//! Parsed view over a single neutron NDJSON event.
//!
//! Mirrors the JSON schema produced by `neutron --json` (see
//! `docs/guides/output-formats.md`). Only the fields the engine needs are
//! materialised; unknown fields are ignored.

use serde_json::Value;

/// What category the underlying event belongs to. Allows rules to match
/// `binder`, `fd_snapshot`, and `process_exit` events without forcing them
/// into the same shape as syscalls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    Syscall,
    Binder,
    /// Sprint-1 PR 3: periodic `/proc/<pid>/fd` poller sample. Carries
    /// `fd_count`, `fd_pct_of_rlimit`, and high-water marks. Drives the
    /// `R001_fd_table_exhaustion`-class rules.
    FdSnapshot,
    /// Sprint-2 PR 1: process exit observed by BPF tracepoint, logcat tail,
    /// or tombstone watcher. Carries `exit_signal`, `exit_classification`,
    /// and `source`. Drives `R003_process_crash`.
    ProcessExit,
    /// Sprint-2 PR 2: synthesised caller→callee binder transaction pair
    /// emitted by the userspace correlator. Carries `caller_pid`,
    /// `callee_pid`, `code`, `flags`, and a lifecycle `status` (completed
    /// / callee_crashed / unmatched). Drives `R004_binder_callee_crash`.
    BinderCall,
}

/// Lightweight read-only view of one event line. Lifetime is bound to the JSON
/// `Value` it was parsed from, so callers must keep the `Value` alive for the
/// duration of any borrow.
#[derive(Debug, Clone)]
pub struct Event<'a> {
    pub kind: EventKind,
    pub ts_ns: u64,
    pub pid: u32,
    pub tid: u32,
    /// Effective UID when supplied by the event producer. In particular,
    /// userspace crash sources may not know it; absence is not UID 0.
    pub uid: Option<u32>,
    /// Syscall number. `-1` for binder events.
    pub syscall_nr: i32,
    pub name: &'a str,
    pub comm: &'a str,
    pub is_enter: bool,
    pub ret: i64,
    pub args: [u64; 6],
    /// Active causal scenario stamped by the trace control socket.
    pub scenario_id: Option<&'a str>,
    /// Resolved path for the syscall's file descriptor, when known.
    pub fd_path: Option<&'a str>,
    /// Verified Binder/AIDL attribution fields, when known.
    pub binder_service: Option<&'a str>,
    pub binder_interface: Option<&'a str>,
    pub binder_method: Option<&'a str>,
    /// Decoded data field — typically a path, sockaddr, or hex blob. May be
    /// absent if the BPF capture failed (PAN on kernel 4.14).
    pub data: Option<&'a str>,
    /// `"RWX"` or `"WX"` for `mmap`/`mprotect`. `None` otherwise.
    pub rwx_alert: Option<&'a str>,
    /// Resolved stack trace (kernel + user, joined with `" <- "` and `" ;; "`).
    /// `None` when stack capture is off or the frames couldn't be resolved.
    pub stack: Option<&'a str>,
    /// Caller-supplied monotonic correlation token. `None` when the producer
    /// did not stamp one (offline NDJSON captured before the field existed).
    pub event_id: Option<u64>,
    /// `fd_count` field from a `type:"fd_snapshot"` event. `None` for
    /// syscall and binder events.
    pub fd_count: Option<u32>,
    /// `fd_pct_of_rlimit` field from a `type:"fd_snapshot"` event when the
    /// rlimit was known. `None` when missing or for non-snapshot events.
    pub fd_pct_of_rlimit: Option<u8>,
    /// Decoded ioctl family — emitted by the post-exit ioctl decoder
    /// (sprint-1 PR 2). Examples: `"dma_heap"`, `"binder"`, `"dma_buf"`.
    /// `None` for non-ioctl syscalls or when the cmd type byte is unknown.
    pub ioctl_family: Option<&'a str>,
    /// Decoded ioctl name — e.g. `"DMA_HEAP_IOCTL_ALLOC"`. `None` when the
    /// command isn't in the userspace decoder registry.
    pub ioctl_name: Option<&'a str>,
    /// Sprint-2 PR 1: signal value from a `type:"process_exit"` event. `0`
    /// when the source did not observe a signal (normal exit, ANR-only).
    /// `None` for non-exit events.
    pub exit_signal: Option<u32>,
    /// Sprint-2 PR 1: classification string (`"crash"`, `"signal_exit"`,
    /// `"abnormal_exit"`, `"normal_exit"`) from a `type:"process_exit"`
    /// event. `None` for non-exit events.
    pub exit_classification: Option<&'a str>,
    /// Sprint-2 PR 1: source attribution (`"tracepoint"` / `"logcat"` /
    /// `"tombstone"`) from a `type:"process_exit"` event. `None` for
    /// non-exit events.
    pub exit_source: Option<&'a str>,
    /// Sprint-2 PR 2: lifecycle status from a `type:"binder_call"` event
    /// (`"completed"` / `"callee_crashed"` / `"unmatched"`). `None` for
    /// non-binder_call events.
    pub binder_status: Option<&'a str>,
    /// Sprint-2 PR 2: AIDL transaction code from a `type:"binder_call"`
    /// event. `None` for non-binder_call events.
    pub binder_code: Option<u32>,
    /// Sprint-2 PR 2: caller-side PID from a `type:"binder_call"` event.
    /// `None` for non-binder_call events.
    pub binder_caller_pid: Option<u32>,
    /// Sprint-2 PR 2: callee-side PID from a `type:"binder_call"` event.
    /// `None` for non-binder_call events.
    pub binder_callee_pid: Option<u32>,
    /// Bounded sendmsg/recvmsg control metadata object emitted by neutron
    /// when `msg_controllen > 0`.
    pub unix_msg_control: bool,
    /// Number of file descriptors in the first SCM_RIGHTS control message.
    /// `None` when the event is not sendmsg/recvmsg or no SCM_RIGHTS header
    /// was captured.
    pub unix_scm_rights_fds: Option<u32>,
    /// True when sendmsg/recvmsg syscall flags included `MSG_PEEK`.
    pub unix_msg_peek: Option<bool>,

    /// Owned JSON value — kept so callers can clone it into snapshots without
    /// re-parsing the raw line. Use [`Event::raw_json`] to access.
    raw: &'a Value,
    /// The original line, for byte-exact snapshots.
    raw_line: Option<&'a str>,
}

impl<'a> Event<'a> {
    /// Parse a `serde_json::Value`. Returns `None` if mandatory fields are
    /// missing or if the JSON object is the wrong shape.
    pub fn from_value(v: &'a Value, raw_line: Option<&'a str>) -> Option<Self> {
        let obj = v.as_object()?;
        let type_str = obj.get("type").and_then(|t| t.as_str());
        let is_binder = type_str == Some("binder");
        let is_fd_snapshot = type_str == Some("fd_snapshot");
        let is_process_exit = type_str == Some("process_exit");
        let is_binder_call = type_str == Some("binder_call");
        let kind = if is_binder {
            EventKind::Binder
        } else if is_fd_snapshot {
            EventKind::FdSnapshot
        } else if is_process_exit {
            EventKind::ProcessExit
        } else if is_binder_call {
            EventKind::BinderCall
        } else {
            EventKind::Syscall
        };

        // Snapshot/exit/call events carry no `nr` field — synthesise a sentinel so
        // existing rule predicates that check `syscall_in` simply fail to
        // match (they do today: list.contains(&-2)/(-3)/(-5) is false for any
        // real syscall number).
        let syscall_nr = if is_binder {
            -1
        } else if is_fd_snapshot {
            -2
        } else if is_process_exit {
            -3
        } else if is_binder_call {
            -5
        } else {
            obj.get("nr").and_then(|n| n.as_i64())? as i32
        };

        let ts_ns = obj.get("ts_ns").and_then(|v| v.as_u64()).unwrap_or(0);
        // For `binder_call` synthetic events the caller-side PID is the
        // useful aggregation key (per_process collapses calls from the same
        // app); the raw JSON does not carry a top-level `pid` field, so map
        // `caller_pid` onto `pid` here.
        let pid = if is_binder_call {
            obj.get("caller_pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32
        } else {
            obj.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32
        };
        let tid = obj.get("tid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let uid = obj
            .get("uid")
            .and_then(|v| v.as_u64())
            .and_then(|value| u32::try_from(value).ok());
        // Schema cleanup (sprint 1): prefer the explicit `phase` field when
        // present, fall back to the legacy `enter` boolean. Defaults to `true`
        // (treat as enter) when neither is supplied — matches prior behaviour
        // for malformed lines.
        let is_enter = match obj.get("phase").and_then(|v| v.as_str()) {
            Some("enter") => true,
            Some("exit") => false,
            _ => obj.get("enter").and_then(|v| v.as_bool()).unwrap_or(true),
        };
        let ret = obj.get("ret").and_then(|v| v.as_i64()).unwrap_or(0);
        let comm = obj.get("comm").and_then(|v| v.as_str()).unwrap_or("");
        let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let data = obj.get("data").and_then(|v| v.as_str());
        let rwx_alert = obj.get("rwx_alert").and_then(|v| v.as_str());
        let stack = obj.get("stack").and_then(|v| v.as_str());
        let event_id = obj.get("event_id").and_then(|v| v.as_u64());
        let scenario_id = obj.get("scenario_id").and_then(|v| v.as_str());
        let fd_path = obj.get("fd_path").and_then(|v| v.as_str());
        let binder_service = obj.get("service").and_then(|v| v.as_str());
        let binder_interface = obj
            .get("interface_descriptor")
            .or_else(|| obj.get("interface"))
            .and_then(|v| v.as_str());
        let binder_method = obj.get("method").and_then(|v| v.as_str());
        // FdSnapshot-only fields. None for syscall/binder events.
        let fd_count = obj
            .get("fd_count")
            .and_then(|v| v.as_u64())
            .map(|n| u32::try_from(n).unwrap_or(u32::MAX));
        let fd_pct_of_rlimit = obj
            .get("fd_pct_of_rlimit")
            .and_then(|v| v.as_u64())
            .map(|n| u8::try_from(n.min(255)).unwrap_or(u8::MAX));
        let ioctl_family = obj.get("ioctl_family").and_then(|v| v.as_str());
        let ioctl_name = obj.get("ioctl_name").and_then(|v| v.as_str());
        let exit_signal = if is_process_exit {
            // Absent = normal exit (no signal). Treat as 0 so predicates that
            // require non-zero signal (R003 with exit_signal_in) just don't
            // match, instead of needing a separate "is exit" guard.
            Some(
                obj.get("exit_signal")
                    .and_then(|v| v.as_u64())
                    .map(|n| u32::try_from(n).unwrap_or(u32::MAX))
                    .unwrap_or(0),
            )
        } else {
            None
        };
        let exit_classification = if is_process_exit {
            obj.get("classification").and_then(|v| v.as_str())
        } else {
            None
        };
        let exit_source = if is_process_exit {
            obj.get("source").and_then(|v| v.as_str())
        } else {
            None
        };
        let binder_status = if is_binder_call {
            obj.get("status").and_then(|v| v.as_str())
        } else {
            None
        };
        let binder_code = if is_binder_call {
            obj.get("code")
                .and_then(|v| v.as_u64())
                .map(|n| u32::try_from(n).unwrap_or(u32::MAX))
        } else {
            None
        };
        let binder_caller_pid = if is_binder_call {
            obj.get("caller_pid")
                .and_then(|v| v.as_u64())
                .map(|n| u32::try_from(n).unwrap_or(u32::MAX))
        } else {
            None
        };
        let binder_callee_pid = if is_binder_call {
            obj.get("callee_pid")
                .and_then(|v| v.as_u64())
                .map(|n| u32::try_from(n).unwrap_or(u32::MAX))
        } else {
            None
        };
        let unix_ctrl = obj.get("unix_msg_control").and_then(|v| v.as_object());
        let unix_msg_control = unix_ctrl.is_some();
        let unix_scm_rights_fds = unix_ctrl
            .and_then(|m| m.get("scm_rights_fds"))
            .and_then(|v| v.as_u64())
            .map(|n| u32::try_from(n).unwrap_or(u32::MAX));
        let unix_msg_peek = unix_ctrl
            .and_then(|m| m.get("msg_peek"))
            .and_then(|v| v.as_bool());

        let mut args = [0u64; 6];
        if let Some(arr) = obj.get("args").and_then(|a| a.as_array()) {
            for (i, slot) in args.iter_mut().enumerate() {
                if let Some(val) = arr.get(i).and_then(|v| v.as_u64()) {
                    *slot = val;
                }
            }
        }

        Some(Event {
            kind,
            ts_ns,
            pid,
            tid,
            uid,
            syscall_nr,
            name,
            comm,
            is_enter,
            ret,
            args,
            scenario_id,
            fd_path,
            binder_service,
            binder_interface,
            binder_method,
            data,
            rwx_alert,
            stack,
            event_id,
            fd_count,
            fd_pct_of_rlimit,
            ioctl_family,
            ioctl_name,
            exit_signal,
            exit_classification,
            exit_source,
            binder_status,
            binder_code,
            binder_caller_pid,
            binder_callee_pid,
            unix_msg_control,
            unix_scm_rights_fds,
            unix_msg_peek,
            raw: v,
            raw_line,
        })
    }

    /// Convenience: parse a single NDJSON line. The returned `Event` borrows
    /// from a `Value` that is dropped at the end of the call — for the engine
    /// hot path use [`Event::from_value`] with an externally-owned `Value`.
    ///
    /// This helper is mainly for tests and tools that read line-by-line.
    pub fn parse_line(_line: &str) -> Option<OwnedEvent> {
        let value: Value = serde_json::from_str(_line).ok()?;
        // We re-validate by constructing an `Event` view to fail fast on bad shape.
        Event::from_value(&value, Some(_line))?;
        Some(OwnedEvent {
            value,
            raw_line: _line.to_string(),
        })
    }

    /// The original JSON value backing this event.
    pub fn raw_json(&self) -> &Value {
        self.raw
    }

    /// The original NDJSON line, if available.
    pub fn raw_line(&self) -> Option<&str> {
        self.raw_line
    }
}

/// Owning wrapper used by [`Event::parse_line`]. Call [`OwnedEvent::view`] to
/// borrow it as a typed [`Event`].
pub struct OwnedEvent {
    value: Value,
    raw_line: String,
}

impl OwnedEvent {
    pub fn view(&self) -> Option<Event<'_>> {
        Event::from_value(&self.value, Some(self.raw_line.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_openat_event() {
        let line = r#"{"ts_ns":100,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,140000,0,0,0,0],"data":"/proc/self/maps"}"#;
        let owned = Event::parse_line(line).unwrap();
        let ev = owned.view().unwrap();
        assert_eq!(ev.kind, EventKind::Syscall);
        assert_eq!(ev.syscall_nr, 56);
        assert_eq!(ev.pid, 42);
        assert!(!ev.is_enter);
        assert_eq!(ev.data, Some("/proc/self/maps"));
    }

    #[test]
    fn parses_binder_event() {
        let line = r#"{"type":"binder","ts_ns":200,"pid":42,"tid":42,"comm":"app","to_proc":"system_server","code":1}"#;
        let owned = Event::parse_line(line).unwrap();
        let ev = owned.view().unwrap();
        assert_eq!(ev.kind, EventKind::Binder);
        assert_eq!(ev.syscall_nr, -1);
    }

    #[test]
    fn process_exit_without_uid_does_not_become_root() {
        let line = r#"{"type":"process_exit","pid":42,"uid":null,"classification":"crash"}"#;
        let owned = Event::parse_line(line).unwrap();
        assert_eq!(owned.view().unwrap().uid, None);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Event::parse_line("not json").is_none());
    }

    #[test]
    fn prefers_phase_over_legacy_enter_boolean() {
        // Producer emits phase:"exit" but stale `enter:true` (e.g. a buggy
        // bridge). The explicit phase field wins.
        let line = r#"{"type":"syscall","ts_ns":100,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":true,"phase":"exit","ret":7,"args":[0,0,0,0,0,0]}"#;
        let owned = Event::parse_line(line).unwrap();
        let ev = owned.view().unwrap();
        assert!(!ev.is_enter);
    }

    #[test]
    fn falls_back_to_enter_boolean_when_phase_absent() {
        // Pre-PR-1 producers don't emit `phase`. We must still parse correctly.
        let line = r#"{"ts_ns":100,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0]}"#;
        let owned = Event::parse_line(line).unwrap();
        let ev = owned.view().unwrap();
        assert!(!ev.is_enter);
    }

    #[test]
    fn parses_event_id_when_present() {
        let line = r#"{"type":"syscall","ts_ns":100,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":true,"phase":"enter","ret":0,"args":[0,0,0,0,0,0],"event_id":4242}"#;
        let owned = Event::parse_line(line).unwrap();
        let ev = owned.view().unwrap();
        assert_eq!(ev.event_id, Some(4242));
    }

    #[test]
    fn omits_event_id_when_absent() {
        let line = r#"{"ts_ns":100,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":true,"ret":0,"args":[0,0,0,0,0,0]}"#;
        let owned = Event::parse_line(line).unwrap();
        let ev = owned.view().unwrap();
        assert_eq!(ev.event_id, None);
    }
}
