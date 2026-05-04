//! Parsed view over a single neutron NDJSON event.
//!
//! Mirrors the JSON schema produced by `neutron --json` (see
//! `docs/guides/output-formats.md`). Only the fields the engine needs are
//! materialised; unknown fields are ignored.

use serde_json::Value;

/// What category the underlying event belongs to. Allows rules to match
/// `binder` events without forcing them into the same shape as syscalls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    Syscall,
    Binder,
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
    pub uid: u32,
    /// Syscall number. `-1` for binder events.
    pub syscall_nr: i32,
    pub name: &'a str,
    pub comm: &'a str,
    pub is_enter: bool,
    pub ret: i64,
    pub args: [u64; 6],
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
        let is_binder = obj.get("type").and_then(|t| t.as_str()) == Some("binder");
        let kind = if is_binder {
            EventKind::Binder
        } else {
            EventKind::Syscall
        };

        let syscall_nr = if is_binder {
            -1
        } else {
            obj.get("nr").and_then(|n| n.as_i64())? as i32
        };

        let ts_ns = obj.get("ts_ns").and_then(|v| v.as_u64()).unwrap_or(0);
        let pid = obj.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let tid = obj.get("tid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let uid = obj.get("uid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
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
            data,
            rwx_alert,
            stack,
            event_id,
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
