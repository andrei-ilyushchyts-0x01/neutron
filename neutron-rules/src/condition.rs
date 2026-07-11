//! Match conditions — predicates evaluated against an [`Event`].
//!
//! A `MatchCondition` is a struct with all-optional fields. Every field that
//! is set must hold for the condition to match (implicit AND). A rule's
//! `conditions:` list AND-joins multiple conditions, but typically a single
//! condition is enough — multiple optional fields collapse the same logic
//! into one entry. YAML form:
//!
//! ```yaml
//! conditions:
//!   - syscall_in: [56]
//!     path_prefix: /proc/self/maps
//! ```
//!
//! The struct-of-options layout is friendlier than a tagged enum for YAML
//! authors and matches the format used by Falco / Sigma-style rule DSLs.

use serde::{Deserialize, Serialize};

use crate::event::{Event, EventKind};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchCondition {
    /// Match an event from one of these causal scenarios.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scenario_in: Option<Vec<String>>,

    /// Match the beginning of the resolved file-descriptor path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fd_path_prefix: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_service_in: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_interface_in: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_method_in: Option<Vec<String>>,

    /// Match a causal process crash or a Binder callee-crashed lifecycle event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_service_crash: Option<bool>,

    /// Match if the event is a syscall with `nr` in this list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syscall_in: Option<Vec<i32>>,

    /// Match if the event is a binder transaction (`type == "binder"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder: Option<bool>,

    /// Match if the event's `data` field starts with this string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,

    /// Match if the event's `data` field contains this substring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_contains: Option<String>,

    /// Match if the event's `data` field is exactly one of these strings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_in: Option<Vec<String>>,

    /// Match if the event's `data` field contains *any* of these substrings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_any: Option<Vec<String>>,

    /// Match only if `data` does NOT contain any of these substrings.
    /// Useful for excluding self-references (`/proc/self/`) when matching
    /// `/proc/<pid>/...` style cross-process inspection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_not_contains: Option<Vec<String>>,

    /// Match if the process `comm` contains *any* of these substrings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comm_contains: Option<Vec<String>>,

    /// Match only if the process `comm` does NOT contain any of these.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comm_not_contains: Option<Vec<String>>,

    /// `true` -> only match enter events; `false` -> only exit events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enter_only: Option<bool>,

    /// Match if `ret < value`. Common idiom: `ret_lt: 0` (failed access check).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ret_lt: Option<i64>,

    /// Match if `ret == value`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ret_eq: Option<i64>,

    /// Match if the `rwx_alert` field equals one of `["RWX", "WX"]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rwx_alert_in: Option<Vec<String>>,

    /// Match if `args[0]` equals this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg0_eq: Option<u64>,

    /// Match if `args[0]` is in this list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg0_in: Option<Vec<u64>>,

    /// Index for the bounded generic argument comparisons below (`0..=5`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg_index: Option<u8>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg_eq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg_gt: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg_gte: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg_lt: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg_lte: Option<u64>,

    /// Match if the resolved `stack` field contains *any* of these substrings.
    /// If the event has no stack, this condition is treated as no-match
    /// (substring presence is required, not optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack_contains: Option<Vec<String>>,

    /// Match only if the resolved `stack` field does NOT contain any of these
    /// substrings. Events without a stack pass this filter trivially.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack_not_contains: Option<Vec<String>>,

    /// Match if the event is an FD-poller snapshot (`type:"fd_snapshot"`).
    /// Sprint-1 PR 3. Required precondition for `fd_count_*` predicates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fd_snapshot: Option<bool>,

    /// Match if the event's `fd_count` is strictly greater than this value.
    /// Implies `EventKind::FdSnapshot` — non-snapshot events have no
    /// fd_count and never match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fd_count_gt: Option<u32>,

    /// Match if the event's `fd_pct_of_rlimit` is strictly greater than
    /// this value. Implies `EventKind::FdSnapshot` AND that the snapshot
    /// carried a non-zero rlimit (events with unknown rlimit never match).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fd_count_pct_of_rlimit_gt: Option<u8>,

    /// Match if the event's decoded `ioctl_family` (e.g. `dma_heap`,
    /// `binder`) equals one of the listed strings. Sprint-1 PR 4. Events
    /// without a decoded family (non-ioctl, undecodable) never match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ioctl_family_in: Option<Vec<String>>,

    /// Match if the event's decoded `ioctl_name` (e.g. `DMA_HEAP_IOCTL_ALLOC`)
    /// equals one of the listed strings. Sprint-1 PR 4. Events without a
    /// known name never match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ioctl_name_in: Option<Vec<String>>,

    /// Match if the event is a `type:"process_exit"` line (sprint-2 PR 1).
    /// Required precondition for any of the `exit_*` predicates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_exit: Option<bool>,

    /// Match if the event's `exit_signal` is in this list. Implies
    /// `EventKind::ProcessExit`. Non-exit events have no signal field and
    /// never match. The list values are POSIX signal numbers (`11` for
    /// SIGSEGV, `6` for SIGABRT, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_signal_in: Option<Vec<u32>>,

    /// Match if the event's `classification` field is one of the listed
    /// values. Allowed values: `"crash"`, `"signal_exit"`, `"abnormal_exit"`,
    /// `"normal_exit"`. Implies `EventKind::ProcessExit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_classification_in: Option<Vec<String>>,

    /// Match if the event's `source` field is one of the listed values.
    /// Allowed: `"tracepoint"`, `"logcat"`, `"tombstone"`. Implies
    /// `EventKind::ProcessExit`. Useful for rules that should only fire
    /// when the signal info actually came from a userspace source (tombstone
    /// or logcat) rather than the bare BPF tracepoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_source_in: Option<Vec<String>>,

    /// Match if the event is a `type:"binder_call"` synthesised pair
    /// (sprint-2 PR 2). Required precondition for any of the `binder_*`
    /// predicates below.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_call: Option<bool>,

    /// Match if the binder_call's `status` is one of the listed strings.
    /// Allowed: `"completed"`, `"callee_crashed"`, `"unmatched"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_status_in: Option<Vec<String>>,

    /// Match if the binder_call's `code` (AIDL transaction code) is in
    /// this list. Use to scope rules to specific service interfaces —
    /// e.g. SurfaceFlinger frame submission codes, AudioFlinger control
    /// codes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder_code_in: Option<Vec<u32>>,

    /// Match if a syscall event carries a `unix_msg_control` object
    /// decoded from sendmsg/recvmsg control metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix_msg_control: Option<bool>,

    /// Match if the first SCM_RIGHTS control message carries at least this
    /// many file descriptors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix_scm_rights_fds_gte: Option<u32>,

    /// Match on the MSG_PEEK bit in sendmsg/recvmsg syscall flags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix_msg_peek: Option<bool>,
}

impl MatchCondition {
    pub fn validate(&self) -> Result<(), String> {
        let comparisons = [
            self.arg_eq,
            self.arg_gt,
            self.arg_gte,
            self.arg_lt,
            self.arg_lte,
        ];
        let has_comparison = comparisons.iter().any(Option::is_some);
        match (self.arg_index, has_comparison) {
            (Some(0..=5), true) | (None, false) => Ok(()),
            (Some(index), _) if index > 5 => Err(format!("arg_index {index} is outside 0..=5")),
            (Some(_), false) => Err("arg_index requires an arg comparison".into()),
            (None, true) => Err("arg comparison requires arg_index".into()),
            _ => unreachable!(),
        }
    }

    /// Returns `true` only if every Some(...) field matches.
    pub fn matches(&self, ev: &Event<'_>) -> bool {
        if let Some(list) = &self.scenario_in {
            match ev.scenario_id {
                Some(value) if list.iter().any(|candidate| candidate == value) => {}
                _ => return false,
            }
        }
        if let Some(prefix) = &self.fd_path_prefix {
            if !ev
                .fd_path
                .is_some_and(|path| path.starts_with(prefix.as_str()))
            {
                return false;
            }
        }
        for (actual, expected) in [
            (ev.binder_service, &self.binder_service_in),
            (ev.binder_interface, &self.binder_interface_in),
            (ev.binder_method, &self.binder_method_in),
        ] {
            if let Some(expected) = expected {
                match actual {
                    Some(value) if expected.iter().any(|candidate| candidate == value) => {}
                    _ => return false,
                }
            }
        }
        if let Some(true) = self.causal_service_crash {
            let process_crash = ev.kind == EventKind::ProcessExit
                && matches!(
                    ev.exit_classification,
                    Some("crash" | "signal_exit" | "abnormal_exit")
                );
            let binder_crash =
                ev.kind == EventKind::BinderCall && ev.binder_status == Some("callee_crashed");
            if !process_crash && !binder_crash {
                return false;
            }
        }
        if let Some(list) = &self.syscall_in {
            if ev.kind != EventKind::Syscall || !list.contains(&ev.syscall_nr) {
                return false;
            }
        }
        if let Some(true) = self.binder {
            if ev.kind != EventKind::Binder {
                return false;
            }
        }
        if let Some(p) = &self.path_prefix {
            if !ev.data.map(|d| d.starts_with(p.as_str())).unwrap_or(false) {
                return false;
            }
        }
        if let Some(p) = &self.path_contains {
            if !ev.data.map(|d| d.contains(p.as_str())).unwrap_or(false) {
                return false;
            }
        }
        if let Some(list) = &self.path_in {
            match ev.data {
                Some(d) if list.iter().any(|s| s == d) => {}
                _ => return false,
            }
        }
        if let Some(needles) = &self.data_any {
            match ev.data {
                Some(d) if needles.iter().any(|n| d.contains(n.as_str())) => {}
                _ => return false,
            }
        }
        if let Some(forbidden) = &self.path_not_contains {
            // No data => trivially matches (nothing forbidden present).
            if let Some(d) = ev.data {
                if forbidden.iter().any(|f| d.contains(f.as_str())) {
                    return false;
                }
            }
        }
        if let Some(list) = &self.comm_contains {
            if !list.iter().any(|c| ev.comm.contains(c.as_str())) {
                return false;
            }
        }
        if let Some(list) = &self.comm_not_contains {
            if list.iter().any(|c| ev.comm.contains(c.as_str())) {
                return false;
            }
        }
        if let Some(want_enter) = self.enter_only {
            if want_enter != ev.is_enter {
                return false;
            }
        }
        if let Some(v) = self.ret_lt {
            if ev.ret >= v {
                return false;
            }
        }
        if let Some(v) = self.ret_eq {
            if ev.ret != v {
                return false;
            }
        }
        if let Some(list) = &self.rwx_alert_in {
            match ev.rwx_alert {
                Some(a) if list.iter().any(|s| s == a) => {}
                _ => return false,
            }
        }
        if let Some(v) = self.arg0_eq {
            if ev.args[0] != v {
                return false;
            }
        }
        if let Some(list) = &self.arg0_in {
            if !list.contains(&ev.args[0]) {
                return false;
            }
        }
        if let Some(index) = self.arg_index {
            let value = ev.args[index as usize];
            if self.arg_eq.is_some_and(|limit| value != limit)
                || self.arg_gt.is_some_and(|limit| value <= limit)
                || self.arg_gte.is_some_and(|limit| value < limit)
                || self.arg_lt.is_some_and(|limit| value >= limit)
                || self.arg_lte.is_some_and(|limit| value > limit)
            {
                return false;
            }
        }
        if let Some(needles) = &self.stack_contains {
            // Absence of stack ⇒ no-match (we can't verify the substring is
            // present). This is intentional — see condition.rs doc.
            match ev.stack {
                Some(s) if needles.iter().any(|n| s.contains(n.as_str())) => {}
                _ => return false,
            }
        }
        if let Some(forbidden) = &self.stack_not_contains {
            // Absence of stack ⇒ trivially passes (nothing forbidden present).
            if let Some(s) = ev.stack {
                if forbidden.iter().any(|f| s.contains(f.as_str())) {
                    return false;
                }
            }
        }
        if let Some(true) = self.fd_snapshot {
            if ev.kind != EventKind::FdSnapshot {
                return false;
            }
        }
        if let Some(threshold) = self.fd_count_gt {
            // Implicit: requires an FdSnapshot event with fd_count present.
            // Non-snapshot events can't satisfy this; rule authors who want
            // to match on syscall-level fd values must use `arg0_*` etc.
            match ev.fd_count {
                Some(c) if c > threshold => {}
                _ => return false,
            }
        }
        if let Some(threshold) = self.fd_count_pct_of_rlimit_gt {
            match ev.fd_pct_of_rlimit {
                Some(pct) if pct > threshold => {}
                _ => return false,
            }
        }
        if let Some(list) = &self.ioctl_family_in {
            match ev.ioctl_family {
                Some(f) if list.iter().any(|s| s == f) => {}
                _ => return false,
            }
        }
        if let Some(list) = &self.ioctl_name_in {
            match ev.ioctl_name {
                Some(n) if list.iter().any(|s| s == n) => {}
                _ => return false,
            }
        }
        if let Some(true) = self.process_exit {
            if ev.kind != EventKind::ProcessExit {
                return false;
            }
        }
        if let Some(list) = &self.exit_signal_in {
            // exit_signal is `Some(0)` on a normal exit; we still want
            // exit_signal_in: [0] to match that case if a rule author writes it,
            // hence Some(s) instead of Some(s) if s != 0.
            match ev.exit_signal {
                Some(s) if list.contains(&s) => {}
                _ => return false,
            }
        }
        if let Some(list) = &self.exit_classification_in {
            match ev.exit_classification {
                Some(c) if list.iter().any(|s| s == c) => {}
                _ => return false,
            }
        }
        if let Some(list) = &self.exit_source_in {
            match ev.exit_source {
                Some(s) if list.iter().any(|x| x == s) => {}
                _ => return false,
            }
        }
        if let Some(true) = self.binder_call {
            if ev.kind != EventKind::BinderCall {
                return false;
            }
        }
        if let Some(list) = &self.binder_status_in {
            match ev.binder_status {
                Some(s) if list.iter().any(|x| x == s) => {}
                _ => return false,
            }
        }
        if let Some(list) = &self.binder_code_in {
            match ev.binder_code {
                Some(c) if list.contains(&c) => {}
                _ => return false,
            }
        }
        if let Some(true) = self.unix_msg_control {
            if !ev.unix_msg_control {
                return false;
            }
        }
        if let Some(min_fds) = self.unix_scm_rights_fds_gte {
            match ev.unix_scm_rights_fds {
                Some(n) if n >= min_fds => {}
                _ => return false,
            }
        }
        if let Some(want_peek) = self.unix_msg_peek {
            match ev.unix_msg_peek {
                Some(v) if v == want_peek => {}
                _ => return false,
            }
        }
        true
    }
}

/// Returns the "target" string for a matched event, used by
/// [`crate::AggregateMode::PerTarget`]. Picks the most identifying field
/// available — typically the path/data — falling back to comm.
pub fn match_target(ev: &Event<'_>) -> String {
    if let Some(d) = ev.data {
        return d.to_string();
    }
    ev.comm.to_string()
}
