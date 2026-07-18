//! Crash-correlation sources (sprint-2 PR 1).
//!
//! Three independent producers feed `ProcessExitEvent` values into the main
//! event loop:
//!
//! 1. **BPF tracepoint** — `sched/sched_process_exit` emits a synthetic
//!    `SyscallEvent` with `syscall_nr == SYSCALL_NR_PROCESS_EXIT (-3)`.
//!    Always available; carries no signal info.
//! 2. **Logcat tail** — spawns `logcat -v threadtime *:F` and parses
//!    `FATAL EXCEPTION` / native `DEBUG` / `ANR in` lines. Emits with
//!    `ExitSource::Logcat`. Android-only (no logcat on host).
//! 3. **Tombstone watcher** — polls `/data/tombstones/`, parses the
//!    header of each new file (signal, fault addr, comm). Emits with
//!    `ExitSource::Tombstone`. Android-only (path absent on host).
//!
//! Per_process aggregation in the rule engine handles the fan-out: a
//! single SIGSEGV typically produces all three events within milliseconds.
//!
//! The userspace sources are abstracted behind traits (`LogcatReader`,
//! `TombstoneWatcher`) so unit tests can feed synthetic streams without
//! touching `/data/tombstones/` or spawning subprocesses.

pub mod binder_tracker;
pub mod logcat;
pub mod lookback;
pub mod tombstone;

use neutron_common::{is_fatal_signal, signal_name, ExitSource};

/// One observed process exit, regardless of which source detected it.
///
/// `signal == 0` means "exit code only" (normal `exit(2)` return). A non-zero
/// signal field combined with `is_fatal_signal == true` is what
/// `R003_process_crash` matches.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProcessExitEvent {
    pub ts_ns: u64,
    pub pid: u32,
    /// Effective UID when the observing source reports it. Logcat native
    /// crash records and older tombstones do not carry a UID; `None` must
    /// never be interpreted as UID 0 (root).
    pub uid: Option<u32>,
    pub comm: String,
    pub exit_code: u8,
    pub exit_signal: u32,
    pub source: ExitSource,
}

/// Classification derived from `exit_signal` + `exit_code`. Used as the
/// `"classification"` field on emitted JSON and as the `exit_classification_in`
/// rule-engine predicate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitClassification {
    /// Killed by a fatal POSIX signal (SIGSEGV/SIGABRT/...).
    Crash,
    /// Killed by a non-fatal signal (SIGKILL/SIGTERM/...) — typically OOM
    /// or graceful shutdown.
    SignalExit,
    /// `exit(N)` with `N != 0`.
    AbnormalExit,
    /// `exit(0)` — clean termination.
    NormalExit,
}

impl ExitClassification {
    pub const fn as_str(self) -> &'static str {
        match self {
            ExitClassification::Crash => "crash",
            ExitClassification::SignalExit => "signal_exit",
            ExitClassification::AbnormalExit => "abnormal_exit",
            ExitClassification::NormalExit => "normal_exit",
        }
    }
}

impl ProcessExitEvent {
    /// Classify the exit. Signal field takes precedence: a process killed by
    /// SIGSEGV with exit_code=0 is a crash, not a normal exit.
    pub fn classify(&self) -> ExitClassification {
        if self.exit_signal != 0 {
            if is_fatal_signal(self.exit_signal) {
                ExitClassification::Crash
            } else {
                ExitClassification::SignalExit
            }
        } else if self.exit_code != 0 {
            ExitClassification::AbnormalExit
        } else {
            ExitClassification::NormalExit
        }
    }

    /// Symbolic name (`"SIGSEGV"`) when the signal is in `signal_name`'s
    /// table, else `None`.
    pub fn signal_name(&self) -> Option<&'static str> {
        if self.exit_signal == 0 {
            None
        } else {
            signal_name(self.exit_signal)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutron_common::{SIGABRT, SIGSEGV};

    #[test]
    fn fatal_signal_classifies_as_crash() {
        let ev = ProcessExitEvent {
            exit_signal: SIGSEGV,
            ..Default::default()
        };
        assert_eq!(ev.classify(), ExitClassification::Crash);
        assert_eq!(ev.signal_name(), Some("SIGSEGV"));
    }

    #[test]
    fn sigkill_classifies_as_signal_exit_not_crash() {
        let ev = ProcessExitEvent {
            exit_signal: 9,
            ..Default::default()
        };
        assert_eq!(ev.classify(), ExitClassification::SignalExit);
    }

    #[test]
    fn nonzero_exit_code_classifies_as_abnormal() {
        let ev = ProcessExitEvent {
            exit_code: 137,
            ..Default::default()
        };
        assert_eq!(ev.classify(), ExitClassification::AbnormalExit);
    }

    #[test]
    fn zero_exit_no_signal_is_normal() {
        let ev = ProcessExitEvent::default();
        assert_eq!(ev.classify(), ExitClassification::NormalExit);
        assert_eq!(ev.signal_name(), None);
    }

    #[test]
    fn signal_takes_precedence_over_exit_code() {
        // Crashing tasks often have exit_code=0 from kernel's perspective
        // because the process never reached exit(2). Verify signal wins.
        let ev = ProcessExitEvent {
            exit_signal: SIGABRT,
            exit_code: 0,
            ..Default::default()
        };
        assert_eq!(ev.classify(), ExitClassification::Crash);
    }
}
