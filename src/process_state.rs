//! Session-local process identity and cache lifetime. No proc failure proves death.

use std::collections::HashMap;
use std::io;

use crate::{fdgraph::FdGraph, symbolize::ProcSymbolizer, SyscallEvent};

#[derive(Default)]
pub struct ProcessState {
    pub fds: FdGraph,
    pub symbols: HashMap<u32, Option<ProcSymbolizer>>,
    identities: HashMap<u32, u64>,
    pending_exits: HashMap<u32, (Option<u64>, SyscallEvent)>,
    pub reconciliation_failures: u64,
}

impl ProcessState {
    /// Call before enriching an event. Unknown identity invalidates cached data.
    pub fn refresh(&mut self, pid: u32, starttime: Option<u64>) -> bool {
        let changed = starttime.is_none() || self.identities.get(&pid).copied() != starttime;
        if changed {
            self.symbols.remove(&pid);
            self.identities.remove(&pid);
        }
        self.fds.validate_incarnation(pid, starttime);
        if let Some(starttime) = starttime {
            self.identities.insert(pid, starttime);
        }
        changed
    }

    pub fn task_exit(&mut self, event: SyscallEvent) {
        let pid = event.pid;
        // Legacy all-process observation also needs a hard ceiling.
        if !self.pending_exits.contains_key(&pid) && self.pending_exits.len() >= 16_384 {
            self.reconciliation_failures = self.reconciliation_failures.saturating_add(1);
            return;
        }
        self.pending_exits
            .insert(pid, (self.identities.get(&pid).copied(), event));
    }

    pub fn confirmed_exits(&mut self) -> Vec<(SyscallEvent, Option<u64>)> {
        let mut confirmed = Vec::new();
        self.pending_exits.retain(
            |pid, (starttime, event)| match process_dead(*pid, *starttime) {
                Ok(true) => {
                    confirmed.push((*event, *starttime));
                    false
                }
                Ok(false) => true,
                Err(_) => {
                    self.reconciliation_failures = self.reconciliation_failures.saturating_add(1);
                    true
                }
            },
        );
        confirmed.sort_by_key(|(event, _)| (event.timestamp_ns, event.pid));
        confirmed
    }

    pub fn drop_pid(&mut self, pid: u32) {
        self.identities.remove(&pid);
        self.symbols.remove(&pid);
        self.fds.drop_pid(pid);
        self.pending_exits.remove(&pid);
    }
}

fn process_dead(pid: u32, expected_starttime: Option<u64>) -> io::Result<bool> {
    match crate::fdgraph::poller::read_bounded_proc_file(
        std::path::Path::new(&format!("/proc/{pid}/stat")),
        64 * 1024,
    ) {
        Ok(bytes) => {
            let stat = std::str::from_utf8(&bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            stat_proves_death(stat, expected_starttime)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}

fn stat_proves_death(stat: &str, expected_starttime: Option<u64>) -> io::Result<bool> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid process stat");
    let (_, fields) = stat.rsplit_once(')').ok_or_else(invalid)?;
    let mut fields = fields.split_whitespace();
    let state = fields.next().ok_or_else(invalid)?;
    let threads = fields
        .nth(16)
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .ok_or_else(invalid)?;
    let starttime = fields
        .nth(1)
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(invalid)?;
    Ok(
        expected_starttime.is_some_and(|expected| expected != starttime)
            || (matches!(state, "Z" | "X" | "x") && threads == 1),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leader_exit_keeps_workers_alive_and_recycled_pid_ends_old_incarnation() {
        let stat = |state, threads, start| {
            format!(
                "42 (comm with ) space) {state} {} {threads} 0 {start}",
                vec!["0"; 16].join(" ")
            )
        };
        assert!(!stat_proves_death(&stat("Z", 2, 100), Some(100)).unwrap());
        assert!(!stat_proves_death(&stat("S", 1, 100), Some(100)).unwrap());
        assert!(stat_proves_death(&stat("Z", 1, 100), Some(100)).unwrap());
        assert!(stat_proves_death(&stat("S", 1, 200), Some(100)).unwrap());
        assert!(stat_proves_death("unreadable", Some(100)).is_err());
    }
}
