//! Per-PID bounded ring buffer of recent NDJSON event lines.
//!
//! When a `ProcessExitEvent` fires, the formatter dumps the last `N` lines
//! we observed for that PID into the `crash_context` field of the emitted
//! `process_exit` JSON event. This makes single-line crash records useful
//! standalone — a triager can see the last `N` syscalls / binder calls /
//! fd snapshots that led up to the exit without grepping through the full
//! stream.
//!
//! ## Memory bound
//!
//! Two-axis cap: `max_pids` distinct PIDs and `max_lines_per_pid` lines per
//! PID. Defaults are conservative (200 PIDs × 100 lines × ~250 bytes ≈ 5 MB
//! worst case). When the PID cap is exceeded, the oldest-touched PID's
//! buffer is evicted in full (LRU). When the per-PID cap is exceeded, the
//! oldest line for that PID is dropped (FIFO inside the buffer).
//!
//! ## Lifecycle
//!
//! - Every emitted JSON line goes through [`RingBufferStore::record`] —
//!   tracepoint syscalls, binder transactions, fd_snapshots, and the
//!   process_exit lines themselves.
//! - On `ProcessExitEvent` the main loop calls [`RingBufferStore::take`]
//!   which removes and returns the buffer (so the same PID's events from
//!   a recycled PID don't bleed into the next process's lookback).

use std::collections::{HashMap, VecDeque};

const DEFAULT_MAX_PIDS: usize = 200;
const DEFAULT_MAX_LINES_PER_PID: usize = 100;

/// Per-PID ring buffer of recent NDJSON event lines.
#[derive(Debug)]
pub struct RingBufferStore {
    max_pids: usize,
    max_lines_per_pid: usize,
    /// `(buffer, lru_tick)` per PID. `lru_tick` is incremented on every
    /// `record`/`take` for that PID; the smallest value is the LRU victim.
    buffers: HashMap<u32, (VecDeque<String>, u64)>,
    tick: u64,
}

impl Default for RingBufferStore {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_PIDS, DEFAULT_MAX_LINES_PER_PID)
    }
}

impl RingBufferStore {
    pub fn new(max_pids: usize, max_lines_per_pid: usize) -> Self {
        Self {
            max_pids: max_pids.max(1),
            max_lines_per_pid: max_lines_per_pid.max(1),
            buffers: HashMap::new(),
            tick: 0,
        }
    }

    pub fn max_pids(&self) -> usize {
        self.max_pids
    }

    pub fn max_lines_per_pid(&self) -> usize {
        self.max_lines_per_pid
    }

    /// Number of distinct PIDs currently buffered. Useful for tests and
    /// summary output; not exposed via JSON.
    pub fn pid_count(&self) -> usize {
        self.buffers.len()
    }

    /// Append `line` to the PID's buffer. The line is cloned (we have no
    /// borrow assumptions about the caller's storage). Drops the oldest
    /// line for that PID when full; evicts the LRU PID when total PID
    /// count would exceed `max_pids`.
    pub fn record(&mut self, pid: u32, line: &str) {
        if pid == 0 {
            return; // never buffer kernel-pid noise
        }
        self.tick = self.tick.wrapping_add(1);
        let max_lines = self.max_lines_per_pid;
        let entry = self
            .buffers
            .entry(pid)
            .or_insert_with(|| (VecDeque::with_capacity(max_lines.min(64)), 0));
        if entry.0.len() == max_lines {
            entry.0.pop_front();
        }
        entry.0.push_back(line.to_string());
        entry.1 = self.tick;
        // Evict LRU PID(s) until we are within the cap.
        while self.buffers.len() > self.max_pids {
            if let Some(victim) = self
                .buffers
                .iter()
                .min_by_key(|(_, v)| v.1)
                .map(|(k, _)| *k)
            {
                self.buffers.remove(&victim);
            } else {
                break;
            }
        }
    }

    /// Return the buffered lines for `pid` and remove them from the store.
    /// Returns an empty vec when the PID was never recorded.
    pub fn take(&mut self, pid: u32) -> Vec<String> {
        match self.buffers.remove(&pid) {
            Some((buf, _)) => buf.into_iter().collect(),
            None => Vec::new(),
        }
    }

    /// Read-only inspection without consuming the buffer. Used by tests.
    #[cfg(test)]
    pub fn peek(&self, pid: u32) -> Vec<String> {
        match self.buffers.get(&pid) {
            Some((buf, _)) => buf.iter().cloned().collect(),
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_take_returns_lines_in_order() {
        let mut s = RingBufferStore::new(10, 5);
        s.record(42, "line1");
        s.record(42, "line2");
        s.record(42, "line3");
        let out = s.take(42);
        assert_eq!(out, vec!["line1", "line2", "line3"]);
        // Take consumes — second take is empty.
        assert!(s.take(42).is_empty());
    }

    #[test]
    fn per_pid_cap_drops_oldest_line() {
        let mut s = RingBufferStore::new(10, 3);
        for i in 0..5 {
            s.record(7, &format!("line{i}"));
        }
        let out = s.take(7);
        // Cap is 3 → only the last 3 survive.
        assert_eq!(out, vec!["line2", "line3", "line4"]);
    }

    #[test]
    fn pid_cap_evicts_lru_pid() {
        let mut s = RingBufferStore::new(2, 5);
        s.record(1, "a");
        s.record(2, "b");
        s.record(3, "c"); // forces eviction of the LRU PID (1).
        assert_eq!(s.pid_count(), 2);
        assert!(s.take(1).is_empty(), "PID 1 should have been evicted");
        assert!(!s.take(2).is_empty());
        assert!(!s.take(3).is_empty());
    }

    #[test]
    fn touching_pid_refreshes_lru_position() {
        let mut s = RingBufferStore::new(2, 5);
        s.record(1, "a");
        s.record(2, "b");
        s.record(1, "a2"); // refreshes PID 1's LRU
        s.record(3, "c"); // should now evict PID 2, not PID 1.
        assert_eq!(s.pid_count(), 2);
        let p1 = s.take(1);
        assert_eq!(p1, vec!["a", "a2"], "PID 1 should still hold its lines");
        assert!(s.take(2).is_empty(), "PID 2 should have been evicted");
    }

    #[test]
    fn pid_zero_is_never_buffered() {
        let mut s = RingBufferStore::new(10, 5);
        s.record(0, "kernel");
        assert!(s.take(0).is_empty());
        assert_eq!(s.pid_count(), 0);
    }

    #[test]
    fn defaults_are_sensible() {
        let s = RingBufferStore::default();
        assert!(s.max_pids() >= 100);
        assert!(s.max_lines_per_pid() >= 50);
    }

    #[test]
    fn peek_does_not_consume() {
        let mut s = RingBufferStore::new(10, 5);
        s.record(99, "x");
        s.record(99, "y");
        let p = s.peek(99);
        assert_eq!(p, vec!["x", "y"]);
        let t = s.take(99);
        assert_eq!(
            t,
            vec!["x", "y"],
            "take must still see the lines after peek"
        );
    }
}
