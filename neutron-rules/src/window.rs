//! Sliding-window counter for frequency-based rules.
//!
//! The engine keeps one window per `(rule_id, pid)`. We avoid per-event
//! allocations by reusing a `VecDeque<u64>` of timestamps in nanoseconds; on
//! each `record` call the front is popped while it falls outside the window.

use std::collections::VecDeque;

#[derive(Debug)]
pub struct SlidingWindow {
    window_ns: u64,
    timestamps: VecDeque<u64>,
}

impl SlidingWindow {
    pub fn new(window_ms: u64) -> Self {
        Self {
            window_ns: window_ms.saturating_mul(1_000_000),
            timestamps: VecDeque::with_capacity(16),
        }
    }

    /// Record an event timestamp. Returns the current window count after
    /// trimming events older than `window_ns`.
    pub fn record(&mut self, ts_ns: u64) -> u32 {
        while let Some(&front) = self.timestamps.front() {
            if ts_ns.saturating_sub(front) > self.window_ns {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }
        self.timestamps.push_back(ts_ns);
        self.timestamps.len() as u32
    }

    pub fn len(&self) -> usize {
        self.timestamps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.timestamps.is_empty()
    }

    /// Average inter-event interval in milliseconds, or `None` if fewer than
    /// 2 samples.
    pub fn period_ms(&self) -> Option<f64> {
        if self.timestamps.len() < 2 {
            return None;
        }
        let first = *self.timestamps.front()?;
        let last = *self.timestamps.back()?;
        let span_ns = last.saturating_sub(first);
        let intervals = (self.timestamps.len() - 1) as f64;
        Some((span_ns as f64) / intervals / 1_000_000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    #[test]
    fn trims_stale_entries() {
        let mut w = SlidingWindow::new(100); // 100ms window
        assert_eq!(w.record(0), 1);
        assert_eq!(w.record(50 * MS), 2);
        assert_eq!(w.record(99 * MS), 3);
        // At 200ms, every prior entry is more than 100ms in the past, so they
        // all evict and only the newly-recorded sample remains.
        assert_eq!(w.record(200 * MS), 1);
        // 250ms — the 200ms sample is only 50ms ago, still inside.
        assert_eq!(w.record(250 * MS), 2);
    }

    #[test]
    fn computes_period_correctly() {
        let mut w = SlidingWindow::new(10_000);
        w.record(0);
        w.record(2_000 * MS);
        w.record(4_000 * MS);
        let p = w.period_ms().unwrap();
        assert!((p - 2_000.0).abs() < 0.01, "period was {p}");
    }
}
