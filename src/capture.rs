//! Phase 1c — `--capture matched+context=<DUR>` support.
//!
//! When a predicate match fires, operators often want a few seconds of
//! context on each side. The ring-buffer here is the userspace half of
//! the answer: it retains every event that *failed* the predicate so the
//! next match can flush the previous `<DUR>` of context, and it also
//! tracks a forward window so the next `<DUR>` of events is emitted
//! unconditionally.
//!
//! Implementation notes:
//!
//! - The ring is bounded twice: by `<DUR>` of wall-clock (events older
//!   than that are evicted on every push) and by a hard event-count cap
//!   (default 100k entries — see [`DEFAULT_MAX_EVENTS`]). Both bounds
//!   apply; whichever fires first wins.
//! - We only push **rejected** events. Matched events flow through the
//!   normal emit path immediately, so duplicating them in the ring would
//!   be wasted memory.
//! - State events that update fdgraph but don't match the predicate are
//!   still pushed (so the backward dump gives operators the open/dup
//!   sequence that led to the matched ioctl).
//! - The forward window resets on every match — back-to-back matches at
//!   `t = 0` and `t = 2s` with `<DUR> = 5s` keep the forward window open
//!   until `t = 7s`.

use std::collections::VecDeque;

/// Hard cap on retained events when no time pressure has fired yet.
/// 100k events × ~600 bytes (typical NDJSON line) ≈ 60 MB worst case,
/// the same order as a small `neutron window` post-processor input.
pub const DEFAULT_MAX_EVENTS: usize = 100_000;

/// Maximum allowed `<DUR>`. Above this the ring gets large enough to
/// matter for memory; we want explicit user opt-in if they really need it.
pub const MAX_DURATION_NS: u64 = 30 * 1_000_000_000;

/// Result of [`ContextRing::observe`]: zero, one, or many JSON lines that
/// the caller should emit in order. Returning `Vec<String>` keeps the
/// hot path's signature cheap (most calls return an empty vec).
pub type Emit = Vec<String>;

/// Backward-context ring buffer combined with a forward-window
/// timestamp. See module-level docs.
#[derive(Debug)]
pub struct ContextRing {
    /// Pending events in chronological order. `(ts_ns, json_line)`.
    events: VecDeque<(u64, String)>,
    duration_ns: u64,
    max_events: usize,
    /// Wall-clock (in `ts_ns`) until which forward emission is unconditional.
    /// `0` when no match is currently active.
    forward_until_ns: u64,
}

impl ContextRing {
    pub fn new(duration_ns: u64, max_events: usize) -> Self {
        Self {
            events: VecDeque::new(),
            duration_ns,
            max_events: max_events.max(1),
            forward_until_ns: 0,
        }
    }

    /// Number of pending rejected events currently in the ring. Test
    /// helper.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// `true` when the ring has no buffered events. Pairs with
    /// [`Self::len`] to satisfy the `len_without_is_empty` contract.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Wall-clock until which the forward window is open. Test helper.
    #[cfg(test)]
    pub fn forward_until_ns(&self) -> u64 {
        self.forward_until_ns
    }

    /// Decide what to emit for one event. `matched` is the userspace
    /// post-filter verdict; `json_line` is the rendered NDJSON form
    /// (passed by reference and cloned only when the caller will emit it).
    pub fn observe(&mut self, ts_ns: u64, matched: bool, json_line: &str) -> Emit {
        self.evict_old(ts_ns);

        if matched {
            // Drain the entire backward window into the emit list.
            let mut out = Vec::with_capacity(self.events.len() + 1);
            for (_, line) in self.events.drain(..) {
                out.push(line);
            }
            out.push(json_line.to_string());
            // (Re)open the forward window.
            self.forward_until_ns = ts_ns.saturating_add(self.duration_ns);
            return out;
        }

        if ts_ns < self.forward_until_ns {
            // Inside an active forward window from a previous match.
            return vec![json_line.to_string()];
        }

        // Reject path: park the event for a potential backward dump.
        if self.events.len() >= self.max_events {
            self.events.pop_front();
        }
        self.events.push_back((ts_ns, json_line.to_string()));
        Vec::new()
    }

    /// Reset buffered backward/forward context at an evidence boundary.
    /// Returns the number of buffered records that were intentionally
    /// discarded so capture health can make the boundary loss explicit.
    pub fn reset_boundary(&mut self) -> usize {
        let discarded = self.events.len();
        self.events.clear();
        self.forward_until_ns = 0;
        discarded
    }

    fn evict_old(&mut self, now_ns: u64) {
        let cutoff = now_ns.saturating_sub(self.duration_ns);
        while let Some((t, _)) = self.events.front() {
            if *t < cutoff {
                self.events.pop_front();
            } else {
                break;
            }
        }
        // The forward window itself is consumed by ts comparison, no
        // explicit clear: ts_ns >= forward_until_ns naturally falls through.
    }
}

/// Parse a `--capture <mode>` value into a [`CaptureMode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureMode {
    Default,
    MatchedWithContext { duration_ns: u64 },
}

impl CaptureMode {
    pub fn from_cli(s: Option<&str>) -> anyhow::Result<Self> {
        let Some(raw) = s else {
            return Ok(CaptureMode::Default);
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(CaptureMode::Default);
        }

        // Accept the explicit short forms too:
        //   "default"               → Default
        //   "matched"               → Default (alias; predicate already gates)
        //   "matched+context=<dur>" → MatchedWithContext
        if trimmed.eq_ignore_ascii_case("default") || trimmed.eq_ignore_ascii_case("matched") {
            return Ok(CaptureMode::Default);
        }
        let lower = trimmed.to_ascii_lowercase();
        let body = lower.strip_prefix("matched+context=").ok_or_else(|| {
            anyhow::anyhow!("--capture: expected 'matched+context=<DUR>', got {trimmed:?}")
        })?;
        let dur_us = crate::matcher::parse_latency_us(body)?;
        let dur_ns = dur_us
            .checked_mul(1_000)
            .ok_or_else(|| anyhow::anyhow!("--capture duration overflow: {body}"))?;
        if dur_ns == 0 {
            anyhow::bail!("--capture duration must be > 0");
        }
        if dur_ns > MAX_DURATION_NS {
            anyhow::bail!(
                "--capture duration {body} exceeds {} ns cap (~{} s)",
                MAX_DURATION_NS,
                MAX_DURATION_NS / 1_000_000_000
            );
        }
        Ok(CaptureMode::MatchedWithContext {
            duration_ns: dur_ns,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_when_flag_missing_or_empty() {
        assert_eq!(CaptureMode::from_cli(None).unwrap(), CaptureMode::Default);
        assert_eq!(
            CaptureMode::from_cli(Some("")).unwrap(),
            CaptureMode::Default
        );
        assert_eq!(
            CaptureMode::from_cli(Some("default")).unwrap(),
            CaptureMode::Default
        );
        assert_eq!(
            CaptureMode::from_cli(Some("matched")).unwrap(),
            CaptureMode::Default
        );
    }

    #[test]
    fn matched_context_parses_duration() {
        match CaptureMode::from_cli(Some("matched+context=2s")).unwrap() {
            CaptureMode::MatchedWithContext { duration_ns } => {
                assert_eq!(duration_ns, 2_000_000_000);
            }
            other => panic!("unexpected: {other:?}"),
        }
        match CaptureMode::from_cli(Some("matched+context=500ms")).unwrap() {
            CaptureMode::MatchedWithContext { duration_ns } => {
                assert_eq!(duration_ns, 500_000_000);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn matched_context_rejects_overflow() {
        let err = CaptureMode::from_cli(Some("matched+context=120s")).unwrap_err();
        assert!(format!("{err:#}").contains("cap"));
    }

    #[test]
    fn evidence_boundary_discards_buffered_and_forward_context() {
        let mut ring = ContextRing::new(1_000, 8);
        assert!(ring.observe(10, false, "before").is_empty());
        assert_eq!(ring.observe(20, true, "match"), ["before", "match"]);
        assert!(ring.forward_until_ns() > 20);
        assert!(ring.observe(21, false, "forward").len() == 1);
        assert!(ring.observe(2_000, false, "buffered").is_empty());

        assert_eq!(ring.reset_boundary(), 1);
        assert!(ring.is_empty());
        assert_eq!(ring.forward_until_ns(), 0);
    }

    #[test]
    fn matched_context_rejects_zero() {
        let err = CaptureMode::from_cli(Some("matched+context=0us")).unwrap_err();
        assert!(format!("{err:#}").contains("> 0"));
    }

    #[test]
    fn unknown_mode_rejected() {
        let err = CaptureMode::from_cli(Some("garbage")).unwrap_err();
        assert!(format!("{err:#}").contains("matched+context"));
    }

    #[test]
    fn ring_emits_only_matched_events_when_no_match_yet() {
        let mut r = ContextRing::new(1_000_000_000, 100);
        let out_a = r.observe(100, false, "a");
        let out_b = r.observe(200, false, "b");
        assert!(out_a.is_empty());
        assert!(out_b.is_empty());
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn ring_dumps_backward_on_match() {
        let mut r = ContextRing::new(1_000_000_000, 100);
        let _ = r.observe(100, false, "a");
        let _ = r.observe(200, false, "b");
        let out = r.observe(300, true, "c");
        assert_eq!(out, vec!["a", "b", "c"]);
        assert_eq!(r.len(), 0);
        assert_eq!(r.forward_until_ns(), 300 + 1_000_000_000);
    }

    #[test]
    fn ring_emits_forward_window_after_match() {
        let mut r = ContextRing::new(1_000_000_000, 100);
        let _ = r.observe(100, true, "match");
        let out = r.observe(500_000_000, false, "during-window");
        assert_eq!(out, vec!["during-window"]);
        // Past the forward window: drop again.
        let out2 = r.observe(2_000_000_000, false, "outside-window");
        assert!(out2.is_empty());
        assert_eq!(r.len(), 1, "outside-window should be parked, not dropped");
    }

    #[test]
    fn ring_drops_old_events_outside_duration() {
        let mut r = ContextRing::new(500_000, 100); // 0.5 ms window
        let _ = r.observe(0, false, "old");
        let _ = r.observe(2_000_000, false, "new");
        let out = r.observe(2_500_000, true, "match");
        // "old" should have been evicted before "match" fired.
        assert!(!out.contains(&"old".to_string()));
        assert!(out.contains(&"new".to_string()));
        assert!(out.contains(&"match".to_string()));
    }

    #[test]
    fn ring_drops_when_event_cap_exceeded() {
        let mut r = ContextRing::new(1_000_000_000_000, 3); // count cap = 3
        for i in 0..5u64 {
            let _ = r.observe(i + 1, false, &format!("e{i}"));
        }
        // Only the last 3 survive.
        let out = r.observe(100, true, "match");
        let lines: Vec<&str> = out.iter().map(|s| s.as_str()).collect();
        assert!(lines.contains(&"e2"));
        assert!(lines.contains(&"e3"));
        assert!(lines.contains(&"e4"));
        assert!(!lines.contains(&"e0"));
        assert!(!lines.contains(&"e1"));
        assert!(lines.contains(&"match"));
    }

    #[test]
    fn ring_match_during_forward_window_extends_it() {
        let mut r = ContextRing::new(1_000_000_000, 100);
        let _ = r.observe(100, true, "first");
        // Second match later still inside forward window.
        let _ = r.observe(500_000_000, true, "second");
        // Forward window should now end at 500_000_000 + 1_000_000_000.
        assert_eq!(r.forward_until_ns(), 500_000_000 + 1_000_000_000);
    }
}
