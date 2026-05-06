//! Phase 1d — sampling primitives for the matched stream.
//!
//! Two independent stages:
//!
//! - [`UniformSampler`]: Bernoulli drop with probability `1 - p`. Uses a
//!   tiny xorshift PRNG so the dependency footprint stays at zero
//!   (`rand` would have been a workspace-level addition for one trivial
//!   use). Deterministic given the same seed — useful for tests and
//!   replayable captures.
//! - [`RateLimiter`]: leaky token bucket. Bucket capacity = 1 second of
//!   tokens; refill rate = `N` tokens/second. When empty, the event is
//!   dropped.
//!
//! State-tracking syscalls (see
//! [`neutron_common::is_state_tracking_nr`]) bypass both stages — per
//! the Phase 1 plan they update userspace state regardless of sampling
//! decisions. The userspace caller is responsible for invoking the
//! sampler only on non-state events; helper [`is_sample_exempt`] makes
//! that decision concrete.

use neutron_common::is_state_tracking_nr;

/// `true` when an event must NEVER be dropped by the sampler chain.
/// Today: state-tracking syscalls and the synthetic process_exit /
/// binder sentinels (negative `nr` values).
#[inline]
pub fn is_sample_exempt(nr: i32) -> bool {
    if nr < 0 {
        // Sentinels: -1 binder, -3 process_exit, -4 binder_received.
        // All of them are critical for downstream correlation.
        return true;
    }
    is_state_tracking_nr(nr)
}

// ── UniformSampler ──────────────────────────────────────────────────────────

/// Probability-based sampler. `p == 1.0` keeps every event; `p == 0.0`
/// drops every non-exempt event.
#[derive(Debug)]
pub struct UniformSampler {
    /// `p * u64::MAX`, precomputed so `keep` is a single comparison.
    threshold: u64,
    state: u64,
}

impl UniformSampler {
    /// Build a sampler from a probability. Clamps to `[0.0, 1.0]` and
    /// rejects NaN. The default seed `0xDEADBEEFCAFEBABE` makes test
    /// runs deterministic; production callers can override via
    /// [`Self::with_seed`] if they need cross-run independence.
    pub fn new(p: f64) -> anyhow::Result<Self> {
        if p.is_nan() {
            anyhow::bail!("--sample probability is NaN");
        }
        let clamped = p.clamp(0.0, 1.0);
        let threshold = if clamped >= 1.0 {
            u64::MAX
        } else if clamped <= 0.0 {
            0
        } else {
            (clamped * (u64::MAX as f64)) as u64
        };
        Ok(Self {
            threshold,
            state: 0xDEAD_BEEF_CAFE_BABE,
        })
    }

    pub fn with_seed(mut self, seed: u64) -> Self {
        // Avoid the all-zero state — xorshift gets stuck there.
        self.state = if seed == 0 { 1 } else { seed };
        self
    }

    /// Decide whether to keep this event. State-tracking exemption is
    /// applied here so callers can pipe every event through the sampler
    /// without remembering the rule.
    pub fn keep(&mut self, nr: i32) -> bool {
        if is_sample_exempt(nr) {
            return true;
        }
        // Always-keep / always-drop fast paths.
        if self.threshold == u64::MAX {
            return true;
        }
        if self.threshold == 0 {
            return false;
        }
        // xorshift64* — quality is fine for "keep N% of events" and it's
        // dependency-free.
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x < self.threshold
    }
}

// ── RateLimiter ────────────────────────────────────────────────────────────

/// Token-bucket rate limiter. Capacity = `events_per_sec`; refill rate =
/// `events_per_sec` per second (linear). One token spent per kept event.
#[derive(Debug)]
pub struct RateLimiter {
    capacity: u64,
    /// Current bucket content (in `events_per_sec` integer units).
    tokens: u64,
    /// Wall-clock of the last refill, in nanoseconds.
    last_ts_ns: u64,
}

impl RateLimiter {
    pub fn new(events_per_sec: u64) -> anyhow::Result<Self> {
        if events_per_sec == 0 {
            anyhow::bail!("--rate-limit must be > 0");
        }
        Ok(Self {
            capacity: events_per_sec,
            tokens: events_per_sec, // start full so first burst goes through
            last_ts_ns: 0,
        })
    }

    /// Try to consume one token at `ts_ns`. Returns `true` if the event
    /// should be kept. Exempt syscall numbers always return `true`.
    pub fn keep(&mut self, ts_ns: u64, nr: i32) -> bool {
        if is_sample_exempt(nr) {
            return true;
        }
        // Refill: tokens accrue at `capacity` per second. On the very
        // first call, `last_ts_ns` is 0 and `dt_ns` equals `ts_ns`,
        // which is fine — the saturating add immediately caps at
        // `capacity`, so the bucket starts full regardless of when the
        // first event lands.
        let dt_ns = ts_ns.saturating_sub(self.last_ts_ns);
        if dt_ns > 0 {
            let refill = capacity_per_ns(self.capacity, dt_ns);
            self.tokens = self.tokens.saturating_add(refill).min(self.capacity);
        }
        self.last_ts_ns = ts_ns;
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

fn capacity_per_ns(capacity: u64, dt_ns: u64) -> u64 {
    // Integer math, rounding down: tokens = capacity * dt_ns / 1e9.
    // Use u128 to keep the arithmetic safe for any plausible capacity.
    ((capacity as u128).saturating_mul(dt_ns as u128) / 1_000_000_000) as u64
}

// ── Convenience wrapper ────────────────────────────────────────────────────

/// Combines a uniform sampler with a rate limiter into one decision
/// point. Either may be `None` (in which case it's a passthrough).
#[derive(Debug, Default)]
pub struct SamplerChain {
    pub uniform: Option<UniformSampler>,
    pub rate_limiter: Option<RateLimiter>,
}

impl SamplerChain {
    pub fn from_args(p: Option<f64>, rate_limit: Option<u64>) -> anyhow::Result<Self> {
        Ok(Self {
            uniform: match p {
                Some(v) => Some(UniformSampler::new(v)?),
                None => None,
            },
            rate_limiter: match rate_limit {
                Some(n) => Some(RateLimiter::new(n)?),
                None => None,
            },
        })
    }

    pub fn is_passthrough(&self) -> bool {
        self.uniform.is_none() && self.rate_limiter.is_none()
    }

    /// Decide whether to emit. Order: uniform sampling first (cheap),
    /// then rate limiting (consumes a token only when uniform passes).
    pub fn keep(&mut self, ts_ns: u64, nr: i32) -> bool {
        if let Some(u) = self.uniform.as_mut() {
            if !u.keep(nr) {
                return false;
            }
        }
        if let Some(r) = self.rate_limiter.as_mut() {
            if !r.keep(ts_ns, nr) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_tracking_syscalls_are_exempt() {
        // A handful of nr values from STATE_TRACKING_NRS.
        for nr in [19, 23, 24, 56, 57, 198, 220, 437] {
            assert!(is_sample_exempt(nr), "nr={nr} should be exempt");
        }
    }

    #[test]
    fn negative_sentinels_are_exempt() {
        for nr in [-1, -3, -4] {
            assert!(is_sample_exempt(nr));
        }
    }

    #[test]
    fn ioctl_is_not_exempt() {
        assert!(!is_sample_exempt(29));
    }

    #[test]
    fn uniform_keep_all_when_p_one() {
        let mut s = UniformSampler::new(1.0).unwrap();
        for _ in 0..1000 {
            assert!(s.keep(29));
        }
    }

    #[test]
    fn uniform_keep_none_when_p_zero_for_non_exempt() {
        let mut s = UniformSampler::new(0.0).unwrap();
        for _ in 0..1000 {
            assert!(!s.keep(29));
        }
    }

    #[test]
    fn uniform_state_tracking_bypasses_zero() {
        let mut s = UniformSampler::new(0.0).unwrap();
        // openat (56) is state-tracking; it should always pass.
        for _ in 0..100 {
            assert!(s.keep(56));
        }
    }

    #[test]
    fn uniform_rejects_nan() {
        assert!(UniformSampler::new(f64::NAN).is_err());
    }

    #[test]
    fn uniform_clamps_out_of_range() {
        // -1.0 clamps to 0.0 → drops everything non-exempt
        let mut s = UniformSampler::new(-1.0).unwrap();
        assert!(!s.keep(29));
        // 2.0 clamps to 1.0 → keeps everything
        let mut s2 = UniformSampler::new(2.0).unwrap();
        assert!(s2.keep(29));
    }

    #[test]
    fn uniform_with_p_half_keeps_roughly_half() {
        let mut s = UniformSampler::new(0.5).unwrap().with_seed(0x1234);
        let kept: usize = (0..10_000).map(|_| s.keep(29)).filter(|b| *b).count();
        // xorshift output is uniform; with 10k draws, the count should be
        // within ~5σ ≈ 3% of 5000.
        assert!(
            kept > 4000 && kept < 6000,
            "kept={kept} not in expected band"
        );
    }

    #[test]
    fn rate_limiter_starts_full() {
        let mut r = RateLimiter::new(10).unwrap();
        // First burst: capacity 10 should pass.
        for _ in 0..10 {
            assert!(r.keep(0, 29));
        }
        // 11th in same instant fails.
        assert!(!r.keep(0, 29));
    }

    #[test]
    fn rate_limiter_refills_over_time() {
        let mut r = RateLimiter::new(1_000).unwrap();
        for _ in 0..1_000 {
            assert!(r.keep(0, 29));
        }
        assert!(!r.keep(0, 29));
        // 100ms later: 100 tokens accrued.
        let later = 100_000_000;
        let mut kept = 0;
        for _ in 0..200 {
            if r.keep(later, 29) {
                kept += 1;
            }
        }
        // Allow ±1 from rounding.
        assert!(
            (99..=101).contains(&kept),
            "expected ~100 refilled tokens, got {kept}"
        );
    }

    #[test]
    fn rate_limiter_state_tracking_bypasses() {
        let mut r = RateLimiter::new(1).unwrap();
        // Eat the only token with non-exempt nr.
        assert!(r.keep(0, 29));
        // Non-exempt now fails.
        assert!(!r.keep(0, 29));
        // State-tracking always passes.
        for _ in 0..100 {
            assert!(r.keep(0, 56));
        }
    }

    #[test]
    fn rate_limiter_rejects_zero() {
        assert!(RateLimiter::new(0).is_err());
    }

    #[test]
    fn sampler_chain_default_is_passthrough() {
        let mut c = SamplerChain::from_args(None, None).unwrap();
        assert!(c.is_passthrough());
        for _ in 0..100 {
            assert!(c.keep(0, 29));
        }
    }

    #[test]
    fn sampler_chain_combines_both_filters() {
        let mut c = SamplerChain::from_args(Some(1.0), Some(2)).unwrap();
        // Uniform passes everything, rate limit caps at 2 per "second".
        assert!(c.keep(0, 29));
        assert!(c.keep(0, 29));
        assert!(!c.keep(0, 29));
        // State-tracking still bypasses both.
        for _ in 0..10 {
            assert!(c.keep(0, 56));
        }
    }

    #[test]
    fn sampler_chain_propagates_errors() {
        assert!(SamplerChain::from_args(Some(f64::NAN), None).is_err());
        assert!(SamplerChain::from_args(None, Some(0)).is_err());
    }
}
