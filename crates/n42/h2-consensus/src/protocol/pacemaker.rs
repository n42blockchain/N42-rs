use n42_h2_primitives::consensus::ViewNumber;
use std::time::Duration;
use tokio::time::{Instant, Sleep};

/// Active Pacemaker for the HotStuff-2 consensus protocol.
///
/// Manages view timeouts with exponential backoff (Jolteon-style):
/// `timeout = min(base_timeout * 2^consecutive_timeouts, max_timeout)`
///
/// Adaptive mode: when `observe_commit_latency` is called with real measurements,
/// the effective base timeout is adjusted to `max(base_timeout, p95_observed * 2)`.
/// This prevents premature timeouts on high-latency global networks while keeping
/// fast timeouts on local/regional deployments.
///
/// Ensures liveness: if the current leader is faulty or the network is slow,
/// validators will eventually time out and trigger a view change.
#[derive(Debug)]
pub struct Pacemaker {
    base_timeout: Duration,
    max_timeout: Duration,
    deadline: Instant,
    /// Adaptive timeout: ring buffer of recent commit latencies.
    /// Used to compute effective base timeout as max(configured, 2 × p95).
    recent_latencies: Vec<Duration>,
    /// Cursor for circular buffer insertion.
    latency_cursor: usize,
}

impl Pacemaker {
    /// Number of recent latency samples to keep for adaptive timeout.
    const LATENCY_WINDOW: usize = 20;
    /// Maximum exponent for backoff calculation to avoid overflow.
    const MAX_BACKOFF_EXPONENT: u32 = 63;

    pub fn new(base_timeout_ms: u64, max_timeout_ms: u64) -> Self {
        let base_timeout = Duration::from_millis(base_timeout_ms);
        let max_timeout = Duration::from_millis(max_timeout_ms);
        Self {
            base_timeout,
            max_timeout,
            deadline: Instant::now() + base_timeout,
            recent_latencies: Vec::with_capacity(Self::LATENCY_WINDOW),
            latency_cursor: 0,
        }
    }

    /// Records an observed commit latency (view start → BlockCommitted).
    ///
    /// After enough samples, the effective base timeout adapts:
    /// `effective_base = max(configured_base, 2 × p95_latency)`
    ///
    /// This prevents premature timeouts on global networks where consensus
    /// naturally takes 600-800ms, while keeping fast timeouts locally.
    pub fn observe_commit_latency(&mut self, latency: Duration) {
        if self.recent_latencies.len() < Self::LATENCY_WINDOW {
            self.recent_latencies.push(latency);
        } else {
            self.recent_latencies[self.latency_cursor % Self::LATENCY_WINDOW] = latency;
        }
        self.latency_cursor += 1;
    }

    /// Returns the effective base timeout, considering adaptive measurements.
    fn effective_base_timeout(&self) -> Duration {
        if self.recent_latencies.len() < 5 {
            return self.base_timeout;
        }
        // Compute p95 of recent latencies.
        let mut sorted: Vec<u64> = self
            .recent_latencies
            .iter()
            .map(|d| d.as_millis() as u64)
            .collect();
        sorted.sort_unstable();
        let p95_idx = (sorted.len() * 95 / 100).min(sorted.len().saturating_sub(1));
        let p95_ms = sorted[p95_idx];
        // Effective base = max(configured, 2 × p95), capped at max_timeout.
        let adaptive_ms = p95_ms.saturating_mul(2);
        let effective = self.base_timeout.as_millis() as u64;
        Duration::from_millis(
            effective
                .max(adaptive_ms)
                .min(self.max_timeout.as_millis() as u64),
        )
    }

    /// Returns the timeout duration for the given number of consecutive timeouts.
    ///
    /// Uses exponential backoff: `effective_base * 2^consecutive_timeouts`, capped at `max_timeout`.
    pub fn timeout_duration(&self, consecutive_timeouts: u32) -> Duration {
        let base = self.effective_base_timeout();
        let exp = consecutive_timeouts.min(Self::MAX_BACKOFF_EXPONENT);
        let multiplier = 1u64.checked_shl(exp).unwrap_or(u64::MAX);
        let timeout_ms = (base.as_millis() as u64).saturating_mul(multiplier);
        Duration::from_millis(timeout_ms.min(self.max_timeout.as_millis() as u64))
    }

    /// Resets the timer for a new view with the appropriate backoff duration.
    pub fn reset_for_view(&mut self, view: ViewNumber, consecutive_timeouts: u32) {
        let duration = self.timeout_duration(consecutive_timeouts);
        self.deadline = Instant::now() + duration;
        tracing::debug!(
            view,
            timeout_ms = duration.as_millis() as u64,
            consecutive_timeouts,
            "pacemaker timer reset"
        );
    }

    /// Returns a `Sleep` future that completes when the current view times out.
    pub fn timeout_sleep(&self) -> Sleep {
        tokio::time::sleep_until(self.deadline)
    }

    /// Returns true if the current view has timed out.
    pub fn is_timed_out(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// Returns the remaining time until timeout.
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    /// Extends the current deadline by the given duration.
    ///
    /// Used at startup to allow extra time for GossipSub mesh formation
    /// before the first proposal.
    pub fn extend_deadline(&mut self, extra: Duration) {
        self.deadline += extra;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_duration_base() {
        let pm = Pacemaker::new(1000, 60000);
        assert_eq!(pm.timeout_duration(0), Duration::from_millis(1000));
    }

    #[test]
    fn test_timeout_duration_backoff() {
        let pm = Pacemaker::new(1000, 60000);
        assert_eq!(pm.timeout_duration(1), Duration::from_millis(2000));
        assert_eq!(pm.timeout_duration(2), Duration::from_millis(4000));
        assert_eq!(pm.timeout_duration(3), Duration::from_millis(8000));
    }

    #[test]
    fn test_timeout_duration_capped() {
        let pm = Pacemaker::new(1000, 30000);
        assert_eq!(pm.timeout_duration(10), Duration::from_millis(30000));
        assert_eq!(pm.timeout_duration(5), Duration::from_millis(30000));
        assert_eq!(pm.timeout_duration(4), Duration::from_millis(16000));
    }

    #[test]
    fn test_is_timed_out_initially() {
        let pm = Pacemaker::new(5000, 60000);
        assert!(!pm.is_timed_out());
    }

    #[test]
    fn test_remaining_positive_initially() {
        let pm = Pacemaker::new(5000, 60000);
        let remaining = pm.remaining();
        assert!(remaining > Duration::ZERO);
        assert!(remaining <= Duration::from_millis(5000));
    }

    #[test]
    fn test_reset_for_view() {
        let mut pm = Pacemaker::new(1000, 60000);

        pm.reset_for_view(2, 0);
        assert!(!pm.is_timed_out());
        assert!(pm.remaining() <= Duration::from_millis(1000));

        pm.reset_for_view(3, 2);
        assert!(!pm.is_timed_out());
        assert!(pm.remaining() <= Duration::from_millis(4000));
    }

    #[test]
    fn test_adaptive_timeout_no_samples() {
        // Without observations, uses configured base timeout.
        let pm = Pacemaker::new(4000, 60000);
        assert_eq!(pm.timeout_duration(0), Duration::from_millis(4000));
    }

    #[test]
    fn test_adaptive_timeout_increases_with_high_latency() {
        // Simulate global network: consensus takes ~700ms.
        let mut pm = Pacemaker::new(4000, 60000);
        for _ in 0..10 {
            pm.observe_commit_latency(Duration::from_millis(700));
        }
        // p95 = 700ms, adaptive = 2 × 700 = 1400ms.
        // But configured base = 4000ms > 1400ms, so stays at 4000ms.
        assert_eq!(pm.timeout_duration(0), Duration::from_millis(4000));
    }

    #[test]
    fn test_adaptive_timeout_adapts_to_slow_network() {
        // Simulate very slow network: consensus takes ~3000ms.
        // base_timeout = 4000ms, but 2 × p95 = 6000ms > 4000ms → adapts.
        let mut pm = Pacemaker::new(4000, 60000);
        for _ in 0..10 {
            pm.observe_commit_latency(Duration::from_millis(3000));
        }
        // p95 = 3000ms, adaptive = 2 × 3000 = 6000ms > 4000ms.
        assert_eq!(pm.timeout_duration(0), Duration::from_millis(6000));
    }

    #[test]
    fn test_adaptive_timeout_capped_by_max() {
        // Even with extreme latency, timeout is capped at max_timeout.
        let mut pm = Pacemaker::new(4000, 10000);
        for _ in 0..10 {
            pm.observe_commit_latency(Duration::from_millis(8000));
        }
        // 2 × 8000 = 16000, but max = 10000.
        assert_eq!(pm.timeout_duration(0), Duration::from_millis(10000));
    }
}
