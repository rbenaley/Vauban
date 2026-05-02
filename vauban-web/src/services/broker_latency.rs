//! Broker latency tracker (Issue Bastion Watch).
//!
//! Sliding-window in-memory tracker for the round-trip latency of
//! supervisor-brokered TCP connections (proxy paths via SCM_RIGHTS as
//! well as the SMTP relay path used by the mailer). The tracker is
//! cheap to update (a single `Mutex` push + lazy cleanup) and exposes
//! a snapshot used by the "FD-passing latency" tile of the
//! Bastion Watch dashboard.
//!
//! Design choices:
//!
//! * **Sliding 5 min window** -- short enough to follow real-time
//!   incidents (a misbehaving SMTP relay, a slow DNS), long enough for
//!   p95 to be stable on a low-traffic deployment (a single ops user
//!   running a session every minute still gets ~5 samples).
//! * **Hard cap on samples** (4096) -- bound memory in pathological
//!   spikes (e.g. a flood of mailer retries). Older samples are
//!   evicted before newer ones to preserve the most recent picture.
//! * **No external dependencies** -- pure `std`. No time-series DB,
//!   no histograms, no Prometheus client. Anyone reading the source
//!   can audit the math; the dashboard is the only consumer.
//! * **`Mutex<VecDeque>` rather than lock-free** -- the call site is
//!   already on a network round-trip path, sub-microsecond contention
//!   is irrelevant compared to the milliseconds spent in the
//!   supervisor and on the wire.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default sliding window size.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(300);

/// Hard upper bound on the number of samples retained at any time.
pub const DEFAULT_CAPACITY: usize = 4096;

/// In-memory sliding-window tracker.
///
/// Records the elapsed time of every supervisor-brokered TCP connect
/// (success or recoverable failure). Failures that hit the request
/// timeout (default 30 s) are intentionally NOT recorded -- they would
/// distort the p95 and mask a healthy-but-rare-broker situation.
///
/// Thread-safe via an internal `Mutex`. The lock is held for the
/// duration of an O(samples-out-of-window) eviction, which in practice
/// is O(1) amortised because eviction happens on every record.
pub struct BrokerLatencyTracker {
    samples: Mutex<VecDeque<(Instant, Duration)>>,
    window: Duration,
    cap: usize,
}

/// Read-only snapshot of the tracker, suitable for rendering.
///
/// `median_us` and `p95_us` are `None` when the tracker has not seen
/// any sample in the current window: the dashboard renders this as
/// "n/a" rather than "0 us" so an idle bastion does not get tagged
/// as a 0-latency broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatencySnapshot {
    pub count: usize,
    pub median_us: Option<u64>,
    pub p95_us: Option<u64>,
    pub window_secs: u64,
}

impl LatencySnapshot {
    /// Median latency rounded to whole milliseconds, `None` when the
    /// tracker has not seen a sample. Used by the dashboard tiles
    /// (Bastion Watch HEALTH hero + system_health panel) so a 159938
    /// us reading renders as `160 ms` rather than the unwieldy raw
    /// microsecond figure.
    pub fn median_ms(&self) -> Option<u64> {
        self.median_us.map(us_to_ms_round)
    }

    /// 95th percentile latency rounded to whole milliseconds. See
    /// [`Self::median_ms`] for the rounding rationale.
    pub fn p95_ms(&self) -> Option<u64> {
        self.p95_us.map(us_to_ms_round)
    }
}

/// Half-up rounding from microseconds to milliseconds, saturating on
/// the (theoretically impossible) `u64::MAX` overflow. Kept private:
/// the tracker is the only caller and the policy ("nearest ms")
/// belongs with the snapshot type.
fn us_to_ms_round(us: u64) -> u64 {
    us.saturating_add(500) / 1_000
}

impl Default for BrokerLatencyTracker {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW, DEFAULT_CAPACITY)
    }
}

impl BrokerLatencyTracker {
    /// Construct a tracker with explicit window + capacity. Tests
    /// drive shorter windows to validate eviction without `sleep`.
    pub fn new(window: Duration, cap: usize) -> Self {
        Self {
            samples: Mutex::new(VecDeque::with_capacity(cap.min(1024))),
            window,
            cap: cap.max(1),
        }
    }

    /// Record a successful broker round-trip duration. Stamped at the
    /// caller's wall clock so the eviction logic can prune purely on
    /// `Instant` arithmetic.
    pub fn record(&self, latency: Duration) {
        let now = Instant::now();
        if let Ok(mut g) = self.samples.lock() {
            self.evict_locked(&mut g, now);
            g.push_back((now, latency));
            // Cap defensively: even with eviction, a sustained burst
            // could outpace the window (e.g. 10k connects/sec).
            while g.len() > self.cap {
                g.pop_front();
            }
        }
    }

    /// Drop samples outside the active window. Called on every
    /// `record` and `snapshot` so a long-idle tracker still returns
    /// `count = 0` rather than stale data from yesterday.
    fn evict_locked(&self, samples: &mut VecDeque<(Instant, Duration)>, now: Instant) {
        while let Some(&(t, _)) = samples.front() {
            if now.saturating_duration_since(t) > self.window {
                samples.pop_front();
            } else {
                break;
            }
        }
    }

    /// Compute median + p95 over the live window. Allocates O(N) for
    /// the percentile sort; with `cap = 4096` this is ~150 us on
    /// modern hardware -- well under the 1 s push cadence of the
    /// dashboard.
    pub fn snapshot(&self) -> LatencySnapshot {
        let now = Instant::now();
        let Ok(mut g) = self.samples.lock() else {
            return LatencySnapshot {
                count: 0,
                median_us: None,
                p95_us: None,
                window_secs: self.window.as_secs(),
            };
        };
        self.evict_locked(&mut g, now);
        let count = g.len();
        if count == 0 {
            return LatencySnapshot {
                count: 0,
                median_us: None,
                p95_us: None,
                window_secs: self.window.as_secs(),
            };
        }
        let mut sorted: Vec<u64> = g.iter().map(|(_, d)| d.as_micros() as u64).collect();
        sorted.sort_unstable();
        let median_us = Some(percentile(&sorted, 50));
        let p95_us = Some(percentile(&sorted, 95));
        LatencySnapshot {
            count,
            median_us,
            p95_us,
            window_secs: self.window.as_secs(),
        }
    }
}

/// Nearest-rank percentile (inclusive) on a pre-sorted slice.
///
/// We use nearest-rank (rather than linear interpolation) so the
/// returned value is always one of the actually observed samples --
/// matching the "FD-passing latency" tile semantics of "the slowest
/// broker round-trip the 5th percentile of users still saw".
fn percentile(sorted: &[u64], p: u8) -> u64 {
    debug_assert!(p <= 100);
    if sorted.is_empty() {
        return 0;
    }
    // rank in [1..=N], rounded up.
    let n = sorted.len();
    let rank = (p as usize * n).div_ceil(100);
    let idx = rank.saturating_sub(1).min(n - 1);
    sorted[idx]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn empty_tracker_returns_none_for_percentiles() {
        let t = BrokerLatencyTracker::default();
        let s = t.snapshot();
        assert_eq!(s.count, 0);
        assert!(s.median_us.is_none());
        assert!(s.p95_us.is_none());
        assert!(s.median_ms().is_none());
        assert!(s.p95_ms().is_none());
        assert_eq!(s.window_secs, 300);
    }

    #[test]
    fn us_to_ms_round_uses_half_up_policy() {
        // Exact-and-edge case sweep for the rounding policy used by
        // `LatencySnapshot::{median_ms, p95_ms}`. Half-up keeps the
        // dashboard tile honest under sub-millisecond noise.
        assert_eq!(us_to_ms_round(0), 0);
        assert_eq!(us_to_ms_round(499), 0);
        assert_eq!(us_to_ms_round(500), 1);
        assert_eq!(us_to_ms_round(1_499), 1);
        assert_eq!(us_to_ms_round(1_500), 2);
        // Concrete production value flagged in the dashboard report:
        // 159_938 us must surface as 160 ms, not 159 (off-by-half).
        assert_eq!(us_to_ms_round(159_938), 160);
        assert_eq!(us_to_ms_round(159_499), 159);
        assert_eq!(us_to_ms_round(159_500), 160);
        // Saturation guard: u64::MAX must not panic.
        assert_eq!(us_to_ms_round(u64::MAX), u64::MAX / 1_000);
    }

    #[test]
    fn snapshot_ms_accessors_round_to_nearest_millisecond() {
        // Synthesise a snapshot directly so the test does not depend
        // on the percentile algorithm; we only verify the us->ms
        // conversion contract that the templates rely on.
        let s = LatencySnapshot {
            count: 42,
            median_us: Some(1_499),
            p95_us: Some(159_938),
            window_secs: 300,
        };
        assert_eq!(s.median_ms(), Some(1));
        assert_eq!(s.p95_ms(), Some(160));
        let empty = LatencySnapshot {
            count: 0,
            median_us: None,
            p95_us: None,
            window_secs: 300,
        };
        assert_eq!(empty.median_ms(), None);
        assert_eq!(empty.p95_ms(), None);
    }

    #[test]
    fn record_then_snapshot_yields_median_and_p95() {
        let t = BrokerLatencyTracker::default();
        for us in [10u64, 20, 30, 40, 50, 60, 70, 80, 90, 100] {
            t.record(Duration::from_micros(us));
        }
        let s = t.snapshot();
        assert_eq!(s.count, 10);
        // nearest-rank: p50 of 10 sorted samples -> rank 5 -> idx 4 -> 50us.
        assert_eq!(s.median_us, Some(50));
        // p95 -> rank ceil(9.5) = 10 -> idx 9 -> 100us.
        assert_eq!(s.p95_us, Some(100));
    }

    #[test]
    fn out_of_window_samples_are_evicted_on_record() {
        let t = BrokerLatencyTracker::new(Duration::from_millis(50), 1024);
        t.record(Duration::from_micros(1000));
        thread::sleep(Duration::from_millis(70));
        // The new record should evict the stale one.
        t.record(Duration::from_micros(2000));
        let s = t.snapshot();
        assert_eq!(s.count, 1);
        assert_eq!(s.median_us, Some(2000));
    }

    #[test]
    fn out_of_window_samples_are_evicted_on_snapshot_alone() {
        let t = BrokerLatencyTracker::new(Duration::from_millis(50), 1024);
        t.record(Duration::from_micros(1000));
        thread::sleep(Duration::from_millis(70));
        // No record() call between sleep and snapshot: snapshot()
        // itself MUST evict, otherwise an idle bastion would forever
        // display its last hour's p95.
        let s = t.snapshot();
        assert_eq!(s.count, 0);
        assert!(s.median_us.is_none());
    }

    #[test]
    fn capacity_cap_bounds_memory_under_burst() {
        let t = BrokerLatencyTracker::new(Duration::from_secs(3600), 8);
        for us in 1..=50u64 {
            t.record(Duration::from_micros(us));
        }
        let s = t.snapshot();
        assert_eq!(
            s.count, 8,
            "tracker MUST cap at `cap` samples, retaining the most \
             recent ones"
        );
        // Most recent 8 samples are 43..=50 us.
        // p50 (rank 4 -> idx 3 -> sorted[3] = 46).
        assert_eq!(s.median_us, Some(46));
        // p95 (rank ceil(7.6)=8 -> idx 7 -> sorted[7] = 50).
        assert_eq!(s.p95_us, Some(50));
    }

    #[test]
    fn concurrent_record_does_not_panic_or_corrupt_count() {
        let t = Arc::new(BrokerLatencyTracker::default());
        let mut handles = Vec::new();
        for k in 0..8 {
            let t = Arc::clone(&t);
            handles.push(thread::spawn(move || {
                for i in 0..125 {
                    t.record(Duration::from_micros((k * 1000 + i) as u64));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let s = t.snapshot();
        assert_eq!(s.count, 8 * 125);
        assert!(s.median_us.is_some());
        assert!(s.p95_us.is_some());
    }

    #[test]
    fn percentile_helper_handles_edge_cases() {
        let s = [1u64, 2, 3, 4, 5];
        assert_eq!(percentile(&s, 0), 1);
        assert_eq!(percentile(&s, 50), 3);
        assert_eq!(percentile(&s, 100), 5);
        assert_eq!(percentile(&[], 50), 0);
    }
}
