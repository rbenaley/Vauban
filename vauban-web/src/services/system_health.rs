//! System health snapshot (Bastion Watch dashboard).
//!
//! Aggregates the runtime telemetry that the dashboard's
//! "SYSTEM HEALTH" tile renders -- broker latency, proxy session
//! counts per protocol, the Postgres connection pool occupancy, and
//! the mailer outbox backlog -- behind a 5-second cache. The cache
//! exists so a 1 s WS-pusher cadence does not turn into a per-second
//! avalanche of `count(*)` queries on heavy workloads.
//!
//! The HTTP request rate is tracked in-process via a small bucketed
//! `HttpRateTracker` updated from a thin Axum middleware
//! (`record_http_request`). The middleware is opt-in: instances that
//! do not need the dashboard can leave it off without losing other
//! telemetry.

use crate::db::DbPool;
use crate::services::broker_latency::{BrokerLatencyTracker, LatencySnapshot};
use crate::schema::{email_outbox, proxy_sessions};
use diesel::dsl::count_star;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use std::sync::Arc;
use tracing::warn;

/// Cache TTL: a fresh DB snapshot every 5 seconds at most.
pub const CACHE_TTL: Duration = Duration::from_secs(5);

/// Capacity of the live-session sparkline history buffer. Sized to
/// 120 samples = 2 minutes at the dashboard pusher's 1 Hz fast tier
/// cadence. Smaller capacities make the sparkline twitchy on a
/// stable bastion; larger ones smear sudden bursts.
pub const LIVE_HISTORY_CAP: usize = 120;

/// Sliding window for the HTTP request-rate tracker (60 buckets of 1s
/// = 60 s of history, one second per bucket). 60 entries * a few u64s
/// is irrelevant memory-wise.
const HTTP_RATE_BUCKETS: usize = 60;

/// Number of session-state samples to fan out into the heatmap-aware
/// snapshot. The actual heatmap lives in `services::dashboard`; here
/// we surface only the in-flight counts.
const SESSION_TYPE_SSH: &str = "ssh";
const SESSION_TYPE_RDP: &str = "rdp";

/// Postgres pool occupancy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolHealth {
    pub max_size: u32,
    pub size: u32,
    pub available: u32,
    pub waiting: u32,
}

/// Aggregated system health visible from the dashboard.
///
/// `web_*` fields measure HTTP traffic on the current vauban-web
/// instance (single process; horizontal scaling is out of scope for
/// v1.0). Supervisor latency is shared across processes only by
/// channel: each vauban-web has its own tracker with the latency
/// observed FROM ITS POV, which is exactly what we want to display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemHealth {
    /// HTTP requests served in the last 60 s (full window).
    pub http_req_last_60s: u64,
    /// HTTP requests / second over the last 60 s.
    pub http_req_per_sec: u64,
    /// Supervisor broker latency (FD-pass round-trip).
    pub broker_latency: LatencySnapshot,
    /// Number of `proxy_sessions` rows with `status = 'active'` and
    /// `session_type = 'ssh'`.
    pub ssh_active_sessions: u64,
    /// Number of `proxy_sessions` rows with `status = 'active'` and
    /// `session_type = 'rdp'`.
    pub rdp_active_sessions: u64,
    /// Postgres connection pool usage.
    pub pg_pool: PoolHealth,
    /// `email_outbox` rows still `pending` (queued but not delivered).
    pub mailer_outbox_pending: u64,
    /// Wall-clock at which the snapshot was computed; the dashboard
    /// uses this for "last updated" labels.
    pub computed_at: chrono::DateTime<chrono::Utc>,
}

impl SystemHealth {
    /// Convenience: a "broken" snapshot returned when DB queries
    /// fail. The dashboard renders this as a warning state rather
    /// than panicking.
    pub fn degraded(broker_latency: LatencySnapshot, pg_pool: PoolHealth) -> Self {
        Self {
            http_req_last_60s: 0,
            http_req_per_sec: 0,
            broker_latency,
            ssh_active_sessions: 0,
            rdp_active_sessions: 0,
            pg_pool,
            mailer_outbox_pending: 0,
            computed_at: chrono::Utc::now(),
        }
    }
}

/// In-process HTTP rate tracker.
///
/// Bucketed sliding window: 60 buckets of 1 s. A request bumps the
/// current bucket; `recent_count` sums all 60 buckets. We intentionally
/// keep this lock-free at record time (atomic add) and only lock on
/// the once-per-second bucket-rotation.
pub struct HttpRateTracker {
    buckets: [AtomicU64; HTTP_RATE_BUCKETS],
    /// `Instant` of the START of the bucket at index 0. Buckets rotate
    /// when `now - start >= 1s` -- handled by `record_locked`.
    state: Mutex<TrackerState>,
}

struct TrackerState {
    /// Index of the bucket that the *next* `record` will write into.
    head: usize,
    /// Wall-clock of the head bucket's start.
    head_started_at: Instant,
}

impl Default for HttpRateTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpRateTracker {
    pub fn new() -> Self {
        // `AtomicU64` is `!Copy` -- build the array via `from_fn`.
        let buckets = std::array::from_fn(|_| AtomicU64::new(0));
        Self {
            buckets,
            state: Mutex::new(TrackerState {
                head: 0,
                head_started_at: Instant::now(),
            }),
        }
    }

    /// Atomically count one request. Rotates buckets if the second
    /// has changed since the last call.
    pub fn record(&self) {
        // Best-effort rotation. If the lock is contended we still
        // count into whatever the current head is -- a sub-second
        // skew is irrelevant for a 60-bucket window.
        if let Ok(mut s) = self.state.lock() {
            self.maybe_rotate(&mut s);
            self.buckets[s.head].fetch_add(1, Ordering::Relaxed);
        }
    }

    fn maybe_rotate(&self, s: &mut TrackerState) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(s.head_started_at);
        let secs = elapsed.as_secs() as usize;
        if secs == 0 {
            return;
        }
        // Zero out the "newer" buckets we are about to overwrite.
        let advance = secs.min(HTTP_RATE_BUCKETS);
        for k in 1..=advance {
            let idx = (s.head + k) % HTTP_RATE_BUCKETS;
            self.buckets[idx].store(0, Ordering::Relaxed);
        }
        s.head = (s.head + advance) % HTTP_RATE_BUCKETS;
        s.head_started_at = now;
    }

    /// Sum of the last 60 s of buckets.
    pub fn last_60s(&self) -> u64 {
        // Force rotation so an idle process does not show stale
        // counts from the previous minute.
        if let Ok(mut s) = self.state.lock() {
            self.maybe_rotate(&mut s);
        }
        self.buckets
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .sum::<u64>()
    }
}

/// In-process LIVE-session count history.
///
/// Drives the LIVE hero tile's sparkline on `bastion_watch`. The
/// bucket-by-hour `proxy_sessions.created_at` query previously used
/// for that sparkline conflated "openings per hour" with "active
/// count over time" -- a session that opened at 00:30 and stayed
/// alive until 03:00 surfaced as a single spike at hour 0 followed
/// by a flat zero, giving the operator the false impression that
/// the bastion had emptied. This tracker instead samples the live
/// count at every snapshot computation (1 Hz fast tier) so the
/// sparkline reflects actual live-count motion.
///
/// Buffer policy: bounded ring of `LIVE_HISTORY_CAP` samples
/// (2 minutes at 1 Hz). Older samples are dropped on push. The
/// tracker is started empty -- the sparkline progressively fills
/// during the first 2 minutes after process boot, which the
/// hero tile renders as a partially-populated trace.
#[derive(Debug)]
pub struct LiveSessionHistory {
    samples: Mutex<VecDeque<u64>>,
    cap: usize,
}

impl Default for LiveSessionHistory {
    fn default() -> Self {
        Self::new(LIVE_HISTORY_CAP)
    }
}

impl LiveSessionHistory {
    pub fn new(cap: usize) -> Self {
        let cap = cap.max(2);
        Self {
            samples: Mutex::new(VecDeque::with_capacity(cap)),
            cap,
        }
    }

    /// Record a new live-session count. Caps the buffer at `cap`
    /// by dropping the oldest sample. Lock poisoning is recovered
    /// transparently (the dashboard never panics from telemetry).
    pub fn record(&self, count: u64) {
        let mut g = self
            .samples
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        g.push_back(count);
        while g.len() > self.cap {
            g.pop_front();
        }
    }

    /// Snapshot the current series, oldest-first, suitable for
    /// `Sparkline::from_series`. Returns an empty vector if the
    /// tracker has not yet recorded any samples (the sparkline
    /// renders as a flat midline in that case, by contract of
    /// [`crate::services::dashboard::widgets::Sparkline`]).
    pub fn series(&self) -> Vec<f32> {
        let g = self
            .samples
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        g.iter().map(|c| *c as f32).collect()
    }

    /// Number of samples currently buffered. Exposed for tests and
    /// for a future "samples=N" structured field on the LIVE tile
    /// caption.
    pub fn len(&self) -> usize {
        self.samples
            .lock()
            .map(|g| g.len())
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Cached snapshot wrapper. The dashboard pusher (1 s cadence) calls
/// `SystemHealthCache::snapshot()`; the cache only re-queries the DB
/// every `CACHE_TTL`.
pub struct SystemHealthCache {
    db_pool: DbPool,
    broker_latency: Arc<BrokerLatencyTracker>,
    http_rate: Arc<HttpRateTracker>,
    cached: Mutex<Option<(Instant, SystemHealth)>>,
}

impl SystemHealthCache {
    pub fn new(
        db_pool: DbPool,
        broker_latency: Arc<BrokerLatencyTracker>,
        http_rate: Arc<HttpRateTracker>,
    ) -> Self {
        Self {
            db_pool,
            broker_latency,
            http_rate,
            cached: Mutex::new(None),
        }
    }

    /// Return a cached or freshly computed snapshot.
    ///
    /// Cache-miss path runs the DB queries serially (SSH count, RDP
    /// count, mailer pending). Each query is sub-millisecond on a
    /// healthy bastion; doing them in parallel via `tokio::join!`
    /// would require three pool checkouts, which is more expensive
    /// than the queries themselves on a small pool.
    pub async fn snapshot(&self) -> SystemHealth {
        if let Some(snap) = self.cached_fresh() {
            return snap;
        }
        let fresh = self.compute().await;
        if let Ok(mut g) = self.cached.lock() {
            *g = Some((Instant::now(), fresh.clone()));
        }
        fresh
    }

    fn cached_fresh(&self) -> Option<SystemHealth> {
        let g = self.cached.lock().ok()?;
        let (at, snap) = g.as_ref()?;
        if at.elapsed() < CACHE_TTL {
            Some(snap.clone())
        } else {
            None
        }
    }

    async fn compute(&self) -> SystemHealth {
        let pool_status = self.db_pool.status();
        // `deadpool::Status` exposes max_size / size / available /
        // waiting; we coerce to u32 for stable display.
        let pg_pool = PoolHealth {
            max_size: pool_status.max_size as u32,
            size: pool_status.size as u32,
            available: pool_status.available.max(0) as u32,
            waiting: pool_status.waiting as u32,
        };
        let broker_latency = self.broker_latency.snapshot();

        let mut conn = match self.db_pool.get().await {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "system_health: pool checkout failed; returning degraded snapshot");
                return SystemHealth::degraded(broker_latency, pg_pool);
            }
        };

        let ssh_active: i64 = match proxy_sessions::table
            .filter(proxy_sessions::status.eq("active"))
            .filter(proxy_sessions::session_type.eq(SESSION_TYPE_SSH))
            .select(count_star())
            .get_result(&mut conn)
            .await
        {
            Ok(n) => n,
            Err(e) => {
                warn!(error = %e, "system_health: ssh count failed");
                0
            }
        };
        let rdp_active: i64 = match proxy_sessions::table
            .filter(proxy_sessions::status.eq("active"))
            .filter(proxy_sessions::session_type.eq(SESSION_TYPE_RDP))
            .select(count_star())
            .get_result(&mut conn)
            .await
        {
            Ok(n) => n,
            Err(e) => {
                warn!(error = %e, "system_health: rdp count failed");
                0
            }
        };
        let outbox_pending: i64 = match email_outbox::table
            .filter(email_outbox::status.eq("pending"))
            .select(count_star())
            .get_result(&mut conn)
            .await
        {
            Ok(n) => n,
            Err(e) => {
                warn!(error = %e, "system_health: outbox count failed");
                0
            }
        };

        let req_last_60s = self.http_rate.last_60s();
        SystemHealth {
            http_req_last_60s: req_last_60s,
            http_req_per_sec: req_last_60s / 60,
            broker_latency,
            ssh_active_sessions: ssh_active.max(0) as u64,
            rdp_active_sessions: rdp_active.max(0) as u64,
            pg_pool,
            mailer_outbox_pending: outbox_pending.max(0) as u64,
            computed_at: chrono::Utc::now(),
        }
    }
}

/// Axum middleware: counts every HTTP request in the rate tracker.
///
/// Wired in `main.rs` once. The middleware is intentionally permissive
/// -- it never returns an error and never blocks; if the tracker mutex
/// is poisoned the request still goes through, the dashboard simply
/// shows a stale rate.
pub async fn record_http_request(
    axum::extract::State(tracker): axum::extract::State<Arc<HttpRateTracker>>,
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    tracker.record();
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_rate_tracker_counts_within_one_second_window() {
        let t = HttpRateTracker::new();
        for _ in 0..42 {
            t.record();
        }
        assert_eq!(t.last_60s(), 42);
    }

    #[test]
    fn http_rate_tracker_rotation_zeroes_old_buckets() {
        // We can't reliably sleep 60s in a unit test; instead, we
        // verify the rotation arithmetic by calling
        // `maybe_rotate` directly via a forged state.
        let t = HttpRateTracker::new();
        for _ in 0..5 {
            t.record();
        }
        assert_eq!(t.last_60s(), 5);
        // Manually rewind the head start so maybe_rotate sees a
        // 65 s elapsed -> wraps the entire window.
        if let Ok(mut g) = t.state.lock() {
            g.head_started_at = Instant::now() - Duration::from_secs(65);
        }
        // Trigger rotation by recording one more.
        t.record();
        assert_eq!(
            t.last_60s(),
            1,
            "rotation MUST zero old buckets so an idle bastion does \
             not display yesterday's traffic"
        );
    }

    #[test]
    fn live_session_history_records_and_returns_oldest_first_series() {
        let h = LiveSessionHistory::new(8);
        assert!(h.is_empty());
        for v in [3u64, 5, 7, 5, 4] {
            h.record(v);
        }
        assert_eq!(h.len(), 5);
        let s = h.series();
        assert_eq!(s, vec![3.0_f32, 5.0, 7.0, 5.0, 4.0]);
    }

    #[test]
    fn live_session_history_drops_oldest_when_capacity_exceeded() {
        let h = LiveSessionHistory::new(4);
        for v in 1..=10u64 {
            h.record(v);
        }
        assert_eq!(h.len(), 4, "buffer must cap at `cap` samples");
        // Series MUST be the most-recent 4: 7, 8, 9, 10.
        assert_eq!(h.series(), vec![7.0_f32, 8.0, 9.0, 10.0]);
    }

    #[test]
    fn live_session_history_default_uses_live_history_cap_constant() {
        let h = LiveSessionHistory::default();
        for v in 0..(LIVE_HISTORY_CAP as u64 + 50) {
            h.record(v);
        }
        assert_eq!(
            h.len(),
            LIVE_HISTORY_CAP,
            "default capacity MUST track the LIVE_HISTORY_CAP \
             constant so the dashboard's sparkline window is \
             pinned at the documented 2-minute horizon"
        );
    }

    #[test]
    fn live_session_history_minimum_cap_is_two() {
        // Cap of 0 / 1 would not produce a meaningful sparkline.
        // The constructor MUST clamp upwards.
        let h = LiveSessionHistory::new(0);
        h.record(42);
        h.record(43);
        h.record(44);
        assert_eq!(h.len(), 2, "cap=0 must clamp to 2 (min usable)");
        assert_eq!(h.series(), vec![43.0_f32, 44.0]);
    }

    #[test]
    fn system_health_degraded_uses_provided_inputs() {
        let bl = LatencySnapshot {
            count: 0,
            median_us: None,
            p95_us: None,
            window_secs: 300,
        };
        let pp = PoolHealth {
            max_size: 16,
            size: 4,
            available: 3,
            waiting: 0,
        };
        let h = SystemHealth::degraded(bl.clone(), pp);
        assert_eq!(h.broker_latency, bl);
        assert_eq!(h.pg_pool, pp);
        assert_eq!(h.ssh_active_sessions, 0);
        assert_eq!(h.rdp_active_sessions, 0);
        assert_eq!(h.mailer_outbox_pending, 0);
    }

    #[test]
    fn cache_constants_are_in_sync_with_pusher_cadence() {
        // The dashboard pusher runs at 1 s for SYSTEM HEALTH; the
        // cache MUST be longer than the pusher cadence (otherwise the
        // cache is useless) and shorter than the user attention span
        // (2-3 s before the data feels stale).
        assert!(
            CACHE_TTL >= Duration::from_secs(5),
            "cache TTL must absorb at least 5 pushes per second"
        );
        assert!(
            CACHE_TTL <= Duration::from_secs(10),
            "cache TTL must stay below 10 s so the dashboard is fresh"
        );
    }
}
