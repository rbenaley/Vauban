//! Recording integrity hydrator.
//!
//! Background task that scans `proxy_sessions` for finalized recordings
//! whose integrity bundle (`recording_blake3`, sizes, durations,
//! geometry, segment count, codec) has not yet been precomputed, reads
//! the on-disk `meta.json` produced by `vauban-audit` via the
//! `SupervisorClient::request_recording_file` SCM_RIGHTS plumbing, and
//! UPDATEs the row.
//!
//! Why hydrate:
//! - The Recording Details page (issue #29) renders these fields on
//!   every GET. Re-reading and parsing `meta.json` per request would
//!   add an FD-passing round-trip + JSON parse to a hot path.
//! - The integrity bundle is immutable post-mortem (the recording file
//!   is never appended to after `RecordingEnd`), so persisting once is
//!   safe and doesn't need invalidation.
//!
//! Design choices:
//! - Lazy: no IPC topology change; reuses the same path
//!   `serve_manifest` ([crate::handlers::web::sessions::serve_manifest])
//!   already uses to read the JSON. Latency budget: one tick interval
//!   (default 30 s) between disconnect and full integrity rendering.
//! - Idempotent: the UPDATE is gated by `recording_finalized_at IS NULL`
//!   so two concurrent hydrators (or replays) cannot double-write.
//! - Self-healing: missing `meta.json` leaves the row unfinalized so the
//!   next tick retries; corrupt JSON is marked finalized with a NULL
//!   format so the page renders "Integrity unavailable" rather than
//!   looping forever.
//! - RDP unification: SSH stores a single hash, RDP stores N segment
//!   hashes. The hydrator computes
//!   `BLAKE3(concat(segment_hashes_hex_bytes))` for RDP so the
//!   `recording_blake3` column has uniform semantics SSH/RDP. See
//!   [aggregate_rdp_blake3].

use std::sync::Arc;
use std::time::Duration;

use blake3::Hasher;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

/// Stable identifier used by [`shared::tasks::spawn_periodic`] for
/// the recording hydrator's daily reconciliation cron. Surfaces in
/// tracing as `task=recording_hydrator` so operators can correlate
/// the spawn line with later activity. Consumed by
/// [`crate::tasks::recording_hydrator::start_daily_reconciliation`].
pub const TASK_NAME: &str = "recording_hydrator";

use crate::AppState;
use crate::db::DbPool;
use crate::ipc::SupervisorClient;
use crate::models::session::SessionType;
use crate::services::broadcast::{BroadcastService, WsChannel, WsMessage};

/// Marker constant strings persisted in `recording_format`. Pinned by
/// the migration's `recording_format_enum` CHECK constraint and by the
/// structural test
/// `test_recording_format_constants_match_check_constraint_values`.
pub const FORMAT_ASCIICAST_V2: &str = "asciicast-v2";
pub const FORMAT_FMP4_DASH: &str = "fmp4-dash";
pub const FORMAT_FMP4_FLAT: &str = "fmp4-flat";

/// Shape of the SSH `meta.json` produced by
/// `vauban-audit::ssh_recording_manager::SshRecordingManager::serialize_meta_json`.
/// Mirrored here (rather than imported) so the audit crate stays
/// hermetic from web concerns.
#[derive(Debug, Deserialize)]
struct SshMeta {
    #[serde(default)]
    format: Option<String>,
    blake3_hex: String,
    total_bytes: u64,
    total_events: u64,
    duration_secs: f64,
    width: u16,
    height: u16,
}

/// Shape of one RDP segment in `meta.json`. Mirrors
/// `vauban-audit::recording_manager::SegmentInfo`.
#[derive(Debug, Deserialize)]
struct RdpSegment {
    #[allow(dead_code)]
    index: u32,
    width: u16,
    height: u16,
    duration_ticks: u64,
    /// moov header size in bytes (deserialised but not used; full
    /// segment file size is taken from `file_size`).
    #[allow(dead_code)]
    init_size: u64,
    file_size: u64,
    blake3_hex: String,
    codec_string: String,
}

/// Wrapper for RDP `meta.json`.
#[derive(Debug, Deserialize)]
struct RdpMeta {
    segments: Vec<RdpSegment>,
}

/// Bundle persisted on `proxy_sessions` after a successful tick.
#[derive(Debug, Clone, PartialEq)]
pub struct IntegrityBundle {
    pub blake3_hex: String,
    pub size_bytes: i64,
    pub duration_ms: i64,
    pub event_count: Option<i32>,
    pub format: String,
    pub width: i16,
    pub height: i16,
    pub segment_count: Option<i32>,
    pub codec: Option<String>,
}

/// Outcome of a single tick (used by tests and metrics).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HydrationReport {
    pub scanned: usize,
    pub finalized: usize,
    /// Race with `vauban-audit`: meta.json not yet on disk for a
    /// session disconnected within the grace period. Logged at DEBUG
    /// only (no operator alert).
    pub skipped_missing_meta: usize,
    /// meta.json missing past grace period -> row marked finalized
    /// with NULL integrity columns. Logged WARN once per session.
    pub marked_finalized_lost: usize,
    /// `recording_path` ends in `.mp4` (legacy fmp4-flat) -> row
    /// marked finalized with `recording_format = 'fmp4-flat'` and the
    /// other integrity columns NULL (no meta.json was ever produced
    /// for this format). Logged INFO once per session.
    pub marked_finalized_legacy_flat: usize,
    pub marked_finalized_corrupt: usize,
    pub errored: usize,
}

/// Errors raised by the hydrator's tick loop.
#[derive(Debug, thiserror::Error)]
pub enum HydrationError {
    #[error("database error: {0}")]
    Database(String),
    #[error("supervisor unavailable")]
    SupervisorMissing,
}

/// Lazy background hydrator. Schedule via
/// [`crate::tasks::recording_hydrator::start_recording_hydrator`].
///
/// The struct owns no cadence -- ticking is the scheduler's
/// responsibility -- only the per-tick state needed by [`Self::tick`].
pub struct RecordingHydrator {
    pool: DbPool,
    supervisor: Arc<SupervisorClient>,
    batch_size: i64,
    storage_base: String,
    missing_meta_grace: Duration,
    /// Live broadcast handle for WS push notifications when a row
    /// transitions to a finalized state. `None` for offline / batch
    /// contexts (e.g. bootstrap on a node that has not yet wired
    /// the WebSocket relay) -- the hydrator stays purely DB-driven
    /// in that case and the user falls back to the next page load.
    broadcast: Option<BroadcastService>,
}

impl RecordingHydrator {
    /// Build a new hydrator. Drives one pass per call to [`Self::tick`];
    /// the periodic schedule lives in
    /// [`crate::tasks::recording_hydrator::start_recording_hydrator`].
    pub fn new(
        pool: DbPool,
        supervisor: Arc<SupervisorClient>,
        batch_size: i64,
        storage_base: String,
        missing_meta_grace: Duration,
        broadcast: Option<BroadcastService>,
    ) -> Self {
        Self {
            pool,
            supervisor,
            batch_size,
            storage_base,
            missing_meta_grace,
            broadcast,
        }
    }

    // Scheduling is intentionally delegated to
    // [`crate::tasks::recording_hydrator::start_recording_hydrator`],
    // which uses `shared::tasks::spawn_periodic` so the hydrator
    // shares the same lifecycle conventions as `session_cleanup` and
    // the dashboard tickers (named tracing, skip-first-tick,
    // Handle-based spawn). This module exposes the pure tick API
    // (`tick`, `hydrate_one`) and keeps no opinion on cadence.

    /// Run one scan + UPDATE pass. Public for tests; the loop calls it
    /// every `interval`.
    pub async fn tick(&self) -> Result<HydrationReport, HydrationError> {
        use crate::schema::proxy_sessions::dsl;

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| HydrationError::Database(format!("pool: {}", e)))?;

        // Candidates: recorded sessions that have a path and have not
        // yet been finalized. The partial index
        // `idx_proxy_sessions_pending_finalization` (created by
        // migration 20260430000000) backs this query.
        type CandidateRow = (
            i32,
            ::uuid::Uuid,
            SessionType,
            Option<String>,
            Option<DateTime<Utc>>,
            DateTime<Utc>,
        );
        let candidates: Vec<CandidateRow> = dsl::proxy_sessions
            .filter(dsl::is_recorded.eq(true))
            .filter(dsl::recording_path.is_not_null())
            .filter(dsl::recording_finalized_at.is_null())
            .order(dsl::created_at.asc())
            .limit(self.batch_size)
            .select((
                dsl::id,
                dsl::uuid,
                dsl::session_type,
                dsl::recording_path,
                dsl::disconnected_at,
                dsl::created_at,
            ))
            .load(&mut conn)
            .await
            .map_err(|e| HydrationError::Database(format!("select: {}", e)))?;

        let mut report = HydrationReport {
            scanned: candidates.len(),
            ..Default::default()
        };

        let now = Utc::now();
        for (id, uuid, session_type, recording_path_opt, disconnected_at, created_at) in candidates
        {
            // The is_not_null filter above guarantees Some(_); be defensive.
            let recording_path = match recording_path_opt {
                Some(p) => p,
                None => continue,
            };

            // Category 1: legacy flat .mp4 (no meta.json was ever
            // produced for this format). Mark finalized once with
            // 'fmp4-flat' so the row stops being a candidate. Logged
            // INFO once and never retried.
            if !recording_path.ends_with('/') {
                match mark_finalized_legacy_flat(&self.pool, id).await {
                    Ok(_) => {
                        info!(
                            session_uuid = %uuid,
                            recording_path = %recording_path,
                            "hydrator: legacy flat .mp4 recording, marking finalized as fmp4-flat"
                        );
                        report.marked_finalized_legacy_flat += 1;
                        broadcast_recording_hydrated(&self.broadcast, &uuid).await;
                    }
                    Err(e) => {
                        error!(
                            session_uuid = %uuid,
                            error = %e,
                            "hydrator: failed to mark legacy flat .mp4 as finalized"
                        );
                        report.errored += 1;
                    }
                }
                continue;
            }

            match self.hydrate_one(&uuid, session_type, &recording_path).await {
                HydrationOutcome::Bundle(bundle) => {
                    if let Err(e) = persist_bundle(&self.pool, id, &bundle).await {
                        error!(
                            session_uuid = %uuid,
                            error = %e,
                            "hydrator: failed to persist integrity bundle"
                        );
                        report.errored += 1;
                    } else {
                        report.finalized += 1;
                        broadcast_recording_hydrated(&self.broadcast, &uuid).await;
                    }
                }
                HydrationOutcome::MissingMeta => {
                    // Decide: race with vauban-audit (recently
                    // disconnected, retry next tick) vs. lost
                    // recording (older than grace period, give up
                    // and mark finalized with NULL fields).
                    let reference = disconnected_at.unwrap_or(created_at);
                    let age = now.signed_duration_since(reference);
                    let grace = chrono::Duration::from_std(self.missing_meta_grace)
                        .unwrap_or(chrono::Duration::seconds(300));
                    if age > grace {
                        match mark_finalized_corrupt(&self.pool, id).await {
                            Ok(_) => {
                                warn!(
                                    session_uuid = %uuid,
                                    age_secs = age.num_seconds(),
                                    "hydrator: meta.json missing past grace period, marking finalized (integrity unavailable)"
                                );
                                report.marked_finalized_lost += 1;
                                broadcast_recording_hydrated(&self.broadcast, &uuid).await;
                            }
                            Err(e) => {
                                error!(
                                    session_uuid = %uuid,
                                    error = %e,
                                    "hydrator: failed to mark lost recording as finalized"
                                );
                                report.errored += 1;
                            }
                        }
                    } else {
                        debug!(
                            session_uuid = %uuid,
                            age_secs = age.num_seconds(),
                            "hydrator: meta.json missing within grace period, will retry next tick"
                        );
                        report.skipped_missing_meta += 1;
                    }
                }
                HydrationOutcome::CorruptMeta(reason) => {
                    error!(
                        session_uuid = %uuid,
                        reason = %reason,
                        "hydrator: meta.json corrupt, marking finalized with NULL format"
                    );
                    if let Err(e) = mark_finalized_corrupt(&self.pool, id).await {
                        error!(
                            session_uuid = %uuid,
                            error = %e,
                            "hydrator: failed to mark corrupt row as finalized"
                        );
                        report.errored += 1;
                    } else {
                        report.marked_finalized_corrupt += 1;
                        broadcast_recording_hydrated(&self.broadcast, &uuid).await;
                    }
                }
                HydrationOutcome::Error(e) => {
                    error!(
                        session_uuid = %uuid,
                        error = %e,
                        "hydrator: unrecoverable error on session"
                    );
                    report.errored += 1;
                }
            }
        }

        Ok(report)
    }

    /// Hydrate a single session by its primary key. Used by the
    /// per-call-site `enqueue_hydration` path: every UPDATE that sets
    /// `disconnected_at` on a recorded session schedules a delayed
    /// call to this method so the integrity bundle is persisted
    /// within seconds of the session ending, without polling.
    ///
    /// Idempotent: the underlying `persist_bundle` /
    /// `mark_finalized_*` UPDATEs are gated by
    /// `recording_finalized_at IS NULL`, so calling this twice (or
    /// concurrently with the daily reconciliation cron) is safe and
    /// the second call is a no-op at the DB level.
    ///
    /// Returns `Ok(report)` so callers can log structured outcomes
    /// (`finalized=1`, `skipped_missing_meta=1`, ...). The single-row
    /// report uses the same counters as `tick()` for uniform logging.
    pub async fn hydrate_session_id(
        &self,
        session_id: i32,
    ) -> Result<HydrationReport, HydrationError> {
        use crate::schema::proxy_sessions::dsl;

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| HydrationError::Database(format!("pool: {}", e)))?;

        type CandidateRow = (
            i32,
            ::uuid::Uuid,
            SessionType,
            Option<String>,
            Option<DateTime<Utc>>,
            DateTime<Utc>,
            bool,
        );
        // Filter on the same predicates as `tick`, plus `id = ?`. The
        // `is_recorded` and `recording_finalized_at IS NULL` clauses
        // make this a no-op for sessions that are already finalised
        // or were never recorded -> safe to call from any call-site
        // without an extra preflight check.
        let row: Option<CandidateRow> = dsl::proxy_sessions
            .filter(dsl::id.eq(session_id))
            .filter(dsl::is_recorded.eq(true))
            .filter(dsl::recording_path.is_not_null())
            .filter(dsl::recording_finalized_at.is_null())
            .select((
                dsl::id,
                dsl::uuid,
                dsl::session_type,
                dsl::recording_path,
                dsl::disconnected_at,
                dsl::created_at,
                dsl::is_recorded,
            ))
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| HydrationError::Database(format!("select by id: {}", e)))?;

        let mut report = HydrationReport::default();
        let (id, uuid, session_type, recording_path_opt, disconnected_at, created_at, _) = match row
        {
            Some(r) => r,
            None => {
                debug!(
                    session_id,
                    "hydrator: nothing to hydrate (already finalized, not recorded, or no path)"
                );
                return Ok(report);
            }
        };
        report.scanned = 1;

        let recording_path = match recording_path_opt {
            Some(p) => p,
            None => return Ok(report),
        };

        // Same legacy-flat short-circuit as `tick`.
        if !recording_path.ends_with('/') {
            match mark_finalized_legacy_flat(&self.pool, id).await {
                Ok(_) => {
                    info!(
                        session_uuid = %uuid,
                        recording_path = %recording_path,
                        "hydrator: legacy flat .mp4 recording, marking finalized as fmp4-flat"
                    );
                    report.marked_finalized_legacy_flat += 1;
                    broadcast_recording_hydrated(&self.broadcast, &uuid).await;
                }
                Err(e) => {
                    error!(
                        session_uuid = %uuid,
                        error = %e,
                        "hydrator: failed to mark legacy flat .mp4 as finalized"
                    );
                    report.errored += 1;
                }
            }
            return Ok(report);
        }

        match self.hydrate_one(&uuid, session_type, &recording_path).await {
            HydrationOutcome::Bundle(bundle) => {
                if let Err(e) = persist_bundle(&self.pool, id, &bundle).await {
                    error!(
                        session_uuid = %uuid,
                        error = %e,
                        "hydrator: failed to persist integrity bundle"
                    );
                    report.errored += 1;
                } else {
                    info!(
                        session_uuid = %uuid,
                        "hydration_finalized: integrity bundle persisted"
                    );
                    report.finalized += 1;
                    broadcast_recording_hydrated(&self.broadcast, &uuid).await;
                }
            }
            HydrationOutcome::MissingMeta => {
                let now = Utc::now();
                let reference = disconnected_at.unwrap_or(created_at);
                let age = now.signed_duration_since(reference);
                let grace = chrono::Duration::from_std(self.missing_meta_grace)
                    .unwrap_or(chrono::Duration::seconds(300));
                if age > grace {
                    match mark_finalized_corrupt(&self.pool, id).await {
                        Ok(_) => {
                            warn!(
                                session_uuid = %uuid,
                                age_secs = age.num_seconds(),
                                "hydrator: meta.json missing past grace period, marking finalized (integrity unavailable)"
                            );
                            report.marked_finalized_lost += 1;
                            broadcast_recording_hydrated(&self.broadcast, &uuid).await;
                        }
                        Err(e) => {
                            error!(
                                session_uuid = %uuid,
                                error = %e,
                                "hydrator: failed to mark lost recording as finalized"
                            );
                            report.errored += 1;
                        }
                    }
                } else {
                    debug!(
                        session_uuid = %uuid,
                        age_secs = age.num_seconds(),
                        "hydrator: meta.json missing within grace period (will retry on next bootstrap or daily cron)"
                    );
                    report.skipped_missing_meta += 1;
                }
            }
            HydrationOutcome::CorruptMeta(reason) => {
                error!(
                    session_uuid = %uuid,
                    reason = %reason,
                    "hydrator: meta.json corrupt, marking finalized with NULL format"
                );
                if let Err(e) = mark_finalized_corrupt(&self.pool, id).await {
                    error!(
                        session_uuid = %uuid,
                        error = %e,
                        "hydrator: failed to mark corrupt row as finalized"
                    );
                    report.errored += 1;
                } else {
                    report.marked_finalized_corrupt += 1;
                    broadcast_recording_hydrated(&self.broadcast, &uuid).await;
                }
            }
            HydrationOutcome::Error(e) => {
                error!(
                    session_uuid = %uuid,
                    error = %e,
                    "hydrator: unrecoverable error on session"
                );
                report.errored += 1;
            }
        }

        Ok(report)
    }

    async fn hydrate_one(
        &self,
        uuid: &::uuid::Uuid,
        session_type: SessionType,
        recording_path: &str,
    ) -> HydrationOutcome {
        let meta_relative = match meta_relative_for(&self.storage_base, recording_path) {
            Some(p) => p,
            None => {
                // Should not happen: the caller filters out flat
                // .mp4 paths before calling hydrate_one. Defensive
                // catch-all so the row is not silently retried.
                return HydrationOutcome::Error(
                    "recording_path does not yield a meta.json relative path (flat .mp4?)"
                        .to_string(),
                );
            }
        };

        let result = match self
            .supervisor
            .request_recording_file(&uuid.to_string(), &meta_relative)
            .await
        {
            Ok(r) => r,
            Err(e) => return HydrationOutcome::Error(format!("supervisor: {}", e)),
        };

        if !result.success {
            return HydrationOutcome::MissingMeta;
        }

        let std_file = match result.file {
            Some(f) => f,
            None => return HydrationOutcome::MissingMeta,
        };

        let mut tokio_file = tokio::fs::File::from_std(std_file);
        let mut buf = String::new();
        if let Err(e) = tokio_file.read_to_string(&mut buf).await {
            return HydrationOutcome::Error(format!("read meta.json: {}", e));
        }

        match parse_meta(session_type, &buf) {
            Ok(bundle) => HydrationOutcome::Bundle(bundle),
            Err(reason) => HydrationOutcome::CorruptMeta(reason),
        }
    }
}

enum HydrationOutcome {
    Bundle(IntegrityBundle),
    MissingMeta,
    CorruptMeta(String),
    Error(String),
}

/// Compute the relative path of the `meta.json` file given the session's
/// `recording_path` (which is either the recording directory, e.g.
/// `recordings/2026/04/UUID/`, or a flat `.mp4` path for legacy RDP).
///
/// Returns `Some(<dir>/meta.json)` for directory-style paths, `None` for
/// the flat-MP4 legacy case (no meta.json was ever written for those).
pub fn meta_relative_for(storage_base: &str, recording_path: &str) -> Option<String> {
    if !recording_path.ends_with('/') {
        return None;
    }
    let stripped = recording_path
        .strip_prefix(storage_base)
        .unwrap_or(recording_path)
        .trim_start_matches('/');
    Some(format!("{}meta.json", stripped))
}

/// Parse a meta.json buffer for a given session type into an
/// [`IntegrityBundle`]. Returns Err with a human-readable reason on
/// any format violation.
pub fn parse_meta(session_type: SessionType, buf: &str) -> Result<IntegrityBundle, String> {
    match session_type {
        SessionType::Ssh => {
            let meta: SshMeta =
                serde_json::from_str(buf).map_err(|e| format!("invalid SSH meta.json: {}", e))?;
            if !is_valid_blake3_hex(&meta.blake3_hex) {
                return Err(format!(
                    "SSH blake3_hex is not 64-char lowercase hex: {}",
                    meta.blake3_hex
                ));
            }
            Ok(IntegrityBundle {
                blake3_hex: meta.blake3_hex,
                size_bytes: i64::try_from(meta.total_bytes).unwrap_or(i64::MAX),
                duration_ms: (meta.duration_secs * 1000.0).round() as i64,
                event_count: i32::try_from(meta.total_events).ok(),
                format: meta
                    .format
                    .unwrap_or_else(|| FORMAT_ASCIICAST_V2.to_string()),
                width: meta.width as i16,
                height: meta.height as i16,
                segment_count: None,
                codec: None,
            })
        }
        SessionType::Rdp => {
            let meta: RdpMeta =
                serde_json::from_str(buf).map_err(|e| format!("invalid RDP meta.json: {}", e))?;
            if meta.segments.is_empty() {
                // Empty segments array is treated as fmp4-flat legacy
                // (no integrity to persist beyond size/format from the
                // file itself; we cannot derive that here without
                // reading the .mp4). Return a placeholder bundle that
                // will be rejected by is_valid_blake3 check; caller
                // must handle.
                return Err("RDP meta.json has no segments".to_string());
            }
            for seg in &meta.segments {
                if !is_valid_blake3_hex(&seg.blake3_hex) {
                    return Err(format!(
                        "RDP segment {} blake3_hex not 64-char hex",
                        seg.index
                    ));
                }
            }
            let aggregated = aggregate_rdp_blake3(&meta.segments);
            // Total size = sum of all per-segment file sizes (init +
            // media boxes). `init_size` is only the moov header bytes;
            // `file_size` is the full segment file on disk.
            let size_bytes: i64 = meta
                .segments
                .iter()
                .map(|s| i64::try_from(s.file_size).unwrap_or(i64::MAX))
                .sum();
            // Duration: sum of per-segment ticks at 90 kHz, then convert
            // to ms.
            let total_ticks: u64 = meta.segments.iter().map(|s| s.duration_ticks).sum();
            let duration_ms = (total_ticks as i64 * 1000) / 90_000;
            // Geometry from the last segment (final resolution shown to
            // the user). Codec from the first segment (DASH players
            // require a stable codec parameter across the manifest).
            let last = meta
                .segments
                .last()
                .ok_or_else(|| "unreachable: empty after non-empty check".to_string())?;
            let first = &meta.segments[0];
            let segment_count = i32::try_from(meta.segments.len()).unwrap_or(i32::MAX);
            Ok(IntegrityBundle {
                blake3_hex: aggregated,
                size_bytes,
                duration_ms,
                event_count: None,
                format: FORMAT_FMP4_DASH.to_string(),
                width: last.width as i16,
                height: last.height as i16,
                segment_count: Some(segment_count),
                codec: Some(first.codec_string.clone()),
            })
        }
    }
}

/// Aggregated BLAKE3 for an RDP recording: hash of the byte sequence
/// formed by concatenating each segment's `blake3_hex` ASCII bytes in
/// segment order. Deterministic, order-sensitive, easy to recompute by
/// hand for verification.
pub fn aggregate_rdp_blake3<S: HasSegmentHash>(segments: &[S]) -> String {
    let mut hasher = Hasher::new();
    for s in segments {
        hasher.update(s.blake3_hex().as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

/// Trait for the segment-hash projection so [`aggregate_rdp_blake3`]
/// works both on the internal `RdpSegment` type and on test fixtures.
pub trait HasSegmentHash {
    fn blake3_hex(&self) -> &str;
}

impl HasSegmentHash for RdpSegment {
    fn blake3_hex(&self) -> &str {
        &self.blake3_hex
    }
}

/// True iff `s` is exactly 64 chars of [0-9a-f]. Mirrors the DB
/// constraint `recording_blake3_format`.
pub fn is_valid_blake3_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Push a `recording_hydrated` WebSocket notification on the
/// `Notifications` channel.
///
/// The payload is a JSON document the Recording Details and Recording
/// List templates filter on (`detail.message.indexOf('recording_hydrated')`
/// and the `session_uuid`). Sent on every state transition the page
/// might want to react to: integrity bundle persisted, row marked
/// "integrity unavailable" (corrupt / missing meta), or row marked
/// legacy-flat. Quietly skipped when no `BroadcastService` was wired
/// (CLI / offline batch contexts).
///
/// Failures are logged at `debug` and never bubble up: a broken WS
/// channel must not stop the hydrator from finalizing rows.
async fn broadcast_recording_hydrated(
    broadcast: &Option<BroadcastService>,
    session_uuid: &::uuid::Uuid,
) {
    let Some(b) = broadcast else { return };
    let payload = format!(
        r#"{{"type":"recording_hydrated","session_uuid":"{}"}}"#,
        session_uuid
    );
    if let Err(()) = b
        .send(
            &WsChannel::Notifications,
            WsMessage::new("jit-notification", payload),
        )
        .await
    {
        debug!(
            session_uuid = %session_uuid,
            "hydrator: WS notify failed (no live subscriber); ignoring"
        );
    }
}

async fn persist_bundle(
    pool: &DbPool,
    session_id: i32,
    bundle: &IntegrityBundle,
) -> Result<(), String> {
    use crate::schema::proxy_sessions::dsl;
    let mut conn = pool.get().await.map_err(|e| format!("pool: {}", e))?;
    let now: DateTime<Utc> = Utc::now();
    let updated = diesel::update(
        dsl::proxy_sessions
            .filter(dsl::id.eq(session_id))
            .filter(dsl::recording_finalized_at.is_null()),
    )
    .set((
        dsl::recording_blake3.eq(&bundle.blake3_hex),
        dsl::recording_size_bytes.eq(bundle.size_bytes),
        dsl::recording_duration_ms.eq(bundle.duration_ms),
        dsl::recording_event_count.eq(bundle.event_count),
        dsl::recording_format.eq(&bundle.format),
        dsl::recording_width.eq(bundle.width),
        dsl::recording_height.eq(bundle.height),
        dsl::recording_segment_count.eq(bundle.segment_count),
        dsl::recording_codec.eq(bundle.codec.as_deref()),
        dsl::recording_finalized_at.eq(now),
    ))
    .execute(&mut conn)
    .await
    .map_err(|e| format!("update: {}", e))?;
    if updated == 0 {
        // Concurrent hydrator already finalized the row; that's fine.
        debug!(session_id, "hydrator: row already finalized concurrently");
    }
    Ok(())
}

/// Mark a recording row as finalized with all integrity columns NULL,
/// signalling "Integrity unavailable" to the page. Used by the
/// hydrator's corrupt-meta and missing-meta-past-grace paths.
/// Exposed for the runbook's "force-finalize a hopelessly broken row"
/// procedure (`docs/runbooks/recording_hydrator.md` section B).
pub async fn mark_finalized_corrupt(pool: &DbPool, session_id: i32) -> Result<(), String> {
    use crate::schema::proxy_sessions::dsl;
    let mut conn = pool.get().await.map_err(|e| format!("pool: {}", e))?;
    let now: DateTime<Utc> = Utc::now();
    diesel::update(
        dsl::proxy_sessions
            .filter(dsl::id.eq(session_id))
            .filter(dsl::recording_finalized_at.is_null()),
    )
    .set((
        dsl::recording_finalized_at.eq(now),
        // All other recording_* columns stay NULL so the page renders
        // "Integrity unavailable" (operator-actionable signal).
    ))
    .execute(&mut conn)
    .await
    .map_err(|e| format!("update: {}", e))?;
    Ok(())
}

/// PRIMARY hydration path, by-UUID variant. Same semantics as
/// [`enqueue_hydration`] but accepts a session UUID -- handy for
/// call-sites whose UPDATE used `WHERE uuid = ?` and never read the
/// integer primary key. The DB lookup happens inside the spawned
/// task (after the grace sleep), so the hot path stays
/// allocation-free.
pub fn enqueue_hydration_by_uuid(
    state: &AppState,
    session_uuid: ::uuid::Uuid,
    grace: Duration,
) -> JoinHandle<()> {
    let supervisor = match state.supervisor.as_ref() {
        Some(s) => Arc::clone(s),
        None => {
            debug!(
                session_uuid = %session_uuid,
                "hydration enqueue skipped: supervisor IPC unavailable (dev mode)"
            );
            return tokio::spawn(async {});
        }
    };
    if !state.config.recording.hydration_enabled {
        debug!(
            session_uuid = %session_uuid,
            "hydration enqueue skipped: recording.hydration_enabled = false"
        );
        return tokio::spawn(async {});
    }
    let pool = state.db_pool.clone();
    let storage_base = state.config.recording.storage_path.clone();
    let batch_size = state.config.recording.hydration_batch_size;
    let missing_meta_grace =
        Duration::from_secs(state.config.recording.hydration_missing_meta_grace_secs);
    let broadcast = state.broadcast.clone();
    debug!(
        session_uuid = %session_uuid,
        grace_secs = grace.as_secs(),
        "enqueue_hydration_by_uuid: scheduled"
    );
    tokio::spawn(async move {
        tokio::time::sleep(grace).await;
        // Resolve UUID -> id. If it cannot be found the task is a
        // no-op; this keeps the call-side allocation free.
        let id_result: Result<Option<i32>, String> = async {
            use crate::schema::proxy_sessions::dsl;
            let mut conn = pool.get().await.map_err(|e| format!("pool: {}", e))?;
            dsl::proxy_sessions
                .filter(dsl::uuid.eq(session_uuid))
                .select(dsl::id)
                .first::<i32>(&mut conn)
                .await
                .optional()
                .map_err(|e| format!("select id by uuid: {}", e))
        }
        .await;
        let id = match id_result {
            Ok(Some(i)) => i,
            Ok(None) => {
                debug!(session_uuid = %session_uuid, "enqueue_hydration_by_uuid: session not found, skipping");
                return;
            }
            Err(e) => {
                error!(session_uuid = %session_uuid, error = %e, "enqueue_hydration_by_uuid: lookup failed");
                return;
            }
        };
        let hydrator = RecordingHydrator::new(
            pool,
            supervisor,
            batch_size,
            storage_base,
            missing_meta_grace,
            Some(broadcast),
        );
        match hydrator.hydrate_session_id(id).await {
            Ok(report) => {
                if report.scanned == 0 {
                    debug!(
                        session_uuid = %session_uuid,
                        "enqueue_hydration_by_uuid: nothing to do (already finalized or not recorded)"
                    );
                }
            }
            Err(e) => {
                error!(session_uuid = %session_uuid, error = %e, "enqueue_hydration_by_uuid: hydrate_session_id failed");
            }
        }
    })
}

/// PRIMARY hydration path. Schedule a single-shot hydration of one
/// session after the configurable grace period
/// (`recording.hydration_enqueue_delay_secs`, default 5 s). Called
/// by every call-site that sets `proxy_sessions.disconnected_at` on
/// a recorded session (WebSocket close, API terminate, admin
/// terminate, user deletion, cleanup transitions).
///
/// Why a delay: `vauban-web` sets `disconnected_at` immediately on
/// session end, but `vauban-audit` may take 1-2 seconds to flush the
/// final segment + `meta.json` to disk. Calling `hydrate_session_id`
/// before that flush would race and degrade to the
/// `MissingMeta` -> retry path. The 5 s default is a prudent margin.
///
/// Idempotent and side-effect-free if there is nothing to do:
/// - returns a JoinHandle that completes immediately when the
///   supervisor IPC channel is unavailable (development mode);
/// - the eventual `hydrate_session_id` is itself a no-op if the row
///   has been finalized concurrently (by the bootstrap, by the
///   daily cron, or by a sibling enqueue).
///
/// The returned JoinHandle is normally dropped (fire-and-forget);
/// tests keep a reference to await completion.
pub fn enqueue_hydration(state: &AppState, session_id: i32, grace: Duration) -> JoinHandle<()> {
    let supervisor = match state.supervisor.as_ref() {
        Some(s) => Arc::clone(s),
        None => {
            debug!(
                session_id,
                "hydration enqueue skipped: supervisor IPC unavailable (dev mode)"
            );
            return tokio::spawn(async {});
        }
    };
    if !state.config.recording.hydration_enabled {
        debug!(
            session_id,
            "hydration enqueue skipped: recording.hydration_enabled = false"
        );
        return tokio::spawn(async {});
    }
    let pool = state.db_pool.clone();
    let storage_base = state.config.recording.storage_path.clone();
    let batch_size = state.config.recording.hydration_batch_size;
    let missing_meta_grace =
        Duration::from_secs(state.config.recording.hydration_missing_meta_grace_secs);
    let broadcast = state.broadcast.clone();
    debug!(
        session_id,
        grace_secs = grace.as_secs(),
        "enqueue_hydration: scheduled"
    );
    tokio::spawn(async move {
        tokio::time::sleep(grace).await;
        let hydrator = RecordingHydrator::new(
            pool,
            supervisor,
            batch_size,
            storage_base,
            missing_meta_grace,
            Some(broadcast),
        );
        match hydrator.hydrate_session_id(session_id).await {
            Ok(report) => {
                if report.scanned == 0 {
                    debug!(
                        session_id,
                        "enqueue_hydration: nothing to do (already finalized or not recorded)"
                    );
                }
            }
            Err(e) => {
                error!(session_id, error = %e, "enqueue_hydration: hydrate_session_id failed");
            }
        }
    })
}

/// Mark a legacy fmp4-flat recording (single `.mp4` file written
/// before the segmentation refactor) as finalized so it stops being
/// a candidate. Sets only `recording_format = 'fmp4-flat'` and
/// `recording_finalized_at`; other integrity columns stay NULL because
/// no `meta.json` was ever produced for this format. The Recording
/// Details page renders "Integrity metadata unavailable for this
/// recording" rather than looping forever.
/// Exposed for tests + the runbook.
pub async fn mark_finalized_legacy_flat(pool: &DbPool, session_id: i32) -> Result<(), String> {
    use crate::schema::proxy_sessions::dsl;
    let mut conn = pool.get().await.map_err(|e| format!("pool: {}", e))?;
    let now: DateTime<Utc> = Utc::now();
    diesel::update(
        dsl::proxy_sessions
            .filter(dsl::id.eq(session_id))
            .filter(dsl::recording_finalized_at.is_null()),
    )
    .set((
        dsl::recording_format.eq(FORMAT_FMP4_FLAT),
        dsl::recording_finalized_at.eq(now),
    ))
    .execute(&mut conn)
    .await
    .map_err(|e| format!("update: {}", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test fixture mirroring the segment shape, for `aggregate_rdp_blake3`.
    struct TestSegment {
        hex: String,
    }

    impl HasSegmentHash for TestSegment {
        fn blake3_hex(&self) -> &str {
            &self.hex
        }
    }

    #[test]
    fn test_is_valid_blake3_hex_accepts_lowercase_64_hex() {
        let s = "0".repeat(64);
        assert!(is_valid_blake3_hex(&s));
        let s2: String = (0..64).map(|i| (b'a' + (i % 6) as u8) as char).collect();
        assert!(is_valid_blake3_hex(&s2));
    }

    #[test]
    fn test_is_valid_blake3_hex_rejects_uppercase() {
        let s = "A".repeat(64);
        assert!(!is_valid_blake3_hex(&s));
    }

    #[test]
    fn test_is_valid_blake3_hex_rejects_wrong_length() {
        assert!(!is_valid_blake3_hex(&"a".repeat(63)));
        assert!(!is_valid_blake3_hex(&"a".repeat(65)));
        assert!(!is_valid_blake3_hex(""));
    }

    #[test]
    fn test_is_valid_blake3_hex_rejects_non_hex_chars() {
        let mut s = "a".repeat(63);
        s.push('z');
        assert!(!is_valid_blake3_hex(&s));
    }

    #[test]
    fn test_meta_relative_for_directory_path() {
        let r = meta_relative_for("recordings", "recordings/2026/04/abc-123/").unwrap();
        assert_eq!(r, "2026/04/abc-123/meta.json");
    }

    #[test]
    fn test_meta_relative_for_directory_path_no_prefix_strip() {
        let r = meta_relative_for("/var/vauban", "recordings/2026/04/abc-123/").unwrap();
        assert_eq!(r, "recordings/2026/04/abc-123/meta.json");
    }

    #[test]
    fn test_meta_relative_for_flat_mp4_returns_none() {
        assert_eq!(
            meta_relative_for("recordings", "recordings/legacy/abc.mp4"),
            None
        );
    }

    #[test]
    fn test_aggregate_rdp_blake3_is_deterministic() {
        let segs = vec![
            TestSegment {
                hex: "11".repeat(32),
            },
            TestSegment {
                hex: "22".repeat(32),
            },
        ];
        let h1 = aggregate_rdp_blake3(&segs);
        let h2 = aggregate_rdp_blake3(&segs);
        assert_eq!(h1, h2);
        assert!(is_valid_blake3_hex(&h1));
    }

    #[test]
    fn test_aggregate_rdp_blake3_is_order_sensitive() {
        let a = vec![
            TestSegment {
                hex: "11".repeat(32),
            },
            TestSegment {
                hex: "22".repeat(32),
            },
        ];
        let b = vec![
            TestSegment {
                hex: "22".repeat(32),
            },
            TestSegment {
                hex: "11".repeat(32),
            },
        ];
        assert_ne!(aggregate_rdp_blake3(&a), aggregate_rdp_blake3(&b));
    }

    #[test]
    fn test_parse_meta_ssh_happy_path() {
        let json = r#"{
            "format": "asciicast-v2",
            "blake3_hex": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "total_bytes": 91234,
            "total_events": 1847,
            "duration_secs": 14.567,
            "width": 132,
            "height": 43
        }"#;
        let bundle = parse_meta(SessionType::Ssh, json).unwrap();
        assert_eq!(bundle.blake3_hex.len(), 64);
        assert_eq!(bundle.size_bytes, 91234);
        assert_eq!(bundle.duration_ms, 14567);
        assert_eq!(bundle.event_count, Some(1847));
        assert_eq!(bundle.format, "asciicast-v2");
        assert_eq!(bundle.width, 132);
        assert_eq!(bundle.height, 43);
        assert_eq!(bundle.segment_count, None);
        assert_eq!(bundle.codec, None);
    }

    #[test]
    fn test_parse_meta_ssh_rejects_uppercase_hash() {
        let json = r#"{
            "blake3_hex": "ABCDEF7890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "total_bytes": 1,
            "total_events": 1,
            "duration_secs": 1.0,
            "width": 80,
            "height": 24
        }"#;
        let r = parse_meta(SessionType::Ssh, json);
        assert!(r.is_err(), "uppercase blake3_hex must be rejected");
    }

    #[test]
    fn test_parse_meta_ssh_rejects_invalid_json() {
        let r = parse_meta(SessionType::Ssh, "{not json");
        assert!(r.is_err());
    }

    #[test]
    fn test_parse_meta_rdp_happy_path() {
        let json = r#"{
            "segments": [
                {
                    "index": 1,
                    "width": 1920,
                    "height": 1080,
                    "duration_ticks": 900000,
                    "init_size": 1024,
                    "file_size": 50000,
                    "blake3_hex": "11111111111111111111111111111111111111111111111111111111111111aa",
                    "codec_string": "avc1.42c01e"
                },
                {
                    "index": 2,
                    "width": 1920,
                    "height": 1080,
                    "duration_ticks": 900000,
                    "init_size": 1024,
                    "file_size": 60000,
                    "blake3_hex": "22222222222222222222222222222222222222222222222222222222222222bb",
                    "codec_string": "avc1.42c01e"
                }
            ]
        }"#;
        let bundle = parse_meta(SessionType::Rdp, json).unwrap();
        assert_eq!(bundle.size_bytes, 110_000);
        // 1_800_000 ticks at 90 kHz = 20s = 20_000ms.
        assert_eq!(bundle.duration_ms, 20_000);
        assert_eq!(bundle.format, "fmp4-dash");
        assert_eq!(bundle.width, 1920);
        assert_eq!(bundle.height, 1080);
        assert_eq!(bundle.segment_count, Some(2));
        assert_eq!(bundle.codec.as_deref(), Some("avc1.42c01e"));
        assert_eq!(bundle.event_count, None);
        assert!(is_valid_blake3_hex(&bundle.blake3_hex));
    }

    #[test]
    fn test_parse_meta_rdp_rejects_empty_segments() {
        let r = parse_meta(SessionType::Rdp, r#"{"segments":[]}"#);
        assert!(r.is_err());
    }

    #[test]
    fn test_parse_meta_rdp_rejects_segment_with_bad_hash() {
        let json = r#"{
            "segments": [{
                "index": 1, "width": 1, "height": 1, "duration_ticks": 1,
                "init_size": 1, "file_size": 1,
                "blake3_hex": "TOOSHORT",
                "codec_string": "avc1.42c01e"
            }]
        }"#;
        assert!(parse_meta(SessionType::Rdp, json).is_err());
    }

    #[test]
    fn test_parse_meta_rdp_geometry_uses_last_segment() {
        let json = r#"{
            "segments": [
                {"index": 1, "width": 800, "height": 600, "duration_ticks": 90000,
                 "init_size": 100, "file_size": 1000,
                 "blake3_hex": "11111111111111111111111111111111111111111111111111111111111111aa",
                 "codec_string": "avc1.42c01e"},
                {"index": 2, "width": 1920, "height": 1080, "duration_ticks": 90000,
                 "init_size": 100, "file_size": 1000,
                 "blake3_hex": "22222222222222222222222222222222222222222222222222222222222222bb",
                 "codec_string": "avc1.640028"}
            ]
        }"#;
        let bundle = parse_meta(SessionType::Rdp, json).unwrap();
        assert_eq!(bundle.width, 1920);
        assert_eq!(bundle.height, 1080);
        // Codec from FIRST segment (stable across the manifest).
        assert_eq!(bundle.codec.as_deref(), Some("avc1.42c01e"));
    }

    #[test]
    fn test_format_constants_match_check_constraint() {
        // Pinned by the migration's recording_format_enum CHECK.
        assert_eq!(FORMAT_ASCIICAST_V2, "asciicast-v2");
        assert_eq!(FORMAT_FMP4_DASH, "fmp4-dash");
        assert_eq!(FORMAT_FMP4_FLAT, "fmp4-flat");
    }

    // ========================================================================
    // WebSocket auto-refresh (issue #29 follow-up): battle-tested layer
    //
    // The hydrator pushes a `recording_hydrated` WS notification on every
    // state transition the Recording Details / List pages care about. The
    // tests below pin BOTH the runtime behaviour (a real subscriber sees a
    // well-formed payload) AND the static call-graph (every transition
    // site fires the broadcast; error branches do NOT).
    // ========================================================================

    #[tokio::test]
    async fn broadcast_recording_hydrated_with_none_is_a_silent_noop() {
        // The CLI / offline batch contexts pass `None` and MUST NOT
        // panic, log at error level, or block. The function is a
        // straight-line return when broadcast is `None`.
        let uuid = ::uuid::Uuid::new_v4();
        broadcast_recording_hydrated(&None, &uuid).await;
    }

    #[tokio::test]
    async fn broadcast_recording_hydrated_emits_on_notifications_channel() {
        let svc = BroadcastService::new();
        let mut rx = svc.subscribe(&WsChannel::Notifications).await;
        let uuid = ::uuid::Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        broadcast_recording_hydrated(&Some(svc.clone()), &uuid).await;
        let payload = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .expect("WS message must arrive within 200ms")
            .expect("subscriber must not be closed");
        // OOB-formatted HTML envelope (BroadcastService::to_htmx_html).
        assert!(
            payload.contains(r#"id="jit-notification""#),
            "must use the global jit-notification OOB target so it \
             rides the existing /ws/notifications relay (no new socket)"
        );
        assert!(payload.contains("hx-swap-oob"), "must be an OOB swap");
        // Body contract: filterable by the templates' indexOf checks.
        assert!(
            payload.contains(r#""type":"recording_hydrated""#),
            "payload MUST carry the 'recording_hydrated' kind so the \
             template's indexOf filter matches"
        );
        assert!(
            payload.contains("11111111-2222-3333-4444-555555555555"),
            "payload MUST embed the session_uuid so per-page filters \
             can ignore unrelated hydration events"
        );
    }

    #[tokio::test]
    async fn broadcast_recording_hydrated_payload_carries_no_pii() {
        // Anti-leak guard: only the (opaque) session_uuid travels on the
        // global Notifications channel. Any future change adding e.g.
        // requester_username, asset_name, or hostname to the payload
        // MUST trip this test and force a deliberate review.
        let svc = BroadcastService::new();
        let mut rx = svc.subscribe(&WsChannel::Notifications).await;
        let uuid = ::uuid::Uuid::nil();
        broadcast_recording_hydrated(&Some(svc.clone()), &uuid).await;
        let payload = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .unwrap()
            .unwrap();
        // Whitelist of permitted JSON keys. Anything else is a leak.
        for key in &[
            "username",
            "user_id",
            "email",
            "asset_name",
            "hostname",
            "ip",
            "address",
            "credential",
        ] {
            assert!(
                !payload.contains(key),
                "WS hydration payload must not carry `{}` -- only the \
                 opaque session_uuid is allowed",
                key
            );
        }
    }

    /// Source-grep helper: returns the body of a function that starts
    /// at `signature`, balanced on `{`/`}` from the first `{` after
    /// the signature. Brace-counter (not regex) so nested blocks
    /// (match arms, `async move {}`, etc.) do not truncate the body.
    fn fn_body(source: &str, signature: &str) -> String {
        let start = source
            .find(signature)
            .unwrap_or_else(|| panic!("signature `{}` not found in source", signature));
        let tail = &source[start..];
        let open = tail
            .find('{')
            .unwrap_or_else(|| panic!("no `{{` after signature `{}`", signature));
        let mut depth: i32 = 0;
        let mut end = tail.len();
        for (i, ch) in tail[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        tail[..end].to_string()
    }

    /// Return the line immediately preceding the first occurrence of
    /// `needle` after `from`, trimmed. Used to assert the line ABOVE
    /// `broadcast_recording_hydrated(...)` increments a success
    /// counter (and never an error one).
    fn line_before(body: &str, from: usize, needle: &str) -> String {
        let idx = body[from..]
            .find(needle)
            .map(|i| from + i)
            .unwrap_or_else(|| panic!("`{}` not found from offset {}", needle, from));
        let prefix = &body[..idx];
        let line_end = prefix
            .rfind('\n')
            .unwrap_or_else(|| panic!("no newline before `{}`", needle));
        let line_start = prefix[..line_end].rfind('\n').map(|i| i + 1).unwrap_or(0);
        prefix[line_start..line_end].trim().to_string()
    }

    /// `tick()` MUST fire the broadcast on every Ok transition (4
    /// branches: legacy-flat, persist_bundle, missing-meta past grace,
    /// corrupt-meta) and MUST NOT fire it on the Err branches. A
    /// regression here would silently break the Recording Details
    /// auto-refresh.
    #[test]
    fn tick_broadcasts_after_every_finalization_transition() {
        let src = include_str!("recording_hydrator.rs");
        let body = fn_body(src, "    pub async fn tick(");
        let count = body.matches("broadcast_recording_hydrated(").count();
        assert_eq!(
            count, 4,
            "tick() must broadcast on EXACTLY 4 transitions: legacy-flat, \
             persist_bundle, missing-meta past grace, corrupt-meta. \
             Found {} occurrences -- adjust the call sites or this pin.",
            count
        );
        // For each broadcast call, the IMMEDIATELY preceding line
        // must increment a success counter -- NEVER `report.errored`.
        // The `if let Err(e) = persist_bundle(...).await { ... } else
        // { ... broadcast ... }` shape places the success branch at
        // the right depth so this one-line window is unambiguous.
        let mut cursor = 0usize;
        let mut visited = 0usize;
        while let Some(found) = body[cursor..].find("broadcast_recording_hydrated(") {
            let prev = line_before(&body, cursor, "broadcast_recording_hydrated(");
            assert!(
                prev.starts_with("report.") && prev.contains("+= 1;"),
                "tick() broadcast call #{} must follow a `report.<success> \
                 += 1;` line; found: `{}`",
                visited + 1,
                prev
            );
            assert!(
                !prev.contains("errored"),
                "tick() must NOT broadcast in an error branch (a broken \
                 transition would lie to the page); found: `{}`",
                prev
            );
            cursor += found + "broadcast_recording_hydrated(".len();
            visited += 1;
        }
        assert_eq!(visited, 4);
    }

    /// Same contract for the single-shot `hydrate_session_id` path.
    #[test]
    fn hydrate_session_id_broadcasts_after_every_finalization_transition() {
        let src = include_str!("recording_hydrator.rs");
        let body = fn_body(src, "pub async fn hydrate_session_id(");
        let count = body.matches("broadcast_recording_hydrated(").count();
        assert_eq!(
            count, 4,
            "hydrate_session_id() must broadcast on EXACTLY 4 transitions \
             to mirror tick(). Found {}.",
            count
        );
        let mut cursor = 0usize;
        let mut visited = 0usize;
        while let Some(found) = body[cursor..].find("broadcast_recording_hydrated(") {
            let prev = line_before(&body, cursor, "broadcast_recording_hydrated(");
            assert!(
                prev.starts_with("report.") && prev.contains("+= 1;"),
                "hydrate_session_id() broadcast call #{} must follow a \
                 `report.<success> += 1;` line; found: `{}`",
                visited + 1,
                prev
            );
            assert!(
                !prev.contains("errored"),
                "hydrate_session_id() must NOT broadcast in an error branch; \
                 found: `{}`",
                prev
            );
            cursor += found + "broadcast_recording_hydrated(".len();
            visited += 1;
        }
        assert_eq!(visited, 4);
    }

    /// Both PRIMARY enqueue paths MUST plumb the live `state.broadcast`
    /// into the hydrator. Without this, an in-process hydration would
    /// finalize the row but the page would not auto-refresh -- defeats
    /// the entire feature.
    #[test]
    fn enqueue_hydration_passes_live_broadcast_to_constructor() {
        let src = include_str!("recording_hydrator.rs");
        for sig in [
            "pub fn enqueue_hydration(",
            "pub fn enqueue_hydration_by_uuid(",
        ] {
            let body = fn_body(src, sig);
            assert!(
                body.contains("state.broadcast.clone()"),
                "{}: must clone state.broadcast before the spawn",
                sig
            );
            assert!(
                body.contains("Some(broadcast)"),
                "{}: must pass `Some(broadcast)` to RecordingHydrator::new \
                 so the in-process hydration can fire WS notifications",
                sig
            );
        }
    }

    /// Pin: the constructor signature accepts the broadcast as the
    /// LAST parameter (not Option-defaulted). A regression that
    /// silently dropped the parameter would skip every WS push.
    #[test]
    fn constructor_signature_carries_broadcast_param() {
        let src = include_str!("recording_hydrator.rs");
        assert!(
            src.contains("broadcast: Option<BroadcastService>,"),
            "RecordingHydrator::new must accept `broadcast: \
             Option<BroadcastService>` as a parameter (not a setter, \
             not derived from another field)"
        );
        assert!(
            src.contains("broadcast: Option<BroadcastService>,\n}"),
            "RecordingHydrator must STORE the broadcast handle as the \
             last field; otherwise the call sites cannot reach it"
        );
    }

    /// Pin: the broadcast helper itself uses the agreed-upon
    /// `Notifications` channel + `jit-notification` OOB target +
    /// stable JSON shape. Changing any of these three would silently
    /// break the page filters that read `detail.message.indexOf(...)`.
    #[test]
    fn broadcast_helper_uses_stable_wire_contract() {
        let src = include_str!("recording_hydrator.rs");
        let body = fn_body(src, "async fn broadcast_recording_hydrated(");
        assert!(
            body.contains("WsChannel::Notifications"),
            "must use the global Notifications channel (the same one \
             /ws/notifications relays to every authenticated user)"
        );
        assert!(
            body.contains(r#""jit-notification""#),
            "must keep the OOB target id `jit-notification` so the \
             existing relay swallows the swap and emits \
             `htmx:wsAfterMessage`"
        );
        assert!(
            body.contains(r#""type":"recording_hydrated""#),
            "JSON payload MUST embed `\"type\":\"recording_hydrated\"` \
             verbatim -- the page filter is a substring match"
        );
        assert!(
            body.contains(r#""session_uuid":"{}"#),
            "JSON payload MUST embed the session_uuid so per-page \
             filters can ignore unrelated hydration events"
        );
    }
}
