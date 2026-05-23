//! VAUBAN Web - Recording integrity hydrator scheduler.
//!
//! Background orchestration (issue #29 / UX-28 v1.4) for the
//! recording integrity bundle. The scheduler is event-driven:
//!
//! ```text
//! PRIMARY:   session ends -> enqueue_hydration -> sleep 5s -> finalize
//! BOOTSTRAP: vauban-web boot -> one-shot scan -> finalize all backlog
//! SAFETY:    daily cron at configured local hour -> bootstrap re-run
//! ```
//!
//! There is intentionally **no periodic 30s ticker**. The PRIMARY
//! path covers nominal operation with ~5 s latency between session
//! end and integrity persistence. The BOOTSTRAP rattrape any backlog
//! left over by a downtime or by legacy recordings produced before
//! the integrity columns existed. The SAFETY cron re-runs the
//! bootstrap once a day to mop up events lost to crashes between
//! `UPDATE disconnected_at` and `tokio::spawn(enqueue)`.
//!
//! See `docs/technical/Vauban_Recording_Architecture_EN(1.3).md`
//! for the full design and `docs/runbooks/recording_hydrator.md`
//! for diagnostics + recovery procedures.
//!
//! Conventions (matching `tasks::cleanup` and `tasks::dashboard`):
//! - The daily reconciliation delegates to
//!   `shared::tasks::spawn_periodic` so every Vauban ticker shares
//!   the same lifecycle (named tracing, skip-first-tick, errors
//!   swallowed inside the closure so the loop never aborts).
//! - The pure pipeline (`tick`, `hydrate_session_id`,
//!   `parse_meta`, persistence helpers, `RecordingHydrator`)
//!   lives in [`crate::services::recording_hydrator`].
//! - Per-call-site PRIMARY enqueue lives in
//!   [`crate::services::recording_hydrator::enqueue_hydration`].
//!
//! Configuration: gated by `config.recording.hydration_enabled` and
//! parameterised by `hydration_batch_size`,
//! `hydration_missing_meta_grace_secs`,
//! `hydration_enqueue_delay_secs`, and
//! `recording_daily_cron_timezone`, `hydration_daily_cron_hour`. See
//! [`crate::config::RecordingConfig`].

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use chrono_tz::Tz;
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::db::DbPool;
use crate::ipc::SupervisorClient;
use crate::services::broadcast::BroadcastService;
use crate::services::recording_hydrator::{RecordingHydrator, TASK_NAME};
use crate::tasks::daily_cron::next_cron_instant;

/// One-shot bootstrap hydration. Scans `proxy_sessions` for any
/// `recording_finalized_at IS NULL` rows, hydrates them in batches
/// of `batch_size`, and exits when the candidate index is empty.
/// Reused by [`start_daily_reconciliation`] for the SAFETY cron.
///
/// `handle` MUST be a live tokio runtime handle (typically
/// `tokio::runtime::Handle::current()` from inside `#[tokio::main]`).
///
/// `broadcast` is the WebSocket relay used to push `recording_hydrated`
/// notifications to live page sessions; pass the same handle as
/// `AppState::broadcast` so the Recording Details / List pages auto-
/// refresh once the bootstrap finalises a row (issue #29 follow-up).
///
/// Spawns a detached task and returns its `JoinHandle`. The boot
/// path normally drops the handle (fire-and-forget); tests await it
/// to assert end-of-bootstrap state.
#[allow(clippy::too_many_arguments)]
pub fn run_bootstrap_hydration(
    handle: &tokio::runtime::Handle,
    db_pool: DbPool,
    supervisor: Arc<SupervisorClient>,
    batch_size: i64,
    storage_base: String,
    missing_meta_grace: Duration,
    broadcast: BroadcastService,
) -> JoinHandle<()> {
    handle.spawn(async move {
        let started = std::time::Instant::now();
        let hydrator = RecordingHydrator::new(
            db_pool,
            supervisor,
            batch_size,
            storage_base,
            missing_meta_grace,
            Some(broadcast),
        );
        let mut total_finalized = 0usize;
        let mut total_skipped_missing_meta = 0usize;
        let mut total_marked_lost = 0usize;
        let mut total_marked_legacy_flat = 0usize;
        let mut total_marked_corrupt = 0usize;
        let mut total_errored = 0usize;
        let mut passes = 0u32;
        info!(task = TASK_NAME, "bootstrap_started");
        loop {
            passes += 1;
            match hydrator.tick().await {
                Ok(report) => {
                    total_finalized += report.finalized;
                    total_skipped_missing_meta += report.skipped_missing_meta;
                    total_marked_lost += report.marked_finalized_lost;
                    total_marked_legacy_flat += report.marked_finalized_legacy_flat;
                    total_marked_corrupt += report.marked_finalized_corrupt;
                    total_errored += report.errored;
                    // Bootstrap completion criterion: a tick that
                    // makes no progress AND has no transient
                    // missing-meta retries pending. The
                    // `skipped_missing_meta` rows would loop forever
                    // here if we required `scanned == 0`; they will
                    // be rattrape'd by the daily cron once their
                    // grace period expires.
                    if report.scanned == 0 || report.scanned == report.skipped_missing_meta {
                        break;
                    }
                }
                Err(e) => {
                    error!(
                        task = TASK_NAME,
                        error = %e,
                        "bootstrap tick failed; aborting bootstrap, daily cron will retry"
                    );
                    total_errored += 1;
                    break;
                }
            }
        }
        info!(
            task = TASK_NAME,
            passes,
            finalized = total_finalized,
            skipped_missing_meta = total_skipped_missing_meta,
            marked_lost = total_marked_lost,
            marked_legacy_flat = total_marked_legacy_flat,
            marked_corrupt = total_marked_corrupt,
            errored = total_errored,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "bootstrap_complete"
        );
    })
}

/// Schedule the daily reconciliation cron. Sleeps until the next
/// `cron_hour:00` in `cron_tz`, then runs `run_bootstrap_hydration` once a
/// day via `shared::tasks::spawn_periodic` (period = 86 400 s).
///
/// This is a SAFETY NET, not the primary finalization path. In
/// nominal operation it logs `bootstrap_complete { finalized=0 }`
/// and exits in milliseconds. The three cases where it actually
/// does work are:
///   1. vauban-web crashed between `UPDATE disconnected_at` and
///      `tokio::spawn(enqueue_hydration)`.
///   2. A new call-site for `disconnected_at` was added without an
///      adjacent `enqueue_hydration` (in theory caught by source-
///      level CI pins).
///   3. vauban-audit flushed `meta.json` with a delay greater than
///      `hydration_enqueue_delay_secs` so the PRIMARY enqueue
///      saw `MissingMeta`.
///
/// `handle` is forwarded to `spawn_periodic` (Handle-based spawn).
#[allow(clippy::too_many_arguments)]
pub fn start_daily_reconciliation(
    handle: tokio::runtime::Handle,
    db_pool: DbPool,
    supervisor: Arc<SupervisorClient>,
    batch_size: i64,
    storage_base: String,
    missing_meta_grace: Duration,
    cron_tz: Tz,
    cron_hour: u8,
    broadcast: BroadcastService,
) {
    let now = Utc::now();
    let delay = next_cron_instant(now, cron_tz, cron_hour);
    info!(
        task = TASK_NAME,
        cron_tz = cron_tz.name(),
        cron_hour,
        delay_secs = delay.as_secs(),
        "daily_reconciliation scheduled at next {:02}:00 {}",
        cron_hour,
        cron_tz.name()
    );
    let handle_for_spawn = handle.clone();
    handle.spawn(async move {
        // Sleep until the first cron firing window.
        tokio::time::sleep(delay).await;
        // Run an immediate first reconciliation, then delegate
        // subsequent firings to spawn_periodic on a 24h cadence.
        let _ = run_bootstrap_hydration(
            &handle_for_spawn,
            db_pool.clone(),
            Arc::clone(&supervisor),
            batch_size,
            storage_base.clone(),
            missing_meta_grace,
            broadcast.clone(),
        )
        .await;
        let pool = db_pool;
        let sup = supervisor;
        let base = storage_base;
        let bcast = broadcast;
        let h_for_periodic = handle_for_spawn.clone();
        shared::tasks::spawn_periodic(
            &handle_for_spawn,
            TASK_NAME,
            Duration::from_secs(86_400),
            move || {
                let pool = pool.clone();
                let sup = Arc::clone(&sup);
                let base = base.clone();
                let bcast = bcast.clone();
                let h = h_for_periodic.clone();
                async move {
                    let _ = run_bootstrap_hydration(
                        &h,
                        pool,
                        sup,
                        batch_size,
                        base,
                        missing_meta_grace,
                        bcast,
                    )
                    .await;
                }
            },
        );
    });
}

#[cfg(test)]
mod tests {
    /// Source-level pin restricted to the non-test portion of the
    /// file so the assertion strings below cannot match themselves.
    fn non_test_source() -> String {
        let full = include_str!("recording_hydrator.rs");
        match full.find("\n#[cfg(test)]") {
            Some(end) => full[..end].to_string(),
            None => full.to_string(),
        }
    }

    /// The PRIMARY/BOOTSTRAP/SAFETY split MUST live in `tasks/`,
    /// not in `services/`. Pinned at the source level so a
    /// regression that re-introduces a 30s ticker (the original
    /// design) cannot silently land.
    #[test]
    fn test_no_30s_ticker_in_recording_hydrator() {
        let source = non_test_source();
        // No `start_recording_hydrator` (the v1.3 ticker entrypoint).
        // We build the banned strings dynamically so this assertion
        // does not match its own source via include_str!.
        let banned1 = format!("pub fn {}(", "start_recording_hydrator");
        let banned2 = format!("pub async fn {}(", "start_recording_hydrator");
        assert!(
            !source.contains(&banned1) && !source.contains(&banned2),
            "v1.4 removes the 30s ticker; the v1.3 entrypoint must not be re-introduced"
        );
        // The only periodic ticker MUST be the 86 400s daily cron.
        assert!(
            source.contains("Duration::from_secs(86_400)")
                || source.contains("Duration::from_secs(86400)"),
            "the daily reconciliation cron MUST tick every 86400s; a different cadence is a regression"
        );
        // Defensive: no other `spawn_periodic` with a small period
        // must creep in.
        assert!(
            !source.contains("Duration::from_secs(30)"),
            "no 30-second ticker must exist in tasks/recording_hydrator.rs (v1.4 is event-driven)"
        );
    }

    #[test]
    fn test_run_bootstrap_hydration_signature() {
        let source = non_test_source();
        assert!(
            source.contains("pub fn run_bootstrap_hydration("),
            "bootstrap entrypoint must be `run_bootstrap_hydration` (one-shot, not a ticker)"
        );
    }

    #[test]
    fn test_start_daily_reconciliation_uses_shared_periodic() {
        let source = non_test_source();
        assert!(
            source.contains("pub fn start_daily_reconciliation("),
            "cron entrypoint must be `start_daily_reconciliation` (mirrors start_cleanup_tasks naming)"
        );
        assert!(
            source.contains("shared::tasks::spawn_periodic"),
            "daily reconciliation must delegate to shared::tasks::spawn_periodic for uniform lifecycle"
        );
        assert!(
            source.contains("daily_cron::next_cron_instant"),
            "daily reconciliation must use timezone-aware daily_cron::next_cron_instant"
        );
    }
}
