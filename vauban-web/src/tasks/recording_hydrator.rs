//! VAUBAN Web - Recording integrity hydrator scheduler.
//!
//! Background orchestration (issue #29 / UX-28 v1.4) for the
//! recording integrity bundle. The scheduler is event-driven:
//!
//! ```text
//! PRIMARY:   session ends -> enqueue_hydration -> sleep 5s -> finalize
//! BOOTSTRAP: vauban-web boot -> one-shot scan -> finalize all backlog
//! SAFETY:    daily cron at 04:00 UTC -> bootstrap re-run
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
//! `hydration_daily_cron_hour_utc`. See
//! [`crate::config::RecordingConfig`].

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::db::DbPool;
use crate::ipc::SupervisorClient;
use crate::services::recording_hydrator::{RecordingHydrator, TASK_NAME};

/// One-shot bootstrap hydration. Scans `proxy_sessions` for any
/// `recording_finalized_at IS NULL` rows, hydrates them in batches
/// of `batch_size`, and exits when the candidate index is empty.
/// Reused by [`start_daily_reconciliation`] for the SAFETY cron.
///
/// `handle` MUST be a live tokio runtime handle (typically
/// `tokio::runtime::Handle::current()` from inside `#[tokio::main]`).
///
/// Spawns a detached task and returns its `JoinHandle`. The boot
/// path normally drops the handle (fire-and-forget); tests await it
/// to assert end-of-bootstrap state.
pub fn run_bootstrap_hydration(
    handle: &tokio::runtime::Handle,
    db_pool: DbPool,
    supervisor: Arc<SupervisorClient>,
    batch_size: i64,
    storage_base: String,
    missing_meta_grace: Duration,
) -> JoinHandle<()> {
    handle.spawn(async move {
        let started = std::time::Instant::now();
        let hydrator = RecordingHydrator::new(
            db_pool,
            supervisor,
            batch_size,
            storage_base,
            missing_meta_grace,
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
/// `hour_utc:00` UTC, then runs `run_bootstrap_hydration` once a
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
pub fn start_daily_reconciliation(
    handle: tokio::runtime::Handle,
    db_pool: DbPool,
    supervisor: Arc<SupervisorClient>,
    batch_size: i64,
    storage_base: String,
    missing_meta_grace: Duration,
    hour_utc: u8,
) {
    let now = Utc::now();
    let delay = next_cron_instant_utc(now, hour_utc);
    info!(
        task = TASK_NAME,
        hour_utc,
        delay_secs = delay.as_secs(),
        "daily_reconciliation scheduled at next {:02}:00 UTC",
        hour_utc
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
        )
        .await;
        let pool = db_pool;
        let sup = supervisor;
        let base = storage_base;
        let h_for_periodic = handle_for_spawn.clone();
        shared::tasks::spawn_periodic(
            &handle_for_spawn,
            TASK_NAME,
            Duration::from_secs(86_400),
            move || {
                let pool = pool.clone();
                let sup = Arc::clone(&sup);
                let base = base.clone();
                let h = h_for_periodic.clone();
                async move {
                    let _ = run_bootstrap_hydration(
                        &h,
                        pool,
                        sup,
                        batch_size,
                        base,
                        missing_meta_grace,
                    )
                    .await;
                }
            },
        );
    });
}

/// Compute the duration between `now` and the next `hour_utc:00:00`
/// UTC instant. Used to align the daily reconciliation cron with a
/// stable wall-clock anchor (e.g. 04:00 UTC). Pure function for
/// unit-testability.
///
/// Examples (with `hour_utc = 4`):
///   - `now = 10:00 UTC` -> `+18h`
///   - `now = 02:00 UTC` -> `+2h`
///   - `now = 04:00:01 UTC` -> `+23h59m59s` (wrap to next day)
pub fn next_cron_instant_utc(now: DateTime<Utc>, hour_utc: u8) -> Duration {
    let target_today = match Utc
        .with_ymd_and_hms(now.year(), now.month(), now.day(), hour_utc as u32, 0, 0)
        .single()
    {
        Some(t) => t,
        None => {
            // Out-of-range hour or ambiguous local time. The boot-time
            // `RecordingConfig::validate` rejects out-of-range hours,
            // so this branch is unreachable in practice. Defensive
            // fallback: schedule the cron 24h in the future.
            return Duration::from_secs(24 * 3600);
        }
    };
    let target = if target_today > now {
        target_today
    } else {
        target_today + chrono::Duration::days(1)
    };
    let delta = target - now;
    Duration::from_secs(delta.num_seconds().max(0) as u64)
}

// `chrono::Datelike` adds `.year()/.month()/.day()` used above by
// `with_ymd_and_hms` to anchor the cron at the start of the
// configured UTC hour.
use chrono::Datelike as _;

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[test]
    fn test_next_cron_instant_utc_now_before_target() {
        // 10:00 UTC, target 04:00 -> next day 04:00 = +18h
        let now = Utc.with_ymd_and_hms(2026, 4, 30, 10, 0, 0).unwrap();
        let d = next_cron_instant_utc(now, 4);
        assert_eq!(d.as_secs(), 18 * 3600);
    }

    #[test]
    fn test_next_cron_instant_utc_now_after_target() {
        // 02:00 UTC, target 04:00 same day -> +2h
        let now = Utc.with_ymd_and_hms(2026, 4, 30, 2, 0, 0).unwrap();
        let d = next_cron_instant_utc(now, 4);
        assert_eq!(d.as_secs(), 2 * 3600);
    }

    #[test]
    fn test_next_cron_instant_utc_just_past_target() {
        // 04:00:01 UTC, target 04:00 -> wrap to next day = ~24h - 1s
        let now = Utc.with_ymd_and_hms(2026, 4, 30, 4, 0, 1).unwrap();
        let d = next_cron_instant_utc(now, 4);
        assert_eq!(d.as_secs(), 24 * 3600 - 1);
    }

    #[test]
    fn test_next_cron_instant_utc_exactly_at_target_wraps() {
        // 04:00:00 UTC, target 04:00 -> we MUST wrap to next day,
        // not fire immediately (otherwise the cron double-fires).
        let now = Utc.with_ymd_and_hms(2026, 4, 30, 4, 0, 0).unwrap();
        let d = next_cron_instant_utc(now, 4);
        assert_eq!(d.as_secs(), 24 * 3600);
    }

    #[test]
    fn test_next_cron_instant_utc_handles_midnight() {
        let now = Utc.with_ymd_and_hms(2026, 4, 30, 23, 30, 0).unwrap();
        let d = next_cron_instant_utc(now, 0);
        // 23:30 -> next 00:00 = +30 min
        assert_eq!(d.as_secs(), 30 * 60);
    }
}
