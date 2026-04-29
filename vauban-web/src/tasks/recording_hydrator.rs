//! VAUBAN Web - Recording integrity hydrator scheduler.
//!
//! Background ticker (issue #29 / UX-28) that scans `proxy_sessions`
//! for finalized recordings whose integrity bundle has not yet been
//! precomputed and populates the columns from the on-disk
//! `meta.json`.
//!
//! Conventions (matching `tasks::cleanup` and `tasks::dashboard`):
//! - Delegates to `shared::tasks::spawn_periodic` so every Vauban
//!   ticker shares the same lifecycle (named tracing, skip-first-tick,
//!   Handle-based spawn, errors swallowed inside the closure so the
//!   loop never aborts).
//! - The pure pipeline (parse_meta, aggregate_rdp_blake3, persist
//!   helpers, the `RecordingHydrator` struct) lives in
//!   [`crate::services::recording_hydrator`]; this module is purely
//!   the scheduling thin wrapper.
//!
//! Configuration: gated by `config.recording.hydration_enabled` and
//! parameterised by `hydration_interval_secs`,
//! `hydration_batch_size`, `hydration_missing_meta_grace_secs`. See
//! [`crate::config::RecordingConfig`] and the runbook
//! `docs/runbooks/recording_hydrator.md`.

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info};

use crate::db::DbPool;
use crate::ipc::SupervisorClient;
use crate::services::recording_hydrator::{RecordingHydrator, TASK_NAME};

/// Start the recording integrity hydrator on the supplied runtime
/// handle. Symmetrical with [`crate::tasks::cleanup::start_cleanup_tasks`]
/// and [`crate::tasks::dashboard::start_dashboard_tasks`].
///
/// `handle` MUST be a live tokio runtime handle (typically
/// `tokio::runtime::Handle::current()` from inside `#[tokio::main]`).
///
/// Returns immediately; the actual loop runs in the background.
pub async fn start_recording_hydrator(
    handle: tokio::runtime::Handle,
    db_pool: DbPool,
    supervisor: Arc<SupervisorClient>,
    interval: Duration,
    batch_size: i64,
    storage_base: String,
    missing_meta_grace: Duration,
) {
    let hydrator = Arc::new(RecordingHydrator::new(
        db_pool,
        supervisor,
        batch_size,
        storage_base,
        missing_meta_grace,
    ));

    info!(
        interval_secs = interval.as_secs(),
        batch_size,
        grace_secs = missing_meta_grace.as_secs(),
        "Recording hydrator background task started"
    );

    shared::tasks::spawn_periodic(&handle, TASK_NAME, interval, move || {
        let hydrator = Arc::clone(&hydrator);
        async move {
            match hydrator.tick().await {
                Ok(report) if report.scanned > 0 => {
                    info!(
                        scanned = report.scanned,
                        finalized = report.finalized,
                        skipped = report.skipped_missing_meta,
                        legacy_flat = report.marked_finalized_legacy_flat,
                        lost = report.marked_finalized_lost,
                        corrupt = report.marked_finalized_corrupt,
                        errored = report.errored,
                        "recording hydrator tick"
                    );
                }
                Ok(_) => {
                    debug!("recording hydrator tick: no candidates");
                }
                Err(e) => {
                    // Swallow inside the closure so the periodic
                    // loop never aborts (per shared::tasks contract).
                    error!(error = %e, "recording hydrator tick failed");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    /// The hydrator scheduler MUST live in the `tasks/` module like
    /// `cleanup` and `dashboard`, and it MUST delegate to
    /// `shared::tasks::spawn_periodic` (no bare `tokio::spawn` loop).
    /// This pins both invariants at the source level so a regression
    /// to `services/recording_hydrator.rs::spawn` (the original
    /// artisanal pattern) cannot silently reappear.
    #[test]
    fn test_start_recording_hydrator_delegates_to_shared_periodic() {
        let source = include_str!("recording_hydrator.rs");
        assert!(
            source.contains("pub async fn start_recording_hydrator("),
            "scheduler entrypoint must be `start_recording_hydrator` (mirrors start_cleanup_tasks)"
        );
        assert!(
            source.contains("shared::tasks::spawn_periodic"),
            "scheduler must delegate to shared::tasks::spawn_periodic"
        );
        // The body must NOT spin its own `tokio::spawn { loop { ... } }`
        // (the original anti-pattern that bypassed the shared scheduler).
        // Bound the slice to the function body (stops at `#[cfg(test)]`
        // so the regex/inspection of this very test does not match).
        let start_idx = source
            .find("pub async fn start_recording_hydrator(")
            .expect("entrypoint exists");
        let body = &source[start_idx..];
        let body_end = body
            .find("#[cfg(test)]")
            .expect("test module marks the end of production code");
        let body = &body[..body_end];
        assert!(
            !body.contains("tokio::spawn("),
            "scheduler must not bypass shared::tasks with a bare tokio::spawn"
        );
    }
}
