//! VAUBAN Web - Recording retention reaper scheduler.
//!
//! Background orchestration for recording purge (TOML-only config):
//!
//! ```text
//! BOOTSTRAP: vauban-web boot -> one-shot scan -> delete aged / quota backlog
//! SAFETY:    daily cron at configured local hour -> bootstrap re-run
//! ```
//!
//! See `docs/runbooks/recording_retention.md` and
//! `docs/technical/Vauban_Recording_Architecture_EN(1.3).md`.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use chrono_tz::Tz;
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::db::DbPool;
use crate::ipc::SupervisorClient;
use crate::services::recording_reaper::{RecordingReaper, TASK_NAME};
use crate::tasks::daily_cron::next_cron_instant;

/// Parameters for the retention bootstrap / daily cron (from `[recording]` TOML).
#[derive(Clone)]
pub struct RecordingRetentionTaskConfig {
    pub retention_days: u32,
    pub max_size_gib: u64,
    pub batch_size: i64,
    pub storage_base: String,
    pub cron_tz: Tz,
    pub cron_hour: u8,
}

/// One-shot bootstrap retention. Loops `RecordingReaper::tick` in batches
/// until no aged or quota candidates remain. Reused by
/// [`start_recording_retention`] for the daily SAFETY cron.
///
/// Spawns a detached task and returns its `JoinHandle`. The boot path
/// normally drops the handle (fire-and-forget); tests await it to assert
/// end-of-bootstrap state.
pub fn run_bootstrap_retention(
    handle: &tokio::runtime::Handle,
    db_pool: DbPool,
    supervisor: Arc<SupervisorClient>,
    config: RecordingRetentionTaskConfig,
) -> JoinHandle<()> {
    handle.spawn(async move {
        let started = std::time::Instant::now();
        let RecordingRetentionTaskConfig {
            retention_days,
            max_size_gib,
            batch_size,
            storage_base,
            cron_tz: _,
            cron_hour: _,
        } = config;
        let reaper = RecordingReaper::new(
            db_pool,
            supervisor,
            retention_days,
            max_size_gib,
            batch_size,
            storage_base,
        );
        let mut total_age = 0usize;
        let mut total_quota = 0usize;
        let mut total_bytes = 0u64;
        let mut total_errors = 0usize;
        let mut passes = 0u32;
        info!(task = TASK_NAME, "bootstrap_started");
        loop {
            passes += 1;
            match reaper.tick().await {
                Ok(report) => {
                    total_age += report.age_reaped;
                    total_quota += report.quota_reaped;
                    total_bytes = total_bytes.saturating_add(report.bytes_freed);
                    total_errors += report.errors;
                    if report.age_reaped == 0 && report.quota_reaped == 0 {
                        break;
                    }
                }
                Err(e) => {
                    error!(
                        task = TASK_NAME,
                        error = %e,
                        "bootstrap tick failed; aborting bootstrap, daily cron will retry"
                    );
                    total_errors += 1;
                    break;
                }
            }
        }
        info!(
            task = TASK_NAME,
            passes,
            age_reaped = total_age,
            quota_reaped = total_quota,
            bytes_freed = total_bytes,
            errors = total_errors,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "bootstrap_complete"
        );
    })
}

/// Schedule the daily retention cron. Sleeps until the next `cron_hour:00`
/// in `cron_tz`, then runs [`run_bootstrap_retention`] once a day via
/// `shared::tasks::spawn_periodic` (period = 86 400 s).
///
/// This is a SAFETY NET complementing the boot bootstrap. In nominal
/// operation it logs `bootstrap_complete { age_reaped=0, quota_reaped=0 }`
/// and exits in milliseconds.
pub fn start_recording_retention(
    handle: tokio::runtime::Handle,
    db_pool: DbPool,
    supervisor: Arc<SupervisorClient>,
    config: RecordingRetentionTaskConfig,
) {
    let cron_tz = config.cron_tz;
    let cron_hour = config.cron_hour;
    let now = Utc::now();
    let delay = next_cron_instant(now, cron_tz, cron_hour);
    info!(
        task = TASK_NAME,
        cron_tz = cron_tz.name(),
        cron_hour,
        delay_secs = delay.as_secs(),
        retention_days = config.retention_days,
        max_size_gib = config.max_size_gib,
        "recording retention scheduled at next {:02}:00 {}",
        cron_hour,
        cron_tz.name()
    );

    let handle_for_spawn = handle.clone();
    handle.spawn(async move {
        tokio::time::sleep(delay).await;
        let _ = run_bootstrap_retention(
            &handle_for_spawn,
            db_pool.clone(),
            Arc::clone(&supervisor),
            config.clone(),
        )
        .await;

        let pool = db_pool;
        let sup = supervisor;
        let cfg = config;
        let h_for_periodic = handle_for_spawn.clone();
        shared::tasks::spawn_periodic(
            &handle_for_spawn,
            TASK_NAME,
            Duration::from_secs(86_400),
            move || {
                let pool = pool.clone();
                let sup = Arc::clone(&sup);
                let cfg = cfg.clone();
                let h = h_for_periodic.clone();
                async move {
                    let _ = run_bootstrap_retention(&h, pool, sup, cfg).await;
                }
            },
        );
    });
}

#[cfg(test)]
mod tests {
    fn non_test_source() -> String {
        let full = include_str!("recording_reaper.rs");
        match full.find("\n#[cfg(test)]") {
            Some(end) => full[..end].to_string(),
            None => full.to_string(),
        }
    }

    #[test]
    fn run_bootstrap_retention_signature() {
        let source = non_test_source();
        assert!(
            source.contains("pub fn run_bootstrap_retention("),
            "bootstrap entrypoint must be `run_bootstrap_retention` (one-shot, not a ticker)"
        );
    }

    #[test]
    fn start_recording_retention_uses_shared_periodic() {
        let source = non_test_source();
        assert!(
            source.contains("shared::tasks::spawn_periodic"),
            "recording retention must delegate to shared::tasks::spawn_periodic"
        );
        assert!(
            source.contains("daily_cron::next_cron_instant"),
            "recording retention must use timezone-aware daily_cron::next_cron_instant"
        );
    }
}
