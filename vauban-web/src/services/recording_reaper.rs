//! Recording retention reaper.
//!
//! Daily task that deletes aged or quota-exceeded session recordings from
//! disk (via supervisor IPC) and clears recording metadata in
//! `proxy_sessions`. Configuration lives exclusively in TOML
//! (`[recording].retention_*`); there is no web UI or API surface.

use std::sync::Arc;

use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use shared::recording_paths::recording_root_relative;
use tracing::{error, info, warn};

use crate::db::DbPool;
use crate::ipc::supervisor::SupervisorClient;
use crate::schema::proxy_sessions::dsl;

/// Stable task name for tracing (`task=recording_reaper`).
pub const TASK_NAME: &str = "recording_reaper";

/// Live session statuses that must never be reaped (pinned in unit tests).
#[allow(dead_code)]
const LIVE_STATUSES: &[&str] = &["active", "connecting", "approved", "pending"];

type CandidateRow = (
    i32,
    uuid::Uuid,
    Option<String>,
    Option<chrono::DateTime<Utc>>,
);

pub struct RecordingReaper {
    db_pool: DbPool,
    supervisor: Arc<SupervisorClient>,
    retention_days: u32,
    max_size_gib: u64,
    batch_size: i64,
    storage_base: String,
}

pub struct ReaperReport {
    pub age_reaped: usize,
    pub quota_reaped: usize,
    pub bytes_freed: u64,
    pub errors: usize,
}

impl RecordingReaper {
    pub fn new(
        db_pool: DbPool,
        supervisor: Arc<SupervisorClient>,
        retention_days: u32,
        max_size_gib: u64,
        batch_size: i64,
        storage_base: String,
    ) -> Self {
        Self {
            db_pool,
            supervisor,
            retention_days,
            max_size_gib,
            batch_size,
            storage_base,
        }
    }

    /// Run one retention pass (age, then optional quota).
    pub async fn tick(&self) -> Result<ReaperReport, String> {
        let mut report = ReaperReport {
            age_reaped: 0,
            quota_reaped: 0,
            bytes_freed: 0,
            errors: 0,
        };

        let cutoff = Utc::now() - Duration::days(i64::from(self.retention_days));
        let mut remaining_batch = self.batch_size;

        while remaining_batch > 0 {
            let mut conn = self.db_pool.get().await.map_err(|e| e.to_string())?;
            let candidates = select_age_candidates(&mut conn, cutoff, remaining_batch).await?;
            if candidates.is_empty() {
                break;
            }
            let count = candidates.len();
            for row in candidates {
                match self.reap_one(row, "age").await {
                    Ok(bytes) => {
                        report.age_reaped += 1;
                        report.bytes_freed = report.bytes_freed.saturating_add(bytes);
                    }
                    Err(e) => {
                        report.errors += 1;
                        error!(task = TASK_NAME, pass = "age", error = %e, "reap_one failed");
                    }
                }
            }
            remaining_batch -= count as i64;
        }

        if self.max_size_gib > 0 {
            let max_bytes = self
                .max_size_gib
                .saturating_mul(1024)
                .saturating_mul(1024)
                .saturating_mul(1024);
            let mut conn = self.db_pool.get().await.map_err(|e| e.to_string())?;
            let total = total_finalized_bytes(&mut conn).await?;
            if total > max_bytes as i64 {
                let mut quota_remaining = self.batch_size;
                while quota_remaining > 0 && total > max_bytes as i64 {
                    let candidates = select_quota_candidates(&mut conn, quota_remaining).await?;
                    if candidates.is_empty() {
                        break;
                    }
                    let count = candidates.len();
                    for row in candidates {
                        match self.reap_one(row, "quota").await {
                            Ok(bytes) => {
                                report.quota_reaped += 1;
                                report.bytes_freed = report.bytes_freed.saturating_add(bytes);
                            }
                            Err(e) => {
                                report.errors += 1;
                                error!(task = TASK_NAME, pass = "quota", error = %e, "reap_one failed");
                            }
                        }
                    }
                    quota_remaining -= count as i64;
                    let total_now = total_finalized_bytes(&mut conn).await?;
                    if total_now <= max_bytes as i64 {
                        break;
                    }
                }
            }
        }

        Ok(report)
    }

    async fn reap_one(&self, row: CandidateRow, pass: &str) -> Result<u64, String> {
        let (id, uuid, recording_path_opt, _disconnected_at) = row;
        let recording_path = recording_path_opt
            .ok_or_else(|| format!("missing recording_path for session id {id}"))?;
        let session_uuid = uuid.to_string();
        let relative =
            recording_root_relative(&self.storage_base, &recording_path).ok_or_else(|| {
                format!("invalid recording_path for session {session_uuid}: {recording_path}")
            })?;

        let delete_result = self
            .supervisor
            .request_recording_delete(&session_uuid, &relative)
            .await?;

        if !delete_result.success {
            return Err(delete_result
                .error
                .unwrap_or_else(|| "supervisor delete failed".into()));
        }

        let mut conn = self.db_pool.get().await.map_err(|e| e.to_string())?;
        let updated = clear_recording_metadata(&mut conn, id).await?;
        if updated == 0 {
            warn!(
                task = TASK_NAME,
                pass,
                session_uuid = %session_uuid,
                "recording metadata already cleared (concurrent reaper?)"
            );
        } else {
            info!(
                task = TASK_NAME,
                pass,
                session_uuid = %session_uuid,
                bytes_freed = delete_result.bytes_freed,
                "recording reaped"
            );
        }

        Ok(delete_result.bytes_freed)
    }
}

pub async fn select_age_candidates(
    conn: &mut diesel_async::AsyncPgConnection,
    cutoff: chrono::DateTime<Utc>,
    limit: i64,
) -> Result<Vec<CandidateRow>, String> {
    dsl::proxy_sessions
        .filter(dsl::is_recorded.eq(true))
        .filter(dsl::recording_path.is_not_null())
        .filter(dsl::disconnected_at.is_not_null())
        .filter(dsl::status.ne("active"))
        .filter(dsl::status.ne("connecting"))
        .filter(dsl::status.ne("approved"))
        .filter(dsl::status.ne("pending"))
        .filter(dsl::disconnected_at.lt(cutoff))
        .order(dsl::disconnected_at.asc())
        .limit(limit)
        .select((
            dsl::id,
            dsl::uuid,
            dsl::recording_path,
            dsl::disconnected_at,
        ))
        .load(conn)
        .await
        .map_err(|e| e.to_string())
}

pub async fn select_quota_candidates(
    conn: &mut diesel_async::AsyncPgConnection,
    limit: i64,
) -> Result<Vec<CandidateRow>, String> {
    dsl::proxy_sessions
        .filter(dsl::is_recorded.eq(true))
        .filter(dsl::recording_path.is_not_null())
        .filter(dsl::disconnected_at.is_not_null())
        .filter(dsl::status.ne("active"))
        .filter(dsl::status.ne("connecting"))
        .filter(dsl::status.ne("approved"))
        .filter(dsl::status.ne("pending"))
        .filter(dsl::recording_finalized_at.is_not_null())
        .filter(dsl::recording_size_bytes.is_not_null())
        .order(dsl::disconnected_at.asc())
        .limit(limit)
        .select((
            dsl::id,
            dsl::uuid,
            dsl::recording_path,
            dsl::disconnected_at,
        ))
        .load(conn)
        .await
        .map_err(|e| e.to_string())
}

pub async fn total_finalized_bytes(
    conn: &mut diesel_async::AsyncPgConnection,
) -> Result<i64, String> {
    let sizes: Vec<Option<i64>> = dsl::proxy_sessions
        .filter(dsl::is_recorded.eq(true))
        .filter(dsl::recording_path.is_not_null())
        .filter(dsl::recording_finalized_at.is_not_null())
        .select(dsl::recording_size_bytes)
        .load(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(sizes.into_iter().flatten().fold(0i64, i64::saturating_add))
}

pub async fn clear_recording_metadata(
    conn: &mut diesel_async::AsyncPgConnection,
    session_id: i32,
) -> Result<usize, String> {
    diesel::update(
        dsl::proxy_sessions
            .filter(dsl::id.eq(session_id))
            .filter(dsl::recording_path.is_not_null()),
    )
    .set((
        dsl::is_recorded.eq(false),
        dsl::recording_path.eq(None::<String>),
        dsl::recording_blake3.eq(None::<String>),
        dsl::recording_size_bytes.eq(None::<i64>),
        dsl::recording_duration_ms.eq(None::<i64>),
        dsl::recording_event_count.eq(None::<i32>),
        dsl::recording_format.eq(None::<String>),
        dsl::recording_width.eq(None::<i16>),
        dsl::recording_height.eq(None::<i16>),
        dsl::recording_segment_count.eq(None::<i32>),
        dsl::recording_codec.eq(None::<String>),
        dsl::recording_finalized_at.eq(None::<chrono::DateTime<Utc>>),
    ))
    .execute(conn)
    .await
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_name_is_stable() {
        assert_eq!(TASK_NAME, "recording_reaper");
    }

    #[test]
    fn live_statuses_exclude_active_sessions() {
        assert!(LIVE_STATUSES.contains(&"active"));
        assert!(LIVE_STATUSES.contains(&"connecting"));
        let source = include_str!("recording_reaper.rs");
        for live in LIVE_STATUSES {
            assert!(
                source.contains(&format!("status.ne(\"{live}\")")),
                "select_* must exclude live status {live}"
            );
        }
    }
}
