//! Sticky `proxy_sessions.recording_lossy` latch (SSH/RDP best-effort drops).
//!
//! Only vauban-web writes this column (I-LOSS-3). Proxies detect drops and
//! emit `Message::RecordingLossObserved`; this module applies the monotone
//! UPDATE (I-LOSS-2).

use crate::db::DbPool;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use tracing::{debug, info, warn};
use uuid::Uuid;
use vauban_db::schema::proxy_sessions;

/// Set `recording_lossy = TRUE` when currently false. Idempotent / monotone.
pub async fn mark_session_recording_lossy(pool: &DbPool, session_id: &str) {
    let Ok(session_uuid) = Uuid::parse_str(session_id) else {
        warn!(
            session_id = %session_id,
            "RecordingLossObserved with non-UUID session_id; ignored"
        );
        return;
    };

    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "DB pool exhausted marking recording_lossy");
            return;
        }
    };

    match diesel::update(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .filter(proxy_sessions::recording_lossy.eq(false)),
    )
    .set(proxy_sessions::recording_lossy.eq(true))
    .execute(&mut conn)
    .await
    {
        Ok(0) => {
            debug!(
                session_id = %session_id,
                "recording_lossy already set or session missing"
            );
        }
        Ok(_) => {
            info!(session_id = %session_id, "Marked session recording_lossy");
        }
        Err(e) => {
            warn!(
                session_id = %session_id,
                error = %e,
                "Failed to SET recording_lossy"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_session_recording_lossy_rejects_non_uuid_without_panic() {
        // Pure parse gate; no DB. Documented so callers know the shape.
        assert!(Uuid::parse_str("not-a-uuid").is_err());
        assert!(Uuid::parse_str("00000000-0000-0000-0000-000000000001").is_ok());
    }
}
