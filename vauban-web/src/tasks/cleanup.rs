/// VAUBAN Web - Cleanup tasks.
///
/// Background tasks for cleaning up expired sessions and API keys.
use chrono::Utc;
use diesel::prelude::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info};

use crate::db::{DbPool, get_connection};
use crate::schema::{api_keys, auth_sessions};

/// Interval for cleanup tasks (30 seconds).
const CLEANUP_INTERVAL_SECS: u64 = 30;

/// Start all cleanup tasks.
pub async fn start_cleanup_tasks(db_pool: DbPool) {
    let db_pool = Arc::new(db_pool);

    // Spawn session cleanup task
    let db_clone = Arc::clone(&db_pool);
    tokio::spawn(async move {
        session_cleanup_task(db_clone).await;
    });

    info!(
        interval_secs = CLEANUP_INTERVAL_SECS,
        "Cleanup background tasks started"
    );
}

/// Task that periodically cleans up expired auth sessions and API keys.
async fn session_cleanup_task(db_pool: Arc<DbPool>) {
    let mut ticker = interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));

    loop {
        ticker.tick().await;

        // Cleanup expired auth sessions
        match cleanup_expired_sessions(&db_pool) {
            Ok(count) => {
                if count > 0 {
                    info!(deleted = count, "Cleaned up expired auth sessions");
                } else {
                    debug!("No expired auth sessions to clean up");
                }
            }
            Err(e) => error!(error = %e, "Failed to clean up expired auth sessions"),
        }

        // Cleanup expired and inactive API keys
        match cleanup_expired_api_keys(&db_pool) {
            Ok(count) => {
                if count > 0 {
                    info!(deleted = count, "Cleaned up expired/inactive API keys");
                } else {
                    debug!("No expired API keys to clean up");
                }
            }
            Err(e) => error!(error = %e, "Failed to clean up expired API keys"),
        }
    }
}

/// Delete expired auth sessions from the database.
fn cleanup_expired_sessions(db_pool: &DbPool) -> Result<usize, String> {
    let mut conn = get_connection(db_pool).map_err(|e| e.to_string())?;

    let deleted = diesel::delete(
        auth_sessions::table.filter(auth_sessions::expires_at.lt(Utc::now())),
    )
    .execute(&mut conn)
    .map_err(|e| e.to_string())?;

    Ok(deleted)
}

/// Delete expired and inactive API keys from the database.
/// Deletes keys that are either:
/// - Expired (expires_at < now)
/// - Marked as inactive (is_active = false)
fn cleanup_expired_api_keys(db_pool: &DbPool) -> Result<usize, String> {
    let mut conn = get_connection(db_pool).map_err(|e| e.to_string())?;

    // Delete expired API keys (where expires_at is set and in the past)
    // OR inactive API keys
    let deleted = diesel::delete(
        api_keys::table.filter(
            api_keys::is_active
                .eq(false)
                .or(api_keys::expires_at.lt(Some(Utc::now()))),
        ),
    )
    .execute(&mut conn)
    .map_err(|e| e.to_string())?;

    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cleanup_interval() {
        assert_eq!(CLEANUP_INTERVAL_SECS, 30);
    }
}
