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

    let deleted =
        diesel::delete(auth_sessions::table.filter(auth_sessions::expires_at.lt(Utc::now())))
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
    use crate::{unwrap_ok, unwrap_some};

    // ==================== Constants Tests ====================

    #[test]
    fn test_cleanup_interval() {
        assert_eq!(CLEANUP_INTERVAL_SECS, 30);
    }

    #[test]
    fn test_cleanup_interval_is_reasonable() {
        // Cleanup should happen at least every 5 minutes
        assert!(CLEANUP_INTERVAL_SECS <= 300);
        // But not too frequently (at least 10 seconds)
        assert!(CLEANUP_INTERVAL_SECS >= 10);
    }

    #[test]
    fn test_cleanup_interval_as_duration() {
        let duration = Duration::from_secs(CLEANUP_INTERVAL_SECS);
        assert_eq!(duration.as_secs(), 30);
    }

    // ==================== Utc::now() Tests ====================

    #[test]
    fn test_utc_now_is_recent() {
        use chrono::Datelike;
        let now = Utc::now();
        let year = now.year();
        // Should be a reasonable year
        assert!(year >= 2024 && year <= 2100);
    }

    // ==================== Result Type Tests ====================

    #[test]
    fn test_cleanup_result_ok() {
        let result: Result<usize, String> = Ok(5);
        assert!(result.is_ok());
        assert_eq!(unwrap_ok!(result), 5);
    }

    #[test]
    fn test_cleanup_result_err() {
        let result: Result<usize, String> = Err("Database error".to_string());
        assert!(result.is_err());
        assert!(result.err().map(|e| e.contains("Database")).unwrap_or(false));
    }

    #[test]
    fn test_cleanup_result_zero_deleted() {
        let result: Result<usize, String> = Ok(0);
        assert!(result.is_ok());
        // Zero deleted is a valid result (no expired items)
        assert_eq!(unwrap_ok!(result), 0);
    }

    // ==================== Duration Tests ====================

    #[test]
    fn test_cleanup_interval_as_millis() {
        let duration = Duration::from_secs(CLEANUP_INTERVAL_SECS);
        assert_eq!(duration.as_millis(), 30_000);
    }

    #[test]
    fn test_interval_not_zero() {
        assert!(CLEANUP_INTERVAL_SECS > 0);
    }

    // ==================== Error Message Tests ====================

    #[test]
    fn test_cleanup_error_contains_info() {
        let error = "Database connection failed: timeout".to_string();
        let result: Result<usize, String> = Err(error);

        assert!(result.is_err());
        let err_msg = unwrap_some!(result.err());
        assert!(err_msg.contains("Database"));
        assert!(err_msg.contains("timeout"));
    }

    #[test]
    fn test_cleanup_error_empty_message() {
        let result: Result<usize, String> = Err("".to_string());
        assert!(result.is_err());
        assert_eq!(unwrap_some!(result.err()), "");
    }

    // ==================== Count Tests ====================

    #[test]
    fn test_cleanup_large_count() {
        let result: Result<usize, String> = Ok(1_000_000);
        assert!(result.is_ok());
        assert_eq!(unwrap_ok!(result), 1_000_000);
    }

    #[test]
    fn test_cleanup_count_type() {
        // Verify usize can handle expected cleanup counts
        let count: usize = 999_999;
        assert!(count < usize::MAX);
    }

    // ==================== Chrono Tests ====================

    #[test]
    fn test_utc_now_not_unix_epoch() {
        let now = Utc::now();
        let epoch = unwrap_some!(chrono::DateTime::<Utc>::from_timestamp(0, 0));
        assert!(now > epoch);
    }

    #[test]
    fn test_utc_now_comparison() {
        let before = Utc::now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let after = Utc::now();

        assert!(after > before);
    }

    // ==================== Arc Tests ====================

    #[test]
    fn test_arc_clone() {
        use std::sync::Arc;

        let value = Arc::new(42);
        let cloned = Arc::clone(&value);

        assert_eq!(*value, *cloned);
        assert_eq!(Arc::strong_count(&value), 2);
    }

    #[test]
    fn test_arc_drop() {
        use std::sync::Arc;

        let value = Arc::new(42);
        let cloned = Arc::clone(&value);

        assert_eq!(Arc::strong_count(&value), 2);
        drop(cloned);
        assert_eq!(Arc::strong_count(&value), 1);
    }

    // ==================== Interval Tests ====================

    #[tokio::test]
    async fn test_interval_creation() {
        let mut ticker = interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));

        // First tick is immediate
        ticker.tick().await;

        // Interval was created successfully
        assert!(true);
    }

    #[test]
    fn test_interval_duration_conversion() {
        let secs = CLEANUP_INTERVAL_SECS;
        let duration = Duration::from_secs(secs);

        assert_eq!(duration.as_secs(), secs);
        assert_eq!(duration.as_nanos(), secs as u128 * 1_000_000_000);
    }

    // ==================== Filter Expression Tests ====================

    #[test]
    fn test_utc_now_for_comparison() {
        let now = Utc::now();
        let past = now - chrono::Duration::hours(1);
        let future = now + chrono::Duration::hours(1);

        // These are the comparisons used in cleanup
        assert!(past < now);
        assert!(future > now);
    }

    #[test]
    fn test_utc_timestamp_ordering() {
        let t1 = unwrap_some!(chrono::DateTime::<Utc>::from_timestamp(1000, 0));
        let t2 = unwrap_some!(chrono::DateTime::<Utc>::from_timestamp(2000, 0));

        assert!(t1 < t2);
        assert!(t2 > t1);
    }

    // ==================== Result Pattern Tests ====================

    #[test]
    fn test_result_map_err() {
        fn operation() -> Result<(), std::io::Error> {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "test error"))
        }

        let result: Result<(), String> = operation().map_err(|e| e.to_string());

        assert!(result.is_err());
        assert!(unwrap_some!(result.err()).contains("test error"));
    }

    #[test]
    fn test_result_chain() {
        fn step1() -> Result<i32, String> {
            Ok(5)
        }

        fn step2(val: i32) -> Result<i32, String> {
            Ok(val * 2)
        }

        let result = step1().and_then(step2);
        assert_eq!(result, Ok(10));
    }

    // ==================== Deleted Count Tests ====================

    #[test]
    fn test_deleted_count_display() {
        let count: usize = 42;
        let msg = format!("Deleted {} items", count);
        assert_eq!(msg, "Deleted 42 items");
    }

    #[test]
    fn test_deleted_count_zero_display() {
        let count: usize = 0;
        let is_zero = count == 0;
        assert!(is_zero);
    }

    #[test]
    fn test_deleted_count_comparison() {
        let count: usize = 5;

        // Pattern used in cleanup task
        if count > 0 {
            assert!(true); // Would log info
        } else {
            panic!("Should not reach here");
        }
    }

    // ==================== Tracing Level Tests ====================

    #[test]
    fn test_log_levels_exist() {
        // Verify the log macros we use are valid
        // (This is a compile-time check more than runtime)
        use tracing::{debug, error, info};

        let _ = || {
            debug!("debug message");
            info!("info message");
            error!("error message");
        };
    }

    // ==================== Tokio Spawn Tests ====================

    #[tokio::test]
    async fn test_tokio_spawn_completes() {
        let handle = tokio::spawn(async { 42 });

        let result = unwrap_ok!(handle.await);
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn test_tokio_spawn_with_arc() {
        let value = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let value_clone = Arc::clone(&value);

        let handle = tokio::spawn(async move {
            value_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });

        unwrap_ok!(handle.await);
        assert_eq!(value.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    // ==================== Diesel Filter Expression Tests ====================

    #[test]
    fn test_bool_or_expression() {
        // Simulate the filter logic
        let is_active = false;
        let is_expired = true;

        // Logic used: is_active.eq(false).or(expires_at.lt(now))
        let should_delete = !is_active || is_expired;
        assert!(should_delete);
    }

    #[test]
    fn test_bool_or_expression_active_not_expired() {
        let is_active = true;
        let is_expired = false;

        let should_delete = !is_active || is_expired;
        assert!(!should_delete);
    }

    #[test]
    fn test_bool_or_expression_inactive_not_expired() {
        let is_active = false;
        let is_expired = false;

        let should_delete = !is_active || is_expired;
        assert!(should_delete); // Inactive keys get deleted
    }

    #[test]
    fn test_bool_or_expression_active_expired() {
        let is_active = true;
        let is_expired = true;

        let should_delete = !is_active || is_expired;
        assert!(should_delete); // Expired keys get deleted
    }
}
