/// VAUBAN Web - Cleanup tasks.
///
/// Background tasks for cleaning up expired sessions, API keys,
/// and JIT access requests.
use chrono::Utc;
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info};

use crate::AppState;
use crate::db::DbPool;
use crate::schema::{api_keys, auth_sessions, proxy_sessions};

/// Interval for cleanup tasks (30 seconds).
const CLEANUP_INTERVAL_SECS: u64 = 30;

/// Pending access requests older than this are expired automatically.
const PENDING_REQUEST_TTL_HOURS: i64 = 24;

/// Sessions stuck in "connecting" longer than this are considered abandoned.
const CONNECTING_TTL_MINUTES: i64 = 2;

/// Active sessions without `expires_at` that have not been updated for this
/// long are considered stale (server restart, network loss, etc.).
const STALE_ACTIVE_TTL_HOURS: i64 = 24;

/// Start all cleanup tasks.
///
/// `idle_timeout_secs` mirrors `config.security.session_idle_timeout_secs`
/// and is forwarded to [`run_cleanup_pass`] (Issue #8) so long-idle login
/// sessions are reaped on the same 30-second tick as already-expired ones.
///
/// `state` exposes the DB pool (for cleanup queries) and is forwarded to
/// the recording hydrator's PRIMARY enqueue path so any session
/// transitioned to `terminated` / `disconnected` by this task gets its
/// integrity bundle hydrated within `hydration_enqueue_delay_secs`
/// (issue #29 v1.4) -- without polling.
///
/// Spawn is delegated to `shared::tasks::spawn_periodic` for a uniform
/// task lifecycle (named tracing, skip-first-tick, Handle-based spawn).
pub async fn start_cleanup_tasks(state: AppState, idle_timeout_secs: u64) {
    let state = Arc::new(state);
    let handle = tokio::runtime::Handle::current();
    let state_for_task = Arc::clone(&state);
    shared::tasks::spawn_periodic(
        &handle,
        "session_cleanup",
        Duration::from_secs(CLEANUP_INTERVAL_SECS),
        move || {
            let state = Arc::clone(&state_for_task);
            async move {
                run_cleanup_pass(&state, idle_timeout_secs).await;
            }
        },
    );

    info!(
        interval_secs = CLEANUP_INTERVAL_SECS,
        idle_timeout_secs, "Cleanup background tasks started"
    );
}

/// One pass of all cleanup operations. Runs on every tick of the
/// shared periodic scheduler. Any per-operation error is logged but
/// never aborts the loop.
async fn run_cleanup_pass(state: &AppState, idle_timeout_secs: u64) {
    let db_pool = &state.db_pool;
    // Cleanup expired or long-idle auth sessions (Issue #8).
    match cleanup_expired_or_idle_sessions(db_pool, idle_timeout_secs).await {
        Ok(count) => {
            if count > 0 {
                info!(deleted = count, "Cleaned up expired or idle auth sessions");
            } else {
                debug!("No expired or idle auth sessions to clean up");
            }
        }
        Err(e) => error!(error = %e, "Failed to clean up expired or idle auth sessions"),
    }

    // Cleanup expired and inactive API keys
    match cleanup_expired_api_keys(db_pool).await {
        Ok(count) => {
            if count > 0 {
                info!(deleted = count, "Cleaned up expired/inactive API keys");
            } else {
                debug!("No expired API keys to clean up");
            }
        }
        Err(e) => error!(error = %e, "Failed to clean up expired API keys"),
    }

    // Terminate proxy sessions past their max_session_duration.
    // Returns the IDs of the rows actually transitioned so we can
    // schedule a recording-hydration enqueue for each one (issue #29
    // v1.4 PRIMARY path).
    match terminate_expired_proxy_sessions(db_pool).await {
        Ok(ids) => {
            if !ids.is_empty() {
                info!(
                    terminated = ids.len(),
                    "Terminated expired proxy sessions (max_session_duration)"
                );
                enqueue_hydration_for(state, &ids);
            }
        }
        Err(e) => error!(error = %e, "Failed to terminate expired proxy sessions"),
    }

    // Expire stale pending access requests
    match expire_stale_pending_requests(db_pool).await {
        Ok(count) => {
            if count > 0 {
                info!(expired = count, "Expired stale pending access requests");
            }
        }
        Err(e) => error!(error = %e, "Failed to expire stale pending requests"),
    }

    // Expire approved sessions past their expires_at deadline
    match expire_stale_approved_sessions(db_pool).await {
        Ok(count) => {
            if count > 0 {
                info!(expired = count, "Expired stale approved sessions");
            }
        }
        Err(e) => error!(error = %e, "Failed to expire stale approved sessions"),
    }

    // Expire sessions stuck in "connecting" for too long.
    // We deliberately do NOT call enqueue_hydration here: a
    // never-connected session has no recording on disk to hydrate.
    match expire_stale_connecting_sessions(db_pool).await {
        Ok(count) => {
            if count > 0 {
                info!(expired = count, "Expired stale connecting sessions");
            }
        }
        Err(e) => error!(error = %e, "Failed to expire stale connecting sessions"),
    }

    // Disconnect stale active sessions without expires_at. These
    // *may* have been recorded; enqueue hydration for each.
    match disconnect_stale_active_sessions(db_pool).await {
        Ok(ids) => {
            if !ids.is_empty() {
                info!(
                    disconnected = ids.len(),
                    "Disconnected stale active sessions (no expiry, no update for {}h)",
                    STALE_ACTIVE_TTL_HOURS
                );
                enqueue_hydration_for(state, &ids);
            }
        }
        Err(e) => error!(error = %e, "Failed to disconnect stale active sessions"),
    }
}

/// Issue an `enqueue_hydration` for every session id transitioned to
/// a terminal state by the current cleanup pass. Idempotent: each
/// enqueue is a no-op for non-recorded rows or rows already finalised
/// concurrently (PRIMARY path, issue #29 v1.4).
fn enqueue_hydration_for(state: &AppState, ids: &[i32]) {
    let grace =
        Duration::from_secs(state.config.recording.hydration_enqueue_delay_secs);
    for id in ids {
        std::mem::drop(crate::services::recording_hydrator::enqueue_hydration(
            state, *id, grace,
        ));
    }
}

/// Delete expired or long-idle auth sessions from the database.
///
/// Issue #8: in addition to the original `expires_at` predicate, this also
/// deletes rows whose `last_activity` is older than `idle_timeout_secs`.
/// Combined with the per-(user, device, IP) UNIQUE index and the purge
/// performed at login (`handlers::auth::insert_session_with_purge`), this
/// keeps the `My login sessions` view free of duplicates and stale
/// entries.
async fn cleanup_expired_or_idle_sessions(
    db_pool: &DbPool,
    idle_timeout_secs: u64,
) -> Result<usize, String> {
    use diesel_async::RunQueryDsl;

    let mut conn = db_pool.get().await.map_err(|e| e.to_string())?;
    let now = Utc::now();
    let idle_cutoff = now - chrono::Duration::seconds(idle_timeout_secs as i64);

    let deleted = diesel::delete(
        auth_sessions::table.filter(
            auth_sessions::expires_at
                .lt(now)
                .or(auth_sessions::last_activity.lt(idle_cutoff)),
        ),
    )
    .execute(&mut conn)
    .await
    .map_err(|e| e.to_string())?;

    Ok(deleted)
}

/// Delete expired and inactive API keys from the database.
/// Deletes keys that are either:
/// - Expired (expires_at < now)
/// - Marked as inactive (is_active = false)
async fn cleanup_expired_api_keys(db_pool: &DbPool) -> Result<usize, String> {
    use diesel_async::RunQueryDsl;

    let mut conn = db_pool.get().await.map_err(|e| e.to_string())?;

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
    .await
    .map_err(|e| e.to_string())?;

    Ok(deleted)
}

/// Terminate active proxy sessions that have exceeded their max_session_duration.
///
/// Finds sessions where `expires_at` is set and has passed, then moves them
/// to "terminated" status. Returns the IDs of the rows actually
/// transitioned so the caller can schedule a recording-hydration enqueue
/// for each (issue #29 v1.4 PRIMARY path).
async fn terminate_expired_proxy_sessions(db_pool: &DbPool) -> Result<Vec<i32>, String> {
    use diesel_async::RunQueryDsl;

    let mut conn = db_pool.get().await.map_err(|e| e.to_string())?;
    let now = Utc::now();

    let terminated_ids: Vec<i32> = diesel::update(
        proxy_sessions::table
            .filter(proxy_sessions::status.eq("active"))
            .filter(proxy_sessions::expires_at.le(now)),
    )
    .set((
        proxy_sessions::status.eq("terminated"),
        proxy_sessions::disconnected_at.eq(Some(now)),
        proxy_sessions::updated_at.eq(now),
    ))
    .returning(proxy_sessions::id)
    .get_results(&mut conn)
    .await
    .map_err(|e| e.to_string())?;

    Ok(terminated_ids)
}

/// Expire approved sessions whose `expires_at` has passed without the user connecting.
///
/// This prevents stale approvals from being reused after their validity window
/// (derived from `max_session_duration`) has elapsed.
async fn expire_stale_approved_sessions(db_pool: &DbPool) -> Result<usize, String> {
    use diesel_async::RunQueryDsl;

    let mut conn = db_pool.get().await.map_err(|e| e.to_string())?;
    let now = Utc::now();

    let expired = diesel::update(
        proxy_sessions::table
            .filter(proxy_sessions::status.eq("approved"))
            .filter(proxy_sessions::expires_at.le(now)),
    )
    .set((
        proxy_sessions::status.eq("expired"),
        proxy_sessions::updated_at.eq(now),
    ))
    .execute(&mut conn)
    .await
    .map_err(|e| e.to_string())?;

    Ok(expired)
}

/// Expire pending access requests that are older than PENDING_REQUEST_TTL_HOURS.
async fn expire_stale_pending_requests(db_pool: &DbPool) -> Result<usize, String> {
    use diesel_async::RunQueryDsl;

    let mut conn = db_pool.get().await.map_err(|e| e.to_string())?;
    let cutoff = Utc::now() - chrono::Duration::hours(PENDING_REQUEST_TTL_HOURS);

    let expired = diesel::update(
        proxy_sessions::table
            .filter(proxy_sessions::status.eq("pending"))
            .filter(proxy_sessions::created_at.lt(cutoff)),
    )
    .set((
        proxy_sessions::status.eq("expired"),
        proxy_sessions::updated_at.eq(Utc::now()),
    ))
    .execute(&mut conn)
    .await
    .map_err(|e| e.to_string())?;

    Ok(expired)
}

/// Expire sessions stuck in "connecting" for longer than CONNECTING_TTL_MINUTES.
///
/// This catches cases where the WebSocket was never established (browser closed,
/// proxy failure, network loss before the connection completed).
async fn expire_stale_connecting_sessions(db_pool: &DbPool) -> Result<usize, String> {
    use diesel_async::RunQueryDsl;

    let mut conn = db_pool.get().await.map_err(|e| e.to_string())?;
    let cutoff = Utc::now() - chrono::Duration::minutes(CONNECTING_TTL_MINUTES);

    let expired = diesel::update(
        proxy_sessions::table
            .filter(proxy_sessions::status.eq("connecting"))
            .filter(proxy_sessions::created_at.lt(cutoff)),
    )
    .set((
        proxy_sessions::status.eq("disconnected"),
        proxy_sessions::disconnected_at.eq(Some(Utc::now())),
        proxy_sessions::updated_at.eq(Utc::now()),
    ))
    .execute(&mut conn)
    .await
    .map_err(|e| e.to_string())?;

    Ok(expired)
}

/// Disconnect active sessions that have no `expires_at` and have not been
/// updated for STALE_ACTIVE_TTL_HOURS.
///
/// Sessions with `expires_at` are handled by `terminate_expired_proxy_sessions`.
/// This catches sessions orphaned by server restarts, network outages, or
/// WebSocket closures that failed to update the database. Returns the
/// IDs of the rows actually transitioned so the caller can schedule a
/// recording-hydration enqueue for each (issue #29 v1.4 PRIMARY path).
async fn disconnect_stale_active_sessions(db_pool: &DbPool) -> Result<Vec<i32>, String> {
    use diesel_async::RunQueryDsl;

    let mut conn = db_pool.get().await.map_err(|e| e.to_string())?;
    let now = Utc::now();
    let cutoff = now - chrono::Duration::hours(STALE_ACTIVE_TTL_HOURS);

    let disconnected_ids: Vec<i32> = diesel::update(
        proxy_sessions::table
            .filter(proxy_sessions::status.eq("active"))
            .filter(proxy_sessions::expires_at.is_null())
            .filter(proxy_sessions::updated_at.lt(cutoff)),
    )
    .set((
        proxy_sessions::status.eq("disconnected"),
        proxy_sessions::disconnected_at.eq(Some(now)),
        proxy_sessions::updated_at.eq(now),
    ))
    .returning(proxy_sessions::id)
    .get_results(&mut conn)
    .await
    .map_err(|e| e.to_string())?;

    Ok(disconnected_ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Constants Tests ====================

    #[test]
    fn test_cleanup_interval() {
        assert_eq!(CLEANUP_INTERVAL_SECS, 30);
    }

    #[test]
    fn test_cleanup_interval_is_reasonable() {
        assert!((10..=300).contains(&CLEANUP_INTERVAL_SECS));
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
        assert!((2024..=2100).contains(&year));
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
        assert!(
            result
                .err()
                .map(|e| e.contains("Database"))
                .unwrap_or(false)
        );
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
        assert_ne!(CLEANUP_INTERVAL_SECS, 0);
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
        let mut ticker = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));

        // First tick is immediate
        ticker.tick().await;

        assert_eq!(ticker.period(), Duration::from_secs(CLEANUP_INTERVAL_SECS));
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
            Err(std::io::Error::other("test error"))
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
        assert_eq!(count, 5);
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

    // ==================== Stale Connecting Sessions Tests ====================

    #[test]
    fn test_connecting_ttl_is_reasonable() {
        assert!(
            (1..=10).contains(&CONNECTING_TTL_MINUTES),
            "CONNECTING_TTL_MINUTES should be between 1 and 10"
        );
    }

    #[test]
    fn test_expire_stale_connecting_sessions_exists() {
        let source = include_str!("cleanup.rs");
        assert!(
            source.contains("fn expire_stale_connecting_sessions"),
            "expire_stale_connecting_sessions function must exist"
        );
    }

    #[test]
    fn test_expire_stale_connecting_filters_status() {
        let source = include_str!("cleanup.rs");
        let fn_start = source
            .find("fn expire_stale_connecting_sessions")
            .expect("function must exist");
        let fn_body = &source[fn_start..];
        let fn_end = fn_body[1..]
            .find("\nasync fn ")
            .or_else(|| fn_body[1..].find("\n/// "))
            .or_else(|| fn_body[1..].find("#[cfg(test)]"))
            .unwrap_or(fn_body.len());
        let fn_body = &fn_body[..fn_end];

        assert!(
            fn_body.contains("status.eq(\"connecting\")"),
            "must filter on status = connecting"
        );
        assert!(
            fn_body.contains("created_at.lt(cutoff)"),
            "must filter on created_at < cutoff"
        );
    }

    #[test]
    fn test_expire_stale_connecting_sets_disconnected() {
        let source = include_str!("cleanup.rs");
        let fn_start = source
            .find("fn expire_stale_connecting_sessions")
            .expect("function must exist");
        let fn_body = &source[fn_start..];
        let fn_end = fn_body[1..]
            .find("\nasync fn ")
            .or_else(|| fn_body[1..].find("\n/// "))
            .or_else(|| fn_body[1..].find("#[cfg(test)]"))
            .unwrap_or(fn_body.len());
        let fn_body = &fn_body[..fn_end];

        assert!(
            fn_body.contains("status.eq(\"disconnected\")"),
            "must set status to disconnected"
        );
    }

    // ==================== Stale Active Sessions Tests ====================

    #[test]
    fn test_stale_active_ttl_is_reasonable() {
        assert!(
            (1..=72).contains(&STALE_ACTIVE_TTL_HOURS),
            "STALE_ACTIVE_TTL_HOURS should be between 1 and 72"
        );
    }

    #[test]
    fn test_disconnect_stale_active_sessions_exists() {
        let source = include_str!("cleanup.rs");
        assert!(
            source.contains("fn disconnect_stale_active_sessions"),
            "disconnect_stale_active_sessions function must exist"
        );
    }

    #[test]
    fn test_disconnect_stale_active_filters_correctly() {
        let source = include_str!("cleanup.rs");
        let fn_start = source
            .find("fn disconnect_stale_active_sessions")
            .expect("function must exist");
        let fn_body = &source[fn_start..];
        let fn_end = fn_body[1..]
            .find("\nasync fn ")
            .or_else(|| fn_body[1..].find("\n/// "))
            .or_else(|| fn_body[1..].find("#[cfg(test)]"))
            .unwrap_or(fn_body.len());
        let fn_body = &fn_body[..fn_end];

        assert!(
            fn_body.contains("status.eq(\"active\")"),
            "must filter on status = active"
        );
        assert!(
            fn_body.contains("expires_at.is_null()"),
            "must only target sessions without expires_at"
        );
        assert!(
            fn_body.contains("updated_at.lt(cutoff)"),
            "must filter on updated_at < cutoff"
        );
    }

    #[test]
    fn test_disconnect_stale_active_sets_disconnected() {
        let source = include_str!("cleanup.rs");
        let fn_start = source
            .find("fn disconnect_stale_active_sessions")
            .expect("function must exist");
        let fn_body = &source[fn_start..];
        let fn_end = fn_body[1..]
            .find("\nasync fn ")
            .or_else(|| fn_body[1..].find("\n/// "))
            .or_else(|| fn_body[1..].find("#[cfg(test)]"))
            .unwrap_or(fn_body.len());
        let fn_body = &fn_body[..fn_end];

        assert!(
            fn_body.contains("status.eq(\"disconnected\")"),
            "must set status to disconnected"
        );
    }

    // ==================== Cleanup Pass Calls All Functions ====================

    /// Helper: extract the body of `run_cleanup_pass` from the source
    /// for source-level pinning. Bounded by the next `async fn` / doc
    /// comment / `#[cfg(test)]` so unrelated code does not pollute
    /// the slice.
    fn run_cleanup_pass_body(source: &str) -> &str {
        let fn_start = source
            .find("fn run_cleanup_pass")
            .expect("run_cleanup_pass must exist");
        let fn_body = &source[fn_start..];
        let fn_end = fn_body[1..]
            .find("\nasync fn ")
            .or_else(|| fn_body[1..].find("\nfn "))
            .or_else(|| fn_body[1..].find("\n/// "))
            .or_else(|| fn_body[1..].find("#[cfg(test)]"))
            .unwrap_or(fn_body.len());
        &fn_body[..fn_end]
    }

    #[test]
    fn test_cleanup_pass_calls_connecting_cleanup() {
        let source = include_str!("cleanup.rs");
        let fn_body = run_cleanup_pass_body(source);
        assert!(
            fn_body.contains("expire_stale_connecting_sessions"),
            "run_cleanup_pass must call expire_stale_connecting_sessions"
        );
    }

    #[test]
    fn test_cleanup_pass_calls_stale_active_cleanup() {
        let source = include_str!("cleanup.rs");
        let fn_body = run_cleanup_pass_body(source);
        assert!(
            fn_body.contains("disconnect_stale_active_sessions"),
            "run_cleanup_pass must call disconnect_stale_active_sessions"
        );
    }

    // ==================== Issue #8 -- Idle session cleanup ====================

    /// `start_cleanup_tasks` must accept `state: AppState` (so it can
    /// forward to `enqueue_hydration` -- issue #29 v1.4) and the idle
    /// timeout as a parameter (issue #8).
    #[test]
    fn test_start_cleanup_tasks_signature() {
        let source = include_str!("cleanup.rs");
        assert!(
            source.contains(
                "pub async fn start_cleanup_tasks(state: AppState, idle_timeout_secs: u64)"
            ),
            "start_cleanup_tasks signature must be (state: AppState, idle_timeout_secs: u64) \
             so it can call enqueue_hydration (issue #29 v1.4) and honour \
             config.security.session_idle_timeout_secs (issue #8)"
        );
    }

    /// The cleanup pass must call the renamed function so the new
    /// idle-cleanup behaviour actually runs on every tick.
    #[test]
    fn test_cleanup_pass_calls_expired_or_idle_cleanup() {
        let source = include_str!("cleanup.rs");
        let fn_body = run_cleanup_pass_body(source);
        assert!(
            fn_body.contains("cleanup_expired_or_idle_sessions"),
            "run_cleanup_pass must call cleanup_expired_or_idle_sessions (Issue #8)"
        );
        assert!(
            fn_body.contains("idle_timeout_secs"),
            "run_cleanup_pass must forward idle_timeout_secs to the cleanup helper"
        );
    }

    // ==================== Issue #29 v1.4 -- PRIMARY enqueue ====================

    /// `terminate_expired_proxy_sessions` must enqueue a recording
    /// hydration for each transitioned id, otherwise sessions
    /// terminated by max_session_duration would only be hydrated by
    /// the daily SAFETY cron (up to 24h delay).
    #[test]
    fn test_cleanup_pass_enqueues_hydration_for_terminated_sessions() {
        let source = include_str!("cleanup.rs");
        let fn_body = run_cleanup_pass_body(source);
        assert!(
            fn_body.contains("terminate_expired_proxy_sessions"),
            "run_cleanup_pass must call terminate_expired_proxy_sessions"
        );
        assert!(
            fn_body.contains("enqueue_hydration_for"),
            "run_cleanup_pass must enqueue hydration for terminated sessions (issue #29 v1.4)"
        );
    }

    /// The `expire_stale_connecting_sessions` path must NOT enqueue a
    /// hydration: never-connected sessions have no recording on disk
    /// to hydrate; doing so would log spurious skipped_missing_meta
    /// entries every cleanup tick.
    #[test]
    fn test_expire_stale_connecting_does_not_enqueue_hydration() {
        let source = include_str!("cleanup.rs");
        let fn_body = run_cleanup_pass_body(source);
        // Find the `expire_stale_connecting_sessions` match arm and
        // ensure no `enqueue_hydration` is in scope until the next
        // `match` (i.e. the next cleanup step).
        let arm_start = fn_body
            .find("expire_stale_connecting_sessions(db_pool)")
            .expect("connecting cleanup arm must exist in run_cleanup_pass");
        let arm_body = &fn_body[arm_start..];
        let arm_end = arm_body[1..]
            .find("match ")
            .map(|i| i + 1)
            .unwrap_or(arm_body.len());
        let arm_body = &arm_body[..arm_end];
        assert!(
            !arm_body.contains("enqueue_hydration"),
            "expire_stale_connecting_sessions arm must NOT enqueue hydration: \
             never-connected sessions have no recording on disk"
        );
    }

    /// The disconnect-stale-active path MUST enqueue a hydration:
    /// these sessions WERE active and may have been recorded; if their
    /// owning vauban-web crashed they could be left in-flight forever.
    #[test]
    fn test_cleanup_pass_enqueues_hydration_for_stale_active() {
        let source = include_str!("cleanup.rs");
        let fn_body = run_cleanup_pass_body(source);
        let arm_start = fn_body
            .find("disconnect_stale_active_sessions(db_pool)")
            .expect("stale-active arm must exist in run_cleanup_pass");
        let arm_body = &fn_body[arm_start..];
        let arm_end = arm_body[1..]
            .find("match ")
            .map(|i| i + 1)
            .unwrap_or(arm_body.len());
        let arm_body = &arm_body[..arm_end];
        assert!(
            arm_body.contains("enqueue_hydration_for"),
            "disconnect_stale_active_sessions arm must enqueue hydration (issue #29 v1.4)"
        );
    }

    /// `enqueue_hydration_for` must derive the grace from
    /// `state.config.recording.hydration_enqueue_delay_secs` so the
    /// configured value is honoured uniformly across the codebase.
    #[test]
    fn test_enqueue_hydration_for_uses_configured_delay() {
        let source = include_str!("cleanup.rs");
        assert!(
            source.contains("hydration_enqueue_delay_secs"),
            "enqueue_hydration_for must read state.config.recording.hydration_enqueue_delay_secs"
        );
    }

    /// `terminate_expired_proxy_sessions` and
    /// `disconnect_stale_active_sessions` must return `Vec<i32>` so
    /// the caller can enqueue per-id (issue #29 v1.4). A regression to
    /// `Result<usize, _>` would silently break the PRIMARY path.
    #[test]
    fn test_terminate_returns_vec_of_ids() {
        let source = include_str!("cleanup.rs");
        assert!(
            source.contains(
                "async fn terminate_expired_proxy_sessions(db_pool: &DbPool) -> Result<Vec<i32>, String>"
            ),
            "terminate_expired_proxy_sessions must return Vec<i32>"
        );
        assert!(
            source.contains(
                "async fn disconnect_stale_active_sessions(db_pool: &DbPool) -> Result<Vec<i32>, String>"
            ),
            "disconnect_stale_active_sessions must return Vec<i32>"
        );
    }

    /// The cleanup helper must filter on BOTH `expires_at < now` (original
    /// behaviour) AND `last_activity < idle_cutoff` (Issue #8), where
    /// `idle_cutoff = now - idle_timeout_secs`.
    #[test]
    fn test_cleanup_expired_or_idle_filters_both_predicates() {
        let source = include_str!("cleanup.rs");
        let fn_start = source
            .find("fn cleanup_expired_or_idle_sessions")
            .expect("cleanup_expired_or_idle_sessions function must exist");
        let fn_body = &source[fn_start..];
        let fn_end = fn_body[1..]
            .find("\nasync fn ")
            .or_else(|| fn_body[1..].find("\n/// "))
            .or_else(|| fn_body[1..].find("#[cfg(test)]"))
            .unwrap_or(fn_body.len());
        let fn_body = &fn_body[..fn_end];

        assert!(
            fn_body.contains("expires_at"),
            "cleanup_expired_or_idle_sessions must still filter on expires_at"
        );
        assert!(
            fn_body.contains("last_activity"),
            "cleanup_expired_or_idle_sessions must filter on last_activity (Issue #8)"
        );
        assert!(
            fn_body.contains(".or("),
            "cleanup_expired_or_idle_sessions must combine the two predicates with OR \
             (so a row matching either is reaped)"
        );
        assert!(
            fn_body.contains("idle_cutoff") && fn_body.contains("idle_timeout_secs"),
            "cleanup_expired_or_idle_sessions must derive idle_cutoff from idle_timeout_secs"
        );
    }

    /// Sanity guard: the idle-cleanup arithmetic must subtract a Duration
    /// from `now` -- not add it -- otherwise we would delete future
    /// sessions instead of stale ones.
    #[test]
    fn test_idle_cutoff_is_in_the_past() {
        let source = include_str!("cleanup.rs");
        assert!(
            source.contains("now - chrono::Duration::seconds(idle_timeout_secs as i64)"),
            "idle_cutoff must be `now - idle_timeout_secs`, not `now + ...`"
        );
    }
}
