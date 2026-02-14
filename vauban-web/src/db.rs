use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
/// VAUBAN Web - Database connection pool setup.
///
/// Uses diesel-async with deadpool for async PostgreSQL connection pooling.
/// This eliminates background threads, making it fully compatible with Capsicum sandbox.
///
/// This module provides:
/// - `create_pool()`: Async pool for production use
/// - `create_pool_sandboxed()`: Pre-establishes all connections for Capsicum sandbox mode
use diesel_async::pooled_connection::deadpool::{Object, Pool};
use secrecy::ExposeSecret;

use crate::config::Config;
use crate::error::{AppError, AppResult};

/// Exit code used when database connection is lost in sandbox mode.
/// The supervisor will respawn the service when it sees this exit code.
pub const EXIT_CODE_CONNECTION_LOST: i32 = 100;

/// Database connection pool type (async, no background threads).
pub type DbPool = Pool<AsyncPgConnection>;

/// Database connection type (pooled async connection).
pub type DbConnection = Object<AsyncPgConnection>;

/// Create a new database connection pool.
///
/// This creates an async pool using deadpool-diesel.
/// No background threads are spawned, making it Capsicum-compatible.
pub async fn create_pool(config: &Config) -> AppResult<DbPool> {
    let manager =
        AsyncDieselConnectionManager::<AsyncPgConnection>::new(config.database.url.expose_secret());

    let pool = Pool::builder(manager)
        .max_size(config.database.max_connections as usize)
        .build()
        .map_err(|e| AppError::Config(format!("Failed to create database pool: {}", e)))?;

    tracing::info!(
        "Database pool created with max {} connections",
        config.database.max_connections
    );

    Ok(pool)
}

/// Create a database connection pool for Capsicum sandbox mode.
///
/// This creates a pool where all connections are pre-established
/// before entering capability mode. No background threads are used.
///
/// After `cap_enter()`, no new connections can be opened. If a connection is lost,
/// the service must exit and be respawned by the supervisor.
///
/// # Errors
/// Returns an error if the pool cannot be created or if any connection fails validation.
pub async fn create_pool_sandboxed(config: &Config) -> AppResult<DbPool> {
    let manager =
        AsyncDieselConnectionManager::<AsyncPgConnection>::new(config.database.url.expose_secret());

    let pool_size = config.database.max_connections as usize;

    let pool = Pool::builder(manager)
        .max_size(pool_size)
        .build()
        .map_err(|e| {
            AppError::Config(format!("Failed to create sandboxed database pool: {}", e))
        })?;

    // Force creation of all connections by borrowing them simultaneously.
    // This ensures all connections are established BEFORE cap_enter().
    force_create_all_connections(&pool, pool_size).await?;

    tracing::info!(
        "Database pool ready for sandbox mode: {} connections pre-established",
        pool_size
    );

    Ok(pool)
}

/// Force creation of all connections by borrowing them simultaneously.
///
/// This function borrows all connections at once, forcing the pool to create them.
/// The connections are then returned to the pool and become available.
///
/// This is essential for Capsicum sandbox mode: all connections must be
/// established BEFORE cap_enter().
async fn force_create_all_connections(pool: &DbPool, count: usize) -> AppResult<()> {
    tracing::debug!("Force-creating {} database connections...", count);

    // Borrow all connections simultaneously to force their creation
    let mut connections = Vec::with_capacity(count);
    for i in 0..count {
        let conn = pool.get().await.map_err(|e| {
            AppError::Config(format!(
                "Failed to establish DB connection {}/{}: {}",
                i + 1,
                count,
                e
            ))
        })?;
        connections.push(conn);
        tracing::trace!("DB connection {}/{} created", i + 1, count);
    }

    tracing::debug!("All {} database connections created and validated", count);

    // Connections are dropped here, returning them to the pool
    drop(connections);

    // Verify the pool state
    let status = pool.status();
    tracing::debug!(
        "Pool state after creation: {} size, {} available",
        status.size,
        status.available
    );

    Ok(())
}

/// Escape LIKE/ILIKE wildcard characters in a search pattern.
///
/// L-5: PostgreSQL LIKE treats `%` and `_` as wildcards. If user input is passed
/// directly into a LIKE pattern, these characters allow unintended pattern matching.
/// This function escapes them so they are treated as literals.
///
/// The backslash `\` is also escaped since it is the default LIKE escape character.
pub fn escape_like_pattern(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Build a LIKE/ILIKE "contains" pattern from user input.
///
/// Returns `%<escaped_input>%` suitable for use with `.ilike()` or `ILIKE $1`.
pub fn like_contains(input: &str) -> String {
    format!("%{}%", escape_like_pattern(input))
}

/// Get a connection from the pool.
///
/// Returns an error that can be handled by the caller.
pub async fn get_connection(pool: &DbPool) -> AppResult<DbConnection> {
    pool.get().await.map_err(|e| {
        AppError::Internal(anyhow::anyhow!("Failed to get database connection: {}", e))
    })
}

/// Get a connection from the pool, or trigger shutdown if connection is lost (sandbox mode).
///
/// This function is designed for Capsicum sandbox mode where the service
/// cannot recover from a lost database connection. If the connection cannot
/// be obtained, a graceful shutdown is triggered via the server handle to
/// allow all Drop/Zeroize destructors to run (M-8/M-10).
///
/// L-3: Uses structured pattern matching on `PoolError` variants instead of
/// fragile string-based error detection.
///
/// Returns `Err` if the connection cannot be obtained and shutdown was triggered.
pub async fn get_connection_or_shutdown(
    pool: &DbPool,
    server_handle: Option<&axum_server::Handle<std::net::SocketAddr>>,
) -> Result<DbConnection, crate::error::AppError> {
    match pool.get().await {
        Ok(conn) => Ok(conn),
        Err(e) => {
            // L-3: Classify errors structurally instead of string matching.
            let (category, detail) = classify_pool_error(&e);
            tracing::error!(
                "Database {} in sandbox mode: {}. Triggering graceful shutdown for respawn.",
                category,
                detail
            );
            // M-8/M-10: Trigger graceful shutdown instead of exit().
            if let Some(handle) = server_handle {
                handle.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
            }
            Err(crate::error::AppError::Internal(anyhow::anyhow!(
                "Database {} in sandbox mode: {}", category, detail
            )))
        }
    }
}

/// Classify a pool error into a human-readable category and detail message.
///
/// L-3: This replaces the former string-based error detection function which relied
/// on fragile substring matching. By pattern-matching on the structured `PoolError`
/// variants from deadpool/diesel-async, we get reliable classification that
/// won't break when upstream libraries change their error messages.
fn classify_pool_error(
    error: &diesel_async::pooled_connection::deadpool::PoolError,
) -> (&'static str, String) {
    use deadpool::managed::{PoolError, TimeoutType};
    use diesel_async::pooled_connection::PoolError as DieselPoolError;

    match error {
        PoolError::Backend(DieselPoolError::ConnectionError(e)) => {
            ("connection lost", format!("backend connection error: {e}"))
        }
        PoolError::Backend(DieselPoolError::QueryError(e)) => {
            ("connection lost", format!("backend query/ping error: {e}"))
        }
        PoolError::Timeout(TimeoutType::Wait) => (
            "pool exhausted",
            "timed out waiting for an available connection".to_string(),
        ),
        PoolError::Timeout(TimeoutType::Create) => (
            "connection timeout",
            "timed out creating a new connection".to_string(),
        ),
        PoolError::Timeout(TimeoutType::Recycle) => (
            "connection timeout",
            "timed out recycling a connection".to_string(),
        ),
        PoolError::Closed => ("pool closed", "connection pool has been closed".to_string()),
        PoolError::NoRuntimeSpecified => (
            "configuration error",
            "no async runtime specified for pool".to_string(),
        ),
        PoolError::PostCreateHook(hook_err) => (
            "connection hook failed",
            format!("post-create hook error: {hook_err}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Type Alias Tests ====================

    #[test]
    fn test_db_pool_type_exists() {
        // Verify DbPool type alias compiles correctly
        fn _check_type(_pool: &DbPool) {}
    }

    #[test]
    fn test_db_connection_type_exists() {
        // Verify DbConnection type alias compiles correctly
        fn _check_type(_conn: &DbConnection) {}
    }

    // ==================== Sandbox Mode Tests ====================

    #[test]
    fn test_exit_code_connection_lost_value() {
        assert_eq!(EXIT_CODE_CONNECTION_LOST, 100);
    }

    // ==================== L-3: Structural Pool Error Classification ====================

    use deadpool::managed::{PoolError, TimeoutType};
    use diesel_async::pooled_connection::PoolError as DieselPoolError;

    /// Helper to build a PoolError::Backend(ConnectionError(...)) for testing.
    fn make_connection_error(
        msg: &str,
    ) -> diesel_async::pooled_connection::deadpool::PoolError {
        PoolError::Backend(DieselPoolError::ConnectionError(
            diesel::result::ConnectionError::BadConnection(msg.to_string()),
        ))
    }

    /// Helper to build a PoolError::Backend(QueryError(...)) for testing.
    fn make_query_error() -> diesel_async::pooled_connection::deadpool::PoolError {
        PoolError::Backend(DieselPoolError::QueryError(
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::Unknown,
                Box::new("connection reset by peer".to_string()),
            ),
        ))
    }

    #[test]
    fn test_classify_backend_connection_error() {
        let err = make_connection_error("Connection refused");
        let (category, detail) = classify_pool_error(&err);
        assert_eq!(category, "connection lost");
        assert!(
            detail.contains("backend connection error"),
            "detail: {}",
            detail
        );
    }

    #[test]
    fn test_classify_backend_query_error() {
        let err = make_query_error();
        let (category, detail) = classify_pool_error(&err);
        assert_eq!(category, "connection lost");
        assert!(
            detail.contains("backend query/ping error"),
            "detail: {}",
            detail
        );
    }

    #[test]
    fn test_classify_timeout_wait() {
        let err: diesel_async::pooled_connection::deadpool::PoolError =
            PoolError::Timeout(TimeoutType::Wait);
        let (category, detail) = classify_pool_error(&err);
        assert_eq!(category, "pool exhausted");
        assert!(detail.contains("waiting"), "detail: {}", detail);
    }

    #[test]
    fn test_classify_timeout_create() {
        let err: diesel_async::pooled_connection::deadpool::PoolError =
            PoolError::Timeout(TimeoutType::Create);
        let (category, detail) = classify_pool_error(&err);
        assert_eq!(category, "connection timeout");
        assert!(detail.contains("creating"), "detail: {}", detail);
    }

    #[test]
    fn test_classify_timeout_recycle() {
        let err: diesel_async::pooled_connection::deadpool::PoolError =
            PoolError::Timeout(TimeoutType::Recycle);
        let (category, detail) = classify_pool_error(&err);
        assert_eq!(category, "connection timeout");
        assert!(detail.contains("recycling"), "detail: {}", detail);
    }

    #[test]
    fn test_classify_pool_closed() {
        let err: diesel_async::pooled_connection::deadpool::PoolError = PoolError::Closed;
        let (category, _detail) = classify_pool_error(&err);
        assert_eq!(category, "pool closed");
    }

    #[test]
    fn test_classify_no_runtime() {
        let err: diesel_async::pooled_connection::deadpool::PoolError =
            PoolError::NoRuntimeSpecified;
        let (category, _detail) = classify_pool_error(&err);
        assert_eq!(category, "configuration error");
    }

    // ==================== L-5: LIKE Pattern Escaping Tests ====================

    #[test]
    fn test_escape_like_pattern_no_special_chars() {
        assert_eq!(escape_like_pattern("hello"), "hello");
    }

    #[test]
    fn test_escape_like_pattern_percent() {
        assert_eq!(escape_like_pattern("100%"), "100\\%");
        assert_eq!(escape_like_pattern("%admin%"), "\\%admin\\%");
    }

    #[test]
    fn test_escape_like_pattern_underscore() {
        assert_eq!(escape_like_pattern("user_name"), "user\\_name");
        assert_eq!(escape_like_pattern("_secret"), "\\_secret");
    }

    #[test]
    fn test_escape_like_pattern_backslash() {
        assert_eq!(escape_like_pattern("path\\file"), "path\\\\file");
    }

    #[test]
    fn test_escape_like_pattern_all_special() {
        assert_eq!(escape_like_pattern("%_\\"), "\\%\\_\\\\");
    }

    #[test]
    fn test_escape_like_pattern_empty() {
        assert_eq!(escape_like_pattern(""), "");
    }

    #[test]
    fn test_like_contains_normal() {
        assert_eq!(like_contains("admin"), "%admin%");
    }

    #[test]
    fn test_like_contains_with_wildcards() {
        assert_eq!(like_contains("100%"), "%100\\%%");
        assert_eq!(like_contains("user_1"), "%user\\_1%");
    }

    #[test]
    fn test_like_contains_empty() {
        assert_eq!(like_contains(""), "%%");
    }
}
