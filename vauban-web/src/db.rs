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

/// Get a connection from the pool.
///
/// Returns an error that can be handled by the caller.
pub async fn get_connection(pool: &DbPool) -> AppResult<DbConnection> {
    pool.get().await.map_err(|e| {
        AppError::Internal(anyhow::anyhow!("Failed to get database connection: {}", e))
    })
}

/// Get a connection from the pool, or exit if connection is lost (sandbox mode).
///
/// This function is designed for Capsicum sandbox mode where the service
/// cannot recover from a lost database connection. If the connection cannot
/// be obtained, the process exits with code 100 to trigger a respawn by
/// the supervisor.
pub async fn get_connection_or_exit(pool: &DbPool) -> DbConnection {
    match pool.get().await {
        Ok(conn) => conn,
        Err(e) => {
            let error_msg = e.to_string();
            if is_connection_lost(&error_msg) {
                tracing::error!(
                    "Database connection lost in sandbox mode: {}. Exiting for respawn.",
                    error_msg
                );
            } else {
                tracing::error!(
                    "Database pool error in sandbox mode: {}. Exiting for respawn.",
                    error_msg
                );
            }
            std::process::exit(EXIT_CODE_CONNECTION_LOST);
        }
    }
}

/// Check if an error message indicates a lost connection.
///
/// This is used to provide more specific logging when a connection is lost
/// versus other pool errors.
fn is_connection_lost(error_msg: &str) -> bool {
    let msg = error_msg.to_lowercase();
    msg.contains("connection")
        || msg.contains("closed")
        || msg.contains("refused")
        || msg.contains("timeout")
        || msg.contains("timed out")
        || msg.contains("reset")
        || msg.contains("broken pipe")
        || msg.contains("network")
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

    #[test]
    fn test_is_connection_lost_connection_refused() {
        assert!(is_connection_lost("Connection refused"));
        assert!(is_connection_lost("connection refused by server"));
    }

    #[test]
    fn test_is_connection_lost_closed() {
        assert!(is_connection_lost("Connection closed"));
        assert!(is_connection_lost("connection closed by peer"));
    }

    #[test]
    fn test_is_connection_lost_timeout() {
        assert!(is_connection_lost("Connection timeout"));
        assert!(is_connection_lost("operation timed out"));
    }

    #[test]
    fn test_is_connection_lost_reset() {
        assert!(is_connection_lost("Connection reset by peer"));
        assert!(is_connection_lost("ECONNRESET"));
    }

    #[test]
    fn test_is_connection_lost_broken_pipe() {
        assert!(is_connection_lost("Broken pipe"));
        assert!(is_connection_lost("broken pipe error"));
    }

    #[test]
    fn test_is_connection_lost_network() {
        assert!(is_connection_lost("Network unreachable"));
        assert!(is_connection_lost("network is down"));
    }

    #[test]
    fn test_is_connection_lost_false_for_other_errors() {
        assert!(!is_connection_lost("duplicate key violation"));
        assert!(!is_connection_lost("syntax error"));
        assert!(!is_connection_lost("permission denied"));
    }

    #[test]
    fn test_is_connection_lost_case_insensitive() {
        assert!(is_connection_lost("CONNECTION REFUSED"));
        assert!(is_connection_lost("Timeout occurred"));
        assert!(is_connection_lost("NETWORK ERROR"));
    }
}
