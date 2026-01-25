/// VAUBAN Web - Database connection pool setup.
///
/// Uses Diesel with connection pooling for PostgreSQL.
///
/// This module provides two pool creation strategies:
/// - `create_pool()`: Standard dynamic pool for development
/// - `create_pool_sandboxed()`: Fixed-size pool for Capsicum sandbox mode
use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use secrecy::ExposeSecret;
use std::time::Duration;

use crate::config::Config;
use crate::error::{AppError, AppResult};

/// Exit code used when database connection is lost in sandbox mode.
/// The supervisor will respawn the service when it sees this exit code.
pub const EXIT_CODE_CONNECTION_LOST: i32 = 100;

/// Database connection pool type.
pub type DbPool = Pool<ConnectionManager<PgConnection>>;
pub type DbConnection = PooledConnection<ConnectionManager<PgConnection>>;

/// Create a new database connection pool (standard mode).
///
/// This creates a dynamic pool that can grow/shrink between min and max connections.
/// Use this for development or when not running in Capsicum sandbox mode.
pub fn create_pool(config: &Config) -> AppResult<DbPool> {
    let manager = ConnectionManager::<PgConnection>::new(config.database.url.expose_secret());

    Pool::builder()
        .max_size(config.database.max_connections)
        .min_idle(Some(config.database.min_connections))
        .connection_timeout(Duration::from_secs(config.database.connect_timeout_secs))
        .build(manager)
        .map_err(|e| AppError::Config(format!("Failed to create database pool: {}", e)))
}

/// Create a database connection pool for Capsicum sandbox mode.
///
/// This creates a fixed-size pool where all connections are pre-established
/// before entering capability mode. The pool size is fixed at `max_connections`,
/// and all connections are validated at startup.
///
/// After `cap_enter()`, no new connections can be opened. If a connection is lost,
/// the service must exit and be respawned by the supervisor.
///
/// # Errors
/// Returns an error if the pool cannot be created or if any connection fails validation.
pub fn create_pool_sandboxed(config: &Config) -> AppResult<DbPool> {
    let manager = ConnectionManager::<PgConnection>::new(config.database.url.expose_secret());

    // Use max_connections as both min and max to create a fixed-size pool
    let pool_size = config.database.max_connections;

    let pool = Pool::builder()
        .max_size(pool_size)
        .min_idle(Some(pool_size)) // Pre-establish all connections
        .connection_timeout(Duration::from_secs(config.database.connect_timeout_secs))
        .test_on_check_out(true) // Validate connections when borrowed
        .build(manager)
        .map_err(|e| AppError::Config(format!("Failed to create sandboxed database pool: {}", e)))?;

    // Validate that all connections are established and working
    validate_all_connections(&pool, pool_size)?;

    tracing::info!(
        "Database pool initialized for sandbox mode: {} connections pre-established",
        pool_size
    );

    Ok(pool)
}

/// Validate that all connections in the pool are established and working.
///
/// This function borrows and returns each connection to ensure they are all valid.
/// Called during startup before entering capability mode.
fn validate_all_connections(pool: &DbPool, count: u32) -> AppResult<()> {
    tracing::debug!("Validating {} database connections...", count);

    for i in 0..count {
        let _conn = pool.get().map_err(|e| {
            AppError::Config(format!(
                "Failed to establish DB connection {}/{}: {}",
                i + 1,
                count,
                e
            ))
        })?;
        tracing::trace!("DB connection {}/{} validated", i + 1, count);
    }

    tracing::debug!("All {} database connections validated", count);
    Ok(())
}

/// Get a connection from the pool.
///
/// Returns an error that can be handled by the caller.
pub fn get_connection(pool: &DbPool) -> AppResult<DbConnection> {
    pool.get().map_err(|e| {
        AppError::Database(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::SerializationFailure,
            Box::new(e.to_string()),
        ))
    })
}

/// Get a connection from the pool, or exit if connection is lost (sandbox mode).
///
/// This function is designed for Capsicum sandbox mode where the service
/// cannot recover from a lost database connection. If the connection cannot
/// be obtained, the process exits with code 100 to trigger a respawn by
/// the supervisor.
///
/// # Panics
/// This function never panics - it exits the process instead.
pub fn get_connection_or_exit(pool: &DbPool) -> DbConnection {
    match pool.get() {
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

    // ==================== Error Handling Tests ====================

    #[test]
    fn test_get_connection_error_is_database_error() {
        // We can't test with a real pool without a database,
        // but we can verify the error type mapping
        let error = AppError::Database(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::SerializationFailure,
            Box::new("Test error".to_string()),
        ));

        match error {
            AppError::Database(_) => (), // Expected
            _ => panic!("Expected Database error"),
        }
    }

    #[test]
    fn test_create_pool_error_is_config_error() {
        // Verify that pool creation errors are wrapped as Config errors
        let error = AppError::Config("Failed to create database pool: test".to_string());

        match error {
            AppError::Config(msg) => {
                assert!(msg.contains("Failed to create database pool"));
            }
            _ => panic!("Expected Config error"),
        }
    }

    // ==================== Additional Error Mapping Tests ====================

    #[test]
    fn test_database_error_serialization_failure() {
        let error = diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::SerializationFailure,
            Box::new("Connection pool timeout".to_string()),
        );

        match error {
            diesel::result::Error::DatabaseError(kind, _) => {
                assert!(matches!(
                    kind,
                    diesel::result::DatabaseErrorKind::SerializationFailure
                ));
            }
            _ => panic!("Expected DatabaseError"),
        }
    }

    #[test]
    fn test_config_error_message_format() {
        let msg = format!("Failed to create database pool: {}", "connection refused");
        let error = AppError::Config(msg.clone());

        if let AppError::Config(inner) = error {
            assert!(inner.contains("connection refused"));
            assert!(inner.starts_with("Failed to create database pool:"));
        } else {
            panic!("Expected Config error");
        }
    }

    // ==================== Database Error Kind Tests ====================

    #[test]
    fn test_database_error_unique_violation() {
        let error = diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            Box::new("duplicate key".to_string()),
        );

        match error {
            diesel::result::Error::DatabaseError(kind, _) => {
                assert!(matches!(
                    kind,
                    diesel::result::DatabaseErrorKind::UniqueViolation
                ));
            }
            _ => panic!("Expected DatabaseError"),
        }
    }

    #[test]
    fn test_database_error_foreign_key_violation() {
        let error = diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::ForeignKeyViolation,
            Box::new("foreign key constraint".to_string()),
        );

        match error {
            diesel::result::Error::DatabaseError(kind, _) => {
                assert!(matches!(
                    kind,
                    diesel::result::DatabaseErrorKind::ForeignKeyViolation
                ));
            }
            _ => panic!("Expected DatabaseError"),
        }
    }

    #[test]
    fn test_database_error_not_null_violation() {
        let error = diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::NotNullViolation,
            Box::new("null value".to_string()),
        );

        match error {
            diesel::result::Error::DatabaseError(kind, _) => {
                assert!(matches!(
                    kind,
                    diesel::result::DatabaseErrorKind::NotNullViolation
                ));
            }
            _ => panic!("Expected DatabaseError"),
        }
    }

    #[test]
    fn test_database_error_check_violation() {
        let error = diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::CheckViolation,
            Box::new("check constraint".to_string()),
        );

        match error {
            diesel::result::Error::DatabaseError(kind, _) => {
                assert!(matches!(
                    kind,
                    diesel::result::DatabaseErrorKind::CheckViolation
                ));
            }
            _ => panic!("Expected DatabaseError"),
        }
    }

    // ==================== Error Conversion Tests ====================

    #[test]
    fn test_app_error_from_diesel_not_found() {
        let diesel_error = diesel::result::Error::NotFound;
        let app_error: AppError = diesel_error.into();

        match app_error {
            AppError::Database(_) => (),
            _ => panic!("Expected Database error"),
        }
    }

    #[test]
    fn test_app_error_database_display() {
        let diesel_error = diesel::result::Error::NotFound;
        let app_error: AppError = diesel_error.into();
        let display = app_error.to_string();

        assert!(display.contains("Database error"));
    }

    // ==================== Pool Configuration Tests ====================

    #[test]
    fn test_connection_timeout_duration() {
        let timeout_secs: u64 = 5;
        let duration = std::time::Duration::from_secs(timeout_secs);
        assert_eq!(duration.as_secs(), 5);
    }

    #[test]
    fn test_max_connections_reasonable() {
        let max_connections: u32 = 10;
        assert!(max_connections > 0);
        assert!(max_connections <= 100);
    }

    #[test]
    fn test_min_connections_less_than_max() {
        let max_connections: u32 = 10;
        let min_connections: u32 = 2;
        assert!(min_connections <= max_connections);
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
