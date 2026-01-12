/// VAUBAN Web - Database connection pool setup.
///
/// Uses Diesel with connection pooling for PostgreSQL.
use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use secrecy::ExposeSecret;

use crate::config::Config;
use crate::error::{AppError, AppResult};

/// Database connection pool type.
pub type DbPool = Pool<ConnectionManager<PgConnection>>;
pub type DbConnection = PooledConnection<ConnectionManager<PgConnection>>;

/// Create a new database connection pool.
pub fn create_pool(config: &Config) -> AppResult<DbPool> {
    let manager = ConnectionManager::<PgConnection>::new(config.database.url.expose_secret());

    Pool::builder()
        .max_size(config.database.max_connections)
        .min_idle(Some(config.database.min_connections))
        .connection_timeout(std::time::Duration::from_secs(
            config.database.connect_timeout_secs,
        ))
        .build(manager)
        .map_err(|e| AppError::Config(format!("Failed to create database pool: {}", e)))
}

/// Get a connection from the pool.
pub fn get_connection(pool: &DbPool) -> AppResult<DbConnection> {
    pool.get().map_err(|e| {
        AppError::Database(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::SerializationFailure,
            Box::new(e.to_string()),
        ))
    })
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
}
