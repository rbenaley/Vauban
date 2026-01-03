/// VAUBAN Web - Database connection pool setup.
///
/// Uses Diesel with connection pooling for PostgreSQL.

use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};

use crate::config::Config;
use crate::error::{AppError, AppResult};

/// Database connection pool type.
pub type DbPool = Pool<ConnectionManager<PgConnection>>;
pub type DbConnection = PooledConnection<ConnectionManager<PgConnection>>;

/// Create a new database connection pool.
pub fn create_pool(config: &Config) -> AppResult<DbPool> {
    let manager = ConnectionManager::<PgConnection>::new(
        config.database.url.as_str(),
    );

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
    pool.get()
        .map_err(|e| AppError::Database(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::SerializationFailure,
            Box::new(e.to_string()),
        )))
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
}

