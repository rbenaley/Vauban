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

