use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::{Object, Pool};

pub type DbPool = Pool<AsyncPgConnection>;
pub type DbConnection = Object<AsyncPgConnection>;

/// Create a database connection pool for Capsicum sandbox mode.
///
/// All connections are pre-established before entering capability mode.
/// After `cap_enter()`, no new connections can be opened.
pub fn create_pool_sandboxed(database_url: &str, pool_size: usize) -> anyhow::Result<DbPool> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);

    let pool = Pool::builder(manager)
        .max_size(pool_size)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to create database pool: {}", e))?;

    Ok(pool)
}

/// Force creation of all connections by borrowing them simultaneously.
///
/// Must be called BEFORE `cap_enter()` since no new connections can be created
/// after entering the Capsicum sandbox.
pub async fn force_create_all_connections(pool: &DbPool, count: usize) -> anyhow::Result<()> {
    tracing::debug!("Force-creating {} database connections...", count);

    let mut connections = Vec::with_capacity(count);
    for i in 0..count {
        let conn = pool.get().await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to establish DB connection {}/{}: {}",
                i + 1,
                count,
                e
            )
        })?;
        connections.push(conn);
    }

    tracing::debug!("All {} database connections created and validated", count);
    drop(connections);

    Ok(())
}

/// Get a connection from the pool.
pub async fn get_connection(pool: &DbPool) -> anyhow::Result<DbConnection> {
    pool.get()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get database connection: {}", e))
}
