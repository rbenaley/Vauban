//! Capsicum-safe Postgres pool for the sealed mailer leaf.
//!
//! Local copy of `vauban-access/src/db.rs` (no shared Diesel surface).
//! All connections MUST be force-created BEFORE `cap_enter()`.

use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::{Object, Pool};

/// Fixed pool size: two concurrent drain / retry sockets.
pub const MAILER_POOL_SIZE: usize = 2;

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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    // Unix socket that cannot exist: connect() returns ENOENT immediately
    // (unlike 127.0.0.1:1, which can sit in TCP SYN timeout for tens of seconds).
    const DEAD_URL: &str = "postgres:///?host=/tmp/vauban-mailer-no-such.sock";

    #[test]
    fn mailer_pool_size_is_two() {
        assert_eq!(MAILER_POOL_SIZE, 2);
    }

    #[test]
    fn create_pool_sandboxed_is_lazy_on_dead_url() {
        let pool =
            create_pool_sandboxed(DEAD_URL, MAILER_POOL_SIZE).expect("builder must not connect");
        assert_eq!(pool.status().max_size, MAILER_POOL_SIZE);
    }

    #[tokio::test]
    async fn force_create_zero_is_ok() {
        let pool = create_pool_sandboxed(DEAD_URL, MAILER_POOL_SIZE).expect("pool");
        force_create_all_connections(&pool, 0)
            .await
            .expect("count 0 must not connect");
    }

    async fn connect_must_fail_fast<F, Fut>(fut: F)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<()>>,
    {
        tokio::time::timeout(std::time::Duration::from_secs(2), fut())
            .await
            .expect("dead unix socket must fail within 2s")
            .expect_err("warm-up must fail");
    }

    #[tokio::test]
    async fn get_connection_on_dead_url_errors() {
        let pool = create_pool_sandboxed(DEAD_URL, 1).expect("pool");
        tokio::time::timeout(std::time::Duration::from_secs(2), get_connection(&pool))
            .await
            .expect("dead unix socket must fail within 2s")
            .err()
            .expect("get must connect and fail");
    }

    #[tokio::test]
    async fn force_create_on_dead_url_errors() {
        let pool = create_pool_sandboxed(DEAD_URL, MAILER_POOL_SIZE).expect("pool");
        connect_must_fail_fast(|| async { force_create_all_connections(&pool, 1).await }).await;
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(8))]

        #[test]
        fn force_create_count_is_total_on_dead_url(n in 0u8..=4) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("rt");
            let pool = create_pool_sandboxed(DEAD_URL, 4).expect("pool");
            let result = rt.block_on(async {
                tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    force_create_all_connections(&pool, n as usize),
                )
                .await
                .expect("dead unix socket must fail within 2s")
            });
            if n == 0 {
                proptest::prop_assert!(result.is_ok());
            } else {
                proptest::prop_assert!(result.is_err());
            }
        }
    }

    #[test]
    fn battle_force_create_dead_url_under_contention() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("rt");
                let pool = create_pool_sandboxed(DEAD_URL, 1).expect("pool");
                barrier.wait();
                rt.block_on(async {
                    tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        force_create_all_connections(&pool, 1),
                    )
                    .await
                    .expect("dead unix socket must fail within 2s")
                    .expect_err("dead URL must fail")
                })
            }));
        }
        for h in handles {
            h.join().expect("battle thread");
        }
    }
}
