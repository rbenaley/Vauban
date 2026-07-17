//! Deterministic JIT grant lifecycle transitions.
//!
//! Callers inject `now`, which keeps cleanup behavior testable without sleeps
//! or dependence on wall-clock timing.

use chrono::{DateTime, Duration, Utc};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;

use crate::db::DbPool;
use crate::schema::proxy_sessions;

/// Expire pending grants older than `ttl_hours`.
///
/// Only `status` and `updated_at` are mutated. Requester, creation time,
/// credential sentinel and connection timestamps remain immutable audit facts.
pub async fn expire_stale_pending_requests_at(
    db_pool: &DbPool,
    now: DateTime<Utc>,
    ttl_hours: i64,
) -> Result<usize, String> {
    let mut conn = db_pool.get().await.map_err(|e| e.to_string())?;
    let cutoff = now - Duration::hours(ttl_hours);

    diesel::update(
        proxy_sessions::table
            .filter(proxy_sessions::status.eq("pending"))
            .filter(proxy_sessions::created_at.lt(cutoff)),
    )
    .set((
        proxy_sessions::status.eq("expired"),
        proxy_sessions::updated_at.eq(now),
    ))
    .execute(&mut conn)
    .await
    .map_err(|e| e.to_string())
}

/// Expire approved grants whose explicit validity horizon has passed.
pub async fn expire_stale_approved_sessions_at(
    db_pool: &DbPool,
    now: DateTime<Utc>,
) -> Result<usize, String> {
    let mut conn = db_pool.get().await.map_err(|e| e.to_string())?;

    diesel::update(
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
    .map_err(|e| e.to_string())
}
