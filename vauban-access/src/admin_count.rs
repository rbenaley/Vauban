//! Boot-time and periodic warning about mono-admin deployments.
//!
//! Why this module exists
//! ----------------------
//! The Approval Audit & Separation of Duties feature enforces a hard
//! invariant: an admin can never decide on their own request. In a
//! deployment with a SINGLE admin, that admin will be unable to obtain
//! JIT access to anything that requires approval -- they'd have to
//! either request access for someone else to approve, or disable the
//! `require_approval` rule (and lose audit coverage).
//!
//! That degraded mode is operationally correct (we'd rather lock the
//! single admin out than let them self-approve) but it is silent
//! unless we surface it. This module:
//!
//! 1. Counts admins at boot (best-effort, after the sandbox closes
//!    is too late, so we run it just before).
//! 2. Spawns a background task that re-counts every 30 minutes and
//!    emits a `WARN` if the count is < 2.
//!
//! Auto-detection: there is no opt-in flag. Every deployment is
//! checked. Operators who knowingly run mono-admin can suppress the
//! WARN with a tracing filter; we'd rather they see the noise.

use crate::db::DbPool;
use crate::schema::users;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use std::time::Duration;
use tracing::{info, warn};

/// Admins below which we emit the WARN. The invariant is "any admin
/// can be excluded from a decision because they are the requester",
/// so we need at least TWO active admins for the system to work
/// end-to-end without manual operator intervention.
pub const MIN_ADMINS_FOR_HEALTHY_SOD: i64 = 2;

/// Period between background re-counts. 30 min is a sweet spot:
/// short enough that an operator who just disabled the second admin
/// sees the WARN within an SRE rotation, long enough that the noise
/// stays manageable.
pub const RECHECK_PERIOD: Duration = Duration::from_secs(30 * 60);

/// Boot-time check. Returns the admin count for logging by the
/// caller. Never fails the boot -- a degraded SoD posture is a
/// warning, not a hard error.
pub async fn check_at_boot(pool: &DbPool) -> i64 {
    let count = count_admins(pool).await.unwrap_or(-1);
    log_count(count);
    count
}

/// Spawn the background re-checker. Owns its own pool clone (cheap;
/// `DbPool` is `Arc` under the hood).
pub fn spawn_periodic(pool: DbPool) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(RECHECK_PERIOD);
        // Skip the first immediate tick: we already logged at boot.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let count = count_admins(&pool).await.unwrap_or(-1);
            log_count(count);
        }
    });
}

async fn count_admins(pool: &DbPool) -> Result<i64, String> {
    let mut conn = pool.get().await.map_err(|e| e.to_string())?;
    users::table
        .filter(users::is_active.eq(true))
        .filter(users::is_deleted.eq(false))
        .filter(
            users::is_superuser
                .eq(true)
                .or(users::is_staff.eq(true)),
        )
        .select(diesel::dsl::count_star())
        .first::<i64>(&mut conn)
        .await
        .map_err(|e| e.to_string())
}

fn log_count(count: i64) {
    if count < 0 {
        warn!(
            "admin_count: failed to count admins; cannot determine whether \
             separation-of-duties has enough headroom. Will retry."
        );
    } else if count < MIN_ADMINS_FOR_HEALTHY_SOD {
        warn!(
            admin_count = count,
            min_required = MIN_ADMINS_FOR_HEALTHY_SOD,
            "MONO-ADMIN DEPLOYMENT DETECTED: separation-of-duties is enforced \
             (admins cannot decide on their own JIT requests), so a single \
             admin cannot obtain access to assets that require approval. \
             Recommended: provision a second admin (is_staff=true OR \
             is_superuser=true). See docs/runbooks/approval_audit.md."
        );
    } else {
        info!(
            admin_count = count,
            "admin_count: healthy ({} >= {} admins)",
            count,
            MIN_ADMINS_FOR_HEALTHY_SOD
        );
    }
}
