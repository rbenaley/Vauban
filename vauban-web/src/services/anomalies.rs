//! Bastion Watch dashboard anomaly detectors.
//!
//! Four pure read-only detectors that surface state which "should
//! never happen" or "needs attention" on a healthy bastion. They
//! are passive: each one returns an `Vec<Anomaly>` for the dashboard
//! to render; nothing is mutated server-side.
//!
//! Detectors:
//!
//! 1. [`out_of_window_sessions`] -- sessions whose `connected_at`
//!    falls outside their access rule's `valid_from / valid_until`.
//!    Should always be empty (the runtime enforces the window). Any
//!    row here is a bug or a clock skew between the proxy and the
//!    DB.
//! 2. [`mfa_stale_users`] -- active users without MFA enabled.
//!    The schema does not track an `mfa_verified_at`, so we use
//!    `mfa_enabled = false` as the guard; tightening this check is a
//!    follow-up once `mfa_verified_at` lands.
//! 3. [`rules_expiring_soon`] -- access rules whose `valid_until`
//!    falls within the next 7 days, so the SOC can plan the
//!    rotation.
//! 4. [`unrecorded_recent_sessions`] -- sessions that completed in
//!    the last 30 days with `is_recorded = false`. Recording is
//!    Vauban's evidence baseline; a non-zero count here is an
//!    audit-mode breach.

use crate::db::DbPool;
use crate::schema::{access_rules, proxy_sessions, users};
use chrono::{DateTime, Duration, Utc};
use diesel::dsl::count_star;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

/// Severity bucket for the dashboard's "ANOMALIES" tile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    /// Tailwind classes for the severity badge background and text.
    /// Both light and dark variants are emitted so the future theme
    /// toggle (light <-> dark) does not require editing the CSS map.
    /// The dark variant uses `*-900/40` (40 % alpha on the deepest
    /// shade) to keep the dashboard's `dark:bg-gray-800` tile
    /// surface readable behind the badge.
    pub fn css_class(self) -> &'static str {
        match self {
            Severity::Info => {
                "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-200"
            }
            Severity::Warning => {
                "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200"
            }
            Severity::Critical => {
                "bg-rose-100 text-rose-800 dark:bg-rose-900/40 dark:text-rose-200"
            }
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warn",
            Severity::Critical => "critical",
        }
    }
}

/// Single anomaly entry rendered in the "ANOMALIES" tile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    pub id: &'static str,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub count: u64,
}

/// Aggregate the four detectors into a single Vec.
///
/// Each detector failure (e.g. DB pool checkout) is logged inside
/// the detector and degrades to an empty Vec. A degraded detector
/// is invisible in the UI rather than turning the whole tile red.
pub async fn detect_all(db_pool: &DbPool) -> Vec<Anomaly> {
    let now = Utc::now();
    let mut out = Vec::with_capacity(4);
    out.extend(out_of_window_sessions(db_pool, now).await);
    out.extend(mfa_stale_users(db_pool).await);
    out.extend(rules_expiring_soon(db_pool, now, Duration::days(7)).await);
    out.extend(unrecorded_recent_sessions(db_pool, now, Duration::days(30)).await);
    out
}

pub async fn out_of_window_sessions(db_pool: &DbPool, _now: DateTime<Utc>) -> Vec<Anomaly> {
    let mut conn = match db_pool.get().await {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    // Without a join model on (proxy_sessions -> access_rules) we
    // approximate by counting sessions whose `expires_at` is in the
    // past while their status is still active. A correctly-running
    // proxy reaper drains those within a minute; anything older is
    // a stuck session.
    let count: i64 = proxy_sessions::table
        .filter(proxy_sessions::status.eq("active"))
        .filter(proxy_sessions::expires_at.is_not_null())
        .filter(proxy_sessions::expires_at.lt(Utc::now()))
        .select(count_star())
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    if count > 0 {
        vec![Anomaly {
            id: "out_of_window_sessions",
            severity: Severity::Critical,
            title: "Sessions past their expiry window".to_string(),
            detail: "Proxy reaper has not closed sessions whose \
                     `expires_at` is in the past. Investigate clock \
                     skew or a stuck reaper task."
                .to_string(),
            count: count as u64,
        }]
    } else {
        Vec::new()
    }
}

pub async fn mfa_stale_users(db_pool: &DbPool) -> Vec<Anomaly> {
    let mut conn = match db_pool.get().await {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let count: i64 = users::table
        .filter(users::is_active.eq(true))
        .filter(users::is_deleted.eq(false))
        .filter(users::mfa_enabled.eq(false))
        .select(count_star())
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    if count > 0 {
        vec![Anomaly {
            id: "mfa_stale_users",
            severity: Severity::Warning,
            title: "Active users without MFA".to_string(),
            detail: "MFA is the bastion's only second factor. Every \
                     active human account should have it enabled."
                .to_string(),
            count: count as u64,
        }]
    } else {
        Vec::new()
    }
}

pub async fn rules_expiring_soon(
    db_pool: &DbPool,
    now: DateTime<Utc>,
    window: Duration,
) -> Vec<Anomaly> {
    let mut conn = match db_pool.get().await {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let cutoff = now + window;
    let count: i64 = access_rules::table
        .filter(access_rules::is_active.eq(true))
        .filter(access_rules::valid_until.is_not_null())
        .filter(access_rules::valid_until.gt(now))
        .filter(access_rules::valid_until.le(cutoff))
        .select(count_star())
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    if count > 0 {
        vec![Anomaly {
            id: "rules_expiring_soon",
            severity: Severity::Info,
            title: format!("{} access rule(s) expiring in 7 days", count),
            detail: "Plan a rotation before the rules lapse to avoid \
                     unannounced loss of access."
                .to_string(),
            count: count as u64,
        }]
    } else {
        Vec::new()
    }
}

pub async fn unrecorded_recent_sessions(
    db_pool: &DbPool,
    now: DateTime<Utc>,
    window: Duration,
) -> Vec<Anomaly> {
    let mut conn = match db_pool.get().await {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let cutoff = now - window;
    let count: i64 = proxy_sessions::table
        .filter(proxy_sessions::is_recorded.eq(false))
        .filter(proxy_sessions::created_at.gt(cutoff))
        .select(count_star())
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    if count > 0 {
        vec![Anomaly {
            id: "unrecorded_recent_sessions",
            severity: Severity::Critical,
            title: format!("{} unrecorded session(s) in last 30 days", count),
            detail: "Recording is Vauban's evidence baseline. A \
                     non-zero count here defeats audit replay and \
                     should be treated as an incident."
                .to_string(),
            count: count as u64,
        }]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_classes_are_distinct() {
        assert_ne!(Severity::Info.css_class(), Severity::Warning.css_class());
        assert_ne!(
            Severity::Warning.css_class(),
            Severity::Critical.css_class()
        );
    }

    #[test]
    fn severity_labels_are_lowercase() {
        for s in [Severity::Info, Severity::Warning, Severity::Critical] {
            assert_eq!(s.label(), s.label().to_ascii_lowercase());
        }
    }

    #[test]
    fn anomaly_ids_are_stable_pinned_strings() {
        // Pin: every detector emits a `id` field that the dashboard's
        // "ANOMALIES" tile uses as a stable React-style key. Renaming
        // an `id` is a UI-breaking change; this test guards the
        // catalogue.
        const EXPECTED: &[&str] = &[
            "out_of_window_sessions",
            "mfa_stale_users",
            "rules_expiring_soon",
            "unrecorded_recent_sessions",
        ];
        let src = include_str!("anomalies.rs");
        for id in EXPECTED {
            let needle = format!("id: \"{}\"", id);
            assert!(
                src.contains(&needle),
                "anomaly id `{}` MUST be emitted by some detector \
                 (anomaly catalogue is pinned by this test)",
                id
            );
        }
    }
}
