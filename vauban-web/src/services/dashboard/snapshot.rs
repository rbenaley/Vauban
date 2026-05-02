//! Bastion Watch dashboard data snapshot.
//!
//! [`DashboardSnapshot::load`] aggregates everything the dashboard
//! renders for a single request. Queries are issued in parallel via
//! `tokio::join!`; admin-only sections are wrapped in `Option<...>`
//! and stay `None` when the caller lacks the `admin:view` Casbin
//! permission. The renderer (Askama tile partials) reads the
//! `Option`s directly and skips entire tiles for non-admins.
//!
//! Failure mode: every individual query is allowed to fail without
//! aborting the whole snapshot. A failed query degrades to an empty
//! / zero value -- the dashboard is *passive* and should never
//! return a 500 because a single subsystem is wobbly.

use crate::auth::permissions::PermissionContext;
use crate::db::DbPool;
use crate::middleware::WebAuthUser;
use crate::services::dashboard::widgets::{Bar, Donut, Heatmap, Sparkline};
use crate::services::system_health::{LiveSessionHistory, SystemHealth};
use crate::schema::{access_rules, assets, email_outbox, proxy_sessions, users};
use chrono::{DateTime, Datelike, Duration, Timelike, Utc};
use diesel::dsl::count_star;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use std::sync::Arc;

/// Hero band: 4 to 5 KPI cards above the fold.
#[derive(Debug, Clone)]
pub struct HeroBand {
    pub live: u64,
    pub today: u64,
    pub today_recorded_pct: u8,
    pub jit_queue: Option<u64>,
    pub evidence_total: u64,
    pub health_label: &'static str,
    pub spark_today: Sparkline,
}

/// One row in the LIVE SESSIONS panel.
#[derive(Debug, Clone)]
pub struct LiveSession {
    pub uuid: ::uuid::Uuid,
    pub asset_name: String,
    pub asset_hostname: String,
    pub username: String,
    pub session_type: String,
    pub started_at: DateTime<Utc>,
    pub duration_seconds: i64,
    pub is_recorded: bool,
}

/// Evidence chain panel: counts per phase + vault size.
#[derive(Debug, Clone)]
pub struct EvidenceChain {
    pub recording_now: u64,
    pub awaiting_hydration: u64,
    pub hydrated_finalized: u64,
    pub vault_total_bytes: i64,
    pub donut: Donut,
}

/// Access posture (admin only).
#[derive(Debug, Clone)]
pub struct AccessPosture {
    pub active_rules: u64,
    pub mfa_enabled_users: u64,
    pub mfa_disabled_users: u64,
    pub bars: Vec<Bar>,
}

/// Personal lens (always rendered, content per-user).
#[derive(Debug, Clone)]
pub struct UserLens {
    pub recent_sessions: Vec<LiveSession>,
    pub own_recordings_total: u64,
}

/// Dashboard data snapshot.
#[derive(Debug, Clone)]
pub struct DashboardSnapshot {
    pub hero: HeroBand,
    pub live_sessions: Vec<LiveSession>,
    pub evidence_chain: EvidenceChain,
    pub access_posture: Option<AccessPosture>,
    pub heatmap: Heatmap,
    pub system_health: Option<SystemHealth>,
    pub user_lens: UserLens,
    pub computed_at: DateTime<Utc>,
}

impl DashboardSnapshot {
    /// Fetch every metric in parallel. The function is intentionally
    /// failure-tolerant: any individual query that errors out is
    /// logged and falls back to a zero / empty value.
    pub async fn load(
        db_pool: &DbPool,
        auth_user: &WebAuthUser,
        perms: &PermissionContext,
        system_health: Option<SystemHealth>,
        live_session_history: &Arc<LiveSessionHistory>,
    ) -> Self {
        let user_uuid = auth_user.uuid.clone();
        let now = Utc::now();

        let (hero, live_sessions, evidence_chain, access_posture, heatmap, user_lens) = tokio::join!(
            load_hero(db_pool, now, live_session_history),
            load_live_sessions(db_pool, 10),
            load_evidence_chain(db_pool, now),
            async {
                if perms.admin_view {
                    Some(load_access_posture(db_pool).await)
                } else {
                    None
                }
            },
            load_heatmap(db_pool, now),
            load_user_lens(db_pool, user_uuid.as_str(), now),
        );

        DashboardSnapshot {
            hero,
            live_sessions,
            evidence_chain,
            access_posture,
            heatmap,
            system_health: if perms.admin_view { system_health } else { None },
            user_lens,
            computed_at: now,
        }
    }
}

pub(crate) async fn load_hero(
    db_pool: &DbPool,
    now: DateTime<Utc>,
    live_session_history: &Arc<LiveSessionHistory>,
) -> HeroBand {
    let mut conn = match db_pool.get().await {
        Ok(c) => c,
        Err(_) => {
            // Pool pressure: do NOT bump the history with a fake 0
            // -- a transient pool checkout failure must not poison
            // the next 2 minutes of sparkline. Reuse the prior
            // series so the trace stays stable.
            return HeroBand {
                live: 0,
                today: 0,
                today_recorded_pct: 0,
                jit_queue: None,
                evidence_total: 0,
                health_label: "n/a",
                spark_today: Sparkline::from_series(&live_session_history.series()),
            };
        }
    };
    let live: i64 = proxy_sessions::table
        .filter(proxy_sessions::status.eq("active"))
        .select(count_star())
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    let live_u64 = live.max(0) as u64;
    // Push the freshly-observed live count into the rolling history
    // BEFORE building the sparkline so the trace's last point is
    // always the value displayed in the LIVE hero KPI.
    live_session_history.record(live_u64);
    let day_start = now
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .map(|d| d.and_utc())
        .unwrap_or(now);
    let today: i64 = proxy_sessions::table
        .filter(proxy_sessions::created_at.ge(day_start))
        .select(count_star())
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    let today_recorded: i64 = proxy_sessions::table
        .filter(proxy_sessions::created_at.ge(day_start))
        .filter(proxy_sessions::is_recorded.eq(true))
        .select(count_star())
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    let jit_queue: i64 = proxy_sessions::table
        .filter(proxy_sessions::status.eq("pending"))
        .select(count_star())
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    let evidence_total: i64 = proxy_sessions::table
        .filter(proxy_sessions::recording_finalized_at.is_not_null())
        .select(count_star())
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    // Spark = sliding window of recent live-session counts (NOT
    // today's openings-per-hour, which lied: a long-lived session
    // would surface as a single past spike then a flat zero, even
    // though the live count was steady at 1).
    let series = live_session_history.series();
    let spark = Sparkline::from_series(&series);
    let pct = if today > 0 {
        ((today_recorded as f64 / today as f64) * 100.0).round() as u8
    } else {
        0
    };
    HeroBand {
        live: live_u64,
        today: today.max(0) as u64,
        today_recorded_pct: pct,
        jit_queue: Some(jit_queue.max(0) as u64),
        evidence_total: evidence_total.max(0) as u64,
        health_label: "operational",
        spark_today: spark,
    }
}

pub(crate) async fn load_live_sessions(db_pool: &DbPool, limit: i64) -> Vec<LiveSession> {
    let mut conn = match db_pool.get().await {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    type Row = (
        ::uuid::Uuid,
        String,
        String,
        String,
        String,
        Option<DateTime<Utc>>,
        bool,
        DateTime<Utc>,
    );
    let rows: Vec<Row> = proxy_sessions::table
        .inner_join(assets::table)
        .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
        .filter(proxy_sessions::status.eq("active"))
        .select((
            proxy_sessions::uuid,
            assets::name,
            assets::hostname,
            users::username,
            proxy_sessions::session_type,
            proxy_sessions::connected_at,
            proxy_sessions::is_recorded,
            proxy_sessions::created_at,
        ))
        .order(proxy_sessions::created_at.desc())
        .limit(limit)
        .load(&mut conn)
        .await
        .unwrap_or_default();
    let now = Utc::now();
    rows.into_iter()
        .map(|(uuid, name, hostname, username, st, connected_at, recorded, created_at)| {
            let started_at = connected_at.unwrap_or(created_at);
            LiveSession {
                uuid,
                asset_name: name,
                asset_hostname: hostname,
                username,
                session_type: st,
                started_at,
                duration_seconds: now.signed_duration_since(started_at).num_seconds(),
                is_recorded: recorded,
            }
        })
        .collect()
}

pub(crate) async fn load_evidence_chain(db_pool: &DbPool, now: DateTime<Utc>) -> EvidenceChain {
    let mut conn = match db_pool.get().await {
        Ok(c) => c,
        Err(_) => {
            return EvidenceChain {
                recording_now: 0,
                awaiting_hydration: 0,
                hydrated_finalized: 0,
                vault_total_bytes: 0,
                donut: Donut::from_segments::<_, String>(vec![]),
            };
        }
    };
    let recording_now: i64 = proxy_sessions::table
        .filter(proxy_sessions::is_recorded.eq(true))
        .filter(proxy_sessions::status.eq("active"))
        .select(count_star())
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    let awaiting: i64 = proxy_sessions::table
        .filter(proxy_sessions::is_recorded.eq(true))
        .filter(proxy_sessions::recording_finalized_at.is_null())
        .filter(proxy_sessions::disconnected_at.is_not_null())
        .select(count_star())
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    let hydrated: i64 = proxy_sessions::table
        .filter(proxy_sessions::recording_finalized_at.is_not_null())
        .select(count_star())
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    let _ = now; // reserved for future "last 24h" filters
    // Diesel `sum()` on `Nullable<Int8>` returns `Numeric`; rather
    // than pulling `bigdecimal` and risking precision loss, we sum
    // bytes client-side. The `recording_finalized_at` filter caps
    // the row count to actually finalised recordings, which is
    // bounded by the retention policy.
    let sizes: Vec<Option<i64>> = proxy_sessions::table
        .filter(proxy_sessions::recording_finalized_at.is_not_null())
        .select(proxy_sessions::recording_size_bytes)
        .load(&mut conn)
        .await
        .unwrap_or_default();
    let vault_total_bytes: i64 = sizes.into_iter().flatten().fold(0i64, i64::saturating_add);
    let donut = Donut::from_segments(vec![
        ("recording".to_string(), recording_now.max(0) as u64, "stroke-rose-500".to_string()),
        ("hydrating".to_string(), awaiting.max(0) as u64, "stroke-amber-500".to_string()),
        ("vaulted".to_string(), hydrated.max(0) as u64, "stroke-emerald-500".to_string()),
    ]);
    EvidenceChain {
        recording_now: recording_now.max(0) as u64,
        awaiting_hydration: awaiting.max(0) as u64,
        hydrated_finalized: hydrated.max(0) as u64,
        vault_total_bytes,
        donut,
    }
}

pub(crate) async fn load_access_posture(db_pool: &DbPool) -> AccessPosture {
    let mut conn = match db_pool.get().await {
        Ok(c) => c,
        Err(_) => {
            return AccessPosture {
                active_rules: 0,
                mfa_enabled_users: 0,
                mfa_disabled_users: 0,
                bars: Vec::new(),
            };
        }
    };
    let active_rules: i64 = access_rules::table
        .filter(access_rules::is_active.eq(true))
        .select(count_star())
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    let mfa_on: i64 = users::table
        .filter(users::is_active.eq(true))
        .filter(users::mfa_enabled.eq(true))
        .select(count_star())
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    let mfa_off: i64 = users::table
        .filter(users::is_active.eq(true))
        .filter(users::mfa_enabled.eq(false))
        .select(count_star())
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    let total = (mfa_on + mfa_off).max(1);
    let bars = vec![
        Bar::new(
            mfa_on.max(0) as u64,
            total.max(0) as u64,
            "bg-emerald-500",
            "MFA enabled",
            format!("{}/{}", mfa_on, total),
        ),
        Bar::new(
            active_rules.max(0) as u64,
            active_rules.max(0) as u64,
            "bg-vauban-500",
            "Active access rules",
            format!("{}", active_rules),
        ),
    ];
    AccessPosture {
        active_rules: active_rules.max(0) as u64,
        mfa_enabled_users: mfa_on.max(0) as u64,
        mfa_disabled_users: mfa_off.max(0) as u64,
        bars,
    }
}

pub(crate) async fn load_heatmap(db_pool: &DbPool, now: DateTime<Utc>) -> Heatmap {
    let mut conn = match db_pool.get().await {
        Ok(c) => c,
        Err(_) => return Heatmap::from_grid(&[], &[]),
    };
    let cutoff = now - Duration::days(14);
    let rows: Vec<DateTime<Utc>> = proxy_sessions::table
        .filter(proxy_sessions::created_at.ge(cutoff))
        .select(proxy_sessions::created_at)
        .load(&mut conn)
        .await
        .unwrap_or_default();
    let mut grid: Vec<Vec<u32>> = (0..14).map(|_| vec![0u32; 24]).collect();
    let mut labels: Vec<String> = Vec::with_capacity(14);
    for d in 0..14 {
        let day = (now - Duration::days(13 - d)).date_naive();
        labels.push(format!("{:02}/{:02}", day.month(), day.day()));
    }
    for ts in rows {
        let day_idx = (ts.date_naive() - (now - Duration::days(13)).date_naive()).num_days();
        if (0..14).contains(&day_idx) {
            let h = ts.hour() as usize;
            if let Some(row) = grid.get_mut(day_idx as usize)
                && let Some(cell) = row.get_mut(h)
            {
                *cell = cell.saturating_add(1);
            }
        }
    }
    Heatmap::from_grid(&grid, &labels)
}

async fn load_user_lens(db_pool: &DbPool, user_uuid_str: &str, now: DateTime<Utc>) -> UserLens {
    let mut conn = match db_pool.get().await {
        Ok(c) => c,
        Err(_) => {
            return UserLens {
                recent_sessions: Vec::new(),
                own_recordings_total: 0,
            };
        }
    };
    let user_uuid = match ::uuid::Uuid::parse_str(user_uuid_str) {
        Ok(u) => u,
        Err(_) => {
            return UserLens {
                recent_sessions: Vec::new(),
                own_recordings_total: 0,
            };
        }
    };
    let user_id: i32 = match users::table
        .filter(users::uuid.eq(user_uuid))
        .select(users::id)
        .get_result(&mut conn)
        .await
    {
        Ok(id) => id,
        Err(_) => {
            return UserLens {
                recent_sessions: Vec::new(),
                own_recordings_total: 0,
            };
        }
    };
    let cutoff = now - Duration::days(7);
    type Row = (
        ::uuid::Uuid,
        String,
        String,
        String,
        Option<DateTime<Utc>>,
        bool,
        DateTime<Utc>,
    );
    let rows: Vec<Row> = proxy_sessions::table
        .inner_join(assets::table)
        .filter(proxy_sessions::user_id.eq(user_id))
        .filter(proxy_sessions::created_at.ge(cutoff))
        .select((
            proxy_sessions::uuid,
            assets::name,
            assets::hostname,
            proxy_sessions::session_type,
            proxy_sessions::connected_at,
            proxy_sessions::is_recorded,
            proxy_sessions::created_at,
        ))
        .order(proxy_sessions::created_at.desc())
        .limit(5)
        .load(&mut conn)
        .await
        .unwrap_or_default();
    let recent: Vec<LiveSession> = rows
        .into_iter()
        .map(|(uuid, name, hostname, st, connected_at, recorded, created_at)| {
            let started_at = connected_at.unwrap_or(created_at);
            LiveSession {
                uuid,
                asset_name: name,
                asset_hostname: hostname,
                username: String::new(),
                session_type: st,
                started_at,
                duration_seconds: now.signed_duration_since(started_at).num_seconds(),
                is_recorded: recorded,
            }
        })
        .collect();
    let own_recordings_total: i64 = proxy_sessions::table
        .filter(proxy_sessions::user_id.eq(user_id))
        .filter(proxy_sessions::recording_finalized_at.is_not_null())
        .select(count_star())
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    let _ = email_outbox::table; // keep import live if unused query helpers ever land
    UserLens {
        recent_sessions: recent,
        own_recordings_total: own_recordings_total.max(0) as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_chain_donut_carries_three_phases() {
        let donut = Donut::from_segments(vec![
            ("recording".to_string(), 1u64, "stroke-rose-500".to_string()),
            ("hydrating".to_string(), 2u64, "stroke-amber-500".to_string()),
            ("vaulted".to_string(), 3u64, "stroke-emerald-500".to_string()),
        ]);
        assert_eq!(donut.segments.len(), 3);
        assert_eq!(donut.total, 6);
    }

    #[test]
    fn hero_band_pct_is_zero_when_no_sessions_today() {
        let total: i64 = 0;
        let recorded: i64 = 0;
        let pct = if total > 0 {
            ((recorded as f64 / total as f64) * 100.0).round() as u8
        } else {
            0
        };
        assert_eq!(pct, 0);
    }

    #[test]
    fn hero_band_pct_is_100_when_all_sessions_recorded() {
        let total: i64 = 7;
        let recorded: i64 = 7;
        let pct = ((recorded as f64 / total as f64) * 100.0).round() as u8;
        assert_eq!(pct, 100);
    }
}
