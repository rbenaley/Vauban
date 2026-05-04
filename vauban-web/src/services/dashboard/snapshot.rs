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
use crate::schema::{access_rules, assets, email_outbox, proxy_sessions, users};
use crate::services::dashboard::widgets::{Bar, Donut, Heatmap, Sparkline};
use crate::services::system_health::{LiveSessionHistory, ScopeKey, SystemHealth};
use chrono::{DateTime, Datelike, Duration, Timelike, Utc};
use diesel::dsl::count_star;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use std::sync::Arc;

/// Per-request data scope for Bastion Watch tiles.
///
/// SECURITY: this is the L1 (type system) layer of the dashboard's
/// 5-layer per-user isolation. Every loader that touches
/// `proxy_sessions` accepts a `DashboardScope` as a MANDATORY
/// parameter -- the compiler refuses an oversight. The discriminant
/// is itself derived from `PermissionContext::sessions_supervise`
/// at the handler/pusher boundary (L3 Casbin gate); the concrete
/// SQL filter is applied loader-side via [`apply_scope`] (L2).
///
/// `Global` -- the caller is a supervisor, all rows visible.
/// `User(id)` -- the caller can only see their own `proxy_sessions`
/// rows; queries inject `WHERE proxy_sessions.user_id = $id`.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum DashboardScope {
    Global,
    User(i32),
}

impl DashboardScope {
    /// Derive the scope from the request's permission context.
    ///
    /// `sessions_supervise == true` -> [`Self::Global`] (the caller
    /// has the Casbin capability to look at every session, no
    /// per-row filter is applied).
    ///
    /// `sessions_supervise == false` -> [`Self::User(user_id)`] (the
    /// caller is restricted to rows they own).
    ///
    /// The `user_id` is the internal `users.id` (i32) for `eq()`
    /// efficiency on the `proxy_sessions.user_id` foreign key.
    pub fn from_perms(perms: &PermissionContext, user_id: i32) -> Self {
        if perms.sessions_supervise {
            Self::Global
        } else {
            Self::User(user_id)
        }
    }
}

impl From<DashboardScope> for ScopeKey {
    fn from(s: DashboardScope) -> Self {
        match s {
            DashboardScope::Global => ScopeKey::Global,
            DashboardScope::User(id) => ScopeKey::User(id),
        }
    }
}

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
        scope: DashboardScope,
    ) -> Self {
        let user_uuid = auth_user.uuid.clone();
        let now = Utc::now();

        let (hero, live_sessions, evidence_chain, access_posture, heatmap, user_lens) = tokio::join!(
            load_hero(db_pool, now, scope, live_session_history),
            load_live_sessions(db_pool, scope, 10),
            load_evidence_chain(db_pool, scope),
            async {
                if perms.sessions_supervise {
                    Some(load_access_posture(db_pool).await)
                } else {
                    None
                }
            },
            load_heatmap(db_pool, now, scope),
            load_user_lens(db_pool, user_uuid.as_str(), now),
        );

        DashboardSnapshot {
            hero,
            live_sessions,
            evidence_chain,
            access_posture,
            heatmap,
            // SECURITY: gouvernance/infra (system_health, anomalies,
            // access_posture) follow the same gate as the rest of the
            // supervisor view. A non-supervisor never observes the
            // pool / req-rate / outbox metrics.
            system_health: if perms.sessions_supervise {
                system_health
            } else {
                None
            },
            user_lens,
            computed_at: now,
        }
    }
}

pub(crate) async fn load_hero(
    db_pool: &DbPool,
    now: DateTime<Utc>,
    scope: DashboardScope,
    live_session_history: &Arc<LiveSessionHistory>,
) -> HeroBand {
    let scope_key: ScopeKey = scope.into();
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
                spark_today: Sparkline::from_series(&live_session_history.series(scope_key)),
            };
        }
    };

    // Helper: scope-aware count. The match is local so each query
    // produces its own boxed Diesel pipeline (Diesel's typed query
    // builder does not allow arming an `Or` after `.into_boxed()`
    // with foreign tables). The closure captures `scope` and
    // applies the L2 SQL filter consistently.
    macro_rules! count_with_scope {
        ($base:expr) => {{
            match scope {
                DashboardScope::Global => $base
                    .select(count_star())
                    .get_result::<i64>(&mut conn)
                    .await
                    .unwrap_or(0),
                DashboardScope::User(uid) => $base
                    .filter(proxy_sessions::user_id.eq(uid))
                    .select(count_star())
                    .get_result::<i64>(&mut conn)
                    .await
                    .unwrap_or(0),
            }
        }};
    }

    let live: i64 =
        count_with_scope!(proxy_sessions::table.filter(proxy_sessions::status.eq("active")));
    let live_u64 = live.max(0) as u64;
    // Push the freshly-observed live count into the per-scope
    // rolling history BEFORE building the sparkline so the trace's
    // last point is always the value displayed in the LIVE hero
    // KPI of the same scope.
    live_session_history.record(scope_key, live_u64);
    let day_start = now
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .map(|d| d.and_utc())
        .unwrap_or(now);
    let today: i64 =
        count_with_scope!(proxy_sessions::table.filter(proxy_sessions::created_at.ge(day_start)));
    let today_recorded: i64 = count_with_scope!(
        proxy_sessions::table
            .filter(proxy_sessions::created_at.ge(day_start))
            .filter(proxy_sessions::is_recorded.eq(true))
    );
    let jit_queue: i64 =
        count_with_scope!(proxy_sessions::table.filter(proxy_sessions::status.eq("pending")));
    let evidence_total: i64 = count_with_scope!(
        proxy_sessions::table.filter(proxy_sessions::recording_finalized_at.is_not_null())
    );
    // Spark = sliding window of recent live-session counts for THIS
    // scope (NOT a global aggregate -- that would leak the rest of
    // the bastion's activity into every user's tile).
    let series = live_session_history.series(scope_key);
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

pub(crate) async fn load_live_sessions(
    db_pool: &DbPool,
    scope: DashboardScope,
    limit: i64,
) -> Vec<LiveSession> {
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
    // The live-sessions panel JOINs assets + users to surface a
    // human-readable row. The L2 SQL filter on `proxy_sessions.user_id`
    // is what guarantees a non-supervisor never observes a row
    // belonging to another tenant. The match below threads `scope`
    // through both branches without losing the typed query.
    let rows: Vec<Row> = match scope {
        DashboardScope::Global => proxy_sessions::table
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
            .unwrap_or_default(),
        DashboardScope::User(uid) => proxy_sessions::table
            .inner_join(assets::table)
            .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
            .filter(proxy_sessions::status.eq("active"))
            .filter(proxy_sessions::user_id.eq(uid))
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
            .unwrap_or_default(),
    };
    let now = Utc::now();
    rows.into_iter()
        .map(
            |(uuid, name, hostname, username, st, connected_at, recorded, created_at)| {
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
            },
        )
        .collect()
}

pub(crate) async fn load_evidence_chain(db_pool: &DbPool, scope: DashboardScope) -> EvidenceChain {
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

    macro_rules! count_with_scope {
        ($base:expr) => {{
            match scope {
                DashboardScope::Global => $base
                    .select(count_star())
                    .get_result::<i64>(&mut conn)
                    .await
                    .unwrap_or(0),
                DashboardScope::User(uid) => $base
                    .filter(proxy_sessions::user_id.eq(uid))
                    .select(count_star())
                    .get_result::<i64>(&mut conn)
                    .await
                    .unwrap_or(0),
            }
        }};
    }

    let recording_now: i64 = count_with_scope!(
        proxy_sessions::table
            .filter(proxy_sessions::is_recorded.eq(true))
            .filter(proxy_sessions::status.eq("active"))
    );
    let awaiting: i64 = count_with_scope!(
        proxy_sessions::table
            .filter(proxy_sessions::is_recorded.eq(true))
            .filter(proxy_sessions::recording_finalized_at.is_null())
            .filter(proxy_sessions::disconnected_at.is_not_null())
    );
    let hydrated: i64 = count_with_scope!(
        proxy_sessions::table.filter(proxy_sessions::recording_finalized_at.is_not_null())
    );
    // Diesel `sum()` on `Nullable<Int8>` returns `Numeric`; rather
    // than pulling `bigdecimal` and risking precision loss, we sum
    // bytes client-side. The `recording_finalized_at` filter caps
    // the row count to actually finalised recordings, which is
    // bounded by the retention policy.
    let sizes: Vec<Option<i64>> = match scope {
        DashboardScope::Global => proxy_sessions::table
            .filter(proxy_sessions::recording_finalized_at.is_not_null())
            .select(proxy_sessions::recording_size_bytes)
            .load(&mut conn)
            .await
            .unwrap_or_default(),
        DashboardScope::User(uid) => proxy_sessions::table
            .filter(proxy_sessions::recording_finalized_at.is_not_null())
            .filter(proxy_sessions::user_id.eq(uid))
            .select(proxy_sessions::recording_size_bytes)
            .load(&mut conn)
            .await
            .unwrap_or_default(),
    };
    let vault_total_bytes: i64 = sizes.into_iter().flatten().fold(0i64, i64::saturating_add);
    let donut = Donut::from_segments(vec![
        (
            "recording".to_string(),
            recording_now.max(0) as u64,
            "stroke-rose-500".to_string(),
        ),
        (
            "hydrating".to_string(),
            awaiting.max(0) as u64,
            "stroke-amber-500".to_string(),
        ),
        (
            "vaulted".to_string(),
            hydrated.max(0) as u64,
            "stroke-emerald-500".to_string(),
        ),
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

pub(crate) async fn load_heatmap(
    db_pool: &DbPool,
    now: DateTime<Utc>,
    scope: DashboardScope,
) -> Heatmap {
    let mut conn = match db_pool.get().await {
        Ok(c) => c,
        Err(_) => return Heatmap::from_grid(&[], &[]),
    };
    let cutoff = now - Duration::days(14);
    let rows: Vec<DateTime<Utc>> = match scope {
        DashboardScope::Global => proxy_sessions::table
            .filter(proxy_sessions::created_at.ge(cutoff))
            .select(proxy_sessions::created_at)
            .load(&mut conn)
            .await
            .unwrap_or_default(),
        DashboardScope::User(uid) => proxy_sessions::table
            .filter(proxy_sessions::created_at.ge(cutoff))
            .filter(proxy_sessions::user_id.eq(uid))
            .select(proxy_sessions::created_at)
            .load(&mut conn)
            .await
            .unwrap_or_default(),
    };
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

/// Resolve a user UUID (from the JWT `sub` claim or a parametric
/// channel name like `dashboard:user:<uuid>`) to the internal
/// `users.id` (i32) used everywhere by the `proxy_sessions.user_id`
/// foreign key.
///
/// Returns `None` if the UUID is malformed, the user is not found,
/// or the DB pool is exhausted -- the caller treats `None` as "fall
/// back to Global on the assumption the supervisor view is safer
/// than fabricating a fake user_id" (the Bastion Watch handler does
/// NOT do this; it surfaces a 500-equivalent fallback to a private
/// scope, see [`crate::handlers::web::dashboard::dashboard_home`]).
///
/// SECURITY: never confuse a *missing* UUID with `User(0)` -- that
/// would deny every row in the per-user filter (the safest
/// degraded behaviour) but the caller MUST still prefer to surface
/// an explicit failure rather than silently degrade. See the
/// [`vauban-web/src/handlers/web/dashboard.rs`] usage for the
/// fallback policy.
pub async fn resolve_user_id_from_uuid(db_pool: &DbPool, user_uuid_str: &str) -> Option<i32> {
    let user_uuid = ::uuid::Uuid::parse_str(user_uuid_str).ok()?;
    let mut conn = db_pool.get().await.ok()?;
    users::table
        .filter(users::uuid.eq(user_uuid))
        .select(users::id)
        .get_result::<i32>(&mut conn)
        .await
        .ok()
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
    // load_user_lens is intrinsically user-scoped by `user_id` (the
    // .filter row directly below). It does NOT participate in the
    // DashboardScope contract because the user_id is sourced from
    // the request's `WebAuthUser`, not from a Casbin gate -- the
    // lens always shows the caller's own lane.
    // allow-global-scope: see comment above
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
        .map(
            |(uuid, name, hostname, st, connected_at, recorded, created_at)| {
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
            },
        )
        .collect();
    // allow-global-scope: same rationale as load_user_lens row above.
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
            (
                "hydrating".to_string(),
                2u64,
                "stroke-amber-500".to_string(),
            ),
            (
                "vaulted".to_string(),
                3u64,
                "stroke-emerald-500".to_string(),
            ),
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
