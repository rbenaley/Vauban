//! Dashboard live-update pusher (Bastion Watch).
//!
//! A single long-lived Tokio task that:
//!
//! 1. Ticks every second.
//! 2. For each active SCOPE (the Global supervisor view +
//!    one per non-supervisor `dashboard:user:<uuid>` channel that
//!    has at least one live subscriber), recomputes the dashboard
//!    snapshot and broadcasts the per-tile fragments on the
//!    matching `WsChannel`.
//! 3. Throttles each tile family by a cadence table (fast / medium
//!    / slow) so a 1 Hz tick does not turn into 12 broadcasts/sec
//!    per user.
//! 4. Calls `LiveSessionHistory::gc_idle_after(5 min)` on the slow
//!    tier so a user who closed their dashboard does not accumulate
//!    state forever.
//!
//! ## Per-scope routing (Bastion Watch isolation, L3+)
//!
//! - `WsChannel::DashboardStats` (singleton, low-cardinality):
//!   carries the `Global` scope. Only supervisors subscribe to it
//!   via `/ws/dashboard`; the pusher only computes the Global
//!   snapshot when at least one supervisor is connected.
//!
//! - `WsChannel::DashboardStatsUser(uuid)` (parametric,
//!   high-cardinality): one channel per non-supervisor browser tab.
//!   The pusher enumerates the active per-user channels via
//!   [`BroadcastService::active_channels_with_prefix`] and computes
//!   one user-scoped snapshot per tick, applying the L2 SQL filter
//!   `WHERE proxy_sessions.user_id = $1`. A user who closes the
//!   tab disappears from the next tick automatically (the
//!   broadcast sender's `receiver_count()` drops to 0).
//!
//! ## Logging
//!
//! Per-tile broadcasts go through `BroadcastService::send_periodic`,
//! which forces the success log to `debug!` regardless of the
//! channel's cardinality. The pusher is a SCHEDULED stream (1 Hz
//! fast tier), so a per-tile `info!` would emit 4-12 lines per
//! second per connected client -- pure noise. The lifecycle
//! events (pusher started / pusher stopped) and the event-driven
//! low-frequency broadcasts on the same channels keep using `send`
//! and stay at `info!`.

use std::time::{Duration, Instant};

use askama::Template;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{debug, warn};

use crate::AppState;
use crate::auth::permissions::PermissionContext;
use crate::services::anomalies;
use crate::services::broadcast::{WsChannel, WsMessage};
use crate::services::dashboard::{DashboardScope, DashboardSnapshot};
use crate::templates::dashboard::tiles::{
    AccessPostureTile, AnomaliesTile, EvidenceChainTile, HeatmapTile, HeroEvidenceTile,
    HeroJitTile, HeroLiveTile, HeroTodayTile, LiveSessionsTile, SystemHealthTile,
    TILE_ACCESS_POSTURE, TILE_ANOMALIES, TILE_EVIDENCE_CHAIN, TILE_HEATMAP, TILE_HERO_EVIDENCE,
    TILE_HERO_JIT, TILE_HERO_LIVE, TILE_HERO_TODAY, TILE_LIVE_SESSIONS, TILE_SYSTEM_HEALTH,
    TILE_USER_LENS, UserLensTile,
};

/// Dashboard tile cadence table.
///
/// 1 s   -- LIVE band, live-sessions, evidence-chain, system-health.
/// 5 s   -- TODAY, JIT, evidence-hero, access-posture, anomalies.
/// 60 s  -- Heatmap (14d * 24h does not change every second).
///
/// Hero "evidence" is included in the 1 s tier because its `live`
/// counter is continuously updated; 5 s would feel laggy on a
/// recording flip.
const CADENCE_FAST: Duration = Duration::from_secs(1);
const CADENCE_MEDIUM: Duration = Duration::from_secs(5);
const CADENCE_SLOW: Duration = Duration::from_secs(60);

/// TTL for the per-user `LiveSessionHistory` rings. A user who
/// closed their dashboard 5 minutes ago has their ring evicted on
/// the next slow-tier tick. Memory upper bound:
/// `LIVE_HISTORY_CAP * 8 bytes per ring * users connected within ttl`.
const LIVE_HISTORY_TTL: Duration = Duration::from_secs(300);

/// Spawn the pusher. Idempotent: if `start_dashboard_pusher` is
/// called twice the second task simply runs in parallel and pushes
/// duplicate updates -- harmless but wasteful, so the call site
/// (`main.rs`) calls it exactly once.
pub fn start_dashboard_pusher(app_state: AppState) {
    tokio::spawn(async move {
        run_pusher(app_state).await;
    });
}

/// Pre-rendered HTML for a tile, ready for `WsMessage`.
fn render_or_empty<T: Template>(tile: &T) -> String {
    match tile.render() {
        Ok(html) => html,
        Err(e) => {
            warn!(error = %e, "dashboard pusher: tile render failed");
            String::new()
        }
    }
}

async fn run_pusher(app_state: AppState) {
    let mut tick = interval(CADENCE_FAST);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut last_fast = Instant::now() - CADENCE_FAST;
    let mut last_medium = Instant::now() - CADENCE_MEDIUM;
    let mut last_slow = Instant::now() - CADENCE_SLOW;

    loop {
        tick.tick().await;
        let now = Instant::now();
        let due_fast = now.duration_since(last_fast) >= CADENCE_FAST;
        let due_medium = now.duration_since(last_medium) >= CADENCE_MEDIUM;
        let due_slow = now.duration_since(last_slow) >= CADENCE_SLOW;
        if !(due_fast || due_medium || due_slow) {
            continue;
        }

        // SLOW tier: GC idle per-user LiveSessionHistory rings before
        // computing snapshots so a user who closed their dashboard
        // does not retain telemetry indefinitely. Global is never
        // evicted (see LiveSessionHistory::gc_idle_after).
        if due_slow {
            let dropped = app_state
                .live_session_history
                .gc_idle_after(LIVE_HISTORY_TTL);
            if dropped > 0 {
                debug!(dropped, "dashboard pusher: gc evicted idle scopes");
            }
        }

        // (1) Global scope: served to supervisors via the singleton
        // channel `dashboard:stats`. Skip the snapshot entirely if
        // no supervisor is connected.
        let global_subs = app_state
            .broadcast
            .subscriber_count(&WsChannel::DashboardStats)
            .await;
        if global_subs > 0 {
            push_for_scope(
                &app_state,
                DashboardScope::Global,
                &WsChannel::DashboardStats,
                /* supervisor_view = */ true,
                due_fast,
                due_medium,
                due_slow,
            )
            .await;
        }

        // (2) Per-user scopes: one snapshot per active
        // `dashboard:user:<uuid>` channel. SECURITY: the `<uuid>`
        // segment of the channel name comes from the WS handler at
        // upgrade time -- it is the connecting user's authenticated
        // UUID. The pusher does not parse user-supplied input here.
        let prefix = WsChannel::DASHBOARD_USER_PREFIX;
        let user_channels = app_state
            .broadcast
            .active_channels_with_prefix(prefix)
            .await;
        for channel_name in user_channels {
            let user_uuid = match channel_name.strip_prefix(prefix) {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => continue,
            };
            let user_id = match crate::services::dashboard::snapshot::resolve_user_id_from_uuid(
                &app_state.db_pool,
                &user_uuid,
            )
            .await
            {
                Some(uid) => uid,
                None => {
                    // User just deactivated / deleted under our
                    // feet. Skip this tick; the WS handler will
                    // catch the next disconnect and clean up.
                    debug!(
                        channel = %channel_name,
                        "dashboard pusher: skipping user scope (uuid unresolved)"
                    );
                    continue;
                }
            };
            let scope = DashboardScope::User(user_id);
            let target_channel = WsChannel::DashboardStatsUser(user_uuid);
            push_for_scope(
                &app_state,
                scope,
                &target_channel,
                /* supervisor_view = */ false,
                due_fast,
                due_medium,
                due_slow,
            )
            .await;
        }

        if due_fast {
            last_fast = now;
        }
        if due_medium {
            last_medium = now;
        }
        if due_slow {
            last_slow = now;
        }
    }
}

/// Compute and broadcast the snapshot for ONE `(scope, channel)`
/// pair. Tile family selection follows the cadence table; `due_*`
/// flags decide which tiers fire on this tick.
///
/// SECURITY: `scope` and `target_channel` MUST be paired
/// consistently by the caller (Global -> DashboardStats, User(id)
/// -> DashboardStatsUser(uuid)). This function trusts the caller
/// for that pairing -- it does not cross-check the SQL filter
/// against the channel name. The caller is `run_pusher` which
/// constructs both ends from the same source of truth (the WS
/// subscriber registry).
async fn push_for_scope(
    app_state: &AppState,
    scope: DashboardScope,
    target_channel: &WsChannel,
    supervisor_view: bool,
    due_fast: bool,
    due_medium: bool,
    due_slow: bool,
) {
    // Always cheap: count() over indexed columns + cached system_health.
    let system_health = if supervisor_view {
        Some(app_state.system_health_cache.snapshot().await)
    } else {
        None
    };
    let snapshot =
        match load_snapshot_for_scope(app_state, scope, supervisor_view, system_health).await {
            Some(s) => s,
            None => return,
        };

    if due_fast {
        push_fast(app_state, target_channel, &snapshot).await;
    }
    if due_medium {
        push_medium(app_state, target_channel, &snapshot, supervisor_view).await;
    }
    if due_slow {
        push_slow(app_state, target_channel, &snapshot).await;
    }
}

/// Standalone snapshot loader for the pusher (no `WebAuthUser`).
/// Mirrors `DashboardSnapshot::load` minus the per-user `UserLens`
/// (the pusher pushes shared tile fragments only; the personal
/// lens is rendered server-side at request time and not refreshed
/// over WS).
async fn load_snapshot_for_scope(
    app_state: &AppState,
    scope: DashboardScope,
    supervisor_view: bool,
    system_health: Option<crate::services::system_health::SystemHealth>,
) -> Option<DashboardSnapshot> {
    use crate::services::dashboard::snapshot;
    let now = chrono::Utc::now();
    let (hero, live_sessions, evidence_chain, access_posture, heatmap) = tokio::join!(
        snapshot::load_hero(
            &app_state.db_pool,
            now,
            scope,
            &app_state.live_session_history
        ),
        snapshot::load_live_sessions(&app_state.db_pool, scope, 10),
        snapshot::load_evidence_chain(&app_state.db_pool, scope),
        async {
            if supervisor_view {
                Some(snapshot::load_access_posture(&app_state.db_pool).await)
            } else {
                None
            }
        },
        snapshot::load_heatmap(&app_state.db_pool, now, scope),
    );
    Some(DashboardSnapshot {
        hero,
        live_sessions,
        evidence_chain,
        access_posture,
        heatmap,
        system_health,
        user_lens: crate::services::dashboard::UserLens {
            recent_sessions: Vec::new(),
            own_recordings_total: 0,
        },
        computed_at: now,
    })
}

async fn push_fast(app_state: &AppState, target_channel: &WsChannel, snapshot: &DashboardSnapshot) {
    let pairs: [(&str, String); 4] = [
        (
            TILE_HERO_LIVE,
            render_or_empty(&HeroLiveTile {
                snapshot: snapshot.clone(),
            }),
        ),
        (
            TILE_LIVE_SESSIONS,
            render_or_empty(&LiveSessionsTile {
                snapshot: snapshot.clone(),
            }),
        ),
        (
            TILE_EVIDENCE_CHAIN,
            render_or_empty(&EvidenceChainTile {
                snapshot: snapshot.clone(),
            }),
        ),
        (
            TILE_SYSTEM_HEALTH,
            render_or_empty(&SystemHealthTile {
                snapshot: snapshot.clone(),
            }),
        ),
    ];
    for (id, html) in pairs {
        let _ = app_state
            .broadcast
            .send_periodic(target_channel, WsMessage::new(id, html))
            .await;
    }
}

async fn push_medium(
    app_state: &AppState,
    target_channel: &WsChannel,
    snapshot: &DashboardSnapshot,
    supervisor_view: bool,
) {
    let mut pairs: Vec<(&str, String)> = vec![
        (
            TILE_HERO_TODAY,
            render_or_empty(&HeroTodayTile {
                snapshot: snapshot.clone(),
            }),
        ),
        (
            TILE_HERO_JIT,
            render_or_empty(&HeroJitTile {
                snapshot: snapshot.clone(),
            }),
        ),
        (
            TILE_HERO_EVIDENCE,
            render_or_empty(&HeroEvidenceTile {
                snapshot: snapshot.clone(),
            }),
        ),
        (
            TILE_ACCESS_POSTURE,
            render_or_empty(&AccessPostureTile {
                snapshot: snapshot.clone(),
            }),
        ),
        (
            TILE_USER_LENS,
            render_or_empty(&UserLensTile {
                snapshot: snapshot.clone(),
                tz: chrono_tz::Tz::UTC,
            }),
        ),
    ];
    if supervisor_view {
        let anomalies_data = anomalies::detect_all(&app_state.db_pool).await;
        pairs.push((
            TILE_ANOMALIES,
            render_or_empty(&AnomaliesTile {
                snapshot: snapshot.clone(),
                anomalies: anomalies_data,
            }),
        ));
    }
    for (id, html) in pairs {
        let _ = app_state
            .broadcast
            .send_periodic(target_channel, WsMessage::new(id, html))
            .await;
    }
}

async fn push_slow(app_state: &AppState, target_channel: &WsChannel, snapshot: &DashboardSnapshot) {
    let html = render_or_empty(&HeatmapTile {
        snapshot: snapshot.clone(),
    });
    let _ = app_state
        .broadcast
        .send_periodic(target_channel, WsMessage::new(TILE_HEATMAP, html))
        .await;
}

// `PermissionContext` is no longer needed in the body of the pusher
// (the supervisor / non-supervisor split is carried by the channel
// kind, not by a fake elevated PermissionContext). Keep the import
// path live for downstream callers that still spell it out.
#[allow(dead_code)]
fn _perm_context_anchor(_: &PermissionContext) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cadences_are_strictly_increasing() {
        // Defensive: a future maintainer flipping CADENCE_FAST and
        // CADENCE_MEDIUM (e.g. setting both to 1 s by accident) would
        // turn the medium tile push into a 1-Hz blast.
        assert!(CADENCE_FAST < CADENCE_MEDIUM);
        assert!(CADENCE_MEDIUM < CADENCE_SLOW);
    }

    #[test]
    fn cadence_fast_is_one_second() {
        assert_eq!(CADENCE_FAST, Duration::from_secs(1));
    }

    #[test]
    fn cadence_slow_is_one_minute() {
        assert_eq!(CADENCE_SLOW, Duration::from_secs(60));
    }

    #[test]
    fn live_history_ttl_is_five_minutes() {
        assert_eq!(LIVE_HISTORY_TTL, Duration::from_secs(300));
    }
}
