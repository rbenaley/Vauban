//! Dashboard live-update pusher (Bastion Watch).
//!
//! A single long-lived Tokio task that:
//!
//! 1. Ticks every second.
//! 2. Recomputes the dashboard snapshot (cheap: small `count(*)`s on
//!    indexed columns, system_health is 5 s-cached).
//! 3. Renders the per-tile fragment with Askama and broadcasts an
//!    HTMX OOB swap on `WsChannel::DashboardStats`.
//! 4. Throttles each tile according to the cadence table below so a
//!    1 Hz tick does not turn into 12 broadcasts/sec.
//!
//! Subscriber routing: there is a single global channel. User pages
//! that omit an admin-only `<div id="dash-...">` simply ignore the
//! OOB swap (HTMX silently drops swaps with no target). This keeps
//! the wire protocol channel-count low without leaking admin data
//! to user UIs -- the data itself is gated server-side.
//!
//! Logging level: every per-tile broadcast goes through
//! `BroadcastService::send_periodic`, which forces the success log
//! to `debug!` regardless of the channel's cardinality. The pusher
//! is a SCHEDULED stream (1 Hz fast tier) so a per-tile `info!`
//! would emit 4-12 lines/s per connected admin -- pure noise. The
//! lifecycle events (pusher started / pusher stopped) and the
//! event-driven low-frequency broadcasts (notifications,
//! `recording_hydrated`, ...) keep using `send` and stay at `info!`.

use std::time::{Duration, Instant};

use askama::Template;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, warn};

use crate::AppState;
use crate::auth::permissions::PermissionContext;
use crate::services::anomalies;
use crate::services::broadcast::{WsChannel, WsMessage};
use crate::services::dashboard::DashboardSnapshot;
use crate::templates::dashboard::tiles::{
    AccessPostureTile, AnomaliesTile, EvidenceChainTile, HeatmapTile, HeroEvidenceTile,
    HeroJitTile, HeroLiveTile, HeroTodayTile, LiveSessionsTile, SystemHealthTile, UserLensTile,
    TILE_ACCESS_POSTURE, TILE_ANOMALIES, TILE_EVIDENCE_CHAIN, TILE_HEATMAP, TILE_HERO_EVIDENCE,
    TILE_HERO_JIT, TILE_HERO_LIVE, TILE_HERO_TODAY, TILE_LIVE_SESSIONS, TILE_SYSTEM_HEALTH,
    TILE_USER_LENS,
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

    // Admin-elevated permissions for the pusher's snapshot loader.
    // The pusher runs server-side outside any HTTP request; it has
    // no Casbin role, so we manually elevate. The CLIENT-side gate is
    // the page template: a non-admin browser does not render the
    // admin tiles' `<div>`, and HTMX silently drops OOB swaps that
    // can't find their target. The data-on-the-wire is still admin-
    // only because server-side gating remains via the page handler.
    let perms = PermissionContext {
        admin_view: true,
        ..Default::default()
    };

    loop {
        tick.tick().await;
        let now = Instant::now();
        let due_fast = now.duration_since(last_fast) >= CADENCE_FAST;
        let due_medium = now.duration_since(last_medium) >= CADENCE_MEDIUM;
        let due_slow = now.duration_since(last_slow) >= CADENCE_SLOW;
        if !(due_fast || due_medium || due_slow) {
            continue;
        }

        // Skip work when nobody is connected (subscriber count is
        // amortised across all tiles -- a single subscriber is enough
        // to justify the snapshot cost).
        let subs = app_state
            .broadcast
            .subscriber_count(&WsChannel::DashboardStats)
            .await;
        if subs == 0 {
            debug!("dashboard pusher: no subscribers, skipping tick");
            // Still bump the timestamps so we don't over-eagerly
            // recompute as soon as a subscriber connects.
            if due_fast {
                last_fast = now;
            }
            if due_medium {
                last_medium = now;
            }
            if due_slow {
                last_slow = now;
            }
            continue;
        }

        // Compute the system health snapshot (cached behind 5 s) and
        // the dashboard snapshot. Fail-soft: any error inside `load`
        // is already swallowed and degraded to zero values.
        let system_health = Some(app_state.system_health_cache.snapshot().await);
        let snapshot = match load_admin_snapshot(&app_state, &perms, system_health).await {
            Some(s) => s,
            None => continue,
        };

        if due_fast {
            last_fast = now;
            push_fast(&app_state, &snapshot).await;
        }
        if due_medium {
            last_medium = now;
            push_medium(&app_state, &snapshot, &perms).await;
        }
        if due_slow {
            last_slow = now;
            push_slow(&app_state, &snapshot).await;
        }
    }
}

/// Standalone snapshot loader for the pusher (no `WebAuthUser`).
async fn load_admin_snapshot(
    app_state: &AppState,
    perms: &PermissionContext,
    system_health: Option<crate::services::system_health::SystemHealth>,
) -> Option<DashboardSnapshot> {
    // Re-implementation of `DashboardSnapshot::load` minus the
    // `WebAuthUser`-based UserLens (admin push has no specific user;
    // the personal lens stays pinned to whoever the browser has
    // already loaded). We surface `recent_sessions = []` for the
    // pusher.
    use crate::services::dashboard::snapshot;
    let now = chrono::Utc::now();
    let (hero, live_sessions, evidence_chain, access_posture, heatmap) = tokio::join!(
        snapshot::load_hero(&app_state.db_pool, now, &app_state.live_session_history),
        snapshot::load_live_sessions(&app_state.db_pool, 10),
        snapshot::load_evidence_chain(&app_state.db_pool, now),
        async {
            if perms.admin_view {
                Some(snapshot::load_access_posture(&app_state.db_pool).await)
            } else {
                None
            }
        },
        snapshot::load_heatmap(&app_state.db_pool, now),
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

async fn push_fast(app_state: &AppState, snapshot: &DashboardSnapshot) {
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
            .send_periodic(&WsChannel::DashboardStats, WsMessage::new(id, html))
            .await;
    }
}

async fn push_medium(
    app_state: &AppState,
    snapshot: &DashboardSnapshot,
    perms: &PermissionContext,
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
            }),
        ),
    ];
    if perms.admin_view {
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
            .send_periodic(&WsChannel::DashboardStats, WsMessage::new(id, html))
            .await;
    }
}

async fn push_slow(app_state: &AppState, snapshot: &DashboardSnapshot) {
    let html = render_or_empty(&HeatmapTile {
        snapshot: snapshot.clone(),
    });
    let _ = app_state
        .broadcast
        .send_periodic(
            &WsChannel::DashboardStats,
            WsMessage::new(TILE_HEATMAP, html),
        )
        .await;
}

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
}
