//! Per-tile fragment templates for the Bastion Watch dashboard.
//!
//! Each tile has its own Askama template here so the dashboard pusher
//! can render a single tile (instead of the whole page) and ship the
//! HTML through the WebSocket. The struct fields mirror what each tile
//! partial reads from the parent context.

use askama::Template;

#[allow(unused_imports)]
use crate::utils::filters;

use crate::services::anomalies::Anomaly;
use crate::services::dashboard::DashboardSnapshot;

/// Common shape used by tiles that only read from `snapshot`.
#[derive(Clone)]
pub struct TileContext {
    pub snapshot: DashboardSnapshot,
}

/// Tile context that ALSO needs the anomaly list (admin-only tiles).
#[derive(Clone)]
pub struct AnomalyTileContext {
    pub snapshot: DashboardSnapshot,
    pub anomalies: Vec<Anomaly>,
}

#[derive(Template, Clone)]
#[template(path = "dashboard/tiles/_hero_live.html")]
pub struct HeroLiveTile {
    pub snapshot: DashboardSnapshot,
}

#[derive(Template, Clone)]
#[template(path = "dashboard/tiles/_hero_today.html")]
pub struct HeroTodayTile {
    pub snapshot: DashboardSnapshot,
}

#[derive(Template, Clone)]
#[template(path = "dashboard/tiles/_hero_jit.html")]
pub struct HeroJitTile {
    pub snapshot: DashboardSnapshot,
}

#[derive(Template, Clone)]
#[template(path = "dashboard/tiles/_hero_evidence.html")]
pub struct HeroEvidenceTile {
    pub snapshot: DashboardSnapshot,
}

#[derive(Template, Clone)]
#[template(path = "dashboard/tiles/_live_sessions.html")]
pub struct LiveSessionsTile {
    pub snapshot: DashboardSnapshot,
}

#[derive(Template, Clone)]
#[template(path = "dashboard/tiles/_evidence_chain.html")]
pub struct EvidenceChainTile {
    pub snapshot: DashboardSnapshot,
}

#[derive(Template, Clone)]
#[template(path = "dashboard/tiles/_access_posture.html")]
pub struct AccessPostureTile {
    pub snapshot: DashboardSnapshot,
}

#[derive(Template, Clone)]
#[template(path = "dashboard/tiles/_anomalies.html")]
pub struct AnomaliesTile {
    pub snapshot: DashboardSnapshot,
    pub anomalies: Vec<Anomaly>,
}

#[derive(Template, Clone)]
#[template(path = "dashboard/tiles/_user_lens.html")]
pub struct UserLensTile {
    pub snapshot: DashboardSnapshot,
    pub tz: chrono_tz::Tz,
}

#[derive(Template, Clone)]
#[template(path = "dashboard/tiles/_heatmap.html")]
pub struct HeatmapTile {
    pub snapshot: DashboardSnapshot,
}

#[derive(Template, Clone)]
#[template(path = "dashboard/tiles/_system_health.html")]
pub struct SystemHealthTile {
    pub snapshot: DashboardSnapshot,
}

/// Stable target id for each tile. Pinned across the codebase: the
/// pusher uses these as `WsMessage::new(target_id, ...)`, the page
/// template uses them as `<div id="...">`. A drift between the two
/// would silently break live updates.
pub const TILE_HERO_LIVE: &str = "dash-hero-live";
pub const TILE_HERO_TODAY: &str = "dash-hero-today";
pub const TILE_HERO_JIT: &str = "dash-hero-jit";
pub const TILE_HERO_EVIDENCE: &str = "dash-hero-evidence";
pub const TILE_LIVE_SESSIONS: &str = "dash-live-sessions";
pub const TILE_EVIDENCE_CHAIN: &str = "dash-evidence-chain";
pub const TILE_ACCESS_POSTURE: &str = "dash-access-posture";
pub const TILE_ANOMALIES: &str = "dash-anomalies";
pub const TILE_USER_LENS: &str = "dash-user-lens";
pub const TILE_HEATMAP: &str = "dash-heatmap";
pub const TILE_SYSTEM_HEALTH: &str = "dash-system-health";

/// Catalogue of every tile id known to the pusher / template. The
/// `bastion_watch_test` pin asserts that every entry here is also
/// rendered as `<div id="...">` by `bastion_watch.html`.
pub const TILE_IDS: &[&str] = &[
    TILE_HERO_LIVE,
    TILE_HERO_TODAY,
    TILE_HERO_JIT,
    TILE_HERO_EVIDENCE,
    TILE_LIVE_SESSIONS,
    TILE_EVIDENCE_CHAIN,
    TILE_ACCESS_POSTURE,
    TILE_ANOMALIES,
    TILE_USER_LENS,
    TILE_HEATMAP,
    TILE_SYSTEM_HEALTH,
];

#[allow(dead_code)] // accessor for AnomalyTileContext for tests / future use
impl AnomalyTileContext {
    pub fn snapshot(&self) -> &DashboardSnapshot {
        &self.snapshot
    }
}

#[allow(dead_code)]
impl TileContext {
    pub fn snapshot(&self) -> &DashboardSnapshot {
        &self.snapshot
    }
}
