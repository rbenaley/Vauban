//! Bastion Watch dashboard template (`/`).
//!
//! Replaces the legacy `HomeTemplate` with a passive, role-aware,
//! WebSocket-driven dashboard. Every tile is read-only; the only
//! mutating verb on the page is the user navigating away.

use askama::Template;

use crate::auth::permissions::PermissionContext;
use crate::services::anomalies::Anomaly;
use crate::services::dashboard::DashboardSnapshot;
use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

#[derive(Template)]
#[template(path = "dashboard/bastion_watch.html")]
pub struct BastionWatchTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<UserContext>,
    /// Read-only snapshot. Carries every metric the tiles render;
    /// `Option<...>` fields stay `None` for non-admin viewers.
    pub snapshot: DashboardSnapshot,
    /// Anomaly entries for the ANOMALIES tile (admin only). Empty
    /// `Vec` when the caller lacks `admin:view`.
    pub anomalies: Vec<Anomaly>,
    /// Casbin-derived permission flags. The template reads
    /// `perms.admin_view` to gate the admin-only tiles.
    pub perms: PermissionContext,
}
