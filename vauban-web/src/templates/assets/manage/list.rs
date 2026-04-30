//! Admin asset list template (`/assets/manage`).
//!
//! Renders every active asset with admin actions (View detail, Edit,
//! Delete). NEVER renders Connect / Request affordances. The user-facing
//! catalogue (`/assets`) lives in [`crate::templates::assets::asset_list`].
use askama::Template;

use crate::templates::accounts::user_list::Pagination;
use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Asset row in the admin "Assets" list.
///
/// Mirrors the user-zone [`crate::templates::assets::asset_list::AssetListItem`]
/// shape (icon-per-type, status pill, optional group label) so that
/// admins land on a familiar surface. The single difference is that
/// the row action is `Details` (read-only navigation to
/// `/assets/manage/{uuid}`) rather than `Connect`/`Request`. The
/// admin list never carries `requires_request`/connection state by
/// construction: it cannot open sessions (issue #27 invariant
/// pinned by `tests/web/manage_assets_invariants_test.rs`).
#[derive(Debug, Clone)]
pub struct ManageAssetItem {
    pub uuid: ::uuid::Uuid,
    pub name: String,
    pub hostname: String,
    pub port: i32,
    pub asset_type: String,
    pub status: String,
    pub group_name: Option<String>,
}

#[derive(Template)]
#[template(path = "assets/manage/list.html")]
pub struct ManageAssetListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub assets: Vec<ManageAssetItem>,
    pub pagination: Option<Pagination>,
    pub search: Option<String>,
    pub type_filter: Option<String>,
    pub status_filter: Option<String>,
    pub asset_types: Vec<(String, String)>,
    pub statuses: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
    /// Source-level invariant: this admin module must never carry a
    /// `Connect` / `Request` / WebSocket reference. Forbidden tokens
    /// are built from `format!` so the test cannot match its own
    /// assertion strings.
    #[test]
    fn admin_list_template_has_no_session_opening_path() {
        let source = include_str!("list.rs");
        let body = source
            .split("#[cfg(test)]")
            .next()
            .expect("module always has a non-test prefix");

        let forbidden = [
            format!("connect{}rdp", "-"),
            format!("connect{}ssh", "_"),
            format!("submit{}access{}request", "_", "_"),
            format!("ws{}://", "s"),
        ];

        for pat in &forbidden {
            assert!(
                !body.contains(pat.as_str()),
                "admin list template module must never reference '{}'",
                pat
            );
        }
    }
}
