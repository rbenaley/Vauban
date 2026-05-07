//! Admin asset detail template (`/assets/manage/{uuid}`).
//!
//! Shows full administrative metadata + Edit / Delete / Fetch host-key
//! affordances. Replaces the legacy `/assets/{uuid}` page that used to
//! mix admin actions with end-user Connect / Request affordances. The
//! admin detail NEVER renders a Connect or Request button — issue #27,
//! enforced by source-level CI tests.
use askama::Template;

use crate::services::audit_authors::AuthorRef;
use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Asset metadata exposed on the admin detail page.
///
/// Notably absent compared to the legacy [`crate::templates::assets::asset_detail::AssetDetail`]:
///
/// - `require_approval` / `require_mfa` (those drive the user-zone
///   request modal).
/// - `has_approved_session` (only meaningful for the Connect button).
/// - `require_justification` (only meaningful for the Connect button).
///
/// All three were removed because the admin zone never opens sessions.
///
/// Carries the audit-author pair (`created_by` / `updated_by`)
/// resolved by [`crate::services::audit_authors::resolve_audit_pair`]
/// for the Metadata UI (issue #22). `None` means either a NULL FK
/// (system bootstrap rows) or a hard-deleted user — both render as
/// `—` in the template, never as a numeric id.
pub struct ManageAssetDetail {
    pub uuid: String,
    pub name: String,
    pub hostname: String,
    pub port: i32,
    pub asset_type: String,
    /// Compact label for the square asset-type tile next to the
    /// asset name (operator-reported overflow 2026-05-08:
    /// `IACS_MODBUS` does not fit a `h-10 w-10` square and crashed
    /// into the title). Source of truth: `AssetType::badge_label`.
    pub badge_label: String,
    /// Human-readable type label used in the Connection Details
    /// "Type" pill. The pill is flexible-width so it can carry the
    /// long form ("IACS - Modbus", "SSH", "RDP") -- the raw
    /// `asset_type` ("iacs_modbus") leaks an internal token that
    /// confuses operators. Source of truth: `AssetType::label`.
    pub type_label: String,
    /// Whether the asset belongs to the IACS family. The detail
    /// template uses this to drive the badge tint and the host-key
    /// affordance gate -- IACS rows have no SSH host key.
    pub is_iacs: bool,
    /// Short industrial protocol name for the purple IACS pill next to status.
    pub iacs_protocol_label: String,
    pub status: String,
    pub group_name: Option<String>,
    pub group_uuid: Option<String>,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub created_by: Option<AuthorRef>,
    pub updated_by: Option<AuthorRef>,
    pub ssh_host_key_fingerprint: Option<String>,
    pub ssh_host_key_mismatch: bool,
}

#[derive(Template)]
#[template(path = "assets/manage/detail.html")]
pub struct ManageAssetDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub asset: ManageAssetDetail,
}

#[cfg(test)]
mod tests {
    /// Source-level invariant: the admin detail module must never
    /// carry a `Connect` / `Request` / WebSocket reference. Forbidden
    /// tokens are built from `format!` to avoid self-matching.
    #[test]
    fn admin_detail_template_has_no_session_opening_path() {
        let source = include_str!("detail.rs");
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
                "admin detail template module must never reference '{}'",
                pat
            );
        }
    }
}
