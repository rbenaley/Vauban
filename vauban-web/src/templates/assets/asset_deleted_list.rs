//! Issue #17 — Read-only audit view of soft-deleted (tombstoned)
//! assets.
//!
//! This template intentionally exposes a NARROWER set of fields than
//! the active asset list:
//!
//! - No "View" / "Edit" / "Restore" links — restoration is forbidden
//!   by policy (RG-ASS-04) and structurally blocked by the
//!   `assets_no_resurrection_trg` trigger; offering a button would
//!   only invite confusion.
//! - No `connection_config` exposure — tombstones carry `{}` by
//!   contract (`assets_tombstone_no_secrets`), so there is nothing
//!   to display, but the template never even sees the column to
//!   keep the audit surface minimal.
//! - No "Connect" affordance — the asset is gone; sessions on its
//!   `id` are reachable via the proxy_sessions history page.
//!
//! Issue #22 — `deleted_by` surfaces the operator that performed
//! the soft-delete. We reuse the `updated_by_id` column (re-stamped
//! by `delete_asset_web`) instead of introducing a dedicated
//! `deleted_by_id`: a tombstone's last write IS the deletion by
//! contract, and the active-asset detail page already uses
//! `updated_by_id` to surface the most recent operator.

use crate::services::audit_authors::AuthorRef;
use crate::templates::accounts::user_list::Pagination;
use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
use askama::Template;

/// One row in the deleted-assets audit list. Mirrors the audit-relevant
/// columns of `assets`; secrets are not represented here on purpose.
///
/// `deleted_by` is sourced from `assets.updated_by_id` (re-stamped at
/// soft-delete time by `delete_asset_web` and `delete_asset` API). A
/// `None` collapses to a muted em-dash so historical tombstones
/// created before the audit columns existed render gracefully.
#[derive(Debug, Clone)]
pub struct DeletedAssetItem {
    pub uuid: ::uuid::Uuid,
    pub name: String,
    pub hostname: String,
    pub port: i32,
    pub connection_username: String,
    pub asset_type: String,
    /// Whether the tombstoned row was an IACS asset. Drives the
    /// row icon (factory pictogram) and the readable type label.
    pub is_iacs: bool,
    /// Friendly type label for the small tombstone pill (e.g.
    /// "IACS - Modbus") so the row reads naturally instead of the
    /// raw `iacs_modbus` token. Source: `AssetType::label`.
    pub type_label: String,
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub deleted_by: Option<AuthorRef>,
}

#[derive(Template)]
#[template(path = "assets/asset_deleted_list.html")]
pub struct AssetDeletedListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<UserContext>,
    pub assets: Vec<DeletedAssetItem>,
    pub pagination: Option<Pagination>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_item() -> DeletedAssetItem {
        DeletedAssetItem {
            uuid: ::uuid::Uuid::new_v4(),
            name: "Decommissioned host".to_string(),
            hostname: "10.10.10.99".to_string(),
            port: 22,
            connection_username: "root".to_string(),
            asset_type: "ssh".to_string(),
            is_iacs: false,
            type_label: "SSH".to_string(),
            deleted_at: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now() - chrono::Duration::days(7),
            deleted_by: Some(AuthorRef {
                username: "alice_admin".to_string(),
                is_active: true,
            }),
        }
    }

    fn make_template(items: Vec<DeletedAssetItem>) -> AssetDeletedListTemplate {
        AssetDeletedListTemplate {
            title: "Deleted Assets".to_string(),
            user: Some(UserContext {
                uuid: "u1".to_string(),
                username: "admin".to_string(),
                display_name: "Admin".to_string(),
                is_superuser: true,
                is_staff: true,
            }),
            vauban: VaubanConfig {
                brand_name: "VAUBAN".to_string(),
                brand_logo: None,
                theme: "dark".to_string(),
                ..Default::default()
            },
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            assets: items,
            pagination: None,
        }
    }

    #[test]
    fn test_renders_with_items() {
        let template = make_template(vec![make_item()]);
        let html = template.render().expect("must render");
        assert!(
            html.contains("Decommissioned host"),
            "tombstone name must be displayed"
        );
        assert!(
            html.contains("10.10.10.99"),
            "tombstone hostname must be displayed"
        );
    }

    #[test]
    fn test_renders_empty_state() {
        let template = make_template(vec![]);
        let html = template.render().expect("must render even when empty");
        assert!(
            html.contains("No deleted assets"),
            "empty state must be communicated to the operator"
        );
    }

    #[test]
    fn test_template_never_offers_restore_action() {
        // We deliberately allow prose mentioning "restored" / "deletion is
        // irreversible" in the page intro -- educating the operator is the
        // whole point. What we forbid is any actionable element (link,
        // button, form) offering to restore or reactivate a tombstone.
        let template = make_template(vec![make_item()]);
        let html = template.render().expect("must render");
        let lowered = html.to_lowercase();

        // Buttons / form submits live in markup like
        //   <button ...>Restore</button>
        //   <a ...>Reactivate</a>
        // so a closing-tag-adjacent capitalised label is the canonical
        // call-to-action shape we refuse to ship.
        assert!(
            !lowered.contains(">restore</") && !lowered.contains(">restore<"),
            "audit view MUST NOT offer a Restore button/link (RG-ASS-04)"
        );
        assert!(
            !lowered.contains(">reactivate</") && !lowered.contains(">reactivate<"),
            "audit view MUST NOT offer a Reactivate button/link"
        );
        assert!(
            !lowered.contains("/restore") && !lowered.contains("/reactivate"),
            "audit view MUST NOT carry a restore/reactivate URL"
        );
    }

    #[test]
    fn test_renders_deleted_by_username() {
        let template = make_template(vec![make_item()]);
        let html = template.render().expect("must render");
        assert!(
            html.contains("alice_admin"),
            "tombstone row must surface the username of the operator that deleted it"
        );
        assert!(
            html.to_lowercase().contains(">by<")
                || html.to_lowercase().contains("deleted by")
                || html.to_lowercase().contains(" by "),
            "tombstone row must label the operator with a 'by' marker"
        );
    }

    #[test]
    fn test_renders_deleted_by_inactive_suffix() {
        let mut item = make_item();
        item.deleted_by = Some(AuthorRef {
            username: "bob_admin".to_string(),
            is_active: false,
        });
        let template = make_template(vec![item]);
        let html = template.render().expect("must render");
        assert!(html.contains("bob_admin"), "username must still render");
        assert!(
            html.contains("(inactive)"),
            "an inactive operator must be flagged so the auditor sees the row was \
             deleted by an account that is no longer active"
        );
    }

    #[test]
    fn test_renders_em_dash_when_deleted_by_missing() {
        let mut item = make_item();
        item.deleted_by = None;
        let template = make_template(vec![item]);
        let html = template.render().expect("must render");
        assert!(
            html.contains("&mdash;") || html.contains("\u{2014}"),
            "a tombstone with no resolvable operator must render the muted em-dash, \
             never an empty cell or 'Some(...)' Debug repr"
        );
    }

    #[test]
    fn test_deleted_by_never_leaks_authorref_repr() {
        let template = make_template(vec![make_item()]);
        let html = template.render().expect("must render");
        for tok in ["AuthorRef {", "is_active:", "username:", "Some("] {
            assert!(
                !html.contains(tok),
                "tombstone row leaked an implementation detail (`{}`) into the audit HTML",
                tok
            );
        }
    }

    #[test]
    fn test_template_never_offers_edit_or_connect() {
        let template = make_template(vec![make_item()]);
        let html = template.render().expect("must render");
        assert!(
            !html.contains("hx-post"),
            "audit view MUST NOT carry any state-changing HTMX action"
        );
        assert!(
            !html.contains("/edit"),
            "audit view MUST NOT link to the edit form"
        );
        assert!(
            !html.contains("/connect"),
            "audit view MUST NOT link to the connect endpoint"
        );
    }
}
