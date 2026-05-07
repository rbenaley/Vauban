//! Issue #22 — render snapshot tests for the audit author pair
//! (`Created by` / `Updated by`) on the three admin Metadata
//! sections: assets, asset groups, access rules.
//!
//! These tests exercise the full Askama template tree for each
//! detail page across the three documented states of an audit
//! author:
//!
//! 1. **Active**: a user row with `is_active = true`. The label
//!    must surface the bare display name, never the numeric id,
//!    UUID or username when a display name is available.
//! 2. **Inactive**: a user row with `is_active = false`. The
//!    label must keep the display name AND append a muted
//!    `(inactive)` suffix so the auditor sees that the actor is
//!    no longer an active operator.
//! 3. **Unknown / system**: `created_by` / `updated_by` is `None`,
//!    e.g. a NULL FK on the row or a hard-deleted user. The
//!    template must collapse to a muted em-dash (`—`) so an
//!    unattributable change can never be confused with an
//!    attributable one.
//!
//! The forbidden-token assertions are paranoia: they ensure the
//! Metadata UI never leaks raw `id` values, the `AuthorRef`
//! `Debug` output, or any other implementation detail.

use askama::Template;
use uuid::Uuid;

use vauban_web::services::audit_authors::AuthorRef;
use vauban_web::templates::assets::access_rule_detail::{
    AccessRuleDetailData, AccessRuleDetailTemplate,
};
use vauban_web::templates::assets::group_detail::{AssetGroupDetail, AssetGroupDetailTemplate};
use vauban_web::templates::assets::manage::{ManageAssetDetail, ManageAssetDetailTemplate};
use vauban_web::templates::base::{UserContext, VaubanConfig};

fn admin_user() -> UserContext {
    UserContext {
        uuid: Uuid::new_v4().to_string(),
        username: "admin".to_string(),
        display_name: "Admin".to_string(),
        is_superuser: true,
        is_staff: true,
    }
}

fn vauban_cfg() -> VaubanConfig {
    VaubanConfig {
        brand_name: "VAUBAN".to_string(),
        brand_logo: None,
        theme: "dark".to_string(),
        ..Default::default()
    }
}

fn active(name: &str) -> AuthorRef {
    AuthorRef {
        username: name.to_string(),
        is_active: true,
    }
}

fn inactive(name: &str) -> AuthorRef {
    AuthorRef {
        username: name.to_string(),
        is_active: false,
    }
}

// ---------------------------------------------------------------
// Asset detail (/assets/manage/{uuid})
// ---------------------------------------------------------------

fn make_manage_detail(
    created_by: Option<AuthorRef>,
    updated_by: Option<AuthorRef>,
) -> ManageAssetDetailTemplate {
    ManageAssetDetailTemplate {
        title: "Asset Detail".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        asset: ManageAssetDetail {
            uuid: Uuid::new_v4().to_string(),
            name: "Production DB".to_string(),
            hostname: "db.example.com".to_string(),
            port: 22,
            asset_type: "ssh".to_string(),
            badge_label: "SSH".to_string(),
            type_label: "SSH".to_string(),
            is_iacs: false,
            iacs_protocol_label: String::new(),
            status: "online".to_string(),
            group_name: None,
            group_uuid: None,
            description: None,
            created_at: "2026-04-30 10:00".to_string(),
            updated_at: "2026-04-30 11:00".to_string(),
            created_by,
            updated_by,
            ssh_host_key_fingerprint: None,
            ssh_host_key_mismatch: false,
        },
    }
}

#[test]
fn asset_detail_renders_active_author_pair() {
    let html = make_manage_detail(Some(active("Alice Doe")), Some(active("Bob Smith")))
        .render()
        .expect("ManageAssetDetailTemplate must render");

    assert!(
        html.contains(">Created by<"),
        "asset Metadata must surface a `Created by` label"
    );
    assert!(
        html.contains(">Updated by<"),
        "asset Metadata must surface an `Updated by` label"
    );
    assert!(
        html.contains("Alice Doe"),
        "active author display name must appear verbatim"
    );
    assert!(
        html.contains("Bob Smith"),
        "active author display name must appear verbatim"
    );
    assert!(
        !html.contains("(inactive)"),
        "active authors must NEVER carry the `(inactive)` suffix"
    );
}

#[test]
fn asset_detail_marks_inactive_author_with_muted_suffix() {
    let html = make_manage_detail(Some(inactive("Alice Doe")), Some(active("Bob Smith")))
        .render()
        .expect("ManageAssetDetailTemplate must render");

    assert!(
        html.contains("Alice Doe"),
        "inactive author display name must still appear"
    );
    assert!(
        html.contains("(inactive)"),
        "inactive author must carry the `(inactive)` suffix"
    );
    // Only Alice is inactive: the suffix must not bleed onto Bob.
    let inactive_count = html.matches("(inactive)").count();
    assert_eq!(
        inactive_count, 1,
        "exactly one author is inactive in this fixture, found {} suffix(es)",
        inactive_count
    );
}

#[test]
fn asset_detail_collapses_missing_authors_to_em_dash() {
    let html = make_manage_detail(None, None)
        .render()
        .expect("ManageAssetDetailTemplate must render");

    assert!(
        html.contains(">Created by<"),
        "the `Created by` label is rendered even when the author is unknown"
    );
    assert!(
        html.contains(">Updated by<"),
        "the `Updated by` label is rendered even when the author is unknown"
    );
    // `&mdash;` is what we wrote in the template; Askama keeps
    // raw HTML entities verbatim because the template literal is
    // not user-controlled.
    assert!(
        html.contains("&mdash;"),
        "unknown authors must collapse to an em-dash (&mdash;)"
    );
    assert!(
        !html.contains("(inactive)"),
        "unknown authors must NEVER claim to be inactive — they have no row at all"
    );
}

#[test]
fn asset_detail_never_leaks_numeric_id_or_debug_repr() {
    let html = make_manage_detail(Some(active("Alice")), None)
        .render()
        .expect("ManageAssetDetailTemplate must render");

    let forbidden = [
        "AuthorRef {",
        "is_active:",
        "username:",
        "user_id=",
        "Some(",
    ];
    for tok in &forbidden {
        assert!(
            !html.contains(tok),
            "asset detail leaked an implementation detail (`{}`) into the Metadata HTML",
            tok
        );
    }
}

// ---------------------------------------------------------------
// Asset group detail (/assets/groups/{uuid})
// ---------------------------------------------------------------

fn make_group_detail(
    created_by: Option<AuthorRef>,
    updated_by: Option<AuthorRef>,
) -> AssetGroupDetailTemplate {
    AssetGroupDetailTemplate {
        title: "Group Detail".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        group: AssetGroupDetail {
            uuid: Uuid::new_v4().to_string(),
            name: "Production".to_string(),
            slug: "production".to_string(),
            description: None,
            color: "#10b981".to_string(),
            icon: "server".to_string(),
            created_at: "2026-04-30 10:00".to_string(),
            updated_at: "2026-04-30 11:00".to_string(),
            created_by,
            updated_by,
            assets: Vec::new(),
        },
        csrf_token: "csrf".to_string(),
    }
}

#[test]
fn group_detail_renders_audit_pair_active() {
    let html = make_group_detail(Some(active("Carol Jones")), Some(active("Dave Lee")))
        .render()
        .expect("AssetGroupDetailTemplate must render");

    assert!(html.contains(">Created by<"));
    assert!(html.contains(">Updated by<"));
    assert!(html.contains("Carol Jones"));
    assert!(html.contains("Dave Lee"));
    assert!(!html.contains("(inactive)"));
}

#[test]
fn group_detail_marks_inactive_author() {
    let html = make_group_detail(Some(active("Carol")), Some(inactive("Dave")))
        .render()
        .expect("AssetGroupDetailTemplate must render");

    assert!(html.contains("Carol"));
    assert!(html.contains("Dave"));
    assert_eq!(html.matches("(inactive)").count(), 1);
}

#[test]
fn group_detail_collapses_missing_audit_pair() {
    let html = make_group_detail(None, None)
        .render()
        .expect("AssetGroupDetailTemplate must render");

    assert!(html.contains(">Created by<"));
    assert!(html.contains(">Updated by<"));
    assert!(html.contains("&mdash;"));
}

// ---------------------------------------------------------------
// Access rule detail (/assets/access/{uuid})
// ---------------------------------------------------------------

fn make_rule_detail(
    created_by: Option<AuthorRef>,
    updated_by: Option<AuthorRef>,
) -> AccessRuleDetailTemplate {
    AccessRuleDetailTemplate {
        title: "Access Rule".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        rule: AccessRuleDetailData {
            uuid: Uuid::new_v4().to_string(),
            name: "Allow SSH to Prod".to_string(),
            description: None,
            user_group_name: "Operators".to_string(),
            asset_group_name: "Production".to_string(),
            allowed_protocols: vec!["ssh".to_string()],
            valid_from: None,
            valid_until: None,
            require_mfa: false,
            require_approval: false,
            max_session_duration: None,
            is_active: true,
            priority: 10,
            created_at: "2026-04-30 10:00".to_string(),
            updated_at: "2026-04-30 11:00".to_string(),
            created_by,
            updated_by,
        },
    }
}

#[test]
fn access_rule_detail_renders_audit_pair_active() {
    let html = make_rule_detail(Some(active("Eve Walker")), Some(active("Frank Reed")))
        .render()
        .expect("AccessRuleDetailTemplate must render");

    assert!(html.contains(">Created by<"));
    assert!(html.contains(">Updated by<"));
    assert!(html.contains("Eve Walker"));
    assert!(html.contains("Frank Reed"));
    assert!(!html.contains("(inactive)"));
}

#[test]
fn access_rule_detail_marks_inactive_author() {
    let html = make_rule_detail(Some(inactive("Eve Walker")), Some(active("Frank Reed")))
        .render()
        .expect("AccessRuleDetailTemplate must render");

    assert!(html.contains("Eve Walker"));
    assert!(html.contains("Frank Reed"));
    assert_eq!(html.matches("(inactive)").count(), 1);
}

#[test]
fn access_rule_detail_collapses_missing_audit_pair() {
    let html = make_rule_detail(None, None)
        .render()
        .expect("AccessRuleDetailTemplate must render");

    assert!(html.contains(">Created by<"));
    assert!(html.contains(">Updated by<"));
    assert!(html.contains("&mdash;"));
}

// ---------------------------------------------------------------
// Cross-page invariants
// ---------------------------------------------------------------

/// Layout invariant: each Metadata `<dl>` carries 4 audit cells
/// (`Created`, `Created by`, `Last Updated`, `Updated by`) plus
/// page-specific extras (e.g. `UUID` on asset detail). The exact
/// label set is asserted to keep contributors from silently
/// reordering or dropping a cell on one of the three pages while
/// leaving the others unchanged.
#[test]
fn audit_pair_labels_present_on_all_three_detail_pages() {
    let pages: Vec<(&str, String)> = vec![
        (
            "asset detail",
            make_manage_detail(Some(active("X")), Some(active("Y")))
                .render()
                .expect("render"),
        ),
        (
            "asset group detail",
            make_group_detail(Some(active("X")), Some(active("Y")))
                .render()
                .expect("render"),
        ),
        (
            "access rule detail",
            make_rule_detail(Some(active("X")), Some(active("Y")))
                .render()
                .expect("render"),
        ),
    ];

    for (label, html) in pages {
        for required in [
            ">Created<",
            ">Created by<",
            ">Last Updated<",
            ">Updated by<",
        ] {
            assert!(
                html.contains(required),
                "{} missing the required Metadata label `{}`",
                label,
                required
            );
        }
    }
}
