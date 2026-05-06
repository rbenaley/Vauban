//! Issue #26 -- render snapshot tests for the "User Zone" /
//! "Administration" sidebar section labels.
//!
//! Pre-fix the sidebar mixed user-personal entries (Dashboard,
//! Assets catalog, My Requests) with the admin block under the
//! single label "Administration", which left the personal section
//! without an anchor. The fix introduces a symmetric "User Zone"
//! label above the personal block so a user scanning the menu has
//! a clear "what's mine vs. what's org-wide" repere.
//!
//! Invariants asserted here (option (a) MVP, no new entries, no
//! new Casbin gates):
//!
//! 1. `User Zone` is ALWAYS rendered, regardless of permissions
//!    (every authenticated user gets the personal block).
//! 2. `Administration` is rendered ssi `admin_view` is true (this
//!    invariant pre-dates the issue and must not regress).
//! 3. `User Zone` appears BEFORE `Administration` in the rendered
//!    HTML so the personal anchor stays at the top of the menu,
//!    matching the user-journey order called out by #26.
//! 4. Both labels share the canonical Tailwind classes -- visual
//!    weight is identical between the two zones.
//!
//! The sidebar partial is included from every page template; we
//! exercise the contract through `ManageAssetDetailTemplate` (which
//! already includes the sidebar via `base.html`) so we reuse a
//! known-good harness rather than invent a new one.

use askama::Template;
use uuid::Uuid;

use vauban_web::auth::PermissionContext;
use vauban_web::templates::assets::manage::{ManageAssetDetail, ManageAssetDetailTemplate};
use vauban_web::templates::base::{UserContext, VaubanConfig};
use vauban_web::templates::partials::sidebar_content::SidebarContentTemplate;

fn vauban_cfg() -> VaubanConfig {
    VaubanConfig {
        brand_name: "VAUBAN".to_string(),
        brand_logo: None,
        theme: "dark".to_string(),
        ..Default::default()
    }
}

fn user_ctx(is_admin: bool) -> UserContext {
    UserContext {
        uuid: Uuid::new_v4().to_string(),
        username: if is_admin { "admin" } else { "alice" }.to_string(),
        display_name: if is_admin { "Admin" } else { "Alice" }.to_string(),
        is_superuser: is_admin,
        is_staff: is_admin,
    }
}

fn admin_perms() -> PermissionContext {
    PermissionContext {
        users_read: true,
        users_write: true,
        groups_read: true,
        groups_write: true,
        access_rules_read: true,
        access_rules_write: true,
        assets_read: true,
        assets_manage: true,
        admin_view: true,
        auth_sessions_read: true,
        auth_sessions_write: true,
        sessions_read: true,
        sessions_write: true,
        profile_read: true,
        profile_write: true,
        users_manage_admins: true,
        assets_read_all: true,
        groups_manage_members: true,
        sessions_supervise: true,
        sessions_bypass_access_rules: true,
        iacs_request: true,
        iacs_read: true,
        iacs_manage: true,
    }
}

fn user_perms() -> PermissionContext {
    PermissionContext {
        assets_read: true,
        profile_read: true,
        profile_write: true,
        sessions_read: true,
        ..PermissionContext::default()
    }
}

fn make_sidebar(user: UserContext, perms: PermissionContext) -> SidebarContentTemplate {
    SidebarContentTemplate {
        user,
        is_dashboard: false,
        is_assets: false,
        is_manage_assets: false,
        is_sessions: false,
        is_recordings: false,
        is_users: false,
        is_groups: false,
        is_approvals: false,
        is_access_rules: false,
        is_my_requests: false,
        is_iacs: false,
        pending_approval_count: 0,
        pending_iacs_count: 0,
        perms,
    }
}

fn render_with(sidebar: SidebarContentTemplate) -> String {
    let user = sidebar.user.clone();
    let template = ManageAssetDetailTemplate {
        title: "Asset Detail".to_string(),
        user: Some(user.clone()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: Some(sidebar),
        header_user: Some(user),
        asset: ManageAssetDetail {
            uuid: Uuid::new_v4().to_string(),
            name: "host01".to_string(),
            hostname: "host01.example.com".to_string(),
            port: 22,
            asset_type: "ssh".to_string(),
            status: "online".to_string(),
            group_name: None,
            group_uuid: None,
            description: None,
            created_at: "today".to_string(),
            updated_at: "today".to_string(),
            created_by: None,
            updated_by: None,
            ssh_host_key_fingerprint: None,
            ssh_host_key_mismatch: false,
        },
    };
    template.render().expect("template renders")
}

// ---------------------------------------------------------------
// User Zone label: always rendered
// ---------------------------------------------------------------

#[test]
fn test_user_zone_label_present_for_admin() {
    let html = render_with(make_sidebar(user_ctx(true), admin_perms()));
    assert!(
        html.contains(">User Zone<"),
        "Sidebar must render the 'User Zone' label for admin users"
    );
}

#[test]
fn test_user_zone_label_present_for_regular_user() {
    let html = render_with(make_sidebar(user_ctx(false), user_perms()));
    assert!(
        html.contains(">User Zone<"),
        "Sidebar must render the 'User Zone' label for regular users (no admin gate)"
    );
}

// ---------------------------------------------------------------
// Administration label: gated by admin_view
// ---------------------------------------------------------------

#[test]
fn test_administration_label_present_for_admin() {
    let html = render_with(make_sidebar(user_ctx(true), admin_perms()));
    assert!(
        html.contains(">Administration<"),
        "Sidebar must render the 'Administration' label when admin_view is true"
    );
}

#[test]
fn test_administration_label_hidden_for_regular_user() {
    let html = render_with(make_sidebar(user_ctx(false), user_perms()));
    assert!(
        !html.contains(">Administration<"),
        "Sidebar must NOT render the 'Administration' label when admin_view is false (gating regression guard)"
    );
}

// ---------------------------------------------------------------
// Ordering: User Zone before Administration
// ---------------------------------------------------------------

#[test]
fn test_user_zone_appears_before_administration_in_html() {
    let html = render_with(make_sidebar(user_ctx(true), admin_perms()));
    let user_zone_idx = html
        .find(">User Zone<")
        .expect("'User Zone' must be in the HTML");
    let admin_idx = html
        .find(">Administration<")
        .expect("'Administration' must be in the HTML");
    assert!(
        user_zone_idx < admin_idx,
        "User Zone (idx {}) must appear BEFORE Administration (idx {}) so the personal block stays at the top of the menu",
        user_zone_idx,
        admin_idx
    );
}

// ---------------------------------------------------------------
// Typography parity: same Tailwind classes as the existing label
// ---------------------------------------------------------------

#[test]
fn test_user_zone_label_matches_administration_typography() {
    // Both labels MUST share the same Tailwind classes so the
    // visual weight is identical -- the entire point of the
    // symmetry the issue called out.
    let html = render_with(make_sidebar(user_ctx(true), admin_perms()));
    let label_class = "class=\"text-xs font-semibold leading-6 text-gray-400\"";
    let admin_label = format!("<div {}>Administration</div>", label_class);
    let user_zone_label = format!("<div {}>User Zone</div>", label_class);
    assert!(
        html.contains(&admin_label),
        "Administration label must keep its canonical Tailwind classes"
    );
    assert!(
        html.contains(&user_zone_label),
        "User Zone label must use the SAME Tailwind classes as Administration so the two zones are visually symmetric"
    );
}
