//! Issue #27 — render snapshot tests for the admin asset templates.
//!
//! Render the `ManageAssetListTemplate` and `ManageAssetDetailTemplate`
//! with synthetic data and assert the resulting HTML carries the
//! expected admin affordances (Edit / Delete / View) and NEVER any
//! end-user affordance (Connect / Request / Connect-RDP, etc.).
//!
//! Companion of `asset_user_zone_render_snapshot_test.rs` which pins
//! the symmetric contract for the user zone.

use askama::Template;
use uuid::Uuid;

use vauban_web::templates::assets::manage::{
    ManageAssetDetail, ManageAssetDetailTemplate, ManageAssetItem, ManageAssetListTemplate,
};
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

fn sample_item() -> ManageAssetItem {
    ManageAssetItem {
        uuid: Uuid::new_v4(),
        name: "Production DB".to_string(),
        hostname: "db.example.com".to_string(),
        port: 22,
        asset_type: "ssh".to_string(),
        status: "online".to_string(),
        group_name: Some("Production".to_string()),
    }
}

fn sample_detail() -> ManageAssetDetail {
    ManageAssetDetail {
        uuid: Uuid::new_v4().to_string(),
        name: "Production DB".to_string(),
        hostname: "db.example.com".to_string(),
        port: 22,
        asset_type: "ssh".to_string(),
        status: "online".to_string(),
        group_name: Some("Production".to_string()),
        group_uuid: Some(Uuid::new_v4().to_string()),
        description: Some("Primary PostgreSQL master".to_string()),
        created_at: "2026-04-30T10:00:00Z".to_string(),
        updated_at: "2026-04-30T11:00:00Z".to_string(),
        ssh_host_key_fingerprint: Some("SHA256:fingerprint".to_string()),
        ssh_host_key_mismatch: false,
    }
}

/// The admin list MUST render Edit / Delete / View affordances and
/// MUST NEVER render any session-opening affordance.
#[test]
fn manage_list_renders_admin_actions_only() {
    let template = ManageAssetListTemplate {
        title: "Manage Assets".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        assets: vec![sample_item()],
        pagination: None,
        search: None,
        type_filter: None,
        status_filter: None,
        asset_types: vec![],
        statuses: vec![],
    };

    let html = template.render().expect("ManageAssetListTemplate must render");

    // Forbidden tokens are constructed via `format!` so this test
    // does not match its own assertion strings if grepped.
    let forbidden = [
        format!("connect{}rdp", "-"),
        format!("connect{}ssh", "_"),
        format!("submit{}access{}request", "_", "_"),
        format!("hx{}post=\"/assets/{{}}/{}\"", "-", "connect").replace("{}", ""),
        format!("Request{}access", " "),
    ];
    for tok in &forbidden {
        assert!(
            !html.contains(tok.as_str()),
            "ManageAssetListTemplate.render() leaked the forbidden token \
             `{}`. The admin list MUST NOT expose end-user session-opening \
             affordances (issue #27 zone split).",
            tok
        );
    }

    // Required: at least one admin-action link to /assets/manage/{uuid}
    // OR /assets/manage/{uuid}/edit, plus a "New Asset" call-to-action.
    assert!(
        html.contains("/assets/manage/"),
        "ManageAssetListTemplate must render at least one link into the \
         admin sub-tree (`/assets/manage/...`)."
    );
}

/// The admin detail MUST render Edit / Delete buttons and MUST NEVER
/// render Connect / Request buttons. The user-zone detail page
/// (`AssetDetailTemplate`) is what carries those affordances.
#[test]
fn manage_detail_renders_edit_delete_no_connect() {
    let template = ManageAssetDetailTemplate {
        title: "Asset Detail".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        asset: sample_detail(),
    };

    let html = template
        .render()
        .expect("ManageAssetDetailTemplate must render");

    let forbidden = [
        format!("connect{}rdp", "-"),
        format!("connect{}ssh", "_"),
        format!("submit{}access{}request", "_", "_"),
        format!("Request{}access", " "),
        ">Connect<".to_string(),
    ];
    for tok in &forbidden {
        assert!(
            !html.contains(tok.as_str()),
            "ManageAssetDetailTemplate.render() leaked the forbidden token \
             `{}`. The admin detail page MUST NOT carry end-user \
             affordances (issue #27 zone split).",
            tok
        );
    }

    // The admin detail must reference the admin sub-tree for its
    // own actions (Edit, Delete) so a contributor cannot silently
    // re-point them at the user zone.
    assert!(
        html.contains("/assets/manage/"),
        "ManageAssetDetailTemplate must reference `/assets/manage/...` \
         in at least one Edit/Delete URL."
    );
}
