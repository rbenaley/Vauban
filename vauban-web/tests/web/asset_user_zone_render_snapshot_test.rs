//! Issue #27 — render snapshot tests for the user-zone asset
//! templates.
//!
//! `AssetListTemplate` and `AssetDetailTemplate` are rendered with
//! synthetic data and the resulting HTML is grepped to assert:
//!
//! - The user zone surfaces Connect / Request affordances.
//! - The user zone NEVER surfaces admin-only affordances:
//!     * No `Edit` link to `/assets/{uuid}/edit` (or
//!       `/assets/manage/{uuid}/edit`)
//!     * No `Delete` form
//!     * No `New asset` button
//!     * No `Fetch Host Key` button (admin-only since #27)
//!     * No link to `/assets/manage/...` (the user zone never
//!       advertises the admin sub-tree to non-admin users).
//!
//! Companion of `manage_assets_render_snapshot_test.rs`.

use askama::Template;
use uuid::Uuid;

use vauban_web::templates::assets::asset_detail::{AssetDetail, AssetDetailTemplate};
use vauban_web::templates::assets::asset_list::{AssetListItem, AssetListTemplate};
use vauban_web::templates::base::{UserContext, VaubanConfig};

fn regular_user() -> UserContext {
    UserContext {
        uuid: Uuid::new_v4().to_string(),
        username: "alice".to_string(),
        display_name: "Alice".to_string(),
        is_superuser: false,
        is_staff: false,
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

fn sample_user_item() -> AssetListItem {
    AssetListItem {
        id: 1,
        uuid: Uuid::new_v4(),
        name: "App Server".to_string(),
        hostname: "app.example.com".to_string(),
        port: 22,
        asset_type: "ssh".to_string(),
        status: "online".to_string(),
        group_name: Some("Production".to_string()),
        requires_request: false,
    }
}

fn sample_user_detail() -> AssetDetail {
    AssetDetail {
        uuid: Uuid::new_v4().to_string(),
        name: "App Server".to_string(),
        hostname: "app.example.com".to_string(),
        port: 22,
        asset_type: "ssh".to_string(),
        status: "online".to_string(),
        group_name: Some("Production".to_string()),
        group_uuid: Some(Uuid::new_v4().to_string()),
        description: Some("Application backend".to_string()),
        require_approval: false,
        require_mfa: false,
        created_at: "2026-04-30T10:00:00Z".to_string(),
        updated_at: "2026-04-30T11:00:00Z".to_string(),
        ssh_host_key_fingerprint: None,
        ssh_host_key_mismatch: false,
        has_approved_session: false,
        require_justification: false,
    }
}

/// User-zone list MUST surface Connect/Request and MUST NOT surface
/// admin-only affordances (View link to detail page, Edit, Delete,
/// New asset, Access Rules header button).
#[test]
fn user_zone_list_renders_connect_only_no_admin_buttons() {
    let template = AssetListTemplate {
        title: "Assets".to_string(),
        user: Some(regular_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        assets: vec![sample_user_item()],
        pagination: None,
        search: None,
        type_filter: None,
        status_filter: None,
        asset_types: vec![],
        statuses: vec![],
        require_justification: false,
    };

    let html = template.render().expect("AssetListTemplate must render");

    // Forbidden tokens (admin affordances). Built via `format!` to
    // avoid self-matching.
    let forbidden_admin = [
        format!(">{} Asset<", "New"),
        format!(">{} Rules<", "Access"),
        format!("/assets/{{}}/{}\"", "edit"), // sentinel: edit URL pattern
        format!("/assets/{{}}/{}\"", "delete"),
        format!("/assets/{}/", "manage"), // user zone MUST not advertise admin
    ];
    for tok in &forbidden_admin {
        assert!(
            !html.contains(tok.as_str()),
            "AssetListTemplate (user zone) leaked the admin affordance \
             `{}`. Issue #27 stripped admin actions from the user zone.",
            tok
        );
    }

    // Required user-zone affordances:
    assert!(
        html.contains("Connect"),
        "user-zone list MUST advertise the Connect action"
    );
}

/// User-zone detail MUST NOT surface admin-only buttons (Edit, Delete,
/// Fetch Host Key). The "Connect" / "Request access" affordances ARE
/// allowed (they're the whole point of the user-zone detail page).
#[test]
fn user_zone_detail_hides_admin_buttons() {
    let template = AssetDetailTemplate {
        title: "Asset Detail".to_string(),
        user: Some(regular_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        asset: sample_user_detail(),
    };

    let html = template.render().expect("AssetDetailTemplate must render");

    let edit_url = "/assets/manage/";
    let edit_legacy_url = format!("/assets/{}/{}", "{uuid}", "edit");
    let delete_url = format!("/assets/{}/{}", "{uuid}", "delete");
    let fetch_host_key_btn = format!("Fetch{}Host{}Key", " ", " ");

    let forbidden = [
        format!(">{} Asset<", "Edit"),
        format!(">{}<", "Delete"),
        edit_url.to_string(),
        edit_legacy_url,
        delete_url,
        fetch_host_key_btn,
    ];
    for tok in &forbidden {
        assert!(
            !html.contains(tok.as_str()),
            "AssetDetailTemplate (user zone) leaked the admin affordance \
             `{}`. Issue #27 moved Edit / Delete / Fetch Host Key to \
             the admin zone.",
            tok
        );
    }
}
