//! Issue #27 / Issue #34 -- render snapshot tests for the user-zone
//! asset templates.
//!
//! `AssetListTemplate` is rendered with synthetic data and the
//! resulting HTML is grepped to assert:
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
//! Issue #34: the legacy `/assets/{uuid}` user-zone DETAIL page has
//! been removed entirely (information leak: description / dates /
//! ssh-host-key fingerprint were rendered for any caller with
//! `assets:read`, including users awaiting JIT approval).  The two
//! modaux (Request Access + Justification) are inlined on the list,
//! so this file no longer covers `AssetDetailTemplate` (it does not
//! exist anymore).
//!
//! Companion of `manage_assets_render_snapshot_test.rs`.

use askama::Template;
use uuid::Uuid;

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
        require_mfa: false,
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

/// Issue #34 -- the legacy `/assets/{uuid}` user-zone detail page has
/// been removed. The list is now the single user-facing surface for
/// browsing the asset catalogue, and the Request Access / Justification
/// modaux are inlined right here.
#[test]
fn user_zone_list_inlines_request_modal_no_detail_page_link() {
    let mut item = sample_user_item();
    item.requires_request = true;
    let template = AssetListTemplate {
        title: "Assets".to_string(),
        user: Some(regular_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        assets: vec![item],
        pagination: None,
        search: None,
        type_filter: None,
        status_filter: None,
        asset_types: vec![],
        statuses: vec![],
        require_justification: false,
    };

    let html = template.render().expect("AssetListTemplate must render");

    // The Request button must NOT navigate to the legacy detail page.
    assert!(
        !html.contains("#request-access"),
        "Request button must NOT use the legacy `#request-access` hash \
         (the /assets/{{uuid}} detail page is gone, issue #34)"
    );
    assert!(
        !html.contains("#justify"),
        "Connect button must NOT use the legacy `#justify` hash"
    );
    // The Request button must trigger the inlined Alpine modal.
    assert!(
        html.contains("$store.accessModal.open("),
        "Request button must populate the inlined Alpine accessModal store"
    );
    // The modal itself must be included on the page so the click resolves.
    assert!(
        html.contains("$store.accessModal.show"),
        "asset_list.html must include the inlined access_request_modal.html"
    );
    // The justification modal must also be inlined (single source of
    // truth for both flows on the list page).
    assert!(
        html.contains("$store.justificationModal.show"),
        "asset_list.html must include the inlined justification_modal.html"
    );
    // Per-row payload: uuid and asset_type must be passed by the
    // button click so the modal opens with the right context.
    assert!(
        html.contains("'ssh'"),
        "Request button must pass the asset_type literal to the modal store"
    );
}
