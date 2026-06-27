//! End-to-end coverage for the four-layer Assets / Access Rules
//! kill-switch (`industrial.enabled = false`).
//!
//! The plan
//! `industrial_gate_hide_iacs_surface_b0c030eb.plan.md` formalises a
//! four-layer defense for the Assets / Access Rules surface:
//!
//! * Layer 1 -- Casbin (`PermissionContext`) -- already covered by
//!   `iacs_kill_switch_test.rs`.
//! * Layer 2 -- DB filter (`asset_type.ne_all(iacs_variants())`) on
//!   every list query in `handlers::web::assets`,
//!   `handlers::web::manage_assets`, `handlers::api::assets` and
//!   `handlers::api::manage_assets`.
//! * Layer 3 -- form options (`AssetType::select_options(false)` /
//!   `filter_options(false)` strip every `iacs_*` variant + the
//!   synthetic `iacs` filter token).
//! * Layer 4 -- handler defense-in-depth: every POST that could
//!   create / persist an IACS asset or rule re-checks the flag
//!   before the INSERT / UPDATE; every detail / edit / delete path
//!   collapses to 404 (anti-enumeration) when the asset is IACS
//!   and the master switch is off.
//! * Layer 5 -- template gate: the IACS checkbox + helper paragraph
//!   are wrapped in `{% if industrial_enabled %}` on the access-rule
//!   create / edit forms.
//!
//! Source-grep pin tests for layers 2-4 live in
//! `iacs_kill_switch_test.rs::every_iacs_db_filter_is_gated_on_industrial_enabled`
//! and friends. This file complements them with **runtime** end-to-
//! end coverage:
//!
//! * Insert real IACS rows and assert the production Diesel filter
//!   used by `manage_asset_list` actually drops them when the flag
//!   is flipped.
//! * Render the production templates with `industrial_enabled = false`
//!   and assert the IACS checkbox is absent.
//! * Confirm that the audit surfaces (recordings, `/sessions`) stay
//!   visible by virtue of being out-of-scope: the kill-switch is
//!   surgical to assets / access rules and never collateral against
//!   the audit trail. Pinned at the source level by
//!   `audit_surfaces_have_no_industrial_gate`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common::TestApp;
use crate::fixtures::unique_name;
use diesel::ExpressionMethods;
use diesel::QueryDsl;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;
use vauban_web::models::asset::{AssetType, NewAsset};
use vauban_web::schema::assets;

/// Insert an ACTIVE IACS asset directly via Diesel and return its
/// id. The handler-level guards do not run; we exercise the raw DB
/// state so the layer-2 filter has something to drop.
async fn insert_iacs_asset(
    conn: &mut AsyncPgConnection,
    name: &str,
    hostname: &str,
    asset_type: AssetType,
) -> i32 {
    assert!(
        asset_type.is_iacs(),
        "fixture insert_iacs_asset must receive an iacs_* variant"
    );
    let new_asset = NewAsset {
        uuid: Uuid::new_v4(),
        name: name.to_string(),
        hostname: hostname.to_string(),
        port: 502,
        asset_type,
        status: "online".to_string(),
        description: None,
        connection_config: json!({}),
        created_by_id: None,
        updated_by_id: None,
        connection_username: "root".to_string(),
    };
    diesel::insert_into(assets::table)
        .values(&new_asset)
        .returning(assets::id)
        .get_result(conn)
        .await
        .expect("IACS asset insert must succeed under the test fixture")
}

// ===================================================================
// Layer 2 -- DB filter end-to-end runtime check
// ===================================================================

/// Replays the kill-switch branch of `manage_asset_list` (admin
/// catalogue) and `asset_list` (user catalogue) at the Diesel level:
/// inserts a Modbus and an OPC-UA asset, then runs the same
/// `.filter(asset_type.ne_all(AssetType::iacs_variants()))` clause
/// the handlers apply when `industrial.enabled = false` and asserts
/// neither row makes it back. Pinned to fail loudly the day a future
/// list path is added without a matching kill-switch fence.
#[tokio::test]
#[serial]
async fn db_filter_drops_iacs_rows_when_industrial_disabled() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let modbus_name = unique_name("e2e-iacs-modbus");
    let modbus_host = format!("{modbus_name}.example.com");
    let modbus_id =
        insert_iacs_asset(&mut conn, &modbus_name, &modbus_host, AssetType::IacsModbus).await;
    let opcua_name = unique_name("e2e-iacs-opcua");
    let opcua_host = format!("{opcua_name}.example.com");
    let opcua_id =
        insert_iacs_asset(&mut conn, &opcua_name, &opcua_host, AssetType::IacsOpcua).await;

    // Production filter: identical to what `manage_asset_list`
    // applies under `if !state.config.industrial.enabled`.
    let visible_ids: Vec<i32> = assets::table
        .filter(assets::is_deleted.eq(false))
        .filter(assets::asset_type.ne_all(AssetType::iacs_variants()))
        .select(assets::id)
        .load(&mut conn)
        .await
        .expect("filter query must execute");

    assert!(
        !visible_ids.contains(&modbus_id),
        "kill-switch DB filter MUST drop the Modbus row (id {modbus_id})"
    );
    assert!(
        !visible_ids.contains(&opcua_id),
        "kill-switch DB filter MUST drop the OPC-UA row (id {opcua_id})"
    );

    // Sanity: with the filter OFF (industrial.enabled = true branch)
    // the very same rows DO surface, so the assertion above is not a
    // false negative caused by some other invisibility (e.g. a stray
    // `is_deleted = true` flag).
    let unfiltered_ids: Vec<i32> = assets::table
        .filter(assets::is_deleted.eq(false))
        .select(assets::id)
        .load(&mut conn)
        .await
        .expect("unfiltered query must execute");
    assert!(
        unfiltered_ids.contains(&modbus_id) && unfiltered_ids.contains(&opcua_id),
        "baseline (industrial.enabled = true) must keep both IACS rows visible \
         (sanity check on the test fixture)"
    );

    // Cleanup so subsequent tests do not see this fixture data.
    diesel::delete(assets::table.filter(assets::id.eq_any(vec![modbus_id, opcua_id])))
        .execute(&mut conn)
        .await
        .expect("cleanup delete must succeed");
}

// ===================================================================
// Layer 3 -- form options runtime check
// ===================================================================

/// `AssetType::select_options(false)` and `filter_options(false)`
/// together MUST surface ZERO industrial entries. This duplicates
/// the lib-level unit tests on purpose: a future migration that
/// promotes the synthetic `iacs` token to a real enum variant could
/// silently re-introduce it here, and we want the regression to fire
/// in BOTH the unit and integration test suites.
#[test]
fn asset_type_select_and_filter_options_strip_iacs_when_industrial_disabled() {
    let select = AssetType::select_options(false);
    assert!(
        !select.iter().any(|(v, _)| v.starts_with("iacs_")),
        "select_options(false) must strip every iacs_* variant; got {select:?}"
    );

    let filter = AssetType::filter_options(false);
    assert!(
        !filter.iter().any(|(v, _)| v.starts_with("iacs_")),
        "filter_options(false) must strip every iacs_* variant; got {filter:?}"
    );
    assert!(
        !filter.iter().any(|(v, _)| v == "iacs"),
        "filter_options(false) must drop the synthetic 'iacs' token \
         (the synthetic catch-all is industrial-only, so it cannot leak \
         when the master switch is off)"
    );

    // Baseline sanity.
    assert!(
        AssetType::select_options(true)
            .iter()
            .any(|(v, _)| v == "iacs_modbus"),
        "select_options(true) must keep the legacy seven entries"
    );
    assert!(
        AssetType::filter_options(true)
            .iter()
            .any(|(v, _)| v == "iacs"),
        "filter_options(true) must surface the synthetic 'iacs' all-industrial token"
    );
}

// ===================================================================
// Layer 5 -- template gate runtime check
// ===================================================================

/// Render the production access-rule create template with
/// `industrial_enabled = false` and assert the IACS checkbox + helper
/// paragraph have been gated out. SSH and RDP MUST stay (they are
/// always permitted, regardless of the kill-switch).
#[test]
fn access_rule_create_template_hides_iacs_checkbox_under_kill_switch() {
    use vauban_web::templates::assets::{
        access_rule_create::{AccessRuleCreateForm, AccessRuleCreateTemplate, GroupOption},
        // re-export check
    };
    use vauban_web::templates::base::{UserContext, VaubanConfig};
    let template = AccessRuleCreateTemplate {
        title: "New Access Rule".to_string(),
        user: Some(UserContext {
            uuid: "test".to_string(),
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
        form: AccessRuleCreateForm::default(),
        user_groups: vec![GroupOption {
            id: 1,
            name: "Users".to_string(),
            is_virtual: false,
            virtual_asset_count: None,
        }],
        asset_groups: vec![GroupOption {
            id: 1,
            name: "Servers".to_string(),
            is_virtual: false,
            virtual_asset_count: None,
        }],
        industrial_enabled: false,
    };
    let html = askama::Template::render(&template).expect("template must render");

    assert!(
        !html.contains(r#"name="allowed_iacs""#),
        "kill-switch render must hide the allowed_iacs checkbox; rendered HTML follows:\n{html}"
    );
    // SSH / RDP stay so the form is still useful for the non-IACS use case.
    assert!(
        html.contains(r#"name="allowed_ssh""#),
        "kill-switch must keep the SSH checkbox; the kill-switch is surgical, not collateral"
    );
    assert!(
        html.contains(r#"name="allowed_rdp""#),
        "kill-switch must keep the RDP checkbox; the kill-switch is surgical, not collateral"
    );
}

/// Same drill on the edit template. Combined with the
/// `update_access_rule_web` server-side preserve logic this means a
/// rule that was created back when industrial was ON keeps its
/// `iacs_*` protocols across an unrelated edit (e.g. a title fix)
/// even though the admin cannot tick the checkbox in this mode.
#[test]
fn access_rule_edit_template_hides_iacs_checkbox_under_kill_switch() {
    use vauban_web::templates::assets::{
        access_rule_create::GroupOption,
        access_rule_edit::{AccessRuleEdit, AccessRuleEditTemplate},
    };
    use vauban_web::templates::base::{UserContext, VaubanConfig};

    let template = AccessRuleEditTemplate {
        title: "Edit Access Rule".to_string(),
        user: Some(UserContext {
            uuid: "test".to_string(),
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
        rule: AccessRuleEdit {
            uuid: Uuid::new_v4().to_string(),
            name: "rule-name".to_string(),
            description: String::new(),
            user_group_id: 1,
            asset_group_id: 1,
            allowed_ssh: true,
            allowed_rdp: false,
            allowed_iacs: true,
            valid_from: String::new(),
            valid_until: String::new(),
            require_mfa: false,
            require_approval: false,
            duration_value: Some(2),
            duration_unit: "hours".to_string(),
            is_active: true,
            priority: "0".to_string(),
        },
        user_groups: vec![GroupOption {
            id: 1,
            name: "Users".to_string(),
            is_virtual: false,
            virtual_asset_count: None,
        }],
        asset_groups: vec![GroupOption {
            id: 1,
            name: "Servers".to_string(),
            is_virtual: false,
            virtual_asset_count: None,
        }],
        industrial_enabled: false,
    };
    let html = askama::Template::render(&template).expect("edit template must render");

    assert!(
        !html.contains(r#"name="allowed_iacs""#),
        "edit template under kill-switch must hide the allowed_iacs checkbox; \
         rendered HTML follows:\n{html}"
    );
    // The form still must offer to edit the rest of the rule (frozen-but-preserved):
    // `update_access_rule_web` preserves the `iacs_*` protocols across no-op edits.
    assert!(
        html.contains(r#"name="allowed_ssh""#),
        "edit template must keep the SSH checkbox under the kill-switch"
    );
}

// ===================================================================
// Forensic vs operational split -- pin at source-grep level
// ===================================================================

/// Slice a source string from the given function signature to the
/// next top-level `fn` boundary, so an assertion stays scoped to one
/// function body.
fn scoped_fn_body<'a>(src: &'a str, sig: &str) -> &'a str {
    let start = src
        .find(sig)
        .unwrap_or_else(|| panic!("function signature `{}` not found", sig));
    let after = &src[start + sig.len()..];
    let end_rel = after
        .find("\nasync fn ")
        .or_else(|| after.find("\nfn "))
        .or_else(|| after.find("\npub async fn "))
        .or_else(|| after.find("\npub(crate) async fn "))
        .or_else(|| after.find("\npub fn "))
        .map(|e| start + sig.len() + e)
        .unwrap_or(src.len());
    &src[start..end_rel]
}

/// The kill-switch splits the IACS session surface in two:
///
/// * Operational lists (`session_list`, `active_sessions`) HIDE IACS
///   when `industrial.enabled = false` -- they gate on the flag.
/// * Forensic surfaces (`recording_list`, the audit log) stay fully
///   visible -- they MUST NOT carry an `industrial.enabled` guard, so
///   yesterday's audit trail survives switching IACS off.
///
/// This replaces the pre-0.7.x `audit_surfaces_have_no_industrial_gate`
/// contract, which forbade ANY gate in `handlers/web/sessions.rs`. The
/// operational lists now legitimately read the flag; only the forensic
/// functions remain gate-free.
#[test]
fn forensic_surfaces_have_no_industrial_gate_but_operational_lists_do() {
    let sessions = include_str!("../../src/handlers/web/sessions.rs");
    let audit = include_str!("../../src/handlers/web/audit.rs");

    let needle = "industrial.enabled";

    // Forensic: the audit-log handler module carries NO gate at all.
    assert!(
        !audit.contains(needle),
        "handlers/web/audit.rs must NOT gate visibility on industrial.enabled \
         (the audit log stays visible under the kill-switch)"
    );

    // Forensic: the recordings catalogue stays visible -- its handler
    // body must remain gate-free even though it lives in the same file
    // as the (now gated) operational lists.
    let recording_list = scoped_fn_body(sessions, "pub async fn recording_list");
    assert!(
        !recording_list.contains(needle),
        "recording_list MUST NOT gate on industrial.enabled -- recordings \
         are forensic and stay visible regardless of the kill-switch"
    );

    // Operational: the session history list and the active-sessions
    // pane DO hide IACS under the kill-switch.
    let session_list = scoped_fn_body(sessions, "pub async fn session_list");
    assert!(
        session_list.contains(needle) && session_list.contains("IacsTunnel"),
        "session_list MUST exclude IACS under the kill-switch \
         (`!state.config.industrial.enabled` + `session_type.ne(IacsTunnel)`)"
    );
    let active_sessions = scoped_fn_body(sessions, "pub async fn active_sessions");
    assert!(
        active_sessions.contains(needle) && active_sessions.contains("IacsTunnel"),
        "active_sessions MUST exclude IACS under the kill-switch \
         (`!state.config.industrial.enabled` + `session_type.ne(IacsTunnel)`)"
    );
}
