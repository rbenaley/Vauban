//! Live web: setting the per-tool mode select on `/sessions/mcp/access`
//! must persist after Save, even when the asset catalogue still has
//! `hitl: true`. Catalogue `hitl` is display-only.
use axum::http::header::{AUTHORIZATION, COOKIE, LOCATION};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serial_test::serial;
use uuid::Uuid;
use vauban_web::models::access_rule::{AccessRule, NewAccessRule};
use vauban_web::models::asset::{Asset, AssetType, NewAsset, NewAssetAssetGroup};
use vauban_web::schema::{
    access_rules, asset_asset_groups, asset_groups, assets, proxy_sessions, users, vauban_groups,
};

use std::collections::BTreeSet;
use vauban_web::services::mcp_session::{
    effective_tools_from_access, resolve_asset_catalog, resolve_rule_hitl_tools,
    resolve_rule_require_plan_tools,
};

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{
    create_admin_user, create_test_asset_group, create_test_vauban_group, unique_name,
};

fn auth_csrf_cookie(token: &str, csrf: &str) -> String {
    format!("access_token={}; __vauban_csrf={}", token, csrf)
}

fn tool_mode_selected(html: &str, tool: &str, mode: &str) -> bool {
    let needle = format!("name=\"mcp_tool_mode[{tool}]\"");
    let Some(after) = html.split(&needle).nth(1) else {
        return false;
    };
    let block = after.split("</select>").next().unwrap_or("");
    block
        .split("<option")
        .any(|chunk| chunk.contains(&format!("value=\"{mode}\"")) && chunk.contains("selected"))
}

#[tokio::test]
#[serial]
async fn mcp_access_uncheck_hitl_survives_save_despite_catalogue_flag() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("mcp_hitl_save")).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("mcp-hitl-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("mcp-hitl-ag")).await;

    let ug_id: i32 = vauban_groups::table
        .filter(vauban_groups::uuid.eq(ug))
        .select(vauban_groups::id)
        .first(&mut conn)
        .await
        .unwrap();
    let ag_id: i32 = asset_groups::table
        .filter(asset_groups::uuid.eq(ag))
        .select(asset_groups::id)
        .first(&mut conn)
        .await
        .unwrap();

    let asset: Asset = diesel::insert_into(assets::table)
        .values(&NewAsset {
            uuid: Uuid::new_v4(),
            name: unique_name("mcp-hitl-asset"),
            hostname: format!("{}.mcp.test", unique_name("up")),
            port: 19001,
            asset_type: AssetType::Mcp,
            status: "online".into(),
            description: Some("catalogue echo HITL sticky".into()),
            connection_config: serde_json::json!({
                "allowed_tools": ["echo"],
                "mcp_tool_catalog": [{
                    "name": "echo",
                    "description": "Echo a message back",
                    "status": "approved",
                    "hitl": true
                }]
            }),
            created_by_id: None,
            updated_by_id: None,
            connection_username: String::new(),
        })
        .get_result(&mut conn)
        .await
        .unwrap();
    diesel::insert_into(asset_asset_groups::table)
        .values(&NewAssetAssetGroup {
            asset_id: asset.id,
            asset_group_id: ag_id,
        })
        .execute(&mut conn)
        .await
        .unwrap();

    let rule_uuid = Uuid::new_v4();
    diesel::insert_into(access_rules::table)
        .values(&NewAccessRule {
            uuid: rule_uuid,
            name: unique_name("mcp-hitl-rule"),
            description: Some("echo allow + hitl".into()),
            user_group_id: ug_id,
            asset_group_id: ag_id,
            allowed_protocols: vec![Some("mcp".into())],
            valid_from: None,
            valid_until: None,
            require_mfa: false,
            require_approval: false,
            max_session_duration: None,
            is_active: true,
            priority: 0,
            created_by_id: None,
            mcp_allowed_tools: Some(vec![Some("echo".into())]),
            mcp_hitl_tools: Some(vec![Some("echo".into())]),
            mcp_require_plan_tools: None,
            mcp_drift_iam: "suspend_group".to_string(),
        })
        .execute(&mut conn)
        .await
        .unwrap();

    let csrf = app.generate_csrf_token();
    let edit_url = format!("/sessions/mcp/access/{rule_uuid}/edit");

    let before = app
        .server
        .get(&edit_url)
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .await;
    if before.status_code().as_u16() != 200 {
        let loc = before
            .headers()
            .get(LOCATION)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        panic!(
            "GET edit expected 200, got {} Location={loc}",
            before.status_code()
        );
    }
    assert!(
        tool_mode_selected(&before.text(), "echo", "hitl"),
        "edit form must select HITL when the rule lists echo"
    );

    let saved = app
        .server
        .post(&edit_url)
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", "mcp-hitl-rule-saved"),
            ("description", "echo allow, hitl cleared"),
            ("user_group_id", &ug_id.to_string()),
            ("asset_group_id", &ag_id.to_string()),
            ("priority", "0"),
            ("is_active", "true"),
            ("mcp_tool_mode[echo]", "allow"),
        ])
        .await;
    let status = saved.status_code().as_u16();
    let location = saved
        .headers()
        .get(LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        status == 302 || status == 303,
        "Save must redirect, got {status}; Location={location}"
    );
    assert!(
        location.contains(&format!("/sessions/mcp/access/{rule_uuid}")),
        "Save must land on the rule, not bounce to edit with an error: {location}"
    );

    let row: AccessRule = access_rules::table
        .filter(access_rules::uuid.eq(rule_uuid))
        .first(&mut conn)
        .await
        .unwrap();
    let allowed: Vec<String> = row
        .mcp_allowed_tools
        .unwrap_or_default()
        .into_iter()
        .flatten()
        .collect();
    let hitl: Vec<String> = row
        .mcp_hitl_tools
        .unwrap_or_default()
        .into_iter()
        .flatten()
        .collect();
    assert_eq!(allowed, vec!["echo".to_string()]);
    assert!(
        !hitl.iter().any(|t| t == "echo"),
        "DB must drop echo from mcp_hitl_tools after Allow+Save, got {hitl:?}"
    );

    let after = app
        .server
        .get(&edit_url)
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .await;
    assert_status(&after, 200);
    assert!(
        tool_mode_selected(&after.text(), "echo", "allow")
            && !tool_mode_selected(&after.text(), "echo", "hitl"),
        "catalogue hitl:true must not re-select HITL after Allow+Save"
    );

    test_db::cleanup(&mut conn).await;
}

/// Opening the PAM Access Rules editor for an MCP rule must land in
/// MCP → Access Rules (`/sessions/mcp/access/{uuid}/edit`).
#[tokio::test]
#[serial]
async fn pam_access_edit_redirects_mcp_rule_to_mcp_nest() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("mcp_pam_redir")).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("mcp-pam-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("mcp-pam-ag")).await;

    let ug_id: i32 = vauban_groups::table
        .filter(vauban_groups::uuid.eq(ug))
        .select(vauban_groups::id)
        .first(&mut conn)
        .await
        .unwrap();
    let ag_id: i32 = asset_groups::table
        .filter(asset_groups::uuid.eq(ag))
        .select(asset_groups::id)
        .first(&mut conn)
        .await
        .unwrap();

    let rule_uuid = Uuid::new_v4();
    diesel::insert_into(access_rules::table)
        .values(&NewAccessRule {
            uuid: rule_uuid,
            name: unique_name("mcp-pam-rule"),
            description: None,
            user_group_id: ug_id,
            asset_group_id: ag_id,
            allowed_protocols: vec![Some("mcp".into())],
            valid_from: None,
            valid_until: None,
            require_mfa: false,
            require_approval: false,
            max_session_duration: None,
            is_active: true,
            priority: 0,
            created_by_id: None,
            mcp_allowed_tools: None,
            mcp_hitl_tools: None,
            mcp_require_plan_tools: None,
            mcp_drift_iam: "suspend_group".to_string(),
        })
        .execute(&mut conn)
        .await
        .unwrap();

    let csrf = app.generate_csrf_token();
    let edit = app
        .server
        .get(&format!("/assets/access/{rule_uuid}/edit"))
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .await;
    let status = edit.status_code().as_u16();
    let location = edit
        .headers()
        .get(LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        status == 302 || status == 303,
        "PAM edit of an MCP rule must redirect, got {status}"
    );
    assert_eq!(
        location,
        format!("/sessions/mcp/access/{rule_uuid}/edit"),
        "must open MCP Access Rules, not stay on /assets/access"
    );

    let detail = app
        .server
        .get(&format!("/assets/access/{rule_uuid}"))
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .await;
    let detail_loc = detail
        .headers()
        .get(LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        detail_loc,
        format!("/sessions/mcp/access/{rule_uuid}"),
        "PAM detail of an MCP rule must redirect into the MCP nest"
    );

    test_db::cleanup(&mut conn).await;
}

/// Connect UI must evaluate access_rules (no superuser bypass) and
/// refuse when the operator has no MCP rule.
#[tokio::test]
#[serial]
async fn connect_mcp_without_rule_is_denied() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("mcp_conn")).await;
    let asset: Asset = diesel::insert_into(assets::table)
        .values(&NewAsset {
            uuid: Uuid::new_v4(),
            name: unique_name("mcp-conn-asset"),
            hostname: format!("{}.mcp.test", unique_name("up")),
            port: 19001,
            asset_type: AssetType::Mcp,
            status: "online".into(),
            description: None,
            connection_config: serde_json::json!({}),
            created_by_id: None,
            updated_by_id: None,
            connection_username: String::new(),
        })
        .get_result(&mut conn)
        .await
        .unwrap();

    let csrf = app.generate_csrf_token();
    let resp = app
        .server
        .post(&format!("/assets/{}/connect-mcp", asset.uuid))
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("justification", "live test connect without an access rule"),
        ])
        .await;
    let status = resp.status_code().as_u16();
    let body = resp.text();
    assert!(
        status == 200 || status == 302 || status == 303 || status == 403,
        "connect-mcp without a rule must not succeed, got {status}"
    );
    if status == 200 {
        assert!(
            body.contains("No access rule") || body.contains("access rule"),
            "toast/body must explain the access deny, got: {}",
            body.chars().take(400).collect::<String>()
        );
    }

    let n: i64 = proxy_sessions::table
        .filter(proxy_sessions::asset_id.eq(asset.id))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap();
    assert_eq!(n, 0, "denied Connect must not leave a proxy_sessions row");

    test_db::cleanup(&mut conn).await;
}

/// Hop 1 API is vbn_-only. A JWT on /api/v1/sessions session_type=mcp
/// must be rejected at the M2M gate (401), never 500.
#[tokio::test]
#[serial]
async fn api_mcp_open_with_jwt_is_forbidden() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("mcp_jwt")).await;
    let asset: Asset = diesel::insert_into(assets::table)
        .values(&NewAsset {
            uuid: Uuid::new_v4(),
            name: unique_name("mcp-jwt-asset"),
            hostname: format!("{}.mcp.test", unique_name("up")),
            port: 19001,
            asset_type: AssetType::Mcp,
            status: "online".into(),
            description: None,
            connection_config: serde_json::json!({}),
            created_by_id: None,
            updated_by_id: None,
            connection_username: String::new(),
        })
        .get_result(&mut conn)
        .await
        .unwrap();

    let resp = app
        .server
        .post("/api/v1/sessions")
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .json(&serde_json::json!({
            "asset_id": asset.uuid.to_string(),
            "credential_id": "mcp",
            "session_type": "mcp",
            "justification": "jwt must not open an MCP hop 1 session"
        }))
        .await;
    assert_eq!(
        resp.status_code().as_u16(),
        401,
        "JWT on /api/v1 MCP hop 1 must be rejected at the M2M gate (401), got {} body={}",
        resp.status_code(),
        resp.text()
    );

    test_db::cleanup(&mut conn).await;
}

/// SSH hop 1 on an MCP asset must not create a pending proxy_sessions row.
#[tokio::test]
#[serial]
async fn api_ssh_session_type_on_mcp_asset_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("mcp_ssh_mismatch"),
    )
    .await;
    let asset: Asset = diesel::insert_into(assets::table)
        .values(&NewAsset {
            uuid: Uuid::new_v4(),
            name: unique_name("mcp-ssh-mismatch"),
            hostname: format!("{}.mcp.test", unique_name("up")),
            port: 19001,
            asset_type: AssetType::Mcp,
            status: "online".into(),
            description: None,
            connection_config: serde_json::json!({}),
            created_by_id: None,
            updated_by_id: None,
            connection_username: String::new(),
        })
        .get_result(&mut conn)
        .await
        .unwrap();

    let resp = app
        .server
        .post("/api/v1/sessions")
        .add_header(AUTHORIZATION, app.api_key_header(&admin.api_key))
        .json(&serde_json::json!({
            "asset_id": asset.uuid.to_string(),
            "credential_id": "mcp",
            "session_type": "ssh",
            "justification": "mismatch must not open an SSH row on an MCP asset"
        }))
        .await;
    assert_eq!(
        resp.status_code().as_u16(),
        400,
        "session_type ssh on MCP asset must be 400, got {} body={}",
        resp.status_code(),
        resp.text()
    );
    let n: i64 = proxy_sessions::table
        .filter(proxy_sessions::asset_id.eq(asset.id))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap();
    assert_eq!(
        n, 0,
        "rejected mismatch must not leave a proxy_sessions row"
    );

    test_db::cleanup(&mut conn).await;
}

/// MCP nest pages must render for an admin (HITL + Access Rules).
#[tokio::test]
#[serial]
async fn mcp_zone_pages_render_for_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("mcp_zone")).await;
    let csrf = app.generate_csrf_token();
    let cookie = auth_csrf_cookie(&admin.token, &csrf);

    for path in [
        "/sessions/mcp/access",
        "/sessions/mcp/access/new",
        "/sessions/mcp/contestations",
    ] {
        let resp = app
            .server
            .get(path)
            .add_header(AUTHORIZATION, app.auth_header(&admin.token))
            .add_header(COOKIE, cookie.as_str())
            .await;
        assert_eq!(
            resp.status_code().as_u16(),
            200,
            "{path} must render, got {} body={}",
            resp.status_code(),
            resp.text().chars().take(200).collect::<String>()
        );
    }

    // HITL landing talks to vauban-proxy-mcp. TestApp has no proxy, so
    // the page fail-closes with a redirect instead of a blank queue.
    let hitl = app
        .server
        .get("/sessions/mcp")
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(COOKIE, cookie.as_str())
        .await;
    let hitl_status = hitl.status_code().as_u16();
    assert!(
        hitl_status == 302 || hitl_status == 303,
        "/sessions/mcp without proxy_mcp must redirect, got {hitl_status}"
    );

    test_db::cleanup(&mut conn).await;
}

/// Creating an MCP access rule via the nest form persists allow + HITL.
#[tokio::test]
#[serial]
async fn mcp_access_create_form_persists_tools() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("mcp_create")).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("mcp-create-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("mcp-create-ag")).await;

    let ug_id: i32 = vauban_groups::table
        .filter(vauban_groups::uuid.eq(ug))
        .select(vauban_groups::id)
        .first(&mut conn)
        .await
        .unwrap();
    let ag_id: i32 = asset_groups::table
        .filter(asset_groups::uuid.eq(ag))
        .select(asset_groups::id)
        .first(&mut conn)
        .await
        .unwrap();

    let asset: Asset = diesel::insert_into(assets::table)
        .values(&NewAsset {
            uuid: Uuid::new_v4(),
            name: unique_name("mcp-create-asset"),
            hostname: format!("{}.mcp.test", unique_name("up")),
            port: 19001,
            asset_type: AssetType::Mcp,
            status: "online".into(),
            description: None,
            connection_config: serde_json::json!({
                "allowed_tools": ["echo"],
                "mcp_tool_catalog": [{
                    "name": "echo",
                    "description": "Echo",
                    "status": "approved",
                    "hitl": false
                }]
            }),
            created_by_id: None,
            updated_by_id: None,
            connection_username: String::new(),
        })
        .get_result(&mut conn)
        .await
        .unwrap();
    diesel::insert_into(asset_asset_groups::table)
        .values(&NewAssetAssetGroup {
            asset_id: asset.id,
            asset_group_id: ag_id,
        })
        .execute(&mut conn)
        .await
        .unwrap();

    let csrf = app.generate_csrf_token();
    let name = unique_name("mcp-create-rule");
    let resp = app
        .server
        .post("/sessions/mcp/access")
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", name.as_str()),
            ("description", "created via live form"),
            ("user_group_id", &ug_id.to_string()),
            ("priority", "0"),
            ("is_active", "true"),
            ("mcp_tool_mode[echo]", "hitl"),
            ("asset_group_id", &ag_id.to_string()),
        ])
        .await;
    let status = resp.status_code().as_u16();
    let location = resp
        .headers()
        .get(LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        status == 302 || status == 303,
        "create must redirect, got {status}; Location={location}"
    );
    assert!(
        location.contains("/sessions/mcp/access/"),
        "must land on the new rule, got {location}"
    );

    let row: AccessRule = access_rules::table
        .filter(access_rules::name.eq(&name))
        .first(&mut conn)
        .await
        .unwrap();
    let allowed: Vec<String> = row
        .mcp_allowed_tools
        .unwrap_or_default()
        .into_iter()
        .flatten()
        .collect();
    let hitl: Vec<String> = row
        .mcp_hitl_tools
        .unwrap_or_default()
        .into_iter()
        .flatten()
        .collect();
    assert_eq!(allowed, vec!["echo".to_string()]);
    assert_eq!(hitl, vec!["echo".to_string()]);
    assert!(
        row.allowed_protocols.iter().flatten().any(|p| p == "mcp"),
        "create must pin allowed_protocols to mcp"
    );
    assert!(
        row.mcp_require_plan_tools
            .unwrap_or_default()
            .into_iter()
            .flatten()
            .next()
            .is_none(),
        "HITL mode must not write require_plan"
    );

    test_db::cleanup(&mut conn).await;
}

/// One select per tool: Require plan joins the allow-list; all Off
/// clears the three SQL columns (unrestricted by this rule).
#[tokio::test]
#[serial]
async fn mcp_access_select_require_plan_then_all_off() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("mcp_sel")).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("mcp-sel-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("mcp-sel-ag")).await;

    let ug_id: i32 = vauban_groups::table
        .filter(vauban_groups::uuid.eq(ug))
        .select(vauban_groups::id)
        .first(&mut conn)
        .await
        .unwrap();
    let ag_id: i32 = asset_groups::table
        .filter(asset_groups::uuid.eq(ag))
        .select(asset_groups::id)
        .first(&mut conn)
        .await
        .unwrap();

    let asset: Asset = diesel::insert_into(assets::table)
        .values(&NewAsset {
            uuid: Uuid::new_v4(),
            name: unique_name("mcp-sel-asset"),
            hostname: format!("{}.mcp.test", unique_name("up")),
            port: 19001,
            asset_type: AssetType::Mcp,
            status: "online".into(),
            description: None,
            connection_config: serde_json::json!({
                "allowed_tools": ["echo", "write_secret"],
                "mcp_tool_catalog": [
                    {
                        "name": "echo",
                        "description": "Echo",
                        "status": "approved",
                        "hitl": false
                    },
                    {
                        "name": "write_secret",
                        "description": "Write",
                        "status": "approved",
                        "hitl": false
                    }
                ]
            }),
            created_by_id: None,
            updated_by_id: None,
            connection_username: String::new(),
        })
        .get_result(&mut conn)
        .await
        .unwrap();
    diesel::insert_into(asset_asset_groups::table)
        .values(&NewAssetAssetGroup {
            asset_id: asset.id,
            asset_group_id: ag_id,
        })
        .execute(&mut conn)
        .await
        .unwrap();

    let csrf = app.generate_csrf_token();
    let cookie = auth_csrf_cookie(&admin.token, &csrf);
    let new_form = app
        .server
        .get("/sessions/mcp/access/new")
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(COOKIE, cookie.as_str())
        .await;
    assert_status(&new_form, 200);
    let new_html = new_form.text();
    assert!(
        !new_html.contains("name=\"mcp_hitl_tools\"") && !new_html.contains("name=\"mcp_tools\""),
        "create form must not render the old checkbox columns"
    );
    if new_html.contains("name=\"mcp_tool_mode[") {
        assert!(
            new_html.contains("<select name=\"mcp_tool_mode["),
            "tool matrix must be a select, not checkboxes"
        );
    }

    let name = unique_name("mcp-sel-rule");
    let created = app
        .server
        .post("/sessions/mcp/access")
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(COOKIE, cookie.as_str())
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", name.as_str()),
            ("description", "select modes"),
            ("user_group_id", &ug_id.to_string()),
            ("asset_group_id", &ag_id.to_string()),
            ("priority", "0"),
            ("is_active", "true"),
            ("mcp_tool_mode[echo]", "require_plan"),
            ("mcp_tool_mode[write_secret]", "off"),
        ])
        .await;
    let location = created
        .headers()
        .get(LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    let status = created.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "create must redirect, got {status}; Location={location}"
    );

    let row: AccessRule = access_rules::table
        .filter(access_rules::name.eq(&name))
        .first(&mut conn)
        .await
        .unwrap();
    let rule_uuid = row.uuid;
    let flatten = |col: Option<Vec<Option<String>>>| -> Vec<String> {
        col.unwrap_or_default().into_iter().flatten().collect()
    };
    assert_eq!(
        flatten(row.mcp_allowed_tools.clone()),
        vec!["echo".to_string()]
    );
    assert!(
        flatten(row.mcp_hitl_tools.clone()).is_empty(),
        "Require plan must not also write mcp_hitl_tools"
    );
    assert_eq!(
        flatten(row.mcp_require_plan_tools.clone()),
        vec!["echo".to_string()]
    );

    let detail = app
        .server
        .get(&format!("/sessions/mcp/access/{rule_uuid}"))
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(COOKIE, cookie.as_str())
        .await;
    assert_status(&detail, 200);
    let detail_html = detail.text();
    assert!(
        detail_html.contains("Modes are this access rule only")
            && detail_html.contains("this rule grants no tool")
            && detail_html.contains("echo")
            && detail_html.contains("Require plan")
            && !detail_html.contains("Allow-list"),
        "detail must show the rule matrix, not a catalogue-filtered allow-list dump"
    );

    let edit_url = format!("/sessions/mcp/access/{rule_uuid}/edit");
    let edit = app
        .server
        .get(&edit_url)
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(COOKIE, cookie.as_str())
        .await;
    assert_status(&edit, 200);
    let edit_html = edit.text();
    assert!(
        tool_mode_selected(&edit_html, "echo", "require_plan")
            && tool_mode_selected(&edit_html, "write_secret", "off"),
        "edit form must restore Require plan / Off from SQL"
    );

    let saved = app
        .server
        .post(&edit_url)
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(COOKIE, cookie.as_str())
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", name.as_str()),
            ("description", "all off"),
            ("user_group_id", &ug_id.to_string()),
            ("asset_group_id", &ag_id.to_string()),
            ("priority", "0"),
            ("is_active", "true"),
            ("mcp_tool_mode[echo]", "off"),
            ("mcp_tool_mode[write_secret]", "off"),
        ])
        .await;
    let save_status = saved.status_code().as_u16();
    assert!(
        save_status == 302 || save_status == 303,
        "all-Off Save must redirect, got {save_status}"
    );

    let cleared: AccessRule = access_rules::table
        .filter(access_rules::uuid.eq(rule_uuid))
        .first(&mut conn)
        .await
        .unwrap();
    assert!(
        cleared.mcp_allowed_tools == Some(Vec::new())
            && cleared.mcp_hitl_tools.is_none()
            && cleared.mcp_require_plan_tools.is_none(),
        "all Off must write an empty allow-list (grants nothing) and NULL gates"
    );

    test_db::cleanup(&mut conn).await;
}

/// Delete from the MCP nest: a forged CSRF token keeps the rule, a valid
/// one removes it, and a second delete of the same UUID is refused.
#[tokio::test]
#[serial]
async fn mcp_access_delete_needs_csrf_and_removes_the_rule_once() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("mcp_del")).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("mcp-del-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("mcp-del-ag")).await;
    let ug_id: i32 = vauban_groups::table
        .filter(vauban_groups::uuid.eq(ug))
        .select(vauban_groups::id)
        .first(&mut conn)
        .await
        .unwrap();
    let ag_id: i32 = asset_groups::table
        .filter(asset_groups::uuid.eq(ag))
        .select(asset_groups::id)
        .first(&mut conn)
        .await
        .unwrap();

    let csrf = app.generate_csrf_token();
    let cookie = auth_csrf_cookie(&admin.token, &csrf);
    let name = unique_name("mcp-del-rule");
    let created = app
        .server
        .post("/sessions/mcp/access")
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(COOKIE, cookie.as_str())
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", name.as_str()),
            ("description", "to delete"),
            ("user_group_id", &ug_id.to_string()),
            ("asset_group_id", &ag_id.to_string()),
            ("priority", "0"),
            ("is_active", "true"),
        ])
        .await;
    let status = created.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "create must redirect, got {status}"
    );
    let rule_uuid: Uuid = access_rules::table
        .filter(access_rules::name.eq(&name))
        .select(access_rules::uuid)
        .first(&mut conn)
        .await
        .unwrap();
    let delete_url = format!("/sessions/mcp/access/{rule_uuid}/delete");
    let location = |resp: &axum_test::TestResponse| {
        resp.headers()
            .get(LOCATION)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    async fn remaining(conn: &mut diesel_async::AsyncPgConnection, uuid: Uuid) -> i64 {
        access_rules::table
            .filter(access_rules::uuid.eq(uuid))
            .count()
            .get_result(conn)
            .await
            .unwrap()
    }

    let forged = app
        .server
        .post(&delete_url)
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(COOKIE, cookie.as_str())
        .form(&[("csrf_token", "forged")])
        .await;
    assert_eq!(
        location(&forged),
        format!("/sessions/mcp/access/{rule_uuid}"),
        "a forged CSRF token must bounce back to the rule"
    );
    assert_eq!(
        remaining(&mut conn, rule_uuid).await,
        1,
        "forged delete must keep the rule"
    );

    let deleted = app
        .server
        .post(&delete_url)
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(COOKIE, cookie.as_str())
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    // The detail page posts with htmx: a 303 would be followed and the
    // list swapped inside the form.
    assert_eq!(deleted.status_code().as_u16(), 200);
    assert_eq!(
        deleted
            .headers()
            .get("hx-redirect")
            .and_then(|h| h.to_str().ok()),
        Some("/sessions/mcp/access")
    );
    assert_eq!(
        remaining(&mut conn, rule_uuid).await,
        0,
        "valid delete must remove the rule"
    );

    let again = app
        .server
        .post(&delete_url)
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(COOKIE, cookie.as_str())
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    let again_status = again.status_code().as_u16();
    assert!(
        (again_status == 302 || again_status == 303) && location(&again) == "/sessions/mcp/access",
        "deleting a gone rule must flash back to the list, got {again_status}"
    );

    test_db::cleanup(&mut conn).await;
}

/// A flash set by a redirect into the MCP zone is shown on the page it
/// lands on: the flash middleware clears the cookie whether it is read or not.
#[tokio::test]
#[serial]
async fn mcp_access_list_shows_the_flash_it_was_redirected_with() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("mcp_flash")).await;

    let csrf = app.generate_csrf_token();
    let resp = app
        .server
        .post(&format!("/sessions/mcp/access/{}/delete", Uuid::new_v4()))
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    let flash = resp
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|c| c.to_str().ok())
        .find(|c| c.contains("__vauban_flash"))
        .and_then(|c| c.split(';').next())
        .map(str::to_string)
        .expect("a refused delete redirects with a flash");

    let page = app
        .server
        .get("/sessions/mcp/access")
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(
            COOKIE,
            format!("{}; {flash}", auth_csrf_cookie(&admin.token, &csrf)),
        )
        .await;
    assert!(
        page.text().contains("Access rule not found"),
        "the flash must be rendered on the landing page"
    );

    test_db::cleanup(&mut conn).await;
}

/// A rule that grants MCP but no approved tool: access allows the asset,
/// the whitelist access computes is empty, so Connect and API hop 1 both
/// refuse before anything is opened on the proxy.
#[tokio::test]
#[serial]
async fn connect_and_hop1_refuse_when_no_approved_tool_is_granted() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("mcp_notool")).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("mcp-notool-ug")).await;
    crate::fixtures::add_user_to_vauban_group(&mut conn, admin.user.id, &ug).await;
    let ug_id: i32 = vauban_groups::table
        .filter(vauban_groups::uuid.eq(ug))
        .select(vauban_groups::id)
        .first(&mut conn)
        .await
        .unwrap();
    let ag = create_test_asset_group(&mut conn, &unique_name("mcp-notool-ag")).await;
    let ag_id: i32 = asset_groups::table
        .filter(asset_groups::uuid.eq(ag))
        .select(asset_groups::id)
        .first(&mut conn)
        .await
        .unwrap();
    let asset: Asset = diesel::insert_into(assets::table)
        .values(&NewAsset {
            uuid: Uuid::new_v4(),
            name: unique_name("mcp-notool-asset"),
            hostname: format!("{}.mcp.test", unique_name("up")),
            port: 19001,
            asset_type: AssetType::Mcp,
            status: "online".into(),
            description: None,
            connection_config: serde_json::json!({ "allowed_tools": ["echo"] }),
            created_by_id: None,
            updated_by_id: None,
            connection_username: String::new(),
        })
        .get_result(&mut conn)
        .await
        .unwrap();
    diesel::insert_into(asset_asset_groups::table)
        .values(&NewAssetAssetGroup {
            asset_id: asset.id,
            asset_group_id: ag_id,
        })
        .execute(&mut conn)
        .await
        .unwrap();
    diesel::insert_into(access_rules::table)
        .values(&NewAccessRule {
            uuid: Uuid::new_v4(),
            name: unique_name("mcp-notool-rule"),
            description: None,
            user_group_id: ug_id,
            asset_group_id: ag_id,
            allowed_protocols: vec![Some("mcp".into())],
            valid_from: None,
            valid_until: None,
            require_mfa: false,
            require_approval: false,
            max_session_duration: None,
            is_active: true,
            priority: 0,
            created_by_id: None,
            mcp_allowed_tools: Some(Vec::new()),
            mcp_hitl_tools: None,
            mcp_require_plan_tools: None,
            mcp_drift_iam: "suspend_group".to_string(),
        })
        .execute(&mut conn)
        .await
        .unwrap();

    let csrf = app.generate_csrf_token();
    let resp = app
        .server
        .post(&format!("/assets/{}/connect-mcp", asset.uuid))
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .add_header("HX-Request", "true")
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("justification", "connect with every tool Off on the rule"),
        ])
        .await;
    let body = resp.text();
    let headers = format!("{:?}", resp.headers());
    assert!(
        body.contains("No MCP tools granted") || headers.contains("No MCP tools granted"),
        "Connect must name the empty whitelist: {headers} {}",
        body.chars().take(400).collect::<String>()
    );

    let resp = app
        .server
        .post("/api/v1/mcp/sessions")
        .add_header(AUTHORIZATION, app.api_key_header(&admin.api_key))
        .json(&serde_json::json!({
            "asset_id": asset.uuid,
            "justification": "hop 1 with every tool Off on the rule",
        }))
        .await;
    assert_eq!(resp.status_code().as_u16(), 400, "{}", resp.text());
    assert!(
        resp.text().contains("No MCP tools granted"),
        "{}",
        resp.text()
    );

    let n: i64 = proxy_sessions::table
        .filter(proxy_sessions::asset_id.eq(asset.id))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap();
    assert_eq!(n, 0, "a refused open leaves no proxy_sessions row");

    test_db::cleanup(&mut conn).await;
}

/// Hop-1 whitelist from the database: a tool is callable only if the
/// catalogue approves it and every active MCP rule of the user names it.
/// A NULL rule grants nothing; an inactive rule does not count.
#[tokio::test]
#[serial]
async fn mcp_effective_tools_need_every_active_rule_and_the_catalogue() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_id = crate::fixtures::create_simple_user(&mut conn, "mcp_eff").await;
    let mut ug_ids = Vec::new();
    for tag in ["mcp-eff-ug-a", "mcp-eff-ug-b"] {
        let ug = create_test_vauban_group(&mut conn, &unique_name(tag)).await;
        crate::fixtures::add_user_to_vauban_group(&mut conn, user_id, &ug).await;
        ug_ids.push(
            vauban_groups::table
                .filter(vauban_groups::uuid.eq(ug))
                .select(vauban_groups::id)
                .first::<i32>(&mut conn)
                .await
                .unwrap(),
        );
    }
    let ag = create_test_asset_group(&mut conn, &unique_name("mcp-eff-ag")).await;
    let ag_id: i32 = asset_groups::table
        .filter(asset_groups::uuid.eq(ag))
        .select(asset_groups::id)
        .first(&mut conn)
        .await
        .unwrap();
    let asset: Asset = diesel::insert_into(assets::table)
        .values(&NewAsset {
            uuid: Uuid::new_v4(),
            name: unique_name("mcp-eff-asset"),
            hostname: format!("{}.mcp.test", unique_name("up")),
            port: 19001,
            asset_type: AssetType::Mcp,
            status: "online".into(),
            description: None,
            connection_config: serde_json::json!({ "allowed_tools": ["echo", "delete_task"] }),
            created_by_id: None,
            updated_by_id: None,
            connection_username: String::new(),
        })
        .get_result(&mut conn)
        .await
        .unwrap();
    diesel::insert_into(asset_asset_groups::table)
        .values(&NewAssetAssetGroup {
            asset_id: asset.id,
            asset_group_id: ag_id,
        })
        .execute(&mut conn)
        .await
        .unwrap();

    let tools = |names: &[&str]| Some(names.iter().map(|n| Some(n.to_string())).collect());
    let mut rule_uuids = Vec::new();
    for (ug_id, allowed) in [
        (ug_ids[0], tools(&["echo", "delete_task", "read_file"])),
        (ug_ids[1], tools(&["echo"])),
    ] {
        let uuid = Uuid::new_v4();
        diesel::insert_into(access_rules::table)
            .values(&NewAccessRule {
                uuid,
                name: unique_name("mcp-eff-rule"),
                description: None,
                user_group_id: ug_id,
                asset_group_id: ag_id,
                allowed_protocols: vec![Some("mcp".into())],
                valid_from: None,
                valid_until: None,
                require_mfa: false,
                require_approval: false,
                max_session_duration: None,
                is_active: true,
                priority: 0,
                created_by_id: None,
                mcp_allowed_tools: allowed,
                mcp_hitl_tools: None,
                mcp_require_plan_tools: None,
                mcp_drift_iam: "suspend_group".to_string(),
            })
            .execute(&mut conn)
            .await
            .unwrap();
        rule_uuids.push(uuid);
    }

    let user_uuid: Uuid = users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(&mut conn)
        .await
        .unwrap();
    let effective = async |asset: &Asset| {
        let mut got = effective_tools_from_access(&app.app_state, &user_uuid.to_string(), asset)
            .await
            .unwrap();
        got.sort();
        got
    };

    assert_eq!(
        effective(&asset).await,
        vec!["echo".to_string()],
        "both rules name echo; read_file is not approved, delete_task not granted by rule b"
    );
    assert_eq!(
        resolve_asset_catalog(&asset),
        Some(vec!["echo".to_string(), "delete_task".to_string()])
    );

    let names = |v: &[&str]| v.iter().map(|n| n.to_string()).collect::<BTreeSet<_>>();
    assert!(
        resolve_rule_hitl_tools(&mut conn, user_id, &asset)
            .await
            .unwrap()
            .is_empty()
            && resolve_rule_require_plan_tools(&mut conn, user_id, &asset)
                .await
                .unwrap()
                .is_empty(),
        "NULL gate columns add no gate"
    );
    diesel::update(access_rules::table.filter(access_rules::uuid.eq(rule_uuids[0])))
        .set((
            access_rules::mcp_hitl_tools.eq(tools(&["delete_task"])),
            access_rules::mcp_require_plan_tools.eq(tools(&["echo"])),
        ))
        .execute(&mut conn)
        .await
        .unwrap();
    diesel::update(access_rules::table.filter(access_rules::uuid.eq(rule_uuids[1])))
        .set(access_rules::mcp_hitl_tools.eq(tools(&["echo"])))
        .execute(&mut conn)
        .await
        .unwrap();
    assert_eq!(
        resolve_rule_hitl_tools(&mut conn, user_id, &asset)
            .await
            .unwrap(),
        names(&["delete_task", "echo"]),
        "HITL is the union of every applicable rule"
    );
    assert_eq!(
        resolve_rule_require_plan_tools(&mut conn, user_id, &asset)
            .await
            .unwrap(),
        names(&["echo"]),
        "Require plan is the union of every applicable rule"
    );
    diesel::update(access_rules::table.filter(access_rules::uuid.eq_any(&rule_uuids)))
        .set((
            access_rules::mcp_hitl_tools.eq(None::<Vec<Option<String>>>),
            access_rules::mcp_require_plan_tools.eq(None::<Vec<Option<String>>>),
        ))
        .execute(&mut conn)
        .await
        .unwrap();

    diesel::update(access_rules::table.filter(access_rules::uuid.eq(rule_uuids[1])))
        .set(access_rules::mcp_allowed_tools.eq(None::<Vec<Option<String>>>))
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(
        effective(&asset).await.is_empty(),
        "a NULL rule grants nothing, so the intersection is empty"
    );

    diesel::update(access_rules::table.filter(access_rules::uuid.eq(rule_uuids[1])))
        .set(access_rules::is_active.eq(false))
        .execute(&mut conn)
        .await
        .unwrap();
    assert_eq!(
        effective(&asset).await,
        vec!["delete_task".to_string(), "echo".to_string()],
        "an inactive rule does not apply"
    );

    test_db::cleanup(&mut conn).await;
}
