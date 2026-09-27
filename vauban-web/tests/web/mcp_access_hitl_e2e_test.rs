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
    access_rules, asset_asset_groups, asset_groups, assets, proxy_sessions, vauban_groups,
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
            && detail_html.contains("does not restrict")
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
        cleared.mcp_allowed_tools.is_none()
            && cleared.mcp_hitl_tools.is_none()
            && cleared.mcp_require_plan_tools.is_none(),
        "all Off must write NULL allow / HITL / plan columns"
    );

    test_db::cleanup(&mut conn).await;
}
