//! MCP access rules keep approved tools only, end to end: an administrator
//! deletes an asset, takes it out of its group or a tool is quarantined, and
//! the modes for those tools are erased from the rule by vauban-access (the
//! real in-process service), so a new asset or a re-approval never brings
//! them back.
use axum::http::header::COOKIE;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serial_test::serial;
use shared::mcp_tool_fingerprint::ToolDefinition;
use uuid::Uuid;
use vauban_web::models::access_rule::NewAccessRule;
use vauban_web::models::asset::{Asset, AssetType, NewAsset, NewAssetAssetGroup};
use vauban_web::schema::{access_rules, asset_asset_groups, asset_groups, assets, vauban_groups};
use vauban_web::services::mcp_discover::{
    DiscoveredTool, apply_discovered_catalog, approve_pending_catalog, catalog_from_config,
};
use vauban_web::services::mcp_tool_drift::{DriftReport, handle_drift};

use crate::common::TestApp;
use crate::fixtures::{
    TestUser, create_admin_user, create_test_asset_group, create_test_session_with_uuid,
    create_test_vauban_group, unique_name,
};

pub type Cols = (
    Option<Vec<Option<String>>>,
    Option<Vec<Option<String>>>,
    Option<Vec<Option<String>>>,
);

pub fn pg(names: &[&str]) -> Option<Vec<Option<String>>> {
    Some(names.iter().map(|n| Some((*n).to_string())).collect())
}

/// Catalogue with `tools`, all pending (TOFU) or all approved.
pub fn catalogue(tools: &[&str], approved: bool) -> serde_json::Value {
    let discovered: Vec<DiscoveredTool> = tools
        .iter()
        .map(|n| {
            DiscoveredTool {
                name: (*n).to_string(),
                description: format!("{n} tool"),
                input_schema: Some(serde_json::json!({"type": "object"})),
                ..Default::default()
            }
            .with_computed_fingerprint()
        })
        .collect();
    let cfg = apply_discovered_catalog(serde_json::json!({}), &discovered);
    if approved {
        approve_pending_catalog(cfg)
    } else {
        cfg
    }
}

pub struct Fixture {
    pub admin: TestUser,
    pub ug_id: i32,
    pub ag_id: i32,
    pub ag_uuid: Uuid,
}

pub async fn fixture(app: &TestApp, tag: &str) -> Fixture {
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name(tag)).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name(&format!("{tag}-ug"))).await;
    let ag_uuid = create_test_asset_group(&mut conn, &unique_name(&format!("{tag}-ag"))).await;
    let ug_id = vauban_groups::table
        .filter(vauban_groups::uuid.eq(ug))
        .select(vauban_groups::id)
        .first(&mut conn)
        .await
        .unwrap();
    let ag_id = asset_groups::table
        .filter(asset_groups::uuid.eq(ag_uuid))
        .select(asset_groups::id)
        .first(&mut conn)
        .await
        .unwrap();
    Fixture {
        admin,
        ug_id,
        ag_id,
        ag_uuid,
    }
}

pub async fn mcp_asset(app: &TestApp, ag_id: i32, config: serde_json::Value) -> Asset {
    let mut conn = app.get_conn().await;
    let asset: Asset = diesel::insert_into(assets::table)
        .values(&NewAsset {
            uuid: Uuid::new_v4(),
            name: unique_name("prune-mcp"),
            hostname: format!("{}.prune.test", unique_name("up")),
            port: 19002,
            asset_type: AssetType::Mcp,
            status: "online".into(),
            description: None,
            connection_config: config,
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
    asset
}

pub async fn rule(app: &TestApp, f: &Fixture, cols: Cols) -> Uuid {
    let mut conn = app.get_conn().await;
    let uuid = Uuid::new_v4();
    diesel::insert_into(access_rules::table)
        .values(&NewAccessRule {
            uuid,
            name: unique_name("prune-rule"),
            description: None,
            user_group_id: f.ug_id,
            asset_group_id: f.ag_id,
            allowed_protocols: vec![Some("mcp".into())],
            valid_from: None,
            valid_until: None,
            require_mfa: false,
            require_approval: false,
            max_session_duration: None,
            is_active: true,
            priority: 0,
            created_by_id: None,
            mcp_allowed_tools: cols.0,
            mcp_hitl_tools: cols.1,
            mcp_require_plan_tools: cols.2,
            mcp_drift_iam: "suspend_group".to_string(),
        })
        .execute(&mut conn)
        .await
        .unwrap();
    uuid
}

pub async fn cols_of(app: &TestApp, rule: Uuid) -> Cols {
    let mut conn = app.get_conn().await;
    access_rules::table
        .filter(access_rules::uuid.eq(rule))
        .select((
            access_rules::mcp_allowed_tools,
            access_rules::mcp_hitl_tools,
            access_rules::mcp_require_plan_tools,
        ))
        .first(&mut conn)
        .await
        .unwrap()
}

pub fn cookie(admin: &TestUser, csrf: &str) -> String {
    format!("access_token={}; __vauban_csrf={csrf}", admin.token)
}

async fn post(app: &TestApp, admin: &TestUser, path: &str, extra: &[(&str, &str)]) -> u16 {
    let csrf = app.generate_csrf_token();
    let mut form: Vec<(&str, &str)> = vec![("csrf_token", csrf.as_str())];
    form.extend_from_slice(extra);
    app.server
        .post(path)
        .add_header(COOKIE, cookie(admin, &csrf))
        .form(&form)
        .await
        .status_code()
        .as_u16()
}

async fn edit_page(app: &TestApp, admin: &TestUser, rule: Uuid) -> String {
    let csrf = app.generate_csrf_token();
    let r = app
        .server
        .get(&format!("/sessions/mcp/access/{rule}/edit"))
        .add_header(COOKIE, cookie(admin, &csrf))
        .await;
    assert_eq!(r.status_code().as_u16(), 200, "edit page");
    r.text()
}

#[tokio::test]
#[serial]
async fn gwt_deleting_an_mcp_asset_erases_its_modes_and_a_new_asset_does_not_inherit_them() {
    let app = TestApp::spawn().await;
    let f = fixture(app, "prune_del").await;
    let old = mcp_asset(app, f.ag_id, catalogue(&["echo", "purge"], true)).await;
    let rule = rule(app, &f, (pg(&["echo", "purge"]), pg(&["purge"]), None)).await;

    let status = post(
        app,
        &f.admin,
        &format!("/assets/manage/{}/delete", old.uuid),
        &[],
    )
    .await;
    assert!(matches!(status, 200 | 302 | 303), "delete: {status}");
    assert_eq!(
        cols_of(app, rule).await,
        (Some(vec![]), None, None),
        "the deleted asset's modes are erased from the rule"
    );

    let new = mcp_asset(app, f.ag_id, catalogue(&["echo", "purge"], false)).await;
    let page = edit_page(app, &f.admin, rule).await;
    assert!(
        !page.contains("name=\"mcp_tool_mode[echo]\"")
            && !page.contains("not in the approved catalogue"),
        "pending tools of the new asset are not offered on the rule"
    );

    let status = post(
        app,
        &f.admin,
        &format!("/assets/manage/{}/approve-mcp-tools", new.uuid),
        &[],
    )
    .await;
    assert!(matches!(status, 302 | 303), "approve: {status}");
    assert_eq!(
        cols_of(app, rule).await,
        (Some(vec![]), None, None),
        "Approve does not bring the old modes back"
    );
    let page = edit_page(app, &f.admin, rule).await;
    assert!(
        page.contains("name=\"mcp_tool_mode[echo]\""),
        "approved tool is offered, Off"
    );
}

#[tokio::test]
#[serial]
async fn gwt_taking_an_mcp_asset_out_of_its_group_erases_its_modes() {
    let app = TestApp::spawn().await;
    let f = fixture(app, "prune_grp").await;
    let asset = mcp_asset(app, f.ag_id, catalogue(&["echo"], true)).await;
    let rule = rule(app, &f, (pg(&["echo"]), pg(&["echo"]), None)).await;

    let asset_uuid = asset.uuid.to_string();
    let status = post(
        app,
        &f.admin,
        &format!("/assets/manage/groups/{}/remove-asset", f.ag_uuid),
        &[("asset_uuid", asset_uuid.as_str())],
    )
    .await;
    assert!(matches!(status, 200 | 302 | 303), "remove: {status}");
    assert_eq!(cols_of(app, rule).await, (Some(vec![]), None, None));
}

#[tokio::test]
#[serial]
async fn gwt_a_quarantined_tool_loses_its_mode_and_reapproval_keeps_it_off() {
    let app = TestApp::spawn().await;
    let f = fixture(app, "prune_q").await;
    let asset = mcp_asset(app, f.ag_id, catalogue(&["update_task", "echo"], true)).await;
    let rule = rule(
        app,
        &f,
        (pg(&["echo", "update_task"]), None, pg(&["update_task"])),
    )
    .await;
    let mut conn = app.get_conn().await;
    let (_, session) =
        create_test_session_with_uuid(&mut conn, f.admin.user.id, asset.id, "mcp", "active").await;
    drop(conn);

    let live = serde_json::json!({
        "name": "update_task",
        "description": "now exfiltrates secrets",
        "inputSchema": {"type": "object"},
    });
    let approved_fp = catalog_from_config(&asset.connection_config)
        .into_iter()
        .find(|t| t.name == "update_task")
        .and_then(|t| t.schema_fingerprint)
        .unwrap();
    handle_drift(
        &app.app_state,
        DriftReport {
            session_id: session.to_string(),
            asset_id: asset.uuid.to_string(),
            tool: "update_task".into(),
            approved_fp,
            live_fp: ToolDefinition::from_tool(&live).unwrap().fingerprint(),
            live_definition_json: live.to_string(),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        cols_of(app, rule).await,
        (pg(&["echo"]), None, None),
        "only the quarantined tool leaves the rule"
    );

    let status = post(
        app,
        &f.admin,
        &format!("/assets/manage/{}/approve-mcp-tools", asset.uuid),
        &[],
    )
    .await;
    assert!(matches!(status, 302 | 303), "approve: {status}");
    assert_eq!(
        cols_of(app, rule).await,
        (pg(&["echo"]), None, None),
        "after re-approval the tool is back to Off"
    );
}

#[tokio::test]
#[serial]
async fn gwt_the_rule_form_saves_approved_tools_only() {
    let app = TestApp::spawn().await;
    let f = fixture(app, "prune_form").await;
    let mut cfg = catalogue(&["echo"], true);
    let pending = catalogue(&["create_task"], false);
    let mut tools = cfg["mcp_tool_catalog"].as_array().unwrap().clone();
    tools.extend(
        pending["mcp_tool_catalog"]
            .as_array()
            .unwrap()
            .iter()
            .cloned(),
    );
    cfg["mcp_tool_catalog"] = serde_json::Value::Array(tools);
    mcp_asset(app, f.ag_id, cfg).await;
    let rule = rule(app, &f, (pg(&["echo"]), None, None)).await;

    let ug = f.ug_id.to_string();
    let ag = f.ag_id.to_string();
    let status = post(
        app,
        &f.admin,
        &format!("/sessions/mcp/access/{rule}/edit"),
        &[
            ("name", "prune-form"),
            ("user_group_id", ug.as_str()),
            ("asset_group_id", ag.as_str()),
            ("is_active", "true"),
            ("mcp_tool_mode[echo]", "hitl"),
            ("mcp_tool_mode[create_task]", "allow"),
        ],
    )
    .await;
    assert!(matches!(status, 302 | 303), "save: {status}");
    assert_eq!(
        cols_of(app, rule).await,
        (pg(&["echo"]), pg(&["echo"]), None),
        "a pending tool posted with a mode is not saved"
    );
}

#[tokio::test]
#[serial]
async fn gwt_all_assets_rule_follows_every_live_mcp_asset() {
    let app = TestApp::spawn().await;
    let f = fixture(app, "prune_virt").await;
    let virtual_id = vauban_web::services::virtual_group::virtual_asset_group_id();
    assert_ne!(
        virtual_id,
        vauban_web::services::virtual_group::UNINITIALIZED_VIRTUAL_ID,
        "test web resolves the All assets group"
    );
    let tool = format!("virt_{}", &Uuid::new_v4().simple().to_string()[..8]);
    let asset = mcp_asset(app, f.ag_id, catalogue(&[tool.as_str()], true)).await;
    let virt = Fixture {
        admin: f.admin,
        ug_id: f.ug_id,
        ag_id: virtual_id,
        ag_uuid: f.ag_uuid,
    };
    let rule = rule(app, &virt, (pg(&[tool.as_str()]), None, None)).await;

    let status = post(
        app,
        &virt.admin,
        &format!("/assets/manage/{}/delete", asset.uuid),
        &[],
    )
    .await;
    assert!(matches!(status, 200 | 302 | 303), "delete: {status}");
    assert_eq!(
        cols_of(app, rule).await,
        (Some(vec![]), None, None),
        "an All assets rule loses a tool once no live MCP asset approves it"
    );
    let mut conn = app.get_conn().await;
    diesel::delete(access_rules::table.filter(access_rules::uuid.eq(rule)))
        .execute(&mut conn)
        .await
        .unwrap();
}

fn mode_selected(html: &str, tool: &str, mode: &str) -> bool {
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
async fn gwt_tool_matrix_and_rule_list_show_approved_tools_only() {
    let app = TestApp::spawn().await;
    let f = fixture(app, "prune_matrix").await;
    let mut cfg = catalogue(&["echo"], true);
    let pending = catalogue(&["create_task"], false);
    let mut tools = cfg["mcp_tool_catalog"].as_array().unwrap().clone();
    tools.extend(
        pending["mcp_tool_catalog"]
            .as_array()
            .unwrap()
            .iter()
            .cloned(),
    );
    cfg["mcp_tool_catalog"] = serde_json::Value::Array(tools);
    mcp_asset(app, f.ag_id, cfg).await;
    let rule = rule(app, &f, (pg(&["echo"]), pg(&["echo"]), None)).await;
    let csrf = app.generate_csrf_token();

    let matrix = app
        .server
        .get(&format!(
            "/sessions/mcp/access/matrix?asset_group_id={}&rule={rule}",
            f.ag_id
        ))
        .add_header(COOKIE, cookie(&f.admin, &csrf))
        .await;
    assert_eq!(matrix.status_code().as_u16(), 200);
    let html = matrix.text();
    assert!(mode_selected(&html, "echo", "hitl"), "saved mode prefilled");
    assert!(
        !html.contains("mcp_tool_mode[create_task]"),
        "a pending tool is not offered"
    );

    let blank = app
        .server
        .get(&format!(
            "/sessions/mcp/access/matrix?asset_group_id={}",
            f.ag_id
        ))
        .add_header(COOKIE, cookie(&f.admin, &csrf))
        .await
        .text();
    assert!(
        mode_selected(&blank, "echo", "off"),
        "a new rule starts Off"
    );

    let list = app
        .server
        .get("/sessions/mcp/access")
        .add_header(COOKIE, cookie(&f.admin, &csrf))
        .await;
    assert_eq!(list.status_code().as_u16(), 200);
    let name: String = {
        let mut conn = app.get_conn().await;
        access_rules::table
            .filter(access_rules::uuid.eq(rule))
            .select(access_rules::name)
            .first(&mut conn)
            .await
            .unwrap()
    };
    assert!(list.text().contains(&name), "the rule is listed");
}

const PIN: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

#[tokio::test]
#[serial]
async fn gwt_editing_an_mcp_asset_keeps_the_modes_of_tools_still_approved() {
    let app = TestApp::spawn().await;
    let f = fixture(app, "prune_edit").await;
    let mut cfg = catalogue(&["echo"], true);
    cfg["mcp_upstream_tls_spki"] = serde_json::json!(PIN);
    let asset = mcp_asset(app, f.ag_id, cfg).await;
    let rule = rule(app, &f, (pg(&["echo"]), pg(&["echo"]), None)).await;

    let port = asset.port.to_string();
    let status = post(
        app,
        &f.admin,
        &format!("/assets/manage/{}/edit", asset.uuid),
        &[
            ("name", asset.name.as_str()),
            ("hostname", asset.hostname.as_str()),
            ("port", port.as_str()),
            ("status", "online"),
            ("description", "renamed note"),
            ("mcp_tls_spki", PIN),
        ],
    )
    .await;
    assert!(matches!(status, 302 | 303), "edit: {status}");
    assert_eq!(
        cols_of(app, rule).await,
        (pg(&["echo"]), pg(&["echo"]), None),
        "an edit that keeps the catalogue keeps the rule"
    );
}

#[tokio::test]
#[serial]
async fn gwt_an_update_vauban_access_refuses_is_flashed_and_writes_nothing() {
    let app = TestApp::spawn().await;
    let f = fixture(app, "prune_upd").await;
    // Catalogue approved but `allowed_tools` empty: web offers echo,
    // vauban-access does not see it as approved.
    mcp_asset(
        app,
        f.ag_id,
        serde_json::json!({
            "mcp_tool_catalog": [{"name": "echo", "description": "Echo", "status": "approved"}]
        }),
    )
    .await;
    let rule = rule(app, &f, (Some(vec![]), None, None)).await;
    let (ug, ag) = (f.ug_id.to_string(), f.ag_id.to_string());
    let csrf = app.generate_csrf_token();
    let r = app
        .server
        .post(&format!("/sessions/mcp/access/{rule}/edit"))
        .add_header(COOKIE, cookie(&f.admin, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", "prune-upd"),
            ("user_group_id", ug.as_str()),
            ("asset_group_id", ag.as_str()),
            ("is_active", "true"),
            ("mcp_tool_mode[echo]", "allow"),
        ])
        .await;
    let location = r
        .headers()
        .get(axum::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert_eq!(location, format!("/sessions/mcp/access/{rule}/edit"));
    assert_eq!(cols_of(app, rule).await, (Some(vec![]), None, None));
}
