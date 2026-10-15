//! `attack_*` E2E on the web side of MCP: each test plays one adversary
//! move over HTTP and checks it is refused without changing state.
use axum::http::header::{AUTHORIZATION, COOKIE};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serial_test::serial;
use vauban_web::schema::access_contestations;

use crate::common::{TestApp, test_db};
use crate::fixtures::{create_admin_user, create_test_user, unique_name};
use crate::web::mcp_contestation_user_zone_e2e_test::seed_terminated_mcp;

async fn contestations_for(
    conn: &mut diesel_async::AsyncPgConnection,
    session_uuid: uuid::Uuid,
) -> Vec<(uuid::Uuid, String, i32)> {
    access_contestations::table
        .filter(access_contestations::session_uuid.eq(session_uuid))
        .select((
            access_contestations::uuid,
            access_contestations::status,
            access_contestations::opened_by_id,
        ))
        .load(conn)
        .await
        .unwrap()
}

#[tokio::test]
#[serial]
async fn attack_contestation_by_other_user_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let subject = create_test_user(&mut conn, &app.auth_service, &unique_name("atk_subject")).await;
    let intruder =
        create_test_user(&mut conn, &app.auth_service, &unique_name("atk_intruder")).await;
    let reviewer = create_admin_user(&mut conn, &app.auth_service, &unique_name("atk_rev")).await;
    let (session_uuid, _) = seed_terminated_mcp(&mut conn, subject.user.id, reviewer.user.id).await;

    let post = |token: String, path: String, fields: Vec<(&'static str, String)>| {
        let csrf = app.generate_csrf_token();
        let mut form = vec![("csrf_token", csrf.clone())];
        form.extend(fields);
        async move {
            app.server
                .post(&path)
                .add_header(AUTHORIZATION, app.auth_header(&token))
                .add_header(
                    COOKIE,
                    format!("access_token={token}; __vauban_csrf={csrf}"),
                )
                .form(&form)
                .await
        }
    };
    let reason = (
        "open_reason",
        "Not my session but I contest it anyway".to_string(),
    );

    let refused = post(
        intruder.token.clone(),
        format!("/sessions/{session_uuid}/contest"),
        vec![reason.clone()],
    )
    .await;
    assert!(!refused.status_code().is_success());
    assert!(
        contestations_for(&mut conn, session_uuid).await.is_empty(),
        "another user cannot open a contestation on someone else's session"
    );

    post(
        subject.token.clone(),
        format!("/sessions/{session_uuid}/contest"),
        vec![reason],
    )
    .await;
    let rows = contestations_for(&mut conn, session_uuid).await;
    assert_eq!(rows.len(), 1, "the subject can contest");
    let (contestation, status, opened_by) = rows[0].clone();
    assert_eq!((status.as_str(), opened_by), ("open", subject.user.id));

    for who in [&subject, &intruder] {
        for verb in ["claim", "uphold", "overturn"] {
            let resp = post(
                who.token.clone(),
                format!("/sessions/mcp/contestations/{contestation}/{verb}"),
                vec![("resolution_note", "self-review attempt".to_string())],
            )
            .await;
            assert!(!resp.status_code().is_success(), "{verb}");
        }
    }
    assert_eq!(
        contestations_for(&mut conn, session_uuid).await[0].1,
        "open",
        "neither the subject nor a stranger can review the contestation"
    );

    test_db::cleanup(&mut conn).await;
}

/// A forged rule form names a pending tool: web drops it, and nothing for
/// that tool reaches the rule.
#[tokio::test]
#[serial]
async fn attack_forged_rule_form_naming_a_pending_tool_writes_nothing_for_it() {
    use crate::web::mcp_rule_prune_e2e_test::{catalogue, cols_of, cookie, fixture, mcp_asset};
    let app = TestApp::spawn().await;
    let f = fixture(app, "atk_pending").await;
    mcp_asset(app, f.ag_id, catalogue(&["create_task"], false)).await;
    let name = unique_name("atk-pending-rule");
    let (ug, ag) = (f.ug_id.to_string(), f.ag_id.to_string());
    let csrf = app.generate_csrf_token();
    let r = app
        .server
        .post("/sessions/mcp/access")
        .add_header(COOKIE, cookie(&f.admin, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", name.as_str()),
            ("user_group_id", ug.as_str()),
            ("asset_group_id", ag.as_str()),
            ("is_active", "true"),
            ("mcp_tool_mode[create_task]", "allow"),
        ])
        .await;
    assert!(matches!(r.status_code().as_u16(), 302 | 303));
    let mut conn = app.get_conn().await;
    let uuid: uuid::Uuid = vauban_web::schema::access_rules::table
        .filter(vauban_web::schema::access_rules::name.eq(&name))
        .select(vauban_web::schema::access_rules::uuid)
        .first(&mut conn)
        .await
        .unwrap();
    assert_eq!(cols_of(app, uuid).await, (Some(vec![]), None, None));
}

/// A peer that skips the web filter and writes a pending tool straight
/// over IPC is refused by vauban-access, and the rule is unchanged.
#[tokio::test]
#[serial]
async fn attack_direct_ipc_rule_write_naming_a_pending_tool_is_refused() {
    use crate::web::mcp_rule_prune_e2e_test::{catalogue, cols_of, fixture, mcp_asset, pg, rule};
    use shared::messages::AccessRuleData;
    let app = TestApp::spawn().await;
    let f = fixture(app, "atk_ipc").await;
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
    let uuid = rule(app, &f, (pg(&["echo"]), None, None)).await;

    let data = |tools: Vec<String>| AccessRuleData {
        name: unique_name("atk-ipc-rule"),
        description: None,
        user_group_id: f.ug_id,
        asset_group_id: f.ag_id,
        allowed_protocols: vec!["mcp".into()],
        valid_from: None,
        valid_until: None,
        require_mfa: false,
        require_approval: false,
        max_session_duration: None,
        is_active: true,
        priority: 0,
        mcp_allowed_tools: Some(tools.clone()),
        mcp_hitl_tools: Some(tools),
        mcp_require_plan_tools: None,
        mcp_drift_iam: "suspend_group".into(),
    };
    let client = &app.app_state.access_client;
    for result in [
        client
            .update_access_rule(
                &uuid.to_string(),
                data(vec!["echo".into(), "create_task".into()]),
                None,
            )
            .await
            .map(|_| ()),
        client
            .create_access_rule(data(vec!["create_task".into()]), None)
            .await
            .map(|_| ()),
    ] {
        match result {
            Err(vauban_web::error::AppError::Ipc(msg)) => assert!(
                msg.starts_with(shared::mcp_policy::RULE_TOOLS_NOT_APPROVED)
                    && msg.contains("create_task"),
                "{msg}"
            ),
            other => panic!("pending tool over IPC must be refused, got {other:?}"),
        }
    }
    assert_eq!(cols_of(app, uuid).await, (pg(&["echo"]), None, None));
}

/// Discover and Approve refuse a forged token, a malformed or unknown
/// asset and a non-MCP asset, and leave the asset untouched.
#[tokio::test]
#[serial]
async fn attack_discover_and_approve_refuse_forged_unknown_and_non_mcp_targets() {
    use crate::web::mcp_rule_prune_e2e_test::cookie;
    use vauban_web::models::asset::{AssetType, NewAsset};
    use vauban_web::schema::assets;
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("atk_disc")).await;
    let ssh: uuid::Uuid = diesel::insert_into(assets::table)
        .values(&NewAsset {
            uuid: uuid::Uuid::new_v4(),
            name: unique_name("atk-disc-ssh"),
            hostname: format!("{}.ssh.test", unique_name("h")),
            port: 22,
            asset_type: AssetType::Ssh,
            status: "online".into(),
            description: None,
            connection_config: serde_json::json!({}),
            created_by_id: None,
            updated_by_id: None,
            connection_username: String::new(),
        })
        .returning(assets::uuid)
        .get_result(&mut conn)
        .await
        .unwrap();

    let edit = format!("/assets/manage/{ssh}/edit");
    for action in ["discover-mcp-tools", "approve-mcp-tools"] {
        for (target, token_ok, back_to) in [
            (ssh.to_string(), false, edit.as_str()),
            ("not-a-uuid".to_string(), true, "/assets/manage"),
            (uuid::Uuid::new_v4().to_string(), true, "/assets/manage"),
            (ssh.to_string(), true, edit.as_str()),
        ] {
            let csrf = app.generate_csrf_token();
            let posted = if token_ok {
                csrf.clone()
            } else {
                "forged".into()
            };
            let r = app
                .server
                .post(&format!("/assets/manage/{target}/{action}"))
                .add_header(COOKIE, cookie(&admin, &csrf))
                .form(&[("csrf_token", posted.as_str())])
                .await;
            assert!(
                matches!(r.status_code().as_u16(), 302 | 303),
                "{action} {target}"
            );
            let location = r
                .headers()
                .get(axum::http::header::LOCATION)
                .and_then(|h| h.to_str().ok())
                .unwrap_or_default()
                .to_string();
            assert_eq!(location, back_to, "{action} {target} (csrf ok: {token_ok})");
        }
    }
    let cfg: serde_json::Value = assets::table
        .filter(assets::uuid.eq(ssh))
        .select(assets::connection_config)
        .first(&mut conn)
        .await
        .unwrap();
    assert_eq!(cfg, serde_json::json!({}), "the SSH asset is untouched");
}

/// Rule writes without a valid token, without a name, for a pair that
/// already has a rule, or naming a tool vauban-access does not see as
/// approved are refused and create nothing; a reader gets no matrix.
#[tokio::test]
#[serial]
async fn attack_rule_form_refusals_create_nothing() {
    use crate::web::mcp_rule_prune_e2e_test::{cookie, fixture, mcp_asset, pg, rule};
    let app = TestApp::spawn().await;
    let f = fixture(app, "atk_form").await;
    // The catalogue says approved but `allowed_tools` does not: web offers
    // the tool, vauban-access refuses it.
    mcp_asset(
        app,
        f.ag_id,
        serde_json::json!({
            "mcp_tool_catalog": [{"name": "echo", "description": "Echo", "status": "approved"}]
        }),
    )
    .await;
    let (ug, ag) = (f.ug_id.to_string(), f.ag_id.to_string());
    let name = unique_name("atk-form-rule");
    let post = async |token_ok: bool, name: &str, mode: Option<&str>| {
        let csrf = app.generate_csrf_token();
        let posted = if token_ok {
            csrf.clone()
        } else {
            "forged".into()
        };
        let mut form: Vec<(&str, &str)> = vec![
            ("csrf_token", posted.as_str()),
            ("name", name),
            ("user_group_id", ug.as_str()),
            ("asset_group_id", ag.as_str()),
            ("is_active", "true"),
        ];
        if let Some(m) = mode {
            form.push(("mcp_tool_mode[echo]", m));
        }
        let r = app
            .server
            .post("/sessions/mcp/access")
            .add_header(COOKIE, cookie(&f.admin, &csrf))
            .form(&form)
            .await;
        r.headers()
            .get(axum::http::header::LOCATION)
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    let count = async || -> i64 {
        let mut conn = app.get_conn().await;
        vauban_web::schema::access_rules::table
            .filter(vauban_web::schema::access_rules::user_group_id.eq(f.ug_id))
            .filter(vauban_web::schema::access_rules::asset_group_id.eq(f.ag_id))
            .count()
            .get_result(&mut conn)
            .await
            .unwrap()
    };

    assert_eq!(post(false, &name, None).await, "/sessions/mcp/access/new");
    assert_eq!(post(true, "  ", None).await, "/sessions/mcp/access/new");
    assert_eq!(
        post(true, &name, Some("allow")).await,
        "/sessions/mcp/access/new"
    );
    assert_eq!(count().await, 0, "no refused write created a rule");

    rule(app, &f, (pg(&[]), None, None)).await;
    assert_eq!(post(true, &name, None).await, "/sessions/mcp/access/new");
    assert_eq!(count().await, 1, "a duplicate pair is refused");

    let mut conn = app.get_conn().await;
    let reader = create_test_user(&mut conn, &app.auth_service, &unique_name("atk_form_rd")).await;
    let csrf = app.generate_csrf_token();
    let r = app
        .server
        .get(&format!(
            "/sessions/mcp/access/matrix?asset_group_id={}",
            f.ag_id
        ))
        .add_header(COOKIE, cookie(&reader, &csrf))
        .await;
    assert!(
        !r.text().contains("mcp_tool_mode[echo]"),
        "a user without access_rules:write gets no matrix"
    );
}
