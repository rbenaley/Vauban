//! MCP access-rule `mcp_drift_iam` form persist + apply_mandate_drift IAM.
use axum::http::header::{AUTHORIZATION, COOKIE, LOCATION};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serial_test::serial;
use uuid::Uuid;
use vauban_web::models::access_rule::{AccessRule, NewAccessRule};
use vauban_web::models::api_key::ApiKeyScope;
use vauban_web::models::asset::{Asset, AssetType, NewAsset, NewAssetAssetGroup};
use vauban_web::schema::{
    access_rules, api_keys, asset_asset_groups, asset_groups, assets, email_outbox, proxy_sessions,
    user_groups, users, vauban_groups,
};

use crate::common::{TestApp, test_db};
use crate::fixtures::{
    add_user_to_vauban_group, create_admin_user, create_real_api_key, create_test_asset_group,
    create_test_session_with_uuid, create_test_user, create_test_vauban_group, unique_name,
};

fn auth_csrf_cookie(token: &str, csrf: &str) -> String {
    format!("access_token={}; __vauban_csrf={}", token, csrf)
}

struct DriftFixture {
    subject: crate::fixtures::TestUser,
    admin: crate::fixtures::TestUser,
    ug_id: i32,
    ag_id: i32,
    asset_id: i32,
    rule_uuid: Uuid,
}

async fn seed_rule(
    conn: &mut diesel_async::AsyncPgConnection,
    app: &TestApp,
    iam: &str,
) -> DriftFixture {
    let admin = create_admin_user(conn, &app.auth_service, &unique_name("drift_adm")).await;
    let subject = create_test_user(conn, &app.auth_service, &unique_name("drift_sub")).await;
    let ug = create_test_vauban_group(conn, &unique_name("drift-ug")).await;
    let ag = create_test_asset_group(conn, &unique_name("drift-ag")).await;
    let ug_id: i32 = vauban_groups::table
        .filter(vauban_groups::uuid.eq(ug))
        .select(vauban_groups::id)
        .first(conn)
        .await
        .unwrap();
    let ag_id: i32 = asset_groups::table
        .filter(asset_groups::uuid.eq(ag))
        .select(asset_groups::id)
        .first(conn)
        .await
        .unwrap();
    add_user_to_vauban_group(conn, subject.user.id, &ug).await;

    let asset: Asset = diesel::insert_into(assets::table)
        .values(&NewAsset {
            uuid: Uuid::new_v4(),
            name: unique_name("drift-asset"),
            hostname: format!("{}.mcp.test", unique_name("up")),
            port: 19001,
            asset_type: AssetType::Mcp,
            status: "online".into(),
            description: None,
            connection_config: serde_json::json!({
                "mcp_tool_catalog": [{
                    "name": "purge_tasks",
                    "description": "lab",
                    "status": "approved"
                }]
            }),
            created_by_id: None,
            updated_by_id: None,
            connection_username: String::new(),
        })
        .get_result(conn)
        .await
        .unwrap();
    diesel::insert_into(asset_asset_groups::table)
        .values(&NewAssetAssetGroup {
            asset_id: asset.id,
            asset_group_id: ag_id,
        })
        .execute(conn)
        .await
        .unwrap();

    let rule_uuid = Uuid::new_v4();
    diesel::insert_into(access_rules::table)
        .values(&NewAccessRule {
            uuid: rule_uuid,
            name: unique_name("drift-rule"),
            description: Some("require plan + drift IAM".into()),
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
            mcp_allowed_tools: Some(vec![Some("purge_tasks".into())]),
            mcp_hitl_tools: None,
            mcp_require_plan_tools: Some(vec![Some("purge_tasks".into())]),
            mcp_drift_iam: iam.into(),
        })
        .execute(conn)
        .await
        .unwrap();

    DriftFixture {
        subject,
        admin,
        ug_id,
        ag_id,
        asset_id: asset.id,
        rule_uuid,
    }
}

async fn member_of(
    conn: &mut diesel_async::AsyncPgConnection,
    user_id: i32,
    group_id: i32,
) -> bool {
    let n: i64 = user_groups::table
        .filter(user_groups::user_id.eq(user_id))
        .filter(user_groups::group_id.eq(group_id))
        .count()
        .get_result(conn)
        .await
        .unwrap();
    n > 0
}

fn enabled_mailer_state(app: &TestApp) -> vauban_web::AppState {
    let mut state = app.app_state.clone();
    state.mailer = vauban_web::services::mailer::Mailer::new(
        std::sync::Arc::new(tokio::sync::Notify::new()),
        true,
        5,
    );
    state
}

#[tokio::test]
#[serial]
async fn mcp_access_form_persists_all_drift_iam_values() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let fx = seed_rule(&mut conn, app, "suspend_group").await;
    let csrf = app.generate_csrf_token();
    let cookie = auth_csrf_cookie(&fx.admin.token, &csrf);
    let edit_url = format!("/sessions/mcp/access/{}/edit", fx.rule_uuid);

    for iam in [
        "terminate",
        "suspend_group",
        "revoke_opener_key",
        "soft_delete_user",
    ] {
        let saved = app
            .server
            .post(&edit_url)
            .add_header(AUTHORIZATION, app.auth_header(&fx.admin.token))
            .add_header(COOKIE, cookie.as_str())
            .form(&[
                ("csrf_token", csrf.as_str()),
                ("name", "drift-rule-saved"),
                ("user_group_id", &fx.ug_id.to_string()),
                ("asset_group_id", &fx.ag_id.to_string()),
                ("priority", "0"),
                ("is_active", "true"),
                ("mcp_tool_mode[purge_tasks]", "require_plan"),
                ("mcp_drift_iam", iam),
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
            "Save {iam} must redirect, got {status} Location={location}"
        );
        let row: AccessRule = access_rules::table
            .filter(access_rules::uuid.eq(fx.rule_uuid))
            .first(&mut conn)
            .await
            .unwrap();
        assert_eq!(row.mcp_drift_iam, iam, "persisted {iam}");
    }

    let bad = app
        .server
        .post(&edit_url)
        .add_header(AUTHORIZATION, app.auth_header(&fx.admin.token))
        .add_header(COOKIE, cookie.as_str())
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", "drift-rule-saved"),
            ("user_group_id", &fx.ug_id.to_string()),
            ("asset_group_id", &fx.ag_id.to_string()),
            ("priority", "0"),
            ("is_active", "true"),
            ("mcp_drift_iam", "999"),
        ])
        .await;
    assert_eq!(
        bad.status_code().as_u16(),
        400,
        "unknown mcp_drift_iam must be 400"
    );
    let row: AccessRule = access_rules::table
        .filter(access_rules::uuid.eq(fx.rule_uuid))
        .first(&mut conn)
        .await
        .unwrap();
    assert_eq!(row.mcp_drift_iam, "soft_delete_user");

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn jwt_cannot_post_drift_iam_on_api() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let fx = seed_rule(&mut conn, app, "suspend_group").await;
    let resp = app
        .server
        .put(&format!("/api/v1/access-rules/{}", fx.rule_uuid))
        .add_header(AUTHORIZATION, app.auth_header(&fx.admin.token))
        .json(&serde_json::json!({ "mcp_drift_iam": "soft_delete_user" }))
        .await;
    assert_eq!(
        resp.status_code().as_u16(),
        401,
        "JWT must not write access rules on /api/v1 (vbn_ only), got {} body={}",
        resp.status_code(),
        resp.text()
    );
    let row: AccessRule = access_rules::table
        .filter(access_rules::uuid.eq(fx.rule_uuid))
        .first(&mut conn)
        .await
        .unwrap();
    assert_eq!(row.mcp_drift_iam, "suspend_group");
    test_db::cleanup(&mut conn).await;
}

async fn apply_on_active(
    app: &TestApp,
    conn: &mut diesel_async::AsyncPgConnection,
    fx: &DriftFixture,
    metadata: serde_json::Value,
) -> Uuid {
    let (_id, session_uuid) =
        create_test_session_with_uuid(conn, fx.subject.user.id, fx.asset_id, "mcp", "active").await;
    diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq(session_uuid)))
        .set(proxy_sessions::metadata.eq(metadata))
        .execute(conn)
        .await
        .unwrap();
    let state = enabled_mailer_state(app);
    vauban_web::services::mcp_drift::apply_mandate_drift(
        &state,
        &session_uuid.to_string(),
        "purge_tasks",
        "binding",
        "M-test",
        &fx.subject.user.uuid.to_string(),
    )
    .await
    .expect("apply_mandate_drift");
    session_uuid
}

async fn session_reason(
    conn: &mut diesel_async::AsyncPgConnection,
    session_uuid: Uuid,
) -> (String, Option<String>) {
    proxy_sessions::table
        .filter(proxy_sessions::uuid.eq(session_uuid))
        .select((proxy_sessions::status, proxy_sessions::termination_reason))
        .first(conn)
        .await
        .unwrap()
}

#[tokio::test]
#[serial]
async fn apply_terminate_keeps_group_cuts_session_and_mails() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let fx = seed_rule(&mut conn, app, "terminate").await;
    let sid = apply_on_active(app, &mut conn, &fx, serde_json::json!({})).await;
    let (status, reason) = session_reason(&mut conn, sid).await;
    assert_eq!(status, "terminated");
    assert_eq!(reason.as_deref(), Some("mandate_drift"));
    assert!(
        member_of(&mut conn, fx.subject.user.id, fx.ug_id).await,
        "terminate must not remove the group"
    );
    let n: i64 = email_outbox::table
        .filter(email_outbox::event_kind.eq("mcp.mandate_drift"))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap();
    assert!(n >= 1, "mailer-on clone must queue mcp.mandate_drift");
    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn apply_suspend_group_removes_membership() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let fx = seed_rule(&mut conn, app, "suspend_group").await;
    let sid = apply_on_active(app, &mut conn, &fx, serde_json::json!({})).await;
    let (_status, reason) = session_reason(&mut conn, sid).await;
    assert_eq!(reason.as_deref(), Some("mandate_drift"));
    assert!(
        !member_of(&mut conn, fx.subject.user.id, fx.ug_id).await,
        "suspend_group must RemoveGroupMember"
    );
    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn apply_revoke_opener_key_deactivates_hop1_key_only() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let fx = seed_rule(&mut conn, app, "revoke_opener_key").await;
    let (key_uuid, _raw) =
        create_real_api_key(&mut conn, fx.subject.user.id, &[ApiKeyScope::Write], None).await;
    let sid = apply_on_active(
        app,
        &mut conn,
        &fx,
        serde_json::json!({ "api_key_id": key_uuid.to_string() }),
    )
    .await;
    let (_status, reason) = session_reason(&mut conn, sid).await;
    assert_eq!(reason.as_deref(), Some("mandate_drift"));
    assert!(member_of(&mut conn, fx.subject.user.id, fx.ug_id).await);
    let active: bool = api_keys::table
        .filter(api_keys::uuid.eq(key_uuid))
        .select(api_keys::is_active)
        .first(&mut conn)
        .await
        .unwrap();
    assert!(!active, "hop-1 key must be deactivated");

    let (other_key, _) =
        create_real_api_key(&mut conn, fx.subject.user.id, &[ApiKeyScope::Write], None).await;
    let sid2 = apply_on_active(app, &mut conn, &fx, serde_json::json!({})).await;
    let (_s2, reason2) = session_reason(&mut conn, sid2).await;
    assert_eq!(reason2.as_deref(), Some("mandate_drift"));
    let other_active: bool = api_keys::table
        .filter(api_keys::uuid.eq(other_key))
        .select(api_keys::is_active)
        .first(&mut conn)
        .await
        .unwrap();
    assert!(
        other_active,
        "Connect UI hop (no api_key_id) must not revoke a phantom key"
    );
    assert!(member_of(&mut conn, fx.subject.user.id, fx.ug_id).await);
    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn apply_soft_delete_tombs_user_but_skips_last_superuser() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let fx = seed_rule(&mut conn, app, "soft_delete_user").await;
    let sid = apply_on_active(app, &mut conn, &fx, serde_json::json!({})).await;
    let (_status, reason) = session_reason(&mut conn, sid).await;
    assert_eq!(reason.as_deref(), Some("mandate_drift"));
    let deleted: bool = users::table
        .filter(users::id.eq(fx.subject.user.id))
        .select(users::is_deleted)
        .first(&mut conn)
        .await
        .unwrap();
    assert!(deleted, "non-superuser must be tombstoned");

    let super_fx_admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("last_su")).await;
    let others: Vec<i32> = users::table
        .filter(users::is_superuser.eq(true))
        .filter(users::is_active.eq(true))
        .filter(users::is_deleted.eq(false))
        .filter(users::id.ne(super_fx_admin.user.id))
        .select(users::id)
        .load(&mut conn)
        .await
        .unwrap();
    diesel::update(users::table.filter(users::id.eq_any(&others)))
        .set(users::is_active.eq(false))
        .execute(&mut conn)
        .await
        .unwrap();

    let ug_uuid: Uuid = vauban_groups::table
        .filter(vauban_groups::id.eq(fx.ug_id))
        .select(vauban_groups::uuid)
        .first(&mut conn)
        .await
        .unwrap();
    add_user_to_vauban_group(&mut conn, super_fx_admin.user.id, &ug_uuid).await;
    let (_id, su_sid) = create_test_session_with_uuid(
        &mut conn,
        super_fx_admin.user.id,
        fx.asset_id,
        "mcp",
        "active",
    )
    .await;
    let state = enabled_mailer_state(app);
    vauban_web::services::mcp_drift::apply_mandate_drift(
        &state,
        &su_sid.to_string(),
        "purge_tasks",
        "binding",
        "M-su",
        &super_fx_admin.user.uuid.to_string(),
    )
    .await
    .expect("apply last superuser");
    let still_deleted: bool = users::table
        .filter(users::id.eq(super_fx_admin.user.id))
        .select(users::is_deleted)
        .first(&mut conn)
        .await
        .unwrap();
    assert!(!still_deleted, "last active superuser must skip tombstone");
    let (_st, su_reason) = session_reason(&mut conn, su_sid).await;
    assert_eq!(su_reason.as_deref(), Some("mandate_drift"));

    diesel::update(users::table.filter(users::id.eq_any(&others)))
        .set(users::is_active.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();
    test_db::cleanup(&mut conn).await;
}
