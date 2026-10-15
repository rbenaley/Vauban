//! E2E + exploratory coverage for MCP terminate stamping, recording paths
//! that keep the hop-1 month, and drift group removal.
//!
//! Mission Seal persistence lives in `vauban-access` `mcp_pdp` (PostgreSQL
//! write-through); recording fail-closed lives in `vauban-proxy-mcp` `gwt_*`.

use axum::http::header::{AUTHORIZATION, COOKIE};
use chrono::{DateTime, Utc};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serial_test::serial;
use uuid::Uuid;
use vauban_web::models::access_rule::NewAccessRule;
use vauban_web::models::asset::{Asset, AssetType, NewAsset, NewAssetAssetGroup};
use vauban_web::models::session::ProxySession;
use vauban_web::schema::{
    access_rules, asset_asset_groups, asset_groups, assets, proxy_sessions, user_groups,
    vauban_groups,
};
use vauban_web_evidence::hydrator::recording_dir_for_session;

use crate::common::{TestApp, test_db};
use crate::fixtures::{
    add_user_to_vauban_group, create_admin_user, create_simple_ssh_asset, create_test_asset_group,
    create_test_session_with_uuid, create_test_user, create_test_vauban_group, unique_name,
};

fn auth_csrf_cookie(token: &str, csrf: &str) -> String {
    format!("access_token={}; __vauban_csrf={}", token, csrf)
}

#[test]
fn mcp_audit_fixes_recording_dir_frozen_yyyy_mm() {
    let dec = DateTime::from_timestamp(1_767_139_200, 0).unwrap();
    let jan = DateTime::from_timestamp(1_767_225_600, 0).unwrap();
    let sid = "550e8400-e29b-41d4-a716-446655440000";
    let d = recording_dir_for_session("/rec", sid, dec);
    let j = recording_dir_for_session("/rec", sid, jan);
    assert!(
        d.contains("/2025/12/"),
        "2025-12-31 must not follow wall clock: {d}"
    );
    assert!(j.contains("/2026/01/"), "2026-01-01 must be January: {j}");
    assert_ne!(d, j);
}

async fn seed_mcp_asset(conn: &mut diesel_async::AsyncPgConnection, created_by: i32) -> Asset {
    diesel::insert_into(assets::table)
        .values(&NewAsset {
            uuid: Uuid::new_v4(),
            name: unique_name("test-mcp-audit-asset"),
            hostname: format!("{}.mcp.test", unique_name("up")),
            port: 19001,
            asset_type: AssetType::Mcp,
            status: "online".into(),
            description: None,
            connection_config: serde_json::json!({}),
            created_by_id: Some(created_by),
            updated_by_id: Some(created_by),
            connection_username: String::new(),
        })
        .get_result(conn)
        .await
        .unwrap()
}

#[tokio::test]
#[serial]
async fn mcp_audit_fixes_proxy_restart_reaps_live_mcp_only() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("test_reap_adm")).await;
    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("test_reap_usr")).await;
    let mcp_asset = seed_mcp_asset(&mut conn, admin.user.id).await;
    let ssh_asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("test-f2-ssh"), admin.user.id).await;

    let (_id_a, uuid_active) =
        create_test_session_with_uuid(&mut conn, user.user.id, mcp_asset.id, "mcp", "active").await;
    let (_id_c, uuid_connecting) =
        create_test_session_with_uuid(&mut conn, user.user.id, mcp_asset.id, "mcp", "active").await;
    diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq(uuid_connecting)))
        .set((
            proxy_sessions::status.eq("connecting"),
            proxy_sessions::disconnected_at.eq(Option::<DateTime<Utc>>::None),
        ))
        .execute(&mut conn)
        .await
        .unwrap();
    let (_id_s, uuid_suspended) =
        create_test_session_with_uuid(&mut conn, user.user.id, mcp_asset.id, "mcp", "active").await;
    diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq(uuid_suspended)))
        .set((
            proxy_sessions::status.eq("suspended"),
            proxy_sessions::disconnected_at.eq(Option::<DateTime<Utc>>::None),
        ))
        .execute(&mut conn)
        .await
        .unwrap();
    let (_id_t, uuid_done) =
        create_test_session_with_uuid(&mut conn, user.user.id, mcp_asset.id, "mcp", "terminated")
            .await;
    let (_id_ssh, uuid_ssh) =
        create_test_session_with_uuid(&mut conn, user.user.id, ssh_asset_id, "ssh", "active").await;

    vauban_web::services::mcp_recheck::terminate_live_mcp_on_proxy_restart(&app.app_state).await;

    let status_reason = |uuid: Uuid| async move {
        let mut c = app.get_conn().await;
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(uuid))
            .select((proxy_sessions::status, proxy_sessions::termination_reason))
            .first::<(String, Option<String>)>(&mut c)
            .await
            .unwrap()
    };

    for (label, uuid) in [
        ("active", uuid_active),
        ("connecting", uuid_connecting),
        ("suspended", uuid_suspended),
    ] {
        let (st, reason) = status_reason(uuid).await;
        assert_eq!(st, "terminated", "{label}");
        assert_eq!(
            reason.as_deref(),
            Some("mcp_proxy_restart"),
            "{label} must be reaped; no vbw_ resurrection"
        );
    }
    let (done_st, done_reason) = status_reason(uuid_done).await;
    assert_eq!(done_st, "terminated");
    assert_ne!(
        done_reason.as_deref(),
        Some("mcp_proxy_restart"),
        "already-terminated MCP must not be re-stamped"
    );
    let (ssh_st, ssh_reason) = status_reason(uuid_ssh).await;
    assert_eq!(ssh_st, "active", "SSH visit must survive");
    assert!(ssh_reason.is_none());

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn mcp_audit_fixes_terminate_recording_path_uses_connected_at() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("test_f4_adm")).await;
    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("test_f4_usr")).await;
    let asset = seed_mcp_asset(&mut conn, admin.user.id).await;
    let (_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, user.user.id, asset.id, "mcp", "active").await;
    let connected = DateTime::from_timestamp(1_767_139_200, 0).unwrap();
    diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq(session_uuid)))
        .set(proxy_sessions::connected_at.eq(connected))
        .execute(&mut conn)
        .await
        .unwrap();

    vauban_web::services::mcp_recheck::terminate_live_mcp_on_proxy_restart(&app.app_state).await;

    let row: ProxySession = proxy_sessions::table
        .filter(proxy_sessions::uuid.eq(session_uuid))
        .first(&mut conn)
        .await
        .unwrap();
    assert_eq!(row.status, "terminated");
    assert_eq!(row.connected_at, Some(connected));
    if let Some(path) = row.recording_path.as_deref() {
        assert!(
            path.contains("/2025/12/"),
            "recording_path must keep hop-1 month, got {path}"
        );
        assert!(
            !path.contains("/2026/"),
            "terminate must not recompute YYYY/MM from now: {path}"
        );
    }

    test_db::cleanup(&mut conn).await;
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

#[tokio::test]
#[serial]
async fn mcp_audit_fixes_suspend_two_groups_overturn_restores_both() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("test_f6_adm")).await;
    let subject = create_test_user(&mut conn, &app.auth_service, &unique_name("test_f6_sub")).await;

    let ug1 = create_test_vauban_group(&mut conn, &unique_name("test-f6-ug1")).await;
    let ug2 = create_test_vauban_group(&mut conn, &unique_name("test-f6-ug2")).await;
    let ag1 = create_test_asset_group(&mut conn, &unique_name("test-f6-ag1")).await;
    let ag2 = create_test_asset_group(&mut conn, &unique_name("test-f6-ag2")).await;
    let ug1_id: i32 = vauban_groups::table
        .filter(vauban_groups::uuid.eq(ug1))
        .select(vauban_groups::id)
        .first(&mut conn)
        .await
        .unwrap();
    let ug2_id: i32 = vauban_groups::table
        .filter(vauban_groups::uuid.eq(ug2))
        .select(vauban_groups::id)
        .first(&mut conn)
        .await
        .unwrap();
    let ag1_id: i32 = asset_groups::table
        .filter(asset_groups::uuid.eq(ag1))
        .select(asset_groups::id)
        .first(&mut conn)
        .await
        .unwrap();
    let ag2_id: i32 = asset_groups::table
        .filter(asset_groups::uuid.eq(ag2))
        .select(asset_groups::id)
        .first(&mut conn)
        .await
        .unwrap();
    add_user_to_vauban_group(&mut conn, subject.user.id, &ug1).await;
    add_user_to_vauban_group(&mut conn, subject.user.id, &ug2).await;

    let asset = seed_mcp_asset(&mut conn, admin.user.id).await;
    for ag_id in [ag1_id, ag2_id] {
        diesel::insert_into(asset_asset_groups::table)
            .values(&NewAssetAssetGroup {
                asset_id: asset.id,
                asset_group_id: ag_id,
            })
            .execute(&mut conn)
            .await
            .unwrap();
    }
    for (ug_id, ag_id) in [(ug1_id, ag1_id), (ug2_id, ag2_id)] {
        diesel::insert_into(access_rules::table)
            .values(&NewAccessRule {
                uuid: Uuid::new_v4(),
                name: unique_name("test-f6-rule"),
                description: Some("two-group drift".into()),
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
                mcp_drift_iam: "suspend_group".into(),
            })
            .execute(&mut conn)
            .await
            .unwrap();
    }

    let (_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, subject.user.id, asset.id, "mcp", "active").await;

    vauban_web::services::mcp_drift::apply_mandate_drift(
        &app.app_state,
        &session_uuid.to_string(),
        "purge_tasks",
        "binding",
        "M-f6",
        &subject.user.uuid.to_string(),
    )
    .await
    .expect("apply_mandate_drift");

    assert!(
        !member_of(&mut conn, subject.user.id, ug1_id).await
            && !member_of(&mut conn, subject.user.id, ug2_id).await,
        "drift must RemoveGroupMember both groups"
    );
    let session: ProxySession = proxy_sessions::table
        .filter(proxy_sessions::uuid.eq(session_uuid))
        .first(&mut conn)
        .await
        .unwrap();
    let ids = session
        .decision_source_group_ids
        .as_ref()
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_i64().map(|n| n as i32))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assert!(
        ids.contains(&ug1_id) && ids.contains(&ug2_id),
        "stamp must persist both group ids, got {ids:?}"
    );

    let opened = vauban_web::services::access_contestation::open_contestation(
        &app.app_state,
        &session,
        subject.user.id,
        "False-positive Mission Seal drift on a documented tool",
    )
    .await
    .expect("open contestation");
    vauban_web::services::access_contestation::claim_contestation(
        &app.app_state,
        opened.uuid,
        admin.user.id,
    )
    .await
    .expect("claim");
    vauban_web::services::access_contestation::overturn_contestation(
        &app.app_state,
        opened.uuid,
        admin.user.id,
        "Restore both access groups the drift removed",
    )
    .await
    .expect("overturn");

    assert!(
        member_of(&mut conn, subject.user.id, ug1_id).await
            && member_of(&mut conn, subject.user.id, ug2_id).await,
        "Overturn must AddGroupMember every stamped group"
    );

    let csrf = app.generate_csrf_token();
    let cookie = auth_csrf_cookie(&admin.token, &csrf);
    let list = app
        .server
        .get("/sessions/mcp/contestations")
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .add_header(COOKIE, cookie.as_str())
        .await;
    assert_eq!(list.status_code().as_u16(), 200);

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn mcp_audit_fixes_restore_falls_back_to_singular_stamp() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("test_f6b_adm")).await;
    let subject =
        create_test_user(&mut conn, &app.auth_service, &unique_name("test_f6b_sub")).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("test-f6b-ug")).await;
    let ug_id: i32 = vauban_groups::table
        .filter(vauban_groups::uuid.eq(ug))
        .select(vauban_groups::id)
        .first(&mut conn)
        .await
        .unwrap();
    let asset = seed_mcp_asset(&mut conn, admin.user.id).await;
    let (_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, subject.user.id, asset.id, "mcp", "terminated")
            .await;
    diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq(session_uuid)))
        .set((
            proxy_sessions::termination_reason.eq("mandate_drift"),
            proxy_sessions::decision_source_group_id.eq(ug_id),
            proxy_sessions::decision_source_group_ids.eq(Option::<serde_json::Value>::None),
        ))
        .execute(&mut conn)
        .await
        .unwrap();
    let session: ProxySession = proxy_sessions::table
        .filter(proxy_sessions::uuid.eq(session_uuid))
        .first(&mut conn)
        .await
        .unwrap();
    let restored = vauban_web::services::access_contestation::resolve_restore_groups_for_session(
        &app.app_state,
        &session,
    )
    .await
    .expect("singular stamp fallback");
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].0, ug_id);

    test_db::cleanup(&mut conn).await;
}
