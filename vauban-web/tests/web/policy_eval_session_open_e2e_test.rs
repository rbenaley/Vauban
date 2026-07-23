//! E2E: SSH connect with require_approval and no approved grant must
//! open the JIT modal and MUST NOT leave a `connecting` proxy_sessions
//! row (token minted then discarded — policy eval 3→2).

use crate::common::{TestApp, assertions::assert_status, test_db};
use crate::fixtures::{
    add_user_to_vauban_group, create_admin_user, create_test_access_rule_with_constraints,
    create_test_asset_group, create_test_asset_in_group, create_test_user,
    create_test_vauban_group, get_asset_uuid, unique_name,
};
use axum::http::header::COOKIE;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serial_test::serial;
use vauban_web::schema::proxy_sessions;

/// Pin host key so connect reaches the JIT branch (host-key preflight
/// runs after mint, before INSERT).
async fn pin_dummy_ssh_host_key(conn: &mut diesel_async::AsyncPgConnection, asset_id: i32) {
    use vauban_web::schema::assets;
    let cfg = serde_json::json!({
        "ssh_host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDummyPolicyEval32PinKey=",
        "auth_type": "password",
        "password": "v1:unused",
    });
    diesel::update(assets::table.filter(assets::id.eq(asset_id)))
        .set(assets::connection_config.eq(cfg))
        .execute(conn)
        .await
        .expect("pin host key");
}

#[tokio::test]
#[serial]
async fn e2e_ssh_jit_required_discards_mint_without_connecting_row() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("pe32_jit_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("pe32-jit-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("pe32-jit-ag")).await;

    let username = unique_name("pe32_jit_usr");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;

    let asset_id = create_test_asset_in_group(
        &mut conn,
        &unique_name("pe32-jit-asset"),
        admin.user.id,
        &ag,
    )
    .await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    pin_dummy_ssh_host_key(&mut conn, asset_id).await;

    create_test_access_rule_with_constraints(
        &mut conn,
        &ug,
        &ag,
        &["ssh"],
        false,
        true,
        Some(3600),
    )
    .await;

    let before: i64 = proxy_sessions::table
        .filter(proxy_sessions::user_id.eq(user.user.id))
        .filter(proxy_sessions::asset_id.eq(asset_id))
        .filter(proxy_sessions::status.eq("connecting"))
        .count()
        .get_result(&mut conn)
        .await
        .expect("count");

    let csrf_token = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/assets/{}/connect", asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", user.token, csrf_token),
        )
        .add_header("HX-Request", "true")
        .form(&serde_json::json!({
            "csrf_token": csrf_token,
        }))
        .await;

    assert_status(&response, 200);
    let trigger = response
        .headers()
        .get("hx-trigger")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        trigger.contains("show-access-request-modal"),
        "JIT without approval must emit show-access-request-modal, hx-trigger={trigger:?}"
    );

    let after: i64 = proxy_sessions::table
        .filter(proxy_sessions::user_id.eq(user.user.id))
        .filter(proxy_sessions::asset_id.eq(asset_id))
        .filter(proxy_sessions::status.eq("connecting"))
        .count()
        .get_result(&mut conn)
        .await
        .expect("count");
    assert_eq!(
        before, after,
        "discarded mint must not INSERT a connecting proxy_sessions row \
         (before={before} after={after})"
    );

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn e2e_ssh_denied_without_rule_no_connecting_row() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("pe32_deny_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("pe32-deny-ag")).await;
    let asset_id = create_test_asset_in_group(
        &mut conn,
        &unique_name("pe32-deny-asset"),
        admin.user.id,
        &ag,
    )
    .await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    pin_dummy_ssh_host_key(&mut conn, asset_id).await;

    let username = unique_name("pe32_deny_usr");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let csrf_token = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/assets/{}/connect", asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", user.token, csrf_token),
        )
        .add_header("HX-Request", "true")
        .form(&serde_json::json!({
            "csrf_token": csrf_token,
        }))
        .await;

    let body = response.text();
    let trigger = response
        .headers()
        .get("hx-trigger")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        body.contains("No access rule")
            || body.contains("showToast")
            || trigger.contains("No access rule")
            || trigger.contains("showToast"),
        "deny without rule; body={:?} hx-trigger={:?}",
        &body[..body.len().min(200)],
        trigger
    );

    let connecting: i64 = proxy_sessions::table
        .filter(proxy_sessions::user_id.eq(user.user.id))
        .filter(proxy_sessions::asset_id.eq(asset_id))
        .filter(proxy_sessions::status.eq("connecting"))
        .count()
        .get_result(&mut conn)
        .await
        .expect("count");
    assert_eq!(connecting, 0, "deny must not create connecting rows");

    test_db::cleanup(&mut conn).await;
}
