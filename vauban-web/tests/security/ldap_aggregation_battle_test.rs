//! Contention tests for LDAPS aggregation: two users, shared streak.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use axum::http::{HeaderName, header};
use serde_json::json;
use serial_test::serial;

use diesel_async::RunQueryDsl as _;

use crate::common::auth_ipc_test_service::{
    LDAP_GOOD_PASSWORD, StubSearchMode, reset_stub_search, set_stub_search,
};
use crate::common::{TestApp, test_aggregation_group_key, test_db, unwrap_ok};
use crate::fixtures::unique_name;
use vauban_web::models::user::{AuthSource, NewUser, User};
use vauban_web::schema::users;

async fn insert_ldap_user(conn: &mut diesel_async::AsyncPgConnection, username: &str) -> User {
    let new_user = NewUser {
        uuid: ::uuid::Uuid::new_v4(),
        username: username.to_string(),
        email: format!("{}@ldap.local", username),
        password_hash: "!ldap-no-local-login".to_string(),
        first_name: None,
        last_name: None,
        phone: None,
        is_active: true,
        is_staff: false,
        is_superuser: false,
        is_service_account: false,
        mfa_enabled: false,
        mfa_enforced: false,
        mfa_secret: None,
        preferences: serde_json::json!({}),
        auth_source: AuthSource::Ldap,
        external_id: Some(username.to_string()),
    };
    unwrap_ok!(
        diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(conn)
            .await
    )
}

async fn login_web_htmx(app: &TestApp, username: &str, password: &str) -> axum_test::TestResponse {
    let csrf = app.generate_csrf_token();
    app.server
        .post("/auth/login")
        .add_header(header::COOKIE, format!("__vauban_csrf={}", csrf))
        .add_header(HeaderName::from_static("hx-request"), "true")
        .json(&json!({
            "username": username,
            "password": password,
            "csrf_token": csrf,
        }))
        .await
}

fn hx_redirect(response: &axum_test::TestResponse) -> Option<String> {
    response
        .headers()
        .get("HX-Redirect")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn incomplete_streak(app: &TestApp) -> u32 {
    let rt = app.app_state.ldap_mapping.as_ref().expect("runtime");
    std::sync::atomic::AtomicU32::load(&rt.incomplete_streak, std::sync::atomic::Ordering::SeqCst)
}

fn reset_aggregation(app: &TestApp) {
    reset_stub_search();
    if let Some(rt) = app.app_state.ldap_mapping.as_ref() {
        rt.reset_counters();
    }
}

#[tokio::test]
#[serial]
async fn battle_two_users_replace_set_in_parallel() {
    let app = TestApp::spawn_ldap_aggregation().await;
    reset_aggregation(app);
    let mut conn = app.get_conn().await;

    let group_name = unique_name("battleops");
    unwrap_ok!(
        app.app_state
            .access_client
            .create_vauban_group(&group_name, None)
            .await
    );
    let ua = unique_name("test_ldap_battle_a");
    let ub = unique_name("test_ldap_battle_b");
    let user_a = insert_ldap_user(&mut conn, &ua).await;
    let user_b = insert_ldap_user(&mut conn, &ub).await;

    set_stub_search(
        StubSearchMode::Complete,
        vec![test_aggregation_group_key(&group_name)],
    );

    let (ra, rb) = tokio::join!(
        login_web_htmx(app, &ua, LDAP_GOOD_PASSWORD),
        login_web_htmx(app, &ub, LDAP_GOOD_PASSWORD),
    );
    assert_eq!(hx_redirect(&ra).as_deref(), Some("/mfa/setup"));
    assert_eq!(hx_redirect(&rb).as_deref(), Some("/mfa/setup"));

    let names_a = unwrap_ok!(
        app.app_state
            .access_client
            .list_user_groups(user_a.id)
            .await
    );
    let names_b = unwrap_ok!(
        app.app_state
            .access_client
            .list_user_groups(user_b.id)
            .await
    );
    assert!(names_a.iter().any(|g| g.name == group_name));
    assert!(names_b.iter().any(|g| g.name == group_name));

    reset_aggregation(app);
    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn battle_two_incomplete_increment_streak_by_two() {
    let app = TestApp::spawn_ldap_aggregation().await;
    reset_aggregation(app);
    let mut conn = app.get_conn().await;

    let ua = unique_name("test_ldap_battle_c1");
    let ub = unique_name("test_ldap_battle_c2");
    insert_ldap_user(&mut conn, &ua).await;
    insert_ldap_user(&mut conn, &ub).await;

    set_stub_search(StubSearchMode::IncompleteUnreachable, Vec::new());
    let (ra, rb) = tokio::join!(
        login_web_htmx(app, &ua, LDAP_GOOD_PASSWORD),
        login_web_htmx(app, &ub, LDAP_GOOD_PASSWORD),
    );
    assert_eq!(hx_redirect(&ra).as_deref(), Some("/mfa/setup"));
    assert_eq!(hx_redirect(&rb).as_deref(), Some("/mfa/setup"));
    assert_eq!(incomplete_streak(app), 2);

    reset_aggregation(app);
    test_db::cleanup(&mut conn).await;
}
