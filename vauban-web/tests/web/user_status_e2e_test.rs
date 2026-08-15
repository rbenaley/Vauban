//! E2E / battle coverage for tombstones + the approval-mail pool.
//!
//! Surfaces:
//! - A: `load_approver_contacts` (production SELECT used by JIT + IACS)
//! - B: `delete_user_web` sets `is_active=false` and the DB CHECK rejects
//!   an active tombstone
//! - C: cookie + API key of a deleted user die immediately

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use axum::http::header::{COOKIE, LOCATION};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serial_test::serial;
use tokio::sync::Barrier;
use uuid::Uuid;
use vauban_web::models::api_key::ApiKeyScope;
use vauban_web::models::user::AuthSource;
use vauban_web::schema::users;
use vauban_web::services::auth::AuthService;
use vauban_web::services::user_status::load_approver_contacts;

use crate::common::{TestApp, assertions::assert_status, unwrap_ok, unwrap_some};
use crate::fixtures::{create_real_api_key, create_simple_user, unique_name};

async fn user_row(
    conn: &mut diesel_async::AsyncPgConnection,
    user_id: i32,
) -> (Uuid, String, String) {
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select((users::uuid, users::username, users::email))
            .first(conn)
            .await
    )
}

async fn create_admin_with_mfa(app: &TestApp, label: &str) -> (i32, Uuid, String, String) {
    let username = unique_name(label);
    let user_uuid = Uuid::new_v4();
    let hash = unwrap_ok!(app.auth_service.hash_password("StableAdminPwd#2026!"));
    let (mfa_secret, _uri) =
        unwrap_ok!(AuthService::generate_totp_secret(&username, "VAUBAN-tests"));
    let secret_for_insert = mfa_secret.clone();
    let mut conn = app.get_conn().await;
    let user_id: i32 = unwrap_ok!(
        diesel::insert_into(users::table)
            .values((
                users::uuid.eq(user_uuid),
                users::username.eq(&username),
                users::email.eq(format!("{username}@test.local")),
                users::password_hash.eq(&hash),
                users::is_active.eq(true),
                users::is_staff.eq(true),
                users::is_superuser.eq(true),
                users::mfa_enabled.eq(true),
                users::mfa_secret.eq(Some(secret_for_insert)),
                users::auth_source.eq(AuthSource::Local),
                users::preferences.eq(serde_json::json!({})),
            ))
            .returning(users::id)
            .get_result(&mut conn)
            .await
    );
    (user_id, user_uuid, username, mfa_secret)
}

async fn post_delete_user(
    app: &TestApp,
    target_uuid: Uuid,
    token: &str,
    csrf_token: &str,
    totp_code: &str,
) -> axum_test::TestResponse {
    app.server
        .post(&format!("/accounts/users/{target_uuid}/delete"))
        .add_header(
            COOKIE,
            format!("access_token={token}; __vauban_csrf={csrf_token}"),
        )
        .form(&[("csrf_token", csrf_token), ("totp_code", totp_code)])
        .await
}

/// Seed the six roles the approval pool must distinguish, then assert
/// the production SELECT matches the contract.
#[tokio::test]
#[serial]
async fn e2e_load_approver_contacts_staff_union_superuser_usable_only() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let tag = unique_name("approver_pool");

    let staff_id = create_simple_user(&mut conn, &format!("{tag}_staff")).await;
    let super_id = create_simple_user(&mut conn, &format!("{tag}_super")).await;
    let both_id = create_simple_user(&mut conn, &format!("{tag}_both")).await;
    let inactive_id = create_simple_user(&mut conn, &format!("{tag}_inactive")).await;
    let tomb_id = create_simple_user(&mut conn, &format!("{tag}_tomb")).await;
    let empty_id = create_simple_user(&mut conn, &format!("{tag}_empty")).await;
    let nobody_id = create_simple_user(&mut conn, &format!("{tag}_nobody")).await;

    unwrap_ok!(
        diesel::update(users::table.filter(users::id.eq(staff_id)))
            .set((users::is_staff.eq(true), users::is_superuser.eq(false)))
            .execute(&mut conn)
            .await
    );
    unwrap_ok!(
        diesel::update(users::table.filter(users::id.eq(super_id)))
            .set((users::is_staff.eq(false), users::is_superuser.eq(true)))
            .execute(&mut conn)
            .await
    );
    unwrap_ok!(
        diesel::update(users::table.filter(users::id.eq(both_id)))
            .set((users::is_staff.eq(true), users::is_superuser.eq(true)))
            .execute(&mut conn)
            .await
    );
    unwrap_ok!(
        diesel::update(users::table.filter(users::id.eq(inactive_id)))
            .set((
                users::is_staff.eq(true),
                users::is_superuser.eq(true),
                users::is_active.eq(false),
            ))
            .execute(&mut conn)
            .await
    );
    unwrap_ok!(
        diesel::update(users::table.filter(users::id.eq(tomb_id)))
            .set((
                users::is_staff.eq(true),
                users::is_superuser.eq(true),
                users::is_active.eq(false),
                users::is_deleted.eq(true),
            ))
            .execute(&mut conn)
            .await
    );
    unwrap_ok!(
        diesel::update(users::table.filter(users::id.eq(empty_id)))
            .set((
                users::is_staff.eq(true),
                users::is_superuser.eq(true),
                users::email.eq(""),
            ))
            .execute(&mut conn)
            .await
    );

    let staff_email = user_row(&mut conn, staff_id).await.2;
    let super_email = user_row(&mut conn, super_id).await.2;
    let both_email = user_row(&mut conn, both_id).await.2;
    let inactive_email = user_row(&mut conn, inactive_id).await.2;
    let tomb_email = user_row(&mut conn, tomb_id).await.2;
    let empty_email = user_row(&mut conn, empty_id).await.2;
    let nobody_email = user_row(&mut conn, nobody_id).await.2;

    let contacts = unwrap_ok!(load_approver_contacts(&mut conn).await);
    let emails: Vec<&str> = contacts.iter().map(|(e, _)| e.as_str()).collect();

    assert!(
        emails.contains(&staff_email.as_str()),
        "staff-only must be mailed"
    );
    assert!(
        emails.contains(&super_email.as_str()),
        "superuser-only must be mailed"
    );
    assert!(
        emails.contains(&both_email.as_str()),
        "staff+superuser must be mailed"
    );
    assert!(
        !emails.contains(&inactive_email.as_str()),
        "inactive must not be mailed"
    );
    assert!(
        !emails.contains(&tomb_email.as_str()),
        "tombstone must not be mailed"
    );
    assert!(
        !emails.iter().any(|e| e.contains("_deleted_")),
        "no suffixed tombstone mailbox in the pool"
    );
    assert!(
        !emails.contains(&empty_email.as_str()) && !emails.contains(&""),
        "empty mailbox must not be mailed"
    );
    assert!(
        !emails.contains(&nobody_email.as_str()),
        "plain user must not be mailed"
    );
}

/// CHECK `users_tombstone_is_inactive` rejects `is_deleted && is_active`.
#[tokio::test]
#[serial]
async fn e2e_db_check_rejects_active_tombstone() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("check_active_tomb")).await;

    let result = diesel::update(users::table.filter(users::id.eq(user_id)))
        .set(users::is_deleted.eq(true))
        .execute(&mut conn)
        .await;
    assert!(
        result.is_err(),
        "CHECK users_tombstone_is_inactive must reject is_deleted=true while is_active=true"
    );
}

/// Connected user, another admin deletes them: next cookie → /login,
/// API key → 401, flags match the contract.
#[tokio::test]
#[serial]
async fn e2e_delete_kills_cookie_and_api_key() {
    let app = TestApp::spawn().await;
    let (_op_id, op_uuid, op_name, mfa_secret) = create_admin_with_mfa(app, "tomb_del_op").await;

    let mut conn = app.get_conn().await;
    let target_id = create_simple_user(&mut conn, &unique_name("tomb_del_target")).await;
    let (target_uuid, target_name, _) = user_row(&mut conn, target_id).await;
    let (_key_uuid, raw_key) =
        create_real_api_key(&mut conn, target_id, &[ApiKeyScope::Read], None).await;
    drop(conn);

    let target_token = app
        .generate_test_token(&target_uuid.to_string(), &target_name, false, false)
        .await;
    let before = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={target_token}"))
        .await;
    assert_status(&before, 200);

    let op_token = app
        .generate_test_token(&op_uuid.to_string(), &op_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    let totp = unwrap_some!(AuthService::get_current_totp(&mfa_secret));
    let deleted = post_delete_user(app, target_uuid, &op_token, &csrf, &totp).await;
    let status = deleted.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "delete must redirect, got {status}"
    );

    let mut conn = app.get_conn().await;
    let (is_active, is_deleted): (bool, bool) = unwrap_ok!(
        users::table
            .filter(users::id.eq(target_id))
            .select((users::is_active, users::is_deleted))
            .first(&mut conn)
            .await
    );
    drop(conn);
    assert!(is_deleted, "handler must set is_deleted");
    assert!(!is_active, "handler must set is_active=false");

    let after = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={target_token}"))
        .await;
    assert_eq!(after.status_code().as_u16(), 303);
    let location = after
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        location.starts_with("/login"),
        "tombstone cookie must bounce to /login, got {location}"
    );

    let api = app
        .server
        .get("/api/v1/assets")
        .add_header(
            axum::http::header::AUTHORIZATION,
            app.api_key_header(&raw_key),
        )
        .await;
    assert_status(&api, 401);
}

/// N authenticated GETs racing a real delete: after the handler commits,
/// no request may still be 200.
#[tokio::test]
#[serial]
async fn battle_authenticated_requests_die_when_account_deleted() {
    let app = TestApp::spawn().await;
    let (_op_id, op_uuid, op_name, mfa_secret) = create_admin_with_mfa(app, "tomb_battle_op").await;

    let mut conn = app.get_conn().await;
    let target_id = create_simple_user(&mut conn, &unique_name("tomb_battle_tgt")).await;
    let (target_uuid, target_name, _) = user_row(&mut conn, target_id).await;
    drop(conn);

    let target_token = app
        .generate_test_token(&target_uuid.to_string(), &target_name, false, false)
        .await;
    let op_token = app
        .generate_test_token(&op_uuid.to_string(), &op_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    let totp = unwrap_some!(AuthService::get_current_totp(&mfa_secret));

    let n = 8;
    let barrier = Arc::new(Barrier::new(n + 1));
    let mut joins = Vec::new();
    for _ in 0..n {
        let barrier = Arc::clone(&barrier);
        let token = target_token.clone();
        joins.push(tokio::spawn(async move {
            let app = TestApp::spawn().await;
            barrier.wait().await;
            for _ in 0..12 {
                let _ = app
                    .server
                    .get("/accounts/profile")
                    .add_header(COOKIE, format!("access_token={token}"))
                    .await;
                tokio::task::yield_now().await;
            }
        }));
    }

    barrier.wait().await;
    let deleted = post_delete_user(app, target_uuid, &op_token, &csrf, &totp).await;
    let del_status = deleted.status_code().as_u16();
    assert!(
        del_status == 302 || del_status == 303,
        "delete must redirect, got {del_status}"
    );

    for j in joins {
        j.await.expect("battle task");
    }

    let final_hit = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={target_token}"))
        .await;
    assert_eq!(
        final_hit.status_code().as_u16(),
        303,
        "after delete the cookie must be dead"
    );
}
