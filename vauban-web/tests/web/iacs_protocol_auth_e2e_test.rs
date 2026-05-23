//! E2E -- IACS protocol authorization binding (asset_type vs access rule).
//!
//! Pins that `POST /assets/{uuid}/connect-iacs` refuses a cross-type
//! tunnel (modbus-only rule, profinet asset) while still granting the
//! matching type.

use crate::common::{TestApp, assertions::assert_status, unwrap_ok};
use crate::fixtures::{
    add_user_to_vauban_group, create_simple_admin_user, create_simple_user,
    create_test_access_rule, create_test_asset_group, create_test_asset_in_group_with_type,
    create_test_vauban_group, unique_name,
};
use axum::http::header::COOKIE;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vauban_web::models::asset::AssetType;

async fn get_user_uuid(conn: &mut AsyncPgConnection, user_id: i32) -> Uuid {
    use vauban_web::schema::users;
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(conn)
            .await
    )
}

async fn get_asset_uuid(conn: &mut AsyncPgConnection, asset_id: i32) -> Uuid {
    use vauban_web::schema::assets;
    unwrap_ok!(
        assets::table
            .filter(assets::id.eq(asset_id))
            .select(assets::uuid)
            .first(conn)
            .await
    )
}

async fn seed_active_ews(conn: &mut AsyncPgConnection, user_id: i32, label: &str) -> Uuid {
    use chrono::Utc;
    let key_seed = Sha256::digest(format!("{}-{}", label, Uuid::new_v4()).as_bytes());
    let fp_hex = hex::encode(key_seed);
    let request_uuid = Uuid::new_v4();
    let ews_uuid = Uuid::new_v4();
    let now = Utc::now();

    diesel::sql_query(
        "INSERT INTO ews_onboarding_requests \
         (uuid, user_id, name, public_key, public_key_fingerprint, key_algo, \
          status, justification, decided_by_id, decided_at, created_at, updated_at) \
         VALUES ($1, $2, $3, 'ssh-ed25519 placeholder', $4, 'ed25519', \
                 'approved', 'seed-justification', $2, $5, $5, $5)",
    )
    .bind::<diesel::sql_types::Uuid, _>(request_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Text, _>(format!("ews_{}", &request_uuid.to_string()[..8]))
    .bind::<diesel::sql_types::Text, _>(&fp_hex)
    .bind::<diesel::sql_types::Timestamptz, _>(now)
    .execute(conn)
    .await
    .expect("insert seed ews_onboarding_requests");

    diesel::sql_query(
        "INSERT INTO ews \
         (uuid, request_uuid, user_id, name, public_key, public_key_fingerprint, \
          key_algo, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, 'ssh-ed25519 placeholder', $5, 'ed25519', $6, $6)",
    )
    .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
    .bind::<diesel::sql_types::Uuid, _>(request_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Text, _>(format!("ews_{}", &ews_uuid.to_string()[..8]))
    .bind::<diesel::sql_types::Text, _>(&fp_hex)
    .bind::<diesel::sql_types::Timestamptz, _>(now)
    .execute(conn)
    .await
    .expect("insert seed ews");

    ews_uuid
}

async fn seed_modbus_rule_shared_group(
    conn: &mut AsyncPgConnection,
    admin_id: i32,
    user_id: i32,
    label: &str,
    profinet_type: AssetType,
) -> (Uuid, Uuid) {
    let suffix = unique_name(label);
    let asset_group_uuid = create_test_asset_group(conn, &format!("{suffix}-ag")).await;
    let user_group_uuid = create_test_vauban_group(conn, &format!("{suffix}-ug")).await;
    add_user_to_vauban_group(conn, user_id, &user_group_uuid).await;

    let modbus_id = create_test_asset_in_group_with_type(
        conn,
        &format!("{suffix}-modbus"),
        admin_id,
        &asset_group_uuid,
        AssetType::IacsModbus,
    )
    .await;
    let profinet_id = create_test_asset_in_group_with_type(
        conn,
        &format!("{suffix}-profinet"),
        admin_id,
        &asset_group_uuid,
        profinet_type,
    )
    .await;

    let _ = create_test_access_rule(
        conn,
        &user_group_uuid,
        &asset_group_uuid,
        &["iacs_modbus"],
    )
    .await;

    let modbus_uuid = get_asset_uuid(conn, modbus_id).await;
    let profinet_uuid = get_asset_uuid(conn, profinet_id).await;
    (modbus_uuid, profinet_uuid)
}

#[tokio::test]
async fn connect_iacs_denied_when_rule_modbus_but_asset_profinet() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("proto_auth_adm")).await;
    let username = unique_name("proto_auth_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let (_modbus_uuid, profinet_uuid) = seed_modbus_rule_shared_group(
        &mut conn,
        admin_id,
        user_id,
        "cross",
        AssetType::IacsProfinet,
    )
    .await;
    let _ews = seed_active_ews(&mut conn, user_id, "cross").await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/{profinet_uuid}/connect-iacs"))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert_status(&response, 403);
}

#[tokio::test]
async fn connect_iacs_grants_when_rule_and_asset_both_modbus() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("proto_ok_adm")).await;
    let username = unique_name("proto_ok_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let (modbus_uuid, _profinet_uuid) = seed_modbus_rule_shared_group(
        &mut conn,
        admin_id,
        user_id,
        "ok",
        AssetType::IacsProfinet,
    )
    .await;
    let _ews = seed_active_ews(&mut conn, user_id, "ok").await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/{modbus_uuid}/connect-iacs"))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    let status = response.status_code().as_u16();
    assert!(
        matches!(status, 302 | 303),
        "matching modbus rule + modbus asset must redirect to status page, got {status}"
    );
}
