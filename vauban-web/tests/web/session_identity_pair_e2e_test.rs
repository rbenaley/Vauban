//! End-to-end coverage for the UX-02 identity pair rendering:
//! the Sessions and Recordings lists surface the full
//! `VAUBAN user &rarr; technical account` identity, against a real DB.

use axum::http::header::COOKIE;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use vauban_web::schema::proxy_sessions;

use crate::common::{TestApp, assertions::assert_status, unwrap_ok};
use crate::fixtures::{
    create_iacs_test_session_with_uuid, create_simple_admin_user, create_simple_iacs_asset,
    create_simple_ssh_asset, create_simple_user, create_test_session_with_uuid, unique_name,
};

async fn user_uuid_of(conn: &mut diesel_async::AsyncPgConnection, user_id: i32) -> uuid::Uuid {
    unwrap_ok!(
        vauban_web::schema::users::table
            .filter(vauban_web::schema::users::id.eq(user_id))
            .select(vauban_web::schema::users::uuid)
            .first(conn)
            .await
    )
}

/// The user fixtures append their own UUID suffix to the requested
/// username; assertions must use the username actually persisted.
async fn username_of(conn: &mut diesel_async::AsyncPgConnection, user_id: i32) -> String {
    unwrap_ok!(
        vauban_web::schema::users::table
            .filter(vauban_web::schema::users::id.eq(user_id))
            .select(vauban_web::schema::users::username)
            .first(conn)
            .await
    )
}

/// Connected SSH session: the /sessions row renders the full pair
/// `requester &rarr; credential` with the accessible title, and the
/// credential sentinel never leaks.
#[tokio::test]
async fn sessions_list_renders_requester_arrow_credential_for_connected_ssh() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("idpair_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = user_uuid_of(&mut conn, admin_id).await;
    let admin_token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let user_id = create_simple_user(&mut conn, &unique_name("idpair_alice")).await;
    let user_name = username_of(&mut conn, user_id).await;
    let asset_name = unique_name("idpair_ssh_asset");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    // The fixture snapshots credential_username = "testuser".
    create_test_session_with_uuid(&mut conn, user_id, asset_id, "ssh", "active").await;

    let response = app
        .server
        .get(&format!("/sessions?asset={asset_name}"))
        .add_header(COOKIE, format!("access_token={admin_token}"))
        .await;
    assert_status(&response, 200);
    let html = response.text();

    assert!(
        html.contains(&format!("{user_name} &rarr; testuser")),
        "the SSH row must render `{user_name} &rarr; testuser`, got: {html}"
    );
    assert!(
        html.contains(&format!("VAUBAN user {user_name} connected as testuser")),
        "the pair span must carry the accessible title attribute"
    );
    assert!(
        !html.contains(">pending<"),
        "the credential sentinel must never cross the UI"
    );
}

/// Recorded session: the /sessions/recordings row renders the same
/// pair (the recordings handler now joins `users`).
#[tokio::test]
async fn recordings_list_renders_requester_arrow_credential() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("idpair_rec_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = user_uuid_of(&mut conn, admin_id).await;
    let admin_token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let user_id = create_simple_user(&mut conn, &unique_name("idpair_rec_alice")).await;
    let user_name = username_of(&mut conn, user_id).await;
    let asset_name = unique_name("idpair_rec_asset");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    let (session_id, _) =
        create_test_session_with_uuid(&mut conn, user_id, asset_id, "ssh", "completed").await;
    unwrap_ok!(
        diesel::update(proxy_sessions::table.filter(proxy_sessions::id.eq(session_id)))
            .set((
                proxy_sessions::is_recorded.eq(true),
                proxy_sessions::recording_path.eq(Some("recordings/idpair/test.cast".to_string())),
            ))
            .execute(&mut conn)
            .await
    );

    let response = app
        .server
        .get(&format!("/sessions/recordings?asset={asset_name}"))
        .add_header(COOKIE, format!("access_token={admin_token}"))
        .await;
    assert_status(&response, 200);
    let html = response.text();

    assert!(
        html.contains(&format!("{user_name} &rarr; testuser")),
        "the recording row must render `{user_name} &rarr; testuser`, got: {html}"
    );
    assert!(
        html.contains(&format!("VAUBAN user {user_name} connected as testuser")),
        "the pair span must carry the accessible title attribute"
    );
}

/// Never-connected JIT grant: no arrow, the current `Requested by`
/// rendering is preserved, and the sentinel never leaks (never
/// `alice &rarr; alice`).
#[tokio::test]
async fn sessions_list_jit_grant_keeps_requested_by_without_arrow() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("idpair_jit_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = user_uuid_of(&mut conn, admin_id).await;
    let admin_token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let user_id = create_simple_user(&mut conn, &unique_name("idpair_jit_alice")).await;
    let user_name = username_of(&mut conn, user_id).await;
    let asset_name = unique_name("idpair_jit_asset");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    let (session_id, _) =
        create_test_session_with_uuid(&mut conn, user_id, asset_id, "ssh", "expired").await;
    // Rewrite the row into a never-connected JIT grant (credential
    // sentinel, no connection timestamps).
    unwrap_ok!(
        diesel::update(proxy_sessions::table.filter(proxy_sessions::id.eq(session_id)))
            .set((
                proxy_sessions::credential_id.eq("pending"),
                proxy_sessions::credential_username.eq("pending"),
                proxy_sessions::connected_at.eq(None::<chrono::DateTime<chrono::Utc>>),
                proxy_sessions::disconnected_at.eq(None::<chrono::DateTime<chrono::Utc>>),
            ))
            .execute(&mut conn)
            .await
    );

    let response = app
        .server
        .get(&format!("/sessions?asset={asset_name}"))
        .add_header(COOKIE, format!("access_token={admin_token}"))
        .await;
    assert_status(&response, 200);
    let html = response.text();

    assert!(
        html.contains(&format!("Requested by {user_name}")),
        "the JIT grant row must keep the `Requested by` rendering, got: {html}"
    );
    assert!(
        !html.contains("&rarr;"),
        "a JIT grant must never render the identity arrow"
    );
    assert!(
        !html.contains(">pending<") && !html.contains("&rarr; pending"),
        "the credential sentinel must never cross the UI"
    );
}

/// IACS tunnel: the pair falls back to the tunnel target snapshot,
/// `requester &rarr; host:port`.
#[tokio::test]
async fn sessions_list_renders_requester_arrow_tunnel_target_for_iacs() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("idpair_iacs_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = user_uuid_of(&mut conn, admin_id).await;
    let admin_token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let user_id = create_simple_user(&mut conn, &unique_name("idpair_iacs_alice")).await;
    let user_name = username_of(&mut conn, user_id).await;
    let asset_name = unique_name("idpair_iacs_asset");
    let asset_id = create_simple_iacs_asset(&mut conn, &asset_name, admin_id).await;
    // The IACS fixture snapshots tunnel_target_addr = "127.0.0.1:4321"
    // and an empty credential_username.
    create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "tunnel_active").await;

    let response = app
        .server
        .get(&format!("/sessions?asset={asset_name}"))
        .add_header(COOKIE, format!("access_token={admin_token}"))
        .await;
    assert_status(&response, 200);
    let html = response.text();

    assert!(
        html.contains(&format!("{user_name} &rarr; 127.0.0.1:4321")),
        "the IACS row must render `{user_name} &rarr; 127.0.0.1:4321`, got: {html}"
    );
}
