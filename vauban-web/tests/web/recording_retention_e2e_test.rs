//! E2E tests for recording retention post-reap UI behaviour.

use crate::common::TestApp;
use crate::fixtures::{
    create_recorded_session_with_type, create_simple_admin_user, create_simple_ssh_asset,
    unique_name,
};
use axum::http::header::COOKIE;
use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use uuid::Uuid;
use vauban_web::schema::proxy_sessions::dsl;
use vauban_web::services::recording_reaper::clear_recording_metadata;

async fn get_user_uuid(conn: &mut diesel_async::AsyncPgConnection, user_id: i32) -> Uuid {
    use vauban_web::schema::users;
    users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(conn)
        .await
        .expect("user uuid")
}

async fn get_session_uuid(conn: &mut diesel_async::AsyncPgConnection, session_id: i32) -> Uuid {
    dsl::proxy_sessions
        .filter(dsl::id.eq(session_id))
        .select(dsl::uuid)
        .first(conn)
        .await
        .expect("session uuid")
}

#[tokio::test]
async fn recording_detail_and_download_404_after_metadata_cleared() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ret_e2e_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("ret-e2e-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    let session_uuid = get_session_uuid(&mut conn, session_id).await;

    diesel::update(dsl::proxy_sessions.filter(dsl::id.eq(session_id)))
        .set((
            dsl::disconnected_at.eq(Utc::now() - Duration::days(400)),
            dsl::recording_path.eq(format!("recordings/2024/01/{session_uuid}/")),
            dsl::recording_finalized_at.eq(Utc::now()),
            dsl::recording_size_bytes.eq(1024_i64),
        ))
        .execute(&mut conn)
        .await
        .expect("age session");

    clear_recording_metadata(&mut conn, session_id)
        .await
        .expect("simulate post-reap DB state");

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let detail = app
        .server
        .get(&format!("/sessions/recordings/{session_uuid}"))
        .add_header(COOKIE, format!("access_token={token}"))
        .await;
    assert_eq!(detail.status_code().as_u16(), 404);

    let download = app
        .server
        .get(&format!("/sessions/recordings/{session_uuid}/download"))
        .add_header(COOKIE, format!("access_token={token}"))
        .await;
    assert_eq!(download.status_code().as_u16(), 404);
}

#[tokio::test]
async fn recording_list_omits_reaped_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ret_list_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("ret-list-asset"), admin_id).await;

    let reaped_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    let reaped_uuid = get_session_uuid(&mut conn, reaped_id).await;
    clear_recording_metadata(&mut conn, reaped_id)
        .await
        .expect("reap");

    let kept_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    let kept_uuid = get_session_uuid(&mut conn, kept_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let list = app
        .server
        .get("/sessions/recordings")
        .add_header(COOKIE, format!("access_token={token}"))
        .await;
    assert_eq!(list.status_code().as_u16(), 200);
    let body = list.text();
    assert!(
        !body.contains(&reaped_uuid.to_string()),
        "reaped session must not appear in list"
    );
    assert!(
        body.contains(&kept_uuid.to_string()),
        "non-reaped session must still appear in list"
    );
}

#[tokio::test]
async fn recent_recording_still_listed_when_only_old_session_reaped() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ret_recent_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("ret-recent-asset"), admin_id).await;

    let old_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    diesel::update(dsl::proxy_sessions.filter(dsl::id.eq(old_id)))
        .set(dsl::disconnected_at.eq(Utc::now() - Duration::days(400)))
        .execute(&mut conn)
        .await
        .expect("old disconnected_at");
    clear_recording_metadata(&mut conn, old_id)
        .await
        .expect("reap old");

    let recent_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    let recent_uuid = get_session_uuid(&mut conn, recent_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let list = app
        .server
        .get("/sessions/recordings")
        .add_header(COOKIE, format!("access_token={token}"))
        .await;
    assert_eq!(list.status_code().as_u16(), 200);
    assert!(list.text().contains(&recent_uuid.to_string()));
}
