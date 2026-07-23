//! Recording Details page integration tests (issue #29 / UX-28).
//!
//! Three groups:
//! 1. Detail page rendering (SSH/RDP/legacy/pending), authorization,
//!    anti-enumeration, sidebar, link resolution.
//! 2. List button rename ("View" -> "Recording Details").
//! 3. Download endpoint authorization and 404 paths. The streaming
//!    body itself (segment ZIP, .cast attachment) requires a live
//!    supervisor and is exercised in production (see runbook).

use crate::common::TestApp;
use crate::fixtures::{
    create_iacs_test_session_with_uuid, create_recorded_session_with_type,
    create_simple_admin_user, create_simple_iacs_asset, create_simple_ssh_asset,
    create_simple_user, unique_name,
};
use axum::http::header::COOKIE;
use chrono::Utc;
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;

/// Helper to read the user's UUID by id.
async fn get_user_uuid(conn: &mut AsyncPgConnection, user_id: i32) -> Uuid {
    use vauban_web::schema::users;
    users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(conn)
        .await
        .expect("user uuid")
}

/// Helper to fetch a session UUID by integer id.
async fn get_session_uuid(conn: &mut AsyncPgConnection, session_id: i32) -> Uuid {
    use vauban_web::schema::proxy_sessions;
    proxy_sessions::table
        .filter(proxy_sessions::id.eq(session_id))
        .select(proxy_sessions::uuid)
        .first(conn)
        .await
        .expect("session uuid")
}

/// Helper to populate the recording integrity bundle directly so the
/// tests don't depend on the supervisor-backed hydrator.
async fn fill_ssh_integrity(conn: &mut AsyncPgConnection, session_id: i32) {
    use vauban_web::schema::proxy_sessions::dsl;
    let now = Utc::now();
    diesel::update(dsl::proxy_sessions.filter(dsl::id.eq(session_id)))
        .set((
            dsl::recording_blake3
                .eq("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            dsl::recording_size_bytes.eq(91_234_i64),
            dsl::recording_duration_ms.eq(14_567_i64),
            dsl::recording_event_count.eq(1847_i32),
            dsl::recording_format.eq("asciicast-v2"),
            dsl::recording_width.eq(132_i16),
            dsl::recording_height.eq(43_i16),
            dsl::recording_finalized_at.eq(now),
        ))
        .execute(conn)
        .await
        .expect("ssh integrity update");
}

async fn fill_rdp_integrity(conn: &mut AsyncPgConnection, session_id: i32) {
    use vauban_web::schema::proxy_sessions::dsl;
    let now = Utc::now();
    diesel::update(dsl::proxy_sessions.filter(dsl::id.eq(session_id)))
        .set((
            dsl::recording_blake3
                .eq("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"),
            dsl::recording_size_bytes.eq(2 * 1024 * 1024_i64 + 500_000),
            dsl::recording_duration_ms.eq(1_823_000_i64),
            dsl::recording_format.eq("fmp4-dash"),
            dsl::recording_width.eq(1920_i16),
            dsl::recording_height.eq(1080_i16),
            dsl::recording_segment_count.eq(7_i32),
            dsl::recording_codec.eq("avc1.42c01e"),
            dsl::recording_finalized_at.eq(now),
        ))
        .execute(conn)
        .await
        .expect("rdp integrity update");
}

/// Populate the integrity bundle of an IACS pcap-bundle recording with
/// a configurable channel count (`recording_segment_count` mirrors
/// `meta.json` `channels.len()`; 0 = auth-only zero-channel session).
async fn fill_iacs_integrity(conn: &mut AsyncPgConnection, session_id: i32, segment_count: i32) {
    use vauban_web::schema::proxy_sessions::dsl;
    let now = Utc::now();
    diesel::update(dsl::proxy_sessions.filter(dsl::id.eq(session_id)))
        .set((
            dsl::recording_blake3
                .eq("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
            dsl::recording_size_bytes.eq(4_096_i64),
            dsl::recording_duration_ms.eq(12_000_i64),
            dsl::recording_event_count.eq(segment_count * 10),
            dsl::recording_format.eq("pcap-bundle"),
            dsl::recording_segment_count.eq(segment_count),
            dsl::recording_finalized_at.eq(now),
        ))
        .execute(conn)
        .await
        .expect("iacs integrity update");
}

/// Spawn an app + admin + one recorded IACS session, returning
/// `(app, token, session_id, session_uuid)`. The session satisfies
/// the `proxy_sessions_iacs_consistency` CHECK (ews row + protocol)
/// and is flagged recorded with a pcap-bundle path.
async fn spawn_iacs_recording(prefix: &str) -> (&'static TestApp, String, i32, Uuid) {
    use vauban_web::schema::proxy_sessions::dsl;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name(&format!("{prefix}_admin"));
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id = create_simple_iacs_asset(
        &mut conn,
        &unique_name(&format!("{prefix}-asset")),
        admin_id,
    )
    .await;
    let (session_id, uuid) =
        create_iacs_test_session_with_uuid(&mut conn, admin_id, asset_id, "terminated").await;
    diesel::update(dsl::proxy_sessions.filter(dsl::id.eq(session_id)))
        .set((
            dsl::is_recorded.eq(true),
            dsl::recording_path.eq(format!("/recordings/iacs/2026/07/{}/", uuid)),
        ))
        .execute(&mut conn)
        .await
        .expect("mark iacs session recorded");
    drop(conn);

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    (app, token, session_id, uuid)
}

// ===========================================================================
// Group 1: Detail page rendering & authorization
// ===========================================================================

#[tokio::test]
async fn test_recording_detail_renders_for_ssh_with_full_integrity() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rd_ssh_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("rd-ssh-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    fill_ssh_integrity(&mut conn, session_id).await;
    let uuid = get_session_uuid(&mut conn, session_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(body.contains("Recording Details"));
    assert!(
        body.contains("01234567...89abcdef"),
        "blake3 truncated form"
    );
    assert!(body.contains("asciicast v2"));
    assert!(body.contains("Session UUID"));
}

#[tokio::test]
async fn test_recording_detail_renders_for_rdp_segmented() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rd_rdp_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("rd-rdp-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "rdp").await;
    fill_rdp_integrity(&mut conn, session_id).await;
    let uuid = get_session_uuid(&mut conn, session_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(body.contains("fragmented MP4 (DASH)"));
    assert!(body.contains("avc1.42c01e"));
    assert!(body.contains("1920 x 1080"));
}

#[tokio::test]
async fn test_recording_detail_renders_pending_integrity_state() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rd_pending_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("rd-pending-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    let uuid = get_session_uuid(&mut conn, session_id).await;
    // No integrity columns populated -> hydrator hasn't run yet.

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        body.contains("Integrity metadata pending finalization"),
        "pending state must surface a friendly message"
    );
    assert!(body.contains("Awaiting hydration"));
}

/// E2E: a pending Recording Details page must ship the dual safety net
/// (WS filter on this UUID + `every 5s` poll) so a lost
/// `recording_hydrated` push still flips the panels without a manual
/// reload / second tab.
#[tokio::test]
async fn e2e_pending_detail_page_embeds_hydrate_ws_safety_net() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rd_ws_net_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("rd-ws-net-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    let uuid = get_session_uuid(&mut conn, session_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();

    assert!(
        body.contains(r#"id="recording-detail-ws-trigger""#),
        "pending page must render the hidden WS refresh trigger"
    );
    assert!(
        body.contains("every 5s"),
        "E2E: rendered HTML must include every 5s poll (I-HYDRATE-WS-4)"
    );
    assert!(
        body.contains("recording_hydrated"),
        "E2E: rendered HTML must filter on recording_hydrated"
    );
    assert!(
        body.contains(&uuid.to_string()),
        "E2E: rendered trigger must bind THIS session uuid (not a placeholder)"
    );
    // The hx-get must target the same UUID route the operator is on.
    assert!(
        body.contains(&format!(r#"hx-get="/sessions/recordings/{}""#, uuid)),
        "E2E: hx-get must refetch this recording detail URL"
    );
}

/// E2E: after integrity is persisted, a refetch (simulating the WS /
/// every-5s trigger) must render the hydrated panels — proving the
/// swap target HTML is what the client would install.
#[tokio::test]
async fn e2e_detail_refetch_after_hydration_shows_integrity_panels() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rd_ws_refetch_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("rd-ws-refetch-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    let uuid = get_session_uuid(&mut conn, session_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    // Pending first load.
    let pending = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(pending.status_code().as_u16(), 200);
    assert!(pending.text().contains("Awaiting hydration"));

    // Hydrator (or WS-triggered refetch after finalize) persists bundle.
    fill_ssh_integrity(&mut conn, session_id).await;

    let hydrated = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(hydrated.status_code().as_u16(), 200);
    let body = hydrated.text();
    assert!(
        body.contains("BLAKE3 hash recorded"),
        "refetch after finalize must show integrity checklist"
    );
    assert!(
        body.contains("Hydrated at"),
        "refetch after finalize must show hydration timestamp"
    );
    assert!(
        !body.contains("Awaiting hydration"),
        "pending copy must be gone after finalize"
    );
}

#[tokio::test]
async fn test_recording_detail_404_when_uuid_unknown() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rd_404_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let bogus = Uuid::new_v4();
    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", bogus))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 404);
}

#[tokio::test]
async fn test_recording_detail_400_when_uuid_malformed() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rd_malformed_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/recordings/not-a-uuid")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Axum's `Path<Uuid>` extractor returns 400 on parse failure.
    assert_eq!(response.status_code().as_u16(), 400);
}

#[tokio::test]
async fn test_recording_detail_404_when_session_not_recorded() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rd_notrec_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("rd-notrec-asset"), admin_id).await;

    use vauban_web::schema::proxy_sessions;
    let uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = "127.0.0.1".parse().unwrap();
    diesel::insert_into(proxy_sessions::table)
        .values((
            proxy_sessions::uuid.eq(uuid),
            proxy_sessions::user_id.eq(admin_id),
            proxy_sessions::asset_id.eq(asset_id),
            proxy_sessions::credential_id.eq("c"),
            proxy_sessions::credential_username.eq("u"),
            proxy_sessions::session_type.eq(vauban_web::models::session::SessionType::Ssh),
            proxy_sessions::status.eq("disconnected"),
            proxy_sessions::client_ip.eq(ip),
            proxy_sessions::is_recorded.eq(false),
            proxy_sessions::metadata.eq(serde_json::json!({})),
        ))
        .execute(&mut conn)
        .await
        .expect("insert non-recorded session");

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Anti-enumeration: same shape as "unknown UUID".
    assert_eq!(response.status_code().as_u16(), 404);
}

#[tokio::test]
async fn test_recording_detail_403_or_404_when_caller_lacks_admin_view() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rd_owner_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("rd-owner-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    let uuid = get_session_uuid(&mut conn, session_id).await;

    let user_name = unique_name("rd_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let s = response.status_code().as_u16();
    assert!(s == 404, "non-admin must see anti-enum 404, got {}", s);
}

#[tokio::test]
async fn test_recording_detail_sidebar_active_tab_remains_recordings() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rd_sidebar_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("rd-sidebar-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    fill_ssh_integrity(&mut conn, session_id).await;
    let uuid = get_session_uuid(&mut conn, session_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    // The sidebar's "Recordings" link gets an `aria-current="page"`
    // attribute when `is_recordings` is true.
    assert!(
        body.contains("Recordings"),
        "sidebar must list a Recordings entry"
    );
    assert!(
        !body.contains("/sessions/recordings/play/"),
        "smoke check: no malformed link"
    );
}

#[tokio::test]
async fn test_recording_detail_back_to_recordings_link_present() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rd_back_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("rd-back-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    fill_ssh_integrity(&mut conn, session_id).await;
    let uuid = get_session_uuid(&mut conn, session_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let body = response.text();
    assert!(
        body.contains(r#"href="/sessions/recordings""#),
        "must link back to /sessions/recordings"
    );
    assert!(body.contains("Back to Recordings"));
}

#[tokio::test]
async fn test_recording_detail_play_and_download_buttons_present() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rd_buttons_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("rd-btn-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    fill_ssh_integrity(&mut conn, session_id).await;
    let uuid = get_session_uuid(&mut conn, session_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let body = response.text();
    assert!(body.contains(&format!(
        r#"href="/sessions/recordings/{}/play""#,
        session_id
    )));
    assert!(body.contains(&format!(r#"href="/sessions/recordings/{}/download""#, uuid)));
}

#[tokio::test]
async fn test_recording_detail_no_inline_script_or_style() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rd_csp_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("rd-csp-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    fill_ssh_integrity(&mut conn, session_id).await;
    let uuid = get_session_uuid(&mut conn, session_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let body = response.text();
    // The detail card itself must not introduce inline <script> or
    // <style> tags. (base.html ships its own controlled scripts; the
    // assertion targets handler-injected content.)
    let script_count = body.matches("<script>").count();
    assert!(
        script_count == 0,
        "no inline `<script>` blocks expected, got {}",
        script_count
    );
    assert!(
        !body.contains("<style>"),
        "no inline `<style>` blocks expected"
    );
}

#[tokio::test]
async fn test_recording_detail_corrupt_integrity_state() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rd_corrupt_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("rd-corrupt-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    let uuid = get_session_uuid(&mut conn, session_id).await;

    // Hydrator's "corrupt" marker: finalized_at set, blake3 NULL.
    use vauban_web::schema::proxy_sessions::dsl;
    diesel::update(dsl::proxy_sessions.filter(dsl::id.eq(session_id)))
        .set(dsl::recording_finalized_at.eq(Utc::now()))
        .execute(&mut conn)
        .await
        .expect("set finalized");

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        body.contains("Integrity metadata unavailable"),
        "corrupt marker must surface unavailable message"
    );
}

#[tokio::test]
async fn test_recording_detail_rejection_narrative_when_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rd_reject_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let requester_name = unique_name("rd_reject_user");
    let requester_id = create_simple_user(&mut conn, &requester_name).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("rd-rej-asset"), admin_id).await;
    let session_id =
        create_recorded_session_with_type(&mut conn, requester_id, asset_id, "ssh").await;
    let uuid = get_session_uuid(&mut conn, session_id).await;

    use vauban_web::schema::proxy_sessions::dsl;
    diesel::update(dsl::proxy_sessions.filter(dsl::id.eq(session_id)))
        .set((
            dsl::status.eq("rejected"),
            dsl::rejected_by_id.eq(admin_id),
            dsl::rejected_at.eq(Utc::now()),
            dsl::decision_reason.eq("Out of business hours"),
        ))
        .execute(&mut conn)
        .await
        .expect("set rejection");

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let body = response.text();
    assert!(
        body.contains("Rejected by"),
        "must show rejection narrative"
    );
    assert!(body.contains("Out of business hours"));
}

#[tokio::test]
async fn test_recording_detail_approval_narrative_when_approved() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rd_appr_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let requester_name = unique_name("rd_appr_user");
    let requester_id = create_simple_user(&mut conn, &requester_name).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("rd-appr-asset"), admin_id).await;
    let session_id =
        create_recorded_session_with_type(&mut conn, requester_id, asset_id, "ssh").await;
    let uuid = get_session_uuid(&mut conn, session_id).await;

    use vauban_web::schema::proxy_sessions::dsl;
    diesel::update(dsl::proxy_sessions.filter(dsl::id.eq(session_id)))
        .set((
            dsl::status.eq("disconnected"),
            dsl::approved_by_id.eq(admin_id),
            dsl::approved_at.eq(Utc::now()),
        ))
        .execute(&mut conn)
        .await
        .expect("set approval");

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let body = response.text();
    assert!(body.contains("Approved by"), "must show approval narrative");
    assert!(body.contains(&admin_name));
}

#[tokio::test]
async fn test_recording_detail_blake3_hex_lowercase_64_chars() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rd_b3_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("rd-b3-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    fill_ssh_integrity(&mut conn, session_id).await;
    let uuid = get_session_uuid(&mut conn, session_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    let body = response.text();

    // The full hex shows up in the title attribute. The SET clause
    // wrote a lowercase 64-char value; verify it round-trips.
    assert!(body.contains("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
}

#[tokio::test]
async fn test_recording_detail_renders_legacy_fmp4_flat() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rd_flat_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("rd-flat-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "rdp").await;
    let uuid = get_session_uuid(&mut conn, session_id).await;

    use vauban_web::schema::proxy_sessions::dsl;
    diesel::update(dsl::proxy_sessions.filter(dsl::id.eq(session_id)))
        .set((
            dsl::recording_blake3
                .eq("ffeeddccbbaa00112233445566778899aabbccddeeff00112233445566778899"),
            dsl::recording_size_bytes.eq(15_000_000_i64),
            dsl::recording_duration_ms.eq(600_000_i64),
            dsl::recording_format.eq("fmp4-flat"),
            dsl::recording_width.eq(1280_i16),
            dsl::recording_height.eq(720_i16),
            dsl::recording_finalized_at.eq(Utc::now()),
        ))
        .execute(&mut conn)
        .await
        .expect("set flat integrity");

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(body.contains("MP4 (legacy)"));
    assert!(body.contains("1280 x 720"));
}

#[tokio::test]
async fn test_recording_detail_includes_session_uuid_in_footer() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rd_uuid_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("rd-uuid-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    let uuid = get_session_uuid(&mut conn, session_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    let body = response.text();
    assert!(body.contains(&uuid.to_string()));
}

#[tokio::test]
async fn test_recording_detail_breadcrumb_present() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rd_bc_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("rd-bc-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    let uuid = get_session_uuid(&mut conn, session_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    let body = response.text();
    assert!(body.contains(r#"aria-label="Breadcrumb""#));
}

// ===========================================================================
// Group 2: List button rename ("View" -> "Recording Details")
// ===========================================================================

#[tokio::test]
async fn test_recording_list_button_says_details_not_view() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rl_label_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("rl-label-asset"), admin_id).await;
    let _session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let response = app
        .server
        .get("/sessions/recordings")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    // On the list, the row-level cross-link must use the short
    // "Details" label (the page header reserves "Recording Details"
    // for the destination page itself; on the table-row there is no
    // ambiguity since context is the recording row).
    let trimmed: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        trimmed.contains("> Details <")
            || body.contains(">Details<")
            || body.contains(">\n                            Details\n                        <"),
        "row link must be labelled 'Details' (got body excerpt around 'Details': {})",
        body.lines()
            .filter(|l| l.contains("Details"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    // Old "View" label must not reappear on the list either.
    assert!(
        !body.contains(">View<")
            && !body.contains(">\n                            View\n                        <"),
        "old 'View' label must stay gone from the recordings list"
    );
}

#[tokio::test]
async fn test_recording_list_button_link_uses_uuid_route() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rl_uuid_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("rl-uuid-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    let uuid = get_session_uuid(&mut conn, session_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let response = app
        .server
        .get("/sessions/recordings")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    let body = response.text();
    assert!(
        body.contains(&format!(r#"href="/sessions/recordings/{}""#, uuid)),
        "list must link to /sessions/recordings/{{uuid}}"
    );
}

#[tokio::test]
async fn test_recording_list_no_link_to_session_id_remains() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rl_nosession_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("rl-nosess-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let response = app
        .server
        .get("/sessions/recordings")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    let body = response.text();

    // The old "View" button linked to /sessions/{session_id} (session
    // detail page). Issue #29 removes that link from the recordings
    // list. The Play button still goes to /sessions/recordings/{id}/play
    // and the literal /sessions/recordings link is the back-button --
    // both legitimate; only the deep `/sessions/{N}` form should be gone.
    assert!(
        !body.contains(&format!(r#"href="/sessions/{}""#, session_id)),
        "old View -> /sessions/{{id}} link must be gone"
    );
}

// ===========================================================================
// Group 3: Download endpoint (auth + 404 only -- streaming requires
// the supervisor and is exercised in production).
// ===========================================================================

#[tokio::test]
async fn test_download_recording_requires_admin_view() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("dl_owner_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("dl-owner-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    let uuid = get_session_uuid(&mut conn, session_id).await;

    let user_name = unique_name("dl_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}/download", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 404);
}

#[tokio::test]
async fn test_download_recording_404_when_uuid_unknown() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("dl_404_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let bogus = Uuid::new_v4();
    let response = app
        .server
        .get(&format!("/sessions/recordings/{}/download", bogus))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 404);
}

#[tokio::test]
async fn test_download_recording_400_when_uuid_malformed() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("dl_400_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/recordings/not-a-uuid/download")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 400);
}

#[tokio::test]
async fn test_download_recording_404_when_supervisor_unavailable() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("dl_no_sup_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("dl-no-sup-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    let uuid = get_session_uuid(&mut conn, session_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    // The test app has `supervisor: None` -- the handler returns
    // 500 (Internal) since the supervisor is required; that's the
    // documented dev-mode behaviour.
    let response = app
        .server
        .get(&format!("/sessions/recordings/{}/download", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    let s = response.status_code().as_u16();
    // Either 500 (supervisor missing) is acceptable.
    assert!(
        s == 500 || s == 404,
        "expected 500 (no supervisor) or 404; got {}",
        s
    );
}

#[tokio::test]
async fn test_download_recording_404_when_session_not_recorded() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("dl_notrec_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("dl-notrec-asset"), admin_id).await;

    use vauban_web::schema::proxy_sessions;
    let uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = "127.0.0.1".parse().unwrap();
    diesel::insert_into(proxy_sessions::table)
        .values((
            proxy_sessions::uuid.eq(uuid),
            proxy_sessions::user_id.eq(admin_id),
            proxy_sessions::asset_id.eq(asset_id),
            proxy_sessions::credential_id.eq("c"),
            proxy_sessions::credential_username.eq("u"),
            proxy_sessions::session_type.eq(vauban_web::models::session::SessionType::Ssh),
            proxy_sessions::status.eq("disconnected"),
            proxy_sessions::client_ip.eq(ip),
            proxy_sessions::is_recorded.eq(false),
            proxy_sessions::metadata.eq(serde_json::json!({})),
        ))
        .execute(&mut conn)
        .await
        .expect("insert");

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}/download", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 404);
}

// ===========================================================================
// Group 4: /sessions/recordings/{id}/play header button -- must point to
// the new Recording Details UUID route, NOT the old session detail page.
// Regression: bug reported on 2026-04-30 where the play page still showed
// "Session Details" linking to /sessions/{id}.
// ===========================================================================

#[tokio::test]
async fn test_play_page_header_button_says_recording_details_not_session_details() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rp_label_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("rp-label-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let response = app
        .server
        .get(&format!("/sessions/recordings/{}/play", session_id))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        body.contains("Recording Details"),
        "play page header must label the cross-link 'Recording Details'"
    );
    assert!(
        !body.contains(">Session Details<"),
        "play page must not advertise a 'Session Details' button anymore"
    );
}

// Regression for the "segment 0001 missing" 404 reported on 2026-04-30:
// the RDP download path concatenated `{:04}.mp4` (four digits) but the
// segments are written by `vauban-audit::recording_manager` as
// `{:03}.mp4` (three digits, see also `build_mpd_xml` in the same
// handler module which emits `001.mp4`/`002.mp4`/...). This test
// pins the format string at the source level so a regression cannot
// silently reappear.
#[tokio::test]
async fn test_rdp_download_uses_three_digit_segment_filename_format() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("handlers")
        .join("web")
        .join("sessions.rs");
    let src = std::fs::read_to_string(&path).expect("read sessions.rs");
    // Grep for the formatter inside the stream_rdp_zip body.
    let stream_rdp_zip_idx = src
        .find("async fn stream_rdp_zip(")
        .expect("stream_rdp_zip should exist");
    let body = &src[stream_rdp_zip_idx..];
    assert!(
        body.contains(r#"format!("{}{:03}.mp4", base_dir, seg.index)"#),
        "stream_rdp_zip must build segment paths with three-digit index"
    );
    assert!(
        !body.contains(r#"format!("{}{:04}.mp4", base_dir, seg.index)"#),
        "regression: stream_rdp_zip must NOT use four-digit segment index ({{:04}})"
    );
}

#[tokio::test]
async fn test_play_page_header_button_links_to_recording_uuid_route() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rp_link_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("rp-link-asset"), admin_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, admin_id, asset_id, "ssh").await;
    let uuid = get_session_uuid(&mut conn, session_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let response = app
        .server
        .get(&format!("/sessions/recordings/{}/play", session_id))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        body.contains(&format!(r#"href="/sessions/recordings/{}""#, uuid)),
        "play page header button must point to /sessions/recordings/{{uuid}}"
    );
    assert!(
        !body.contains(&format!(r#"href="/sessions/{}""#, session_id)),
        "play page must not link to the old /sessions/{{id}} session-detail route"
    );
}

// ============================================================================
// Issue #29 follow-up: WS-driven auto-refresh on hydration completion
// ----------------------------------------------------------------------------
// The Recording Details page reacts to a `recording_hydrated` WebSocket
// message (broadcast by `services::recording_hydrator` after every
// finalization transition) by refetching itself and swapping the
// container. The pin tests below guard the wire contract on the
// CLIENT side (template). The SERVER side is pinned in
// `vauban-web/src/services/recording_hydrator.rs` (broadcast call
// sites + payload shape).
// ============================================================================

const RECORDING_DETAIL_HTML: &str = include_str!("../../templates/sessions/recording_detail.html");
const RECORDING_LIST_HTML: &str = include_str!("../../templates/sessions/recording_list.html");

#[test]
fn recording_detail_template_wraps_content_in_stable_container_id() {
    // The `hx-target` of the WS-driven refresh trigger relies on a
    // wrapper id that survives across renders. Removing or renaming
    // it would break the swap silently.
    assert!(
        RECORDING_DETAIL_HTML.contains(r#"id="recording-detail-container""#),
        "recording_detail.html must wrap its body in `id=\"recording-detail-container\"` \
         so the WS auto-refresh hx-target/hx-select can find it"
    );
}

#[test]
fn recording_detail_template_carries_ws_refresh_trigger() {
    // The hidden trigger uses HTMX's `htmx:wsAfterMessage` to pick up
    // messages relayed through the inherited `/ws/notifications`
    // socket (no extra connection). The filter MUST check both the
    // event kind AND the current session UUID -- otherwise every
    // open Recording Details tab would refetch on every hydration
    // event, which is a thundering-herd footgun.
    let body = RECORDING_DETAIL_HTML;
    assert!(
        body.contains("htmx:wsAfterMessage"),
        "recording_detail.html must hook into `htmx:wsAfterMessage`"
    );
    assert!(
        body.contains("every 5s"),
        "recording_detail.html must poll every 5s as a safety net for \
         the race where `recording_hydrated` is broadcast before this \
         tab's /ws/notifications subscription is live"
    );
    assert!(
        body.contains("'recording_hydrated'"),
        "WS filter MUST match the literal `recording_hydrated` event \
         kind (the hydrator's payload contract)"
    );
    assert!(
        body.contains("{{ recording.session_uuid }}"),
        "WS filter MUST narrow to THIS session's UUID; otherwise \
         every Recording Details tab refetches on every hydration"
    );
    assert!(
        body.contains("hx-select=\"#recording-detail-container\""),
        "WS trigger must `hx-select` the wrapper container (server \
         renders the FULL page, we cherry-pick the changing slice)"
    );
    assert!(
        body.contains("hx-target=\"#recording-detail-container\""),
        "WS trigger must `hx-target` the same wrapper container \
         (outerHTML swap)"
    );
    assert!(
        body.contains("hx-swap=\"outerHTML\""),
        "WS trigger must use `outerHTML` swap to replace the wrapper \
         (innerHTML would leak the previous container's children)"
    );
    assert!(
        body.contains("throttle:1s"),
        "WS trigger must throttle at 1s to coalesce bursts from \
         consecutive hydrator transitions on the same row"
    );
}

#[test]
fn recording_detail_ws_trigger_is_hidden_from_layout() {
    // The trigger is a layout-invisible HTMX hook -- visible would
    // shift the page on hydration. Pin the `hidden` class so a
    // cosmetic refactor cannot accidentally expose it.
    let body = RECORDING_DETAIL_HTML;
    let trigger_idx = body
        .find(r#"id="recording-detail-ws-trigger""#)
        .expect("WS trigger element must exist");
    let window = &body[trigger_idx..trigger_idx.saturating_add(120)];
    assert!(
        window.contains("hidden"),
        "WS trigger must carry the `hidden` class so it never affects \
         the visible layout"
    );
}

#[test]
fn recording_list_template_extends_filter_to_hydration_events() {
    // The list page already auto-refreshed on `recording_ready`
    // (session-end). Now also reacts to `recording_hydrated` so the
    // size-badge / format column reflects the integrity bundle as
    // soon as it is persisted, with no manual reload.
    let body = RECORDING_LIST_HTML;
    assert!(
        body.contains("'recording_ready'"),
        "list filter must keep the existing `recording_ready` trigger \
         (regression guard)"
    );
    assert!(
        body.contains("'recording_hydrated'"),
        "list filter must ALSO match `recording_hydrated` so the size \
         column lights up after the hydrator finalises a row"
    );
}

// ===========================================================================
// Group 4: Inspect button visibility for IACS bundles.
//
// /sessions/recordings/{uuid}/inspect 404s when the bundle carries
// zero channels (auth-only session) or is not hydrated yet. The UI
// must therefore hide the Inspect button in those two cases instead
// of rendering a dead link (regression: 404 on zero-pcap recordings).
// ===========================================================================

#[tokio::test]
async fn test_inspect_button_disabled_for_iacs_zero_channel_recording() {
    let (app, token, session_id, uuid) = spawn_iacs_recording("ri_zero").await;
    let mut conn = app.get_conn().await;
    // Hydrated zero-channel bundle: meta.json existed with channels: [].
    fill_iacs_integrity(&mut conn, session_id, 0).await;
    drop(conn);

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        !body.contains(&format!("/sessions/recordings/{}/inspect", uuid)),
        "zero-channel IACS recording must NOT link to /inspect (it 404s)"
    );
    assert!(
        body.contains("Inspect Capture")
            && body.contains("aria-disabled=\"true\"")
            && body.contains("cursor-not-allowed"),
        "zero-channel IACS recording must keep the Inspect Capture \
         button visible but disabled (layout consistency, no dead link)"
    );
}

#[tokio::test]
async fn test_inspect_button_disabled_for_iacs_recording_pending_hydration() {
    // recording_segment_count is still NULL (hydrator has not run):
    // /inspect 404s on the missing finalized_at, so the button renders
    // disabled until hydration lands a positive channel count.
    let (app, token, _session_id, uuid) = spawn_iacs_recording("ri_pending").await;

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        !body.contains(&format!("/sessions/recordings/{}/inspect", uuid)),
        "pending-hydration IACS recording must NOT link to /inspect"
    );
    assert!(
        body.contains("Inspect Capture") && body.contains("aria-disabled=\"true\""),
        "pending-hydration IACS recording must render the disabled button"
    );
}

#[tokio::test]
async fn test_inspect_button_shown_for_iacs_recording_with_channels() {
    let (app, token, session_id, uuid) = spawn_iacs_recording("ri_chan").await;
    let mut conn = app.get_conn().await;
    fill_iacs_integrity(&mut conn, session_id, 2).await;
    drop(conn);

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        body.contains(&format!("/sessions/recordings/{}/inspect", uuid)),
        "hydrated IACS recording with channels must keep its Inspect link"
    );
    assert!(
        body.contains("Inspect Capture"),
        "hydrated IACS recording with channels must render the Inspect button"
    );
}

#[tokio::test]
async fn test_recording_list_disables_inspect_for_zero_channel_but_keeps_link_for_channels() {
    // One list, two IACS rows: zero-channel (disabled button, no link)
    // vs 3 channels (live link). Sharing the app pins both branches of
    // the row gate against the same rendered HTML. The disabled button
    // stays in the DOM so the action column keeps its alignment.
    let (app, token, zero_session_id, zero_uuid) = spawn_iacs_recording("rl_insp").await;
    let mut conn = app.get_conn().await;
    fill_iacs_integrity(&mut conn, zero_session_id, 0).await;

    let admin_name = unique_name("rl_insp_admin2");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let asset_id =
        create_simple_iacs_asset(&mut conn, &unique_name("rl-insp-asset2"), admin_id).await;
    let (chan_session_id, chan_uuid) =
        create_iacs_test_session_with_uuid(&mut conn, admin_id, asset_id, "terminated").await;
    {
        use vauban_web::schema::proxy_sessions::dsl;
        diesel::update(dsl::proxy_sessions.filter(dsl::id.eq(chan_session_id)))
            .set((
                dsl::is_recorded.eq(true),
                dsl::recording_path.eq(format!("/recordings/iacs/2026/07/{}/", chan_uuid)),
            ))
            .execute(&mut conn)
            .await
            .expect("mark second iacs session recorded");
    }
    fill_iacs_integrity(&mut conn, chan_session_id, 3).await;
    drop(conn);

    let response = app
        .server
        .get("/sessions/recordings")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        !body.contains(&format!("/sessions/recordings/{}/inspect", zero_uuid)),
        "list row of a zero-channel IACS recording must NOT link to /inspect"
    );
    assert!(
        body.contains("aria-disabled=\"true\"") && body.contains("cursor-not-allowed"),
        "the zero-channel row must render the Inspect button as a \
         disabled, non-clickable element (alignment preserved)"
    );
    assert!(
        body.contains(&format!("/sessions/recordings/{}/inspect", chan_uuid)),
        "list row of an IACS recording with channels must keep its Inspect link"
    );
}

#[tokio::test]
async fn test_inspect_route_returns_404_for_zero_channel_recording() {
    // The server-side contract the visibility gate mirrors: /inspect
    // stays a 404 for zero-channel bundles (anti-enumeration), the UI
    // just stops advertising it. If this ever becomes a 200, the
    // button gate should be revisited.
    let (app, token, session_id, uuid) = spawn_iacs_recording("ri_404").await;
    let mut conn = app.get_conn().await;
    fill_iacs_integrity(&mut conn, session_id, 0).await;
    drop(conn);

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}/inspect", uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 404);
}
