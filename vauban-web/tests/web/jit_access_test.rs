// VAUBAN Web - JIT Access Tests.
//
// Tests for Just-In-Time access request, approval, and rejection flows.

use crate::common::{TestApp, assertions::assert_status, unwrap_ok};
use crate::fixtures::{
    create_approval_request, create_approval_request_with_duration, create_approved_session,
    create_expired_approved_session, create_simple_admin_user, create_simple_ssh_asset,
    create_simple_user, unique_name,
};
use axum::http::header::COOKIE;
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;
use vauban_web::schema::proxy_sessions;

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

#[tokio::test]
async fn test_approval_list_page_admin_sees_pending_requests() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("jit_admin_list");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_name = unique_name("jit_requester_list");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    let asset_name = unique_name("jit_asset_list");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    create_approval_request(&mut conn, user_id, asset_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/approvals")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("Need access for maintenance"),
        "approvals list should show justification; body len {}",
        body.len()
    );
}

#[tokio::test]
async fn test_approval_list_page_forbidden_for_regular_user() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("jit_normal_approvals");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get("/sessions/approvals")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 403,
        "regular user should get redirect or forbidden, got {}",
        status
    );
}

#[tokio::test]
async fn test_approve_session_updates_status() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("jit_admin_approve");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_name = unique_name("jit_user_approve");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    let asset_name = unique_name("jit_asset_approve");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    let session_uuid = create_approval_request(&mut conn, user_id, asset_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!(
            "/sessions/approvals/{}/approve",
            session_uuid
        ))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "approve should redirect, got {}",
        status
    );

    let new_status: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(new_status, "approved");

    let approved_by_id: Option<i32> = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select(proxy_sessions::approved_by_id)
            .first(&mut conn)
            .await
    );
    assert!(
        approved_by_id.is_some(),
        "approved_by_id should be set after approval"
    );
    assert_eq!(approved_by_id, Some(admin_id));
}

#[tokio::test]
async fn test_reject_session_updates_status() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("jit_admin_reject");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_name = unique_name("jit_user_reject");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    let asset_name = unique_name("jit_asset_reject");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    let session_uuid = create_approval_request(&mut conn, user_id, asset_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!(
            "/sessions/approvals/{}/reject",
            session_uuid
        ))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "reject should redirect, got {}",
        status
    );

    let new_status: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(new_status, "rejected");
}

#[tokio::test]
async fn test_my_requests_page_shows_user_requests() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_name = unique_name("jit_my_requests");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let admin_name = unique_name("jit_asset_owner_mr");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;

    let asset_name = unique_name("jit_asset_mr");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    create_approval_request(&mut conn, user_id, asset_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;

    let response = app
        .server
        .get("/sessions/my-requests")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    let lower = body.to_lowercase();
    assert!(
        lower.contains("pending"),
        "my-requests should mention pending status"
    );
}

#[tokio::test]
async fn test_my_requests_page_shows_duration() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_name = unique_name("jit_mr_dur");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let admin_name = unique_name("jit_mr_dur_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;

    let asset_name = unique_name("jit_mr_dur_asset");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    create_approval_request_with_duration(&mut conn, user_id, asset_id, Some(7200)).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;

    let response = app
        .server
        .get("/sessions/my-requests")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("2h"),
        "my-requests should display duration '2h' for 7200s"
    );
}

#[tokio::test]
async fn test_my_requests_page_shows_unlimited_when_no_duration() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_name = unique_name("jit_mr_unlim");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let admin_name = unique_name("jit_mr_unlim_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;

    let asset_name = unique_name("jit_mr_unlim_asset");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    create_approval_request_with_duration(&mut conn, user_id, asset_id, None).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;

    let response = app
        .server
        .get("/sessions/my-requests")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("Unlimited"),
        "my-requests should display 'Unlimited' when no max_session_duration"
    );
}

#[tokio::test]
async fn test_my_requests_page_has_websocket_connection() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_name = unique_name("jit_mr_ws");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;

    let response = app
        .server
        .get("/sessions/my-requests")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("ws-connect=\"/ws/notifications\""),
        "my-requests page should connect to /ws/notifications"
    );
    assert!(
        body.contains("id=\"jit-notification\""),
        "my-requests page should have jit-notification OOB target"
    );
    assert!(
        body.contains("request_approved"),
        "jit-notification trigger should filter on request_approved"
    );
}

#[tokio::test]
async fn test_cancel_own_pending_request() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_name = unique_name("jit_cancel_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let admin_name = unique_name("jit_cancel_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;

    let asset_name = unique_name("jit_asset_cancel");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    let session_uuid = create_approval_request(&mut conn, user_id, asset_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!(
            "/sessions/my-requests/{}/cancel",
            session_uuid
        ))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "cancel should redirect, got {}",
        status
    );

    let new_status: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(new_status, "expired");
}

#[tokio::test]
async fn test_sidebar_shows_my_requests_link() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("jit_sidebar_mr");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get("/")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(body.contains("My Requests"));
    assert!(body.contains("/sessions/my-requests"));
}

#[tokio::test]
async fn test_sidebar_shows_approval_badge_for_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("jit_sidebar_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_name = unique_name("jit_sidebar_requester");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    let asset_name = unique_name("jit_sidebar_asset");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    create_approval_request(&mut conn, user_id, asset_id).await;

    // Same aggregate as `apply_sidebar_rbac` (shared DB may already have other pending rows).
    let expected_pending: i64 = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::status.eq("pending"))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert!(
        expected_pending >= 1,
        "fixture should contribute at least one pending session"
    );

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(body.contains("Approvals"));

    let badge_anchor = "ml-auto inline-flex items-center rounded-full bg-vauban-600";
    let start = body
        .find(badge_anchor)
        .expect("pending approval badge in admin sidebar");
    let rel = &body[start..];
    let end_rel = rel.find("</span>").expect("badge span closes");
    let chunk = &rel[..end_rel];
    let open = chunk.rfind("\">").expect("opening span closes with \">");
    let badge_text = chunk[open + 2..].trim();
    assert_eq!(
        badge_text,
        expected_pending.to_string(),
        "sidebar badge should match pending session count in DB"
    );
}

#[tokio::test]
async fn test_approve_with_duration_override_updates_max_session_duration() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("jit_adm_dur_ovr");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_name = unique_name("jit_usr_dur_ovr");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    let asset_name = unique_name("jit_ast_dur_ovr");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    let session_uuid =
        create_approval_request_with_duration(&mut conn, user_id, asset_id, Some(3600)).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/sessions/approvals/{}/approve", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("duration_value", "2"),
            ("duration_unit", "hours"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "approve with override should redirect, got {}",
        status
    );

    let db_duration: Option<i32> = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select(proxy_sessions::max_session_duration)
            .first(&mut conn)
            .await
    );
    assert_eq!(
        db_duration,
        Some(7200),
        "max_session_duration should be overridden to 7200"
    );
}

#[tokio::test]
async fn test_approve_without_duration_keeps_default() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("jit_adm_dur_keep");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_name = unique_name("jit_usr_dur_keep");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    let asset_name = unique_name("jit_ast_dur_keep");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    let session_uuid =
        create_approval_request_with_duration(&mut conn, user_id, asset_id, Some(3600)).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/sessions/approvals/{}/approve", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "approve without override should redirect, got {}",
        status
    );

    let db_duration: Option<i32> = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select(proxy_sessions::max_session_duration)
            .first(&mut conn)
            .await
    );
    assert_eq!(
        db_duration,
        Some(3600),
        "max_session_duration should remain unchanged at 3600"
    );
}

#[tokio::test]
async fn test_approve_with_invalid_duration_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("jit_adm_dur_inv");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_name = unique_name("jit_usr_dur_inv");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    let asset_name = unique_name("jit_ast_dur_inv");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    let session_uuid =
        create_approval_request_with_duration(&mut conn, user_id, asset_id, Some(3600)).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/sessions/approvals/{}/approve", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("duration_value", "0"),
            ("duration_unit", "minutes"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "invalid duration should redirect with flash error, got {}",
        status
    );

    let db_status: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(
        db_status, "pending",
        "session should remain pending after invalid duration"
    );
}

#[tokio::test]
async fn test_approval_detail_shows_duration() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("jit_adm_dur_det");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_name = unique_name("jit_usr_dur_det");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    let asset_name = unique_name("jit_ast_dur_det");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    let _session_uuid =
        create_approval_request_with_duration(&mut conn, user_id, asset_id, Some(7200)).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get(&format!("/sessions/approvals/{}", _session_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("Session Duration"),
        "detail page should show Session Duration label"
    );
    assert!(
        body.contains("2h"),
        "detail page should show '2h' for 7200s duration"
    );
}

#[tokio::test]
async fn test_approval_list_shows_duration_field_for_pending() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("jit_adm_dur_fld");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_name = unique_name("jit_usr_dur_fld");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    let asset_name = unique_name("jit_ast_dur_fld");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    let _session_uuid =
        create_approval_request_with_duration(&mut conn, user_id, asset_id, Some(3600)).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/sessions/approvals")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("duration_value"),
        "approval list should contain duration_value input for pending requests"
    );
    assert!(
        body.contains("duration_unit"),
        "approval list should contain duration_unit select for pending requests"
    );
}

// =============================================================================
// Approval expiration & consumption tests (bugfix validation)
// =============================================================================

/// Approving a session with max_session_duration must set expires_at on the
/// approved row itself, bounding the approval validity window.
#[tokio::test]
async fn test_approve_sets_expires_at_on_approved_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("jit_adm_exp_set");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_name = unique_name("jit_usr_exp_set");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    let asset_name = unique_name("jit_ast_exp_set");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    let session_uuid =
        create_approval_request_with_duration(&mut conn, user_id, asset_id, Some(900)).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let _response = app
        .server
        .post(&format!("/sessions/approvals/{}/approve", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let (db_status, db_expires_at): (String, Option<chrono::DateTime<chrono::Utc>>) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select((proxy_sessions::status, proxy_sessions::expires_at))
            .first(&mut conn)
            .await
    );

    assert_eq!(db_status, "approved");
    assert!(
        db_expires_at.is_some(),
        "expires_at must be set on approved session with max_session_duration"
    );

    let expires = db_expires_at.unwrap();
    let now = chrono::Utc::now();
    let diff = (expires - now).num_seconds();
    assert!(
        diff > 0 && diff <= 900,
        "expires_at should be within 900s from now, got {} seconds",
        diff
    );
}

/// Approving a session with admin duration override must use the override
/// to compute expires_at (not the original max_session_duration).
#[tokio::test]
async fn test_approve_with_override_sets_correct_expires_at() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("jit_adm_ovr_exp");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_name = unique_name("jit_usr_ovr_exp");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    let asset_name = unique_name("jit_ast_ovr_exp");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    let session_uuid =
        create_approval_request_with_duration(&mut conn, user_id, asset_id, Some(900)).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let _response = app
        .server
        .post(&format!("/sessions/approvals/{}/approve", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("duration_value", "30"),
            ("duration_unit", "minutes"),
        ])
        .await;

    let (db_duration, db_expires_at): (Option<i32>, Option<chrono::DateTime<chrono::Utc>>) =
        unwrap_ok!(
            proxy_sessions::table
                .filter(proxy_sessions::uuid.eq(session_uuid))
                .select((
                    proxy_sessions::max_session_duration,
                    proxy_sessions::expires_at
                ))
                .first(&mut conn)
                .await
        );

    assert_eq!(db_duration, Some(1800), "duration should be 30 min = 1800s");
    assert!(db_expires_at.is_some(), "expires_at must be set");

    let diff = (db_expires_at.unwrap() - chrono::Utc::now()).num_seconds();
    assert!(
        diff > 0 && diff <= 1800,
        "expires_at should be within 1800s, got {}",
        diff
    );
}

/// Approving a session WITHOUT max_session_duration should leave expires_at
/// as NULL (unlimited approval validity).
#[tokio::test]
async fn test_approve_without_duration_leaves_expires_at_null() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("jit_adm_nodur_exp");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_name = unique_name("jit_usr_nodur_exp");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    let asset_name = unique_name("jit_ast_nodur_exp");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    let session_uuid =
        create_approval_request_with_duration(&mut conn, user_id, asset_id, None).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let _response = app
        .server
        .post(&format!("/sessions/approvals/{}/approve", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let db_expires_at: Option<chrono::DateTime<chrono::Utc>> = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select(proxy_sessions::expires_at)
            .first(&mut conn)
            .await
    );

    assert!(
        db_expires_at.is_none(),
        "expires_at should remain NULL for sessions without max_session_duration"
    );
}

/// An expired approved session must not be found when querying for valid
/// approvals. This tests the DB-level filtering that SSH/RDP handlers use.
#[tokio::test]
async fn test_expired_approved_session_not_found_by_status_query() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_name = unique_name("jit_usr_exp_nf");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    let admin_name = unique_name("jit_adm_exp_nf");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;

    let asset_name = unique_name("jit_ast_exp_nf");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;

    let _expired_uuid =
        create_expired_approved_session(&mut conn, user_id, asset_id).await;

    // Query like SSH/RDP handlers do: approved + not expired
    let now = chrono::Utc::now();
    let found: Option<Uuid> = proxy_sessions::table
        .filter(proxy_sessions::user_id.eq(user_id))
        .filter(proxy_sessions::asset_id.eq(asset_id))
        .filter(proxy_sessions::status.eq("approved"))
        .filter(
            proxy_sessions::expires_at
                .is_null()
                .or(proxy_sessions::expires_at.gt(now)),
        )
        .select(proxy_sessions::uuid)
        .first(&mut conn)
        .await
        .ok();

    assert!(
        found.is_none(),
        "expired approved session must NOT be returned by the handler query"
    );
}

/// A valid (non-expired) approved session must be found by the handler query.
#[tokio::test]
async fn test_valid_approved_session_found_by_status_query() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_name = unique_name("jit_usr_val_f");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    let admin_name = unique_name("jit_adm_val_f");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;

    let asset_name = unique_name("jit_ast_val_f");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;

    let approved_uuid =
        create_approved_session(&mut conn, user_id, asset_id, Some(900)).await;

    let now = chrono::Utc::now();
    let found: Option<Uuid> = proxy_sessions::table
        .filter(proxy_sessions::user_id.eq(user_id))
        .filter(proxy_sessions::asset_id.eq(asset_id))
        .filter(proxy_sessions::status.eq("approved"))
        .filter(
            proxy_sessions::expires_at
                .is_null()
                .or(proxy_sessions::expires_at.gt(now)),
        )
        .select(proxy_sessions::uuid)
        .first(&mut conn)
        .await
        .ok();

    assert_eq!(
        found,
        Some(approved_uuid),
        "valid approved session should be found"
    );
}

/// After consuming an approved session (status -> consumed), it must not
/// be found by subsequent queries. This proves one-time-use approval.
#[tokio::test]
async fn test_consumed_approved_session_not_reusable() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_name = unique_name("jit_usr_consume");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    let admin_name = unique_name("jit_adm_consume");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;

    let asset_name = unique_name("jit_ast_consume");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;

    let approved_uuid =
        create_approved_session(&mut conn, user_id, asset_id, Some(900)).await;

    // Simulate what the SSH/RDP handler does: consume the approval
    let now = chrono::Utc::now();
    unwrap_ok!(
        diesel::update(
            proxy_sessions::table
                .filter(proxy_sessions::uuid.eq(approved_uuid))
                .filter(proxy_sessions::status.eq("approved")),
        )
        .set((
            proxy_sessions::status.eq("consumed"),
            proxy_sessions::updated_at.eq(now),
        ))
        .execute(&mut conn)
        .await
    );

    // Verify the consumed session is no longer found
    let found: Option<Uuid> = proxy_sessions::table
        .filter(proxy_sessions::user_id.eq(user_id))
        .filter(proxy_sessions::asset_id.eq(asset_id))
        .filter(proxy_sessions::status.eq("approved"))
        .filter(
            proxy_sessions::expires_at
                .is_null()
                .or(proxy_sessions::expires_at.gt(now)),
        )
        .select(proxy_sessions::uuid)
        .first(&mut conn)
        .await
        .ok();

    assert!(
        found.is_none(),
        "consumed session must NOT be found - approval is single-use"
    );

    // Verify the original session is marked as consumed
    let db_status: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(approved_uuid))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(db_status, "consumed");
}

/// The cleanup task must expire approved sessions whose expires_at has passed.
#[tokio::test]
async fn test_cleanup_expires_stale_approved_sessions() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_name = unique_name("jit_usr_cleanup");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    let admin_name = unique_name("jit_adm_cleanup");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;

    let asset_name = unique_name("jit_ast_cleanup");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;

    let expired_uuid =
        create_expired_approved_session(&mut conn, user_id, asset_id).await;

    // Simulate what the cleanup task does
    let now = chrono::Utc::now();
    let expired_count = unwrap_ok!(
        diesel::update(
            proxy_sessions::table
                .filter(proxy_sessions::status.eq("approved"))
                .filter(proxy_sessions::expires_at.le(now)),
        )
        .set((
            proxy_sessions::status.eq("expired"),
            proxy_sessions::updated_at.eq(now),
        ))
        .execute(&mut conn)
        .await
    );

    assert!(
        expired_count >= 1,
        "cleanup should expire at least the stale approved session"
    );

    let db_status: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(expired_uuid))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(
        db_status, "expired",
        "stale approved session should be marked expired by cleanup"
    );
}

/// Having both an expired and a valid approved session for the same user/asset
/// must only return the valid one.
#[tokio::test]
async fn test_mixed_expired_and_valid_approvals_returns_valid_only() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_name = unique_name("jit_usr_mixed");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    let admin_name = unique_name("jit_adm_mixed");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;

    let asset_name = unique_name("jit_ast_mixed");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;

    // Create one expired and one valid
    let _expired_uuid =
        create_expired_approved_session(&mut conn, user_id, asset_id).await;
    let valid_uuid =
        create_approved_session(&mut conn, user_id, asset_id, Some(3600)).await;

    let now = chrono::Utc::now();
    let found: Option<Uuid> = proxy_sessions::table
        .filter(proxy_sessions::user_id.eq(user_id))
        .filter(proxy_sessions::asset_id.eq(asset_id))
        .filter(proxy_sessions::status.eq("approved"))
        .filter(
            proxy_sessions::expires_at
                .is_null()
                .or(proxy_sessions::expires_at.gt(now)),
        )
        .select(proxy_sessions::uuid)
        .first(&mut conn)
        .await
        .ok();

    assert_eq!(
        found,
        Some(valid_uuid),
        "only the valid (non-expired) approval should be returned"
    );
}

/// Approved sessions with NULL expires_at (legacy / unlimited) must still
/// be found by the handler query.
#[tokio::test]
async fn test_approved_session_without_expires_at_still_valid() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_name = unique_name("jit_usr_null_exp");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    let admin_name = unique_name("jit_adm_null_exp");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;

    let asset_name = unique_name("jit_ast_null_exp");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;

    // Create approved session with no duration (NULL expires_at)
    let approved_uuid =
        create_approved_session(&mut conn, user_id, asset_id, None).await;

    let now = chrono::Utc::now();
    let found: Option<Uuid> = proxy_sessions::table
        .filter(proxy_sessions::user_id.eq(user_id))
        .filter(proxy_sessions::asset_id.eq(asset_id))
        .filter(proxy_sessions::status.eq("approved"))
        .filter(
            proxy_sessions::expires_at
                .is_null()
                .or(proxy_sessions::expires_at.gt(now)),
        )
        .select(proxy_sessions::uuid)
        .first(&mut conn)
        .await
        .ok();

    assert_eq!(
        found,
        Some(approved_uuid),
        "approved session with NULL expires_at should still be valid"
    );
}

/// The cleanup task must NOT expire approved sessions with NULL expires_at.
#[tokio::test]
async fn test_cleanup_does_not_expire_unlimited_approved_sessions() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_name = unique_name("jit_usr_unlim_cl");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    let admin_name = unique_name("jit_adm_unlim_cl");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;

    let asset_name = unique_name("jit_ast_unlim_cl");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;

    let unlimited_uuid =
        create_approved_session(&mut conn, user_id, asset_id, None).await;

    // Run cleanup logic
    let now = chrono::Utc::now();
    let _expired_count = unwrap_ok!(
        diesel::update(
            proxy_sessions::table
                .filter(proxy_sessions::status.eq("approved"))
                .filter(proxy_sessions::expires_at.le(now)),
        )
        .set((
            proxy_sessions::status.eq("expired"),
            proxy_sessions::updated_at.eq(now),
        ))
        .execute(&mut conn)
        .await
    );

    // The unlimited session should NOT have been expired
    let db_status: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(unlimited_uuid))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(
        db_status, "approved",
        "unlimited session (NULL expires_at) must NOT be expired by cleanup"
    );
}
