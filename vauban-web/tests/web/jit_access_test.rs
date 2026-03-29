/// VAUBAN Web - JIT Access Tests.
///
/// Tests for Just-In-Time access request, approval, and rejection flows.

use crate::common::{TestApp, assertions::assert_status, unwrap_ok};
use crate::fixtures::{
    create_approval_request, create_approval_request_with_duration, create_simple_admin_user,
    create_simple_ssh_asset, create_simple_user, unique_name,
};
use axum::http::header::COOKIE;
use diesel::{ExpressionMethods, QueryDsl};
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
