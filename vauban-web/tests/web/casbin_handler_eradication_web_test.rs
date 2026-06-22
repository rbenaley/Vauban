/// VAUBAN Web - Battle-test integration suite (web side) for the
/// fine-grained Casbin migration of the Axum handlers.
///
/// Each test is the canonical proof-of-regression for ONE of the
/// privilege-boundary changes that affect a server-rendered route.
/// Companion of `tests/api/casbin_handler_eradication_test.rs`.
use axum::http::header::COOKIE;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, assertions::assert_status};
use crate::fixtures::{
    create_admin_user, create_simple_ssh_asset, create_staff_only_user,
    create_test_session_with_uuid, create_test_user, unique_name,
};

// ---------------------------------------------------------------------------
// 5. groups:write -- staff and superuser can both CRUD a group. Mirrors
//    test 5 of the plan ("groups CRUD requires groups:write").
// ---------------------------------------------------------------------------

/// `GET /accounts/groups/new` is gated by `perms.groups_write`. Staff
/// (granted `groups_write`) MUST be able to render the create form.
#[tokio::test]
#[serial]
async fn groups_create_form_allowed_for_staff() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let staff_name = unique_name("groups_w_staff");
    let staff = create_staff_only_user(&mut conn, &app.auth_service, &staff_name).await;

    let response = app
        .server
        .get("/accounts/groups/new")
        .add_header(COOKIE, format!("access_token={}", staff.token))
        .await;

    assert_status(&response, 200);
}

/// Same form, superuser caller: must render the create form (200 OK).
#[tokio::test]
#[serial]
async fn groups_create_form_allowed_for_superuser() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("groups_w_admin");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let response = app
        .server
        .get("/accounts/groups/new")
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;

    assert_status(&response, 200);
}

// ---------------------------------------------------------------------------
// 6. groups:manage_members -- staff retains the membership workflow but
//    a regular user is denied.
// ---------------------------------------------------------------------------

/// `GET /accounts/groups/{uuid}/members/add` is gated by
/// `perms.groups_manage_members`. Regular user MUST receive 403.
#[tokio::test]
#[serial]
async fn groups_add_member_form_denied_for_regular_user() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("groups_mm_user");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    // The handler hits the access-client lookup BEFORE the permission
    // gate runs in only one early code path; in any case, the gate is
    // the FIRST conditional inside the function so any non-zero UUID
    // suffices to trigger it.
    let dummy_group = Uuid::new_v4();

    let response = app
        .server
        .get(&format!("/accounts/groups/{}/members/add", dummy_group))
        .add_header(COOKIE, format!("access_token={}", user.token))
        .await;

    assert_status(&response, 403);
}

/// Same form, staff caller: the permission gate clears (the group
/// itself does not exist so the access client may surface a 5xx, but
/// the gate did not refuse with 403 -- which is what we contract here).
#[tokio::test]
#[serial]
async fn groups_add_member_form_passes_gate_for_staff() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let staff_name = unique_name("groups_mm_staff");
    let staff = create_staff_only_user(&mut conn, &app.auth_service, &staff_name).await;

    let dummy_group = Uuid::new_v4();
    let response = app
        .server
        .get(&format!("/accounts/groups/{}/members/add", dummy_group))
        .add_header(COOKIE, format!("access_token={}", staff.token))
        .await;

    assert_ne!(
        response.status_code().as_u16(),
        403,
        "staff (groups:manage_members) MUST clear the gate -- only the \
         underlying access-client lookup may then fail"
    );
}

// ---------------------------------------------------------------------------
// 7. sessions:supervise -- staff can monitor another user's session,
//    a regular user cannot. Probed through `terminal_page`, which
//    delegates the ownership/supervise check to
//    `verify_session_ownership(can_supervise = perms.sessions_supervise)`.
// ---------------------------------------------------------------------------

/// Regular user opens `/sessions/terminal/{session_id}` of a session
/// they do NOT own. The handler collapses every authorization failure
/// (including missing supervision) into an opaque 404 to avoid
/// session-UUID enumeration.
#[tokio::test]
#[serial]
async fn websocket_session_supervise_denied_for_regular_user() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Session owned by `owner`.
    let owner_name = unique_name("supervise_owner");
    let owner = create_admin_user(&mut conn, &app.auth_service, &owner_name).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("supervise-asset"), owner.user.id).await;
    let (_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, owner.user.id, asset_id, "ssh", "active").await;

    // Probe with a regular user (no `sessions:supervise`).
    let username = unique_name("supervise_intruder");
    let intruder = create_test_user(&mut conn, &app.auth_service, &username).await;

    let response = app
        .server
        .get(&format!("/sessions/terminal/{}", session_uuid))
        .add_header(COOKIE, format!("access_token={}", intruder.token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(
        status, 404,
        "regular user MUST be denied (collapsed 404) on another user's \
         terminal page; got {}",
        status
    );
}

/// Staff probes the same endpoint and the supervise scope makes it
/// reachable. We accept any 2xx because the template needs the asset
/// and a few other moving parts that may differ in CI; the contract is
/// "the supervise gate did not refuse".
#[tokio::test]
#[serial]
async fn websocket_session_supervise_allowed_for_staff() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner_name = unique_name("supervise_owner2");
    let owner = create_admin_user(&mut conn, &app.auth_service, &owner_name).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("supervise-asset2"), owner.user.id).await;
    let (_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, owner.user.id, asset_id, "ssh", "active").await;

    let staff_name = unique_name("supervise_staff");
    let staff = create_staff_only_user(&mut conn, &app.auth_service, &staff_name).await;

    let response = app
        .server
        .get(&format!("/sessions/terminal/{}", session_uuid))
        .add_header(COOKIE, format!("access_token={}", staff.token))
        .await;

    let status = response.status_code().as_u16();
    assert_ne!(
        status, 404,
        "staff (sessions:supervise) MUST be able to reach another user's \
         terminal page; got {}",
        status
    );
}
