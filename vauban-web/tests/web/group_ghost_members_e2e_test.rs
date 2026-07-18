//! E2E pin for the ghost-members bug (July 2026).
//!
//! Production symptom: after soft-deleting users, `/accounts/groups`
//! kept showing "2 members" while the detail page showed an empty
//! member list, and the group could not be deleted anymore (the delete
//! guard counted the raw `user_groups` rows, which survive a
//! soft-delete because the FK cascade only fires on physical DELETE).
//!
//! These tests drive the full HTTP surface: create a group and users,
//! add memberships, soft-delete the users through the real
//! `POST /accounts/users/{uuid}/delete` handler (CSRF + step-up TOTP),
//! then assert the list count, the detail page and the group deletion
//! all agree.

use axum::http::header::{COOKIE, LOCATION};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serial_test::serial;
use uuid::Uuid;

use crate::common::TestApp;
use crate::fixtures::{
    TestUserWithMfa, add_user_to_vauban_group, create_admin_user_with_mfa, create_test_user,
    create_test_vauban_group, current_totp_for, unique_name,
};

/// Read back the (internally uniquified) name of a test vauban group.
async fn group_name(conn: &mut AsyncPgConnection, group_uuid: &Uuid) -> String {
    use vauban_web::schema::vauban_groups;
    vauban_groups::table
        .filter(vauban_groups::uuid.eq(group_uuid))
        .select(vauban_groups::name)
        .first(conn)
        .await
        .expect("group name")
}

/// Soft-delete a user through the real web handler (CSRF + step-up
/// TOTP), asserting the PRG redirect back to the user list.
async fn delete_user_via_web(app: &TestApp, operator: &TestUserWithMfa, target_uuid: &Uuid) {
    let csrf = app.generate_csrf_token();
    let totp = current_totp_for(&operator.mfa_secret);
    let response = app
        .server
        .post(&format!("/accounts/users/{}/delete", target_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", operator.token, csrf),
        )
        .form(&[("csrf_token", csrf.as_str()), ("totp_code", totp.as_str())])
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "user delete must PRG-redirect, got {status}"
    );
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("delete redirect must carry Location");
    assert_eq!(
        location, "/accounts/users",
        "a successful delete redirects to the user list (an error would \
         bounce back to the detail page)"
    );
}

/// The step-up TOTP proof is single-use per operator per 30 s window;
/// clear the replay marker so the same operator can perform a second
/// deletion within the same test without waiting a full window.
async fn reset_totp_replay(conn: &mut AsyncPgConnection, operator_id: i32) {
    use vauban_web::schema::users;
    diesel::update(users::table.filter(users::id.eq(operator_id)))
        .set(users::last_totp_used_window.eq(None::<i64>))
        .execute(conn)
        .await
        .expect("reset totp replay window");
}

/// GET the group list filtered on the group's unique name so the body
/// contains exactly one member-count badge (ours).
async fn group_list_filtered(app: &TestApp, token: &str, name: &str) -> String {
    let response = app
        .server
        .get(&format!("/accounts/groups?search={name}"))
        .add_header(COOKIE, format!("access_token={token}"))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    response.text()
}

async fn group_detail(app: &TestApp, token: &str, group_uuid: &Uuid) -> String {
    let response = app
        .server
        .get(&format!("/accounts/groups/{group_uuid}"))
        .add_header(COOKIE, format!("access_token={token}"))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    response.text()
}

/// Full scenario: 2 members, both soft-deleted through the web =>
/// list shows "0 members", detail shows the empty state, and the group
/// delete SUCCEEDS (the "undeletable group" pin).
#[tokio::test]
#[serial]
async fn deleted_users_disappear_from_group_count_and_group_is_deletable() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let operator =
        create_admin_user_with_mfa(&mut conn, &app.auth_service, &unique_name("test_ghost_op"))
            .await;
    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("test-ghost-full")).await;
    let name = group_name(&mut conn, &group_uuid).await;

    let u1 = create_test_user(&mut conn, &app.auth_service, &unique_name("test_ghost_u1")).await;
    let u2 = create_test_user(&mut conn, &app.auth_service, &unique_name("test_ghost_u2")).await;
    add_user_to_vauban_group(&mut conn, u1.user.id, &group_uuid).await;
    add_user_to_vauban_group(&mut conn, u2.user.id, &group_uuid).await;

    let body = group_list_filtered(app, &operator.token, &name).await;
    assert!(
        body.contains("2 members"),
        "list must show 2 members before any deletion"
    );

    delete_user_via_web(app, &operator, &u1.user.uuid).await;
    reset_totp_replay(&mut conn, operator.user.id).await;
    delete_user_via_web(app, &operator, &u2.user.uuid).await;

    // The production bug: this kept saying "2 members".
    let body = group_list_filtered(app, &operator.token, &name).await;
    assert!(
        body.contains("0 members"),
        "list must show 0 members once every member is soft-deleted"
    );
    assert!(
        !body.contains("2 members"),
        "the ghost count '2 members' must be gone"
    );

    let detail = group_detail(app, &operator.token, &group_uuid).await;
    assert!(
        detail.contains("0 members in this group."),
        "detail header must agree with the list count"
    );
    assert!(
        detail.contains("No members"),
        "detail must render the empty state"
    );

    // The group was undeletable pre-fix (guard counted raw rows).
    let csrf = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/accounts/groups/{group_uuid}/delete"))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", operator.token, csrf),
        )
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "group delete must redirect, got {status}"
    );

    use vauban_web::schema::vauban_groups;
    let still_there: Option<i32> = vauban_groups::table
        .filter(vauban_groups::uuid.eq(group_uuid))
        .select(vauban_groups::id)
        .first(&mut conn)
        .await
        .optional()
        .expect("query group");
    assert!(
        still_there.is_none(),
        "a group whose members were all soft-deleted must be deletable \
         (undeletable-group bug pinned)"
    );
}

/// Partial scenario (production "Administrators" case): 1 of 2 members
/// soft-deleted => "1 member" in the list, and the detail page lists
/// exactly the active user.
#[tokio::test]
#[serial]
async fn partially_deleted_group_shows_only_active_member() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let operator =
        create_admin_user_with_mfa(&mut conn, &app.auth_service, &unique_name("test_ghost_op2"))
            .await;
    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("test-ghost-part")).await;
    let name = group_name(&mut conn, &group_uuid).await;

    let kept = create_test_user(
        &mut conn,
        &app.auth_service,
        &unique_name("test_ghost_keep"),
    )
    .await;
    let doomed = create_test_user(
        &mut conn,
        &app.auth_service,
        &unique_name("test_ghost_gone"),
    )
    .await;
    add_user_to_vauban_group(&mut conn, kept.user.id, &group_uuid).await;
    add_user_to_vauban_group(&mut conn, doomed.user.id, &group_uuid).await;

    delete_user_via_web(app, &operator, &doomed.user.uuid).await;

    let body = group_list_filtered(app, &operator.token, &name).await;
    assert!(
        body.contains("1 member"),
        "list must show exactly 1 member after 1 of 2 was soft-deleted"
    );
    assert!(
        !body.contains("2 members"),
        "the raw count '2 members' must be gone"
    );

    let detail = group_detail(app, &operator.token, &group_uuid).await;
    assert!(
        detail.contains("1 member in this group."),
        "detail header must show the visible count"
    );
    assert!(
        detail.contains(&kept.user.username),
        "the active member must still be listed"
    );
    // The soft-delete suffixes the username (tombstone), so any
    // occurrence of the original name would mean the deleted member's
    // row is still rendered.
    assert!(
        !detail.contains(&doomed.user.username),
        "the soft-deleted member must not be rendered on the detail page"
    );
}
