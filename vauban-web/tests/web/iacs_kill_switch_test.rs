//! IACS kill-switch (`[industrial].enabled = false`) regression tests.
//!
//! The IACS module exposes a global kill-switch in `vauban.conf`. The
//! contract -- documented in [`crate::auth::permissions`] and pinned
//! by the `check_iacs_kill_switch.sh` lint -- is that the switch is
//! enforced in EXACTLY one place: the `PermissionContext::load`
//! constructor folds `state.config.industrial.enabled` into every
//! `iacs_*` flag. No handler or template is allowed to read the
//! config flag directly; they all consume the pre-computed
//! `PermissionContext`.
//!
//! These tests verify that the central enforcement seam actually
//! fires:
//!
//! 1. With the default test config (`industrial.enabled = true`)
//!    every IACS flag respects the Casbin policy.
//! 2. When the test clones the AppState and flips the flag to
//!    `false`, every `iacs_*` flag collapses to `false` for every
//!    subject (user / staff / superuser) -- regardless of what
//!    Casbin says.
//!
//! Path-level coverage (`/iacs/*` 404, `/iacs/admin/*` 403) is the
//! sibling test `iacs_test::iacs_admin_routes_block_regular_user_with_403`;
//! we do not duplicate it here because the global `TestApp` runs with
//! the kill-switch ON, and the production enforcement contract is
//! the one PermissionContext seam.

use crate::common::TestApp;
use crate::fixtures::{create_simple_admin_user, create_simple_user, unique_name};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;
use vauban_web::auth::PermissionContext;
use vauban_web::middleware::auth::AuthUser;

async fn get_user_uuid(conn: &mut AsyncPgConnection, user_id: i32) -> Uuid {
    use vauban_web::schema::users;
    users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(conn)
        .await
        .expect("user uuid")
}

/// Build a minimal `AuthUser` matching the role flags. The kill-switch
/// test does not need a JWT round-trip: it bypasses the middleware
/// and calls `PermissionContext::load` directly with a hand-crafted
/// AppState.
fn auth_user_for(uuid: Uuid, username: &str, is_superuser: bool, is_staff: bool) -> AuthUser {
    AuthUser {
        uuid: uuid.to_string(),
        username: username.to_string(),
        mfa_verified: true,
        is_superuser,
        is_staff,
    }
}

// ===================================================================
// Default state (`industrial.enabled = true`): policy is honored
// ===================================================================

/// With the kill-switch ON, `role:user` retains `iacs_request` /
/// `iacs_read` (granted by `default_policy.csv`) and a superuser
/// retains `iacs_manage` (covered by `role:superuser, *, *`).
/// This is the baseline the next test inverts.
#[tokio::test]
async fn iacs_perms_follow_casbin_when_kill_switch_is_on() {
    let app = TestApp::spawn().await;
    assert!(
        app.app_state.config.industrial.enabled,
        "test fixture must default to industrial.enabled = true \
         (changing this default would silently break every kill-switch test)"
    );

    let mut conn = app.get_conn().await;

    let user_name = unique_name("iacs_ks_on_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let user = auth_user_for(user_uuid, &user_name, false, false);

    let admin_name = unique_name("iacs_ks_on_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let admin = auth_user_for(admin_uuid, &admin_name, true, true);

    let user_perms = PermissionContext::load(&app.app_state, &user).await;
    assert!(
        user_perms.iacs_request,
        "role:user must hold iacs_request when kill-switch is on"
    );
    assert!(
        user_perms.iacs_read,
        "role:user must hold iacs_read when kill-switch is on"
    );
    assert!(
        !user_perms.iacs_manage,
        "role:user must NOT hold iacs_manage even when kill-switch is on"
    );

    let admin_perms = PermissionContext::load(&app.app_state, &admin).await;
    assert!(
        admin_perms.iacs_manage,
        "role:superuser must hold iacs_manage when kill-switch is on"
    );
}

// ===================================================================
// Kill-switch = false collapses every iacs_* flag
// ===================================================================

/// With `industrial.enabled = false`, every IACS permission collapses
/// to `false` regardless of subject. This is the canonical seam: any
/// future regression that adds a parallel enforcement path (a handler
/// or template reading `state.config.industrial.enabled` on its own)
/// would silently bypass this single fold; the
/// `check_iacs_kill_switch.sh` lint pins the source-level invariant
/// while this test pins the runtime invariant.
#[tokio::test]
async fn iacs_kill_switch_off_collapses_every_subject_to_no_access() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_name = unique_name("iacs_ks_off_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let user = auth_user_for(user_uuid, &user_name, false, false);

    let admin_name = unique_name("iacs_ks_off_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let admin = auth_user_for(admin_uuid, &admin_name, true, true);

    let mut killed_state = app.app_state.clone();
    killed_state.config.industrial.enabled = false;

    let user_perms = PermissionContext::load(&killed_state, &user).await;
    assert!(
        !user_perms.iacs_request,
        "kill-switch must drop iacs_request to false (was {:?})",
        user_perms.iacs_request
    );
    assert!(
        !user_perms.iacs_read,
        "kill-switch must drop iacs_read to false"
    );
    assert!(
        !user_perms.iacs_manage,
        "kill-switch must drop iacs_manage to false"
    );
    assert!(
        !user_perms.assets_connect_iacs,
        "kill-switch must drop assets_connect_iacs to false"
    );

    // Non-IACS permissions stay untouched -- the kill-switch is
    // surgical, never collateral.
    assert!(
        user_perms.profile_read,
        "kill-switch must NOT degrade profile_read for role:user"
    );

    let admin_perms = PermissionContext::load(&killed_state, &admin).await;
    assert!(
        !admin_perms.iacs_request,
        "kill-switch must drop iacs_request to false even for superuser"
    );
    assert!(
        !admin_perms.iacs_read,
        "kill-switch must drop iacs_read to false even for superuser"
    );
    assert!(
        !admin_perms.iacs_manage,
        "kill-switch must drop iacs_manage to false even for superuser"
    );

    // Sanity: the superuser still holds non-IACS admin powers.
    assert!(
        admin_perms.users_write,
        "kill-switch must NOT degrade users_write for role:superuser"
    );
    assert!(
        admin_perms.admin_view,
        "kill-switch must NOT degrade admin_view for role:superuser"
    );
}
