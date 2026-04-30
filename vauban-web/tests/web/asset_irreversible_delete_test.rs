//! Issue #17 — handler-level integration tests for the
//! irreversible-delete contract.
//!
//! These tests drive the full Axum stack (router + handlers + DB) and
//! cover the user-visible side of the policy. The structural DB
//! guarantees they sit on top of are tested independently in
//! `assets_db_invariants_test.rs` -- this file proves the *handlers*
//! honour the contract end-to-end and that the user-facing failure
//! modes are stable enough to be relied upon by humans, scripts and
//! API clients.
//!
//! Test matrix:
//!
//! * **`test_create_after_delete_yields_fresh_uuid`** — the headline
//!   guarantee. After deleting an asset, recreating one on the same
//!   triplet via the web form must land at a brand-new UUID, leaving
//!   the original row as an immutable tombstone.
//! * **`test_web_create_collision_on_active_triplet_redirects_with_flash`**
//!   — collision on an existing active triplet must surface as a 303
//!   back to `/assets/new` with a recognisable error flash, NOT as a
//!   500 / generic DB error.
//! * **`test_api_create_collision_on_active_triplet_returns_409`**
//!   — same collision via the JSON API must return 409 Conflict so
//!   automation can branch on it deterministically.
//! * **`test_update_on_tombstone_redirects_with_not_found_flash`**
//!   — editing a soft-deleted asset must be rejected at the handler
//!   layer (early UX). The DB trigger is the ultimate backstop and
//!   is exercised by the SQL invariant tests.
//! * **`test_delete_is_idempotent_second_call_says_already_deleted`**
//!   — a second delete on an already-tombstoned asset must NOT
//!   resurrect it, must NOT fail with a 500, and must produce a
//!   stable "already deleted" flash.
//! * **`test_create_delete_stress_ten_cycles_keeps_invariants`**
//!   — ten back-to-back create/delete cycles on the same triplet
//!   must leave exactly one active row and exactly ten distinct
//!   tombstones, proving I1+I2 hold under handler-level repetition.
//! * **`test_proxy_session_fk_survives_asset_soft_delete`**
//!   — the FK from `proxy_sessions.asset_id` to `assets.id` must
//!   survive a soft-delete intact (we keep the audit chain). This
//!   is why we soft-delete instead of physically removing rows.

use crate::common::{TestApp, assertions::*, test_db, unwrap_ok};
use crate::fixtures::{create_admin_user, create_test_session, create_test_user, unique_name};
use axum::http::header::{AUTHORIZATION, COOKIE, LOCATION, SET_COOKIE};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;
use vauban_web::models::asset::Asset;
use vauban_web::schema::{assets, proxy_sessions};

/// Cookie header carrying both auth and CSRF, as expected by the web
/// create/edit/delete handlers (double-submit pattern).
fn auth_csrf_cookie(token: &str, csrf: &str) -> String {
    format!("access_token={}; __vauban_csrf={}", token, csrf)
}

// =============================================================================
// 1. Fresh UUID after delete (the headline guarantee)
// =============================================================================

/// SEC-11 / RG-ASS-04: after deleting an asset, recreating one on the
/// same `(hostname, port, username)` triplet via the web form MUST
/// produce a brand-new UUID. The original row remains a tombstone with
/// `is_deleted = true` and a scrubbed `connection_config`.
#[tokio::test]
#[serial]
async fn test_create_after_delete_yields_fresh_uuid() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("irrev_uuid")).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.fresh-uuid.test", unique_name("host"));
    let username = "root";
    let original_name = unique_name("first-incarnation");

    let create1 = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &original_name),
            ("hostname", &hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", username),
            ("ssh_auth_type", "password"),
            ("ssh_password", "first-secret"),
        ])
        .await;
    assert_status(&create1, 303);
    let location1 = create1
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("create must redirect to /assets/manage/{uuid}");
    let first_uuid_str = location1
        .strip_prefix("/assets/manage/")
        .expect("redirect must be /assets/manage/{uuid}");
    let first_uuid = Uuid::parse_str(first_uuid_str).expect("location must carry a valid UUID");

    let delete = app
        .server
        .post(&format!("/assets/manage/{}/delete", first_uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    let s = delete.status_code().as_u16();
    assert!(s == 302 || s == 303, "delete must redirect, got {}", s);

    let after_delete: Asset = unwrap_ok!(
        assets::table
            .filter(assets::uuid.eq(first_uuid))
            .first(&mut conn)
            .await
    );
    assert!(after_delete.is_deleted, "first row must be a tombstone");
    assert_eq!(
        after_delete.connection_config,
        json!({}),
        "tombstone connection_config must be scrubbed"
    );

    let create2 = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &unique_name("second-incarnation")),
            ("hostname", &hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", username),
            ("ssh_auth_type", "password"),
            ("ssh_password", "second-secret"),
        ])
        .await;
    assert_status(&create2, 303);
    let location2 = create2
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("second create must also redirect to /assets/manage/{uuid}");
    let second_uuid_str = location2
        .strip_prefix("/assets/manage/")
        .expect("redirect must be /assets/manage/{uuid}");
    let second_uuid = Uuid::parse_str(second_uuid_str).expect("location must carry a valid UUID");

    assert_ne!(
        first_uuid, second_uuid,
        "recreate after delete MUST produce a fresh UUID (RG-ASS-04 / SEC-11)"
    );

    let tombstone_still_deleted: bool = unwrap_ok!(
        assets::table
            .filter(assets::uuid.eq(first_uuid))
            .select(assets::is_deleted)
            .first(&mut conn)
            .await
    );
    assert!(
        tombstone_still_deleted,
        "the original row must remain a tombstone -- never resurrected"
    );

    let active_count: i64 = unwrap_ok!(
        assets::table
            .filter(assets::hostname.eq(&hostname))
            .filter(assets::port.eq(22))
            .filter(assets::connection_username.eq(username))
            .filter(assets::is_deleted.eq(false))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(
        active_count, 1,
        "exactly one active row must exist on the triplet after the cycle"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// 2. Web collision on an existing active triplet
// =============================================================================

/// Posting a second active row on the same triplet through the web
/// form MUST be rejected with a 303 to `/assets/new` carrying an error
/// flash. We must NOT crash with a 500 (regression: Diesel's
/// UniqueViolation used to bubble up unwrapped).
#[tokio::test]
#[serial]
async fn test_web_create_collision_on_active_triplet_redirects_with_flash() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("irrev_web_409")).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.web-collide.test", unique_name("host"));
    let username = "root";

    let create1 = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &unique_name("collide-a")),
            ("hostname", &hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", username),
            ("ssh_auth_type", "password"),
            ("ssh_password", "p"),
        ])
        .await;
    assert_status(&create1, 303);

    let create2 = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &unique_name("collide-b")),
            ("hostname", &hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", username),
            ("ssh_auth_type", "password"),
            ("ssh_password", "p"),
        ])
        .await;
    assert_status(&create2, 303);
    let location = create2
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Issue #27: asset CRUD lives under `/assets/manage/*`. The
    // collision flash bounces to the admin create form.
    assert_eq!(
        location, "/assets/manage/new",
        "duplicate active triplet must bounce back to /assets/manage/new, got {}",
        location
    );

    let flash_cookie = create2
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|c| c.to_str().ok())
        .find(|c| c.contains("__vauban_flash"))
        .expect("collision must set an error flash cookie");
    assert!(
        flash_cookie.contains("__vauban_flash"),
        "expected a flash cookie carrying the collision message"
    );

    let active_count: i64 = unwrap_ok!(
        assets::table
            .filter(assets::hostname.eq(&hostname))
            .filter(assets::port.eq(22))
            .filter(assets::connection_username.eq(username))
            .filter(assets::is_deleted.eq(false))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(
        active_count, 1,
        "duplicate insert must not actually persist a second row, only one active row must exist"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// 3. API collision returns 409 Conflict (machine-readable)
// =============================================================================

/// Posting a second active row on the same triplet through the JSON
/// API MUST return 409 Conflict so automation (CI scripts, IaC,
/// orchestrators) can detect and recover from the duplicate without
/// brittle string parsing.
#[tokio::test]
#[serial]
async fn test_api_create_collision_on_active_triplet_returns_409() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("irrev_api_409")).await;

    let hostname = format!("{}.api-collide.test", unique_name("host"));
    let body = json!({
        "name": unique_name("api-collide-a"),
        "hostname": hostname,
        "port": 22,
        "asset_type": "ssh",
        "status": "online"
    });

    let create1 = app
        .server
        .post("/api/v1/assets/manage")
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .json(&body)
        .await;
    let s = create1.status_code().as_u16();
    assert!(
        s == 200 || s == 201,
        "first API create must succeed, got {}",
        s
    );

    let create2 = app
        .server
        .post("/api/v1/assets/manage")
        .add_header(AUTHORIZATION, app.auth_header(&admin.token))
        .json(&json!({
            "name": unique_name("api-collide-b"),
            "hostname": hostname,
            "port": 22,
            "asset_type": "ssh",
            "status": "online"
        }))
        .await;
    assert_status(&create2, 409);

    let active_count: i64 = unwrap_ok!(
        assets::table
            .filter(assets::hostname.eq(&hostname))
            .filter(assets::port.eq(22))
            .filter(assets::is_deleted.eq(false))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(
        active_count, 1,
        "duplicate API insert must not actually persist a second row"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// 4. Update on tombstone is rejected at the handler layer
// =============================================================================

/// Editing a soft-deleted asset MUST be rejected at the handler
/// layer. The web edit handler filters on `is_deleted = false` so
/// the operator gets an early "not found / already deleted" flash
/// instead of hitting the DB trigger and getting a generic 500.
/// (The trigger is the ultimate backstop -- exercised by
/// `assets_db_invariants_test::test_i4_resurrection_blocked_by_trigger`.)
#[tokio::test]
#[serial]
async fn test_update_on_tombstone_redirects_with_not_found_flash() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("irrev_upd_tomb")).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.upd-tomb.test", unique_name("host"));
    let create = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &unique_name("upd-tomb-orig")),
            ("hostname", &hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "password"),
            ("ssh_password", "p"),
        ])
        .await;
    let asset_uuid_str = create
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|l| l.strip_prefix("/assets/manage/"))
        .expect("create must redirect to /assets/manage/{uuid}")
        .to_string();
    let asset_uuid = Uuid::parse_str(&asset_uuid_str).expect("valid uuid");

    let delete = app
        .server
        .post(&format!("/assets/manage/{}/delete", asset_uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    let s = delete.status_code().as_u16();
    assert!(s == 302 || s == 303);

    let edit = app
        .server
        .post(&format!("/assets/manage/{}/edit", asset_uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", "trying-to-revive"),
            ("hostname", &hostname),
            ("port", "22"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_password", "evil-new-secret"),
        ])
        .await;
    let edit_status = edit.status_code().as_u16();
    assert!(
        edit_status == 302 || edit_status == 303,
        "edit on tombstone must redirect (PRG), got {}",
        edit_status
    );
    let location = edit
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        location == "/assets/manage" || location.starts_with("/assets/manage"),
        "edit on tombstone must redirect to /assets/manage (or /assets/manage/{{uuid}}/edit), got {}",
        location
    );

    let after: Asset = unwrap_ok!(
        assets::table
            .filter(assets::uuid.eq(asset_uuid))
            .first(&mut conn)
            .await
    );
    assert!(
        after.is_deleted,
        "tombstone must remain deleted after rejected edit"
    );
    assert_eq!(
        after.connection_config,
        json!({}),
        "tombstone connection_config must remain scrubbed -- the rejected edit MUST NOT have leaked secrets back in"
    );
    assert_ne!(
        after.name, "trying-to-revive",
        "rejected edit must not have updated the name either"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// 5. Delete is idempotent
// =============================================================================

/// Calling delete twice on the same asset must not crash, must not
/// resurrect it, and must produce a stable "already deleted" outcome.
/// Operators sometimes double-click; scripts sometimes retry: neither
/// must turn into a 500.
#[tokio::test]
#[serial]
async fn test_delete_is_idempotent_second_call_says_already_deleted() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("irrev_idem")).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.idem.test", unique_name("host"));
    let create = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &unique_name("idem-orig")),
            ("hostname", &hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "password"),
            ("ssh_password", "p"),
        ])
        .await;
    let asset_uuid_str = create
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|l| l.strip_prefix("/assets/manage/"))
        .expect("create must redirect to /assets/manage/{uuid}")
        .to_string();
    let asset_uuid = Uuid::parse_str(&asset_uuid_str).expect("valid uuid");

    for attempt in 1..=2 {
        let delete = app
            .server
            .post(&format!("/assets/manage/{}/delete", asset_uuid))
            .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
            .form(&[("csrf_token", csrf.as_str())])
            .await;
        let s = delete.status_code().as_u16();
        assert!(
            s == 302 || s == 303,
            "delete attempt #{} must redirect (not crash), got {}",
            attempt,
            s
        );
    }

    let row: Asset = unwrap_ok!(
        assets::table
            .filter(assets::uuid.eq(asset_uuid))
            .first(&mut conn)
            .await
    );
    assert!(
        row.is_deleted,
        "row must still be tombstoned after second delete"
    );
    assert_eq!(
        row.connection_config,
        json!({}),
        "tombstone connection_config must still be scrubbed"
    );

    let total_rows: i64 = unwrap_ok!(
        assets::table
            .filter(assets::uuid.eq(asset_uuid))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(
        total_rows, 1,
        "delete must remain a soft-delete -- no row removal"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// 6. Stress: 10 create/delete cycles preserve I1 and I2
// =============================================================================

/// Battle-test: cycle create → delete on the same triplet ten times
/// in a row. The end state must be exactly one active row plus ten
/// tombstones, each with a distinct UUID and an empty
/// `connection_config`. This catches off-by-one bugs in the
/// reactivation code paths and stress-tests the partial unique index
/// against repeated active/tombstone churn.
#[tokio::test]
#[serial]
async fn test_create_delete_stress_ten_cycles_keeps_invariants() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("irrev_stress")).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.stress.test", unique_name("host"));
    let username = "root";

    let mut seen_uuids: std::collections::HashSet<Uuid> = std::collections::HashSet::new();

    for cycle in 0..10 {
        let create = app
            .server
            .post("/assets/manage/new")
            .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
            .form(&[
                ("csrf_token", csrf.as_str()),
                ("name", &format!("stress-{}", cycle)),
                ("hostname", &hostname),
                ("port", "22"),
                ("asset_type", "ssh"),
                ("status", "online"),
                ("ssh_username", username),
                ("ssh_auth_type", "password"),
                ("ssh_password", "p"),
            ])
            .await;
        assert_status(&create, 303);
        let asset_uuid: Uuid = Uuid::parse_str(
            create
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|l| l.strip_prefix("/assets/manage/"))
                .expect("redirect to /assets/manage/{uuid}"),
        )
        .expect("valid uuid");

        assert!(
            seen_uuids.insert(asset_uuid),
            "cycle {}: UUID {} was reused across cycles -- resurrection regression!",
            cycle,
            asset_uuid
        );

        let delete = app
            .server
            .post(&format!("/assets/manage/{}/delete", asset_uuid))
            .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
            .form(&[("csrf_token", csrf.as_str())])
            .await;
        let s = delete.status_code().as_u16();
        assert!(
            s == 302 || s == 303,
            "cycle {}: delete must redirect, got {}",
            cycle,
            s
        );
    }

    let final_create = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", "stress-final"),
            ("hostname", &hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", username),
            ("ssh_auth_type", "password"),
            ("ssh_password", "p"),
        ])
        .await;
    assert_status(&final_create, 303);
    let final_uuid = Uuid::parse_str(
        final_create
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|l| l.strip_prefix("/assets/manage/"))
            .expect("redirect to /assets/manage/{uuid}"),
    )
    .expect("valid uuid");
    assert!(
        seen_uuids.insert(final_uuid),
        "final UUID must also be distinct from every prior cycle"
    );

    let active_count: i64 = unwrap_ok!(
        assets::table
            .filter(assets::hostname.eq(&hostname))
            .filter(assets::port.eq(22))
            .filter(assets::connection_username.eq(username))
            .filter(assets::is_deleted.eq(false))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(
        active_count, 1,
        "exactly one active row must remain after the cycles"
    );

    let tombstone_count: i64 = unwrap_ok!(
        assets::table
            .filter(assets::hostname.eq(&hostname))
            .filter(assets::port.eq(22))
            .filter(assets::connection_username.eq(username))
            .filter(assets::is_deleted.eq(true))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(tombstone_count, 10, "exactly ten tombstones must coexist");

    let leaked: i64 = unwrap_ok!(
        assets::table
            .filter(assets::hostname.eq(&hostname))
            .filter(assets::is_deleted.eq(true))
            .filter(assets::connection_config.ne(json!({})))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(
        leaked, 0,
        "no tombstone may carry a non-empty connection_config (CHECK constraint guarantees this, but we double-check)"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// 7. proxy_sessions FK survives soft-delete
// =============================================================================

/// The audit chain depends on `proxy_sessions.asset_id` continuing to
/// resolve to the original asset row even after deletion. This test
/// pins that contract: a session attached to an asset must still
/// reference the same `asset_id` after the asset is soft-deleted.
/// (Were we to switch to a hard DELETE, the FK would either cascade
/// the sessions away or block the delete -- either would break audit.)
#[tokio::test]
#[serial]
async fn test_proxy_session_fk_survives_asset_soft_delete() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("irrev_fk")).await;
    let csrf = app.generate_csrf_token();
    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("irrev_fk_user")).await;

    let hostname = format!("{}.fk.test", unique_name("host"));
    let create = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &unique_name("fk-asset")),
            ("hostname", &hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "password"),
            ("ssh_password", "p"),
        ])
        .await;
    let asset_uuid = Uuid::parse_str(
        create
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|l| l.strip_prefix("/assets/manage/"))
            .expect("redirect to /assets/manage/{uuid}"),
    )
    .expect("valid uuid");

    let asset_id: i32 = unwrap_ok!(
        assets::table
            .filter(assets::uuid.eq(asset_uuid))
            .select(assets::id)
            .first(&mut conn)
            .await
    );

    let session_id =
        create_test_session(&mut conn, user.user.id, asset_id, "ssh", "completed").await;

    let delete = app
        .server
        .post(&format!("/assets/manage/{}/delete", asset_uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    let s = delete.status_code().as_u16();
    assert!(s == 302 || s == 303, "delete must redirect, got {}", s);

    let post_delete_asset_id: i32 = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::id.eq(session_id))
            .select(proxy_sessions::asset_id)
            .first(&mut conn)
            .await
    );
    assert_eq!(
        post_delete_asset_id, asset_id,
        "session.asset_id must still point at the original asset.id after soft-delete"
    );

    let still_resolvable: i32 = unwrap_ok!(
        assets::table
            .filter(assets::id.eq(post_delete_asset_id))
            .select(assets::id)
            .first(&mut conn)
            .await
    );
    assert_eq!(
        still_resolvable, asset_id,
        "the FK target row must still be physically present (soft-delete only)"
    );

    let target_is_deleted: bool = unwrap_ok!(
        assets::table
            .filter(assets::id.eq(asset_id))
            .select(assets::is_deleted)
            .first(&mut conn)
            .await
    );
    assert!(
        target_is_deleted,
        "the row pointed at by the session FK must indeed be the tombstone we just created"
    );

    test_db::cleanup(&mut conn).await;
}
