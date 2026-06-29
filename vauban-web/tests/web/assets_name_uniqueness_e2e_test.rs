//! End-to-end coverage for the relaxed asset uniqueness model
//! (migration `20260625000000_assets_relax_uniqueness_to_name`).
//!
//! Before the migration, `assets` were unique on the
//! `(hostname, port, connection_username)` triplet, which made it
//! impossible to register several accounts on the same host or to keep
//! two distinct catalog entries pointing at the same target. The new
//! contract enforces uniqueness on the asset `name` among ACTIVE rows
//! only (`idx_assets_name_active`).
//!
//! These tests drive the full Axum stack (router + handlers + DB) so
//! they pin the operator-visible behaviour end-to-end:
//!
//! * **multi-account, same host** (SSH and RDP) — several active assets
//!   on the exact same `(hostname, port, username)` succeed as long as
//!   their names differ, and all show up in the admin list.
//! * **name collision is global** — a name already taken by an active
//!   asset is rejected even across protocols (SSH vs RDP) and across
//!   hosts.
//! * **edit-into-collision** — renaming an asset onto another active
//!   asset's name is rejected and leaves the row untouched (no partial
//!   write, no secret leak).
//! * **deleted names are reusable** — once an asset is soft-deleted its
//!   name frees up for a brand-new active asset (fresh UUID; the
//!   tombstone is excluded from the unique index).

use crate::common::{TestApp, assertions::*, test_db, unwrap_ok};
use crate::fixtures::{create_admin_user, unique_name};
use axum::http::header::{AUTHORIZATION, COOKIE, LOCATION, SET_COOKIE};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;
use vauban_web::schema::assets;

/// Cookie header carrying both auth and CSRF, as expected by the web
/// create/edit/delete handlers (double-submit pattern).
fn auth_csrf_cookie(token: &str, csrf: &str) -> String {
    format!("access_token={}; __vauban_csrf={}", token, csrf)
}

/// Pull the freshly-allocated asset UUID out of a successful create
/// redirect (`Location: /assets/manage/{uuid}`). Panics with a helpful
/// message if the create bounced back to the form instead.
fn uuid_from_create(resp: &axum_test::TestResponse, what: &str) -> Uuid {
    let location = resp
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let raw = location.strip_prefix("/assets/manage/").unwrap_or_else(|| {
        panic!(
            "create '{}' was expected to succeed and redirect to \
             /assets/manage/{{uuid}}, but Location was '{}'",
            what, location
        )
    });
    Uuid::parse_str(raw).expect("create redirect must carry a valid UUID")
}

// =============================================================================
// 1. Multiple accounts on the same host (SSH)
// =============================================================================

/// Three SSH assets on the SAME `(hostname, port)` with three DIFFERENT
/// accounts (`root`, `deploy`, `audit`) and three distinct names must
/// all be created, and all must surface in the admin list. This is the
/// canonical "multiple accounts per host" scenario.
#[tokio::test]
#[serial]
async fn test_e2e_multiple_ssh_accounts_same_host_all_created() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("name_uniq_ssh")).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.multi-ssh.test", unique_name("host"));
    let names: Vec<String> = ["root", "deploy", "audit"]
        .iter()
        .map(|acct| unique_name(&format!("ssh-{acct}")))
        .collect();

    for (acct, name) in ["root", "deploy", "audit"].iter().zip(names.iter()) {
        let resp = app
            .server
            .post("/assets/manage/new")
            .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
            .form(&[
                ("csrf_token", csrf.as_str()),
                ("name", name.as_str()),
                ("hostname", &hostname),
                ("port", "22"),
                ("asset_type", "ssh"),
                ("status", "online"),
                ("ssh_username", acct),
                ("ssh_auth_type", "password"),
                ("ssh_password", "p"),
            ])
            .await;
        assert_status(&resp, 303);
        let _ = uuid_from_create(&resp, name);
    }

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
        active_count, 3,
        "three SSH accounts on the same host:port must coexist"
    );

    // All three names must render on the admin manage list. Scope the
    // query to our hostname (ilike match on name OR hostname) so the
    // assertion is independent of global pagination.
    let list = app
        .server
        .get(&format!("/assets/manage?search={hostname}"))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&list, 200);
    let body = list.text();
    for name in &names {
        assert!(
            body.contains(name.as_str()),
            "admin list must show '{}'",
            name
        );
    }

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// 2. Multiple accounts on the same host (RDP)
// =============================================================================

/// RDP counterpart: two RDP catalog entries on the same
/// `(hostname, port, account)` with distinct names both succeed. Pins
/// that the relaxed model is protocol-agnostic.
#[tokio::test]
#[serial]
async fn test_e2e_multiple_rdp_entries_same_host_all_created() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("name_uniq_rdp")).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.multi-rdp.test", unique_name("host"));

    let mut uuids = std::collections::HashSet::new();
    for label in ["rdp-primary", "rdp-failover"] {
        let name = unique_name(label);
        let resp = app
            .server
            .post("/assets/manage/new")
            .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
            .form(&[
                ("csrf_token", csrf.as_str()),
                ("name", name.as_str()),
                ("hostname", &hostname),
                ("port", "3389"),
                ("asset_type", "rdp"),
                ("status", "online"),
                ("ssh_username", "Administrator"),
                ("ssh_password", "p"),
            ])
            .await;
        assert_status(&resp, 303);
        assert!(uuids.insert(uuid_from_create(&resp, &name)));
    }

    let active_count: i64 = unwrap_ok!(
        assets::table
            .filter(assets::hostname.eq(&hostname))
            .filter(assets::port.eq(3389))
            .filter(assets::connection_username.eq("Administrator"))
            .filter(assets::is_deleted.eq(false))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(
        active_count, 2,
        "two RDP entries on the same host/account must coexist under distinct names"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// 3. Name uniqueness is global (cross-protocol, cross-host)
// =============================================================================

/// A name already used by an active SSH asset must be refused for a new
/// RDP asset on a completely different host. The name -- not the
/// (host, port, type) -- is the uniqueness key.
#[tokio::test]
#[serial]
async fn test_e2e_name_collision_across_protocols_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("name_uniq_cross"),
    )
    .await;
    let csrf = app.generate_csrf_token();

    let shared_name = unique_name("cross-proto");

    let ssh = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &shared_name),
            (
                "hostname",
                &format!("{}.cross-ssh.test", unique_name("host")),
            ),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "password"),
            ("ssh_password", "p"),
        ])
        .await;
    assert_status(&ssh, 303);
    let _ = uuid_from_create(&ssh, &shared_name);

    let rdp = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &shared_name),
            (
                "hostname",
                &format!("{}.cross-rdp.test", unique_name("host")),
            ),
            ("port", "3389"),
            ("asset_type", "rdp"),
            ("status", "online"),
            ("ssh_username", "Administrator"),
            ("ssh_password", "p"),
        ])
        .await;
    assert_status(&rdp, 303);
    let location = rdp
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        location, "/assets/manage/new",
        "RDP create on an already-used name must bounce to /assets/manage/new, got {}",
        location
    );
    let flash = rdp
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|c| c.to_str().ok())
        .find(|c| c.contains("__vauban_flash"));
    assert!(flash.is_some(), "name collision must set an error flash");

    let count_for_name: i64 = unwrap_ok!(
        assets::table
            .filter(assets::name.eq(&shared_name))
            .filter(assets::is_deleted.eq(false))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(
        count_for_name, 1,
        "only the first asset may hold the shared name"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// 4. Editing an asset onto another active name is rejected
// =============================================================================

/// Renaming asset B onto asset A's active name must be refused and must
/// leave B untouched (its original name preserved). Pins the
/// UniqueViolation arm of `update_asset_web`.
#[tokio::test]
#[serial]
async fn test_e2e_edit_into_existing_name_is_rejected_and_preserves_row() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("name_uniq_edit")).await;
    let csrf = app.generate_csrf_token();

    let name_a = unique_name("edit-A");
    let name_b = unique_name("edit-B");
    let host_a = format!("{}.edit-a.test", unique_name("host"));
    let host_b = format!("{}.edit-b.test", unique_name("host"));

    let create_a = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &name_a),
            ("hostname", &host_a),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "password"),
            ("ssh_password", "p"),
        ])
        .await;
    assert_status(&create_a, 303);
    let _ = uuid_from_create(&create_a, &name_a);

    let create_b = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &name_b),
            ("hostname", &host_b),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "password"),
            ("ssh_password", "p"),
        ])
        .await;
    assert_status(&create_b, 303);
    let uuid_b = uuid_from_create(&create_b, &name_b);

    // Try to rename B -> A (collision). Keep B's existing password
    // (empty = keep) so the only thing that can fail is the name.
    let edit = app
        .server
        .post(&format!("/assets/manage/{}/edit", uuid_b))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &name_a),
            ("hostname", &host_b),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "password"),
            ("ssh_password", ""),
        ])
        .await;
    let s = edit.status_code().as_u16();
    assert!(
        s == 302 || s == 303,
        "edit-into-collision must redirect (PRG), got {}",
        s
    );

    // B keeps its own name; A is still the sole holder of name_a.
    let b_name_now: String = unwrap_ok!(
        assets::table
            .filter(assets::uuid.eq(uuid_b))
            .select(assets::name)
            .first(&mut conn)
            .await
    );
    assert_eq!(
        b_name_now, name_b,
        "rejected rename must leave B's name unchanged"
    );

    let holders_of_a: i64 = unwrap_ok!(
        assets::table
            .filter(assets::name.eq(&name_a))
            .filter(assets::is_deleted.eq(false))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(holders_of_a, 1, "name_a must still have exactly one holder");

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// 5. A soft-deleted name is reusable by a fresh asset
// =============================================================================

/// After soft-deleting an asset, its `name` must free up: a brand-new
/// active asset may reuse it and gets a fresh UUID. The tombstone is
/// excluded from `idx_assets_name_active`.
#[tokio::test]
#[serial]
async fn test_e2e_deleted_name_can_be_reused_with_fresh_uuid() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("name_uniq_reuse"),
    )
    .await;
    let csrf = app.generate_csrf_token();

    let name = unique_name("reusable");
    let hostname = format!("{}.reuse.test", unique_name("host"));

    let create1 = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &name),
            ("hostname", &hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "password"),
            ("ssh_password", "p"),
        ])
        .await;
    assert_status(&create1, 303);
    let uuid1 = uuid_from_create(&create1, &name);

    let delete = app
        .server
        .post(&format!("/assets/manage/{}/delete", uuid1))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    let ds = delete.status_code().as_u16();
    assert!(ds == 302 || ds == 303, "delete must redirect, got {}", ds);

    let create2 = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &name),
            ("hostname", &hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "password"),
            ("ssh_password", "p"),
        ])
        .await;
    assert_status(&create2, 303);
    let uuid2 = uuid_from_create(&create2, &name);

    assert_ne!(
        uuid1, uuid2,
        "reusing a deleted name must allocate a fresh UUID, never resurrect the tombstone"
    );

    let active_holders: i64 = unwrap_ok!(
        assets::table
            .filter(assets::name.eq(&name))
            .filter(assets::is_deleted.eq(false))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(
        active_holders, 1,
        "exactly one active row may hold the name"
    );

    let tombstones: i64 = unwrap_ok!(
        assets::table
            .filter(assets::name.eq(&name))
            .filter(assets::is_deleted.eq(true))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(tombstones, 1, "the original row must remain a tombstone");

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// 6. API: multiple accounts succeed, name collision is 409
// =============================================================================

/// JSON API parity: two assets on the same host with distinct names
/// both succeed (200/201); a third reusing an existing active name
/// returns 409 Conflict.
#[tokio::test]
#[serial]
async fn test_e2e_api_multi_account_ok_then_name_conflict_409() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("name_uniq_api")).await;

    let hostname = format!("{}.api-multi.test", unique_name("host"));
    let name_first = unique_name("api-first");
    let name_second = unique_name("api-second");

    for name in [&name_first, &name_second] {
        let resp = app
            .server
            .post("/api/v1/assets/manage")
            .add_header(AUTHORIZATION, app.api_key_header(&admin.api_key))
            .json(&json!({
                "name": name,
                "hostname": hostname,
                "port": 22,
                "asset_type": "ssh",
                "status": "online"
            }))
            .await;
        let s = resp.status_code().as_u16();
        assert!(
            s == 200 || s == 201,
            "API create '{}' on shared host must succeed, got {}",
            name,
            s
        );
    }

    // Reusing name_first must be a 409 even on a different host.
    let conflict = app
        .server
        .post("/api/v1/assets/manage")
        .add_header(AUTHORIZATION, app.api_key_header(&admin.api_key))
        .json(&json!({
            "name": name_first,
            "hostname": format!("{}.api-other.test", unique_name("host")),
            "port": 22,
            "asset_type": "ssh",
            "status": "online"
        }))
        .await;
    assert_status(&conflict, 409);

    let active_on_host: i64 = unwrap_ok!(
        assets::table
            .filter(assets::hostname.eq(&hostname))
            .filter(assets::is_deleted.eq(false))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(
        active_on_host, 2,
        "both distinct-name API creates on the shared host must have persisted"
    );

    test_db::cleanup(&mut conn).await;
}
