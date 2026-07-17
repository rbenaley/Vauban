//! VAUBAN Web - Input-format validation E2E tests (July 2026 hardening).
//!
//! Real HTTP + real Postgres + real in-process vauban-access. For each
//! surface that persists a closed-format field (asset groups, secret
//! groups, vault secrets, users, assets), a forged POST with an
//! invalid value MUST:
//!
//!   1. bounce with a PRG redirect (302/303) carrying an error flash,
//!   2. write NOTHING to the database (zero created / modified rows).
//!
//! Then a valid POST must succeed and its redirect must resolve
//! (navigation-flow pattern from the QA skill).
//!
//! The last section proves the DB CHECK constraints hold even if every
//! applicative layer regresses: direct Diesel INSERTs with invalid
//! slug / color / status values must fail with a `DatabaseError`.

use axum::http::header::{self, COOKIE};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{
    create_admin_user, create_test_asset_group, create_test_secret_group, create_test_ssh_asset,
    create_test_user, create_test_vault_secret, unique_name,
};

/// Admin cookie header (JWT + CSRF double-submit).
fn auth_csrf_cookie(token: &str, csrf: &str) -> String {
    format!("access_token={token}; __vauban_csrf={csrf}")
}

/// Assert the response is a PRG bounce (302/303) that sets an error
/// flash cookie.
fn assert_flash_redirect(response: &axum_test::TestResponse, context: &str) {
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "{context}: expected PRG redirect, got {status}"
    );
    let sets_flash = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|c| c.starts_with("__vauban_flash=") && !c.starts_with("__vauban_flash=;"));
    assert!(
        sets_flash,
        "{context}: rejection must surface an error flash cookie"
    );
}

const INVALID_SLUG: &str = "Prod uction {BUG}";
const INVALID_COLOR: &str = "#zzz";
const INVALID_ICON: &str = "rocket";
const INVALID_STATUS: &str = "garbage";
const INVALID_HOSTNAME: &str = "host name.example.com";
const INVALID_USERNAME: &str = "bad user!";
const INVALID_EMAIL: &str = "not-an-email";

// =============================================================================
// Asset groups
// =============================================================================

async fn asset_group_count_by_name(conn: &mut diesel_async::AsyncPgConnection, name: &str) -> i64 {
    use vauban_web::schema::asset_groups;
    asset_groups::table
        .filter(asset_groups::name.eq(name))
        .count()
        .get_result(conn)
        .await
        .unwrap_or(0)
}

/// Forged asset-group creates with a bad slug, color or icon are all
/// rejected with zero DB writes; the valid POST then succeeds and its
/// redirect resolves.
#[tokio::test]
#[serial]
async fn asset_group_create_rejects_invalid_formats_with_zero_db_writes() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("fmt_ag_c")).await;
    let csrf = app.generate_csrf_token();

    let cases: &[(&str, &str, &str, &str)] = &[
        ("bad slug", INVALID_SLUG, "#3b82f6", "server"),
        ("bad color", "valid-slug-fmt", INVALID_COLOR, "server"),
        ("bad icon", "valid-slug-fmt", "#3b82f6", INVALID_ICON),
    ];
    for (label, slug, color, icon) in cases {
        let group_name = unique_name("fmt-ag-rejected");
        let response = app
            .server
            .post("/assets/manage/groups")
            .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
            .form(&[
                ("csrf_token", csrf.as_str()),
                ("name", group_name.as_str()),
                ("slug", slug),
                ("color", color),
                ("icon", icon),
            ])
            .await;
        assert_flash_redirect(&response, label);
        assert_eq!(
            asset_group_count_by_name(&mut conn, &group_name).await,
            0,
            "{label}: no asset group row may be created"
        );
    }

    // Valid POST: created + redirect resolves (navigation flow).
    let group_name = unique_name("fmt-ag-ok");
    let group_slug = unique_name("fmt-ag-ok-slug");
    let response = app
        .server
        .post("/assets/manage/groups")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", group_name.as_str()),
            ("slug", group_slug.as_str()),
            ("color", "#3B82F6"), // upper-case hex accepted, normalized
            ("icon", "server"),
        ])
        .await;
    let status = response.status_code().as_u16();
    assert!(status == 302 || status == 303, "valid create, got {status}");
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        location.starts_with("/assets/manage/groups/"),
        "must redirect to the group detail, got {location}"
    );
    let response = app
        .server
        .get(&location)
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);

    // The color was persisted lower-cased (canonical form).
    use vauban_web::schema::asset_groups;
    let color: String = asset_groups::table
        .filter(asset_groups::slug.eq(&group_slug))
        .select(asset_groups::color)
        .first(&mut conn)
        .await
        .expect("created group must exist");
    assert_eq!(color, "#3b82f6", "color must be persisted lower-cased");

    test_db::cleanup(&mut conn).await;
}

/// Forged asset-group updates with a bad slug leave the row untouched;
/// a valid update that keeps the slug works (control case).
#[tokio::test]
#[serial]
async fn asset_group_update_rejects_invalid_slug_and_keeps_row_intact() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("fmt_ag_u")).await;
    let csrf = app.generate_csrf_token();

    let group_name = unique_name("fmt-ag-upd");
    let group_uuid = create_test_asset_group(&mut conn, &group_name).await;

    use vauban_web::schema::asset_groups;
    let (orig_slug, orig_color): (String, String) = asset_groups::table
        .filter(asset_groups::uuid.eq(group_uuid))
        .select((asset_groups::slug, asset_groups::color))
        .first(&mut conn)
        .await
        .expect("fixture group must exist");

    let response = app
        .server
        .post(&format!("/assets/manage/groups/{group_uuid}/edit"))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", group_name.as_str()),
            ("slug", INVALID_SLUG),
            ("color", "#3b82f6"),
            ("icon", "server"),
        ])
        .await;
    assert_flash_redirect(&response, "asset group update with bad slug");

    let (slug_after, color_after): (String, String) = asset_groups::table
        .filter(asset_groups::uuid.eq(group_uuid))
        .select((asset_groups::slug, asset_groups::color))
        .first(&mut conn)
        .await
        .expect("group must still exist");
    assert_eq!(slug_after, orig_slug, "slug must be unchanged");
    assert_eq!(color_after, orig_color, "color must be unchanged");

    // Control: valid update keeping the same slug succeeds.
    let response = app
        .server
        .post(&format!("/assets/manage/groups/{group_uuid}/edit"))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", group_name.as_str()),
            ("slug", orig_slug.as_str()),
            ("color", "#112233"),
            ("icon", "database"),
        ])
        .await;
    let status = response.status_code().as_u16();
    assert!(status == 302 || status == 303, "valid update, got {status}");
    let color_now: String = asset_groups::table
        .filter(asset_groups::uuid.eq(group_uuid))
        .select(asset_groups::color)
        .first(&mut conn)
        .await
        .expect("group must still exist");
    assert_eq!(color_now, "#112233", "valid update must be persisted");

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Secret groups
// =============================================================================

/// Forged secret-group create/update with a bad slug: rejected, zero
/// DB writes.
#[tokio::test]
#[serial]
async fn secret_group_rejects_invalid_slug_with_zero_db_writes() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("fmt_sg")).await;
    let csrf = app.generate_csrf_token();

    // Create with invalid slug.
    let sg_name = unique_name("fmt-sg-rejected");
    let response = app
        .server
        .post("/vault/secrets/groups")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", sg_name.as_str()),
            ("slug", INVALID_SLUG),
        ])
        .await;
    assert_flash_redirect(&response, "secret group create with bad slug");

    use vauban_web::schema::secret_groups;
    let count: i64 = secret_groups::table
        .filter(secret_groups::name.eq(&sg_name))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    assert_eq!(count, 0, "no secret group row may be created");

    // Update an existing group with an invalid slug: row untouched.
    let (_sg_id, sg_uuid) = create_test_secret_group(&mut conn, "fmt-upd").await;
    let (orig_name, orig_slug): (String, String) = secret_groups::table
        .filter(secret_groups::uuid.eq(sg_uuid))
        .select((secret_groups::name, secret_groups::slug))
        .first(&mut conn)
        .await
        .expect("fixture secret group must exist");

    let response = app
        .server
        .post(&format!("/vault/secrets/groups/{sg_uuid}/edit"))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", orig_name.as_str()),
            ("slug", INVALID_SLUG),
        ])
        .await;
    assert_flash_redirect(&response, "secret group update with bad slug");

    let slug_after: String = secret_groups::table
        .filter(secret_groups::uuid.eq(sg_uuid))
        .select(secret_groups::slug)
        .first(&mut conn)
        .await
        .expect("secret group must still exist");
    assert_eq!(slug_after, orig_slug, "slug must be unchanged");

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Vault secrets (name follows the slug policy: M2M lookup key)
// =============================================================================

/// Forged vault-secret create/update with a non-slug name: rejected,
/// zero DB writes; a valid update keeping the name works (control).
#[tokio::test]
#[serial]
async fn vault_secret_rejects_invalid_name_with_zero_db_writes() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("fmt_vs")).await;
    let csrf = app.generate_csrf_token();

    // Create with an invalid (spaced / uppercase) name.
    let response = app
        .server
        .post("/vault/secrets")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", "My Secret {BUG}"),
            ("value", "some-value"),
        ])
        .await;
    assert_flash_redirect(&response, "vault secret create with bad name");

    use vauban_web::schema::vault_secrets;
    let count: i64 = vault_secrets::table
        .filter(vault_secrets::name.eq("My Secret {BUG}"))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    assert_eq!(count, 0, "no vault secret row may be created");

    // Update an existing secret with an invalid name: row untouched.
    let (_id, secret_uuid) = create_test_vault_secret(&mut conn, "fmtupd", "v0", true).await;
    let orig_name: String = vault_secrets::table
        .filter(vault_secrets::uuid.eq(secret_uuid))
        .select(vault_secrets::name)
        .first(&mut conn)
        .await
        .expect("fixture secret must exist");

    let response = app
        .server
        .post(&format!("/vault/secrets/{secret_uuid}/edit"))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", INVALID_SLUG),
            ("value", ""),
        ])
        .await;
    assert_flash_redirect(&response, "vault secret update with bad name");

    let name_after: String = vault_secrets::table
        .filter(vault_secrets::uuid.eq(secret_uuid))
        .select(vault_secrets::name)
        .first(&mut conn)
        .await
        .expect("secret must still exist");
    assert_eq!(name_after, orig_name, "name must be unchanged");

    // Control: valid update keeping the canonical name succeeds.
    let response = app
        .server
        .post(&format!("/vault/secrets/{secret_uuid}/edit"))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", orig_name.as_str()),
            ("description", "updated description"),
            ("value", ""),
            ("is_active", "true"),
        ])
        .await;
    let status = response.status_code().as_u16();
    assert!(status == 302 || status == 303, "valid update, got {status}");

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Users (username charset + email format on the WEB zone)
// =============================================================================

/// Forged user creates with a bad username or email: rejected, zero
/// DB writes; the valid POST then succeeds.
#[tokio::test]
#[serial]
async fn user_create_rejects_invalid_username_and_email_with_zero_db_writes() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("fmt_usr_c")).await;
    let csrf = app.generate_csrf_token();

    use vauban_web::schema::users;

    // Bad username (space + '!' survive normalization -> charset reject).
    let response = app
        .server
        .post("/accounts/users")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("username", INVALID_USERNAME),
            ("email", "valid@example.com"),
            ("password", "ValidPassword123!"),
        ])
        .await;
    assert_flash_redirect(&response, "user create with bad username");
    let count: i64 = users::table
        .filter(users::username.eq("bad user!"))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    assert_eq!(count, 0, "no user row may be created for a bad username");

    // Bad email.
    let bad_email_username = unique_name("fmt-bad-email");
    let response = app
        .server
        .post("/accounts/users")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("username", bad_email_username.as_str()),
            ("email", INVALID_EMAIL),
            ("password", "ValidPassword123!"),
        ])
        .await;
    assert_flash_redirect(&response, "user create with bad email");
    let count: i64 = users::table
        .filter(users::username.eq(&bad_email_username))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    assert_eq!(count, 0, "no user row may be created for a bad email");

    // Valid POST succeeds (username is normalized to lowercase).
    let valid_username = unique_name("Fmt-OK-User");
    let response = app
        .server
        .post("/accounts/users")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("username", valid_username.as_str()),
            ("email", "fmt-ok@example.com"),
            ("password", "ValidPassword123!"),
            ("is_active", "on"),
        ])
        .await;
    let status = response.status_code().as_u16();
    assert!(status == 302 || status == 303, "valid create, got {status}");
    let count: i64 = users::table
        .filter(users::username.eq(valid_username.to_lowercase()))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    assert_eq!(count, 1, "valid user must be created (normalized)");

    test_db::cleanup(&mut conn).await;
}

/// Forged user update with a bad email leaves the row untouched.
#[tokio::test]
#[serial]
async fn user_update_rejects_invalid_email_and_keeps_row_intact() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("fmt_usr_u")).await;
    let target = create_test_user(&mut conn, &app.auth_service, &unique_name("fmt_target")).await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/accounts/users/{}", target.user.uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("username", target.user.username.as_str()),
            ("email", INVALID_EMAIL),
        ])
        .await;
    assert_flash_redirect(&response, "user update with bad email");

    use vauban_web::schema::users;
    let email_after: String = users::table
        .filter(users::uuid.eq(target.user.uuid))
        .select(users::email)
        .first(&mut conn)
        .await
        .expect("target user must still exist");
    assert_eq!(
        email_after, target.user.email,
        "email must be unchanged after a rejected update"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Assets (status closed vocabulary + hostname charset)
// =============================================================================

/// Forged asset creates with an unknown status or a spaced hostname:
/// rejected, zero DB writes.
#[tokio::test]
#[serial]
async fn asset_create_rejects_invalid_status_and_hostname_with_zero_db_writes() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("fmt_ast_c")).await;
    let csrf = app.generate_csrf_token();

    use vauban_web::schema::assets;

    let cases: &[(&str, &str, &str)] = &[
        ("bad status", "host.example.com", INVALID_STATUS),
        ("bad hostname", INVALID_HOSTNAME, "online"),
    ];
    for (label, hostname, status) in cases {
        let asset_name = unique_name("fmt-asset-rejected");
        let response = app
            .server
            .post("/assets/manage/new")
            .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
            .form(&[
                ("csrf_token", csrf.as_str()),
                ("name", asset_name.as_str()),
                ("hostname", hostname),
                ("port", "22"),
                ("asset_type", "ssh"),
                ("status", status),
                ("ssh_username", "root"),
                ("ssh_auth_type", "password"),
                ("ssh_password", "secret"),
            ])
            .await;
        assert_flash_redirect(&response, label);
        let count: i64 = assets::table
            .filter(assets::name.eq(&asset_name))
            .count()
            .get_result(&mut conn)
            .await
            .unwrap_or(0);
        assert_eq!(count, 0, "{label}: no asset row may be created");
    }

    test_db::cleanup(&mut conn).await;
}

/// Forged asset update with an unknown status leaves the row intact.
#[tokio::test]
#[serial]
async fn asset_update_rejects_invalid_status_and_keeps_row_intact() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("fmt_ast_u")).await;
    let asset = create_test_ssh_asset(&mut conn, &unique_name("fmt-asset-upd")).await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/manage/{}/edit", asset.asset.uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", asset.asset.name.as_str()),
            ("hostname", asset.asset.hostname.as_str()),
            ("port", "22"),
            ("status", INVALID_STATUS),
        ])
        .await;
    assert_flash_redirect(&response, "asset update with bad status");

    use vauban_web::schema::assets;
    let status_after: String = assets::table
        .filter(assets::uuid.eq(asset.asset.uuid))
        .select(assets::status)
        .first(&mut conn)
        .await
        .expect("asset must still exist");
    assert_eq!(
        status_after, asset.asset.status,
        "status must be unchanged after a rejected update"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Control: system virtual groups stay readable and intact
// =============================================================================

/// The system-seeded virtual groups keep their double-underscore slugs
/// (exempted from the CHECK) and stay readable after the hardening.
#[tokio::test]
#[serial]
async fn system_virtual_group_slugs_stay_intact_and_readable() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    use vauban_web::schema::{asset_groups, secret_groups};

    let all_assets_slug: String = asset_groups::table
        .filter(asset_groups::kind.eq("all"))
        .select(asset_groups::slug)
        .first(&mut conn)
        .await
        .expect("the virtual 'All assets' group must exist");
    assert_eq!(all_assets_slug, "__all-assets__");

    let all_secrets_slug: String = secret_groups::table
        .filter(secret_groups::kind.eq("all"))
        .select(secret_groups::slug)
        .first(&mut conn)
        .await
        .expect("the virtual 'All secrets' group must exist");
    assert!(
        all_secrets_slug.starts_with("__"),
        "virtual secret group keeps its system slug, got {all_secrets_slug}"
    );

    // And the admin group list still renders.
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("fmt_virt")).await;
    let response = app
        .server
        .get("/assets/manage/groups")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// DB defense-in-depth: the CHECK constraints hold on direct INSERTs
// =============================================================================

/// Direct Diesel INSERTs bypassing every applicative layer must be
/// refused by the CHECK constraints (asset group slug + color, secret
/// group slug, vault secret name, asset status).
#[tokio::test]
#[serial]
async fn db_check_constraints_reject_direct_invalid_inserts() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    use vauban_web::schema::{asset_groups, assets, secret_groups, vault_secrets};

    // Asset group: invalid slug.
    let result = diesel::insert_into(asset_groups::table)
        .values((
            asset_groups::uuid.eq(Uuid::new_v4()),
            asset_groups::name.eq(unique_name("fmt-db-slug")),
            asset_groups::slug.eq(INVALID_SLUG),
            asset_groups::color.eq("#3b82f6"),
            asset_groups::icon.eq("server"),
        ))
        .execute(&mut conn)
        .await;
    assert!(
        matches!(result, Err(diesel::result::Error::DatabaseError(_, _))),
        "asset_groups_slug_format_chk must reject an invalid slug, got {result:?}"
    );

    // Asset group: invalid color.
    let result = diesel::insert_into(asset_groups::table)
        .values((
            asset_groups::uuid.eq(Uuid::new_v4()),
            asset_groups::name.eq(unique_name("fmt-db-color")),
            asset_groups::slug.eq(unique_name("fmt-db-color-slug")),
            asset_groups::color.eq(INVALID_COLOR),
            asset_groups::icon.eq("server"),
        ))
        .execute(&mut conn)
        .await;
    assert!(
        matches!(result, Err(diesel::result::Error::DatabaseError(_, _))),
        "asset_groups_color_chk must reject an invalid color, got {result:?}"
    );

    // Secret group: invalid slug.
    let result = diesel::insert_into(secret_groups::table)
        .values((
            secret_groups::uuid.eq(Uuid::new_v4()),
            secret_groups::name.eq(unique_name("fmt-db-sg")),
            secret_groups::slug.eq(INVALID_SLUG),
            secret_groups::kind.eq("static"),
        ))
        .execute(&mut conn)
        .await;
    assert!(
        matches!(result, Err(diesel::result::Error::DatabaseError(_, _))),
        "secret_groups_slug_format_chk must reject an invalid slug, got {result:?}"
    );

    // Vault secret: invalid name.
    let result = diesel::insert_into(vault_secrets::table)
        .values((
            vault_secrets::uuid.eq(Uuid::new_v4()),
            vault_secrets::name.eq("My Secret {BUG}"),
            vault_secrets::ciphertext.eq("v1:abc"),
            vault_secrets::is_active.eq(true),
        ))
        .execute(&mut conn)
        .await;
    assert!(
        matches!(result, Err(diesel::result::Error::DatabaseError(_, _))),
        "vault_secrets_name_format_chk must reject an invalid name, got {result:?}"
    );

    // Asset: invalid status.
    let result = diesel::insert_into(assets::table)
        .values((
            assets::uuid.eq(Uuid::new_v4()),
            assets::name.eq(unique_name("fmt-db-status")),
            assets::hostname.eq("db-check.example.com"),
            assets::port.eq(22),
            assets::asset_type.eq("ssh"),
            assets::status.eq(INVALID_STATUS),
            assets::connection_username.eq("root"),
            assets::connection_config.eq(serde_json::json!({})),
        ))
        .execute(&mut conn)
        .await;
    assert!(
        matches!(result, Err(diesel::result::Error::DatabaseError(_, _))),
        "assets_status_chk must reject an unknown status, got {result:?}"
    );

    test_db::cleanup(&mut conn).await;
}
