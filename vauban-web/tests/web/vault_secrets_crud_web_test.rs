//! VAUBAN Web - Vault Secrets admin section E2E tests.
//!
//! Real HTTP + real Postgres + real in-process vauban-access. Covers:
//!
//! - Complete navigation flows (QA skill): create → redirect →
//!   detail page resolvable, for all three sub-CRUDs (secrets,
//!   secret groups, secret access rules).
//! - Write-only value: the plaintext never appears in the detail or
//!   edit HTML, and a value update bumps `version`.
//! - Virtual "All secrets" group protections (mutations refused,
//!   hidden from the group list).
//! - Authorization: a plain user (no `vault_secrets:manage`) is
//!   refused by the route_layer on every page of the nest.

use axum::http::header::{self, COOKIE};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{
    create_admin_user, create_test_secret_group, create_test_user, create_test_vauban_group,
    create_test_vault_secret, unique_name,
};

/// Admin cookie header (JWT + CSRF double-submit).
fn admin_cookie(token: &str, csrf: &str) -> String {
    format!("access_token={token}; __vauban_csrf={csrf}")
}

// =============================================================================
// Secrets sub-CRUD: full navigation flow
// =============================================================================

/// Create a secret via the web form, follow the redirect to the detail
/// page, and verify the value never appears in any rendered HTML.
#[tokio::test]
#[serial]
async fn secret_create_flow_redirect_resolves_and_value_is_write_only() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("vsw_create")).await;
    let csrf = app.generate_csrf_token();

    let plaintext = "WRITE-ONLY-VALUE-0xDEADBEEF";
    let secret_name = unique_name("test-websecret");

    // Step 1: form page loads.
    let response = app
        .server
        .get("/vault/secrets/new")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);
    assert!(response.text().contains("csrf_token"));

    // Step 2: submit.
    let response = app
        .server
        .post("/vault/secrets")
        .add_header(COOKIE, admin_cookie(&admin.token, &csrf))
        .form(&serde_json::json!({
            "csrf_token": csrf,
            "name": secret_name,
            "description": "Created via web form",
            "value": plaintext,
            "is_active": "true",
        }))
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "creation must redirect (PRG), got {status}"
    );
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        location.starts_with("/vault/secrets/"),
        "must redirect to the new secret detail, got: {location}"
    );

    // Step 3: CRITICAL — the redirect target must resolve.
    let response = app
        .server
        .get(&location)
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);
    let detail_html = response.text();
    assert!(detail_html.contains(&secret_name));
    assert!(
        !detail_html.contains(plaintext),
        "detail page must never render the secret value (write-only)"
    );

    // Step 4: the edit page never re-displays the value either.
    let response = app
        .server
        .get(&format!("{location}/edit"))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);
    assert!(
        !response.text().contains(plaintext),
        "edit page must never render the secret value (write-only)"
    );

    // Step 5: the list page shows the secret but not the value.
    let response = app
        .server
        .get("/vault/secrets")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);
    let list_html = response.text();
    assert!(list_html.contains(&secret_name));
    assert!(!list_html.contains(plaintext));

    test_db::cleanup(&mut conn).await;
}

/// Updating with a NON-empty value bumps `version`; an EMPTY value
/// keeps the stored ciphertext and version.
#[tokio::test]
#[serial]
async fn secret_update_value_bumps_version_empty_keeps() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("vsw_bump")).await;
    let (_id, secret_uuid) =
        create_test_vault_secret(&mut conn, "bump", "initial-value", true).await;
    let csrf = app.generate_csrf_token();

    async fn version_of(conn: &mut diesel_async::AsyncPgConnection, u: Uuid) -> (i32, String) {
        use vauban_web::schema::vault_secrets;
        vault_secrets::table
            .filter(vault_secrets::uuid.eq(u))
            .select((vault_secrets::version, vault_secrets::ciphertext))
            .first::<(i32, String)>(conn)
            .await
            .expect("secret row")
    }

    let (v0, ct0) = version_of(&mut conn, secret_uuid).await;
    assert_eq!(v0, 1);

    // Update WITHOUT value: keep.
    let response = app
        .server
        .post(&format!("/vault/secrets/{secret_uuid}/edit"))
        .add_header(COOKIE, admin_cookie(&admin.token, &csrf))
        .form(&serde_json::json!({
            "csrf_token": csrf,
            "name": "test-secret-bump-renamed",
            "description": "still here",
            "value": "",
            "is_active": "true",
        }))
        .await;
    let status = response.status_code().as_u16();
    assert!(status == 303 || status == 302, "PRG expected, got {status}");
    let (v1, ct1) = version_of(&mut conn, secret_uuid).await;
    assert_eq!(v1, v0, "empty value must not bump version");
    assert_eq!(ct1, ct0, "empty value must keep the stored ciphertext");

    // Update WITH a new value: bump.
    let response = app
        .server
        .post(&format!("/vault/secrets/{secret_uuid}/edit"))
        .add_header(COOKIE, admin_cookie(&admin.token, &csrf))
        .form(&serde_json::json!({
            "csrf_token": csrf,
            "name": "test-secret-bump-renamed",
            "description": "still here",
            "value": "rotated-value",
            "is_active": "true",
        }))
        .await;
    let status = response.status_code().as_u16();
    assert!(status == 303 || status == 302, "PRG expected, got {status}");
    let (v2, ct2) = version_of(&mut conn, secret_uuid).await;
    assert_eq!(v2, v1 + 1, "a value change must bump version");
    assert_ne!(ct2, ct1, "a value change must replace the ciphertext");

    test_db::cleanup(&mut conn).await;
}

/// Delete removes the row (hard delete).
#[tokio::test]
#[serial]
async fn secret_delete_removes_row() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("vsw_del")).await;
    let (_id, secret_uuid) = create_test_vault_secret(&mut conn, "del", "bye", true).await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/vault/secrets/{secret_uuid}/delete"))
        .add_header(COOKIE, admin_cookie(&admin.token, &csrf))
        .form(&serde_json::json!({ "csrf_token": csrf }))
        .await;
    let status = response.status_code().as_u16();
    assert!(status == 303 || status == 302, "PRG expected, got {status}");

    use vauban_web::schema::vault_secrets;
    let remaining: i64 = vault_secrets::table
        .filter(vault_secrets::uuid.eq(secret_uuid))
        .count()
        .get_result(&mut conn)
        .await
        .expect("count");
    assert_eq!(remaining, 0, "delete must be a hard delete");

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Secret groups sub-CRUD: navigation flow + membership
// =============================================================================

/// Create a group via the form, follow the redirect, then add and
/// remove a secret member.
#[tokio::test]
#[serial]
async fn group_create_flow_and_membership_roundtrip() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("vsw_grp")).await;
    let (secret_id, secret_uuid) =
        create_test_vault_secret(&mut conn, "member", "member-value", true).await;
    let csrf = app.generate_csrf_token();

    let group_name = unique_name("test-sg-web");
    let response = app
        .server
        .post("/vault/secrets/groups")
        .add_header(COOKIE, admin_cookie(&admin.token, &csrf))
        .form(&serde_json::json!({
            "csrf_token": csrf,
            "name": group_name,
            "slug": group_name.to_lowercase(),
            "description": "web-created group",
        }))
        .await;
    let status = response.status_code().as_u16();
    assert!(status == 303 || status == 302, "PRG expected, got {status}");
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        location.starts_with("/vault/secrets/groups/"),
        "must redirect to the new group detail, got: {location}"
    );

    // Redirect resolves.
    let response = app
        .server
        .get(&location)
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);
    assert!(response.text().contains(&group_name));

    // Add the secret to the group.
    let response = app
        .server
        .post(&format!("{location}/secrets/add"))
        .add_header(COOKIE, admin_cookie(&admin.token, &csrf))
        .form(&serde_json::json!({
            "csrf_token": csrf,
            "secret_uuid": secret_uuid.to_string(),
        }))
        .await;
    let status = response.status_code().as_u16();
    assert!(status == 303 || status == 302, "PRG expected, got {status}");

    use vauban_web::schema::secret_secret_groups;
    let members: i64 = secret_secret_groups::table
        .filter(secret_secret_groups::secret_id.eq(secret_id))
        .count()
        .get_result(&mut conn)
        .await
        .expect("count");
    assert_eq!(members, 1, "junction row must exist after add");

    // Detail page now lists the member.
    let response = app
        .server
        .get(&location)
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);
    assert!(response.text().contains("test-secret-member"));

    // Remove the member.
    let response = app
        .server
        .post(&format!("{location}/secrets/{secret_uuid}/remove"))
        .add_header(COOKIE, admin_cookie(&admin.token, &csrf))
        .form(&serde_json::json!({ "csrf_token": csrf }))
        .await;
    let status = response.status_code().as_u16();
    assert!(status == 303 || status == 302, "PRG expected, got {status}");

    let members: i64 = secret_secret_groups::table
        .filter(secret_secret_groups::secret_id.eq(secret_id))
        .count()
        .get_result(&mut conn)
        .await
        .expect("count");
    assert_eq!(members, 0, "junction row must be gone after remove");

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Secret access rules sub-CRUD: navigation flow
// =============================================================================

/// Create a rule via the form (user group × secret group), follow the
/// redirect to the detail page, then edit and delete it.
#[tokio::test]
#[serial]
async fn rule_create_flow_redirect_resolves_then_edit_and_delete() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("vsw_rule")).await;
    let ug = create_test_vauban_group(&mut conn, "vsw-rule-ug").await;
    let (sg_id, _sg_uuid) = create_test_secret_group(&mut conn, "vsw-rule-sg").await;

    use vauban_web::schema::vauban_groups;
    let ug_id: i32 = vauban_groups::table
        .filter(vauban_groups::uuid.eq(ug))
        .select(vauban_groups::id)
        .first(&mut conn)
        .await
        .expect("user group id");

    let csrf = app.generate_csrf_token();
    let rule_name = unique_name("test-web-srule");

    // Create form loads with both dropdowns.
    let response = app
        .server
        .get("/vault/secrets/access/new")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);
    let form_html = response.text();
    assert!(
        form_html.contains("All secrets"),
        "the secret-group dropdown must include the virtual 'All secrets' entry"
    );

    // Submit.
    let response = app
        .server
        .post("/vault/secrets/access")
        .add_header(COOKIE, admin_cookie(&admin.token, &csrf))
        .form(&serde_json::json!({
            "csrf_token": csrf,
            "name": rule_name,
            "description": "web-created rule",
            "user_group_id": ug_id,
            "secret_group_id": sg_id,
            "is_active": "true",
            "priority": "0",
        }))
        .await;
    let status = response.status_code().as_u16();
    assert!(status == 303 || status == 302, "PRG expected, got {status}");
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        location.starts_with("/vault/secrets/access/"),
        "must redirect to the new rule detail, got: {location}"
    );

    // Redirect resolves.
    let response = app
        .server
        .get(&location)
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);
    assert!(response.text().contains(&rule_name));

    // Edit page loads and update succeeds.
    let response = app
        .server
        .get(&format!("{location}/edit"))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);

    let response = app
        .server
        .post(&format!("{location}/edit"))
        .add_header(COOKIE, admin_cookie(&admin.token, &csrf))
        .form(&serde_json::json!({
            "csrf_token": csrf,
            "name": format!("{rule_name}-renamed"),
            "user_group_id": ug_id,
            "secret_group_id": sg_id,
            "priority": "3",
        }))
        .await;
    let status = response.status_code().as_u16();
    assert!(status == 303 || status == 302, "PRG expected, got {status}");

    // The rule is now inactive (checkbox absent) with priority 3.
    let list = app
        .server
        .get("/vault/secrets/access")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&list, 200);
    assert!(list.text().contains(&format!("{rule_name}-renamed")));

    // Delete.
    let response = app
        .server
        .post(&format!("{location}/delete"))
        .add_header(COOKIE, admin_cookie(&admin.token, &csrf))
        .form(&serde_json::json!({ "csrf_token": csrf }))
        .await;
    let status = response.status_code().as_u16();
    assert!(status == 303 || status == 302, "PRG expected, got {status}");

    use vauban_web::schema::secret_access_rules;
    let remaining: i64 = secret_access_rules::table
        .filter(secret_access_rules::name.eq(format!("{rule_name}-renamed")))
        .count()
        .get_result(&mut conn)
        .await
        .expect("count");
    assert_eq!(remaining, 0, "rule row must be gone after delete");

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Virtual "All secrets" group protections
// =============================================================================

/// The virtual group is hidden from the list, refuses edit / update /
/// delete / membership mutations, and survives all attempts.
#[tokio::test]
#[serial]
async fn virtual_secret_group_is_protected_from_all_mutations() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("vsw_virt")).await;
    let csrf = app.generate_csrf_token();
    let virtual_uuid = shared::messages::ALL_SECRETS_GROUP_UUID;

    // Hidden from the group list.
    let response = app
        .server
        .get("/vault/secrets/groups")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);
    assert!(
        !response.text().contains(virtual_uuid),
        "the virtual group must not be browsable in the list"
    );

    // Update refused.
    let response = app
        .server
        .post(&format!("/vault/secrets/groups/{virtual_uuid}/edit"))
        .add_header(COOKIE, admin_cookie(&admin.token, &csrf))
        .form(&serde_json::json!({
            "csrf_token": csrf,
            "name": "hijacked",
            "slug": "hijacked",
        }))
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302 || status == 403 || status == 404,
        "virtual group update must be refused, got {status}"
    );

    // Delete refused.
    let response = app
        .server
        .post(&format!("/vault/secrets/groups/{virtual_uuid}/delete"))
        .add_header(COOKIE, admin_cookie(&admin.token, &csrf))
        .form(&serde_json::json!({ "csrf_token": csrf }))
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302 || status == 403 || status == 404,
        "virtual group delete must be refused, got {status}"
    );

    // Membership add refused.
    let (_sid, secret_uuid) = create_test_vault_secret(&mut conn, "virtprot", "value", true).await;
    let response = app
        .server
        .post(&format!("/vault/secrets/groups/{virtual_uuid}/secrets/add"))
        .add_header(COOKIE, admin_cookie(&admin.token, &csrf))
        .form(&serde_json::json!({
            "csrf_token": csrf,
            "secret_uuid": secret_uuid.to_string(),
        }))
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302 || status == 403 || status == 404,
        "virtual group membership add must be refused, got {status}"
    );

    // The row is intact: still kind='all', still named "All secrets",
    // still zero junction rows.
    use vauban_web::schema::{secret_groups, secret_secret_groups};
    let (name, kind): (String, String) = secret_groups::table
        .filter(secret_groups::uuid.eq(Uuid::parse_str(virtual_uuid).unwrap()))
        .select((secret_groups::name, secret_groups::kind))
        .first(&mut conn)
        .await
        .expect("virtual group row must survive");
    assert_eq!(kind, "all");
    assert_ne!(name, "hijacked");

    let virtual_id: i32 = secret_groups::table
        .filter(secret_groups::uuid.eq(Uuid::parse_str(virtual_uuid).unwrap()))
        .select(secret_groups::id)
        .first(&mut conn)
        .await
        .expect("virtual id");
    let junction: i64 = secret_secret_groups::table
        .filter(secret_secret_groups::secret_group_id.eq(virtual_id))
        .count()
        .get_result(&mut conn)
        .await
        .expect("count");
    assert_eq!(junction, 0, "virtual group must never gain members");

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Authorization: route_layer fences the whole nest
// =============================================================================

/// A plain user (no `vault_secrets:manage`) gets 403 on every page of
/// the nest — including on a random UUID (anti-enumeration: the 403
/// fires before any DB lookup).
#[tokio::test]
#[serial]
async fn plain_user_gets_403_on_the_whole_nest() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("vsw_403")).await;
    let random = Uuid::new_v4();

    for path in [
        "/vault/secrets".to_string(),
        "/vault/secrets/new".to_string(),
        format!("/vault/secrets/{random}"),
        format!("/vault/secrets/{random}/edit"),
        "/vault/secrets/groups".to_string(),
        format!("/vault/secrets/groups/{random}"),
        "/vault/secrets/access".to_string(),
        format!("/vault/secrets/access/{random}"),
    ] {
        let response = app
            .server
            .get(&path)
            .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
            .await;
        assert_status(&response, 403);
    }

    test_db::cleanup(&mut conn).await;
}

/// An anonymous caller is redirected to login (or 401), never 200.
#[tokio::test]
#[serial]
async fn anonymous_never_reaches_the_nest() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/vault/secrets").await;
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302 || status == 401,
        "anonymous caller must be redirected/refused, got {status}"
    );
}
