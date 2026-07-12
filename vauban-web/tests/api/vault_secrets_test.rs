//! VAUBAN Web - Vault Secrets M2M API E2E tests.
//!
//! Real HTTP + real Postgres + real in-process vauban-access (Casbin +
//! Diesel evaluation of `secret_access_rules`). The suite cements:
//!
//! - Rule-governed read: a user covered by an active rule sees the
//!   filtered list and round-trips the exact value.
//! - Provenance: every call is made "from" a known asset (source IP
//!   simulated via `X-Forwarded-For` on the trusted-proxy variant, host
//!   identity answered by the deterministic stub verifier). The
//!   provenance-denial scenarios live in `vault_provenance_test.rs`.
//! - Honest status matrix (`services::api_response_invariants`): no
//!   rule / inactive rule / expired rule are 403 (the secret exists,
//!   the caller is not covered), inactive secret / unknown UUID are
//!   404, malformed UUID is 400.
//! - Virtual group: a rule on "All secrets" covers freshly created
//!   secrets with zero group membership.
//! - NO bypass: a superuser WITHOUT a covering rule gets 403 on
//!   `/value` (there is no `read_all` equivalent for secrets).
//! - Scope isolation: `read`/`write`/`admin` keys get 403 on
//!   `/api/v1/vault/*`; a `secrets` key gets 200 there and 403
//!   everywhere else.

use axum::http::header;
use serde_json::Value;
use serial_test::serial;
use uuid::Uuid;

use vauban_web::models::api_key::ApiKeyScope;
use vauban_web::models::asset::AssetType;

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{
    add_secret_to_secret_group, add_user_to_vauban_group, all_assets_group_id,
    all_secrets_group_id, create_admin_user, create_provenance_asset, create_real_api_key,
    create_test_secret_access_rule, create_test_secret_group, create_test_user,
    create_test_vauban_group, create_test_vault_secret, unique_name,
};

/// Seed a provenance-verified SSH asset at `ip:22`: literal-IP hostname,
/// pinned fingerprint in `connection_config`, matching fingerprint in
/// the stub verifier map. Returns `(asset_id, asset_uuid)`.
pub async fn seed_verified_asset(
    conn: &mut diesel_async::AsyncPgConnection,
    app: &TestApp,
    hint: &str,
    ip: &str,
) -> (i32, Uuid) {
    let fingerprint = format!("SHA256:prov-{}", &Uuid::new_v4().to_string()[..13]);
    let (asset_id, asset_uuid) =
        create_provenance_asset(conn, hint, ip, 22, AssetType::Ssh, Some(&fingerprint)).await;
    app.pin_host_fingerprint(ip.parse().expect("literal IP"), 22, &fingerprint);
    (asset_id, asset_uuid)
}

/// Seed a user covered by an active rule on a static secret group that
/// contains `secret_id`; provenance dimension = virtual "All assets".
/// Returns the raw `secrets`-scoped API key.
async fn seed_covered_user(
    conn: &mut diesel_async::AsyncPgConnection,
    app: &TestApp,
    hint: &str,
    secret_id: i32,
) -> String {
    let user = create_test_user(conn, &app.auth_service, &unique_name(hint)).await;
    let ug = create_test_vauban_group(conn, &format!("{hint}-ug")).await;
    add_user_to_vauban_group(conn, user.user.id, &ug).await;

    let (sg_id, _sg_uuid) = create_test_secret_group(conn, &format!("{hint}-sg")).await;
    add_secret_to_secret_group(conn, secret_id, sg_id).await;
    let ag_id = all_assets_group_id(conn).await;
    create_test_secret_access_rule(conn, &ug, sg_id, ag_id, true, None, None).await;

    let (_key_uuid, raw_key) =
        create_real_api_key(conn, user.user.id, &[ApiKeyScope::Secrets], None).await;
    raw_key
}

// =============================================================================
// Happy path: rule-governed list + value round-trip
// =============================================================================

/// A user covered by an active rule, calling from a verified asset,
/// sees exactly the granted secret in the list, and the value endpoint
/// round-trips the exact plaintext.
#[tokio::test]
#[serial]
async fn covered_user_lists_and_reads_exact_value() {
    let app = TestApp::spawn_vault_provenance().await;
    let mut conn = app.get_conn().await;

    let caller_ip = "10.99.10.1";
    seed_verified_asset(&mut conn, app, "vsec_happy_asset", caller_ip).await;

    let plaintext = "s3cr3t-value-#42/with:specials";
    let (secret_id, secret_uuid) =
        create_test_vault_secret(&mut conn, "covered", plaintext, true).await;
    // A second secret NOT covered by any rule must stay invisible.
    let (_other_id, other_uuid) =
        create_test_vault_secret(&mut conn, "uncovered", "other-value", true).await;

    let raw_key = seed_covered_user(&mut conn, app, "vsec_happy", secret_id).await;

    // List: only the covered secret, metadata only (no value/ciphertext).
    let response = app
        .server
        .get("/api/v1/vault/secrets")
        .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
        .add_header("x-forwarded-for", caller_ip)
        .await;
    assert_status(&response, 200);
    let body: Value = response.json();
    let list = body.as_array().expect("list is a JSON array");
    assert_eq!(list.len(), 1, "exactly the covered secret must be listed");
    assert_eq!(list[0]["uuid"], secret_uuid.to_string());
    assert!(
        list[0].get("value").is_none() && list[0].get("ciphertext").is_none(),
        "list must expose metadata only"
    );
    assert!(
        !response.text().contains(&other_uuid.to_string()),
        "uncovered secret must not leak into the list"
    );

    // Metadata endpoint.
    let response = app
        .server
        .get(&format!("/api/v1/vault/secrets/{secret_uuid}"))
        .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
        .add_header("x-forwarded-for", caller_ip)
        .await;
    assert_status(&response, 200);
    let meta: Value = response.json();
    assert_eq!(meta["uuid"], secret_uuid.to_string());
    assert!(meta.get("value").is_none());

    // Value endpoint: exact round-trip + no-store.
    let response = app
        .server
        .get(&format!("/api/v1/vault/secrets/{secret_uuid}/value"))
        .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
        .add_header("x-forwarded-for", caller_ip)
        .await;
    assert_status(&response, 200);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .expect("value response must carry Cache-Control")
            .to_str()
            .unwrap(),
        "no-store"
    );
    let value_body: Value = response.json();
    assert_eq!(value_body["value"], plaintext);
    assert_eq!(value_body["uuid"], secret_uuid.to_string());

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Honest status matrix: 403 = not covered, 404 = does not exist, 400 = malformed
// =============================================================================

/// Fetch the value endpoint for a UUID, assert the expected status and
/// return the body text.
async fn value_body_with_status(
    app: &TestApp,
    raw_key: &str,
    caller_ip: &str,
    uuid_str: &str,
    expected_status: u16,
) -> String {
    let response = app
        .server
        .get(&format!("/api/v1/vault/secrets/{uuid_str}/value"))
        .add_header(header::AUTHORIZATION, app.api_key_header(raw_key))
        .add_header("x-forwarded-for", caller_ip)
        .await;
    assert_status(&response, expected_status);
    response.text()
}

/// Six denial paths, three honest statuses (INV-API-3/4/5): rule-level
/// refusals (no rule / inactive rule / expired rule) are 403 with the
/// canonical authorization message; non-existence (inactive secret /
/// unknown UUID) is 404; a malformed UUID is 400. The caller IS a
/// verified asset, so no denial here is a provenance denial (that 403
/// is pinned in `vault_provenance_test.rs`).
#[tokio::test]
#[serial]
async fn denials_follow_honest_status_matrix() {
    let app = TestApp::spawn_vault_provenance().await;
    let mut conn = app.get_conn().await;

    let caller_ip = "10.99.10.2";
    seed_verified_asset(&mut conn, app, "vsec_deny_asset", caller_ip).await;
    let ag_id = all_assets_group_id(&mut conn).await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("vsec_deny")).await;
    let ug = create_test_vauban_group(&mut conn, "vsec-deny-ug").await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    let (_key_uuid, raw_key) =
        create_real_api_key(&mut conn, user.user.id, &[ApiKeyScope::Secrets], None).await;

    // 1. Secret with NO covering rule at all.
    let (_id1, no_rule_uuid) =
        create_test_vault_secret(&mut conn, "norule", "v1-plain", true).await;

    // 2. Secret covered by an INACTIVE rule.
    let (id2, inactive_rule_uuid) =
        create_test_vault_secret(&mut conn, "inactiverule", "v2-plain", true).await;
    let (sg2, _) = create_test_secret_group(&mut conn, "deny-sg2").await;
    add_secret_to_secret_group(&mut conn, id2, sg2).await;
    create_test_secret_access_rule(&mut conn, &ug, sg2, ag_id, false, None, None).await;

    // 3. Secret covered by an EXPIRED rule.
    let (id3, expired_rule_uuid) =
        create_test_vault_secret(&mut conn, "expiredrule", "v3-plain", true).await;
    let (sg3, _) = create_test_secret_group(&mut conn, "deny-sg3").await;
    add_secret_to_secret_group(&mut conn, id3, sg3).await;
    create_test_secret_access_rule(
        &mut conn,
        &ug,
        sg3,
        ag_id,
        true,
        Some(chrono::Utc::now() - chrono::Duration::days(10)),
        Some(chrono::Utc::now() - chrono::Duration::days(1)),
    )
    .await;

    // 4. INACTIVE secret covered by an active rule.
    let (id4, inactive_secret_uuid) =
        create_test_vault_secret(&mut conn, "inactivesecret", "v4-plain", false).await;
    let (sg4, _) = create_test_secret_group(&mut conn, "deny-sg4").await;
    add_secret_to_secret_group(&mut conn, id4, sg4).await;
    create_test_secret_access_rule(&mut conn, &ug, sg4, ag_id, true, None, None).await;

    // 5. Unknown (random) UUID. 6. Malformed UUID.
    let unknown_uuid = Uuid::new_v4().to_string();

    // Rule-level refusals: the secret exists, the caller is not
    // covered -> 403 with the canonical authorization message.
    let forbidden_bodies = [
        value_body_with_status(app, &raw_key, caller_ip, &no_rule_uuid.to_string(), 403).await,
        value_body_with_status(
            app,
            &raw_key,
            caller_ip,
            &inactive_rule_uuid.to_string(),
            403,
        )
        .await,
        value_body_with_status(
            app,
            &raw_key,
            caller_ip,
            &expired_rule_uuid.to_string(),
            403,
        )
        .await,
    ];
    for (i, body) in forbidden_bodies.iter().enumerate() {
        assert!(
            body.contains("Not authorized to access this secret"),
            "rule-level denial #{i} must carry the canonical 403 message, got: {body}"
        );
        assert_eq!(
            body, &forbidden_bodies[0],
            "rule-level denial #{i} must be byte-identical to #0"
        );
    }

    // Non-existence: inactive secret and unknown UUID -> canonical 404.
    let not_found_bodies = [
        value_body_with_status(
            app,
            &raw_key,
            caller_ip,
            &inactive_secret_uuid.to_string(),
            404,
        )
        .await,
        value_body_with_status(app, &raw_key, caller_ip, &unknown_uuid, 404).await,
    ];
    for (i, body) in not_found_bodies.iter().enumerate() {
        assert!(
            body.contains("Secret not found"),
            "non-existence denial #{i} must carry the canonical 404 message, got: {body}"
        );
        assert_eq!(
            body, &not_found_bodies[0],
            "non-existence denial #{i} must be byte-identical to #0"
        );
    }

    // Malformed UUID -> 400 (INV-API-5), no phantom 404.
    let malformed_body = value_body_with_status(app, &raw_key, caller_ip, "not-a-uuid", 400).await;
    assert!(
        malformed_body.contains("Invalid UUID format"),
        "malformed UUID must carry the canonical 400 message, got: {malformed_body}"
    );

    // The metadata endpoint follows the same contract.
    let response = app
        .server
        .get(&format!("/api/v1/vault/secrets/{no_rule_uuid}"))
        .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
        .add_header("x-forwarded-for", caller_ip)
        .await;
    assert_status(&response, 403);
    let response = app
        .server
        .get(&format!("/api/v1/vault/secrets/{unknown_uuid}"))
        .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
        .add_header("x-forwarded-for", caller_ip)
        .await;
    assert_status(&response, 404);

    // And none of the denied secrets appear in the list.
    let response = app
        .server
        .get("/api/v1/vault/secrets")
        .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
        .add_header("x-forwarded-for", caller_ip)
        .await;
    assert_status(&response, 200);
    let text = response.text();
    for denied in [
        no_rule_uuid.to_string(),
        inactive_rule_uuid.to_string(),
        expired_rule_uuid.to_string(),
        inactive_secret_uuid.to_string(),
    ] {
        assert!(
            !text.contains(&denied),
            "denied secret {denied} must not appear in the list"
        );
    }

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Virtual "All secrets" group
// =============================================================================

/// A rule targeting the virtual "All secrets" group grants access to a
/// freshly created secret that belongs to NO static group.
#[tokio::test]
#[serial]
async fn virtual_all_secrets_rule_covers_fresh_secret() {
    let app = TestApp::spawn_vault_provenance().await;
    let mut conn = app.get_conn().await;

    let caller_ip = "10.99.10.3";
    seed_verified_asset(&mut conn, app, "vsec_virt_asset", caller_ip).await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("vsec_virt")).await;
    let ug = create_test_vauban_group(&mut conn, "vsec-virt-ug").await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;

    let virtual_id = all_secrets_group_id(&mut conn).await;
    let ag_id = all_assets_group_id(&mut conn).await;
    create_test_secret_access_rule(&mut conn, &ug, virtual_id, ag_id, true, None, None).await;

    // Freshly created secret, zero group membership.
    let plaintext = "fresh-secret-value";
    let (_id, secret_uuid) =
        create_test_vault_secret(&mut conn, "virtfresh", plaintext, true).await;

    let (_key_uuid, raw_key) =
        create_real_api_key(&mut conn, user.user.id, &[ApiKeyScope::Secrets], None).await;

    let response = app
        .server
        .get(&format!("/api/v1/vault/secrets/{secret_uuid}/value"))
        .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
        .add_header("x-forwarded-for", caller_ip)
        .await;
    assert_status(&response, 200);
    let body: Value = response.json();
    assert_eq!(body["value"], plaintext);

    // The list also surfaces it.
    let response = app
        .server
        .get("/api/v1/vault/secrets")
        .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
        .add_header("x-forwarded-for", caller_ip)
        .await;
    assert_status(&response, 200);
    assert!(response.text().contains(&secret_uuid.to_string()));

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// NO bypass: superuser without a rule
// =============================================================================

/// A superuser WITHOUT a covering rule gets 403 on `/value` even when
/// calling from a verified asset: secrets have no `read_all`-style
/// bypass, the rule is the only path in. (403 and not 404: the secret
/// exists, the caller is simply not covered -- INV-API-3.)
#[tokio::test]
#[serial]
async fn superuser_without_rule_gets_403_on_value() {
    let app = TestApp::spawn_vault_provenance().await;
    let mut conn = app.get_conn().await;

    let caller_ip = "10.99.10.4";
    seed_verified_asset(&mut conn, app, "vsec_su_asset", caller_ip).await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("vsec_su")).await;
    let (_key_uuid, raw_key) =
        create_real_api_key(&mut conn, admin.user.id, &[ApiKeyScope::Secrets], None).await;

    let (_id, secret_uuid) =
        create_test_vault_secret(&mut conn, "su-norule", "root-cannot-see", true).await;

    let response = app
        .server
        .get(&format!("/api/v1/vault/secrets/{secret_uuid}/value"))
        .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
        .add_header("x-forwarded-for", caller_ip)
        .await;
    assert_status(&response, 403);

    // The list is empty too (provenance passed, zero grants).
    let response = app
        .server
        .get("/api/v1/vault/secrets")
        .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
        .add_header("x-forwarded-for", caller_ip)
        .await;
    assert_status(&response, 200);
    assert!(
        !response.text().contains(&secret_uuid.to_string()),
        "superuser without a rule must not see the secret in the list"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Scope matrix: `secrets` is isolated from the read/write/admin hierarchy
// =============================================================================

/// read / write / admin keys are all rejected (403) on the vault zone.
/// The scope gate fires BEFORE provenance, so no asset seeding needed.
#[tokio::test]
#[serial]
async fn hierarchy_scoped_keys_denied_on_vault_zone() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("vsec_scope")).await;

    for scope in [ApiKeyScope::Read, ApiKeyScope::Write, ApiKeyScope::Admin] {
        let (_uuid, raw_key) = create_real_api_key(&mut conn, admin.user.id, &[scope], None).await;

        let response = app
            .server
            .get("/api/v1/vault/secrets")
            .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
            .await;
        assert_status(&response, 403);

        let response = app
            .server
            .get(&format!("/api/v1/vault/secrets/{}/value", Uuid::new_v4()))
            .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
            .await;
        assert_status(&response, 403);
    }

    test_db::cleanup(&mut conn).await;
}

/// A `secrets` key passes the scope gate on the vault zone but is
/// rejected (403) on every hierarchical zone, even a plain read.
#[tokio::test]
#[serial]
async fn secrets_key_isolated_from_hierarchy_zones() {
    let app = TestApp::spawn_vault_provenance().await;
    let mut conn = app.get_conn().await;

    let caller_ip = "10.99.10.5";
    seed_verified_asset(&mut conn, app, "vsec_iso_asset", caller_ip).await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("vsec_iso")).await;
    let (_uuid, raw_key) =
        create_real_api_key(&mut conn, user.user.id, &[ApiKeyScope::Secrets], None).await;

    // Vault zone: scope gate + provenance pass, list succeeds (empty is
    // fine: no rule covers this user).
    let response = app
        .server
        .get("/api/v1/vault/secrets")
        .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
        .add_header("x-forwarded-for", caller_ip)
        .await;
    assert_status(&response, 200);

    // Read zone: 403 (secrets does not imply read).
    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
        .await;
    assert_status(&response, 403);

    // Write zone: 403.
    let response = app
        .server
        .post("/api/v1/sessions")
        .add_header(header::AUTHORIZATION, app.api_key_header(&raw_key))
        .json(&serde_json::json!({
            "asset_uuid": Uuid::new_v4().to_string(),
            "protocol": "ssh"
        }))
        .await;
    assert_status(&response, 403);

    test_db::cleanup(&mut conn).await;
}
