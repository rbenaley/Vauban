//! VAUBAN Web - Vault Secrets M2M provenance E2E tests.
//!
//! The `/api/v1/vault/*` surface may ONLY be consumed from a machine
//! that is a known, identity-verified asset of the bastion. This suite
//! pins the whole provenance pipeline against real HTTP, real Postgres
//! and the in-process vauban-access oracle, with the caller's source IP
//! simulated through `X-Forwarded-For` (trusted-proxy loopback variant)
//! and the active host-identity challenge answered by the deterministic
//! [`StaticHostIdentityVerifier`]:
//!
//! - Unknown IP -> canonical 403 (`ApiDenial::ProvenanceDenied`) on
//!   ALL endpoints, the list included (never `200 []` for a non-asset
//!   caller), byte-identical across endpoints.
//! - Asset without a pinned fingerprint -> fail-closed 403.
//! - Fingerprint mismatch (MITM / IP squatting) -> 403, NEVER cached:
//!   every retry re-challenges.
//! - Triplet enforcement: an identity-verified asset OUTSIDE the rule's
//!   asset group is denied; the same user calling from an asset inside
//!   the group is granted.
//! - "All assets" rule: any known verified asset is accepted.
//! - RDP provenance: an RDP asset proves its identity through the
//!   certificate pin.
//! - Verification cache: a second call within the 60 s TTL does not
//!   re-challenge the host.

use std::sync::atomic::Ordering;

use axum::http::header;
use serde_json::Value;
use serial_test::serial;
use uuid::Uuid;

use vauban_web::models::api_key::ApiKeyScope;
use vauban_web::models::asset::AssetType;

use crate::api::vault_secrets_test::seed_verified_asset;
use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{
    add_asset_to_asset_group_by_id, add_secret_to_secret_group, add_user_to_vauban_group,
    all_assets_group_id, asset_group_id_by_uuid, create_provenance_asset, create_real_api_key,
    create_test_asset_group, create_test_secret_access_rule, create_test_secret_group,
    create_test_user, create_test_vauban_group, create_test_vault_secret, unique_name,
};

/// Seed a user in a fresh group with a `secrets`-scoped key, an active
/// secret, a static secret group containing it, and one active rule
/// `(user group, secret group, asset_group_id)`. Returns
/// `(raw_key, secret_uuid)`.
async fn seed_user_secret_rule(
    conn: &mut diesel_async::AsyncPgConnection,
    app: &TestApp,
    hint: &str,
    asset_group_id: i32,
) -> (String, Uuid) {
    let user = create_test_user(conn, &app.auth_service, &unique_name(hint)).await;
    let ug = create_test_vauban_group(conn, &format!("{hint}-ug")).await;
    add_user_to_vauban_group(conn, user.user.id, &ug).await;

    let (secret_id, secret_uuid) =
        create_test_vault_secret(conn, &format!("{hint}-sec"), "prov-value", true).await;
    let (sg_id, _) = create_test_secret_group(conn, &format!("{hint}-sg")).await;
    add_secret_to_secret_group(conn, secret_id, sg_id).await;
    create_test_secret_access_rule(conn, &ug, sg_id, asset_group_id, true, None, None).await;

    let (_key_uuid, raw_key) =
        create_real_api_key(conn, user.user.id, &[ApiKeyScope::Secrets], None).await;
    (raw_key, secret_uuid)
}

async fn get_with_xff(
    app: &TestApp,
    path: &str,
    raw_key: &str,
    caller_ip: &str,
) -> axum_test::TestResponse {
    app.server
        .get(path)
        .add_header(header::AUTHORIZATION, app.api_key_header(raw_key))
        .add_header("x-forwarded-for", caller_ip)
        .await
}

// =============================================================================
// Unknown IP: global refusal, list included, canonical 403
// =============================================================================

/// A caller whose source IP matches NO asset gets the canonical 403
/// (`ApiDenial::ProvenanceDenied`) on every endpoint — the LIST
/// INCLUDED (no `200 []` oracle) — byte-identical across the three
/// endpoints. A verified caller asking for an unknown UUID gets a
/// distinct honest 404 (INV-API-4): existence and authorization are
/// separate answers on the M2M zone.
#[tokio::test]
#[serial]
async fn unknown_ip_gets_canonical_403_everywhere_including_list() {
    let app = TestApp::spawn_vault_provenance().await;
    let mut conn = app.get_conn().await;

    let ag_all = all_assets_group_id(&mut conn).await;
    let (raw_key, secret_uuid) = seed_user_secret_rule(&mut conn, app, "prov_noip", ag_all).await;

    // 203.0.113.99 matches no asset hostname.
    let ghost_ip = "203.0.113.99";
    let list = get_with_xff(app, "/api/v1/vault/secrets", &raw_key, ghost_ip).await;
    assert_status(&list, 403);
    let meta = get_with_xff(
        app,
        &format!("/api/v1/vault/secrets/{secret_uuid}"),
        &raw_key,
        ghost_ip,
    )
    .await;
    assert_status(&meta, 403);
    let value = get_with_xff(
        app,
        &format!("/api/v1/vault/secrets/{secret_uuid}/value"),
        &raw_key,
        ghost_ip,
    )
    .await;
    assert_status(&value, 403);

    let reference_body = list.text();
    assert!(
        reference_body.contains("Caller is not an identity-verified asset"),
        "provenance denial must carry the canonical message, got: {reference_body}"
    );
    for (name, body) in [("metadata", meta.text()), ("value", value.text())] {
        assert_eq!(
            body, reference_body,
            "provenance denial on {name} must be byte-identical to the list denial"
        );
    }

    // A verified caller asking for an unknown UUID gets an honest 404,
    // clearly distinct from the provenance 403.
    let caller_ip = "10.99.20.1";
    seed_verified_asset(&mut conn, app, "prov_noip_ref", caller_ip).await;
    let reference = get_with_xff(
        app,
        &format!("/api/v1/vault/secrets/{}/value", Uuid::new_v4()),
        &raw_key,
        caller_ip,
    )
    .await;
    assert_status(&reference, 404);

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Fail-closed: no pinned fingerprint
// =============================================================================

/// An asset matching the caller IP but WITHOUT a pinned fingerprint can
/// never anchor provenance: canonical 403 even with a covering rule,
/// and no challenge is even attempted (nothing to compare against).
#[tokio::test]
#[serial]
async fn asset_without_pinned_fingerprint_is_fail_closed() {
    let app = TestApp::spawn_vault_provenance().await;
    let mut conn = app.get_conn().await;

    let caller_ip = "10.99.20.2";
    create_provenance_asset(&mut conn, "nopin", caller_ip, 22, AssetType::Ssh, None).await;
    // Even if the "host" would answer a challenge, the missing pin
    // disqualifies the candidate BEFORE any challenge.
    app.pin_host_fingerprint(caller_ip.parse().expect("ip"), 22, "SHA256:whatever");

    let ag_all = all_assets_group_id(&mut conn).await;
    let (raw_key, secret_uuid) = seed_user_secret_rule(&mut conn, app, "prov_nopin", ag_all).await;

    let before = app.identity_challenges.load(Ordering::SeqCst);
    let response = get_with_xff(
        app,
        &format!("/api/v1/vault/secrets/{secret_uuid}/value"),
        &raw_key,
        caller_ip,
    )
    .await;
    assert_status(&response, 403);
    assert_eq!(
        app.identity_challenges.load(Ordering::SeqCst),
        before,
        "an unpinned candidate must be skipped without challenging the host"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Fingerprint mismatch: denied, audited, NEVER cached
// =============================================================================

/// A candidate that answers the challenge with a fingerprint different
/// from the pin is rejected (403) and the failure is NEVER cached:
/// every retry re-challenges the host.
#[tokio::test]
#[serial]
async fn fingerprint_mismatch_is_denied_and_never_cached() {
    let app = TestApp::spawn_vault_provenance().await;
    let mut conn = app.get_conn().await;

    let caller_ip = "10.99.20.3";
    create_provenance_asset(
        &mut conn,
        "mitm",
        caller_ip,
        22,
        AssetType::Ssh,
        Some("SHA256:the-real-pin"),
    )
    .await;
    // The "host" (squatter) presents a DIFFERENT fingerprint.
    app.pin_host_fingerprint(caller_ip.parse().expect("ip"), 22, "SHA256:evil-imposter");

    let ag_all = all_assets_group_id(&mut conn).await;
    let (raw_key, secret_uuid) = seed_user_secret_rule(&mut conn, app, "prov_mitm", ag_all).await;

    let cached_before = app.app_state.vault_provenance.verified_len();
    let challenges_before = app.identity_challenges.load(Ordering::SeqCst);

    let first = get_with_xff(
        app,
        &format!("/api/v1/vault/secrets/{secret_uuid}/value"),
        &raw_key,
        caller_ip,
    )
    .await;
    assert_status(&first, 403);
    let second = get_with_xff(
        app,
        &format!("/api/v1/vault/secrets/{secret_uuid}/value"),
        &raw_key,
        caller_ip,
    )
    .await;
    assert_status(&second, 403);

    assert_eq!(
        app.identity_challenges.load(Ordering::SeqCst),
        challenges_before + 2,
        "a mismatch must NEVER be cached: each call re-challenges the host"
    );
    assert_eq!(
        app.app_state.vault_provenance.verified_len(),
        cached_before,
        "a mismatch must never be inserted into the verification cache"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Triplet enforcement: the asset group dimension
// =============================================================================

/// The rule's asset group restricts WHERE the call may come from: the
/// same user is denied from a verified asset OUTSIDE the rule's asset
/// group and granted from a verified asset INSIDE it.
#[tokio::test]
#[serial]
async fn asset_outside_rule_asset_group_is_denied_inside_is_granted() {
    let app = TestApp::spawn_vault_provenance().await;
    let mut conn = app.get_conn().await;

    // Static asset group holding only the "inside" asset.
    let ag_uuid = create_test_asset_group(&mut conn, &unique_name("prov-ag")).await;
    let ag_id = asset_group_id_by_uuid(&mut conn, &ag_uuid).await;

    let inside_ip = "10.99.20.4";
    let (inside_id, _) = seed_verified_asset(&mut conn, app, "prov_inside", inside_ip).await;
    add_asset_to_asset_group_by_id(&mut conn, inside_id, ag_id).await;

    let outside_ip = "10.99.20.5";
    seed_verified_asset(&mut conn, app, "prov_outside", outside_ip).await;

    let (raw_key, secret_uuid) = seed_user_secret_rule(&mut conn, app, "prov_triplet", ag_id).await;

    // From the OUTSIDE asset: identity verified, but the triplet does
    // not cover it -> rule-level denial (403 on value, empty list):
    // the secret exists, the caller is not covered from there.
    let response = get_with_xff(
        app,
        &format!("/api/v1/vault/secrets/{secret_uuid}/value"),
        &raw_key,
        outside_ip,
    )
    .await;
    assert_status(&response, 403);
    let list = get_with_xff(app, "/api/v1/vault/secrets", &raw_key, outside_ip).await;
    assert_status(&list, 200);
    assert!(
        !list.text().contains(&secret_uuid.to_string()),
        "an out-of-group caller must not see the secret in the list"
    );

    // From the INSIDE asset: granted.
    let response = get_with_xff(
        app,
        &format!("/api/v1/vault/secrets/{secret_uuid}/value"),
        &raw_key,
        inside_ip,
    )
    .await;
    assert_status(&response, 200);
    let body: Value = response.json();
    assert_eq!(body["value"], "prov-value");

    test_db::cleanup(&mut conn).await;
}

/// A rule on the virtual "All assets" group means "any known verified
/// asset" — an asset that belongs to NO static group is accepted.
#[tokio::test]
#[serial]
async fn all_assets_rule_accepts_any_verified_asset() {
    let app = TestApp::spawn_vault_provenance().await;
    let mut conn = app.get_conn().await;

    let caller_ip = "10.99.20.6";
    seed_verified_asset(&mut conn, app, "prov_anyasset", caller_ip).await;

    let ag_all = all_assets_group_id(&mut conn).await;
    let (raw_key, secret_uuid) = seed_user_secret_rule(&mut conn, app, "prov_any", ag_all).await;

    let response = get_with_xff(
        app,
        &format!("/api/v1/vault/secrets/{secret_uuid}/value"),
        &raw_key,
        caller_ip,
    )
    .await;
    assert_status(&response, 200);

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// RDP provenance
// =============================================================================

/// An RDP asset proves its identity through the pinned server
/// certificate fingerprint.
#[tokio::test]
#[serial]
async fn rdp_asset_proves_identity_via_certificate_pin() {
    let app = TestApp::spawn_vault_provenance().await;
    let mut conn = app.get_conn().await;

    let caller_ip = "10.99.20.7";
    let fingerprint = format!("SHA256:rdp-{}", &Uuid::new_v4().to_string()[..13]);
    create_provenance_asset(
        &mut conn,
        "rdp",
        caller_ip,
        3389,
        AssetType::Rdp,
        Some(&fingerprint),
    )
    .await;
    app.pin_host_fingerprint(caller_ip.parse().expect("ip"), 3389, &fingerprint);

    let ag_all = all_assets_group_id(&mut conn).await;
    let (raw_key, secret_uuid) = seed_user_secret_rule(&mut conn, app, "prov_rdp", ag_all).await;

    let response = get_with_xff(
        app,
        &format!("/api/v1/vault/secrets/{secret_uuid}/value"),
        &raw_key,
        caller_ip,
    )
    .await;
    assert_status(&response, 200);

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Verification cache (TTL 60 s)
// =============================================================================

/// A second call within the TTL is served from the verification cache:
/// no new challenge is issued, and the call still succeeds.
#[tokio::test]
#[serial]
async fn second_call_within_ttl_does_not_rechallenge() {
    let app = TestApp::spawn_vault_provenance().await;
    let mut conn = app.get_conn().await;

    let caller_ip = "10.99.20.8";
    seed_verified_asset(&mut conn, app, "prov_cache", caller_ip).await;

    let ag_all = all_assets_group_id(&mut conn).await;
    let (raw_key, secret_uuid) =
        seed_user_secret_rule(&mut conn, app, "prov_cachetest", ag_all).await;

    let before = app.identity_challenges.load(Ordering::SeqCst);

    let first = get_with_xff(
        app,
        &format!("/api/v1/vault/secrets/{secret_uuid}/value"),
        &raw_key,
        caller_ip,
    )
    .await;
    assert_status(&first, 200);
    let after_first = app.identity_challenges.load(Ordering::SeqCst);
    assert_eq!(after_first, before + 1, "first call must challenge once");

    let second = get_with_xff(
        app,
        &format!("/api/v1/vault/secrets/{secret_uuid}/value"),
        &raw_key,
        caller_ip,
    )
    .await;
    assert_status(&second, 200);
    assert_eq!(
        app.identity_challenges.load(Ordering::SeqCst),
        after_first,
        "second call within the 60 s TTL must NOT re-challenge the host"
    );

    test_db::cleanup(&mut conn).await;
}
