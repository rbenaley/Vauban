//! SSH key-authentication redesign -- adversarial + end-to-end battery.
//!
//! This suite hardens the SSH asset key-auth surface ahead of the LTS
//! release. Where `ssh_key_auth_test.rs` pins the structural lints and the
//! no-proxy pre-flight of the push/test handlers, and
//! `asset_protocol_test.rs` covers the happy create/edit paths, THIS file
//! attacks the create/edit handlers with hostile inputs and walks the full
//! create -> detail -> edit navigation flow.
//!
//! The handlers here are fully exercisable without an SSH proxy or vault:
//! every assertion targets the validation / persistence / rendering layers
//! that run before any network egress. The push/test happy path (real SSH
//! server) is intentionally out of scope -- `state.ssh_proxy` is a concrete
//! `Arc<ProxySshClient>`, not a trait, so it cannot be mocked without a
//! production refactor; its fail-closed behaviour is pinned in
//! `ssh_key_auth_test.rs`.
//!
//! Invariants pinned:
//!   1. A tampered `ssh_key_source` (anything other than `generated`) still
//!      demands BOTH key halves and is normalised to `existing` at rest.
//!   2. A mismatched / public-only / swapped key pair never persists and
//!      never mutates an existing row.
//!   3. Cross-protocol smuggling (RDP carrying SSH key material) is dropped.
//!   4. Switching `ssh_key -> password` scrubs every key-mode secret.
//!   5. A description-only edit preserves the stored pair, the
//!      `ssh_pubkey_pushed` flag, and host-key pinning.
//!   6. Rotating the public key resets `ssh_pubkey_pushed` (the new key is
//!      not yet on the target).
//!   7. The stored public key is rendered HTML-escaped (no stored XSS via a
//!      hostile key comment).

use crate::common::{TestApp, assertions::*, unwrap_ok};
use crate::fixtures::{create_admin_user, unique_name};
use axum::http::header::COOKIE;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value as Json;
use serial_test::serial;
use uuid::Uuid;
use vauban_web::models::asset::{Asset, AssetType, NewAsset};
use vauban_web::schema::assets;

// =============================================================================
// Helpers (local copies -- each integration test module is its own crate
// module, so helpers from sibling files are not in scope).
// =============================================================================

fn auth_csrf_cookie(token: &str, csrf: &str) -> String {
    format!("access_token={}; __vauban_csrf={}", token, csrf)
}

/// `<algo> <base64>` projection of an OpenSSH public key, comment-stripped,
/// so two keys with identical material but different comments compare equal.
fn ssh_pubkey_body(line: &str) -> String {
    line.split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

async fn read_asset_by_triplet(
    conn: &mut AsyncPgConnection,
    hostname: &str,
    port: i32,
    username: &str,
) -> Option<Asset> {
    assets::table
        .filter(assets::hostname.eq(hostname))
        .filter(assets::port.eq(port))
        .filter(assets::connection_username.eq(username))
        .first(conn)
        .await
        .ok()
}

async fn read_asset_by_uuid(conn: &mut AsyncPgConnection, asset_uuid: Uuid) -> Option<Asset> {
    assets::table
        .filter(assets::uuid.eq(asset_uuid))
        .first(conn)
        .await
        .ok()
}

async fn insert_asset_with_config(
    conn: &mut AsyncPgConnection,
    name: &str,
    hostname: &str,
    port: i32,
    asset_type: AssetType,
    connection_username: &str,
    connection_config: Json,
) -> Asset {
    let new_asset = NewAsset {
        uuid: Uuid::new_v4(),
        name: name.to_string(),
        hostname: hostname.to_string(),
        port,
        asset_type,
        status: "online".to_string(),
        description: None,
        connection_config,
        created_by_id: None,
        updated_by_id: None,
        connection_username: connection_username.to_string(),
    };
    unwrap_ok!(
        diesel::insert_into(assets::table)
            .values(&new_asset)
            .get_result(conn)
            .await
    )
}

/// Seed an SSH asset already configured for key-based auth with a stored
/// (plaintext-in-tests) pair, host key pinned, and `ssh_pubkey_pushed`.
async fn seed_ssh_key_asset(
    conn: &mut AsyncPgConnection,
    hostname: &str,
    username: &str,
    public_openssh: &str,
    private_openssh: &str,
    pushed: bool,
) -> Asset {
    const HOST_KEY: &str = "ecdsa-sha2-nistp256 AAAAADVERSARIALHOSTKEY20260625";
    const FINGERPRINT: &str = "SHA256:ADVERSARIALPINNED20260625aaaaaaaaaaaaaaaaaaa";
    insert_asset_with_config(
        conn,
        &unique_name("ssh-adv"),
        hostname,
        22,
        AssetType::Ssh,
        username,
        serde_json::json!({
            "username": username,
            "auth_type": "ssh_key",
            "ssh_key_source": "existing",
            "ssh_public_key": public_openssh,
            "private_key": private_openssh,
            "ssh_pubkey_pushed": pushed,
            "ssh_host_key": HOST_KEY,
            "ssh_host_key_fingerprint": FINGERPRINT,
        }),
    )
    .await
}

// =============================================================================
// CREATE -- adversarial
// =============================================================================

/// Invariant #1 (first line): a forged `ssh_key_source=bogus` must NOT slip
/// past the key-material requirement. With no key pasted, the create is
/// rejected and nothing is persisted.
#[tokio::test]
#[serial]
async fn create_ssh_tampered_source_without_keys_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("adv_src_nokey")).await;
    let csrf = app.generate_csrf_token();
    let hostname = format!("{}.adv.test", unique_name("host"));

    let response = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &unique_name("adv-src")),
            ("hostname", &hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "ssh_key"),
            ("ssh_key_source", "bogus-source-value"),
        ])
        .await;

    assert_status(&response, 303);
    assert!(
        read_asset_by_triplet(&mut conn, &hostname, 22, "root")
            .await
            .is_none(),
        "a tampered key source without key material must persist nothing"
    );
}

/// Invariant #1 (second line): a forged source WITH a valid pasted pair is
/// accepted but normalised to `existing` at rest -- no arbitrary string is
/// persisted in `ssh_key_source`.
#[tokio::test]
#[serial]
async fn create_ssh_tampered_source_with_valid_pair_normalises_to_existing() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("adv_src_norm")).await;
    let csrf = app.generate_csrf_token();
    let hostname = format!("{}.adv.test", unique_name("host"));

    let kp = shared::ssh_keygen::generate_ed25519_keypair("root@asset").expect("keygen");

    let response = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &unique_name("adv-norm")),
            ("hostname", &hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "ssh_key"),
            ("ssh_key_source", "../../etc/passwd"),
            ("ssh_public_key", kp.public_openssh.as_str()),
            ("ssh_private_key", kp.private_openssh.as_str()),
        ])
        .await;

    assert_status(&response, 303);
    let asset = read_asset_by_triplet(&mut conn, &hostname, 22, "root")
        .await
        .expect("a valid pair must persist even with a tampered source");
    assert_eq!(
        asset
            .connection_config
            .get("ssh_key_source")
            .and_then(|v| v.as_str()),
        Some("existing"),
        "the stored source must be normalised to `existing`, never the raw tampered value"
    );
    assert_eq!(
        asset
            .connection_config
            .get("ssh_public_key")
            .and_then(|v| v.as_str())
            .map(ssh_pubkey_body),
        Some(ssh_pubkey_body(&kp.public_openssh)),
    );
}

/// Invariant #3: an RDP create that smuggles an SSH public key (with
/// password auth) must persist the password but DROP the key field -- no
/// dormant SSH credential on an RDP row. (A smuggled *private* key is a
/// harder reject handled by `validate_auth_inputs`, pinned in
/// `asset_protocol_test.rs`; here we cover the public-key smuggling path
/// that `validate_auth_inputs` does not reject and that must be silently
/// dropped by `build_connection_config`.)
#[tokio::test]
#[serial]
async fn create_rdp_smuggled_public_key_is_dropped() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("adv_rdp_smug")).await;
    let csrf = app.generate_csrf_token();
    let hostname = format!("{}.adv-rdp.test", unique_name("host"));
    let kp = shared::ssh_keygen::generate_ed25519_keypair("x@y").expect("keygen");

    let response = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &unique_name("adv-rdp")),
            ("hostname", &hostname),
            ("port", "3389"),
            ("asset_type", "rdp"),
            ("status", "online"),
            ("ssh_username", "Administrator"),
            ("ssh_password", "rdp-secret"),
            // Smuggled SSH public key -- must be ignored on an RDP row.
            ("ssh_public_key", kp.public_openssh.as_str()),
        ])
        .await;

    assert_status(&response, 303);
    let asset = read_asset_by_triplet(&mut conn, &hostname, 3389, "Administrator")
        .await
        .expect("RDP asset must persist");
    let cfg = asset.connection_config;
    assert_eq!(cfg.get("password").and_then(|v| v.as_str()), Some("rdp-secret"));
    assert!(
        cfg.get("ssh_public_key").is_none(),
        "no SSH public key may persist on an RDP row, got: {cfg:?}"
    );
    assert!(
        cfg.get("private_key").is_none(),
        "no SSH private key may persist on an RDP row, got: {cfg:?}"
    );
}

// =============================================================================
// EDIT -- adversarial
// =============================================================================

/// Invariant #2: rotating with a public/private pair that does NOT match is
/// rejected and the previously stored pair is left untouched.
#[tokio::test]
#[serial]
async fn edit_ssh_rotate_mismatched_pair_is_rejected_and_preserves_old() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("adv_rot_mismatch")).await;
    let csrf = app.generate_csrf_token();
    let hostname = format!("{}.adv-rot.test", unique_name("host"));

    let old = shared::ssh_keygen::generate_ed25519_keypair("old@asset").expect("keygen old");
    let new_a = shared::ssh_keygen::generate_ed25519_keypair("a@asset").expect("keygen a");
    let new_b = shared::ssh_keygen::generate_ed25519_keypair("b@asset").expect("keygen b");

    let asset = seed_ssh_key_asset(
        &mut conn,
        &hostname,
        "root",
        &old.public_openssh,
        &old.private_openssh,
        true,
    )
    .await;

    let response = app
        .server
        .post(&format!("/assets/manage/{}/edit", asset.uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &asset.name),
            ("hostname", &hostname),
            ("port", "22"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "ssh_key"),
            ("ssh_key_source", "existing"),
            // public from A, private from B -> mismatch.
            ("ssh_public_key", new_a.public_openssh.as_str()),
            ("ssh_private_key", new_b.private_openssh.as_str()),
        ])
        .await;

    assert_status(&response, 303);
    let after = read_asset_by_uuid(&mut conn, asset.uuid).await.unwrap();
    assert_eq!(
        after
            .connection_config
            .get("ssh_public_key")
            .and_then(|v| v.as_str())
            .map(ssh_pubkey_body),
        Some(ssh_pubkey_body(&old.public_openssh)),
        "a mismatched rotation must leave the old public key in place"
    );
    assert_eq!(
        after
            .connection_config
            .get("ssh_pubkey_pushed")
            .and_then(|v| v.as_bool()),
        Some(true),
        "a rejected rotation must not touch the pushed flag"
    );
}

/// Invariant #2: pasting a new public key WITHOUT a matching private key
/// cannot be verified against the vault-sealed private key, so the edit is
/// refused and the old key is preserved.
#[tokio::test]
#[serial]
async fn edit_ssh_public_only_is_rejected_and_preserves_old() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("adv_pub_only")).await;
    let csrf = app.generate_csrf_token();
    let hostname = format!("{}.adv-pubonly.test", unique_name("host"));

    let old = shared::ssh_keygen::generate_ed25519_keypair("old@asset").expect("keygen old");
    let new = shared::ssh_keygen::generate_ed25519_keypair("new@asset").expect("keygen new");

    let asset = seed_ssh_key_asset(
        &mut conn,
        &hostname,
        "root",
        &old.public_openssh,
        &old.private_openssh,
        true,
    )
    .await;

    let response = app
        .server
        .post(&format!("/assets/manage/{}/edit", asset.uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &asset.name),
            ("hostname", &hostname),
            ("port", "22"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "ssh_key"),
            ("ssh_key_source", "existing"),
            ("ssh_public_key", new.public_openssh.as_str()),
            ("ssh_private_key", ""),
        ])
        .await;

    assert_status(&response, 303);
    let after = read_asset_by_uuid(&mut conn, asset.uuid).await.unwrap();
    assert_eq!(
        after
            .connection_config
            .get("ssh_public_key")
            .and_then(|v| v.as_str())
            .map(ssh_pubkey_body),
        Some(ssh_pubkey_body(&old.public_openssh)),
        "a public-only edit must not replace the stored public key"
    );
}

/// Invariant #4: switching `ssh_key -> password` scrubs the private key,
/// passphrase, public key, source and pushed flag, while preserving the
/// pinned host key (SEC-12 family).
#[tokio::test]
#[serial]
async fn edit_ssh_switch_to_password_strips_key_material() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("adv_to_pwd")).await;
    let csrf = app.generate_csrf_token();
    let hostname = format!("{}.adv-topwd.test", unique_name("host"));

    let kp = shared::ssh_keygen::generate_ed25519_keypair("root@asset").expect("keygen");
    let asset = seed_ssh_key_asset(
        &mut conn,
        &hostname,
        "root",
        &kp.public_openssh,
        &kp.private_openssh,
        true,
    )
    .await;

    let response = app
        .server
        .post(&format!("/assets/manage/{}/edit", asset.uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &asset.name),
            ("hostname", &hostname),
            ("port", "22"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "password"),
            ("ssh_password", "now-a-password"),
        ])
        .await;

    assert_status(&response, 303);
    let cfg = read_asset_by_uuid(&mut conn, asset.uuid)
        .await
        .unwrap()
        .connection_config;
    assert_eq!(cfg.get("auth_type").and_then(|v| v.as_str()), Some("password"));
    assert_eq!(
        cfg.get("password").and_then(|v| v.as_str()),
        Some("now-a-password")
    );
    for stripped in [
        "private_key",
        "passphrase",
        "ssh_public_key",
        "ssh_key_source",
        "ssh_pubkey_pushed",
    ] {
        assert!(
            cfg.get(stripped).is_none(),
            "`{stripped}` must be scrubbed when switching to password auth, got: {cfg:?}"
        );
    }
    assert!(
        cfg.get("ssh_host_key").is_some(),
        "host-key pinning must survive an auth-mode switch"
    );
}

/// Invariant #5: a description-only edit (both key fields left blank)
/// preserves the stored pair, the `ssh_pubkey_pushed` flag, and host-key
/// pinning.
#[tokio::test]
#[serial]
async fn edit_ssh_description_only_preserves_keypair_and_pinning() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("adv_desconly")).await;
    let csrf = app.generate_csrf_token();
    let hostname = format!("{}.adv-desc.test", unique_name("host"));

    let kp = shared::ssh_keygen::generate_ed25519_keypair("root@asset").expect("keygen");
    let asset = seed_ssh_key_asset(
        &mut conn,
        &hostname,
        "root",
        &kp.public_openssh,
        &kp.private_openssh,
        true,
    )
    .await;

    let response = app
        .server
        .post(&format!("/assets/manage/{}/edit", asset.uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &asset.name),
            ("hostname", &hostname),
            ("port", "22"),
            ("status", "online"),
            ("description", "just a description change"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "ssh_key"),
            ("ssh_key_source", "existing"),
            ("ssh_public_key", ""),
            ("ssh_private_key", ""),
        ])
        .await;

    assert_status(&response, 303);
    let cfg = read_asset_by_uuid(&mut conn, asset.uuid)
        .await
        .unwrap()
        .connection_config;
    assert_eq!(
        cfg.get("ssh_public_key").and_then(|v| v.as_str()),
        Some(kp.public_openssh.trim()),
        "the stored public key must round-trip untouched"
    );
    assert!(
        cfg.get("private_key").and_then(|v| v.as_str()).is_some(),
        "the stored private key must be preserved"
    );
    assert_eq!(
        cfg.get("ssh_pubkey_pushed").and_then(|v| v.as_bool()),
        Some(true),
        "a description-only edit must not reset the pushed flag"
    );
    assert!(cfg.get("ssh_host_key").is_some(), "host key must be preserved");
}

/// Invariant #6: rotating to a NEW (valid) pair resets `ssh_pubkey_pushed`
/// to false -- the freshly stored key is not yet in the target's
/// authorized_keys.
#[tokio::test]
#[serial]
async fn edit_ssh_rotate_valid_pair_resets_pushed_flag() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("adv_rot_reset")).await;
    let csrf = app.generate_csrf_token();
    let hostname = format!("{}.adv-reset.test", unique_name("host"));

    let old = shared::ssh_keygen::generate_ed25519_keypair("old@asset").expect("keygen old");
    let new = shared::ssh_keygen::generate_ed25519_keypair("new@asset").expect("keygen new");

    let asset = seed_ssh_key_asset(
        &mut conn,
        &hostname,
        "root",
        &old.public_openssh,
        &old.private_openssh,
        true, // previously pushed
    )
    .await;

    let response = app
        .server
        .post(&format!("/assets/manage/{}/edit", asset.uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &asset.name),
            ("hostname", &hostname),
            ("port", "22"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "ssh_key"),
            ("ssh_key_source", "existing"),
            ("ssh_public_key", new.public_openssh.as_str()),
            ("ssh_private_key", new.private_openssh.as_str()),
        ])
        .await;

    assert_status(&response, 303);
    let cfg = read_asset_by_uuid(&mut conn, asset.uuid)
        .await
        .unwrap()
        .connection_config;
    assert_eq!(
        cfg.get("ssh_public_key").and_then(|v| v.as_str()).map(ssh_pubkey_body),
        Some(ssh_pubkey_body(&new.public_openssh)),
        "the rotated public key must be stored"
    );
    assert_eq!(
        cfg.get("ssh_pubkey_pushed").and_then(|v| v.as_bool()),
        Some(false),
        "rotating the key must reset the pushed flag (the new key is not on the target yet)"
    );
}

// =============================================================================
// END-TO-END navigation
// =============================================================================

/// E2E: create a `generated`-source SSH key asset, then follow the flow to
/// the detail page and the edit page. The edit page must render the SSH key
/// pair card, the stored public key, and the Test / Push actions.
#[tokio::test]
#[serial]
async fn e2e_create_generated_then_navigate_detail_and_edit() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("e2e_gen_nav")).await;
    let csrf = app.generate_csrf_token();
    let hostname = format!("{}.e2e.test", unique_name("host"));

    // Step 1: create.
    let create = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &unique_name("e2e-gen")),
            ("hostname", &hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "ssh_key"),
            ("ssh_key_source", "generated"),
        ])
        .await;
    assert_status(&create, 303);

    let asset = read_asset_by_triplet(&mut conn, &hostname, 22, "root")
        .await
        .expect("generated SSH asset must persist");
    let stored_pubkey = asset
        .connection_config
        .get("ssh_public_key")
        .and_then(|v| v.as_str())
        .expect("a generated asset carries a public key")
        .to_string();

    // Step 2: detail page resolves.
    let detail = app
        .server
        .get(&format!("/assets/manage/{}", asset.uuid))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&detail, 200);

    // Step 3: edit page renders the key-pair card + actions + public key.
    let edit = app
        .server
        .get(&format!("/assets/manage/{}/edit", asset.uuid))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&edit, 200);
    let body = edit.text();
    assert!(
        body.contains("data-testid=\"ssh-key-pair-card\""),
        "edit page must render the SSH key pair card"
    );
    assert!(
        body.contains("data-testid=\"ssh-test-button\""),
        "edit page must render the Test key-based auth button"
    );
    assert!(
        body.contains("data-testid=\"ssh-push-button\""),
        "edit page must render the Push public key button"
    );
    assert!(
        body.contains(ssh_pubkey_body(&stored_pubkey).as_str()),
        "edit page must display the stored public key material"
    );
}

/// E2E + invariant #7: a hostile comment baked into an imported public key
/// must be rendered HTML-escaped on the edit page (no stored XSS). The
/// verification layer stores the key verbatim; the template auto-escaping is
/// the single chokepoint, and this test pins it end to end.
#[tokio::test]
#[serial]
async fn e2e_existing_public_key_comment_is_html_escaped_on_edit() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("e2e_xss_pub")).await;
    let csrf = app.generate_csrf_token();
    let hostname = format!("{}.e2e-xss.test", unique_name("host"));

    // A valid pair whose public key carries a hostile (space-free) comment.
    let kp = shared::ssh_keygen::generate_ed25519_keypair("").expect("keygen");
    let payload = "</pre><script>alert(document.cookie)</script>";
    let hostile_pub = format!("{} {}", kp.public_openssh.trim(), payload);

    let create = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &unique_name("e2e-xss")),
            ("hostname", &hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "ssh_key"),
            ("ssh_key_source", "existing"),
            ("ssh_public_key", hostile_pub.as_str()),
            ("ssh_private_key", kp.private_openssh.as_str()),
        ])
        .await;
    assert_status(&create, 303);

    let asset = read_asset_by_triplet(&mut conn, &hostname, 22, "root")
        .await
        .expect("asset with hostile-comment key must persist");
    // Stored verbatim (the comment is preserved; escaping happens at render).
    assert_eq!(
        asset
            .connection_config
            .get("ssh_public_key")
            .and_then(|v| v.as_str()),
        Some(hostile_pub.as_str()),
    );

    let edit = app
        .server
        .get(&format!("/assets/manage/{}/edit", asset.uuid))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&edit, 200);
    let body = edit.text();
    assert!(
        !body.contains(payload),
        "the hostile comment must NOT appear unescaped in the edit page (stored XSS)"
    );
    assert!(
        !body.contains("<script>alert(document.cookie)"),
        "no raw <script> from the key comment may reach the page"
    );
    // Askama escapes with numeric entities (`&#60;`/`&#62;`), not named ones.
    assert!(
        body.contains("&#60;script&#62;alert(document.cookie)&#60;/script&#62;"),
        "the hostile comment must be rendered HTML-escaped"
    );
}
