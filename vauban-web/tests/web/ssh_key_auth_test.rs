//! SSH key-authentication redesign -- structural + behavioural pins.
//!
//! This file plays the role `rdp_cert_lints_test.rs` plays for VAU-001:
//! it (a) runs the `check_ssh_key_auth_paths.sh` structural lint from
//! `cargo test` so a developer trips the #4 invariants without shelling
//! out manually, and (b) pins the deterministic, no-proxy-required
//! pre-flight behaviour of the `push-public-key` / `test-key-auth`
//! admin handlers at the HTTP layer.
//!
//! The full happy-path (real SSH server + in-process Vault + proxy) is
//! covered by the unit suites it would otherwise duplicate
//! (`shared::ssh_keygen` for keygen + public-key derivation,
//! `shared::messages` for the SshSessionOpen / Push / Test wire
//! round-trips, `vauban-proxy-ssh::vault` for the decrypt-only client,
//! `vauban-web` lib for `compute_updated_connection_config`) plus the
//! create/edit integration tests in `asset_protocol_test.rs`.

use std::path::PathBuf;
use std::process::Command;

use crate::common::TestApp;
use crate::fixtures::{create_admin_user, create_test_user, unique_name};
use axum::http::header::COOKIE;
use serial_test::serial;

fn auth_csrf_cookie(token: &str, csrf: &str) -> String {
    format!("access_token={}; __vauban_csrf={}", token, csrf)
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn script_path() -> PathBuf {
    manifest_dir()
        .join("scripts")
        .join("check_ssh_key_auth_paths.sh")
}

// =============================================================================
// Lint wrapper -- 3 tests
// =============================================================================

/// The structural lint must pass on the current tree.
#[test]
fn check_ssh_key_auth_paths_passes() {
    let script = script_path();
    assert!(
        script.exists(),
        "lint script not found: {}",
        script.display()
    );

    let out = Command::new("bash")
        .arg(&script)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {}", script.display(), e));

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "check_ssh_key_auth_paths.sh failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// The script must exist and keep its executable bit (CI invokes
/// `bash scripts/*.sh`, so a dropped chmod is otherwise invisible until
/// a contributor runs it directly).
#[test]
fn ssh_key_auth_lint_script_exists_and_executable() {
    use std::os::unix::fs::PermissionsExt;
    let path = script_path();
    assert!(path.exists(), "missing lint script: {}", path.display());
    let meta = std::fs::metadata(&path).expect("metadata");
    let mode = meta.permissions().mode();
    assert!(
        mode & 0o111 != 0,
        "lint script not executable: {} (mode={:o})",
        path.display(),
        mode
    );
}

/// The script body must keep guarding the #4 core invariants. A future
/// cleanup that loosens these greps must update this list deliberately.
#[test]
fn ssh_key_auth_lint_script_covers_core_invariants() {
    let body = std::fs::read_to_string(script_path()).expect("read script");
    for needle in [
        "password_ciphertext",
        "private_key_ciphertext",
        "passphrase_ciphertext",
        "SshPushPublicKey",
        "SshTestKeyAuth",
        "VaultDecryptClient",
        "build_credential_via_vault",
        "Pin the SSH host key first",
        r"\.decrypt\(",
    ] {
        assert!(
            body.contains(needle),
            "check_ssh_key_auth_paths.sh must still reference `{needle}` -- \
             removing the grep loosens a #4 SSH key-auth invariant."
        );
    }
}

// =============================================================================
// Handler pre-flight -- HTTP-layer pins (no proxy required)
// =============================================================================

/// Extract the toast message an `htmx_error_response` carried in the
/// `HX-Trigger` header. The body is intentionally empty; the operator
/// feedback rides on the header.
fn hx_trigger(response: &axum_test::TestResponse) -> String {
    response
        .headers()
        .get("HX-Trigger")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Anti-enumeration: the `/assets/manage/*` route_layer fences the whole
/// sub-tree, so a non-admin gets 403 BEFORE the push handler (and before
/// any DB lookup that could leak asset existence).
#[tokio::test]
#[serial]
async fn push_public_key_non_admin_is_forbidden_at_routing_layer() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("ssh_push_user")).await;
    let csrf = app.generate_csrf_token();
    let any_uuid = uuid::Uuid::new_v4();

    let response = app
        .server
        .post(&format!("/assets/manage/{}/push-public-key", any_uuid))
        .add_header(COOKIE, auth_csrf_cookie(&user.token, &csrf))
        .form(&[("csrf_token", csrf.as_str()), ("password", "irrelevant")])
        .await;

    assert_eq!(
        response.status_code().as_u16(),
        403,
        "a non-admin must be fenced at the routing layer, not reach the handler"
    );
}

#[tokio::test]
#[serial]
async fn test_key_auth_non_admin_is_forbidden_at_routing_layer() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("ssh_test_user")).await;
    let csrf = app.generate_csrf_token();
    let any_uuid = uuid::Uuid::new_v4();

    let response = app
        .server
        .post(&format!("/assets/manage/{}/test-key-auth", any_uuid))
        .add_header(COOKIE, auth_csrf_cookie(&user.token, &csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;

    assert_eq!(response.status_code().as_u16(), 403);
}

/// An admin with a bad CSRF token is rejected with the standard toast
/// before any side effect.
#[tokio::test]
#[serial]
async fn push_public_key_rejects_invalid_csrf() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("ssh_push_csrf")).await;
    let good_csrf = app.generate_csrf_token();
    let any_uuid = uuid::Uuid::new_v4();

    // Cookie carries a valid CSRF value, but the form token is garbage:
    // the double-submit check fails.
    let response = app
        .server
        .post(&format!("/assets/manage/{}/push-public-key", any_uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &good_csrf))
        .form(&[("csrf_token", "forged-token"), ("password", "irrelevant")])
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    assert!(
        hx_trigger(&response).contains("Invalid CSRF token"),
        "expected an Invalid CSRF toast, got: {}",
        hx_trigger(&response)
    );
}

/// Push requires the one-shot password (it authenticates by password to
/// install the key). An empty password is refused before contacting the
/// proxy.
#[tokio::test]
#[serial]
async fn push_public_key_requires_password() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("ssh_push_nopwd")).await;
    let csrf = app.generate_csrf_token();
    let any_uuid = uuid::Uuid::new_v4();

    let response = app
        .server
        .post(&format!("/assets/manage/{}/push-public-key", any_uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[("csrf_token", csrf.as_str()), ("password", "")])
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    assert!(
        hx_trigger(&response).contains("password is required"),
        "expected a password-required toast, got: {}",
        hx_trigger(&response)
    );
}

/// A malformed UUID is rejected with a dedicated message (and never
/// reaches the DB), pinning the URL-type contract.
#[tokio::test]
#[serial]
async fn push_public_key_rejects_invalid_uuid() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("ssh_push_uuid")).await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post("/assets/manage/not-a-uuid/push-public-key")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[("csrf_token", csrf.as_str()), ("password", "secret")])
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    assert!(
        hx_trigger(&response).contains("Invalid asset identifier"),
        "expected an invalid-identifier toast, got: {}",
        hx_trigger(&response)
    );
}

/// In the test harness `ssh_proxy = None`. The handler must fail closed
/// with a clear toast rather than panicking or silently succeeding.
#[tokio::test]
#[serial]
async fn push_public_key_without_proxy_fails_closed() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("ssh_push_noproxy"),
    )
    .await;
    let csrf = app.generate_csrf_token();
    let any_uuid = uuid::Uuid::new_v4();

    let response = app
        .server
        .post(&format!("/assets/manage/{}/push-public-key", any_uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[("csrf_token", csrf.as_str()), ("password", "secret")])
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    assert!(
        hx_trigger(&response).contains("SSH proxy not available"),
        "expected a proxy-unavailable toast, got: {}",
        hx_trigger(&response)
    );
}

#[tokio::test]
#[serial]
async fn test_key_auth_without_proxy_fails_closed() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("ssh_test_noproxy"),
    )
    .await;
    let csrf = app.generate_csrf_token();
    let any_uuid = uuid::Uuid::new_v4();

    let response = app
        .server
        .post(&format!("/assets/manage/{}/test-key-auth", any_uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    assert!(
        hx_trigger(&response).contains("SSH proxy not available"),
        "expected a proxy-unavailable toast, got: {}",
        hx_trigger(&response)
    );
}
