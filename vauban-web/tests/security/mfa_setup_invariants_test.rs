//! VAUBAN Web - MFA setup invariants (source pins) for VAU-008.
//!
//! Drift guards on the source itself (not runtime behaviour), complementing
//! the HTTP E2E suite in `tests/web/mfa_setup_vau008_test.rs`. They fail fast
//! if a future refactor reintroduces a side effect on the GET path or moves
//! secret generation out of the CSRF + step-up POST.

use std::fs;
use std::path::PathBuf;

fn read_src(rel: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Extract the body of a single function: everything from `start_marker` up to
/// (but excluding) the next `async fn ` boundary, which delimits the following
/// item. Good enough to scope grep-style assertions to one handler.
fn slice_fn(src: &str, start_marker: &str) -> String {
    let start = src
        .find(start_marker)
        .unwrap_or_else(|| panic!("marker not found: {start_marker}"));
    let after = start + start_marker.len();
    let end_rel = src[after..]
        .find("async fn ")
        .map(|i| after + i)
        .unwrap_or(src.len());
    src[start..end_rel].to_string()
}

// ---------------------------------------------------------------------------
// INV-1: GET handlers are side-effect free
// ---------------------------------------------------------------------------

#[test]
fn inv1_get_mfa_setup_page_has_no_db_write() {
    let src = read_src("src/handlers/auth.rs");
    let body = slice_fn(&src, "pub async fn mfa_setup_page(");
    assert!(
        !body.contains("diesel::update"),
        "GET mfa_setup_page must not perform any diesel::update (INV-1)"
    );
    assert!(
        !body.contains("diesel::insert_into"),
        "GET mfa_setup_page must not insert (INV-1)"
    );
}

#[test]
fn inv1_get_accounts_mfa_has_no_db_write() {
    let src = read_src("src/handlers/web/users.rs");
    let body = slice_fn(&src, "pub async fn mfa_setup(");
    assert!(
        !body.contains("diesel::update"),
        "GET /accounts/mfa (mfa_setup) must not perform any diesel::update (INV-1)"
    );
    assert!(
        !body.contains("diesel::insert_into"),
        "GET /accounts/mfa (mfa_setup) must not insert (INV-1)"
    );
}

// ---------------------------------------------------------------------------
// INV-2: secret generation is confined to the CSRF + step-up POST
// ---------------------------------------------------------------------------

#[test]
fn inv2_get_handlers_never_generate_a_secret() {
    let auth = read_src("src/handlers/auth.rs");
    let users = read_src("src/handlers/web/users.rs");
    for (name, body) in [
        (
            "mfa_setup_page",
            slice_fn(&auth, "pub async fn mfa_setup_page("),
        ),
        ("mfa_setup", slice_fn(&users, "pub async fn mfa_setup(")),
    ] {
        assert!(
            !body.contains("mfa_generate"),
            "GET {name} must not call vault.mfa_generate (INV-2)"
        );
        assert!(
            !body.contains("generate_totp_secret"),
            "GET {name} must not call generate_totp_secret (INV-2)"
        );
    }
}

#[test]
fn inv2_init_is_gated_by_csrf_and_password_stepup() {
    let auth = read_src("src/handlers/auth.rs");
    let init = slice_fn(&auth, "pub async fn mfa_setup_init(");
    assert!(
        init.contains("validate_double_submit"),
        "init must validate CSRF (INV-2)"
    );
    assert!(
        init.contains("verify_password"),
        "init must enforce a password step-up (INV-2)"
    );
    assert!(
        init.contains("mfa_generate") || init.contains("generate_totp_secret"),
        "init must be the place that generates the secret (INV-2)"
    );
}

// ---------------------------------------------------------------------------
// INV-3: pending isolation; mfa_secret promoted only on confirm
// ---------------------------------------------------------------------------

#[test]
fn inv3_init_writes_only_pending() {
    let auth = read_src("src/handlers/auth.rs");
    let init = slice_fn(&auth, "pub async fn mfa_setup_init(");
    assert!(
        init.contains("pending_mfa_secret.eq("),
        "init must write the pending secret (INV-3)"
    );
    assert!(
        !init.contains("users::mfa_secret.eq("),
        "init must NOT write mfa_secret -- only pending_mfa_secret (INV-3)"
    );
}

#[test]
fn inv3_confirm_promotes_and_clears_pending() {
    let auth = read_src("src/handlers/auth.rs");
    let confirm = slice_fn(&auth, "pub async fn mfa_setup_submit(");
    assert!(
        confirm.contains("users::mfa_secret.eq("),
        "confirm must promote the secret to mfa_secret (INV-3)"
    );
    assert!(
        confirm.contains("pending_mfa_secret.eq(None"),
        "confirm must clear the pending secret (INV-3)"
    );
    // The candidate is read from pending, never from mfa_secret.
    assert!(
        confirm.contains("pending_mfa_secret"),
        "confirm must read the candidate from pending_mfa_secret (INV-3)"
    );
}

// ---------------------------------------------------------------------------
// INV-4: auditability + routing
// ---------------------------------------------------------------------------

#[test]
fn inv4_init_emits_generation_audit_event() {
    let auth = read_src("src/handlers/auth.rs");
    let init = slice_fn(&auth, "pub async fn mfa_setup_init(");
    assert!(
        init.contains("AuditEventType::MfaSecretGenerated"),
        "init must emit MfaSecretGenerated (INV-4)"
    );
}

#[test]
fn init_route_is_wired() {
    let main = read_src("src/main.rs");
    assert!(
        main.contains("/mfa/setup/init") && main.contains("mfa_setup_init"),
        "POST /mfa/setup/init must be routed to handlers::auth::mfa_setup_init"
    );
}
