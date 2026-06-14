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
// INV-1: GET handlers are side-effect free + the column is gone everywhere
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
    assert!(
        !body.contains(".put("),
        "GET mfa_setup_page must not write to the candidate store (INV-1)"
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
    assert!(
        !body.contains(".put("),
        "GET /accounts/mfa must not write to the candidate store (INV-1)"
    );
}

/// The persisted candidate column is fully retired: no handler may reference
/// `pending_mfa_secret` (it no longer exists in the schema).
#[test]
fn inv1_pending_column_is_retired_from_handlers() {
    for rel in ["src/handlers/auth.rs", "src/handlers/web/users.rs"] {
        let src = read_src(rel);
        assert!(
            !src.contains("pending_mfa_secret"),
            "{rel} must not reference the retired pending_mfa_secret column (INV-1)"
        );
    }
}

// ---------------------------------------------------------------------------
// INV-2: secret generation is confined to the CSRF-gated POST
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

/// The init POST is the sole generation site, gated by CSRF. First enrolment
/// takes NO password (the double-password regression), while rotation proves
/// the current factor with a TOTP code.
#[test]
fn inv2_init_is_gated_by_csrf_and_generates() {
    let auth = read_src("src/handlers/auth.rs");
    let init = slice_fn(&auth, "pub async fn mfa_setup_init(");
    assert!(
        init.contains("validate_double_submit"),
        "init must validate CSRF (INV-2)"
    );
    assert!(
        !init.contains("verify_password"),
        "init must NOT ask for a password (first enrolment is password-free) (INV-3)"
    );
    assert!(
        init.contains("verify_totp"),
        "init must verify the current TOTP for rotation step-up (INV-3)"
    );
    assert!(
        init.contains("mfa_already_enabled"),
        "init must branch on whether MFA is already enabled (INV-3)"
    );
    assert!(
        init.contains("mfa_generate") || init.contains("generate_totp_secret"),
        "init must be the place that generates the secret (INV-2)"
    );
}

// ---------------------------------------------------------------------------
// INV-1/INV-2: candidate lives only in the per-session in-memory store
// ---------------------------------------------------------------------------

#[test]
fn inv3_init_writes_only_the_store_never_mfa_secret() {
    let auth = read_src("src/handlers/auth.rs");
    let init = slice_fn(&auth, "pub async fn mfa_setup_init(");
    assert!(
        init.contains("pending_mfa") && init.contains(".put("),
        "init must store the candidate in the in-memory store (INV-1)"
    );
    assert!(
        !init.contains("users::mfa_secret.eq("),
        "init must NOT write mfa_secret -- only the in-memory store (INV-1)"
    );
}

#[test]
fn inv2_store_is_keyed_by_session_jti() {
    let auth = read_src("src/handlers/auth.rs");
    for marker in [
        "pub async fn mfa_setup_init(",
        "pub async fn mfa_setup_submit(",
        "pub async fn mfa_setup_page(",
    ] {
        let body = slice_fn(&auth, marker);
        assert!(
            body.contains("claims.jti") || body.contains("session_jti"),
            "{marker} must key the candidate store on the session jti (INV-2)"
        );
    }
}

#[test]
fn inv3_confirm_promotes_and_evicts_from_store() {
    let auth = read_src("src/handlers/auth.rs");
    let confirm = slice_fn(&auth, "pub async fn mfa_setup_submit(");
    assert!(
        confirm.contains("users::mfa_secret.eq("),
        "confirm must promote the secret to mfa_secret (INV-1)"
    );
    assert!(
        confirm.contains("pending_mfa") && confirm.contains(".get("),
        "confirm must read the candidate from the in-memory store (INV-1)"
    );
    assert!(
        confirm.contains(".evict("),
        "confirm must evict the candidate from the store after enrolment (INV-1)"
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
