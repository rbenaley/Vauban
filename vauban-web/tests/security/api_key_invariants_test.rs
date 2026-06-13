//! VAUBAN Web - API key invariants (source pins) for VAU-007.
//!
//! These are drift guards on the source itself (not runtime behavior),
//! complementing the HTTP E2E suite in
//! `tests/api/api_key_auth_test.rs`. They fail fast if a future refactor
//! quietly breaks one of the four invariants.

use std::fs;
use std::path::PathBuf;

fn read_src(rel: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// INV-4 (single seam): the API key lookup (`ApiKey::hash_key` /
/// `api_keys.key_hash`) lives ONLY in `middleware/api_key.rs`. No
/// `/api/v1/*` handler may re-implement credential parsing/lookup.
#[test]
fn inv4_api_key_lookup_is_a_single_seam() {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("src/handlers/api");

    for entry in fs::read_dir(&dir).expect("read src/handlers/api") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let body = fs::read_to_string(&path).expect("read handler source");
        assert!(
            !body.contains("hash_key"),
            "{}: API handlers must not call ApiKey::hash_key -- the key seam \
             is middleware/api_key.rs (INV-4)",
            path.display()
        );
        assert!(
            !body.contains("key_hash"),
            "{}: API handlers must not query api_keys.key_hash -- the key seam \
             is middleware/api_key.rs (INV-4)",
            path.display()
        );
    }
}

/// INV-4 (single seam, positive side): the seam DOES resolve the key in
/// `middleware/api_key.rs`.
#[test]
fn inv4_seam_resolves_the_key_hash() {
    let seam = read_src("src/middleware/api_key.rs");
    assert!(
        seam.contains("ApiKey::hash_key"),
        "the api_key middleware must be the place that hashes the raw key"
    );
    assert!(
        seam.contains("key_hash.eq"),
        "the api_key middleware must be the place that looks up api_keys.key_hash"
    );
}

/// INV-1 (M2M-only): `auth_middleware` short-circuits the `/api/` zone to
/// the API-key-only branch and `return`s BEFORE any JWT extraction, so a
/// human token never authenticates an API request.
#[test]
fn inv1_api_zone_returns_before_jwt_path() {
    let auth = read_src("src/middleware/auth.rs");

    let api_branch = auth
        .find("starts_with(\"/api/\")")
        .expect("auth_middleware must special-case the /api/ zone");
    let return_branch = auth
        .find("return Ok(api_key_auth(")
        .expect("auth_middleware must delegate the /api/ zone to api_key_auth and return");
    let jwt_extract = auth
        .find("extract_token_with_source(&jar")
        .expect("auth_middleware must still extract the JWT for the web/ws path");

    assert!(
        api_branch < return_branch && return_branch < jwt_extract,
        "the /api/ API-key-only branch must run and return BEFORE the JWT extraction \
         (INV-1: no human JWT on the API)"
    );
}

/// INV-1 (reciprocal): the key extractor only accepts a `Bearer` token
/// carrying the `vbn_` prefix, so a human JWT is never parsed as a key.
#[test]
fn inv1_extractor_requires_vbn_prefix_on_bearer() {
    let seam = read_src("src/middleware/api_key.rs");
    assert!(
        seam.contains("API_KEY_PREFIX") && seam.contains("\"vbn_\""),
        "extract_api_key must gate the Bearer form on the vbn_ prefix"
    );
    assert!(
        seam.contains("token.starts_with(API_KEY_PREFIX)"),
        "extract_api_key must reject a Bearer that is not a vbn_ key"
    );
}

/// VAU-007 hardening: the bare `AuthUser` extractor refuses a
/// half-authenticated (pre-MFA) principal. Closes the residual MFA-bypass
/// on the web action handlers that consume `AuthUser` directly.
#[test]
fn auth_user_extractor_requires_mfa_verified() {
    let auth = read_src("src/middleware/auth.rs");
    assert!(
        auth.contains("Some(user) if user.mfa_verified => Ok(user)"),
        "AuthUser::from_request_parts must accept only mfa_verified principals"
    );
}

/// INV-3 (scope <= role): the scope layer is the gate and the admin zone
/// is mapped to the `admin` scope.
#[test]
fn inv3_scope_layer_maps_admin_zone() {
    let seam = read_src("src/middleware/api_key.rs");
    assert!(
        seam.contains("fn api_scope_enforcement"),
        "the scope enforcement layer must exist"
    );
    assert!(
        seam.contains("/api/v1/accounts") && seam.contains("/assets/manage"),
        "required_scope must map the accounts and assets/manage zones to admin"
    );
}
