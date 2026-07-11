//! API-key creation form — source-level structural pins.
//!
//! Regression 2026-07-11: the Create API Key modal silently did nothing
//! because `axum::extract::Form` (serde_urlencoded) 422-rejected the
//! browser body BEFORE the handler ran, on two legitimate shapes:
//!
//! - repeated keys from the scope checkboxes (`scopes=read&scopes=secrets`),
//! - the empty `expires_in_days=` posted by the "Never" expiry option.
//!
//! The fix parses the raw body via `CreateApiKeyForm::from_bytes`. These
//! pins make the three load-bearing choices structural so a future
//! refactor cannot silently reintroduce the 422:
//!
//! 1. the handler consumes `axum::body::Bytes` + `from_bytes`, never the
//!    `Form` extractor;
//! 2. posted scopes are whitelisted through `ApiKeyScope::parse` before
//!    landing in the JSONB column;
//! 3. every checkbox `value` in the template is a valid `ApiKeyScope`
//!    wire form (template <-> enum lock-step), and the dedicated
//!    `secrets` scope stays exposed.

use vauban_web::models::api_key::ApiKeyScope;

/// Extract the body of `pub async fn create_api_key(` (up to the next
/// top-level `pub async fn`) from the users handler source.
fn create_api_key_fn_body() -> String {
    let src = include_str!("../../src/handlers/web/users.rs");
    let start = src
        .find("pub async fn create_api_key(")
        .expect("users.rs must define create_api_key");
    let rest = &src[start..];
    let end = rest[1..]
        .find("\npub async fn ")
        .map(|i| i + 1)
        .unwrap_or(rest.len());
    rest[..end].to_string()
}

// =============================================================================
// 1. Extractor pin: raw body, never serde_urlencoded
// =============================================================================

#[test]
fn create_api_key_parses_raw_body_not_form_extractor() {
    let body = create_api_key_fn_body();

    assert!(
        body.contains("body: axum::body::Bytes"),
        "create_api_key must consume the raw body (axum::body::Bytes): \
         serde_urlencoded cannot collect repeated `scopes` keys nor an \
         empty `expires_in_days=` and 422s before the handler runs"
    );
    assert!(
        body.contains("CreateApiKeyForm::from_bytes(&body)"),
        "create_api_key must parse the body via CreateApiKeyForm::from_bytes"
    );

    // Forbidden token built via format! so this file never self-matches.
    let forbidden = format!("Form<{}>", "CreateApiKeyForm");
    assert!(
        !body.contains(&forbidden),
        "create_api_key must NOT go back to the axum Form extractor \
         (the exact regression that killed the Create modal)"
    );
}

// =============================================================================
// 2. Whitelist pin: scopes go through ApiKeyScope::parse
// =============================================================================

#[test]
fn create_api_key_whitelists_scopes_through_apikeyscope_parse() {
    let body = create_api_key_fn_body();
    assert!(
        body.contains("ApiKeyScope::parse"),
        "create_api_key must filter posted scopes through \
         ApiKeyScope::parse so arbitrary strings never land in the \
         JSONB scopes column"
    );
}

// =============================================================================
// 3. Template <-> enum lock-step
// =============================================================================

/// Every `value="..."` carried by a `name="scopes"` checkbox in the
/// creation form must be a valid `ApiKeyScope` wire form. Otherwise the
/// checkbox would render but its value would be silently dropped by the
/// whitelist — a UI lying to the operator.
#[test]
fn template_scope_checkbox_values_all_parse_as_apikeyscope() {
    let html = include_str!("../../templates/accounts/apikey_create_form.html");

    let mut found = Vec::new();
    for chunk in html.split("<input").skip(1) {
        if !chunk.contains("name=\"scopes\"") {
            continue;
        }
        let value = chunk
            .split("value=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("every scopes checkbox must carry a value attribute");
        assert!(
            ApiKeyScope::parse(value).is_some(),
            "checkbox value {value:?} is not a valid ApiKeyScope wire form; \
             it would be silently dropped by the create_api_key whitelist"
        );
        found.push(value.to_string());
    }

    assert!(
        !found.is_empty(),
        "the creation form must expose at least one scopes checkbox"
    );
    assert!(
        found.iter().any(|v| v == ApiKeyScope::Secrets.as_str()),
        "the dedicated `secrets` scope must stay exposed in the creation \
         form: it is the only way to mint a key for the /api/v1/vault/* \
         M2M surface"
    );
}
