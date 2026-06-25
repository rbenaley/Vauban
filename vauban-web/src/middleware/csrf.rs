/// VAUBAN Web - CSRF protection helpers.
///
/// Implements signed CSRF tokens using HMAC-SHA3-256 and a double-submit cookie.
use axum_extra::extract::cookie::{Cookie, SameSite};
use hkdf::hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use secrecy::ExposeSecret;
use sha3::Sha3_256;
use time::Duration;

/// Type alias for HMAC-SHA3-256.
type HmacSha3 = Hmac<Sha3_256>;

/// Cookie name for CSRF tokens.
pub const CSRF_COOKIE_NAME: &str = "__vauban_csrf";

/// Generate a signed CSRF token (token.signature).
pub fn generate_csrf_token(secret_key: &[u8]) -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = base64_encode_bytes(&bytes);
    let signature = sign(secret_key, token.as_bytes());
    format!("{}.{}", token, signature)
}

/// Build the CSRF cookie with secure defaults.
pub fn build_csrf_cookie(token: &str) -> Cookie<'static> {
    Cookie::build((CSRF_COOKIE_NAME, token.to_string()))
        .path("/")
        .http_only(false)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(Duration::hours(1))
        .build()
}

/// Verify a signed CSRF token.
pub fn verify_csrf_token(secret_key: &[u8], token: &str) -> bool {
    let parts: Vec<&str> = token.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return false;
    }
    let signature = parts[0];
    let value = parts[1];
    let expected = sign(secret_key, value.as_bytes());
    constant_time_compare(signature, &expected)
}

/// Validate a double-submit CSRF token (cookie == form, signature valid).
pub fn validate_double_submit(
    secret_key: &[u8],
    cookie_value: Option<&str>,
    form_value: &str,
) -> bool {
    if cookie_value != Some(form_value) {
        return false;
    }
    verify_csrf_token(secret_key, form_value)
}

/// Middleware to ensure a CSRF cookie exists on responses.
///
/// Only adds a cookie if ALL of the following hold:
/// 1. The incoming request doesn't have a valid CSRF cookie, AND
/// 2. The response is an HTML **document** (`Content-Type: text/html`), AND
/// 3. The handler hasn't already set a CSRF cookie in the response.
///
/// Condition (2) is the fix for the recurring "Invalid or expired form"
/// bug on the login page. A cold page load fires several concurrent
/// requests -- the HTML document PLUS `favicon.ico`, CSS, JS, ... -- and
/// the early subresources (notably the speculative favicon fetch) often
/// race ahead of the document's `Set-Cookie` being stored. If every
/// cookie-less request were allowed to mint its own random token, the
/// last `Set-Cookie` the browser happens to process would clobber the
/// token embedded in the login HTML, desynchronising the double-submit
/// pair (`__vauban_csrf` cookie vs. the form's hidden field) and failing
/// the very first sign-in. Restricting minting to `text/html` responses
/// guarantees that only the page the user is actually looking at
/// establishes the cookie, and that cookie always matches the token
/// rendered into that page. Static assets, images, JSON and redirects
/// never touch the cookie, so they can no longer clobber it.
///
/// Condition (3) prevents conflicts where both middleware and handler
/// generate different tokens (the login page mints + sets its own).
pub async fn csrf_cookie_middleware(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let jar = axum_extra::extract::CookieJar::from_headers(req.headers());
    let secret = state.config.secret_key.expose_secret().as_bytes();

    // Check if request already has a valid CSRF cookie
    let needs_cookie = jar
        .get(CSRF_COOKIE_NAME)
        .map(|c| c.value())
        .filter(|val| verify_csrf_token(secret, val))
        .is_none();

    let response = next.run(req).await;

    // Only mint on HTML documents (see condition 2 above) so a racing
    // favicon / static-asset response can never overwrite the token the
    // login page just embedded.
    let is_html_document = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/html"));

    // Only add cookie if request didn't have one, the response is an HTML
    // document, AND the handler didn't already set one.
    if needs_cookie && is_html_document {
        // Check if the handler already set a CSRF cookie in the response
        let handler_set_cookie = response
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .any(|v| {
                v.to_str()
                    .map(|s| s.starts_with(CSRF_COOKIE_NAME))
                    .unwrap_or(false)
            });

        if !handler_set_cookie {
            // Handler didn't set a CSRF cookie, so we add one
            let token = generate_csrf_token(secret);
            let cookie = build_csrf_cookie(&token);
            let mut response = response;
            if let Ok(value) = cookie.to_string().parse() {
                response
                    .headers_mut()
                    .append(axum::http::header::SET_COOKIE, value);
            }
            return response;
        }
    }

    response
}

/// Sign data using HMAC-SHA3-256.
fn sign(secret_key: &[u8], data: &[u8]) -> String {
    // SAFETY: HMAC accepts any key size per RFC 2104
    #[allow(clippy::expect_used)]
    let mut mac = HmacSha3::new_from_slice(secret_key).expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

// Base64 encoding helpers (URL-safe)
fn base64_encode_bytes(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

// constant_time_compare deduplicated - use crate::crypto::constant_time_compare_str
use crate::crypto::constant_time_compare_str as constant_time_compare;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_verify_token() {
        let secret = b"test-secret";
        let token = generate_csrf_token(secret);
        assert!(verify_csrf_token(secret, &token));
    }

    #[test]
    fn test_verify_token_invalid_signature() {
        let secret = b"test-secret";
        let token = generate_csrf_token(secret);
        let tampered = format!("{}{}", &token[..token.len() - 2], "aa");
        assert!(!verify_csrf_token(secret, &tampered));
    }

    #[test]
    fn test_verify_token_invalid_format() {
        let secret = b"test-secret";
        assert!(!verify_csrf_token(secret, "no-dot-token"));
    }
}
