/// VAUBAN Web - Flash messages middleware.
///
/// Implements flash messages using signed cookies (HMAC-SHA256).
/// Flash messages are stored in a cookie and cleared after being read.
use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, IntoResponseParts, Response, ResponseParts},
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use hkdf::hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use time::Duration;

/// Type alias for HMAC-SHA3-256.
type HmacSha3 = Hmac<Sha3_256>;

/// Cookie name for flash messages.
const FLASH_COOKIE_NAME: &str = "__vauban_flash";

/// Flash message structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlashMessage {
    /// Message level: "success", "error", "warning", "info".
    pub level: String,
    /// Message content.
    pub message: String,
}

impl FlashMessage {
    /// Create a success flash message.
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            level: "success".to_string(),
            message: message.into(),
        }
    }

    /// Create an error flash message.
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            level: "error".to_string(),
            message: message.into(),
        }
    }

    /// Create a warning flash message.
    pub fn warning(message: impl Into<String>) -> Self {
        Self {
            level: "warning".to_string(),
            message: message.into(),
        }
    }

    /// Create an info flash message.
    pub fn info(message: impl Into<String>) -> Self {
        Self {
            level: "info".to_string(),
            message: message.into(),
        }
    }
}

/// Flash messages container for responses.
/// Use this to add flash messages that will be available on the next request.
#[derive(Debug, Clone)]
pub struct Flash {
    messages: Vec<FlashMessage>,
    secret_key: Vec<u8>,
}

impl Flash {
    /// Create a new Flash with a secret key.
    pub fn new(secret_key: &[u8]) -> Self {
        Self {
            messages: Vec::new(),
            secret_key: secret_key.to_vec(),
        }
    }

    /// Add a success message.
    pub fn success(mut self, message: impl Into<String>) -> Self {
        self.messages.push(FlashMessage::success(message));
        self
    }

    /// Add an error message.
    pub fn error(mut self, message: impl Into<String>) -> Self {
        self.messages.push(FlashMessage::error(message));
        self
    }

    /// Add a warning message.
    pub fn warning(mut self, message: impl Into<String>) -> Self {
        self.messages.push(FlashMessage::warning(message));
        self
    }

    /// Add an info message.
    pub fn info(mut self, message: impl Into<String>) -> Self {
        self.messages.push(FlashMessage::info(message));
        self
    }

    /// Sign a message using HMAC-SHA3-256.
    fn sign(&self, data: &[u8]) -> String {
        // SAFETY: HMAC accepts any key size per RFC 2104
        #[allow(clippy::expect_used)]
        let mut mac =
            HmacSha3::new_from_slice(&self.secret_key).expect("HMAC can take key of any size");
        mac.update(data);
        let result = mac.finalize();
        hex::encode(result.into_bytes())
    }

    /// Create a signed cookie value.
    fn create_signed_value(&self) -> Option<String> {
        if self.messages.is_empty() {
            return None;
        }

        let json = serde_json::to_string(&self.messages).ok()?;
        let signature = self.sign(json.as_bytes());
        // Format: base64(json).signature
        let encoded = base64_encode(&json);
        Some(format!("{}.{}", encoded, signature))
    }
}

impl IntoResponseParts for Flash {
    type Error = std::convert::Infallible;

    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        if let Some(signed_value) = self.create_signed_value() {
            let cookie = Cookie::build((FLASH_COOKIE_NAME, signed_value))
                .path("/")
                .http_only(true)
                .secure(true)
                .same_site(SameSite::Lax)
                .max_age(Duration::seconds(30)) // Short TTL
                .build();

            if let Ok(header_value) = cookie.to_string().parse() {
                res.headers_mut()
                    .append(axum::http::header::SET_COOKIE, header_value);
            }
        }
        Ok(res)
    }
}

/// Incoming flash messages extractor.
/// Extracts flash messages from the request and clears the cookie.
#[derive(Debug, Clone)]
pub struct IncomingFlash {
    /// The flash messages from the previous request.
    pub messages: Vec<FlashMessage>,
    /// Secret key for creating new flash messages.
    secret_key: Vec<u8>,
}

impl IncomingFlash {
    /// Get the flash messages.
    pub fn messages(&self) -> &[FlashMessage] {
        &self.messages
    }

    /// Check if there are any messages.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Check if there are any error messages.
    pub fn has_errors(&self) -> bool {
        self.messages.iter().any(|m| m.level == "error")
    }

    /// Get error messages only.
    pub fn errors(&self) -> Vec<&FlashMessage> {
        self.messages
            .iter()
            .filter(|m| m.level == "error")
            .collect()
    }

    /// Get success messages only.
    pub fn successes(&self) -> Vec<&FlashMessage> {
        self.messages
            .iter()
            .filter(|m| m.level == "success")
            .collect()
    }

    /// Create a new Flash for adding messages to the response.
    pub fn flash(&self) -> Flash {
        Flash::new(&self.secret_key)
    }

    /// Verify a signed cookie value.
    fn verify_and_decode(secret_key: &[u8], signed_value: &str) -> Option<Vec<FlashMessage>> {
        // Format: base64(json).signature
        let parts: Vec<&str> = signed_value.rsplitn(2, '.').collect();
        if parts.len() != 2 {
            return None;
        }

        let signature = parts[0];
        let encoded = parts[1];

        // Decode base64
        let json = base64_decode(encoded)?;

        // Verify signature
        // SAFETY: HMAC accepts any key size per RFC 2104
        #[allow(clippy::expect_used)]
        let mut mac = HmacSha3::new_from_slice(secret_key).expect("HMAC can take key of any size");
        mac.update(json.as_bytes());

        let expected_signature = hex::encode(mac.finalize().into_bytes());
        if !constant_time_compare(signature, &expected_signature) {
            return None;
        }

        // Parse JSON
        serde_json::from_str(&json).ok()
    }
}

impl<S> FromRequestParts<S> for IncomingFlash
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Get secret key from extensions (set by middleware)
        let secret_key = parts
            .extensions
            .get::<FlashSecretKey>()
            .map(|k| k.0.clone())
            .unwrap_or_default();

        // Extract cookies from headers
        let cookies = parts
            .headers
            .get_all(axum::http::header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|s| s.split(';'))
            .map(|s| s.trim())
            .collect::<Vec<_>>();

        // Find flash cookie
        let flash_value = cookies
            .iter()
            .filter_map(|c| {
                let (name, value) = c.split_once('=')?;
                if name.trim() == FLASH_COOKIE_NAME {
                    Some(value.trim().to_string())
                } else {
                    None
                }
            })
            .next();

        let messages = flash_value
            .and_then(|v| IncomingFlash::verify_and_decode(&secret_key, &v))
            .unwrap_or_default();

        Ok(IncomingFlash {
            messages,
            secret_key,
        })
    }
}

/// Response type that clears the flash cookie.
///
/// **Usually unnecessary**: `flash_middleware` already clears the
/// cookie on every GET that arrived with one, so handlers do not have
/// to remember this. Kept as a public API for the rare case where a
/// handler wants to force the cleanup unconditionally (e.g. during
/// logout, before the auth middleware drops the session). The
/// middleware detects an existing `Set-Cookie` and skips its own
/// cleanup, so combining the two is safe and produces a single header.
pub struct ClearFlashCookie;

impl IntoResponseParts for ClearFlashCookie {
    type Error = std::convert::Infallible;

    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        // Clear the flash cookie by setting it to empty with immediate expiry
        let cookie = Cookie::build((FLASH_COOKIE_NAME, ""))
            .path("/")
            .http_only(true)
            .secure(true)
            .same_site(SameSite::Lax)
            .max_age(Duration::ZERO)
            .build();

        if let Ok(header_value) = cookie.to_string().parse() {
            res.headers_mut()
                .append(axum::http::header::SET_COOKIE, header_value);
        }
        Ok(res)
    }
}

/// Secret key for flash message signing.
/// Add this to request extensions via middleware.
#[derive(Clone)]
pub struct FlashSecretKey(pub Vec<u8>);

/// Flash middleware.
///
/// Two responsibilities:
///
/// 1. Inject the signing secret into request extensions so the
///    `IncomingFlash` extractor can verify the cookie.
/// 2. Enforce the **flash-once semantics**: if the incoming request
///    carried a `__vauban_flash` cookie, the response MUST clear it,
///    otherwise the browser keeps re-sending it for `max_age` seconds
///    and the banner is re-rendered on every subsequent page load --
///    including after logout, since the cookie outlives the session.
///
/// The clearing `Set-Cookie` is only appended when the handler did not
/// itself set a fresh `__vauban_flash` cookie. This preserves the
/// POST-Redirect-GET pattern: a POST handler calling `flash_redirect`
/// installs a brand-new flash cookie and we leave it alone so the
/// destination GET can render it once -- and that next request, in
/// turn, will purge it.
///
/// Handlers that explicitly emit `ClearFlashCookie` continue to work:
/// the middleware sees their `Set-Cookie: __vauban_flash=; Max-Age=0`
/// and skips its own cleanup, so no duplicate header is produced.
pub async fn flash_middleware(
    axum::extract::State(secret_key): axum::extract::State<FlashSecretKey>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let had_flash_cookie = request_has_flash_cookie(&request);
    request.extensions_mut().insert(secret_key);

    let mut response = next.run(request).await;

    if had_flash_cookie && !response_sets_flash_cookie(&response) {
        // Build the clearing cookie ourselves: same attributes as the
        // ones produced by `flash_redirect` so the browser actually
        // matches and overwrites the existing entry.
        let cookie = Cookie::build((FLASH_COOKIE_NAME, ""))
            .path("/")
            .http_only(true)
            .secure(true)
            .same_site(SameSite::Lax)
            .max_age(Duration::ZERO)
            .build();
        if let Ok(header_value) = cookie.to_string().parse() {
            response
                .headers_mut()
                .append(axum::http::header::SET_COOKIE, header_value);
        }
    }

    response
}

/// Whether the incoming request carries a `__vauban_flash` cookie.
fn request_has_flash_cookie(request: &axum::extract::Request) -> bool {
    request
        .headers()
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(|s| s.trim())
        .any(|c| {
            c.split_once('=')
                .is_some_and(|(name, _)| name.trim() == FLASH_COOKIE_NAME)
        })
}

/// Whether the outgoing response already has a `Set-Cookie` for the
/// flash cookie (either a fresh one from `flash_redirect` or a clearing
/// one from `ClearFlashCookie`).
fn response_sets_flash_cookie(response: &Response) -> bool {
    response
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|sc| {
            // Set-Cookie format: `name=value; attr=...; ...`
            sc.split_once('=')
                .is_some_and(|(name, _)| name.trim() == FLASH_COOKIE_NAME)
        })
}

/// Helper to create a flash and redirect response.
/// Uses HTTP 302 redirect for PRG pattern (POST-Redirect-GET).
///
/// The flash cookie is set here and will be read and cleared by the
/// destination page's GET handler.
pub fn flash_redirect(flash: Flash, location: &str) -> Response {
    // Set flash cookie and redirect - DO NOT clear the cookie here!
    // The cookie will be cleared when the GET handler reads it.
    (flash, axum::response::Redirect::to(location)).into_response()
}

// Base64 encoding/decoding helpers (URL-safe)
fn base64_encode(data: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data.as_bytes())
}

fn base64_decode(encoded: &str) -> Option<String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()?;
    String::from_utf8(bytes).ok()
}

// constant_time_compare deduplicated - use crate::crypto::constant_time_compare_str
use crate::crypto::constant_time_compare_str as constant_time_compare;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flash_message_success() {
        let msg = FlashMessage::success("Operation completed");
        assert_eq!(msg.level, "success");
        assert_eq!(msg.message, "Operation completed");
    }

    #[test]
    fn test_flash_message_error() {
        let msg = FlashMessage::error("Something went wrong");
        assert_eq!(msg.level, "error");
        assert_eq!(msg.message, "Something went wrong");
    }

    #[test]
    fn test_flash_message_warning() {
        let msg = FlashMessage::warning("Be careful");
        assert_eq!(msg.level, "warning");
    }

    #[test]
    fn test_flash_message_info() {
        let msg = FlashMessage::info("FYI");
        assert_eq!(msg.level, "info");
    }

    #[test]
    fn test_flash_chain() {
        let secret = b"test-secret-key";
        let flash = Flash::new(secret)
            .success("Done")
            .error("Failed")
            .warning("Careful");

        assert_eq!(flash.messages.len(), 3);
    }

    #[test]
    fn test_flash_signed_value() {
        let secret = b"test-secret-key";
        let flash = Flash::new(secret).success("Test message");

        let signed = flash.create_signed_value();
        assert!(signed.is_some());

        let value = unwrap_some!(signed);
        assert!(value.contains('.'));
    }

    #[test]
    fn test_verify_and_decode_valid() {
        let secret = b"test-secret-key";
        let flash = Flash::new(secret).success("Test message");

        let signed = unwrap_some!(flash.create_signed_value());
        let decoded = IncomingFlash::verify_and_decode(secret, &signed);

        assert!(decoded.is_some());
        let messages = unwrap_some!(decoded);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message, "Test message");
    }

    #[test]
    fn test_verify_and_decode_invalid_signature() {
        let secret = b"test-secret-key";
        let wrong_secret = b"wrong-secret-key";
        let flash = Flash::new(secret).success("Test message");

        let signed = unwrap_some!(flash.create_signed_value());
        let decoded = IncomingFlash::verify_and_decode(wrong_secret, &signed);

        assert!(decoded.is_none());
    }

    #[test]
    fn test_verify_and_decode_tampered() {
        let secret = b"test-secret-key";
        let flash = Flash::new(secret).success("Test message");

        let signed = unwrap_some!(flash.create_signed_value());
        let tampered = format!("{}tampered", signed);
        let decoded = IncomingFlash::verify_and_decode(secret, &tampered);

        assert!(decoded.is_none());
    }

    #[test]
    fn test_incoming_flash_helpers() {
        let flash = IncomingFlash {
            messages: vec![
                FlashMessage::success("OK"),
                FlashMessage::error("Error 1"),
                FlashMessage::error("Error 2"),
            ],
            secret_key: vec![],
        };

        assert!(!flash.is_empty());
        assert!(flash.has_errors());
        assert_eq!(flash.errors().len(), 2);
        assert_eq!(flash.successes().len(), 1);
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("hello", "hello"));
        assert!(!constant_time_compare("hello", "world"));
        assert!(!constant_time_compare("hello", "hello!"));
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = "Test message with special chars: éàü";
        let encoded = base64_encode(original);
        let decoded = base64_decode(&encoded);
        assert_eq!(decoded, Some(original.to_string()));
    }

    // -------------------------------------------------------------------
    // Flash-once middleware semantics
    //
    // Regression coverage for the bug where the flash banner kept being
    // re-rendered on every page (and after logout) for the cookie's full
    // 30-second TTL because nothing ever cleared it.
    // -------------------------------------------------------------------

    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode, header::SET_COOKIE},
        middleware::from_fn_with_state,
        routing::get,
    };
    use tower::ServiceExt; // for `oneshot`

    fn make_app() -> Router {
        let key = FlashSecretKey(b"test-secret-key".to_vec());

        async fn echo() -> &'static str {
            "ok"
        }

        async fn with_flash() -> Response {
            let flash = Flash::new(b"test-secret-key").success("Saved!");
            (flash, axum::response::Redirect::to("/echo")).into_response()
        }

        async fn manual_clear() -> Response {
            (ClearFlashCookie, "ok").into_response()
        }

        Router::new()
            .route("/echo", get(echo))
            .route("/set", get(with_flash))
            .route("/manual-clear", get(manual_clear))
            .layer(from_fn_with_state(key, flash_middleware))
    }

    fn flash_set_cookies(headers: &axum::http::HeaderMap) -> Vec<String> {
        headers
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter(|sc| sc.starts_with(FLASH_COOKIE_NAME))
            .map(|s| s.to_string())
            .collect()
    }

    /// A request with no flash cookie MUST NOT trigger any cleanup
    /// header: the middleware has nothing to clear and we don't want
    /// stray `Set-Cookie` noise on every single page load.
    #[tokio::test]
    async fn middleware_does_not_clear_when_no_incoming_cookie() {
        let app = make_app();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/echo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(flash_set_cookies(res.headers()).is_empty());
    }

    /// The core fix: a GET that arrives with a flash cookie MUST exit
    /// with a `Set-Cookie: __vauban_flash=; Max-Age=0` so the browser
    /// drops it on the very next request -- guaranteeing the banner is
    /// rendered exactly once.
    #[tokio::test]
    async fn middleware_clears_incoming_flash_cookie_after_one_request() {
        let app = make_app();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/echo")
                    .header(
                        axum::http::header::COOKIE,
                        format!("{}=anything.signature", FLASH_COOKIE_NAME),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let cookies = flash_set_cookies(res.headers());
        assert_eq!(cookies.len(), 1, "expected exactly one clearing cookie");
        assert!(
            cookies[0].contains("Max-Age=0"),
            "clearing cookie must use Max-Age=0, got: {}",
            cookies[0]
        );
    }

    /// PRG safeguard: when a POST handler installs a fresh flash via
    /// `flash_redirect`, the middleware MUST NOT also append a clearing
    /// header -- otherwise the destination GET would never see the
    /// message. Only one Set-Cookie for the flash, and it must be the
    /// fresh signed payload, not the empty clearing one.
    #[tokio::test]
    async fn middleware_does_not_clobber_freshly_set_flash_cookie() {
        let app = make_app();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/set")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let cookies = flash_set_cookies(res.headers());
        assert_eq!(cookies.len(), 1, "exactly one __vauban_flash cookie expected");
        assert!(
            !cookies[0].contains("Max-Age=0"),
            "the fresh flash must not be replaced by a clearing cookie: {}",
            cookies[0]
        );
    }

    /// Backwards compatibility with the handful of handlers that still
    /// emit `ClearFlashCookie` explicitly: the middleware must detect
    /// the existing Set-Cookie and skip its own cleanup, otherwise the
    /// browser would receive two duplicate headers (harmless but ugly).
    #[tokio::test]
    async fn middleware_skips_when_handler_already_cleared() {
        let app = make_app();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/manual-clear")
                    .header(
                        axum::http::header::COOKIE,
                        format!("{}=anything.signature", FLASH_COOKIE_NAME),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let cookies = flash_set_cookies(res.headers());
        assert_eq!(
            cookies.len(),
            1,
            "ClearFlashCookie + middleware must not emit duplicate headers"
        );
    }
}
