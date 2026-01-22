/// VAUBAN Web - Security Headers Middleware.
///
/// Injects security headers on all HTTP responses to protect against:
/// - XSS attacks (Content-Security-Policy, X-XSS-Protection)
/// - Clickjacking (X-Frame-Options)
/// - MIME sniffing (X-Content-Type-Options)
/// - Protocol downgrade (Strict-Transport-Security)
/// - Information leakage (Referrer-Policy, Permissions-Policy)
use axum::{
    body::Body,
    http::{Request, Response, header::HeaderValue},
    middleware::Next,
};

/// Security headers middleware.
///
/// Adds the following security headers to all responses:
/// - `X-Content-Type-Options: nosniff`
/// - `X-Frame-Options: DENY`
/// - `X-XSS-Protection: 1; mode=block`
/// - `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' wss:`
/// - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
/// - `Referrer-Policy: strict-origin-when-cross-origin`
/// - `Permissions-Policy: geolocation=(), camera=(), microphone=()`
pub async fn security_headers_middleware(
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // Prevent MIME type sniffing
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );

    // Prevent clickjacking
    headers.insert(
        "x-frame-options",
        HeaderValue::from_static("DENY"),
    );

    // XSS protection (legacy, but still useful for older browsers)
    headers.insert(
        "x-xss-protection",
        HeaderValue::from_static("1; mode=block"),
    );

    // Content Security Policy
    // - default-src 'self': Only allow resources from same origin
    // - script-src: Allow scripts from self, inline, and CDNs (Tailwind, HTMX, Alpine)
    // - style-src: Allow styles from self, inline, and CDNs
    // - img-src 'self' data:: Allow images from same origin and data URIs
    // - font-src 'self': Allow fonts from same origin
    // - connect-src 'self' wss:: Allow WebSocket connections
    //
    // Note: CDN URLs are required for development. In production, bundle assets locally.
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; \
             script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://unpkg.com; \
             style-src 'self' 'unsafe-inline'; \
             img-src 'self' data:; \
             font-src 'self'; \
             connect-src 'self' wss:"
        ),
    );

    // HTTP Strict Transport Security (1 year)
    headers.insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );

    // Referrer policy - send referrer for same-origin, origin only for cross-origin
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    // Permissions policy - disable sensitive features
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("geolocation=(), camera=(), microphone=()"),
    );

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get, body::Body, http::Request};
    use tower::ServiceExt;
    use crate::unwrap_ok;

    async fn test_handler() -> &'static str {
        "OK"
    }

    #[tokio::test]
    async fn test_security_headers_present() {
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(axum::middleware::from_fn(security_headers_middleware));

        let response = unwrap_ok!(app
            .oneshot(unwrap_ok!(Request::builder().uri("/").body(Body::empty())))
            .await);

        let headers = response.headers();

        assert_eq!(
            unwrap_ok!(headers.get("x-content-type-options").ok_or("missing header")),
            "nosniff"
        );
        assert_eq!(
            unwrap_ok!(headers.get("x-frame-options").ok_or("missing header")),
            "DENY"
        );
        assert_eq!(
            unwrap_ok!(headers.get("x-xss-protection").ok_or("missing header")),
            "1; mode=block"
        );
        assert!(headers.get("content-security-policy").is_some());
        assert!(headers.get("strict-transport-security").is_some());
        assert!(headers.get("referrer-policy").is_some());
        assert!(headers.get("permissions-policy").is_some());
    }

    #[tokio::test]
    async fn test_csp_contains_required_directives() {
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(axum::middleware::from_fn(security_headers_middleware));

        let response = unwrap_ok!(app
            .oneshot(unwrap_ok!(Request::builder().uri("/").body(Body::empty())))
            .await);

        let csp = unwrap_ok!(unwrap_ok!(response
            .headers()
            .get("content-security-policy")
            .ok_or("missing header"))
            .to_str());

        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src"));
        assert!(csp.contains("style-src"));
    }

    #[tokio::test]
    async fn test_hsts_has_max_age() {
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(axum::middleware::from_fn(security_headers_middleware));

        let response = unwrap_ok!(app
            .oneshot(unwrap_ok!(Request::builder().uri("/").body(Body::empty())))
            .await);

        let hsts = unwrap_ok!(unwrap_ok!(response
            .headers()
            .get("strict-transport-security")
            .ok_or("missing header"))
            .to_str());

        assert!(hsts.contains("max-age="));
        assert!(hsts.contains("includeSubDomains"));
    }
}
