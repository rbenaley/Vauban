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
/// - `Content-Security-Policy` (see below for directives)
/// - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
/// - `Referrer-Policy: strict-origin-when-cross-origin`
/// - `Permissions-Policy: geolocation=(), camera=(), microphone=()`
///
/// ## Content-Security-Policy
///
/// All inline `<script>` and `<style>` blocks have been moved to external
/// files served from `/static/`, which allows the CSP to drop `'unsafe-inline'`
/// from both `script-src` and `style-src`.
///
/// `'unsafe-inline'` is kept **only** in `style-src` to support dynamic inline
/// `style=""` attributes used for theming (e.g. `background-color: {{ color }}`).
/// CSS-based injection is vastly less dangerous than script injection, and
/// moving to CSS custom-properties will allow removing it later.
///
/// `'unsafe-eval'` remains in `script-src` because Alpine.js (standard build)
/// requires `new Function()` for inline expressions such as `x-data="{...}"`.
/// To remove it, switch to the `@alpinejs/csp` build and pre-register all
/// data components.
pub async fn security_headers_middleware(request: Request<Body>, next: Next) -> Response<Body> {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // Prevent MIME type sniffing
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );

    // Prevent clickjacking
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));

    // XSS protection (legacy, but still useful for older browsers)
    headers.insert(
        "x-xss-protection",
        HeaderValue::from_static("1; mode=block"),
    );

    // Content Security Policy
    //
    // - default-src 'self':  Only allow resources from same origin
    // - script-src:          Allow scripts from self + CDNs; NO 'unsafe-inline'
    //                        'unsafe-eval' kept for Alpine.js (see doc-comment)
    // - style-src:           Allow styles from self + CDN; 'unsafe-inline' only
    //                        for dynamic style="" attributes (see doc-comment)
    // - img-src:              Allow images from same origin, data: and blob: URIs
    //                        (blob: needed for RDP display updates rendered via canvas)
    // - font-src 'self':     Allow fonts from same origin only
    // - connect-src:         Allow XHR/fetch to self and WebSocket connections
    // - base-uri 'self':     Prevent <base> tag hijacking
    // - form-action 'self':  Restrict form submissions to same origin
    // - frame-ancestors:     Prevent framing (mirrors X-Frame-Options)
    //
    // Note: CDN URLs are required for dev. In production, bundle assets locally
    //       and remove the CDN origins for a stricter policy.
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; \
             script-src 'self' 'unsafe-eval' https://cdn.tailwindcss.com https://unpkg.com https://cdn.jsdelivr.net; \
             style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; \
             img-src 'self' data: blob:; \
             font-src 'self'; \
             connect-src 'self' wss:; \
             base-uri 'self'; \
             form-action 'self'; \
             frame-ancestors 'none'"
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
    use axum::{Router, body::Body, http::Request, routing::get};
    use tower::ServiceExt;

    async fn test_handler() -> &'static str {
        "OK"
    }

    #[tokio::test]
    async fn test_security_headers_present() {
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(axum::middleware::from_fn(security_headers_middleware));

        let response = unwrap_ok!(
            app.oneshot(unwrap_ok!(Request::builder().uri("/").body(Body::empty())))
                .await
        );

        let headers = response.headers();

        assert_eq!(
            unwrap_ok!(
                headers
                    .get("x-content-type-options")
                    .ok_or("missing header")
            ),
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

        let response = unwrap_ok!(
            app.oneshot(unwrap_ok!(Request::builder().uri("/").body(Body::empty())))
                .await
        );

        let csp = unwrap_ok!(
            unwrap_ok!(
                response
                    .headers()
                    .get("content-security-policy")
                    .ok_or("missing header")
            )
            .to_str()
        );

        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src"));
        assert!(csp.contains("style-src"));
        assert!(csp.contains("base-uri 'self'"));
        assert!(csp.contains("form-action 'self'"));
        assert!(csp.contains("frame-ancestors 'none'"));
    }

    #[tokio::test]
    async fn test_csp_no_unsafe_inline_in_script_src() {
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(axum::middleware::from_fn(security_headers_middleware));

        let response = unwrap_ok!(
            app.oneshot(unwrap_ok!(Request::builder().uri("/").body(Body::empty())))
                .await
        );

        let csp = unwrap_ok!(
            unwrap_ok!(
                response
                    .headers()
                    .get("content-security-policy")
                    .ok_or("missing header")
            )
            .to_str()
        );

        // Extract the script-src directive
        let script_src = csp
            .split(';')
            .find(|d| d.trim().starts_with("script-src"))
            .expect("CSP must contain script-src directive");

        assert!(
            !script_src.contains("'unsafe-inline'"),
            "script-src MUST NOT contain 'unsafe-inline', got: {}",
            script_src
        );
    }

    #[tokio::test]
    async fn test_hsts_has_max_age() {
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(axum::middleware::from_fn(security_headers_middleware));

        let response = unwrap_ok!(
            app.oneshot(unwrap_ok!(Request::builder().uri("/").body(Body::empty())))
                .await
        );

        let hsts = unwrap_ok!(
            unwrap_ok!(
                response
                    .headers()
                    .get("strict-transport-security")
                    .ok_or("missing header")
            )
            .to_str()
        );

        assert!(hsts.contains("max-age="));
        assert!(hsts.contains("includeSubDomains"));
    }

    #[tokio::test]
    async fn test_csp_img_src_allows_blob_urls() {
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(axum::middleware::from_fn(security_headers_middleware));

        let response = unwrap_ok!(
            app.oneshot(unwrap_ok!(Request::builder().uri("/").body(Body::empty())))
                .await
        );

        let csp = unwrap_ok!(
            unwrap_ok!(
                response
                    .headers()
                    .get("content-security-policy")
                    .ok_or("missing header")
            )
            .to_str()
        );

        let img_src = csp
            .split(';')
            .find(|d| d.trim().starts_with("img-src"))
            .expect("CSP must contain img-src directive");

        assert!(
            img_src.contains("blob:"),
            "img-src MUST include blob: for RDP display updates rendered via canvas, got: {}",
            img_src
        );
    }

    #[tokio::test]
    async fn test_csp_connect_src_allows_wss() {
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(axum::middleware::from_fn(security_headers_middleware));

        let response = unwrap_ok!(
            app.oneshot(unwrap_ok!(Request::builder().uri("/").body(Body::empty())))
                .await
        );

        let csp = unwrap_ok!(
            unwrap_ok!(
                response
                    .headers()
                    .get("content-security-policy")
                    .ok_or("missing header")
            )
            .to_str()
        );

        let connect_src = csp
            .split(';')
            .find(|d| d.trim().starts_with("connect-src"))
            .expect("CSP must contain connect-src directive");

        assert!(
            connect_src.contains("wss:"),
            "connect-src MUST include wss: for RDP/SSH WebSocket connections, got: {}",
            connect_src
        );
    }
}
