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
/// Every front-end dependency is **self-hosted** under `/static/` (htmx,
/// Alpine.js, the xterm stack and the Tailwind JIT compiler are vendored in
/// `static/js/vendor` and `static/css/vendor`). The CSP therefore carries **no
/// CDN origin**: `script-src`/`style-src`/`connect-src` are scoped to `'self'`,
/// so the browser never reaches a third-party server at runtime.
///
/// `connect-src 'self'` covers every WebSocket: the SSH/RDP terminals and the
/// htmx notification channel all dial `window.location.host` (same origin), and
/// CSP Level 3 matches same-origin `ws:`/`wss:` under `'self'`. The previous
/// blanket `wss:` source (any host) has been dropped.
///
/// `object-src 'none'` forbids `<object>`/`<embed>`/applets outright (no plugin
/// surface), tightening the `default-src 'self'` fallback to a hard block.
///
/// `'unsafe-inline'` is kept in `style-src` because:
/// - the vendored Tailwind JIT compiler injects a generated `<style>` block,
/// - xterm.js injects `<style>` elements at runtime for terminal sizing/theming
///   (dropping it regressed the SSH terminal rendering),
/// - a few dynamic inline `style=""` attributes are used for theming.
///
/// `'unsafe-eval'` is kept in `script-src` because both the Tailwind JIT
/// compiler and Alpine.js (standard build) rely on `new Function()` (Tailwind to
/// evaluate utility classes, Alpine for inline `x-data="{...}"` expressions).
///
/// Removing `'unsafe-eval'`/`'unsafe-inline'` would require pre-compiling
/// Tailwind and migrating to the `@alpinejs/csp` build (tracked in VAU-011);
/// that hardening is intentionally out of scope here -- this change only
/// removes the third-party CDN dependency.
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
    // - script-src:          Scripts from self only (every JS lib is vendored
    //                        under /static); 'unsafe-eval' kept for the Tailwind
    //                        JIT compiler + Alpine.js (see doc-comment). NO CDN.
    // - style-src:           Styles from self only; 'unsafe-inline' kept for the
    //                        Tailwind JIT + xterm injected <style> + dynamic
    //                        style="" attributes (see doc-comment). NO CDN.
    // - img-src:              Allow images from same origin, data: and blob: URIs
    //                        (blob: needed for RDP display updates rendered via canvas)
    // - media-src:           Allow media from same origin and blob: URIs
    //                        (blob: needed for Shaka Player / MSE segmented playback)
    // - font-src 'self':     Allow fonts from same origin only
    // - connect-src 'self':  XHR/fetch + WebSockets to same origin only. The
    //                        SSH/RDP terminals and htmx notifications all dial
    //                        window.location.host, which 'self' covers (CSP3).
    // - object-src 'none':   Forbid <object>/<embed>/applets (no plugin surface)
    // - base-uri 'self':     Prevent <base> tag hijacking
    // - form-action 'self':  Restrict form submissions to same origin
    // - frame-ancestors:     Prevent framing (mirrors X-Frame-Options)
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; \
             script-src 'self' 'unsafe-eval'; \
             style-src 'self' 'unsafe-inline'; \
             img-src 'self' data: blob:; \
             media-src 'self' blob:; \
             font-src 'self'; \
             connect-src 'self'; \
             object-src 'none'; \
             base-uri 'self'; \
             form-action 'self'; \
             frame-ancestors 'none'",
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
    async fn test_csp_media_src_allows_blob_urls() {
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

        let media_src = csp
            .split(';')
            .find(|d| d.trim().starts_with("media-src"))
            .expect("CSP must contain media-src directive");

        assert!(
            media_src.contains("blob:"),
            "media-src MUST include blob: for Shaka Player / MSE segmented playback, got: {}",
            media_src
        );
    }

    /// connect-src is scoped to same origin only. Same-origin `ws:`/`wss:`
    /// (SSH/RDP terminals + htmx notifications dial `window.location.host`) is
    /// covered by `'self'` under CSP Level 3, so the blanket `wss:` source has
    /// been dropped and MUST NOT come back (it would re-allow XHR/WS to any
    /// host).
    #[tokio::test]
    async fn test_csp_connect_src_has_no_blanket_wss() {
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
            !connect_src.contains("wss:"),
            "connect-src MUST NOT carry a blanket wss: source; 'self' covers \
             same-origin WebSockets, got: {}",
            connect_src
        );
    }

    async fn csp_header() -> String {
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(axum::middleware::from_fn(security_headers_middleware));

        let response = unwrap_ok!(
            app.oneshot(unwrap_ok!(Request::builder().uri("/").body(Body::empty())))
                .await
        );

        unwrap_ok!(
            unwrap_ok!(
                response
                    .headers()
                    .get("content-security-policy")
                    .ok_or("missing header")
            )
            .to_str()
        )
        .to_string()
    }

    /// Every front-end dependency is self-hosted: the CSP MUST NOT reference any
    /// third-party CDN origin (regression guard against re-introducing one).
    #[tokio::test]
    async fn test_csp_has_no_cdn_origin() {
        let csp = csp_header().await;
        for origin in [
            "cdn.tailwindcss.com",
            "unpkg.com",
            "cdn.jsdelivr.net",
            "https://",
        ] {
            assert!(
                !csp.contains(origin),
                "CSP MUST NOT reference CDN origin {origin}, got: {csp}"
            );
        }
    }

    /// 'unsafe-eval' / 'unsafe-inline' are intentionally kept (Tailwind JIT,
    /// Alpine standard build, xterm injected <style>). This pins that contract
    /// so a well-meaning hardening does not silently break those libs without
    /// the corresponding VAU-011 migration.
    #[tokio::test]
    async fn test_csp_keeps_unsafe_eval_and_unsafe_inline() {
        let csp = csp_header().await;

        let script_src = csp
            .split(';')
            .find(|d| d.trim().starts_with("script-src"))
            .expect("CSP must contain script-src directive");
        assert!(
            script_src.contains("'unsafe-eval'"),
            "script-src MUST keep 'unsafe-eval' for Tailwind JIT + Alpine, got: {script_src}"
        );

        let style_src = csp
            .split(';')
            .find(|d| d.trim().starts_with("style-src"))
            .expect("CSP must contain style-src directive");
        assert!(
            style_src.contains("'unsafe-inline'"),
            "style-src MUST keep 'unsafe-inline' for Tailwind JIT + xterm, got: {style_src}"
        );
    }

    /// connect-src is scoped to exactly 'self' (no CDN, no blanket wss:), so no
    /// XHR/fetch/WebSocket can reach a third party at runtime.
    #[tokio::test]
    async fn test_csp_connect_src_is_exactly_self() {
        let csp = csp_header().await;
        let connect_src = csp
            .split(';')
            .find(|d| d.trim().starts_with("connect-src"))
            .expect("CSP must contain connect-src directive")
            .trim();
        assert_eq!(
            connect_src, "connect-src 'self'",
            "connect-src must be exactly 'self', got: {connect_src}"
        );
    }

    /// object-src is locked to 'none': no <object>/<embed>/applet plugin surface
    /// (a stricter hard block than the default-src 'self' fallback).
    #[tokio::test]
    async fn test_csp_object_src_is_none() {
        let csp = csp_header().await;
        let object_src = csp
            .split(';')
            .find(|d| d.trim().starts_with("object-src"))
            .expect("CSP must contain object-src directive")
            .trim();
        assert_eq!(
            object_src, "object-src 'none'",
            "object-src must be exactly 'none', got: {object_src}"
        );
    }
}
