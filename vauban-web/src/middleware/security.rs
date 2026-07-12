/// VAUBAN Web - Security Headers Middleware (per-surface).
///
/// Injects security headers on every HTTP response, shaped by the
/// surface that serves the request:
///
/// - **Web/WS** (HTML pages, HTMX fragments, WebSocket upgrades):
///   browser-facing hardening (CSP, referrer, permissions policy).
/// - **API** (`/api` and everything under `/api/`): M2M JSON zone.
///   Browser-only directives are useless there (the caller is curl /
///   an SDK / an orchestrator, never a rendering engine), so the API
///   surface carries only the transport-level base set plus a
///   cache-hardening directive for its (often sensitive) JSON bodies.
///
/// ## Invariants (pinned by the unit tests below and by the E2E matrix
/// in `tests/security/response_headers_test.rs`)
///
/// | Invariant  | Contract                                                  |
/// |------------|-----------------------------------------------------------|
/// | INV-HDR-1  | Every response, both surfaces: `x-content-type-options:  |
/// |            | nosniff`, `x-frame-options: DENY`,                        |
/// |            | `strict-transport-security` (1 year, includeSubDomains). |
/// | INV-HDR-2  | Web surface only: `content-security-policy`,              |
/// |            | `referrer-policy`, `permissions-policy`.                  |
/// | INV-HDR-3  | The legacy `x-xss` protection header is NEVER emitted:    |
/// |            | the XSS auditor has been removed from every modern        |
/// |            | browser and the header is deprecated (its filtering mode  |
/// |            | could even introduce vulnerabilities). Forbidden token,   |
/// |            | pinned structurally in `response_headers_test.rs`.        |
/// | INV-HDR-4  | API surface: `Cache-Control: no-store` injected when the  |
/// |            | handler did not set its own cache directive (the vault    |
/// |            | `/value` endpoint sets it explicitly and stays in charge).|
/// | INV-HDR-5  | CORS (`CorsLayer`, see `middleware::cors`) is mounted on  |
/// |            | the web and WS routers only: `/api/*` responses never     |
/// |            | carry `vary: origin, ...` / `access-control-*` headers.   |
/// |            | CORS is a browser-only mechanism; the API zone is M2M.    |
///
/// ## Content-Security-Policy (web surface)
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
/// that hardening is intentionally out of scope here.
use axum::{
    body::Body,
    http::{Request, Response, header, header::HeaderValue},
    middleware::Next,
};

/// The two response-shaping surfaces of the bastion. Pure classifier so
/// the header matrix can be unit-tested without any HTTP plumbing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseSurface {
    /// HTML pages, HTMX fragments, static assets, WebSocket upgrades.
    Web,
    /// The M2M JSON zone: `/api` and everything under `/api/`.
    Api,
}

impl ResponseSurface {
    /// Classify a request path. `Api` iff the path is exactly `/api` or
    /// starts with `/api/` — a plain prefix test on `/api` would
    /// misclassify web paths like `/apikeys`.
    pub fn for_path(path: &str) -> Self {
        if path == "/api" || path.starts_with("/api/") {
            ResponseSurface::Api
        } else {
            ResponseSurface::Web
        }
    }
}

/// Per-surface security headers middleware. See the module doc for the
/// INV-HDR matrix.
pub async fn security_headers_middleware(request: Request<Body>, next: Next) -> Response<Body> {
    let surface = ResponseSurface::for_path(request.uri().path());
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // INV-HDR-1: base set on every response.
    //
    // - nosniff: even a JSON body benefits (a browser pointed directly
    //   at an API URL cannot MIME-sniff it into executable HTML).
    // - X-Frame-Options: cheap clickjacking defence-in-depth, also
    //   recommended by OWASP for API responses.
    // - HSTS: domain-wide TLS pinning, kept uniform across surfaces.
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );

    match surface {
        ResponseSurface::Web => {
            // INV-HDR-2: browser-facing directives, web surface only.
            //
            // Content Security Policy:
            // - default-src 'self':  Only allow resources from same origin
            // - script-src:          Scripts from self only (every JS lib is vendored
            //                        under /static); 'unsafe-eval' kept for the Tailwind
            //                        JIT compiler + Alpine.js (see doc-comment). NO CDN.
            // - style-src:           Styles from self only; 'unsafe-inline' kept for the
            //                        Tailwind JIT + xterm injected <style> + dynamic
            //                        style="" attributes (see doc-comment). NO CDN.
            // - img-src:             Allow images from same origin, data: and blob: URIs
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

            // Referrer policy - send referrer for same-origin, origin only
            // for cross-origin navigations (browser-only semantics).
            headers.insert(
                "referrer-policy",
                HeaderValue::from_static("strict-origin-when-cross-origin"),
            );

            // Permissions policy - disable sensitive document features.
            headers.insert(
                "permissions-policy",
                HeaderValue::from_static("geolocation=(), camera=(), microphone=()"),
            );
        }
        ResponseSurface::Api => {
            // INV-HDR-4: M2M JSON bodies are often sensitive (sessions,
            // accounts, secret metadata) and must never be stored by an
            // intermediary cache. Injected only when the handler did
            // not choose its own directive (the vault value endpoint
            // sets `no-store` itself and stays authoritative).
            headers
                .entry(header::CACHE_CONTROL)
                .or_insert(HeaderValue::from_static("no-store"));
        }
    }

    response
}

#[cfg(test)]
mod tests {
    use axum::{Router, body::Body, http::Request, routing::get};
    use tower::ServiceExt;

    use super::*;

    async fn test_handler() -> &'static str {
        "OK"
    }

    /// Handler that sets its own Cache-Control (mirrors the vault
    /// `/value` endpoint contract).
    async fn caching_handler() -> impl axum::response::IntoResponse {
        ([(header::CACHE_CONTROL, "private, max-age=60")], "OK")
    }

    async fn response_for(path: &str) -> Response<Body> {
        let app = Router::new()
            .route("/", get(test_handler))
            .route("/login", get(test_handler))
            .route("/apikeys", get(test_handler))
            .route("/api", get(test_handler))
            .route("/api/v1/sessions", get(test_handler))
            .route("/api/v1/vault/secrets/x/value", get(caching_handler))
            .layer(axum::middleware::from_fn(security_headers_middleware));

        unwrap_ok!(
            app.oneshot(unwrap_ok!(Request::builder().uri(path).body(Body::empty())))
                .await
        )
    }

    // ==================== ResponseSurface classifier ====================

    #[test]
    fn test_surface_classifier_matrix() {
        let cases = [
            ("/", ResponseSurface::Web),
            ("/login", ResponseSurface::Web),
            ("/accounts/apikeys", ResponseSurface::Web),
            // Prefix boundary: /apikeys is NOT the API zone.
            ("/apikeys", ResponseSurface::Web),
            ("/apiary", ResponseSurface::Web),
            ("/api", ResponseSurface::Api),
            ("/api/", ResponseSurface::Api),
            ("/api/v1", ResponseSurface::Api),
            ("/api/v1/sessions", ResponseSurface::Api),
            ("/api/v1/vault/secrets/x/value", ResponseSurface::Api),
        ];
        for (path, expected) in cases {
            assert_eq!(
                ResponseSurface::for_path(path),
                expected,
                "surface classifier drifted for {path}"
            );
        }
    }

    // ==================== INV-HDR-1: base set, both surfaces ====================

    #[tokio::test]
    async fn test_base_headers_on_both_surfaces() {
        for path in ["/login", "/api/v1/sessions"] {
            let response = response_for(path).await;
            let headers = response.headers();

            assert_eq!(
                unwrap_ok!(
                    headers
                        .get("x-content-type-options")
                        .ok_or("missing header")
                ),
                "nosniff",
                "{path}: nosniff must be present on every surface"
            );
            assert_eq!(
                unwrap_ok!(headers.get("x-frame-options").ok_or("missing header")),
                "DENY",
                "{path}: x-frame-options must be present on every surface"
            );
            let hsts = unwrap_ok!(
                unwrap_ok!(
                    headers
                        .get("strict-transport-security")
                        .ok_or("missing header")
                )
                .to_str()
            );
            assert!(hsts.contains("max-age=") && hsts.contains("includeSubDomains"));
        }
    }

    // ==================== INV-HDR-2: browser directives, web only ====================

    #[tokio::test]
    async fn test_web_surface_carries_browser_directives() {
        let response = response_for("/login").await;
        let headers = response.headers();
        assert!(headers.get("content-security-policy").is_some());
        assert!(headers.get("referrer-policy").is_some());
        assert!(headers.get("permissions-policy").is_some());
    }

    #[tokio::test]
    async fn test_api_surface_has_no_browser_directives() {
        for path in ["/api", "/api/v1/sessions"] {
            let response = response_for(path).await;
            let headers = response.headers();
            for name in [
                "content-security-policy",
                "referrer-policy",
                "permissions-policy",
            ] {
                assert!(
                    headers.get(name).is_none(),
                    "{path}: browser-only header '{name}' must NOT be emitted on the API surface"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_prefix_boundary_apikeys_is_web() {
        let response = response_for("/apikeys").await;
        assert!(
            response.headers().get("content-security-policy").is_some(),
            "/apikeys is a web path and must keep the CSP"
        );
        assert!(
            response.headers().get(header::CACHE_CONTROL).is_none(),
            "/apikeys must not receive the API no-store injection"
        );
    }

    // ============== INV-HDR-3: legacy XSS-auditor header never emitted ==============

    #[tokio::test]
    async fn test_x_xss_protection_never_emitted() {
        // The XSS auditor was removed from Chrome/Edge/Firefox; the
        // header is deprecated and must not come back on any surface.
        let forbidden = format!("x-xss-{}", "protection");
        for path in ["/", "/login", "/api", "/api/v1/sessions"] {
            let response = response_for(path).await;
            assert!(
                response.headers().get(forbidden.as_str()).is_none(),
                "{path}: the deprecated {forbidden} header must never be emitted"
            );
        }
    }

    // ==================== INV-HDR-4: no-store on the API surface ====================

    #[tokio::test]
    async fn test_api_surface_gets_no_store() {
        let response = response_for("/api/v1/sessions").await;
        assert_eq!(
            unwrap_ok!(
                response
                    .headers()
                    .get(header::CACHE_CONTROL)
                    .ok_or("missing header")
            ),
            "no-store",
            "API responses must default to Cache-Control: no-store"
        );
    }

    #[tokio::test]
    async fn test_handler_cache_control_is_preserved() {
        // A handler that sets its own directive stays authoritative:
        // the middleware only fills the gap (or_insert semantics).
        let response = response_for("/api/v1/vault/secrets/x/value").await;
        assert_eq!(
            unwrap_ok!(
                response
                    .headers()
                    .get(header::CACHE_CONTROL)
                    .ok_or("missing header")
            ),
            "private, max-age=60",
            "a handler-set Cache-Control must never be overwritten"
        );
    }

    #[tokio::test]
    async fn test_web_surface_gets_no_cache_control_injection() {
        let response = response_for("/login").await;
        assert!(
            response.headers().get(header::CACHE_CONTROL).is_none(),
            "the web surface must not receive the API no-store injection"
        );
    }

    // ==================== CSP content pins (web surface) ====================

    async fn csp_header() -> String {
        let response = response_for("/login").await;
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

    #[tokio::test]
    async fn test_csp_contains_required_directives() {
        let csp = csp_header().await;
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src"));
        assert!(csp.contains("style-src"));
        assert!(csp.contains("base-uri 'self'"));
        assert!(csp.contains("form-action 'self'"));
        assert!(csp.contains("frame-ancestors 'none'"));
    }

    #[tokio::test]
    async fn test_csp_no_unsafe_inline_in_script_src() {
        let csp = csp_header().await;
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
    async fn test_csp_img_src_allows_blob_urls() {
        let csp = csp_header().await;
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
        let csp = csp_header().await;
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
