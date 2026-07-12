/// VAUBAN Web - CORS layer (VAU-010).
///
/// Single seam for the CORS origin decision, consumed by BOTH the
/// production router (`main.rs`) and the E2E test router
/// (`tests/common/mod.rs`) so the two cannot drift apart.
///
/// ## Scope (INV-HDR-5)
///
/// CORS is a **browser-only** mechanism: it instructs a rendering
/// engine which cross-origin scripts may read a response. The M2M API
/// zone (`/api/*`) is consumed by curl / SDKs / orchestrators that
/// ignore CORS entirely, so the layer is mounted on the **web and WS
/// routers only** — never on the API branch (enabled or disabled).
/// `/api/*` responses therefore carry no `access-control-*` header and
/// no `vary: origin, ...` noise.
///
/// ## Origin decision (VAU-010)
///
/// The decision is driven EXCLUSIVELY by the fixed
/// `server.public_origins` allowlist, never by the client-controlled
/// `Host` header. `AllowOrigin::list` performs an exact match and, by
/// construction, has no access to the request `Host`.
use axum::http::Method;
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Build the CORS layer from the fixed `server.public_origins` allowlist
/// (VAU-010). The single seam for the CORS origin decision: it uses
/// `AllowOrigin::list` (exact match against the configured origins) and is
/// therefore structurally incapable of consulting the client-controlled
/// `Host` header. An unparseable entry is skipped; an empty allowlist
/// admits no cross-origin request (fail-closed).
pub fn build_cors_layer(origins: &[String]) -> CorsLayer {
    let allow = AllowOrigin::list(
        origins
            .iter()
            .filter_map(|o| o.parse::<axum::http::HeaderValue>().ok()),
    );
    CorsLayer::new()
        .allow_origin(allow)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::header::ACCEPT,
        ])
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== CORS Origin Tests (VAU-010) ====================
    //
    // These drive the REAL `build_cors_layer` through a tiny router via
    // `tower::ServiceExt::oneshot`, asserting the `access-control-allow-origin`
    // (ACAO) response header. They prove the CORS decision comes ONLY from the
    // configured allowlist and is NEVER influenced by the client `Host` header.

    /// Send a simple (non-preflight) GET carrying `Origin` (+ optional `Host`)
    /// through a router that mounts `build_cors_layer(allowlist)`. Returns the
    /// reflected ACAO header value, if any.
    async fn cors_acao_for(
        allowlist: &[String],
        origin: &str,
        host: Option<&str>,
    ) -> Option<String> {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use tower::ServiceExt;

        let app = axum::Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(build_cors_layer(allowlist));

        let mut builder = Request::builder()
            .uri("/")
            .header(axum::http::header::ORIGIN, origin);
        if let Some(h) = host {
            builder = builder.header(axum::http::header::HOST, h);
        }
        let req = builder.body(Body::empty()).expect("request builder");

        let resp = app.oneshot(req).await.expect("oneshot");
        resp.headers()
            .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    /// Drive a CORS preflight (OPTIONS + `Access-Control-Request-Method`)
    /// through `build_cors_layer` and return the reflected ACAO header.
    async fn cors_preflight_acao(allowlist: &[String], origin: &str) -> Option<String> {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use tower::ServiceExt;

        let app = axum::Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(build_cors_layer(allowlist));
        let req = Request::builder()
            .method(Method::OPTIONS)
            .uri("/")
            .header(axum::http::header::ORIGIN, origin)
            .header(axum::http::header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .body(Body::empty())
            .expect("request builder");
        app.oneshot(req)
            .await
            .expect("oneshot")
            .headers()
            .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    /// INV-2 / normal: an allowlisted origin is reflected, regardless of the
    /// `Host` header value.
    #[tokio::test]
    async fn cors_allows_configured_origin_regardless_of_host() {
        let allow = vec!["https://bastion.example.com".to_string()];
        // No Host, complicit Host, and unrelated Host all behave identically.
        for host in [None, Some("bastion.example.com"), Some("evil.com")] {
            let acao = cors_acao_for(&allow, "https://bastion.example.com", host).await;
            assert_eq!(
                acao.as_deref(),
                Some("https://bastion.example.com"),
                "configured origin must be allowed (host = {host:?})"
            );
        }
    }

    /// INV-1 / INV-3 (the VAU-010 fix): a forged origin is REFUSED even when a
    /// complicit `Host` header "confirms" it. Pre-fix, `Host: evil.com` +
    /// `Origin: https://evil.com` was accepted as same-origin.
    #[tokio::test]
    async fn cors_refuses_forged_origin_even_with_complicit_host() {
        let allow = vec!["https://bastion.example.com".to_string()];
        let acao = cors_acao_for(&allow, "https://evil.com", Some("evil.com")).await;
        assert_eq!(
            acao, None,
            "a forged Origin must NOT be allowed by a complicit Host header (VAU-010)"
        );
    }

    /// An origin absent from the allowlist is refused.
    #[tokio::test]
    async fn cors_refuses_unlisted_origin() {
        let allow = vec!["https://bastion.example.com".to_string()];
        let acao = cors_acao_for(&allow, "https://other.example.com", None).await;
        assert_eq!(acao, None);
    }

    /// Fail-closed: an empty allowlist admits no cross-origin request.
    #[tokio::test]
    async fn cors_empty_allowlist_admits_nothing() {
        let acao = cors_acao_for(&[], "https://bastion.example.com", None).await;
        assert_eq!(acao, None);
    }

    /// Preflight (OPTIONS): an allowlisted origin gets CORS headers, an
    /// unlisted one does not.
    #[tokio::test]
    async fn cors_preflight_respects_allowlist() {
        let allow = vec!["https://bastion.example.com".to_string()];
        assert_eq!(
            cors_preflight_acao(&allow, "https://bastion.example.com")
                .await
                .as_deref(),
            Some("https://bastion.example.com")
        );
        assert_eq!(cors_preflight_acao(&allow, "https://evil.com").await, None);
    }

    /// Drift guard (VAU-010, INV-1/INV-2): the CORS seam must stay on the
    /// config allowlist and never regain access to the request `Host`. The
    /// closure-based predicate API is the only tower-http surface that
    /// exposes the request parts (hence `Host`); its absence -- together with
    /// the presence of `AllowOrigin::list` and `build_cors_layer` --
    /// structurally guarantees the origin decision cannot consult `Host`.
    #[test]
    fn cors_seam_is_pinned_to_config_allowlist() {
        let src = include_str!("cors.rs");
        // Build the banned needles from fragments so this very test's source
        // (read back via include_str!) does not match itself.
        let banned_fn = ["fn ", "is_same_origin"].concat();
        let banned_predicate = ["AllowOrigin", "::predicate"].concat();
        assert!(
            !src.contains(&banned_fn),
            "is_same_origin (Host-based CORS) must stay deleted (VAU-010 INV-1)."
        );
        assert!(
            !src.contains(&banned_predicate),
            "the CORS seam must not use the Host-capable predicate API; \
             use AllowOrigin::list over the config allowlist (VAU-010 INV-1)."
        );
        assert!(
            src.contains("fn build_cors_layer(") && src.contains("AllowOrigin::list"),
            "the CORS seam must be build_cors_layer + AllowOrigin::list (VAU-010 INV-2)."
        );

        // The production router must feed the seam from the config
        // allowlist and mount it on the web/WS branches only.
        let main_src = include_str!("../main.rs");
        assert!(
            main_src.contains("build_cors_layer(&state.config.server.parsed_public_origins())"),
            "create_app must feed the CORS layer from server.parsed_public_origins() (VAU-010 INV-2)."
        );
    }
}
