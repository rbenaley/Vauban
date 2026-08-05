//! Module router root: `/` redirect, `/login`, `/{org}/…`.

mod _components;
mod admin;
mod issue_thumbs;
mod login;
mod org;

pub(crate) use issue_thumbs::{
    DiscussionPane, DiscussionRow, issue_discussion, shot_file_input, thumbs_for_comment,
};

pub use crate::list_page::{
    BUILDS_PAGE_SIZE, LIST_PAGE_SIZE, clamp_page, page_count, page_slice, parse_page,
};
pub use org::builds_list_href;

use std::sync::Arc;

use toasty::Db;
use topcoat::{
    Result,
    asset::{Asset, AssetBundle, AssetConfig, RouterBuilderAssetExt, asset},
    context::{Cx, CxBuilder, try_app_context},
    cookie::RouterBuilderCookieExt,
    font,
    mail::{MailConfig as TopcoatMailConfig, MemoryTransport, RouterBuilderMailExt},
    router::{
        Body, HeaderValue, IntoResponse, Next, Response, Router, RouterBuilderDiscoverExt,
        StatusCode,
        error::{redirect, redirect_permanent},
        header, layer, layout, method, route, uri,
    },
    session::{RouterBuilderSessionExt, SessionConfig},
    tailwind,
    view::view,
};

/// Brand mark for `<link rel="icon" type="image/svg+xml">`.
const FAVICON_SVG: Asset = asset!("assets/favicon.svg");
const FAVICON_16: Asset = asset!("assets/favicon-16x16.png");
const FAVICON_32: Asset = asset!("assets/favicon-32x32.png");
const APPLE_TOUCH_ICON: Asset = asset!("assets/apple-touch-icon.png");
/// First-party script: persist browser IANA zone as `vcp_tz` for SSR dates.
const VCP_TZ_JS: Asset = asset!("assets/vcp_tz.js");
/// First-party WebAuthn ceremony helper (C1 / KEY).
/// Declared once here so Topcoat does not register duplicate asset routes.
pub const VCP_WEBAUTHN_JS: Asset = asset!("assets/vcp_webauthn.js");
/// Well-known OS/browser probe paths (fixed URLs; not content-hashed).
/// Layout `<link rel="icon">` still uses `asset!` above — do not generalize.
const FAVICON_ICO_BYTES: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/favicon.ico"));
const APPLE_TOUCH_ICON_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/apple-touch-icon.png"
));
const APPLE_TOUCH_ICON_PRECOMPOSED_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/apple-touch-icon-precomposed.png"
));

use crate::{
    auth::{PostAuthLanding, current_user, post_auth_landing},
    config::{Config, Environment},
    fonts::{HANKEN_GROTESK, JETBRAINS_MONO},
    http_canonical::{should_redirect_trailing_slash, trailing_slash_redirect_location},
    login_limit::LoginRateLimiter,
    mailer::build_smtp_transport,
    perms::PolicyStore,
    storage::StorageClient,
};

/// When true, the security layer attaches HSTS on every response.
#[derive(Clone, Copy)]
struct EnableHsts(bool);

pub fn router(db: Db, policy: Arc<PolicyStore>, cfg: &Config) -> Router {
    let transport = build_smtp_transport(&cfg.mail).unwrap_or_else(|e| {
        panic!("invalid mail.smtp configuration: {e}");
    });
    router_with_mail(
        db,
        policy,
        cfg,
        TopcoatMailConfig::builder().transport(transport).build(),
    )
}

/// Test helper: same router with an in-memory mail capture (no SMTP).
pub fn router_with_memory_mail(
    db: Db,
    policy: Arc<PolicyStore>,
    cfg: &Config,
    memory: MemoryTransport,
) -> Router {
    router_with_mail(
        db,
        policy,
        cfg,
        TopcoatMailConfig::builder().transport(memory).build(),
    )
}

fn router_with_mail(
    db: Db,
    policy: Arc<PolicyStore>,
    cfg: &Config,
    mail: TopcoatMailConfig,
) -> Router {
    let mut sessions = SessionConfig::builder();
    for origin in &cfg.server.public_origins {
        sessions = sessions.trust_origin(origin.clone());
    }
    let sessions = sessions.build();

    let assets = load_assets(cfg.environment);
    let enable_hsts = EnableHsts(cfg.environment == Environment::Production);
    let login_limiter = Arc::new(LoginRateLimiter::new(&cfg.login));
    let storage = Arc::new(StorageClient::connect(&cfg.storage).unwrap_or_else(|e| {
        panic!(
            "storage helper connect failed ({}): {e}",
            cfg.storage.ipc.as_str()
        );
    }));

    topcoat::router::module_router!()
        .cookies()
        .sessions(sessions)
        .assets(assets)
        .mail(mail)
        .app_context(db)
        .app_context(policy)
        .app_context(Arc::new(cfg.clone()))
        .app_context(enable_hsts)
        .app_context(login_limiter)
        .app_context(storage)
        .discover()
        .build()
}

fn load_assets(env: Environment) -> AssetConfig {
    let bundle = match AssetBundle::load() {
        Ok(bundle) => bundle,
        Err(err) => {
            panic!(
                "asset bundle missing ({err}); run `just bundle` or `just run` after \
                 `cargo build` (bare `cargo run` skips bundling)"
            );
        }
    };
    let config = AssetConfig::serve(bundle);
    // Tailwind's asset! path includes OUT_DIR, so a rebuild without rebundle
    // leaves stale IDs in target/assets/manifest.toml and panics on first HTML
    // render. Fail at boot with an actionable message instead.
    require_catalog_assets(
        &config,
        env,
        &[
            ("favicon.svg", FAVICON_SVG),
            ("favicon-16", FAVICON_16),
            ("favicon-32", FAVICON_32),
            ("apple-touch-icon", APPLE_TOUCH_ICON),
            ("vcp_tz.js", VCP_TZ_JS),
            ("vcp_webauthn.js", VCP_WEBAUTHN_JS),
            ("tailwind stylesheet", tailwind::stylesheet!()),
            ("topcoat runtime script", topcoat::runtime::SCRIPT),
        ],
    );
    config
}

fn require_catalog_assets(config: &AssetConfig, env: Environment, assets: &[(&str, Asset)]) {
    let mut missing = Vec::new();
    for (label, asset) in assets {
        if config.get(*asset).is_none() {
            missing.push(*label);
        }
    }
    if missing.is_empty() {
        return;
    }
    panic!(
        "asset catalog is stale or incomplete (missing: {}); \
         rebuild the bundle with `just bundle` or `just run` so binary AssetIds \
         match target/assets (environment={env:?})",
        missing.join(", "),
    );
}

#[layout]
pub(crate) async fn root_layout(slot: Result) -> Result {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>"Vauban Portal"</title>
                <link rel="icon" type="image/svg+xml" href=(FAVICON_SVG)>
                <link rel="icon" type="image/png" sizes="32x32" href=(FAVICON_32)>
                <link rel="icon" type="image/png" sizes="16x16" href=(FAVICON_16)>
                <link rel="apple-touch-icon" href=(APPLE_TOUCH_ICON)>
                font::link(font: HANKEN_GROTESK)
                font::link(font: JETBRAINS_MONO)
                <link rel="stylesheet" href=(tailwind::stylesheet!())>
                <script src=(VCP_TZ_JS) defer=""></script>
                topcoat::runtime::script()
                topcoat::dev::script()
            </head>
            <body>(slot?)</body>
        </html>
    }
}

#[layer]
async fn security_headers(cx: &mut CxBuilder, body: Body, next: Next<'_>) -> Result<Response> {
    let enable_hsts = try_app_context::<EnableHsts>(cx)
        .map(|h| h.0)
        .unwrap_or(false);

    // Wide canonical redirect: strip trailing slashes via Topcoat
    // `redirect_permanent` (HTTP 308) on GET/HEAD only.
    let redirect_to = if should_redirect_trailing_slash(method(cx)) {
        let req_uri = uri(cx);
        trailing_slash_redirect_location(req_uri.path(), req_uri.query())
    } else {
        None
    };
    let mut response = match redirect_to {
        Some(location) => redirect_permanent(&location).into_response(cx)?,
        None => match next.run(cx, body).await {
            Ok(response) => response,
            // Handler `Err(redirect/…)` must still get security headers — do not `?` out.
            Err(error) => error.into_response(cx)?,
        },
    };

    apply_security_headers(response.headers_mut(), enable_hsts);
    Ok(response)
}

fn apply_security_headers(headers: &mut http::HeaderMap, enable_hsts: bool) {
    // Dynamic HTML/API/redirects: never cache. Leave asset/font routes alone —
    // Topcoat already sets `public, max-age=31536000, immutable` on those.
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    // Clickjacking: deny framing (partial CSP; avoid a full policy that would
    // fight Topcoat runtime / Fontsource CDN without an audit).
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'none'"),
    );
    headers.insert(
        http::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("geolocation=(), camera=(), microphone=()"),
    );
    if enable_hsts {
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
}

/// Entry: authenticated users land on their portal home or org picker; others go to login.
/// Navigational GET -> `redirect` (307), not `see_other` (303 PRG).
#[route(GET "/")]
async fn root(cx: &Cx) -> Result {
    if let Some(user) = current_user(cx).await {
        match post_auth_landing(cx, user).await? {
            PostAuthLanding::Org(slug) => {
                return Err(redirect(&format!("/{slug}")).into());
            }
            PostAuthLanding::ChooseOrg => {
                return Err(redirect("/choose-org").into());
            }
            PostAuthLanding::None => {}
        }
    }
    Err(redirect("/login").into())
}

/// Fixed-path icon probes (`/favicon.ico`, apple-touch). Outside `asset!`
/// on purpose — hashed URLs cannot satisfy OS/browser probes.
fn static_icon_response(content_type: &'static str, bytes: &'static [u8]) -> Result<Response> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "public, max-age=604800")
        .body(Body::from(bytes))?)
}

#[route(GET "/favicon.ico")]
async fn favicon_ico() -> Result<Response> {
    static_icon_response("image/x-icon", FAVICON_ICO_BYTES)
}

#[route(GET "/apple-touch-icon.png")]
async fn apple_touch_icon() -> Result<Response> {
    static_icon_response("image/png", APPLE_TOUCH_ICON_BYTES)
}

#[route(GET "/apple-touch-icon-precomposed.png")]
async fn apple_touch_icon_precomposed() -> Result<Response> {
    static_icon_response("image/png", APPLE_TOUCH_ICON_PRECOMPOSED_BYTES)
}
