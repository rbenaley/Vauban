//! Module router root: `/` redirect, `/login`, `/{org}/…`.

mod _components;
pub(crate) mod admin;
pub mod hrefs;
mod issue_thumbs;
pub(crate) mod login;
pub(crate) mod org;
pub(crate) mod releases;

pub(crate) use issue_thumbs::{
    DiscussionPane, DiscussionRow, issue_discussion, shot_file_input, thumbs_for_comment,
};
pub use issue_thumbs::{ISSUE_LB_NEXT, ISSUE_LB_PREV, lightbox_step_index};

pub use crate::list_page::{
    BUILDS_PAGE_SIZE, LIST_PAGE_SIZE, clamp_page, page_count, page_slice, parse_page,
};
pub use admin::admin_releases_list_href;
pub use org::Org;
pub use org::builds_list_href;
pub use org::{DL_ERROR_PARAM, DownloadError, download_error_href};

use std::sync::Arc;

use toasty::Db;
use topcoat::{
    Result,
    asset::{Asset, AssetBundle, AssetConfig, RouterBuilderAssetExt, asset},
    context::{Cx, try_app_context},
    cookie::RouterBuilderCookieExt,
    font,
    mail::{MailConfig as TopcoatMailConfig, MemoryTransport, RouterBuilderMailExt},
    router::{
        Body, BodyLimit, HeaderValue, Layer, LayerFuture, Next, OriginPolicy, Path, Router,
        RouterBuilderDiscoverExt, Slot, StatusCode,
        error::{NotFoundError, redirect, redirect_permanent},
        header, href, layout,
        request::{method, uri},
        response::{IntoResponse, Response},
        route,
    },
    runtime::RouterBuilderRuntimeExt,
    session::{RouterBuilderSessionExt, SessionConfig},
    tailwind,
    view::{View, error_boundary, view},
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
    mail_circuit::MailCircuitBreaker,
    mailer::build_smtp_transport,
    perms::PolicyStore,
    request_intern::StringIntern,
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
        Arc::new(MailCircuitBreaker::new(&cfg.mail)),
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
        Arc::new(MailCircuitBreaker::new(&cfg.mail)),
    )
}

/// Test helper: memory mail plus a shared [`MailCircuitBreaker`] handle.
pub fn router_with_memory_mail_circuit(
    db: Db,
    policy: Arc<PolicyStore>,
    cfg: &Config,
    memory: MemoryTransport,
    mail_circuit: Arc<MailCircuitBreaker>,
) -> Router {
    router_with_mail(
        db,
        policy,
        cfg,
        TopcoatMailConfig::builder().transport(memory).build(),
        mail_circuit,
    )
}

fn router_with_mail(
    db: Db,
    policy: Arc<PolicyStore>,
    cfg: &Config,
    mail: TopcoatMailConfig,
    mail_circuit: Arc<MailCircuitBreaker>,
) -> Router {
    let sessions = SessionConfig::default();
    let origin_policy =
        OriginPolicy::new().trust_origins(cfg.server.public_origins.iter().cloned());

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
        .origin_policy(origin_policy)
        .layer(BodyLimit::max(cfg.server.max_request_body_bytes()))
        // Pathless: 0.6 `#[layer]` in this module is scoped to `/` and does
        // not run on unmatched URLs (trailing-slash `/login/` is a miss).
        .layer(SecurityHeaders)
        .cookies()
        .sessions(sessions)
        .assets(assets)
        .mail(mail)
        .app_context(db)
        .app_context(policy)
        .app_context(Arc::new(cfg.clone()))
        .app_context(enable_hsts)
        .app_context(login_limiter)
        .app_context(mail_circuit)
        .app_context(storage)
        .base_url(cfg.primary_public_origin())
        .discover()
        .runtime()
        .build()
}

fn load_assets(env: Environment) -> AssetConfig {
    let bundle = match load_asset_bundle() {
        Ok(bundle) => bundle,
        Err(err) => {
            panic!(
                "asset bundle missing ({err}); run `just bundle` or `just run` after \
                 `cargo build` (bare `cargo run` skips bundling). Packaged installs \
                 ship the release bundle at /usr/local/share/vcp/assets"
            );
        }
    };
    let config = AssetConfig::serve(bundle);
    // Tailwind's asset! path includes OUT_DIR, so a rebuild without rebundle
    // leaves stale IDs in the exe-adjacent assets/manifest.toml and panics on first HTML
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

/// Prefer the packaged (or `VCP_PACKAGE_ROOT`) share tree; fall back to
/// Topcoat 0.6 exe-adjacent `assets/` (`target/{profile}/vcp` + `assets/`).
/// Integration tests run from `target/{profile}/deps/`, so walk parents for
/// `assets/manifest.toml` after `AssetBundle::load()` (next to current_exe).
///
/// Only treat `package_root/assets` as a bundle when `manifest.toml` is present —
/// the checkout source tree also has an `assets/` directory of unbundled inputs.
fn load_asset_bundle() -> std::io::Result<AssetBundle> {
    if let Ok(pkg_root) = Config::package_root() {
        let packaged = pkg_root.join("assets");
        if packaged.join("manifest.toml").is_file() {
            return AssetBundle::load_dir(packaged);
        }
    }
    if let Ok(bundle) = AssetBundle::load() {
        return Ok(bundle);
    }
    if let Ok(pkg_root) = Config::package_root() {
        for rel in [
            "target/debug/assets",
            "target/test/assets",
            "target/release/assets",
        ] {
            let candidate = pkg_root.join(rel);
            if candidate.join("manifest.toml").is_file() {
                return AssetBundle::load_dir(candidate);
            }
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(std::path::Path::to_path_buf);
        while let Some(parent) = dir {
            let candidate = parent.join("assets");
            if candidate.join("manifest.toml").is_file() {
                return AssetBundle::load_dir(candidate);
            }
            dir = parent.parent().map(std::path::Path::to_path_buf);
        }
    }
    AssetBundle::load()
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
         match the exe-adjacent assets/ bundle (environment={env:?})",
        missing.join(", "),
    );
}

use _components::branded_404_body;

#[layout]
pub(crate) async fn root_layout(cx: &Cx, slot: Slot<'_>) -> Result<impl View> {
    Ok(view! {
        cx =>
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
            <body>
                error_boundary(
                    fallback: |error| {
                        if error.downcast_ref::<NotFoundError>().is_none() {
                            return Err(error);
                        }
                        Ok(
                            view! {
                                (StatusCode::NOT_FOUND)
                                branded_404_body()
                            },
                        )
                    },
                    (slot)
                )
            </body>
        </html>
    })
}

/// Site-wide security headers + trailing-slash 308. `path()` is `None` so
/// unmatched URLs (`/login/`) still run this layer (Topcoat 0.6).
struct SecurityHeaders;

impl Layer for SecurityHeaders {
    fn path(&self) -> Option<&Path> {
        None
    }

    fn handle<'a>(&'a self, cx: &'a Cx, body: Body, next: Next<'a>) -> LayerFuture<'a> {
        Box::pin(async move { security_headers(cx, body, next).await })
    }
}

async fn security_headers(cx: &Cx, body: Body, next: Next<'_>) -> Result<Response> {
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
    let cx = cx.with(StringIntern::default());
    let mut response = match redirect_to {
        Some(location) => redirect_permanent(&location).into_response(&cx)?,
        None => match next.run(&cx, body).await {
            Ok(response) => response,
            // Handler `Err(redirect/…)` must still get security headers — do not `?` out.
            Err(error) => error.into_response(&cx)?,
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
pub(crate) async fn root(cx: &Cx) -> Result<()> {
    if let Some(user) = current_user(cx).await {
        match post_auth_landing(cx, user).await? {
            PostAuthLanding::Org(slug) => {
                return Err(redirect(
                    href!(crate::app::org::dashboard, crate::app::org::Org(slug)).resolve(cx),
                )
                .into());
            }
            PostAuthLanding::ChooseOrg => {
                return Err(redirect(href!(crate::app::login::choose_org_page).resolve(cx)).into());
            }
            PostAuthLanding::None => {}
        }
    }
    Err(redirect(href!(crate::app::login::login_page).resolve(cx)).into())
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

/// Scan this cfg(test) harness so integration tests (same lib OUT_DIR) resolve
/// Tailwind / runtime AssetIds. `topcoat asset bundle --profile test` rebuilds
/// the non-test bin and hashes a different OUT_DIR.
#[cfg(test)]
mod asset_bundle_tests {
    use std::path::PathBuf;

    use topcoat_asset::{Bundler, BundlerConfig};

    #[test]
    fn bundle_test_harness_assets_into_debug_assets() {
        let exe = std::env::current_exe().expect("current_exe");
        let bytes = std::fs::read(&exe).expect("read test harness");
        let config = BundlerConfig::new();
        let bundler = Bundler::new(&config);
        let debug_out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/debug/assets");
        bundler
            .bundle(&bytes, &debug_out)
            .expect("bundle target/debug/assets");
        if let Some(parent) = exe.parent() {
            bundler
                .bundle(&bytes, parent.join("assets"))
                .expect("bundle next to test harness");
        }
        assert!(
            debug_out.join("manifest.toml").is_file(),
            "test harness bundle must write manifest.toml"
        );
    }
}
