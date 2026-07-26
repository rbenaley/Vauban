//! Module router root: `/` redirect, `/login`, `/{org}/…`.

mod _components;
mod login;
mod org;

use std::sync::Arc;

use toasty::Db;
use topcoat::{
    Result,
    asset::{Asset, AssetBundle, RouterBuilderAssetExt, asset},
    context::{CxBuilder, try_app_context},
    cookie::RouterBuilderCookieExt,
    font,
    router::{
        Body, HeaderValue, Next, Response, Router, RouterBuilderDiscoverExt, SeeOther, Slot,
        StatusCode, header, layer, layout, route, see_other,
    },
    session::{Config as SessionConfig, RouterBuilderSessionExt},
    tailwind,
    view::view,
};

/// Brand mark for `<link rel="icon" type="image/svg+xml">`.
const FAVICON_SVG: Asset = asset!("assets/favicon.svg");
const FAVICON_16: Asset = asset!("assets/favicon-16x16.png");
const FAVICON_32: Asset = asset!("assets/favicon-32x32.png");
const APPLE_TOUCH_ICON: Asset = asset!("assets/apple-touch-icon.png");

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
    config::{Config, Environment},
    fonts::{HANKEN_GROTESK, JETBRAINS_MONO},
    perms::PolicyStore,
};

/// When true, the security layer attaches HSTS on every response.
#[derive(Clone, Copy)]
struct EnableHsts(bool);

pub fn router(db: Db, policy: Arc<PolicyStore>, cfg: &Config) -> Router {
    let mut sessions = SessionConfig::builder();
    for origin in &cfg.server.public_origins {
        sessions = sessions.trust_origin(origin.clone());
    }
    if cfg.session.dangerous_disable_origin_verification {
        sessions = sessions.dangerous_disable_origin_verification();
    }
    let sessions = sessions.build();

    let assets = load_assets(cfg.environment);
    let enable_hsts = EnableHsts(cfg.environment == Environment::Production);

    topcoat::router::module_router!()
        .cookies()
        .sessions(sessions)
        .assets(assets)
        .app_context(db)
        .app_context(policy)
        .app_context(enable_hsts)
        .discover()
        .build()
}

fn load_assets(env: Environment) -> AssetBundle {
    match AssetBundle::load() {
        Ok(bundle) => bundle,
        Err(err) => {
            if env.is_production() {
                panic!("asset bundle required in production: {err}");
            }
            tracing::warn!(
                error = %err,
                "asset bundle missing; run `topcoat asset bundle` after `cargo build` \
                 (or use `just run` / `just test`)"
            );
            AssetBundle::empty()
        }
    }
}

#[layout]
async fn root_layout(slot: Slot<'_>) -> Result {
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
                topcoat::runtime::script()
                topcoat::dev::script()
            </head>
            <body>(slot.await?)</body>
        </html>
    }
}

#[layer]
async fn security_headers(cx: &mut CxBuilder, body: Body, next: Next<'_>) -> Result<Response> {
    let enable_hsts = try_app_context::<EnableHsts>(cx)
        .map(|h| h.0)
        .unwrap_or(false);
    let mut response = next.run(cx, body).await?;
    let headers = response.headers_mut();
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
    Ok(response)
}

/// Unauthenticated entry: send browsers to the login form.
#[route(GET "/")]
async fn root() -> Result<SeeOther> {
    Ok(see_other("/login"))
}

/// Browser / OS probes that otherwise spam CLF with 404s.
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
