//! Module router root: `/` redirect, `/login`, `/{org}/…`.

mod _components;
mod login;
mod org;

use std::sync::Arc;

use toasty::Db;
use topcoat::{
    Result,
    asset::{AssetBundle, RouterBuilderAssetExt},
    context::{CxBuilder, try_app_context},
    cookie::RouterBuilderCookieExt,
    font,
    router::{
        Body, HeaderValue, Next, Response, Router, RouterBuilderDiscoverExt, SeeOther, Slot, layer,
        layout, route, see_other,
    },
    session::{Config as SessionConfig, RouterBuilderSessionExt},
    tailwind,
    view::view,
};

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
    if enable_hsts {
        response.headers_mut().insert(
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
