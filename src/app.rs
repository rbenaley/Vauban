//! Module router root: `/` redirect, `/login`, `/{org}/…`.

mod login;
mod org;

use std::sync::Arc;

use toasty::Db;
use topcoat::{
    Result,
    asset::{AssetBundle, RouterBuilderAssetExt},
    context::{CxBuilder, try_app_context},
    cookie::RouterBuilderCookieExt,
    router::{
        Body, HeaderValue, Next, Response, Router, RouterBuilderDiscoverExt, SeeOther, layer,
        route, see_other,
    },
    session::{Config as SessionConfig, RouterBuilderSessionExt},
};

use crate::{
    config::{Config, Environment},
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

    let assets = AssetBundle::load().unwrap_or_else(|_| AssetBundle::empty());
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
