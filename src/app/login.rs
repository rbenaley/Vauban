use std::sync::Arc;

use serde::Deserialize;
use topcoat::{
    Result,
    context::{Cx, app_context},
    router::{
        content::Form,
        error::{SeeOther, redirect, see_other},
        layout, page, route,
    },
    session,
    view::view,
};

use crate::{
    auth::{current_user, db, delete_session_hash, home_org_slug, persist_session},
    login_limit::{LoginRateLimiter, verify_login_password},
    models::{PORTAL_ROLE_ADMIN, RESERVED_ORG_SLUG, User},
};

#[layout]
async fn login_layout(slot: Result) -> Result {
    view! {
        <div class="vb-login-body">
            <div class="vb-login-wrap">
                <div class="vb-login-brand">
                    <svg
                        width="120"
                        height="120"
                        viewBox="0 0 100 100"
                        fill="none"
                        aria-hidden="true"
                    >
                        <polygon
                            points="50,4 65,24.02 89.84,27 80,50 89.84,73 65,75.98 50,96 35,75.98 10.16,73 20,50 10.16,27 35,24.02"
                            stroke="#3ec2ad"
                            stroke-width="4"
                            stroke-linejoin="round"
                        ></polygon>
                        <circle cx="50" cy="50" r="9" stroke="#3ec2ad" stroke-width="4"></circle>
                    </svg>
                    <h1>"VAUBAN"</h1>
                    <p>"CUSTOMER PORTAL"</p>
                </div>
                <div class="vb-login-panel">(slot?)</div>
            </div>
        </div>
    }
}

#[page]
async fn login_page(cx: &Cx) -> Result {
    // Valid session: skip the login form and land on the portal home.
    if let Some(user) = current_user(cx).await
        && let Some(slug) = home_org_slug(cx, user).await?
    {
        return Err(redirect(&format!("/{slug}")).into());
    }

    view! {
        <h2>"Sign in"</h2>
        <p class="vb-muted">"Access your customer organization."</p>
        <form method="POST" action="/login">
            <label for="email">"Email"</label>
            <input
                id="email"
                name="email"
                type="email"
                required=""
                autocomplete="username"
            >
            <label for="password">"Password"</label>
            <input
                id="password"
                name="password"
                type="password"
                required=""
                autocomplete="current-password"
            >
            <button type="submit">"Sign in"</button>
        </form>
        <p class="vb-muted" style="margin-top: 16px; font-size: 12px;">
            "Seed: support@vauban.sh / password · company accounts use password until magic links"
        </p>
    }
}

#[derive(Deserialize)]
struct LoginForm {
    email: String,
    password: String,
}

#[route(POST "/login")]
async fn login(cx: &Cx, Form(form): Form<LoginForm>) -> Result<SeeOther> {
    let email = form.email.trim().to_lowercase();
    let limiter = app_context::<Arc<LoginRateLimiter>>(cx);

    // Locked out: still run dummy verify so timing stays similar, then same redirect.
    let allowed = limiter.allow(&email);
    let mut database = db(cx);
    let users = User::all()
        .filter(User::fields().email().eq(&email))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let user = users.into_iter().next();
    let hash = user.as_ref().map(|u| u.password_hash.as_str());
    let password_ok = verify_login_password(&form.password, hash);

    if !allowed || !password_ok {
        if allowed {
            limiter.record_failure(&email);
        }
        return Ok(see_other("/login"));
    }

    let user = user.expect("password_ok implies user");
    limiter.clear(&email);

    let session = session::start(cx).await?;
    persist_session(cx, session, user.id).await?;

    // Land on the user's real home org — never invent a client slug (e.g. Acme).
    let slug = match home_org_slug(cx, &user).await? {
        Some(slug) => slug,
        None if user.portal_role == PORTAL_ROLE_ADMIN => RESERVED_ORG_SLUG.to_owned(),
        None => {
            // Authenticated but no tenant membership: clear session and stay on login.
            if let Some(hash) = session::stop(cx).await? {
                delete_session_hash(cx, &hash).await?;
            }
            return Ok(see_other("/login"));
        }
    };
    Ok(see_other(&format!("/{slug}")))
}

#[route(POST "/logout")]
async fn logout(cx: &Cx) -> Result<SeeOther> {
    if let Some(hash) = session::stop(cx).await? {
        delete_session_hash(cx, &hash).await?;
    }
    Ok(see_other("/login"))
}
