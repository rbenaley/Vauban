use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{Form, SeeOther, page, route, see_other},
    session,
    view::view,
};

use crate::{
    auth::{current_user, db, delete_session_hash, persist_session},
    db::verify_password,
    layout,
    models::{Membership, Organization, User},
};

#[page]
async fn login_page(cx: &Cx) -> Result {
    let continue_slug = if let Some(user) = current_user(cx).await {
        first_org_slug(cx, user.id).await?
    } else {
        None
    };

    layout::login_shell(
        cx,
        view! {
            <h2>"Sign in"</h2>
            <p class="vb-muted">"Access your customer organization."</p>
            if let Some(slug) = continue_slug.clone() {
                <p style="margin: 0 0 16px;">
                    <a class="vb-btn" href=(format!("/{slug}"))>"Continue to portal"</a>
                </p>
            }
            <form method="POST" action="/login">
                <label for="email">"Email"</label>
                <input id="email" name="email" type="email" required="" autocomplete="username">
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
                "Seed: admin@acme.example / password"
            </p>
        },
    )
    .await
}

#[derive(Deserialize)]
struct LoginForm {
    email: String,
    password: String,
}

#[route(POST "/login")]
async fn login(cx: &Cx, Form(form): Form<LoginForm>) -> Result<SeeOther> {
    let mut database = db(cx);
    let email = form.email.trim().to_lowercase();
    let users = User::all()
        .filter(User::fields().email().eq(&email))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let Some(user) = users.into_iter().next() else {
        return Ok(see_other("/login"));
    };
    if !verify_password(&form.password, &user.password_hash) {
        return Ok(see_other("/login"));
    }

    let session = session::start(cx).await?;
    persist_session(cx, session, user.id).await?;

    let slug = first_org_slug(cx, user.id)
        .await?
        .unwrap_or_else(|| "acme-infrastructure".to_owned());
    Ok(see_other(&format!("/{slug}")))
}

#[route(POST "/logout")]
async fn logout(cx: &Cx) -> Result<SeeOther> {
    if let Some(hash) = session::stop(cx).await? {
        delete_session_hash(cx, &hash).await?;
    }
    Ok(see_other("/login"))
}

async fn first_org_slug(cx: &Cx, user_id: u64) -> Result<Option<String>> {
    let mut database = db(cx);
    let memberships = Membership::all()
        .filter(Membership::fields().user_id().eq(user_id))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let Some(m) = memberships.into_iter().next() else {
        return Ok(None);
    };
    match Organization::get_by_id(&mut database, m.organization_id).await {
        Ok(org) => Ok(Some(org.slug)),
        Err(_) => Ok(None),
    }
}
