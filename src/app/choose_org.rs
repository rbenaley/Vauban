//! `/choose-org`: multi-org picker after magic-link / session entry when a
//! client user has more than one membership.
//!
//! A module page (0.8.1) so `root_layout` wraps it; the `/login` splash chrome
//! is composed explicitly because `login_layout` only covers `/login/*`.

use topcoat::{
    Result,
    context::Cx,
    router::{error::redirect, href, page},
    session,
    view::{View, view},
};

use crate::{
    app::{
        login::{login_page, login_splash},
        org::{Org, dashboard},
    },
    auth::{client_orgs_for_user, current_user, delete_session_hash},
    models::{PORTAL_ROLE_ADMIN, RESERVED_ORG_SLUG},
};

/// Navigational GET -> `redirect` (307), not `see_other` (303 PRG).
#[page]
pub(crate) async fn choose_org_page(cx: &Cx) -> Result<impl View> {
    let Some(user) = current_user(cx).await else {
        return Err(redirect(href!(login_page).resolve(cx)).into());
    };

    if user.portal_role == PORTAL_ROLE_ADMIN {
        return Err(redirect(href!(dashboard, Org(RESERVED_ORG_SLUG)).resolve(cx)).into());
    }

    let clients = client_orgs_for_user(cx, user.id).await?;
    match clients.len() {
        0 => {
            if let Some(hash) = session::stop(cx).await? {
                delete_session_hash(cx, &hash).await?;
            }
            return Err(redirect(href!(login_page).resolve(cx)).into());
        }
        1 => {
            return Err(
                redirect(href!(dashboard, Org(clients[0].slug.as_str())).resolve(cx)).into(),
            );
        }
        _ => {}
    }

    Ok(view! {
        cx =>
        login_splash(
            <h2>"Choose an organization"</h2>
            <p class="vb-muted">"Select which organization to open."</p>
            <ul class="vb-login-org-list">
                for org in &clients {
                    <li>
                        <a
                            class="vb-login-org-link"
                            href=(href!(dashboard, Org(org.slug.as_str())))
                        >
                            <span class="vb-login-org-name">(org.name.clone())</span>
                            <span class="vb-login-org-slug vb-mono">(org.slug.clone())</span>
                        </a>
                    </li>
                }
            </ul>
        )
    })
}
