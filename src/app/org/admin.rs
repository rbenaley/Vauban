//! Admin zone under `/{org}/admin/…` — fail-closed via `admin_view`.

mod companies;
mod docs;
mod releases;

use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, page, path_param},
    view::view,
};

use crate::{
    app::org::Org,
    auth::require_org,
    layout::{self, NavSection},
    perms::perms_for_user,
};

#[page]
async fn admin_index(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.admin_view {
        return Err(forbidden().into());
    }

    let body = view! {
        <h1>"Administration"</h1>
        <p class="muted">"Manage documentation, releases, and client companies."</p>
        <div style="display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin-top: 18px;">
            <a class="card" href=(format!("/{}/admin/docs", slug)) style="text-decoration: none; color: inherit;">
                <div style="font-weight: 700;">"Documentation editor"</div>
                <p class="muted">"Publish and revise the knowledge base."</p>
            </a>
            <a class="card" href=(format!("/{}/admin/releases", slug)) style="text-decoration: none; color: inherit;">
                <div style="font-weight: 700;">"Release manager"</div>
                <p class="muted">"Channels, signatures, and build metadata."</p>
            </a>
            <a class="card" href=(format!("/{}/admin/companies", slug)) style="text-decoration: none; color: inherit;">
                <div style="font-weight: 700;">"Client companies"</div>
                <p class="muted">"Tenants, plans, and seat limits (max 5 users)."</p>
            </a>
        </div>
    };

    layout::shell(cx, &ctx, &perms, NavSection::AdminHome, "admin", body).await
}
