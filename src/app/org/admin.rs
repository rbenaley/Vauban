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

use crate::{app::org::Org, auth::require_org, perms::perms_for_user};

#[page]
async fn admin_index(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.admin_view {
        return Err(forbidden().into());
    }

    view! {
        <h1 class="vb-title">"Administration"</h1>
        <p class="vb-lead">"Manage documentation, releases, and client companies."</p>
        <div class="vb-grid-3">
            <a
                class="vb-card"
                href=(format!("/{}/admin/docs", slug))
                style="padding: 20px; min-height: 140px;"
            >
                <div style="font-size: 20px; margin-bottom: 12px;">"✎"</div>
                <div style="font-weight: 700; margin-bottom: 5px;">
                    "Documentation editor"
                </div>
                <div class="vb-muted" style="font-size: 13px; flex: 1;">
                    "Publish and revise the knowledge base."
                </div>
                <div class="vb-link">"Open →"</div>
            </a>
            <a
                class="vb-card"
                href=(format!("/{}/admin/releases", slug))
                style="padding: 20px; min-height: 140px;"
            >
                <div style="font-size: 20px; margin-bottom: 12px;">"↑"</div>
                <div style="font-weight: 700; margin-bottom: 5px;">
                    "Release manager"
                </div>
                <div class="vb-muted" style="font-size: 13px; flex: 1;">
                    "Channels, signatures, and build metadata."
                </div>
                <div class="vb-link">"Open →"</div>
            </a>
            <a
                class="vb-card"
                href=(format!("/{}/admin/companies", slug))
                style="padding: 20px; min-height: 140px;"
            >
                <div style="font-size: 20px; margin-bottom: 12px;">"⌂"</div>
                <div style="font-weight: 700; margin-bottom: 5px;">
                    "Client companies"
                </div>
                <div class="vb-muted" style="font-size: 13px; flex: 1;">
                    "Tenants, plans, and seat limits (max 5 users)."
                </div>
                <div class="vb-link">"Open →"</div>
            </a>
        </div>
    }
}
