use topcoat::{
    Result,
    context::Cx,
    view::{component, view},
};

use crate::auth::require_org;

/// Org topbar chrome. Resolves org name via memoized `require_org`.
#[component]
pub async fn vb_topbar(cx: &Cx, org_slug: &str, crumb: &str) -> Result {
    let ctx = require_org(cx, org_slug).await?;
    let org_slug = org_slug.to_owned();
    let org_name = ctx.org.name.clone();
    let crumb = crumb.to_owned();

    view! {
        cx =>
        <header class="vb-topbar">
            <div class="vb-crumb">
                <span class="root">"vauban://portal"</span>
                <span>"/"</span>
                <span>(org_slug)</span>
                <span>"/"</span>
                <span class="active">(crumb)</span>
            </div>
            <div class="vb-org-label">(org_name)</div>
        </header>
    }
}
