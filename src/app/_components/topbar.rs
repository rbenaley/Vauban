use topcoat::{
    Result,
    context::Cx,
    view::{component, view},
};

#[component]
pub async fn vb_topbar(cx: &Cx, org_slug: &str, org_name: &str, crumb: &str) -> Result {
    let org_slug = org_slug.to_owned();
    let org_name = org_name.to_owned();
    let crumb = crumb.to_owned();

    view! { cx =>
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
