use topcoat::{
    Result,
    context::Cx,
    view::{component, view},
};

use crate::{auth::require_org, nav::NavSection, perms::perms_for_user, ui};

use super::icons::{ico_builds, ico_docs, ico_edit, ico_home, ico_issues, ico_orgs, ico_release};

/// Org rail chrome. Resolves org/perms via memoized `require_org` (locality).
#[component]
pub async fn vb_rail(cx: &Cx, org_slug: &str, section: NavSection) -> Result {
    let ctx = require_org(cx, org_slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    let org_name = ctx.org.name.clone();
    let show_admin = perms.admin_view;

    let home_href = format!("/{org_slug}");
    let docs_href = format!("/{org_slug}/docs");
    let builds_href = format!("/{org_slug}/builds");
    let issues_href = format!("/{org_slug}/issues");
    let account_href = format!("/{org_slug}/account");
    let admin_docs_href = format!("/{org_slug}/admin/docs");
    let admin_rel_href = format!("/{org_slug}/admin/releases");
    let admin_orgs_href = format!("/{org_slug}/admin/companies");
    let initials = ui::org_initials(&org_name);

    view! {
        cx =>
        <nav class="vb-rail" aria-label="Primary">
            <svg
                class="vb-rail-logo"
                width="28"
                height="28"
                viewBox="0 0 100 100"
                fill="none"
                aria-hidden="true"
            >
                <polygon
                    points="50,4 65,24.02 89.84,27 80,50 89.84,73 65,75.98 50,96 35,75.98 10.16,73 20,50 10.16,27 35,24.02"
                    stroke="color-mix(in srgb, var(--accent,#117a6b) 60%, #fff)"
                    stroke-width="4"
                    stroke-linejoin="round"
                ></polygon>
                <circle
                    cx="50"
                    cy="50"
                    r="9"
                    stroke="color-mix(in srgb, var(--accent,#117a6b) 60%, #fff)"
                    stroke-width="4"
                ></circle>
            </svg>
            <a href=(home_href.clone()) class=(rail_class(section == NavSection::Home))>
                (ico_home(cx, 17).await?)
                <span class="lbl">"Home"</span>
            </a>
            <a href=(docs_href) class=(rail_class(section == NavSection::Docs))>
                (ico_docs(cx, 17).await?)
                <span class="lbl">"Docs"</span>
            </a>
            <a href=(builds_href) class=(rail_class(section == NavSection::Builds))>
                (ico_builds(cx, 17).await?)
                <span class="lbl">"Builds"</span>
            </a>
            <a href=(issues_href) class=(rail_class(section == NavSection::Issues))>
                (ico_issues(cx, 17).await?)
                <span class="lbl">"Issues"</span>
            </a>
            if show_admin {
                <div class="vb-rail-rule"></div>
                <div class="vb-rail-admin">"ADMIN"</div>
                <a
                    href=(admin_docs_href)
                    class=(rail_class(section == NavSection::AdminDocs))
                >
                    (ico_edit(cx, 17).await?)
                    <span class="lbl">"Docs"</span>
                </a>
                <a
                    href=(admin_rel_href)
                    class=(rail_class(section == NavSection::AdminReleases))
                >
                    (ico_release(cx, 17).await?)
                    <span class="lbl">"Rel."</span>
                </a>
                <a
                    href=(admin_orgs_href)
                    class=(rail_class(section == NavSection::AdminCompanies))
                >
                    (ico_orgs(cx, 17).await?)
                    <span class="lbl">"Orgs"</span>
                </a>
            }
            <a href=(account_href) class="vb-rail-account" title="Account">
                (initials)
            </a>
        </nav>
    }
}

fn rail_class(active: bool) -> &'static str {
    if active {
        "vb-rail-item active"
    } else {
        "vb-rail-item"
    }
}
