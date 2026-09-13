use topcoat::{
    Result,
    context::Cx,
    router::href,
    view::{View, component, view},
};

use crate::{
    app::{
        admin::{
            companies::admin_companies_page, docs::admin_docs_page, issues::admin_issues_page,
            key::admin_key_page, releases::admin_releases_page,
        },
        org::{
            Org, account::account_page, builds::builds_page, dashboard, docs::docs_page,
            issues::issues_page,
        },
    },
    auth::require_org,
    nav::NavSection,
    perms::perms_for_user,
    release_pkg::org_builds_entitled,
    ui,
};

use super::icons::{
    ico_builds, ico_docs, ico_edit, ico_home, ico_issues, ico_key, ico_orgs, ico_release,
};

/// Org rail chrome. Resolves org/perms via memoized `require_org` (locality).
#[component]
pub async fn vb_rail(cx: &Cx, org_slug: &str, section: NavSection) -> Result<impl View> {
    let ctx = require_org(cx, org_slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    let org_name = ctx.org.name.clone();
    let show_admin = perms.admin_view;
    let show_builds = org_builds_entitled(
        org_slug,
        ctx.org.lts_subscriptions,
        ctx.org.industrial_lts_subscriptions,
    );

    let home = href!(dashboard, Org(org_slug));
    let home_href = home.resolve(cx);
    let docs = href!(docs_page, Org(org_slug));
    let docs_href = docs.resolve(cx);
    let builds = href!(builds_page, Org(org_slug));
    let builds_href = builds.resolve(cx);
    // Staff Issues live under `/admin/issues` (not `/{org}/issues`).
    let issues_href = if show_admin {
        href!(admin_issues_page).resolve(cx)
    } else {
        href!(issues_page, Org(org_slug)).resolve(cx)
    };
    let issues_current = if show_admin {
        href!(admin_issues_page).is_current(cx)
    } else {
        href!(issues_page, Org(org_slug)).is_current(cx)
    };
    let account_href = href!(account_page, Org(org_slug)).resolve(cx);
    let admin_issues = href!(admin_issues_page);
    let admin_issues_href = admin_issues.resolve(cx);
    let admin_docs = href!(admin_docs_page);
    let admin_docs_href = admin_docs.resolve(cx);
    let admin_releases = href!(admin_releases_page);
    let admin_releases_href = admin_releases.resolve(cx);
    let admin_companies = href!(admin_companies_page);
    let admin_companies_href = admin_companies.resolve(cx);
    let admin_key = href!(admin_key_page);
    let admin_key_href = admin_key.resolve(cx);
    let initials = ui::org_initials(&org_name);

    Ok(view! {
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
            <a
                href=(home_href.clone())
                class=(rail_class(section == NavSection::Home || home.is_current(cx)))
            >
                ico_home(size: 17)
                <span class="lbl">"Home"</span>
            </a>
            <a
                href=(docs_href)
                class=(rail_class(section == NavSection::Docs || docs.is_current(cx)))
            >
                ico_docs(size: 17)
                <span class="lbl">"Docs"</span>
            </a>
            if show_builds {
                <a
                    href=(builds_href)
                    class=(rail_class(
                        section == NavSection::Builds || builds.is_current(cx),
                    ))
                >
                    ico_builds(size: 17)
                    <span class="lbl">"Builds"</span>
                </a>
            }
            <a
                href=(issues_href.clone())
                class=(rail_class(
                    section == NavSection::Issues
                        || section == NavSection::AdminIssues
                        || issues_current,
                ))
            >
                ico_issues(size: 17)
                <span class="lbl">"Issues"</span>
            </a>
            if show_admin {
                <div class="vb-rail-rule"></div>
                <div class="vb-rail-admin">"ADMIN"</div>
                <a
                    href=(admin_issues_href)
                    class=(rail_class(
                        section == NavSection::AdminIssues
                            || admin_issues.is_current(cx),
                    ))
                >
                    ico_issues(size: 17)
                    <span class="lbl">"Issues"</span>
                </a>
                <a
                    href=(admin_docs_href)
                    class=(rail_class(
                        section == NavSection::AdminDocs || admin_docs.is_current(cx),
                    ))
                >
                    ico_edit(size: 17)
                    <span class="lbl">"Docs"</span>
                </a>
                <a
                    href=(admin_releases_href)
                    class=(rail_class(
                        section == NavSection::AdminReleases
                            || admin_releases.is_current(cx),
                    ))
                >
                    ico_release(size: 17)
                    <span class="lbl">"Rel."</span>
                </a>
                <a
                    href=(admin_companies_href)
                    class=(rail_class(
                        section == NavSection::AdminCompanies
                            || admin_companies.is_current(cx),
                    ))
                >
                    ico_orgs(size: 17)
                    <span class="lbl">"Orgs"</span>
                </a>
                if perms.key_manage {
                    <a
                        href=(admin_key_href)
                        class=(rail_class(
                            section == NavSection::AdminKey || admin_key.is_current(cx),
                        ))
                    >
                        ico_key(size: 17)
                        <span class="lbl">"Keys"</span>
                    </a>
                }
            }
            <a href=(account_href) class="vb-rail-account" title="Account">
                (initials)
            </a>
        </nav>
    })
}

fn rail_class(active: bool) -> &'static str {
    if active {
        "vb-rail-item active"
    } else {
        "vb-rail-item"
    }
}
