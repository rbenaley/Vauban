//! Shared shell: Concept mockup rail, topbar, fonts (Topcoat SSR).

use topcoat::{Result, context::Cx, view::view};

use crate::{auth::OrgContext, perms::PermissionContext, ui};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NavSection {
    Home,
    Docs,
    Builds,
    Issues,
    Account,
    AdminHome,
    AdminDocs,
    AdminReleases,
    AdminCompanies,
}

fn rail_class(active: bool) -> &'static str {
    if active {
        "vb-rail-item active"
    } else {
        "vb-rail-item"
    }
}

pub async fn shell(
    cx: &Cx,
    ctx: &OrgContext,
    perms: &PermissionContext,
    section: NavSection,
    crumb: &str,
    body: Result,
) -> Result {
    let empty = view! { cx => };
    shell_with_modal(cx, ctx, perms, section, crumb, body, empty).await
}

/// Like [`shell`], but renders a Concept-style overlay (article modal) as a
/// sibling of the main column so `position: fixed` is not clipped by scroll.
pub async fn shell_with_modal(
    cx: &Cx,
    ctx: &OrgContext,
    perms: &PermissionContext,
    section: NavSection,
    crumb: &str,
    body: Result,
    modal: Result,
) -> Result {
    let slug = &ctx.org.slug;
    let home_href = format!("/{slug}");
    let docs_href = format!("/{slug}/docs");
    let builds_href = format!("/{slug}/builds");
    let issues_href = format!("/{slug}/issues");
    let account_href = format!("/{slug}/account");
    let admin_docs_href = format!("/{slug}/admin/docs");
    let admin_rel_href = format!("/{slug}/admin/releases");
    let admin_orgs_href = format!("/{slug}/admin/companies");
    let initials = ui::org_initials(&ctx.org.name);
    let org_name = ctx.org.name.clone();
    let show_admin = perms.admin_view;
    let css = ui::stylesheet();
    let crumb = crumb.to_owned();
    let org_slug = slug.clone();

    view! { cx =>
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>"Vauban Portal"</title>
                <link rel="preconnect" href="https://fonts.googleapis.com">
                <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="">
                <link
                    href="https://fonts.googleapis.com/css2?family=Hanken+Grotesk:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap"
                    rel="stylesheet"
                >
                topcoat::dev::script()
                <style>(css)</style>
            </head>
            <body>
                <div class="vb-shell">
                    <nav class="vb-rail" aria-label="Primary">
                        <svg class="vb-rail-logo" width="28" height="28" viewBox="0 0 100 100" fill="none" aria-hidden="true">
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
                            <span class="ico">"▦"</span>
                            <span>"Home"</span>
                        </a>
                        <a href=(docs_href) class=(rail_class(section == NavSection::Docs))>
                            <span class="ico">"❏"</span>
                            <span>"Docs"</span>
                        </a>
                        <a href=(builds_href) class=(rail_class(section == NavSection::Builds))>
                            <span class="ico">"⬡"</span>
                            <span>"Builds"</span>
                        </a>
                        <a href=(issues_href) class=(rail_class(section == NavSection::Issues))>
                            <span class="ico">"⚑"</span>
                            <span>"Issues"</span>
                        </a>
                        if show_admin {
                            <div class="vb-rail-rule"></div>
                            <div class="vb-rail-admin">"ADMIN"</div>
                            <a href=(admin_docs_href) class=(rail_class(section == NavSection::AdminDocs))>
                                <span class="ico">"✎"</span>
                                <span>"Docs"</span>
                            </a>
                            <a href=(admin_rel_href) class=(rail_class(section == NavSection::AdminReleases))>
                                <span class="ico">"↑"</span>
                                <span>"Rel."</span>
                            </a>
                            <a href=(admin_orgs_href) class=(rail_class(section == NavSection::AdminCompanies))>
                                <span class="ico">"⌂"</span>
                                <span>"Orgs"</span>
                            </a>
                        }
                        <a
                            href=(account_href)
                            class="vb-rail-account"
                            title="Account"
                        >
                            (initials)
                        </a>
                    </nav>
                    <div class="vb-main">
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
                        <div class="vb-scroll">
                            <div class="vb-screen">(body?)</div>
                        </div>
                    </div>
                    (modal?)
                </div>
            </body>
        </html>
    }
}

pub async fn login_shell(cx: &Cx, body: Result) -> Result {
    let css = ui::stylesheet();
    view! { cx =>
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>"Sign in — Vauban Portal"</title>
                <link rel="preconnect" href="https://fonts.googleapis.com">
                <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="">
                <link
                    href="https://fonts.googleapis.com/css2?family=Hanken+Grotesk:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap"
                    rel="stylesheet"
                >
                topcoat::dev::script()
                <style>(css)</style>
            </head>
            <body class="vb-login-body">
                <div class="vb-login-wrap">
                    <div class="vb-login-brand">
                        <svg width="120" height="120" viewBox="0 0 100 100" fill="none" aria-hidden="true">
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
                    <div class="vb-login-panel">(body?)</div>
                </div>
            </body>
        </html>
    }
}
