//! Shared shell: dark rail, breadcrumb, accent teal.

use topcoat::{Result, context::Cx, view::view};

use crate::{auth::OrgContext, perms::PermissionContext};

/// Brand accent (teal) shared with Concept mockups.
pub const ACCENT: &str = "#117a6b";

fn accent_root_css() -> String {
    format!(":root {{ --accent: {ACCENT}; }}")
}

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

fn org_initials(name: &str) -> String {
    let mut initials = String::new();
    for part in name.split_whitespace().take(2) {
        if let Some(c) = part.chars().next() {
            initials.push(c.to_ascii_uppercase());
        }
    }
    if initials.is_empty() {
        initials.push('V');
    }
    initials
}

pub async fn shell(
    cx: &Cx,
    ctx: &OrgContext,
    perms: &PermissionContext,
    section: NavSection,
    crumb: &str,
    body: Result,
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
    let initials = org_initials(&ctx.org.name);
    let org_name = ctx.org.name.clone();
    let user_label = ctx.user.display_name.clone();
    let show_admin = perms.admin_view;
    let root_css = accent_root_css();

    view! { cx =>
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>"Vauban Portal"</title>
                topcoat::dev::script()
                <style>
                    (root_css)
                    "body { margin: 0; font-family: 'IBM Plex Sans', 'Segoe UI', sans-serif; background: #eef0ec; color: #14171c; }"
                    ".rail { width: 64px; background: #1a1e24; color: #c5cbc6; display: flex; flex-direction: column; align-items: center; padding: 12px 0; gap: 8px; min-height: 100vh; }"
                    ".rail a { width: 40px; height: 40px; border-radius: 6px; display: flex; align-items: center; justify-content: center; color: inherit; text-decoration: none; font-size: 11px; text-align: center; line-height: 1.1; }"
                    ".rail a.active { background: var(--accent); color: #0c2520; font-weight: 700; }"
                    ".rail .admin-label { font-family: ui-monospace, monospace; font-size: 8px; letter-spacing: 0.14em; color: #565c64; margin: 10px 0 4px; }"
                    ".shell { display: flex; min-height: 100vh; }"
                    ".main { flex: 1; display: flex; flex-direction: column; min-width: 0; }"
                    ".topbar { display: flex; justify-content: space-between; align-items: center; padding: 14px 28px; font-family: ui-monospace, monospace; font-size: 12px; color: #5a5f66; }"
                    ".content { padding: 8px 28px 40px; }"
                    ".card { background: #fff; border: 1px solid #e0e2de; border-radius: 4px; padding: 20px; }"
                    ".btn { display: inline-block; background: var(--accent); color: #fff; border-radius: 4px; padding: 10px 16px; text-decoration: none; font-size: 13px; border: 0; cursor: pointer; }"
                    ".muted { color: #6b6f76; font-size: 14px; }"
                    "h1 { font-size: 25px; font-weight: 800; margin: 0 0 6px; letter-spacing: -0.01em; }"
                    "table { width: 100%; border-collapse: collapse; }"
                    "th, td { text-align: left; padding: 12px 10px; border-bottom: 1px solid #e8ebe6; font-size: 14px; }"
                    "th { font-family: ui-monospace, monospace; font-size: 11px; color: #8a8f96; letter-spacing: 0.06em; }"
                </style>
            </head>
            <body>
                <div class="shell">
                    <nav class="rail" aria-label="Primary">
                        <a href=(home_href.clone()) class=(if section == NavSection::Home { "active" } else { "" })>"Home"</a>
                        <a href=(docs_href) class=(if section == NavSection::Docs { "active" } else { "" })>"Docs"</a>
                        <a href=(builds_href) class=(if section == NavSection::Builds { "active" } else { "" })>"Builds"</a>
                        <a href=(issues_href) class=(if section == NavSection::Issues { "active" } else { "" })>"Issues"</a>
                        if show_admin {
                            <div class="admin-label">"ADMIN"</div>
                            <a href=(admin_docs_href) class=(if section == NavSection::AdminDocs { "active" } else { "" })>"Docs"</a>
                            <a href=(admin_rel_href) class=(if section == NavSection::AdminReleases { "active" } else { "" })>"Rel."</a>
                            <a href=(admin_orgs_href) class=(if section == NavSection::AdminCompanies { "active" } else { "" })>"Orgs"</a>
                        }
                        <a
                            href=(account_href)
                            class=(if section == NavSection::Account { "active" } else { "" })
                            style="margin-top: auto; background: color-mix(in srgb, var(--accent) 80%, #fff); color: #0c2520; font-weight: 800;"
                            title="Account"
                        >
                            (initials)
                        </a>
                    </nav>
                    <div class="main">
                        <div class="topbar">
                            <div>
                                "vauban://portal / "
                                (slug.clone())
                                " / "
                                (crumb.to_owned())
                            </div>
                            <div>
                                (org_name)
                                " · "
                                (user_label)
                            </div>
                        </div>
                        <div class="content">(body?)</div>
                    </div>
                </div>
            </body>
        </html>
    }
}

pub async fn login_shell(cx: &Cx, body: Result) -> Result {
    view! { cx =>
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>"Sign in — Vauban Portal"</title>
                topcoat::dev::script()
                <style>
                    "body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; background: #14171c; color: #d6e3df; font-family: 'IBM Plex Sans', sans-serif; }"
                    ".panel { width: min(420px, 92vw); background: #1a1e24; border: 1px solid #2a3038; border-radius: 8px; padding: 28px; }"
                    "h1 { margin: 0 0 8px; font-size: 22px; }"
                    "label { display: block; font-size: 13px; margin: 14px 0 6px; color: #9aa3ab; }"
                    "input { width: 100%; box-sizing: border-box; padding: 10px 12px; border-radius: 4px; border: 1px solid #3a424c; background: #11151a; color: #fff; }"
                    "button { margin-top: 18px; width: 100%; padding: 11px; border: 0; border-radius: 4px; background: #117a6b; color: #fff; font-weight: 600; cursor: pointer; }"
                    ".muted { color: #6b7280; font-size: 13px; margin-bottom: 18px; }"
                    "a.btn { display: inline-block; background: #117a6b; color: #fff; border-radius: 4px; padding: 10px 16px; text-decoration: none; font-size: 13px; }"
                </style>
            </head>
            <body>
                <div class="panel">(body?)</div>
            </body>
        </html>
    }
}
