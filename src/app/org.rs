//! Org-scoped routes under `/{org}/…`.

mod account;
mod admin;
mod builds;
mod docs;
mod issues;

use topcoat::{
    Result,
    context::Cx,
    router::{page, path_param},
    view::view,
};

use crate::{
    auth::require_org,
    layout::{self, NavSection},
    models::{Issue, Release},
    perms::perms_for_user,
};

#[path_param]
pub struct Org(str);

#[page]
async fn dashboard(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;

    let mut database = crate::auth::db(cx);
    let releases = Release::all().exec(&mut database).await.unwrap_or_default();
    let issues = Issue::all()
        .filter(Issue::fields().organization_id().eq(ctx.org.id))
        .exec(&mut database)
        .await
        .unwrap_or_default();

    let build_version = releases
        .first()
        .map(|r| r.version.clone())
        .unwrap_or_else(|| "—".to_owned());
    let open_count = issues
        .iter()
        .filter(|i| i.status != "Resolved" && i.status != "Closed")
        .count();
    let in_analysis = issues.iter().filter(|i| i.status == "In analysis").count();

    let body = view! {
        <h1>"Dashboard"</h1>
        <p class="muted">"Overview for " (ctx.org.name.clone()) "."</p>
        <div style="display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin: 20px 0;">
            <div class="card">
                <div class="muted" style="font-family: ui-monospace, monospace; font-size: 10px;">
                    "CURRENT BUILD"
                </div>
                <div style="font-family: ui-monospace, monospace; font-size: 22px; font-weight: 700; margin-top: 6px;">
                    (build_version.clone())
                </div>
            </div>
            <div class="card">
                <div class="muted" style="font-family: ui-monospace, monospace; font-size: 10px;">
                    "OPEN ISSUES"
                </div>
                <div style="font-family: ui-monospace, monospace; font-size: 22px; font-weight: 700; margin-top: 6px;">
                    (open_count.to_string())
                </div>
            </div>
            <div class="card">
                <div class="muted" style="font-family: ui-monospace, monospace; font-size: 10px;">
                    "IN ANALYSIS"
                </div>
                <div style="font-family: ui-monospace, monospace; font-size: 22px; font-weight: 700; margin-top: 6px; color: #a67c2d;">
                    (in_analysis.to_string())
                </div>
            </div>
        </div>
        <div style="display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px;">
            <a class="card" href=(format!("/{}/docs", slug)) style="text-decoration: none; color: inherit;">
                <div style="font-weight: 700;">"Documentation"</div>
                <p class="muted">"Guides, API reference, and deployment runbooks."</p>
            </a>
            <a class="card" href=(format!("/{}/builds", slug)) style="text-decoration: none; color: inherit;">
                <div style="font-weight: 700;">"LTS builds & changelogs"</div>
                <p class="muted">"Signed, verified binaries with long-term support."</p>
                <div style="font-family: ui-monospace, monospace; font-size: 12px; color: var(--accent);">
                    (build_version)
                    " · signed"
                </div>
            </a>
            <a class="card" href=(format!("/{}/issues", slug)) style="text-decoration: none; color: inherit;">
                <div style="font-weight: 700;">"Issue tracker"</div>
                <p class="muted">"Report an issue. Initial analysis within 2–5 business days."</p>
            </a>
        </div>
    };

    layout::shell(cx, &ctx, &perms, NavSection::Home, "dashboard", body).await
}
