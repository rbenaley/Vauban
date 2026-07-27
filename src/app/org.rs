//! Org-scoped routes under `/{org}/…`.

mod account;
mod admin;
mod builds;
mod docs;
mod issues;

use topcoat::{
    Result,
    context::Cx,
    router::{Slot, layout, page, path_param},
    view::view,
};

use crate::{
    auth::require_org,
    models::{DocArticle, Issue, Release},
    nav::nav_from_cx,
};

use super::_components::{vb_rail, vb_topbar};

#[path_param]
pub struct Org(str);

#[layout]
async fn org_layout(cx: &Cx, slot: Slot<'_>) -> Result {
    let slug = path_param::<Org>(cx);
    // Membership gate (memoized; rail/topbar re-use the same lookup).
    let _ctx = require_org(cx, slug).await?;
    let (section, crumb) = nav_from_cx(cx);
    let org_slug = slug.to_owned();

    view! {
        cx =>
        <div class="vb-shell">
            vb_rail(org_slug: &org_slug, section: section)
            <div class="vb-main">
                vb_topbar(org_slug: &org_slug, crumb: &crumb)
                <div class="vb-scroll"><div class="vb-screen">(slot.await?)</div></div>
            </div>
        </div>
    }
}

#[page]
async fn dashboard(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;

    let mut database = crate::auth::db(cx);
    let releases = Release::all().exec(&mut database).await.unwrap_or_default();
    let issues = Issue::all()
        .filter(Issue::fields().organization_id().eq(ctx.org.id))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let articles = DocArticle::all()
        .exec(&mut database)
        .await
        .unwrap_or_default();

    let build_version = releases
        .first()
        .map(|r| r.version.clone())
        .unwrap_or_else(|| "—".to_owned());
    let build_channel = releases
        .first()
        .map(|r| r.channel.clone())
        .unwrap_or_else(|| "LTS".to_owned());
    let build_notes = releases
        .first()
        .map(|r| r.notes.clone())
        .unwrap_or_default();
    let open_count = issues
        .iter()
        .filter(|i| i.status != "Resolved" && i.status != "Closed")
        .count();
    let in_analysis = issues.iter().filter(|i| i.status == "In analysis").count();
    let article_count = articles.len();

    let note_lines: Vec<(String, String)> = build_notes
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            if let Some((tag, rest)) = line.split_once(':') {
                (tag.trim().to_owned(), rest.trim().to_owned())
            } else {
                ("NOTE".to_owned(), line.trim().to_owned())
            }
        })
        .collect();

    view! {
        <h1 class="vb-title">"Dashboard"</h1>

        <div class="vb-stat-row">
            <div class="vb-stat">
                <div class="vb-stat-label">"CURRENT BUILD"</div>
                <div class="vb-stat-value">(build_version.clone())</div>
            </div>
            <div class="vb-stat">
                <div class="vb-stat-label">"OPEN ISSUES"</div>
                <div class="vb-stat-value">(open_count.to_string())</div>
            </div>
            <div class="vb-stat">
                <div class="vb-stat-label">"IN ANALYSIS"</div>
                <div class="vb-stat-value warn">(in_analysis.to_string())</div>
            </div>
        </div>

        <div class="vb-grid-3">
            <a
                class="vb-card"
                href=(format!("/{}/docs", slug))
                style="padding: 20px; min-height: 168px;"
            >
                <div
                    style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;"
                >
                    <span style="font-size: 20px;">"❏"</span>
                    <span
                        class="vb-mono"
                        style="font-size: 10px; color: var(--muted-2);"
                    >
                        (article_count.to_string())
                        " articles"
                    </span>
                </div>
                <div style="font-size: 16px; font-weight: 700; margin-bottom: 5px;">
                    "Documentation"
                </div>
                <div
                    style="font-size: 13px; color: var(--muted); line-height: 1.45; flex: 1;"
                >
                    "Guides, API reference, and deployment runbooks."
                </div>
                <div class="vb-link">"Open →"</div>
            </a>
            <a
                class="vb-card"
                href=(format!("/{}/builds", slug))
                style="padding: 20px; min-height: 168px;"
            >
                <div
                    style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;"
                >
                    <span style="font-size: 20px;">"⬡"</span>
                    <span class="vb-mono" style="font-size: 10px; color: var(--ok);">
                        (build_version.clone())
                        " · signed ✓"
                    </span>
                </div>
                <div style="font-size: 16px; font-weight: 700; margin-bottom: 5px;">
                    "LTS builds & changelogs"
                </div>
                <div
                    style="font-size: 13px; color: var(--muted); line-height: 1.45; flex: 1;"
                >
                    "Signed, verified binaries with long-term support."
                </div>
                <div class="vb-link">"Open →"</div>
            </a>
            <a
                class="vb-card"
                href=(format!("/{}/issues", slug))
                style="padding: 20px; min-height: 168px;"
            >
                <div
                    style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;"
                >
                    <span style="font-size: 20px;">"⚑"</span>
                    <span class="vb-mono" style="font-size: 10px; color: var(--warn);">
                        (open_count.to_string())
                        " open"
                    </span>
                </div>
                <div style="font-size: 16px; font-weight: 700; margin-bottom: 5px;">
                    "Issue tracker"
                </div>
                <div
                    style="font-size: 13px; color: var(--muted); line-height: 1.45; flex: 1;"
                >
                    "Report an issue. Initial analysis within 2–5 business days."
                </div>
                <div class="vb-link">"Open →"</div>
            </a>
        </div>

        <div class="vb-grid-2">
            <div class="vb-panel">
                <div class="vb-section-label">"RECENT ACTIVITY"</div>
                <div class="vb-activity-item">
                    <div class="vb-dot"></div>
                    <div style="flex: 1; font-size: 13.5px; color: #3a3f46;">
                        <span
                            class="vb-mono"
                            style="color: var(--accent); font-size: 12.5px;"
                        >
                            (build_version.clone())
                        </span>
                        " ("
                        (build_channel.clone())
                        ") certified and signed"
                    </div>
                    <div class="vb-mono" style="font-size: 11px; color: #9aa0a6;">
                        "Jun 23"
                    </div>
                </div>
                if let Some(issue) = issues.first() {
                    <div class="vb-activity-item">
                        <div class="vb-dot warn"></div>
                        <div style="flex: 1; font-size: 13.5px; color: #3a3f46;">
                            <span
                                class="vb-mono"
                                style="color: var(--accent); font-size: 12.5px;"
                            >
                                (issue.key.clone())
                            </span>
                            " moved to analysis"
                        </div>
                        <div class="vb-mono" style="font-size: 11px; color: #9aa0a6;">
                            "3h ago"
                        </div>
                    </div>
                }
                if let Some(doc) = articles.first() {
                    <div class="vb-activity-item">
                        <div class="vb-dot muted"></div>
                        <div style="flex: 1; font-size: 13.5px; color: #3a3f46;">
                            (doc.title.clone())
                            " — documentation updated"
                        </div>
                        <div class="vb-mono" style="font-size: 11px; color: #9aa0a6;">
                            "Jun 12"
                        </div>
                    </div>
                }
            </div>
            <div class="vb-panel">
                <div class="vb-section-label">"LATEST CERTIFIED BUILD"</div>
                <div
                    style="display: flex; align-items: baseline; gap: 10px; margin-bottom: 12px; flex-wrap: wrap;"
                >
                    <span class="vb-mono" style="font-size: 22px; font-weight: 700;">
                        (build_version)
                    </span>
                    <span class="vb-badge">(build_channel)</span>
                    <span class="vb-mono" style="font-size: 11px; color: var(--ok);">
                        "signed ✓"
                    </span>
                </div>
                for (tag, text) in note_lines {
                    <div style="display: flex; gap: 10px; margin-bottom: 8px;">
                        <span
                            class="vb-mono"
                            style="font-size: 9px; font-weight: 600; color: var(--ok); flex: none;"
                        >
                            (tag)
                        </span>
                        <span
                            style="font-size: 13px; color: #5a5f66; line-height: 1.5;"
                        >
                            (text)
                        </span>
                    </div>
                }
                <a
                    class="vb-link"
                    href=(format!("/{}/builds", slug))
                    style="display: inline-block; margin-top: 14px;"
                >
                    "All builds →"
                </a>
            </div>
        </div>
    }
}
