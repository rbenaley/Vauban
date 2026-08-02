//! Org-scoped routes under `/{org}/…`.

mod account;
mod builds;
mod docs;
mod issues;

pub use builds::builds_list_href;

use topcoat::{
    Result,
    context::Cx,
    router::{layout, page, path_param},
    view::view,
};

use crate::{
    auth::require_org,
    dashboard_stats::{DASHBOARD_ISSUES_CAP, latest_issue_by_updated_at, summarize_issue_stats},
    db::now_unix,
    models::{DOC_STATUS_PUBLISHED, DocArticle, Issue, RESERVED_ORG_SLUG},
    nav::nav_from_cx,
    tz::{browser_tz, format_relative, format_unix_local},
    ui::{channel_badge_class, note_tag_color},
};

use super::_components::{ico_builds, ico_docs, ico_issues, vb_rail, vb_topbar};

#[path_param]
pub struct Org(str);

#[layout]
async fn org_layout(cx: &Cx, slot: Result) -> Result {
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
                <div class="vb-scroll"><div class="vb-screen">(slot?)</div></div>
            </div>
        </div>
    }
}

#[page]
async fn dashboard(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;

    let releases = builds::load_releases_for_org(cx, ctx.org.id, slug, "").await;
    let mut database = crate::auth::db(cx);
    let org_id = ctx.org.id;
    // Typical orgs have tens of issues — one org-scoped load + Rust stats
    // beats multiple SQL COUNT round-trips (capacity audit dashboard fan-out).
    let org_issues = Issue::all()
        .filter(Issue::fields().organization_id().eq(org_id))
        .order_by(Issue::fields().updated_at().desc())
        .limit(DASHBOARD_ISSUES_CAP)
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let issue_stats = summarize_issue_stats(&org_issues);
    let open_count = issue_stats.open_count;
    let in_analysis = issue_stats.in_analysis_count;
    let latest_issue = latest_issue_by_updated_at(&org_issues).cloned();
    let article_count = DocArticle::all()
        .filter(DocArticle::fields().status().eq(DOC_STATUS_PUBLISHED))
        .count()
        .exec(&mut database)
        .await
        .unwrap_or(0) as usize;
    let latest_doc_row = DocArticle::all()
        .filter(DocArticle::fields().status().eq(DOC_STATUS_PUBLISHED))
        .order_by(DocArticle::fields().updated_at().desc())
        .limit(1)
        .exec(&mut database)
        .await
        .unwrap_or_default()
        .into_iter()
        .next();

    let issues_href = if slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG) {
        "/admin/issues".to_owned()
    } else {
        format!("/{slug}/issues")
    };

    let latest_release = releases.first();
    let build_version = latest_release
        .map(|r| r.version.clone())
        .unwrap_or_else(|| "—".to_owned());
    let build_channel = latest_release
        .map(|r| r.channel.clone())
        .unwrap_or_else(|| "LTS".to_owned());
    let build_notes = latest_release.map(|r| r.notes.clone()).unwrap_or_default();
    let build_released_on = latest_release
        .map(|r| r.released_on.clone())
        .unwrap_or_default();

    let note_lines: Vec<(String, String, &'static str)> = build_notes
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            if let Some((tag, rest)) = line.split_once(':') {
                let tag = tag.trim().to_owned();
                let color = note_tag_color(&tag);
                (tag, rest.trim().to_owned(), color)
            } else {
                (
                    "NOTE".to_owned(),
                    line.trim().to_owned(),
                    note_tag_color("NOTE"),
                )
            }
        })
        .collect();
    let channel_badge = channel_badge_class(&build_channel).to_owned();

    let tz = browser_tz(cx);
    let now = now_unix();
    let issue_activity = latest_issue.as_ref().map(|issue| {
        let copy = if issue.status.eq_ignore_ascii_case("In analysis") {
            " moved to analysis"
        } else if issue.status.eq_ignore_ascii_case("Resolved")
            || issue.status.eq_ignore_ascii_case("Closed")
        {
            " was closed"
        } else {
            " was updated"
        };
        (
            issue.key.clone(),
            copy,
            format_relative(issue.updated_at, now, tz),
        )
    });
    let latest_doc = latest_doc_row
        .as_ref()
        .map(|a| (a.title.clone(), format_unix_local(a.updated_at, tz)));

    view! {
        <h1 class="vb-title dash">"Dashboard"</h1>

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
                    (ico_docs(cx, 20).await?)
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
                <div class="vb-link">"Open"</div>
            </a>
            <a
                class="vb-card"
                href=(format!("/{}/builds", slug))
                style="padding: 20px; min-height: 168px;"
            >
                <div
                    style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;"
                >
                    (ico_builds(cx, 20).await?)
                    <span
                        class="vb-mono vb-signed"
                        style="font-size: 10px; color: var(--ok);"
                    >
                        (build_version.clone())
                        " · signed"
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
                <div class="vb-link">"Open"</div>
            </a>
            <a
                class="vb-card"
                href=(issues_href)
                style="padding: 20px; min-height: 168px;"
            >
                <div
                    style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;"
                >
                    (ico_issues(cx, 20).await?)
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
                <div class="vb-link">"Open"</div>
            </a>
        </div>

        <div class="vb-grid-2">
            <div class="vb-panel">
                <div class="vb-section-label">"RECENT ACTIVITY"</div>
                if !build_version.is_empty() && build_version != "—" {
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
                            (build_released_on.clone())
                        </div>
                    </div>
                }
                if let Some((key, copy, when)) = issue_activity {
                    <div class="vb-activity-item">
                        <div class="vb-dot warn"></div>
                        <div style="flex: 1; font-size: 13.5px; color: #3a3f46;">
                            <span
                                class="vb-mono"
                                style="color: var(--accent); font-size: 12.5px;"
                            >
                                (key)
                            </span>
                            (copy)
                        </div>
                        <div class="vb-mono" style="font-size: 11px; color: #9aa0a6;">
                            (when)
                        </div>
                    </div>
                }
                if let Some((title, when)) = latest_doc {
                    <div class="vb-activity-item">
                        <div class="vb-dot muted"></div>
                        <div style="flex: 1; font-size: 13.5px; color: #3a3f46;">
                            (title)
                            " — documentation updated"
                        </div>
                        <div class="vb-mono" style="font-size: 11px; color: #9aa0a6;">
                            (when)
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
                    <span class=(channel_badge.clone())>(build_channel)</span>
                    <span
                        class="vb-mono vb-signed"
                        style="font-size: 11px; color: var(--ok);"
                    >
                        "signed"
                    </span>
                </div>
                for (tag, text, color) in note_lines {
                    <div
                        style="display: flex; gap: 8px; align-items: baseline; margin-bottom: 7px;"
                    >
                        <span
                            class="vb-mono"
                            style=(format!(
                                "font-size: 9px; font-weight: 600; letter-spacing: 0.04em; color: {color}; flex: none;"
                            ))
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
                    "All builds"
                </a>
            </div>
        </div>
    }
}
