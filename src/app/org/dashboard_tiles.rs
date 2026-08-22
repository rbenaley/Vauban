//! Org dashboard tiles: memoized loaders + sibling `#[component]`s (0.6 concurrent I/O).

use topcoat::{
    Result,
    context::{Cx, memoize},
    view::{component, view},
};

use crate::{
    app::_components::{ico_builds, ico_docs, ico_issues, note_inline_text},
    dashboard_stats::{
        DASHBOARD_ISSUES_CAP, issue_activity_copy, latest_issue_by_updated_at,
        summarize_issue_stats,
    },
    models::{DOC_STATUS_PUBLISHED, DocArticle, Issue, Release},
    release_pkg::version_for_display,
    request_intern::interned,
    ui::{channel_badge_class, note_tag_color},
};

use super::builds;

/// One org-scoped issues SELECT (capped). Concurrent tile components share
/// this in-flight future via `#[memoize]`.
#[memoize]
async fn dashboard_issue_rows(cx: &Cx, org_id: u64) -> Vec<Issue> {
    let mut database = crate::auth::db(cx);
    Issue::all()
        .filter(Issue::fields().organization_id().eq(org_id))
        .order_by(Issue::fields().updated_at().desc())
        .limit(DASHBOARD_ISSUES_CAP)
        .exec(&mut database)
        .await
        .unwrap_or_default()
}

#[memoize]
async fn dashboard_releases(
    cx: &Cx,
    org_id: u64,
    slug_id: usize,
    lts: i32,
    industrial: i32,
    show_builds: bool,
) -> Vec<Release> {
    if !show_builds {
        return Vec::new();
    }
    let slug = interned(cx, slug_id);
    builds::load_releases_for_org(cx, org_id, &slug, "", lts, industrial).await
}

struct DashboardDocs {
    article_count: usize,
    latest_title: Option<String>,
}

#[memoize]
async fn dashboard_docs(cx: &Cx) -> DashboardDocs {
    let mut database = crate::auth::db(cx);
    let article_count = DocArticle::all()
        .filter(DocArticle::fields().status().eq(DOC_STATUS_PUBLISHED))
        .count()
        .exec(&mut database)
        .await
        .unwrap_or(0) as usize;
    let latest_title = DocArticle::all()
        .filter(DocArticle::fields().status().eq(DOC_STATUS_PUBLISHED))
        .order_by(DocArticle::fields().updated_at().desc())
        .limit(1)
        .exec(&mut database)
        .await
        .unwrap_or_default()
        .into_iter()
        .next()
        .map(|a| a.title);
    DashboardDocs {
        article_count,
        latest_title,
    }
}

/// Shared loader key for build-backed tiles (avoids `too_many_arguments`).
#[derive(Clone, Copy)]
pub(super) struct DashLoad {
    pub org_id: u64,
    pub slug_id: usize,
    pub lts: i32,
    pub industrial: i32,
    pub show_builds: bool,
}

fn display_build_version(releases: &[Release]) -> String {
    releases
        .first()
        .map(|r| version_for_display(&r.version).to_owned())
        .unwrap_or_else(|| "—".to_owned())
}

#[component]
pub(super) async fn dash_stat_build(cx: &Cx, load: DashLoad) -> Result {
    let releases = dashboard_releases(
        cx,
        load.org_id,
        load.slug_id,
        load.lts,
        load.industrial,
        load.show_builds,
    )
    .await;
    let build_version = display_build_version(releases);
    view! {
        <div class="vb-stat">
            <div class="vb-stat-label">"CURRENT BUILD"</div>
            <div class="vb-stat-value">(build_version)</div>
        </div>
    }
}

#[component]
pub(super) async fn dash_stat_open(cx: &Cx, org_id: u64) -> Result {
    let rows = dashboard_issue_rows(cx, org_id).await;
    let open_count = summarize_issue_stats(rows).open_count.to_string();
    view! {
        <div class="vb-stat">
            <div class="vb-stat-label">"OPEN ISSUES"</div>
            <div class="vb-stat-value">(open_count)</div>
        </div>
    }
}

#[component]
pub(super) async fn dash_stat_analysis(cx: &Cx, org_id: u64) -> Result {
    let rows = dashboard_issue_rows(cx, org_id).await;
    let in_analysis = summarize_issue_stats(rows).in_analysis_count.to_string();
    view! {
        <div class="vb-stat">
            <div class="vb-stat-label">"IN ANALYSIS"</div>
            <div class="vb-stat-value warn">(in_analysis)</div>
        </div>
    }
}

#[component]
pub(super) async fn dash_card_docs(cx: &Cx, docs_href: &str) -> Result {
    let docs = dashboard_docs(cx).await;
    let article_count = docs.article_count.to_string();
    let href = docs_href.to_owned();
    view! {
        cx =>
        <a
            class="vb-card"
            href=(href)
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
                    (article_count)
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
    }
}

#[component]
pub(super) async fn dash_card_builds(cx: &Cx, load: DashLoad, builds_href: &str) -> Result {
    if !load.show_builds {
        return view! {};
    }
    let releases = dashboard_releases(
        cx,
        load.org_id,
        load.slug_id,
        load.lts,
        load.industrial,
        load.show_builds,
    )
    .await;
    let build_version = display_build_version(releases);
    let href = builds_href.to_owned();
    view! {
        cx =>
        <a
            class="vb-card"
            href=(href)
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
                    (build_version)
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
    }
}

#[component]
pub(super) async fn dash_card_issues(cx: &Cx, org_id: u64, issues_href: &str) -> Result {
    let rows = dashboard_issue_rows(cx, org_id).await;
    let open_count = summarize_issue_stats(rows).open_count.to_string();
    let href = issues_href.to_owned();
    view! {
        cx =>
        <a
            class="vb-card"
            href=(href)
            style="padding: 20px; min-height: 168px;"
        >
            <div
                style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;"
            >
                (ico_issues(cx, 20).await?)
                <span class="vb-mono" style="font-size: 10px; color: var(--warn);">
                    (open_count)
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
    }
}

#[component]
pub(super) async fn dash_activity(cx: &Cx, load: DashLoad) -> Result {
    let releases = dashboard_releases(
        cx,
        load.org_id,
        load.slug_id,
        load.lts,
        load.industrial,
        load.show_builds,
    )
    .await;
    let rows = dashboard_issue_rows(cx, load.org_id).await;
    let docs = dashboard_docs(cx).await;
    let build_version = display_build_version(releases);
    let build_channel = releases
        .first()
        .map(|r| r.channel.clone())
        .unwrap_or_else(|| "LTS".to_owned());
    let show_build_line = !build_version.is_empty() && build_version != "—";
    let issue_activity = latest_issue_by_updated_at(rows)
        .map(|issue| (issue.key.clone(), issue_activity_copy(&issue.status)));
    let latest_doc = docs.latest_title.clone();
    view! {
        <div class="vb-panel">
            <div class="vb-section-label">"RECENT ACTIVITY"</div>
            if show_build_line {
                <div class="vb-activity-item">
                    <div class="vb-dot"></div>
                    <div style="flex: 1; font-size: 13.5px; color: #3a3f46;">
                        <span
                            class="vb-mono"
                            style="color: var(--accent); font-size: 12.5px;"
                        >
                            (build_version)
                        </span>
                        " ("
                        (build_channel)
                        ") certified and signed"
                    </div>
                </div>
            }
            if let Some((key, copy)) = issue_activity {
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
                </div>
            }
            if let Some(title) = latest_doc {
                <div class="vb-activity-item">
                    <div class="vb-dot muted"></div>
                    <div style="flex: 1; font-size: 13.5px; color: #3a3f46;">
                        (title)
                        " — documentation updated"
                    </div>
                </div>
            }
        </div>
    }
}

#[component]
pub(super) async fn dash_notes(cx: &Cx, load: DashLoad, builds_href: &str) -> Result {
    let releases = dashboard_releases(
        cx,
        load.org_id,
        load.slug_id,
        load.lts,
        load.industrial,
        load.show_builds,
    )
    .await;
    let build_version = display_build_version(releases);
    let build_channel = releases
        .first()
        .map(|r| r.channel.clone())
        .unwrap_or_else(|| "LTS".to_owned());
    let build_notes = releases
        .first()
        .map(|r| r.notes.clone())
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
    let href = builds_href.to_owned();
    view! {
        cx =>
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
                        note_inline_text(text: &text)
                    </span>
                </div>
            }
            if load.show_builds {
                <a
                    class="vb-link"
                    href=(href.clone())
                    style="display: inline-block; margin-top: 14px;"
                >
                    "All builds"
                </a>
            }
        </div>
    }
}
