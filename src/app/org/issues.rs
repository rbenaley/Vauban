//! Issue tracker list at `/{org}/issues`.

mod issue_key;
mod new;

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{Form, SeeOther, forbidden, page, path_param, query_params, route, see_other},
    view::view,
};

use crate::{
    app::org::Org,
    auth::{db, require_org},
    layout::{self, NavSection},
    models::Issue,
    perms::perms_for_user,
};

const STATUSES: &[&str] = &["Open", "In analysis", "Resolved", "Closed"];

#[query_params]
struct IssuesQuery {
    q: Option<String>,
    status: Option<String>,
}

#[page]
async fn issues_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.issues_read {
        return Err(forbidden().into());
    }

    let query = query_params::<IssuesQuery>(cx).ok();
    let q = query
        .and_then(|q| q.q.as_deref())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let status = query
        .and_then(|q| q.status.as_deref())
        .unwrap_or("")
        .trim()
        .to_owned();

    let mut database = crate::auth::db(cx);
    let issues = Issue::all()
        .filter(Issue::fields().organization_id().eq(ctx.org.id))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let filtered: Vec<_> = issues
        .into_iter()
        .filter(|i| {
            let status_ok = status.is_empty() || i.status.eq_ignore_ascii_case(&status);
            let q_ok = q.is_empty()
                || i.key.to_lowercase().contains(&q)
                || i.title.to_lowercase().contains(&q);
            status_ok && q_ok
        })
        .collect();

    let base = format!("/{}/issues", slug);
    let all_class = if status.is_empty() {
        "vb-chip active"
    } else {
        "vb-chip"
    };
    let q_value = query.and_then(|q| q.q.clone()).unwrap_or_default();

    let body = view! {
        <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap; margin-bottom: 6px;">
            <h1 class="vb-title" style="margin: 0;">"Issue tracker"</h1>
            if perms.issues_write {
                <a class="vb-btn" href=(format!("/{}/issues/new", slug))>"＋ Report an issue"</a>
            }
        </div>
        <p class="vb-lead" style="display: flex; align-items: center; gap: 8px;">
            <span style="width: 6px; height: 6px; border-radius: 50%; background: var(--warn); display: inline-block;"></span>
            "SLA: initial analysis within "
            <strong style="color: var(--text); font-weight: 700;">"2–5 business days"</strong>
            "."
        </p>

        <form method="GET" action=(base.clone()) style="display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; align-items: center;">
            <input
                class="vb-search"
                style="margin: 0; flex: 1; min-width: 240px;"
                type="search"
                name="q"
                value=(q_value)
                placeholder="Search (ID, title)…"
            >
            if !status.is_empty() {
                <input type="hidden" name="status" value=(status.clone())>
            }
        </form>

        <div class="vb-chip-row">
            <a class=(all_class) href=(base.clone())>"All"</a>
            for s in STATUSES {
                let href = if q.is_empty() {
                    format!("{base}?status={}", urlencoding_encode(s))
                } else {
                    format!(
                        "{base}?q={}&status={}",
                        urlencoding_encode(&q),
                        urlencoding_encode(s)
                    )
                };
                let class = if status.eq_ignore_ascii_case(s) {
                    "vb-chip active"
                } else {
                    "vb-chip"
                };
                <a class=(class) href=(href)>(*s)</a>
            }
        </div>

        <div class="vb-list">
            if filtered.is_empty() {
                <div class="vb-empty">"No matching issues."</div>
            } else {
                for issue in filtered {
                    let sev_class = sev_class(&issue.severity);
                    let status_class = status_class(&issue.status);
                    <a class="vb-row" href=(format!("/{}/issues/{}", slug, issue.key))>
                        <div class="vb-mono" style="color: var(--accent); font-size: 12px; font-weight: 700; width: 76px; flex: none;">
                            (issue.key.clone())
                        </div>
                        <div style="flex: 1; min-width: 0;">
                            <div style="font-size: 14.5px; font-weight: 600; margin-bottom: 4px;">
                                (issue.title.clone())
                            </div>
                            <div class="vb-mono" style="font-size: 11px; color: #8a8f96;">
                                (issue.component.clone())
                                " · opened by customer · updated recently"
                            </div>
                        </div>
                        <span class=(sev_class)>(issue.severity.clone())</span>
                        <span class=(status_class)>(issue.status.clone())</span>
                    </a>
                }
            }
        </div>
    };

    layout::shell(cx, &ctx, &perms, NavSection::Issues, "issues", body).await
}

#[derive(Deserialize)]
struct ReportForm {
    title: String,
    component: String,
    severity: String,
    details: String,
}

#[route(POST "/{org}/issues")]
async fn report_issue(cx: &Cx, Form(form): Form<ReportForm>) -> Result<SeeOther> {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug)
        .await
        .map_err(|_| topcoat::router::not_found())?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.issues_write {
        return Ok(see_other(&format!("/{slug}/issues")));
    }

    let mut database = db(cx);
    let existing = Issue::all()
        .filter(Issue::fields().organization_id().eq(ctx.org.id))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let next = existing.len() + 200;
    let key = format!("VBN-{next}");
    let title = form.title.trim().to_owned();
    let component = form.component.trim().to_owned();
    let severity = form.severity.trim().to_owned();
    let _details = form.details.trim().to_owned();

    if !title.is_empty() {
        let _ = toasty::create!(Issue {
            key: key.clone(),
            title,
            component,
            severity,
            status: "Open".to_owned(),
            organization_id: ctx.org.id,
        })
        .exec(&mut database)
        .await;
        return Ok(see_other(&format!("/{slug}/issues/{key}")));
    }

    Ok(see_other(&format!("/{slug}/issues")))
}

pub(super) fn sev_class(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => "vb-sev critical",
        "major" => "vb-sev major",
        _ => "vb-sev minor",
    }
}

pub(super) fn status_class(status: &str) -> &'static str {
    let s = status.to_ascii_lowercase();
    if s.contains("analysis") {
        "vb-status analysis"
    } else if s == "resolved" {
        "vb-status resolved"
    } else if s == "closed" {
        "vb-status closed"
    } else {
        "vb-status open"
    }
}

fn urlencoding_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
