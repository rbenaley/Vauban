//! Issue tracker list at `/{org}/issues`.

mod issue_key;
mod new;
mod search_shard;

pub(super) use search_shard::issues_search_results;

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{Form, SeeOther, page, path_param, query_params, redirect, route, see_other},
    view::view,
};

use crate::{
    app::_components::ico_plus,
    app::org::Org,
    auth::{capability_denied, db, require_org},
    db::now_unix,
    issues_search::{normalize_query, normalize_status},
    models::{Issue, RESERVED_ORG_SLUG},
    perms::perms_for_user,
};

const STATUSES: &[&str] = &["Open", "In analysis", "Resolved", "Closed"];

#[query_params]
struct IssuesQuery {
    q: Option<String>,
    status: Option<String>,
}

#[route(GET "/vauban/issues")]
async fn redirect_reserved_issues_list() -> Result {
    Err(redirect("/admin/issues").into())
}

/// POST alias: keep `see_other` (303) so the follow-up is GET, not a re-POST.
#[route(POST "/vauban/issues")]
async fn redirect_reserved_issues_create() -> Result<SeeOther> {
    Ok(see_other("/admin/issues"))
}

#[page]
async fn issues_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    if slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG) {
        return Err(redirect("/admin/issues").into());
    }
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.issues_read {
        return Err(capability_denied().into());
    }

    let query = query_params::<IssuesQuery>(cx).ok();
    let q = normalize_query(query.and_then(|q| q.q.as_deref()).unwrap_or(""));
    let status = normalize_status(query.and_then(|q| q.status.as_deref()).unwrap_or(""));

    let base = format!("/{}/issues", slug);
    let all_class = if status.is_empty() {
        "vb-chip active"
    } else {
        "vb-chip"
    };
    let q_value = query.and_then(|q| q.q.clone()).unwrap_or_default();
    let org = slug.to_owned();
    let status_owned = status.clone();

    view! {
        cx =>
        signal query = q_value.clone();

        <div
            style="display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap; margin-bottom: 6px;"
        >
            <h1 class="vb-title" style="margin: 0;">"Issue tracker"</h1>
            if perms.issues_write {
                <a class="vb-btn vb-btn-ico" href=(format!("/{}/issues/new", slug))>
                    (ico_plus(cx, 14).await?)
                    <span>"Report an issue"</span>
                </a>
            }
        </div>
        <p class="vb-lead" style="display: flex; align-items: center; gap: 8px;">
            <span
                style="width: 6px; height: 6px; border-radius: 50%; background: var(--warn); display: inline-block;"
            ></span>
            "SLA: initial analysis within "
            <strong style="color: var(--text); font-weight: 700;">
                "2–5 business days"
            </strong>
            "."
        </p>

        <form
            method="GET"
            action=(base.clone())
            style="display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; align-items: center;"
        >
            <input
                class="vb-search"
                style="margin: 0; flex: 1; min-width: 240px;"
                type="search"
                name="q"
                value=(q_value.clone())
                placeholder="Search (ID, title)…"
                @input=$(|e: topcoat::runtime::Event| query.set(e.target.value))
            >
            if !status_owned.is_empty() {
                <input type="hidden" name="status" value=(status_owned.clone())>
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

        issues_search_results(
            org_slug: $(org.clone()),
            q: $(query.get()),
            status: $(status_owned.clone())
        )
    }
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
    if slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG) {
        return Ok(see_other("/admin/issues"));
    }
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
    let details = form.details.trim().to_owned();

    if !title.is_empty() {
        let now = now_unix();
        let _ = toasty::create!(Issue {
            key: key.clone(),
            title,
            component,
            severity,
            status: "Open".to_owned(),
            organization_id: ctx.org.id,
            details,
            opened_by_user_id: ctx.user.id,
            created_at: now,
            updated_at: now,
        })
        .exec(&mut database)
        .await;
        return Ok(see_other(&format!("/{slug}/issues/{key}")));
    }

    Ok(see_other(&format!("/{slug}/issues")))
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
