//! Issue tracker list at `/{org}/issues`.

mod issue_key;
mod new;
mod search_shard;

pub(super) use search_shard::issues_search_results;

use serde::Deserialize;
use topcoat::{
    Result,
    context::{Cx, memoize},
    router::{
        content::Form,
        error::{SeeOther, not_found, redirect, see_other},
        page, path_param, query_params, route,
    },
    view::view,
};

use crate::{
    app::_components::{filter_row, ico_plus},
    app::org::Org,
    auth::{capability_denied, db, require_org},
    db::now_unix,
    issue_key::{
        ISSUE_KEY_CREATE_ATTEMPTS, ISSUE_KEY_PREFIX, allocate_issue_key, is_unique_violation,
        parse_vbn_suffix,
    },
    issues_search::{normalize_query, normalize_status},
    list_page::{
        LIST_PAGE_SIZE, PagerLinks, clamp_page, href_with_query, page_count, page_offset,
        parse_page, with_page_param,
    },
    models::{Issue, RESERVED_ORG_SLUG},
    perms::perms_for_user,
    sql_search::ilike_contains,
};

const STATUSES: &[&str] = &["Open", "In analysis", "Resolved", "Closed"];

#[query_params]
struct IssuesQuery {
    q: Option<String>,
    status: Option<String>,
    /// 1-based page index; omitted means page 1.
    page: Option<u32>,
}

/// Shareable issues list URL (`page=1` and empty filters omitted).
pub(super) fn issues_list_href(org: &str, q: &str, status: &str, page: usize) -> String {
    let mut parts = Vec::new();
    if !q.is_empty() {
        parts.push(format!("q={}", urlencoding_encode(q)));
    }
    if !status.is_empty() {
        parts.push(format!("status={}", urlencoding_encode(status)));
    }
    with_page_param(&mut parts, page);
    href_with_query(&format!("/{org}/issues"), &parts)
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
    let q = normalize_query(query.as_ref().and_then(|q| q.q.as_deref()).unwrap_or(""));
    let status = normalize_status(
        query
            .as_ref()
            .and_then(|q| q.status.as_deref())
            .unwrap_or(""),
    );
    let mut page = parse_page(query.as_ref().and_then(|q| q.page));

    let total = count_filtered_issues(cx, ctx.org.id, &q, &status).await;
    let pages = page_count(total, LIST_PAGE_SIZE);
    page = clamp_page(page, pages);

    let base = format!("/{}/issues", slug);
    let q_value = query.as_ref().and_then(|q| q.q.clone()).unwrap_or_default();
    let org = slug.to_owned();
    let status_owned = status.clone();
    let org_for_pager = org.clone();
    let q_for_pager = q.clone();
    let status_for_pager = status_owned.clone();
    let pager = PagerLinks::from_hrefs(page, pages, |n| {
        issues_list_href(&org_for_pager, &q_for_pager, &status_for_pager, n)
    });
    let pager_opt = if pager.show() { Some(pager) } else { None };

    // Chip hrefs omit `page` (reset). All clears filters; status chips keep q.
    let mut chips: Vec<(String, String, bool)> =
        vec![("All".to_owned(), base.clone(), status.is_empty())];
    for s in STATUSES {
        chips.push((
            (*s).to_owned(),
            issues_list_href(&org, &q, s, 1),
            status.eq_ignore_ascii_case(s),
        ));
    }

    let page_init = page.to_string();

    view! {
        cx =>
        signal query = q_value.clone();
        signal page = page_init.clone();

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
        <p class="vb-lead">
            "SLA: initial analysis within "
            <strong style="color: var(--text); font-weight: 700;">
                "2–5 business days"
            </strong>
            "."
        </p>

        // Filter only (shareable ?q=); live results use the shard. Not a mutation.
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
                @input=$(|e: topcoat::runtime::Event| {
                    page.set("1".to_owned());
                    query.set(e.target.value);
                })
            >
            if !status_owned.is_empty() {
                <input type="hidden" name="status" value=(status_owned.clone())>
            }
        </form>

        filter_row(chips: &chips, pager: &pager_opt)

        issues_search_results(
            org_slug: $(org.clone()),
            q: $(query.get()),
            status: $(status_owned.clone()),
            page: $(page.get())
        )
    }
}

/// Shared org-scoped issue query (tenant + optional status / search).
macro_rules! org_issues_filtered_query {
    ($org_id:expr, $q:expr, $status:expr) => {{
        let org_id = $org_id;
        let q = $q;
        let status = $status;
        let mut query = Issue::all().filter(Issue::fields().organization_id().eq(org_id));
        if !status.is_empty() {
            query = query.filter(Issue::fields().status().eq(status.to_owned()));
        }
        if let Some(pat) = ilike_contains(q) {
            query = query.filter(
                Issue::fields()
                    .key()
                    .ilike_with_escape(pat.clone(), '\\')
                    .or(Issue::fields().title().ilike_with_escape(pat, '\\')),
            );
        }
        query
    }};
}

/// Request-scoped COUNT so list page + embedded shard share one SQL round-trip.
#[memoize]
async fn count_filtered_issues_memo(cx: &Cx, org_id: u64, q: &str, status: &str) -> usize {
    let mut database = db(cx);
    org_issues_filtered_query!(org_id, q, status)
        .count()
        .exec(&mut database)
        .await
        .unwrap_or(0) as usize
}

/// Count org issues matching `q` / `status` (SQL; memoized per request).
pub(super) async fn count_filtered_issues(cx: &Cx, org_id: u64, q: &str, status: &str) -> usize {
    *count_filtered_issues_memo(cx, org_id, q, status).await
}

/// One page of org issues matching `q` / `status` (SQL order + limit/offset).
pub(super) async fn load_filtered_issues_page(
    cx: &Cx,
    org_id: u64,
    q: &str,
    status: &str,
    page: usize,
) -> Vec<Issue> {
    let total = count_filtered_issues(cx, org_id, q, status).await;
    let pages = page_count(total, LIST_PAGE_SIZE);
    let page = clamp_page(page, pages);
    let mut database = db(cx);
    org_issues_filtered_query!(org_id, q, status)
        .order_by(Issue::fields().updated_at().desc())
        .limit(LIST_PAGE_SIZE)
        .offset(page_offset(page, LIST_PAGE_SIZE))
        .exec(&mut database)
        .await
        .unwrap_or_default()
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
    let ctx = require_org(cx, slug).await.map_err(|_| not_found())?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.issues_write {
        return Ok(see_other(&format!("/{slug}/issues")));
    }

    let title = form.title.trim().to_owned();
    let component = form.component.trim().to_owned();
    let severity = form.severity.trim().to_owned();
    let details = form.details.trim().to_owned();

    if title.is_empty() {
        return Ok(see_other(&format!("/{slug}/issues")));
    }

    let mut database = db(cx);
    let now = now_unix();
    let mut last_err: Option<String> = None;
    let mut candidate: Option<String> = None;

    for attempt in 0..ISSUE_KEY_CREATE_ATTEMPTS {
        let key = match candidate.take() {
            Some(k) => k,
            None => allocate_issue_key(&mut database, ctx.org.id).await,
        };
        match toasty::create!(Issue {
            key: key.clone(),
            title: title.clone(),
            component: component.clone(),
            severity: severity.clone(),
            status: "Open".to_owned(),
            organization_id: ctx.org.id,
            details: details.clone(),
            opened_by_user_id: ctx.user.id,
            created_at: now,
            updated_at: now,
        })
        .exec(&mut database)
        .await
        {
            Ok(_) => return Ok(see_other(&format!("/{slug}/issues/{key}"))),
            Err(err) if is_unique_violation(&err) && attempt + 1 < ISSUE_KEY_CREATE_ATTEMPTS => {
                tracing::warn!(
                    org = %slug,
                    attempt,
                    key = %key,
                    "issue create unique conflict; retrying with new key"
                );
                last_err = Some(err.to_string());
                // Fan out past the collided tip so parallel retries diverge.
                let collided = parse_vbn_suffix(&key).unwrap_or(0);
                let fresh = allocate_issue_key(&mut database, ctx.org.id).await;
                let fresh_n = parse_vbn_suffix(&fresh).unwrap_or(collided.saturating_add(1));
                let next = fresh_n
                    .max(collided.saturating_add(1))
                    .saturating_add(attempt);
                candidate = Some(format!("{ISSUE_KEY_PREFIX}{next}"));
            }
            Err(err) => {
                tracing::warn!(
                    org = %slug,
                    key = %key,
                    error = %err,
                    "issue create failed"
                );
                last_err = Some(err.to_string());
                break;
            }
        }
    }

    if let Some(err) = last_err {
        tracing::warn!(org = %slug, error = %err, "issue create exhausted retries");
    }
    Ok(see_other(&format!("/{slug}/issues?err=create")))
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

#[cfg(test)]
mod issues_list_href_tests {
    use super::issues_list_href;

    #[test]
    fn issues_list_href_omits_page_one_and_empty_filters() {
        assert_eq!(issues_list_href("acme", "", "", 1), "/acme/issues");
        assert_eq!(issues_list_href("acme", "ssh", "", 1), "/acme/issues?q=ssh");
        assert_eq!(
            issues_list_href("acme", "ssh", "Open", 2),
            "/acme/issues?q=ssh&status=Open&page=2"
        );
    }
}
