//! Aggregated issue tracker at `/admin/issues` (all orgs, staff-only).

mod issue_key;
mod search_shard;

pub(super) use search_shard::admin_issues_search_results;

use topcoat::{
    Result,
    context::Cx,
    router::{page, query_params},
    view::view,
};

use crate::{
    app::_components::filter_row,
    auth::{capability_denied, require_staff},
    issues_search::{
        issue_matches_org, issue_matches_query, issue_matches_status, normalize_org_filter,
        normalize_query, normalize_status, resolve_org_filter,
    },
    list_page::{
        LIST_PAGE_SIZE, PagerLinks, clamp_page, href_with_query, page_count, parse_page,
        with_page_param,
    },
    models::{Issue, Organization},
    perms::perms_for_user,
};

const STATUSES: &[&str] = &["Open", "In analysis", "Resolved", "Closed"];

#[query_params]
struct AdminIssuesQuery {
    q: Option<String>,
    status: Option<String>,
    org: Option<String>,
    /// 1-based page index; omitted means page 1.
    page: Option<u32>,
}

#[page]
async fn admin_issues_page(cx: &Cx) -> Result {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.issues_read {
        return Err(capability_denied().into());
    }

    let query = query_params::<AdminIssuesQuery>(cx).ok();
    let q = normalize_query(query.as_ref().and_then(|q| q.q.as_deref()).unwrap_or(""));
    let status = normalize_status(
        query
            .as_ref()
            .and_then(|q| q.status.as_deref())
            .unwrap_or(""),
    );
    let org_filter =
        normalize_org_filter(query.as_ref().and_then(|q| q.org.as_deref()).unwrap_or(""));
    let raw_page = query.as_ref().and_then(|q| q.page);

    let mut database = crate::auth::db(cx);
    let mut issues = Issue::all().exec(&mut database).await.unwrap_or_default();
    issues.sort_by_key(|i| std::cmp::Reverse(i.updated_at));
    let orgs = Organization::all()
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let org_id_filter =
        resolve_org_filter(orgs.iter().map(|o| (o.id, o.slug.as_str())), &org_filter);
    let filtered_total = issues
        .iter()
        .filter(|i| {
            issue_matches_org(&org_filter, org_id_filter, i.organization_id)
                && issue_matches_status(&status, &i.status)
                && issue_matches_query(&q, &i.key, &i.title)
        })
        .count();
    let pages = page_count(filtered_total, LIST_PAGE_SIZE);
    let page = clamp_page(parse_page(raw_page), pages);
    let page_init = page.to_string();

    let base = "/admin/issues".to_owned();
    let q_value = query.and_then(|q| q.q.clone()).unwrap_or_default();
    let org_value = org_filter.clone();
    let status_owned = status.clone();

    let mut chips: Vec<(String, String, bool)> = Vec::with_capacity(1 + STATUSES.len());
    chips.push((
        "All".to_owned(),
        chip_href(&base, &q, &org_filter, ""),
        status.is_empty(),
    ));
    for s in STATUSES {
        chips.push((
            (*s).to_owned(),
            chip_href(&base, &q, &org_filter, s),
            status.eq_ignore_ascii_case(s),
        ));
    }

    let q_for_pager = q.clone();
    let org_for_pager = org_filter.clone();
    let status_for_pager = status.clone();
    let pager = PagerLinks::from_hrefs(page, pages, |n| {
        list_href(&base, &q_for_pager, &org_for_pager, &status_for_pager, n)
    });
    let pager_opt = if pager.show() { Some(pager) } else { None };

    view! {
        cx =>
        signal query = q_value.clone();
        signal org_query = org_value.clone();
        signal page = page_init.clone();

        <div style="margin-bottom: 6px;">
            <h1 class="vb-title" style="margin: 0;">"Issues"</h1>
        </div>
        <p class="vb-lead" style="display: flex; align-items: center; gap: 8px;">
            <span
                style="width: 6px; height: 6px; border-radius: 50%; background: var(--warn); display: inline-block;"
            ></span>
            "Aggregated support queue across all organizations. SLA: initial analysis within "
            <strong style="color: var(--text); font-weight: 700;">
                "2–5 business days"
            </strong>
            "."
        </p>

        // Filter only (shareable ?q= / ?org=); live results use the shard. Not a mutation.
        <form
            method="GET"
            action=(base.clone())
            style="display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; align-items: center;"
        >
            <input
                class="vb-search"
                style="margin: 0; flex: 1; min-width: 200px;"
                type="search"
                name="q"
                value=(q_value.clone())
                placeholder="Search (ID, title)…"
                @input=$(|e: topcoat::runtime::Event| {
                    page.set("1".to_owned());
                    query.set(e.target.value);
                })
            >
            <input
                class="vb-search"
                style="margin: 0; width: 180px;"
                type="search"
                name="org"
                value=(org_value.clone())
                placeholder="Org slug or id…"
                @input=$(|e: topcoat::runtime::Event| {
                    page.set("1".to_owned());
                    org_query.set(e.target.value);
                })
            >
            if !status_owned.is_empty() {
                <input type="hidden" name="status" value=(status_owned.clone())>
            }
        </form>

        filter_row(chips: &chips, pager: &pager_opt)

        admin_issues_search_results(
            q: $(query.get()),
            org: $(org_query.get()),
            status: $(status_owned.clone()),
            page: $(page.get())
        )
    }
}

/// Chip / filter href — omits `page` so filters reset to page 1.
fn chip_href(base: &str, q: &str, org: &str, status: &str) -> String {
    list_href(base, q, org, status, 1)
}

fn list_href(base: &str, q: &str, org: &str, status: &str, page: usize) -> String {
    let mut parts = Vec::new();
    if !q.is_empty() {
        parts.push(format!("q={}", urlencoding_encode(q)));
    }
    if !org.is_empty() {
        parts.push(format!("org={}", urlencoding_encode(org)));
    }
    if !status.is_empty() {
        parts.push(format!("status={}", urlencoding_encode(status)));
    }
    with_page_param(&mut parts, page);
    href_with_query(base, &parts)
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
