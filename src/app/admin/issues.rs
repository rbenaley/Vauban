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
    auth::{capability_denied, require_staff},
    issues_search::{normalize_org_filter, normalize_query, normalize_status},
    perms::perms_for_user,
};

const STATUSES: &[&str] = &["Open", "In analysis", "Resolved", "Closed"];

#[query_params]
struct AdminIssuesQuery {
    q: Option<String>,
    status: Option<String>,
    org: Option<String>,
}

#[page]
async fn admin_issues_page(cx: &Cx) -> Result {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.issues_read {
        return Err(capability_denied().into());
    }

    let query = query_params::<AdminIssuesQuery>(cx).ok();
    let q = normalize_query(query.and_then(|q| q.q.as_deref()).unwrap_or(""));
    let status = normalize_status(query.and_then(|q| q.status.as_deref()).unwrap_or(""));
    let org_filter = normalize_org_filter(query.and_then(|q| q.org.as_deref()).unwrap_or(""));

    let base = "/admin/issues".to_owned();
    let all_class = if status.is_empty() {
        "vb-chip active"
    } else {
        "vb-chip"
    };
    let q_value = query.and_then(|q| q.q.clone()).unwrap_or_default();
    let org_value = org_filter.clone();
    let status_owned = status.clone();

    view! {
        cx =>
        signal query = q_value.clone();
        signal org_query = org_value.clone();

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
                @input=$(|e: topcoat::runtime::Event| query.set(e.target.value))
            >
            <input
                class="vb-search"
                style="margin: 0; width: 180px;"
                type="search"
                name="org"
                value=(org_value.clone())
                placeholder="Org slug or id…"
                @input=$(|e: topcoat::runtime::Event| org_query.set(e.target.value))
            >
            if !status_owned.is_empty() {
                <input type="hidden" name="status" value=(status_owned.clone())>
            }
        </form>

        <div class="vb-chip-row">
            <a class=(all_class) href=(chip_href(&base, &q, &org_filter, ""))>"All"</a>
            for s in STATUSES {
                let href = chip_href(&base, &q, &org_filter, s);
                let class = if status.eq_ignore_ascii_case(s) {
                    "vb-chip active"
                } else {
                    "vb-chip"
                };
                <a class=(class) href=(href)>(*s)</a>
            }
        </div>

        admin_issues_search_results(
            q: $(query.get()),
            org: $(org_query.get()),
            status: $(status_owned.clone())
        )
    }
}

fn chip_href(base: &str, q: &str, org: &str, status: &str) -> String {
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
    if parts.is_empty() {
        base.to_owned()
    } else {
        format!("{base}?{}", parts.join("&"))
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
