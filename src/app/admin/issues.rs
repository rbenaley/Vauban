//! Aggregated issue tracker at `/admin/issues` (all orgs, staff-only).

mod issue_key;

use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, page, query_params},
    view::view,
};

use crate::{
    app::_components::{severity_badge, status_badge},
    auth::require_staff,
    db::now_unix,
    models::{Issue, Organization, User},
    perms::perms_for_user,
    tz::{browser_tz, format_relative},
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
        return Err(forbidden().into());
    }

    let query = query_params::<AdminIssuesQuery>(cx).ok();
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
    let org_filter = query
        .and_then(|q| q.org.as_deref())
        .unwrap_or("")
        .trim()
        .to_owned();

    let mut database = crate::auth::db(cx);
    let mut issues = Issue::all().exec(&mut database).await.unwrap_or_default();
    issues.sort_by_key(|i| std::cmp::Reverse(i.updated_at));
    let orgs = Organization::all()
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let users = User::all().exec(&mut database).await.unwrap_or_default();

    let org_id_filter = resolve_org_filter(&orgs, &org_filter);

    let tz = browser_tz(cx);
    let now = now_unix();
    let filtered: Vec<_> = issues
        .into_iter()
        .filter(|i| {
            let org_ok = if org_filter.is_empty() {
                true
            } else {
                org_id_filter == Some(i.organization_id)
            };
            let status_ok = status.is_empty() || i.status.eq_ignore_ascii_case(&status);
            let q_ok = q.is_empty()
                || i.key.to_lowercase().contains(&q)
                || i.title.to_lowercase().contains(&q);
            org_ok && status_ok && q_ok
        })
        .collect();

    let base = "/admin/issues".to_owned();
    let all_class = if status.is_empty() {
        "vb-chip active"
    } else {
        "vb-chip"
    };
    let q_value = query.and_then(|q| q.q.clone()).unwrap_or_default();
    let org_value = org_filter.clone();

    view! {
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
                value=(q_value)
                placeholder="Search (ID, title)…"
            >
            <input
                class="vb-search"
                style="margin: 0; width: 180px;"
                type="search"
                name="org"
                value=(org_value)
                placeholder="Org slug or id…"
            >
            if !status.is_empty() {
                <input type="hidden" name="status" value=(status.clone())>
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

        <div class="vb-list">
            if filtered.is_empty() {
                <div class="vb-empty">"No matching issues."</div>
            } else {
                for issue in filtered {
                    let opener = users
                        .iter()
                        .find(|u| u.id == issue.opened_by_user_id)
                        .map(|u| u.display_name.clone())
                        .unwrap_or_else(|| "Unknown".to_owned());
                    let org_label = orgs
                        .iter()
                        .find(|o| o.id == issue.organization_id)
                        .map(|o| format!("{} ({})", o.name, o.slug))
                        .unwrap_or_else(|| format!("org#{}", issue.organization_id));
                    let updated = format_relative(issue.updated_at, now, tz);
                    let meta = format!(
                        "{} · {} · opened by {} · updated {}", org_label, issue
                        .component, opener, updated
                    );
                    <a class="vb-row" href=(format!("/admin/issues/{}", issue.key))>
                        <div
                            class="vb-mono"
                            style="color: var(--accent); font-size: 12px; font-weight: 700; width: 76px; flex: none;"
                        >
                            (issue.key.clone())
                        </div>
                        <div style="flex: 1; min-width: 0;">
                            <div
                                style="font-size: 14.5px; font-weight: 600; margin-bottom: 4px;"
                            >
                                (issue.title.clone())
                            </div>
                            <div
                                class="vb-mono"
                                style="font-size: 11px; color: #8a8f96;"
                            >
                                (meta)
                            </div>
                        </div>
                        severity_badge(severity: &issue.severity)
                        status_badge(status: &issue.status)
                    </a>
                }
            }
        </div>
    }
}

fn resolve_org_filter(orgs: &[Organization], raw: &str) -> Option<u64> {
    if raw.is_empty() {
        return None;
    }
    if let Ok(id) = raw.parse::<u64>()
        && orgs.iter().any(|o| o.id == id)
    {
        return Some(id);
    }
    orgs.iter()
        .find(|o| o.slug.eq_ignore_ascii_case(raw))
        .map(|o| o.id)
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
