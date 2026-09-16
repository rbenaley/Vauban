//! Live admin issues search shard — re-checks staff + issues_read on every render.
//!
//! Shard POSTs hit `/_topcoat/runtime/shards/{id}` — admin layout does not run.
//! Always re-authorize with `require_staff` before loading data.

use topcoat::{
    Result,
    context::{Cx, memoize},
    runtime::shard,
    view::{View, view},
};

use crate::{
    app::_components::{severity_badge, status_badge},
    auth::{capability_denied, require_staff},
    db::now_unix,
    id_lookups::{orgs_by_ids, users_by_ids},
    issues_search::{normalize_org_filter, normalize_query, normalize_status},
    list_page::{LIST_PAGE_SIZE, clamp_page, page_count, page_offset, parse_page},
    models::{Issue, Organization},
    perms::perms_for_user,
    sql_search::{escape_ilike_literal, ilike_contains},
    tz::{browser_tz, format_relative},
    ui::row_dom_id,
};

/// Resolve admin org chip/filter to an organization id (SQL; case-insensitive slug).
async fn resolve_org_id_sql(db: &mut toasty::Db, raw: &str) -> Option<u64> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(id) = raw.parse::<u64>() {
        return Some(id);
    }
    let pat = escape_ilike_literal(raw);
    Organization::all()
        .filter(Organization::fields().slug().ilike_with_escape(pat, '\\'))
        .limit(1)
        .exec(db)
        .await
        .ok()?
        .into_iter()
        .next()
        .map(|o| o.id)
}

/// Request-scoped org hint resolve (page pager + shard share one lookup).
#[memoize(as_ref)]
async fn resolve_org_id_memo(cx: &Cx, raw: &str) -> Option<u64> {
    let mut database = crate::auth::db(cx);
    resolve_org_id_sql(&mut database, raw).await
}

async fn resolve_org_id(cx: &Cx, raw: &str) -> Option<u64> {
    resolve_org_id_memo(cx, raw).await.copied()
}

macro_rules! admin_issues_filtered_query {
    ($org_id:expr, $q:expr, $status:expr) => {{
        let org_id: Option<u64> = $org_id;
        let q = $q;
        let status = $status;
        let mut query = Issue::all();
        if let Some(id) = org_id {
            query = query.filter(Issue::fields().organization_id().eq(id));
        }
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

/// Shard args are attacker-controlled — always re-authorize.
#[shard]
pub async fn admin_issues_search_results(
    cx: &Cx,
    q: String,
    org: String,
    status: String,
    page: String,
) -> Result<impl View> {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.issues_read {
        return Err(capability_denied().into());
    }

    let q = normalize_query(&q);
    let status = normalize_status(&status);
    let org_filter = normalize_org_filter(&org);
    let page = parse_page(page.parse().ok());

    let org_id = resolve_org_id(cx, &org_filter).await;
    // Unknown slug filter -> empty result (same as no match).
    let unknown_org = !org_filter.is_empty() && org_id.is_none();

    let total = if unknown_org {
        0
    } else {
        count_admin_filtered_issues(cx, &q, &org_filter, &status).await
    };
    let pages = page_count(total, LIST_PAGE_SIZE);
    let page = clamp_page(page, pages);
    let mut database = crate::auth::db(cx);
    let page_issues = if unknown_org {
        Vec::new()
    } else {
        admin_issues_filtered_query!(org_id, &q, &status)
            .order_by(Issue::fields().updated_at().desc())
            .limit(LIST_PAGE_SIZE)
            .offset(page_offset(page, LIST_PAGE_SIZE))
            .exec(&mut database)
            .await
            .unwrap_or_default()
    };

    let user_ids: Vec<u64> = page_issues.iter().map(|i| i.opened_by_user_id).collect();
    let org_ids: Vec<u64> = page_issues.iter().map(|i| i.organization_id).collect();
    let users = users_by_ids(&mut database, &user_ids)
        .await
        .unwrap_or_default();
    let orgs = orgs_by_ids(&mut database, &org_ids)
        .await
        .unwrap_or_default();

    let tz = browser_tz(cx);
    let now = now_unix();

    Ok(view! {
        cx =>
        <div class="vb-list" data-admin-issues-search-shard="1">
            if page_issues.is_empty() {
                <div class="vb-empty">"No matching issues."</div>
            } else {
                for issue in page_issues {
                    let opener = users
                        .iter()
                        .find(|u| u.id == issue.opened_by_user_id)
                        .map(|u| u.display_name.clone())
                        .unwrap_or_else(|| "Unknown".to_owned());
                    let org_slug = orgs
                        .iter()
                        .find(|o| o.id == issue.organization_id)
                        .map(|o| o.slug.as_str())
                        .unwrap_or("");
                    let org_label = orgs
                        .iter()
                        .find(|o| o.id == issue.organization_id)
                        .map(|o| format!("{} ({})", o.name, o.slug))
                        .unwrap_or_else(|| format!("org#{}", issue.organization_id));
                    let href = super::issue_key::admin_issue_detail_href(
                        cx,
                        &issue.key,
                        org_slug,
                        None,
                    );
                    let updated = format_relative(issue.updated_at, now, tz);
                    let meta = format!(
                        "{} · {} · opened by {} · updated {}",
                        org_label,
                        issue.component,
                        opener,
                        updated,
                    );
                    <a id=(row_dom_id("issue", &issue.key)) class="vb-row" href=(href)>
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
    })
}

/// Request-scoped COUNT so list page + embedded shard share one SQL round-trip.
#[memoize]
async fn count_admin_filtered_issues_memo(
    cx: &Cx,
    q: &str,
    org_filter: &str,
    status: &str,
) -> usize {
    let org_id = resolve_org_id(cx, org_filter).await;
    if !org_filter.is_empty() && org_id.is_none() {
        return 0;
    }
    let mut database = crate::auth::db(cx);
    admin_issues_filtered_query!(org_id, q, status)
        .count()
        .exec(&mut database)
        .await
        .unwrap_or(0) as usize
}

/// Count matching admin issues (shared with list pager; memoized per request).
pub(super) async fn count_admin_filtered_issues(
    cx: &Cx,
    q: &str,
    org_filter: &str,
    status: &str,
) -> usize {
    *count_admin_filtered_issues_memo(cx, q, org_filter, status).await
}
