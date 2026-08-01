//! Live admin issues search shard — re-checks staff + issues_read on every render.
//!
//! Shard POSTs hit `/_topcoat/shards/{id}` — admin layout does not run.
//! Always re-authorize with `require_staff` before loading data.

use topcoat::{Result, context::Cx, runtime::shard, view::view};

use crate::{
    app::_components::{severity_badge, status_badge},
    auth::{capability_denied, require_staff},
    db::now_unix,
    issues_search::{
        issue_matches_org, issue_matches_query, issue_matches_status, normalize_org_filter,
        normalize_query, normalize_status, resolve_org_filter,
    },
    list_page::{LIST_PAGE_SIZE, page_slice, parse_page},
    models::{Issue, Organization, User},
    perms::perms_for_user,
    tz::{browser_tz, format_relative},
};

/// Shard args are attacker-controlled — always re-authorize.
#[shard]
pub async fn admin_issues_search_results(
    cx: &Cx,
    q: String,
    org: String,
    status: String,
    page: String,
) -> Result {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.issues_read {
        return Err(capability_denied().into());
    }

    let q = normalize_query(&q);
    let status = normalize_status(&status);
    let org_filter = normalize_org_filter(&org);
    let page = parse_page(page.parse().ok());

    let mut database = crate::auth::db(cx);
    let mut issues = Issue::all().exec(&mut database).await.unwrap_or_default();
    issues.sort_by_key(|i| std::cmp::Reverse(i.updated_at));
    let orgs = Organization::all()
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let users = User::all().exec(&mut database).await.unwrap_or_default();

    let org_id_filter =
        resolve_org_filter(orgs.iter().map(|o| (o.id, o.slug.as_str())), &org_filter);

    let tz = browser_tz(cx);
    let now = now_unix();
    let filtered: Vec<_> = issues
        .into_iter()
        .filter(|i| {
            issue_matches_org(&org_filter, org_id_filter, i.organization_id)
                && issue_matches_status(&status, &i.status)
                && issue_matches_query(&q, &i.key, &i.title)
        })
        .collect();
    let page_issues = page_slice(&filtered, page, LIST_PAGE_SIZE);

    view! {
        cx =>
        <div class="vb-list" data-admin-issues-search-shard="1">
            if filtered.is_empty() {
                <div class="vb-empty">"No matching issues."</div>
            } else {
                for issue in page_issues {
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
