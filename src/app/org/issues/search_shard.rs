//! Live org issues search shard — re-checks org + issues_read on every render.
//!
//! Shard POSTs hit `/_topcoat/runtime/shards/{id}` — there is no `{org}` path
//! segment. Tenant must come from the shard argument (re-authorized below).

use topcoat::{
    Result,
    context::Cx,
    router::{error::not_found, href},
    runtime::shard,
    view::{View, view},
};

use super::load_filtered_issues_page;
use crate::{
    app::_components::{severity_badge, status_badge},
    app::org::Org,
    app::org::issues::issue_key::{IssueKey, issue_detail_page},
    auth::{capability_denied, require_org},
    db::now_unix,
    docs_search::normalize_org_slug,
    id_lookups::users_by_ids,
    issues_search::{normalize_query, normalize_status},
    list_page::parse_page,
    perms::perms_for_user,
    tz::{browser_tz, format_relative},
};

/// Shard args are attacker-controlled — always re-authorize.
#[shard]
pub async fn issues_search_results(
    cx: &Cx,
    org_slug: String,
    q: String,
    status: String,
    page: String,
) -> Result<impl View> {
    let org = normalize_org_slug(&org_slug).ok_or_else(not_found)?;
    let ctx = require_org(cx, org).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.issues_read {
        return Err(capability_denied().into());
    }

    let q = normalize_query(&q);
    let status = normalize_status(&status);
    let page = parse_page(page.parse().ok());
    let page_items = load_filtered_issues_page(cx, ctx.org.id, &q, &status, page).await;

    let opener_ids: Vec<u64> = page_items.iter().map(|i| i.opened_by_user_id).collect();
    let mut database = crate::auth::db(cx);
    let users = users_by_ids(&mut database, &opener_ids)
        .await
        .unwrap_or_default();
    let tz = browser_tz(cx);
    let now = now_unix();

    // Links use the authorized org slug, never the raw shard arg.
    let org = ctx.org.slug.clone();

    Ok(view! {
        cx =>
        <div class="vb-list" data-issues-search-shard="1">
            if page_items.is_empty() {
                <div class="vb-empty">"No matching issues."</div>
            } else {
                for issue in page_items {
                    let opener = users
                        .iter()
                        .find(|u| u.id == issue.opened_by_user_id)
                        .map(|u| u.display_name.clone())
                        .unwrap_or_else(|| "Unknown".to_owned());
                    let updated = format_relative(issue.updated_at, now, tz);
                    let meta = format!(
                        "{} · opened by {} · updated {}",
                        issue.component,
                        opener,
                        updated,
                    );
                    <a
                        class="vb-row"
                        href=(href!(
                            issue_detail_page,
                            Org(org.as_str()),
                            IssueKey(issue.key.as_str()),
                        ))
                    >
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
