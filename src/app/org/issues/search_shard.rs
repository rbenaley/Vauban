//! Live org issues search shard — re-checks org + issues_read on every render.
//!
//! Shard POSTs hit `/_topcoat/shards/{id}` — there is no `{org}` path
//! segment. Tenant must come from the shard argument (re-authorized below).

use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, not_found},
    runtime::shard,
    view::view,
};

use crate::{
    app::_components::{severity_badge, status_badge},
    auth::require_org,
    db::now_unix,
    docs_search::normalize_org_slug,
    issues_search::{issue_matches_query, issue_matches_status, normalize_query, normalize_status},
    models::{Issue, User},
    perms::perms_for_user,
    tz::{browser_tz, format_relative},
};

/// Shard args are attacker-controlled — always re-authorize.
#[shard]
pub async fn issues_search_results(cx: &Cx, org_slug: String, q: String, status: String) -> Result {
    let org = normalize_org_slug(&org_slug).ok_or_else(not_found)?;
    let ctx = require_org(cx, org).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.issues_read {
        return Err(forbidden().into());
    }

    let q = normalize_query(&q);
    let status = normalize_status(&status);

    let mut database = crate::auth::db(cx);
    let mut issues = Issue::all()
        .filter(Issue::fields().organization_id().eq(ctx.org.id))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    issues.sort_by_key(|i| std::cmp::Reverse(i.updated_at));
    let users = User::all().exec(&mut database).await.unwrap_or_default();
    let tz = browser_tz(cx);
    let now = now_unix();
    let filtered: Vec<_> = issues
        .into_iter()
        .filter(|i| {
            issue_matches_status(&status, &i.status) && issue_matches_query(&q, &i.key, &i.title)
        })
        .collect();

    // Links use the authorized org slug, never the raw shard arg.
    let org = ctx.org.slug.clone();

    view! {
        cx =>
        <div class="vb-list" data-issues-search-shard="1">
            if filtered.is_empty() {
                <div class="vb-empty">"No matching issues."</div>
            } else {
                for issue in filtered {
                    let opener = users
                        .iter()
                        .find(|u| u.id == issue.opened_by_user_id)
                        .map(|u| u.display_name.clone())
                        .unwrap_or_else(|| "Unknown".to_owned());
                    let updated = format_relative(issue.updated_at, now, tz);
                    let meta = format!(
                        "{} · opened by {} · updated {}", issue.component, opener, updated
                    );
                    <a class="vb-row" href=(format!("/{}/issues/{}", org, issue.key))>
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
