//! Live docs search shard — re-checks org + docs_read on every render.
//!
//! Shard POSTs hit `/_topcoat/shards/{id}` — there is no `{org}` path
//! segment. Tenant must come from the shard argument (re-authorized below).

use topcoat::{Result, context::Cx, router::error::not_found, runtime::shard, view::view};

use super::{DocsFilter, load_filtered_docs_page};
use crate::{
    app::_components::ico_chevron_right,
    auth::{capability_denied, require_org},
    docs_search::normalize_org_slug,
    list_page::parse_page,
    perms::perms_for_user,
};

/// Shard args are attacker-controlled — always re-authorize.
#[shard]
pub async fn docs_search_results(
    cx: &Cx,
    org_slug: String,
    q: String,
    cat: String,
    page: String,
) -> Result {
    let org = normalize_org_slug(&org_slug).ok_or_else(not_found)?;
    let ctx = require_org(cx, org).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.docs_read {
        return Err(capability_denied().into());
    }

    let filter = DocsFilter::normalized(&q, &cat);
    let page = parse_page(page.parse().ok());
    let page_items = load_filtered_docs_page(cx, &filter, page).await;
    // Links use the authorized org slug, never the raw shard arg.
    let org = ctx.org.slug.clone();

    view! {
        cx =>
        <div class="vb-list" data-docs-search-shard="1">
            if page_items.is_empty() {
                <div class="vb-empty">"No matching articles."</div>
            } else {
                for article in page_items {
                    <a class="vb-row" href=(format!("/{}/docs/{}", org, article.slug))>
                        <div style="flex: 1; min-width: 0;">
                            <div style="font-weight: 700;">(article.title.clone())</div>
                            <div
                                style="font-size: 12.5px; color: var(--muted); margin-top: 2px;"
                            >
                                (article.summary.clone())
                            </div>
                        </div>
                        <div style="text-align: right; flex: none;">
                            <div
                                class="vb-mono"
                                style="font-size: 10px; color: var(--accent);"
                            >
                                (article.category.clone())
                            </div>
                            <div
                                class="vb-mono"
                                style="font-size: 10px; color: #9aa0a6; margin-top: 3px;"
                            >
                                "Updated "
                                (article.version.clone())
                            </div>
                        </div>
                        <span style="color: #c2c6cb; flex: none; display: inline-flex;">
                            (ico_chevron_right(cx, 16).await?)
                        </span>
                    </a>
                }
            }
        </div>
    }
}
