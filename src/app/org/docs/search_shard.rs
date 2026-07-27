//! Live docs search shard — re-checks org + docs_read on every render.

use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, path_param},
    runtime::shard,
    view::view,
};

use super::{DocsFilter, load_filtered_docs};
use crate::{app::org::Org, auth::require_org, perms::perms_for_user};

/// Shard args are attacker-controlled — always re-authorize.
#[shard]
pub async fn docs_search_results(cx: &Cx, org_slug: String, q: String, cat: String) -> Result {
    let path_org = path_param::<Org>(cx);
    // Prefer path org; fall back to shard arg only if path missing.
    let org = if (*path_org).is_empty() {
        org_slug.as_str()
    } else {
        // Reject cross-tenant shard args.
        if !org_slug.is_empty() && org_slug != *path_org {
            return Err(forbidden().into());
        }
        path_org
    };
    let ctx = require_org(cx, org).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.docs_read {
        return Err(forbidden().into());
    }

    let filter = DocsFilter {
        q: q.trim().to_lowercase(),
        cat: cat.trim().to_owned(),
    };
    let (_, _, filtered) = load_filtered_docs(cx, &filter).await;
    let org = ctx.org.slug.clone();

    view! {
        cx =>
        <div class="vb-list" data-docs-search-shard="1">
            if filtered.is_empty() {
                <div class="vb-empty">"No matching articles."</div>
            } else {
                for article in filtered {
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
                        <span style="font-size: 16px; color: #c2c6cb; flex: none;">
                            "→"
                        </span>
                    </a>
                }
            }
        </div>
    }
}
