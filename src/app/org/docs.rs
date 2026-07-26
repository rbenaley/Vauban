use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, page, path_param},
    view::view,
};

use crate::{
    app::org::Org,
    auth::require_org,
    layout::{self, NavSection},
    models::DocArticle,
    perms::perms_for_user,
};

#[page]
async fn docs_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.docs_read {
        return Err(forbidden().into());
    }

    let mut database = crate::auth::db(cx);
    let articles = DocArticle::all()
        .exec(&mut database)
        .await
        .unwrap_or_default();

    let body = view! {
        <h1>"Documentation & knowledge base"</h1>
        <p class="muted">"Operations, security, API, and deployment runbooks."</p>
        <div style="margin: 18px 0; display: flex; flex-wrap: wrap; gap: 8px;">
            <span class="btn">"All"</span>
            <span class="card" style="padding: 8px 12px;">"Getting started"</span>
            <span class="card" style="padding: 8px 12px;">"Deployment"</span>
            <span class="card" style="padding: 8px 12px;">"Security"</span>
            <span class="card" style="padding: 8px 12px;">"API"</span>
            <span class="card" style="padding: 8px 12px;">"Operations"</span>
        </div>
        if articles.is_empty() {
            <div class="card muted">"No published articles yet."</div>
        } else {
            <div style="display: flex; flex-direction: column; gap: 10px;">
                for article in articles {
                    <div class="card" style="display: flex; justify-content: space-between; gap: 16px;">
                        <div>
                            <div style="font-weight: 700;">(article.title.clone())</div>
                            <p class="muted" style="margin: 4px 0 0;">(article.summary.clone())</p>
                        </div>
                        <div class="muted" style="font-family: ui-monospace, monospace; font-size: 12px; white-space: nowrap;">
                            (article.category.clone())
                        </div>
                    </div>
                }
            </div>
        }
    };

    layout::shell(cx, &ctx, &perms, NavSection::Docs, "documentation", body).await
}
