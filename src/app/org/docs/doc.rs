//! Article modal at `/{org}/docs/{doc}` — Concept overlay over the docs list.

use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, not_found, page, path_param},
    view::view,
};

use super::{DocsFilter, docs_list_view};
use crate::{
    app::_components::article_modal_shell,
    app::org::Org,
    auth::require_org,
    models::{DOC_STATUS_PUBLISHED, DocArticle},
    perms::perms_for_user,
    tz::{browser_tz, format_unix_local, unix_rfc3339},
};

#[path_param]
struct Doc(str);

#[page]
async fn doc_article_page(cx: &Cx) -> Result {
    let org_slug = path_param::<Org>(cx);
    let doc_slug = path_param::<Doc>(cx);
    let ctx = require_org(cx, org_slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.docs_read {
        return Err(forbidden().into());
    }

    let mut database = crate::auth::db(cx);
    let slug_key = doc_slug.to_string();
    let Some(article) = DocArticle::all()
        .filter(DocArticle::fields().slug().eq(&slug_key))
        .include(DocArticle::fields().body())
        .exec(&mut database)
        .await
        .ok()
        .and_then(|mut rows| rows.pop())
    else {
        return Err(not_found().into());
    };
    if article.status != DOC_STATUS_PUBLISHED {
        return Err(not_found().into());
    }

    let filter = DocsFilter::from_cx(cx);
    let list = docs_list_view(cx, org_slug, &filter.q, &filter.cat).await;
    let close_href = format!("/{org_slug}/docs");
    let title = article.title.clone();
    let category = article.category.clone();
    let version = article.version.clone();
    let body = article.body.get().clone();
    let tz = browser_tz(cx);
    let updated = format_unix_local(article.updated_at, tz);
    let updated_rfc = unix_rfc3339(article.updated_at);

    view! {
        cx =>
        (list?)
        article_modal_shell(
            title: &title,
            category: &category,
            version: &version,
            close_href: &close_href,
            body: view! {
                cx =>
                <p class="vb-muted" style="font-size: 12px; margin-bottom: 12px;">
                    "Updated "
                    <time datetime=(updated_rfc)>(updated)</time>
                </p>
                <div style="white-space: pre-wrap; font-size: 14px; line-height: 1.55;">
                    (body)
                </div>
            }
        )
    }
}
