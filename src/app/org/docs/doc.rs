//! Article modal at `/{org}/docs/{doc}` — Concept overlay over the docs list.

use topcoat::{
    Result,
    context::Cx,
    router::{error::not_found, page, path_param},
    view::view,
};

use super::{DocsFilter, docs_list_view};
use crate::{
    app::_components::{article_modal_shell, ico_issues},
    app::org::Org,
    auth::{capability_denied, require_org},
    docs_body::{self, Block},
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
        return Err(capability_denied().into());
    }

    let mut database = crate::auth::db(cx);
    let slug_key = doc_slug.to_string();
    let mut published = DocArticle::all()
        .filter(DocArticle::fields().slug().eq(&slug_key))
        .filter(DocArticle::fields().status().eq(DOC_STATUS_PUBLISHED))
        .include(DocArticle::fields().body())
        .exec(&mut database)
        .await
        .unwrap_or_default();
    // Defensive: prefer newest if more than one published slipped through.
    published.sort_by_key(|a| std::cmp::Reverse(a.updated_at));
    let Some(article) = published.into_iter().next() else {
        return Err(not_found().into());
    };

    let filter = DocsFilter::from_cx(cx);
    let page = DocsFilter::page_from_cx(cx);
    let list = docs_list_view(cx, org_slug, &filter.q, &filter.cat, page).await;
    let close_href = format!("/{org_slug}/docs");
    let title = article.title.clone();
    let category = article.category.clone();
    let version = article.version.clone();
    let body_text = article.body.get().clone();
    let tz = browser_tz(cx);
    let updated = format_unix_local(article.updated_at, tz);
    let updated_rfc = unix_rfc3339(article.updated_at);
    let blocks = render_body_blocks(cx, &body_text).await;

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
                <p class="vb-muted" style="font-size: 12px; margin-bottom: 4px;">
                    "Updated "
                    <time datetime=(updated_rfc)>(updated)</time>
                </p>
                (blocks?)
            }
        )
    }
}

/// Render dialect body from DB (no slug-specific HTML bypass).
async fn render_body_blocks(cx: &Cx, body: &str) -> Result {
    let blocks = docs_body::parse(body);
    view! {
        cx =>
        for block in blocks {
            (render_block(cx, block).await?)
        }
    }
}

async fn render_block(cx: &Cx, block: Block) -> Result {
    match block {
        Block::Heading(text) => {
            view! { cx => <h3>(text)</h3> }
        }
        Block::Paragraph(text) => {
            view! { cx => <p style="white-space: pre-wrap;">(text)</p> }
        }
        Block::Pre(text) => {
            view! { cx => <pre class="vb-pre">(text)</pre> }
        }
        Block::Callout(text) => {
            view! {
                cx =>
                <div class="vb-callout">
                    (ico_issues(cx, 16).await?)
                    <span style="white-space: pre-wrap;">(text)</span>
                </div>
            }
        }
        Block::List(items) => {
            view! {
                cx =>
                <ul>
                    for item in items {
                        <li>(item)</li>
                    }
                </ul>
            }
        }
    }
}
