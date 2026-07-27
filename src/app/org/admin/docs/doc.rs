//! Admin edit / publish at `/{org}/admin/docs/{doc}`.

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{Form, SeeOther, forbidden, not_found, page, path_param, route, see_other},
    view::view,
};

use crate::{
    app::org::Org,
    auth::{db, require_org},
    db::now_unix,
    models::{DOC_STATUS_DRAFT, DOC_STATUS_PUBLISHED, DocArticle},
    perms::perms_for_user,
    tz::{browser_tz, format_unix_local, unix_rfc3339},
};

#[path_param]
struct Doc(str);

#[derive(Deserialize)]
struct UpdateDocForm {
    title: String,
    category: String,
    body: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    version: String,
}

async fn load_article(cx: &Cx, doc_slug: &str) -> Option<DocArticle> {
    let mut database = db(cx);
    let key = doc_slug.to_owned();
    DocArticle::all()
        .filter(DocArticle::fields().slug().eq(&key))
        .include(DocArticle::fields().body())
        .exec(&mut database)
        .await
        .ok()
        .and_then(|mut rows| rows.pop())
}

#[page]
async fn admin_docs_edit_page(cx: &Cx) -> Result {
    let org_slug = path_param::<Org>(cx);
    let doc_slug = path_param::<Doc>(cx);
    let ctx = require_org(cx, org_slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.admin_view || !perms.docs_write {
        return Err(forbidden().into());
    }

    let Some(article) = load_article(cx, doc_slug).await else {
        return Err(not_found().into());
    };

    let back = format!("/{org_slug}/admin/docs");
    let action = format!("/{org_slug}/admin/docs/{doc_slug}");
    let publish = format!("/{org_slug}/admin/docs/{doc_slug}/publish");
    let unpublish = format!("/{org_slug}/admin/docs/{doc_slug}/unpublish");
    let is_published = article.status == DOC_STATUS_PUBLISHED;
    let tz = browser_tz(cx);
    let updated = format_unix_local(article.updated_at, tz);
    let updated_rfc = unix_rfc3339(article.updated_at);

    view! {
        <div style="max-width: 720px;">
            <a
                class="vb-link"
                href=(back.clone())
                style="display: inline-block; margin-bottom: 16px;"
            >
                "← Documentation editor"
            </a>
            <h1 class="vb-title">"Edit article"</h1>
            <p class="vb-lead">
                "Slug "
                <span class="vb-mono">(article.slug.clone())</span>
                " · "
                <time datetime=(updated_rfc)>(updated)</time>
            </p>
            <div class="vb-panel" style="padding: 24px;">
                <form class="vb-form" method="POST" action=(action)>
                    <label for="title">"Title"</label>
                    <input
                        id="title"
                        name="title"
                        required=""
                        value=(article.title.clone())
                    >
                    <label for="category">"Category"</label>
                    <input
                        id="category"
                        name="category"
                        required=""
                        value=(article.category.clone())
                    >
                    <label for="summary">"Summary"</label>
                    <input
                        id="summary"
                        name="summary"
                        value=(article.summary.clone())
                    >
                    <label for="version">"Version"</label>
                    <input
                        id="version"
                        name="version"
                        value=(article.version.clone())
                    >
                    <label for="body">"Body"</label>
                    <textarea
                        id="body"
                        name="body"
                        style="min-height: 180px;"
                        required=""
                    >(article.body.get().clone())</textarea>
                    <div style="display: flex; gap: 12px; margin-top: 18px; flex-wrap: wrap;">
                        <button class="vb-btn" type="submit">"Save"</button>
                        <a
                            class="vb-link"
                            href=(back)
                            style="margin: 0; align-self: center;"
                        >
                            "Cancel"
                        </a>
                    </div>
                </form>
                <div style="display: flex; gap: 12px; margin-top: 18px;">
                    if is_published {
                        <form method="POST" action=(unpublish)>
                            <button class="vb-btn muted" type="submit">"Unpublish"</button>
                        </form>
                    } else {
                        <form method="POST" action=(publish)>
                            <button class="vb-btn" type="submit">"Publish"</button>
                        </form>
                    }
                </div>
            </div>
        </div>
    }
}

#[route(POST "/{org}/admin/docs/{doc}")]
async fn admin_docs_update(cx: &Cx, Form(form): Form<UpdateDocForm>) -> Result<SeeOther> {
    let org_slug = path_param::<Org>(cx);
    let doc_slug = path_param::<Doc>(cx);
    let ctx = require_org(cx, org_slug).await.map_err(|_| forbidden())?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.admin_view || !perms.docs_write {
        return Err(forbidden().into());
    }

    let Some(mut article) = load_article(cx, doc_slug).await else {
        return Err(not_found().into());
    };

    let title = form.title.trim().to_owned();
    let category = form.category.trim().to_owned();
    let body = form.body.trim().to_owned();
    let summary = {
        let s = form.summary.trim();
        if s.is_empty() {
            body.lines().next().unwrap_or("").trim().to_owned()
        } else {
            s.to_owned()
        }
    };
    let version = {
        let v = form.version.trim();
        if v.is_empty() {
            article.version.clone()
        } else {
            v.to_owned()
        }
    };

    let mut database = db(cx);
    let _ = article
        .update()
        .title(title)
        .category(category)
        .summary(summary)
        .body(body)
        .version(version)
        .updated_at(now_unix())
        .exec(&mut database)
        .await;

    Ok(see_other(&format!("/{org_slug}/admin/docs/{doc_slug}")))
}

#[route(POST "/{org}/admin/docs/{doc}/publish")]
async fn admin_docs_publish(cx: &Cx) -> Result<SeeOther> {
    set_status(cx, DOC_STATUS_PUBLISHED).await
}

#[route(POST "/{org}/admin/docs/{doc}/unpublish")]
async fn admin_docs_unpublish(cx: &Cx) -> Result<SeeOther> {
    set_status(cx, DOC_STATUS_DRAFT).await
}

async fn set_status(cx: &Cx, status: &str) -> Result<SeeOther> {
    let org_slug = path_param::<Org>(cx);
    let doc_slug = path_param::<Doc>(cx);
    let ctx = require_org(cx, org_slug).await.map_err(|_| forbidden())?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.admin_view || !perms.docs_write {
        return Err(forbidden().into());
    }
    let Some(mut article) = load_article(cx, doc_slug).await else {
        return Err(not_found().into());
    };
    let mut database = db(cx);
    let _ = article
        .update()
        .status(status.to_owned())
        .updated_at(now_unix())
        .exec(&mut database)
        .await;
    Ok(see_other(&format!("/{org_slug}/admin/docs/{doc_slug}")))
}
