//! Admin compose / create at `/{org}/admin/docs/new`.

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{Form, SeeOther, forbidden, page, path_param, route, see_other},
    view::view,
};

use crate::{
    app::org::Org,
    auth::{db, require_org},
    db::now_unix,
    models::{DOC_STATUS_DRAFT, DOC_STATUS_PUBLISHED, DocArticle},
    perms::perms_for_user,
    slug::slugify,
};

#[derive(Deserialize)]
struct CreateDocForm {
    title: String,
    category: String,
    body: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    publish: Option<String>,
}

#[page]
async fn admin_docs_new_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.admin_view || !perms.docs_write {
        return Err(forbidden().into());
    }

    let back = format!("/{slug}/admin/docs");
    let action = format!("/{slug}/admin/docs/new");

    view! {
        <div style="max-width: 720px;">
            <a
                class="vb-link"
                href=(back.clone())
                style="display: inline-block; margin-bottom: 16px;"
            >
                "← Documentation editor"
            </a>
            <h1 class="vb-title">"Publish article"</h1>
            <p class="vb-lead">"Draft or publish a knowledge-base article."</p>
            <div class="vb-panel" style="padding: 24px;">
                <form class="vb-form" method="POST" action=(action)>
                    <label for="title">"Title"</label>
                    <input
                        id="title"
                        name="title"
                        required=""
                        placeholder="Article title"
                    >
                    <label for="category">"Category"</label>
                    <select id="category" name="category">
                        <option>"Getting started"</option>
                        <option>"Deployment"</option>
                        <option>"Security"</option>
                        <option>"API"</option>
                        <option>"Operations"</option>
                    </select>
                    <label for="summary">"Summary"</label>
                    <input id="summary" name="summary" placeholder="One-line summary">
                    <label for="body">"Body"</label>
                    <textarea
                        id="body"
                        name="body"
                        placeholder="Plain-text content…"
                        style="min-height: 180px;"
                        required=""
                    ></textarea>
                    <div
                        style="display: flex; gap: 12px; margin-top: 18px; flex-wrap: wrap;"
                    >
                        <button class="vb-btn" type="submit" name="publish" value="1">
                            "Publish"
                        </button>
                        <button class="vb-btn muted" type="submit">"Save draft"</button>
                        <a
                            class="vb-link"
                            href=(back)
                            style="margin: 0; align-self: center;"
                        >
                            "Cancel"
                        </a>
                    </div>
                </form>
            </div>
        </div>
    }
}

#[route(POST "/{org}/admin/docs/new")]
async fn admin_docs_create(cx: &Cx, Form(form): Form<CreateDocForm>) -> Result<SeeOther> {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await.map_err(|_| forbidden())?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.admin_view || !perms.docs_write {
        return Err(forbidden().into());
    }

    let title = form.title.trim().to_owned();
    if title.is_empty() {
        return Ok(see_other(&format!("/{slug}/admin/docs/new")));
    }
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
    let mut article_slug = slugify(&title);
    let mut database = db(cx);
    // Ensure uniqueness.
    let mut n = 2u32;
    loop {
        let clash = DocArticle::all()
            .filter(DocArticle::fields().slug().eq(&article_slug))
            .exec(&mut database)
            .await
            .unwrap_or_default();
        if clash.is_empty() {
            break;
        }
        article_slug = format!("{}-{n}", slugify(&title));
        n += 1;
        if n > 100 {
            break;
        }
    }
    let status = if form.publish.is_some() {
        DOC_STATUS_PUBLISHED.to_owned()
    } else {
        DOC_STATUS_DRAFT.to_owned()
    };

    let _ = toasty::create!(DocArticle {
        title,
        summary,
        category,
        slug: article_slug.clone(),
        version: "v1".to_owned(),
        status,
        body: body,
        updated_at: now_unix(),
    })
    .exec(&mut database)
    .await;

    Ok(see_other(&format!("/{slug}/admin/docs/{article_slug}")))
}
