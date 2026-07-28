//! Admin compose / create at `/admin/docs/new`.

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{Form, SeeOther, page, route, see_other},
    view::view,
};

use crate::{
    auth::{capability_denied, db, require_staff},
    db::now_unix,
    models::{DOC_CATEGORIES, DOC_STATUS_DRAFT, DOC_STATUS_PUBLISHED, DocArticle},
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
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.docs_write {
        return Err(capability_denied().into());
    }

    view! {
        <div>
            <a
                class="vb-back"
                href="/admin/docs"
                style="margin-bottom: 16px; margin-top: 0;"
            >
                "Back to articles"
            </a>
            <h1 class="vb-title">"Compose article"</h1>
            <p class="vb-lead">"Draft or publish a knowledge-base article."</p>
            <div class="vb-panel" style="padding: 24px;">
                <form class="vb-form" method="POST" action="/admin/docs/new">
                    <label for="title">"Title"</label>
                    <input
                        id="title"
                        name="title"
                        required=""
                        placeholder="Article title"
                    >
                    <div class="vb-form-grid2">
                        <div>
                            <label for="category">"Category"</label>
                            <select id="category" name="category" required="">
                                for cat in DOC_CATEGORIES {
                                    let label = (*cat).to_owned();
                                    <option value=(label.clone())>(label)</option>
                                }
                            </select>
                        </div>
                        <div>
                            <label for="summary">"Excerpt"</label>
                            <input
                                id="summary"
                                name="summary"
                                placeholder="One-line summary"
                            >
                        </div>
                    </div>
                    <label for="body">"Content"</label>
                    <textarea
                        id="body"
                        name="body"
                        placeholder="Write the article…"
                        style="min-height: 280px;"
                        required=""
                    ></textarea>
                    <p class="vb-form-hint">
                        "Formatting · ## Heading · blank line = new paragraph · - item for bullet lists · ::: callout … ::: · ``` to fence a code block"
                    </p>
                    <div
                        style="display: flex; gap: 12px; margin-top: 20px; flex-wrap: wrap; align-items: center;"
                    >
                        <button class="vb-btn" type="submit" name="publish" value="1">
                            "Publish article"
                        </button>
                        <button class="vb-btn muted" type="submit">"Save draft"</button>
                        <a class="vb-link" href="/admin/docs" style="margin: 0;">
                            "Cancel"
                        </a>
                    </div>
                </form>
            </div>
        </div>
    }
}

#[route(POST "/admin/docs/new")]
async fn admin_docs_create(cx: &Cx, Form(form): Form<CreateDocForm>) -> Result<SeeOther> {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.docs_write {
        return Err(capability_denied().into());
    }

    let title = form.title.trim().to_owned();
    if title.is_empty() {
        return Ok(see_other("/admin/docs/new"));
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

    Ok(see_other("/admin/docs"))
}
