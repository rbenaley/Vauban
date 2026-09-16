//! Admin edit / publish / delete at `/admin/docs/{doc}` (article id).

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{
        content::Form,
        error::{SeeOther, not_found, see_other},
        href, page, path_param, route,
    },
    view::{View, view},
};

use crate::app::admin::docs::admin_docs_page;
use crate::{
    app::_components::ico_issues,
    auth::{capability_denied, db, require_staff},
    db::now_unix,
    docs_version::{bump_version, is_delete_confirm, unpublish_other_published},
    models::{DOC_CATEGORIES, DOC_STATUS_DRAFT, DOC_STATUS_PUBLISHED, DocArticle},
    perms::perms_for_user,
    tz::{browser_tz, format_unix_local, unix_rfc3339},
};

path_param!(pub(crate) doc);

#[derive(Deserialize)]
struct UpdateDocForm {
    title: String,
    category: String,
    body: String,
    #[serde(default)]
    summary: String,
}

#[derive(Deserialize)]
struct DeleteDocForm {
    confirm: String,
}

async fn load_article_by_id(cx: &Cx, id: u64) -> Option<DocArticle> {
    let mut database = db(cx);
    DocArticle::all()
        .filter(DocArticle::fields().id().eq(id))
        .include(DocArticle::fields().body())
        .exec(&mut database)
        .await
        .ok()
        .and_then(|mut rows| rows.pop())
}

fn parse_doc_id(raw: &str) -> Option<u64> {
    raw.parse::<u64>().ok()
}

#[page]
pub(crate) async fn admin_docs_edit_page(cx: &Cx) -> Result<impl View> {
    let doc_raw = path_param::<Doc>(cx);
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.docs_write {
        return Err(capability_denied().into());
    }

    let Some(doc_id) = parse_doc_id(doc_raw) else {
        return Err(not_found().into());
    };
    let Some(article) = load_article_by_id(cx, doc_id).await else {
        return Err(not_found().into());
    };

    let action = href!(admin_docs_update, Doc(doc_id.to_string())).resolve(cx);
    let is_published = article.status == DOC_STATUS_PUBLISHED;
    let tz = browser_tz(cx);
    let updated = format_unix_local(article.updated_at, tz);
    let updated_rfc = unix_rfc3339(article.updated_at);
    let save_label = if is_published {
        "Publish new version"
    } else {
        "Save"
    };
    let current_cat = article.category.clone();

    Ok(view! {
        <div>
            <a
                class="vb-back"
                href=(href!(admin_docs_page))
                style="margin-bottom: 16px; margin-top: 0;"
            >
                "Back to articles"
            </a>
            <h1 class="vb-title">"Compose article"</h1>
            <p class="vb-lead">
                "Slug "
                <span class="vb-mono">(article.slug.clone())</span>
                " · "
                <span class="vb-mono">(article.version.clone())</span>
                " · "
                <time datetime=(updated_rfc)>(updated)</time>
            </p>
            if is_published {
                <div class="vb-callout" style="margin-bottom: 18px;">
                    ico_issues(size: 16)
                    <span>
                        "Editing a published article publishes a new version and unpublishes the previous one — so both appear in the editor list."
                    </span>
                </div>
            }
            <div class="vb-panel" style="padding: 24px;">
                <form class="vb-form" method="POST" action=(action)>
                    <label for="title">"Title"</label>
                    <input
                        id="title"
                        name="title"
                        required=""
                        value=(article.title.clone())
                    >
                    <div class="vb-form-grid2">
                        <div>
                            <label for="category">"Category"</label>
                            <select id="category" name="category" required="">
                                for cat in DOC_CATEGORIES {
                                    let label = (*cat).to_owned();
                                    if *cat == current_cat.as_str() {
                                        <option value=(label.clone()) selected=(true)>
                                            (label)
                                        </option>
                                    } else {
                                        <option value=(label.clone())>(label)</option>
                                    }
                                }
                            </select>
                        </div>
                        <div>
                            <label for="summary">"Excerpt"</label>
                            <input
                                id="summary"
                                name="summary"
                                value=(article.summary.clone())
                                placeholder="One-line summary"
                            >
                        </div>
                    </div>
                    <label for="body">"Content"</label>
                    <textarea
                        id="body"
                        name="body"
                        style="min-height: 280px;"
                        required=""
                    >
                        (article.body.get().clone())
                    </textarea>
                    <p class="vb-form-hint">(crate::docs_body::DIALECT_HINT)</p>
                    <div
                        style="display: flex; gap: 12px; margin-top: 20px; flex-wrap: wrap; align-items: center;"
                    >
                        <button class="vb-btn" type="submit">(save_label)</button>
                        <a
                            class="vb-link"
                            href=(href!(admin_docs_page))
                            style="margin: 0;"
                        >
                            "Cancel"
                        </a>
                    </div>
                </form>
            </div>
        </div>
    })
}

#[route(POST)]
pub(crate) async fn admin_docs_update(
    cx: &Cx,
    Form(form): Form<UpdateDocForm>,
) -> Result<SeeOther> {
    let doc_raw = path_param::<Doc>(cx);
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.docs_write {
        return Err(capability_denied().into());
    }

    let Some(doc_id) = parse_doc_id(doc_raw) else {
        return Err(not_found().into());
    };
    let Some(article) = load_article_by_id(cx, doc_id).await else {
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

    let mut database = db(cx);
    let now = now_unix();

    if article.status == DOC_STATUS_PUBLISHED {
        let new_version = bump_version(&article.version);
        let created = toasty::create!(DocArticle {
            title,
            summary,
            category,
            slug: article.slug.clone(),
            version: new_version,
            status: DOC_STATUS_PUBLISHED.to_owned(),
            body,
            updated_at: now,
        })
        .exec(&mut database)
        .await;
        if let Ok(created) = created {
            let _ = unpublish_other_published(&mut database, &article.slug, created.id).await;
        }
    } else {
        let mut article = article;
        let _ = article
            .update()
            .title(title)
            .category(category)
            .summary(summary)
            .body(body)
            .updated_at(now)
            .exec(&mut database)
            .await;
    }

    Ok(see_other(href!(admin_docs_page).resolve(cx)))
}

#[route(POST "./publish")]
pub(crate) async fn admin_docs_publish(cx: &Cx) -> Result<SeeOther> {
    set_status(cx, DOC_STATUS_PUBLISHED).await
}

#[route(POST "./unpublish")]
pub(crate) async fn admin_docs_unpublish(cx: &Cx) -> Result<SeeOther> {
    set_status(cx, DOC_STATUS_DRAFT).await
}

#[route(POST "./delete")]
pub(crate) async fn admin_docs_delete(
    cx: &Cx,
    Form(form): Form<DeleteDocForm>,
) -> Result<SeeOther> {
    let doc_raw = path_param::<Doc>(cx);
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.docs_write {
        return Err(capability_denied().into());
    }

    let Some(doc_id) = parse_doc_id(doc_raw) else {
        return Err(not_found().into());
    };
    let Some(article) = load_article_by_id(cx, doc_id).await else {
        return Err(not_found().into());
    };

    if !is_delete_confirm(&form.confirm) {
        return Ok(see_other(
            href!(admin_docs_page)
                .query(crate::app::hrefs::DeleteErrQ {
                    delete: doc_id,
                    err: "confirm",
                })
                .resolve(cx),
        ));
    }

    let mut database = db(cx);
    let _ = article.delete().exec(&mut database).await;

    Ok(see_other(href!(admin_docs_page).resolve(cx)))
}

async fn set_status(cx: &Cx, status: &str) -> Result<SeeOther> {
    let doc_raw = path_param::<Doc>(cx);
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.docs_write {
        return Err(capability_denied().into());
    }
    let Some(doc_id) = parse_doc_id(doc_raw) else {
        return Err(not_found().into());
    };
    let Some(mut article) = load_article_by_id(cx, doc_id).await else {
        return Err(not_found().into());
    };
    let mut database = db(cx);
    let now = now_unix();
    let _ = article
        .update()
        .status(status.to_owned())
        .updated_at(now)
        .exec(&mut database)
        .await;
    if status == DOC_STATUS_PUBLISHED {
        let _ = unpublish_other_published(&mut database, &article.slug, article.id).await;
    }
    Ok(see_other(href!(admin_docs_page).resolve(cx)))
}
