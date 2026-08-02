//! Admin documentation list at `/admin/docs`.

mod doc;
mod new;

use topcoat::{
    Result,
    context::Cx,
    router::{page, query_params},
    view::view,
};

use crate::{
    app::_components::{ico_trash, list_toolbar},
    auth::{capability_denied, require_staff},
    list_page::{
        LIST_PAGE_SIZE, PagerLinks, clamp_page, href_with_query, page_count, parse_page,
        with_page_param,
    },
    models::{DOC_STATUS_PUBLISHED, DocArticle},
    perms::perms_for_user,
    ui::doc_status_badge_class,
};

#[query_params]
struct AdminDocsQuery {
    delete: Option<String>,
    err: Option<String>,
    /// 1-based page index; omitted means page 1.
    page: Option<u32>,
}

#[page]
async fn admin_docs_page(cx: &Cx) -> Result {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.docs_write {
        return Err(capability_denied().into());
    }

    let mut database = crate::auth::db(cx);
    let total = DocArticle::all()
        .count()
        .exec(&mut database)
        .await
        .unwrap_or(0) as usize;

    let q = query_params::<AdminDocsQuery>(cx).ok();
    let delete_id = q
        .as_ref()
        .and_then(|q| q.delete.as_deref())
        .and_then(|s| s.parse::<u64>().ok());
    let delete_err = q
        .as_ref()
        .and_then(|q| q.err.as_deref())
        .is_some_and(|e| e == "confirm");
    // Resolve delete target by id (not via a full-table scan).
    let delete_target = if let Some(id) = delete_id {
        DocArticle::all()
            .filter(DocArticle::fields().id().eq(id))
            .limit(1)
            .exec(&mut database)
            .await
            .unwrap_or_default()
            .into_iter()
            .next()
    } else {
        None
    };

    let mut page = parse_page(q.as_ref().and_then(|q| q.page));
    let pages = page_count(total, LIST_PAGE_SIZE);
    page = clamp_page(page, pages);
    // Newest edit first (SQL). Version/id tie-break stays approximate vs prior Rust sort.
    let page_articles = DocArticle::all()
        .order_by(DocArticle::fields().updated_at().desc())
        .limit(LIST_PAGE_SIZE)
        .offset(crate::list_page::page_offset(page, LIST_PAGE_SIZE))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    // Pager keeps only `page` — never sticky `delete` / `err` (overlay query).
    let pager = PagerLinks::from_hrefs(page, pages, |n| {
        let mut parts = Vec::new();
        with_page_param(&mut parts, n);
        href_with_query("/admin/docs", &parts)
    });

    view! {
        cx =>
        <div
            style="display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap; margin-bottom: 18px;"
        >
            <div>
                <h1 class="vb-title">"Documentation editor"</h1>
                <p class="vb-lead" style="margin-bottom: 0;">
                    "Write, version, publish or hide knowledge-base articles."
                </p>
            </div>
            <a class="vb-btn" href="/admin/docs/new">"+ New article"</a>
        </div>

        list_toolbar(links: &pager)

        <div class="vb-table-wrap">
            <table class="vb-table">
                <thead>
                    <tr>
                        <th>"TITLE"</th>
                        <th>"CATEGORY"</th>
                        <th>"VER."</th>
                        <th>"STATUS"</th>
                        <th class="vb-col-actions">"ACTIONS"</th>
                    </tr>
                </thead>
                <tbody>
                    if total == 0 {
                        <tr>
                            <td colspan="5">
                                <div class="vb-empty">"No articles yet."</div>
                            </td>
                        </tr>
                    } else {
                        for article in page_articles {
                            let edit_href = format!("/admin/docs/{}", article.id);
                            let publish_action = format!("/admin/docs/{}/publish", article.id);
                            let unpublish_action = format!(
                                "/admin/docs/{}/unpublish", article.id
                            );
                            let delete_href = format!("/admin/docs?delete={}", article.id);
                            let is_published = article.status == DOC_STATUS_PUBLISHED;
                            let status_badge = doc_status_badge_class(&article.status)
                                .to_owned();
                            let summary = if article.summary.trim().is_empty() {
                                "—".to_owned()
                            } else {
                                article.summary.clone()
                            };
                            <tr>
                                <td>
                                    <div class="vb-title-cell">
                                        <div class="vb-title-main">(article.title.clone())</div>
                                        <div class="vb-title-sub">(summary)</div>
                                    </div>
                                </td>
                                <td
                                    class="vb-mono"
                                    style="font-size: 11px; color: var(--accent);"
                                >
                                    (article.category.clone())
                                </td>
                                <td
                                    class="vb-mono"
                                    style="font-size: 12px; color: #5a5f66;"
                                >
                                    (article.version.clone())
                                </td>
                                <td>
                                    <span class=(status_badge)>(article.status.clone())</span>
                                </td>
                                <td class="vb-col-actions">
                                    <div class="vb-row-actions">
                                        <a class="vb-btn muted compact" href=(edit_href)>"Edit"</a>
                                        if is_published {
                                            <form method="POST" action=(unpublish_action)>
                                                <button class="vb-btn outline compact" type="submit">
                                                    "Unpublish"
                                                </button>
                                            </form>
                                        } else {
                                            <form method="POST" action=(publish_action)>
                                                <button class="vb-btn outline compact" type="submit">
                                                    "Publish"
                                                </button>
                                            </form>
                                        }
                                        <a
                                            class="vb-btn danger"
                                            href=(delete_href)
                                            title="Delete article"
                                            aria-label="Delete article"
                                        >
                                            (ico_trash(cx, 14).await?)
                                        </a>
                                    </div>
                                </td>
                            </tr>
                        }
                    }
                </tbody>
            </table>
        </div>

        if let Some(target) = delete_target {
            let cancel = "/admin/docs".to_owned();
            let action = format!("/admin/docs/{}/delete", target.id);
            <div
                class="vb-confirm-root"
                role="dialog"
                aria-modal="true"
                aria-label="Delete article"
            >
                <div class="vb-confirm">
                    <h2>"Delete this article?"</h2>
                    <p>
                        "This permanently removes "
                        <strong>(target.title.clone())</strong>
                        ". Type "
                        <span class="vb-mono">"delete"</span>
                        " to confirm."
                    </p>
                    if delete_err {
                        <p style="color: #b5403a; margin-bottom: 14px;">
                            "Confirmation text must be exactly "
                            <span class="vb-mono">"delete"</span>
                            "."
                        </p>
                    }
                    <form class="vb-form" method="POST" action=(action)>
                        <label for="confirm">"Confirm"</label>
                        <input
                            id="confirm"
                            name="confirm"
                            required=""
                            placeholder="delete"
                            autocomplete="off"
                        >
                        <div class="vb-confirm-actions">
                            <a class="vb-btn muted compact" href=(cancel)>"Cancel"</a>
                            <button
                                class="vb-btn danger"
                                type="submit"
                                style="padding: 10px 18px; font-size: 13px;"
                            >
                                "Delete permanently"
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        }
    }
}
