//! Admin documentation list at `/{org}/admin/docs`.

mod doc;
mod new;

use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, page, path_param},
    view::view,
};

use crate::{
    app::org::Org,
    auth::require_org,
    models::DocArticle,
    perms::perms_for_user,
    tz::{browser_tz, format_unix_local},
};

#[page]
async fn admin_docs_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.admin_view || !perms.docs_write {
        return Err(forbidden().into());
    }

    let mut database = crate::auth::db(cx);
    let articles = DocArticle::all()
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let tz = browser_tz(cx);

    view! {
        <div
            style="display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap; margin-bottom: 18px;"
        >
            <div>
                <h1 class="vb-title">"Documentation editor"</h1>
                <p class="vb-lead" style="margin-bottom: 0;">
                    "Draft, publish, and revise knowledge-base articles."
                </p>
            </div>
            <a class="vb-btn" href=(format!("/{}/admin/docs/new", slug))>
                "+ New article"
            </a>
        </div>

        <div class="vb-table-wrap">
            <table class="vb-table">
                <thead>
                    <tr>
                        <th>"TITLE"</th>
                        <th>"CATEGORY"</th>
                        <th>"VER."</th>
                        <th>"STATUS"</th>
                        <th>"UPDATED"</th>
                        <th>"ACTIONS"</th>
                    </tr>
                </thead>
                <tbody>
                    if articles.is_empty() {
                        <tr>
                            <td colspan="6">
                                <div class="vb-empty">"No articles yet."</div>
                            </td>
                        </tr>
                    } else {
                        for article in articles {
                            let updated = format_unix_local(article.updated_at, tz);
                            <tr>
                                <td
                                    style="font-family: 'Hanken Grotesk', sans-serif; font-weight: 700;"
                                >
                                    (article.title.clone())
                                </td>
                                <td>(article.category.clone())</td>
                                <td>(article.version.clone())</td>
                                <td>
                                    <span class="vb-badge soft">(article.status.clone())</span>
                                </td>
                                <td class="vb-mono" style="font-size: 11px;">(updated)</td>
                                <td>
                                    <a
                                        class="vb-link"
                                        href=(format!(
                                            "/{}/admin/docs/{}", slug, article.slug
                                        ))
                                        style="margin: 0;"
                                    >
                                        "Edit"
                                    </a>
                                </td>
                            </tr>
                        }
                    }
                </tbody>
            </table>
        </div>
    }
}
