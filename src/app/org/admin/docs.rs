//! Admin documentation list at `/{org}/admin/docs`.

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
    layout::{self, NavSection},
    models::DocArticle,
    perms::perms_for_user,
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

    let body = view! {
        <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap; margin-bottom: 18px;">
            <div>
                <h1 class="vb-title">"Documentation editor"</h1>
                <p class="vb-lead" style="margin-bottom: 0;">
                    "Draft, publish, and revise knowledge-base articles."
                </p>
            </div>
            <a class="vb-btn" href=(format!("/{}/admin/docs/new", slug))>"+ New article"</a>
        </div>

        <div class="vb-table-wrap">
            <table class="vb-table">
                <thead>
                    <tr>
                        <th>"TITLE"</th>
                        <th>"CATEGORY"</th>
                        <th>"VER."</th>
                        <th>"STATUS"</th>
                        <th>"ACTIONS"</th>
                    </tr>
                </thead>
                <tbody>
                    if articles.is_empty() {
                        <tr>
                            <td colspan="5"><div class="vb-empty">"No articles yet."</div></td>
                        </tr>
                    } else {
                        for article in articles {
                            <tr>
                                <td style="font-family: 'Hanken Grotesk', sans-serif; font-weight: 700;">
                                    (article.title.clone())
                                </td>
                                <td>(article.category.clone())</td>
                                <td>(article.version.clone())</td>
                                <td>
                                    <span class="vb-badge soft">(article.status.clone())</span>
                                </td>
                                <td>
                                    <a class="vb-link" href=(format!("/{}/admin/docs/new", slug)) style="margin: 0;">
                                        "Edit"
                                    </a>
                                </td>
                            </tr>
                        }
                    }
                </tbody>
            </table>
        </div>
        <p class="vb-muted" style="margin-top: 14px;">
            "Publish / unpublish mutations ship in a later slice."
        </p>
    };

    layout::shell(
        cx,
        &ctx,
        &perms,
        NavSection::AdminDocs,
        "admin / docs",
        body,
    )
    .await
}
