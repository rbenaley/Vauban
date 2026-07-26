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
        <h1>"Documentation editor"</h1>
        <p class="muted">"Draft and publish knowledge-base articles (stub)."</p>
        <div class="card" style="margin-top: 18px;">
            if articles.is_empty() {
                <p class="muted">"No articles. Editor UI ships in a later slice."</p>
            } else {
                <table>
                    <thead>
                        <tr>
                            <th>"TITLE"</th>
                            <th>"CATEGORY"</th>
                            <th>"SLUG"</th>
                        </tr>
                    </thead>
                    <tbody>
                        for article in articles {
                            <tr>
                                <td>(article.title.clone())</td>
                                <td>(article.category.clone())</td>
                                <td style="font-family: ui-monospace, monospace;">
                                    (article.slug.clone())
                                </td>
                            </tr>
                        }
                    </tbody>
                </table>
            }
        </div>
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
