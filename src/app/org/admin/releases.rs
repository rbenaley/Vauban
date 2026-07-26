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
    models::Release,
    perms::perms_for_user,
};

#[page]
async fn admin_releases_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.admin_view || !perms.releases_manage {
        return Err(forbidden().into());
    }

    let mut database = crate::auth::db(cx);
    let releases = Release::all().exec(&mut database).await.unwrap_or_default();

    let body = view! {
        <h1>"Release manager"</h1>
        <p class="muted">"Publish signed LTS builds (stub — no upload yet)."</p>
        <div class="card" style="margin-top: 18px;">
            if releases.is_empty() {
                <p class="muted">"No releases recorded."</p>
            } else {
                <table>
                    <thead>
                        <tr>
                            <th>"VERSION"</th>
                            <th>"CHANNEL"</th>
                            <th>"DATE"</th>
                            <th>"SIZE"</th>
                        </tr>
                    </thead>
                    <tbody>
                        for rel in releases {
                            <tr>
                                <td style="font-family: ui-monospace, monospace;">
                                    (rel.version.clone())
                                </td>
                                <td>(rel.channel.clone())</td>
                                <td>(rel.released_on.clone())</td>
                                <td>(rel.size_mb.clone()) " MB"</td>
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
        NavSection::AdminReleases,
        "admin / releases",
        body,
    )
    .await
}
