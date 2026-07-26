//! Admin releases list at `/{org}/admin/releases`.

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
        <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap; margin-bottom: 18px;">
            <div>
                <h1 class="vb-title">"Release manager"</h1>
                <p class="vb-lead" style="margin-bottom: 0;">
                    "Publish signed builds that appear in the customer Builds list."
                </p>
            </div>
            <a class="vb-btn" href=(format!("/{}/admin/releases/new", slug))>"+ Publish release"</a>
        </div>

        <div class="vb-table-wrap">
            <table class="vb-table">
                <thead>
                    <tr>
                        <th>"VERSION"</th>
                        <th>"CHANNEL"</th>
                        <th>"DATE"</th>
                        <th>"SIZE"</th>
                        <th>"STATUS"</th>
                        <th>"ACTIONS"</th>
                    </tr>
                </thead>
                <tbody>
                    if releases.is_empty() {
                        <tr>
                            <td colspan="6"><div class="vb-empty">"No releases recorded."</div></td>
                        </tr>
                    } else {
                        for rel in releases {
                            <tr>
                                <td style="font-weight: 700;">(rel.version.clone())</td>
                                <td><span class="vb-badge soft">(rel.channel.clone())</span></td>
                                <td>(rel.released_on.clone())</td>
                                <td>(rel.size_mb.clone()) " MB"</td>
                                <td>(rel.status.clone())</td>
                                <td>
                                    <a class="vb-link" href=(format!("/{}/admin/releases/new", slug)) style="margin: 0;">
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
            "Upload and signing workflow ships in a later slice."
        </p>
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
