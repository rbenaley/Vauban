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
async fn builds_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.builds_read {
        return Err(forbidden().into());
    }

    let mut database = crate::auth::db(cx);
    let releases = Release::all().exec(&mut database).await.unwrap_or_default();

    let body = view! {
        <h1>"Certified LTS builds"</h1>
        <p class="muted">"Signed binaries for your supported channels."</p>
        <div class="card" style="margin-top: 18px; overflow-x: auto;">
            <table>
                <thead>
                    <tr>
                        <th>"VERSION"</th>
                        <th>"CHANNEL"</th>
                        <th>"DATE"</th>
                        <th>"SIGNATURE"</th>
                        <th>"SIZE"</th>
                    </tr>
                </thead>
                <tbody>
                    if releases.is_empty() {
                        <tr><td colspan="5" class="muted">"No published builds."</td></tr>
                    } else {
                        for rel in releases {
                            <tr>
                                <td style="font-family: ui-monospace, monospace; font-weight: 700;">
                                    (rel.version.clone())
                                </td>
                                <td>(rel.channel.clone())</td>
                                <td>(rel.released_on.clone())</td>
                                <td style="font-family: ui-monospace, monospace;">
                                    (rel.signature_prefix.clone())
                                    "…"
                                </td>
                                <td>(rel.size_mb.clone()) " MB"</td>
                            </tr>
                        }
                    }
                </tbody>
            </table>
            if perms.builds_download {
                <p class="muted" style="margin-top: 14px;">
                    "Download and time-limited links will land in a later slice."
                </p>
            }
        </div>
    };

    layout::shell(cx, &ctx, &perms, NavSection::Builds, "builds", body).await
}
