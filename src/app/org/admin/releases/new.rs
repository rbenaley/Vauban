//! Admin publish release stub at `/{org}/admin/releases/new`.

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
    perms::perms_for_user,
};

#[page]
async fn admin_releases_new_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.admin_view || !perms.releases_manage {
        return Err(forbidden().into());
    }

    let back = format!("/{slug}/admin/releases");

    let body = view! {
        <div style="max-width: 720px;">
            <a class="vb-link" href=(back.clone()) style="display: inline-block; margin-bottom: 16px;">
                "← Release manager"
            </a>
            <h1 class="vb-title">"Publish release"</h1>
            <p class="vb-lead">"Channel metadata and notes. Binary upload ships later."</p>
            <div class="vb-panel" style="padding: 24px;">
                <form class="vb-form" method="GET" action=(back.clone())>
                    <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px;">
                        <div>
                            <label for="version">"Version"</label>
                            <input id="version" name="version" required="" placeholder="v1.1.0">
                        </div>
                        <div>
                            <label for="channel">"Channel"</label>
                            <select id="channel" name="channel">
                                <option>"LTS"</option>
                                <option>"Stable"</option>
                                <option>"EOL"</option>
                            </select>
                        </div>
                        <div>
                            <label for="date">"Date"</label>
                            <input id="date" name="date" type="date">
                        </div>
                    </div>
                    <label for="notes">"Release notes (TAG: text)"</label>
                    <textarea id="notes" name="notes" style="min-height: 120px;" placeholder="FIX: …\nFEAT: …"></textarea>
                    <div class="vb-drop" style="margin-top: 18px;">
                        <span style="font-size: 22px; color: var(--accent);">"⇪"</span>
                        <span>"Binary upload stub"</span>
                        <span class="vb-mono" style="font-size: 10.5px; color: #9aa0a6;">
                            "SHA-256 computed server-side in a later slice"
                        </span>
                    </div>
                    <div style="display: flex; gap: 12px; margin-top: 18px;">
                        <button class="vb-btn" type="submit">"Publish (stub)"</button>
                        <a class="vb-link" href=(back) style="margin: 0; align-self: center;">"Cancel"</a>
                    </div>
                </form>
            </div>
        </div>
    };

    layout::shell(
        cx,
        &ctx,
        &perms,
        NavSection::AdminReleases,
        "admin / releases / new",
        body,
    )
    .await
}
