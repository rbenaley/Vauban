//! Admin publish release at `/{org}/admin/releases/new`.

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{Form, SeeOther, forbidden, page, path_param, route, see_other},
    view::view,
};

use crate::{
    app::org::Org,
    auth::{db, require_org},
    models::Release,
    perms::perms_for_user,
};

#[derive(Deserialize)]
struct CreateReleaseForm {
    version: String,
    channel: String,
    #[serde(default)]
    date: String,
    #[serde(default)]
    notes: String,
}

#[page]
async fn admin_releases_new_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.admin_view || !perms.releases_manage {
        return Err(forbidden().into());
    }

    let back = format!("/{slug}/admin/releases");
    let action = format!("/{slug}/admin/releases/new");

    view! {
        <div style="max-width: 720px;">
            <a
                class="vb-back"
                href=(back.clone())
                style="margin-bottom: 16px; margin-top: 0;"
            >
                "Release manager"
            </a>
            <h1 class="vb-title">"Publish release"</h1>
            <p class="vb-lead">
                "Channel metadata and notes. Binary upload ships later."
            </p>
            <div class="vb-panel" style="padding: 24px;">
                <form class="vb-form" method="POST" action=(action)>
                    <div
                        style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px;"
                    >
                        <div>
                            <label for="version">"Version"</label>
                            <input
                                id="version"
                                name="version"
                                required=""
                                placeholder="v1.1.0"
                            >
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
                    <textarea
                        id="notes"
                        name="notes"
                        style="min-height: 120px;"
                        placeholder="FIX: …\nFEAT: …"
                    ></textarea>
                    <div class="vb-drop" style="margin-top: 18px;">
                        <span style="font-size: 22px; color: var(--accent);">
                            "⇪"
                        </span>
                        <span>"Binary upload stub"</span>
                        <span
                            class="vb-mono"
                            style="font-size: 10.5px; color: #9aa0a6;"
                        >
                            "SHA-256 computed server-side in a later slice"
                        </span>
                    </div>
                    <div style="display: flex; gap: 12px; margin-top: 18px;">
                        <button class="vb-btn" type="submit">"Publish"</button>
                        <a
                            class="vb-link"
                            href=(back)
                            style="margin: 0; align-self: center;"
                        >
                            "Cancel"
                        </a>
                    </div>
                </form>
            </div>
        </div>
    }
}

#[route(POST "/{org}/admin/releases/new")]
async fn admin_releases_create(cx: &Cx, Form(form): Form<CreateReleaseForm>) -> Result<SeeOther> {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await.map_err(|_| forbidden())?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.admin_view || !perms.releases_manage {
        return Err(forbidden().into());
    }

    let version = form.version.trim().to_owned();
    if version.is_empty() {
        return Ok(see_other(&format!("/{slug}/admin/releases/new")));
    }
    let channel = form.channel.trim().to_owned();
    let released_on = {
        let d = form.date.trim();
        if d.is_empty() {
            "1970-01-01".to_owned()
        } else {
            d.to_owned()
        }
    };
    let notes = form.notes.trim().to_owned();

    let mut database = db(cx);
    let _ = toasty::create!(Release {
        version,
        channel,
        released_on,
        size_mb: "0.0".to_owned(),
        signature_prefix: "pending".to_owned(),
        status: "PUBLISHED".to_owned(),
        notes,
    })
    .exec(&mut database)
    .await;

    Ok(see_other(&format!("/{slug}/admin/releases")))
}
