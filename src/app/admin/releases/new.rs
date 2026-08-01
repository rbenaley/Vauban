//! Admin publish release at `/admin/releases/new`.

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{
        content::Form,
        error::{SeeOther, see_other},
        page, route,
    },
    view::view,
};

use crate::{
    auth::{capability_denied, db, require_staff},
    models::{Organization, RELEASE_GA_ORG_ID, Release},
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
    /// Empty / missing = GA ([`RELEASE_GA_ORG_ID`]).
    #[serde(default)]
    organization_id: String,
}

#[page]
async fn admin_releases_new_page(cx: &Cx) -> Result {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.releases_manage {
        return Err(capability_denied().into());
    }

    let mut database = db(cx);
    let mut orgs = Organization::all()
        .exec(&mut database)
        .await
        .unwrap_or_default();
    orgs.sort_by(|a, b| a.name.cmp(&b.name));

    view! {
        <div style="max-width: 720px;">
            <a
                class="vb-back"
                href="/admin/releases"
                style="margin-bottom: 16px; margin-top: 0;"
            >
                "Release manager"
            </a>
            <h1 class="vb-title">"Publish release"</h1>
            <p class="vb-lead">
                "Channel metadata and notes. Binary upload ships later."
            </p>
            <div class="vb-panel" style="padding: 24px;">
                <form class="vb-form" method="POST" action="/admin/releases/new">
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
                    <label for="organization_id">"Target organization"</label>
                    <select id="organization_id" name="organization_id">
                        <option value="">"Generally available (all orgs)"</option>
                        for org in orgs {
                            let value = org.id.to_string();
                            let label = format!("{} ({})", org.name, org.slug);
                            <option value=(value)>(label)</option>
                        }
                    </select>
                    <p class="vb-form-hint">
                        "Leave empty for a GA build visible to every organization. Pick an org for a private hotfix."
                    </p>
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
                            href="/admin/releases"
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

#[route(POST "/admin/releases/new")]
async fn admin_releases_create(cx: &Cx, Form(form): Form<CreateReleaseForm>) -> Result<SeeOther> {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.releases_manage {
        return Err(capability_denied().into());
    }

    let version = form.version.trim().to_owned();
    if version.is_empty() {
        return Ok(see_other("/admin/releases/new"));
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
    let organization_id = {
        let raw = form.organization_id.trim();
        if raw.is_empty() {
            RELEASE_GA_ORG_ID
        } else {
            raw.parse::<u64>().unwrap_or(RELEASE_GA_ORG_ID)
        }
    };

    let mut database = db(cx);
    let _ = toasty::create!(Release {
        version,
        channel,
        released_on,
        size_mb: "0.0".to_owned(),
        sha256: "pending".to_owned(),
        status: "PUBLISHED".to_owned(),
        notes,
        organization_id,
    })
    .exec(&mut database)
    .await;

    Ok(see_other("/admin/releases"))
}
