//! Admin edit / publish / unpublish / delete at `/admin/releases/{release_id}`.

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{
        content::Form,
        error::{SeeOther, not_found, see_other},
        page, path_param, route,
    },
    view::view,
};

use crate::{
    auth::{capability_denied, db, require_staff, storage},
    docs_version::is_delete_confirm,
    models::{
        Organization, RELEASE_GA_ORG_ID, RELEASE_STATUS_HIDDEN, RELEASE_STATUS_PUBLISHED, Release,
    },
    perms::perms_for_user,
    storage::{delete_release_object, find_release_object},
};

#[path_param]
struct ReleaseId(str);

#[derive(Deserialize)]
struct UpdateReleaseForm {
    version: String,
    channel: String,
    #[serde(default)]
    date: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    organization_id: String,
}

#[derive(Deserialize)]
struct DeleteReleaseForm {
    confirm: String,
}

async fn load_release_by_id(cx: &Cx, id: u64) -> Option<Release> {
    let mut database = db(cx);
    Release::all()
        .filter(Release::fields().id().eq(id))
        .exec(&mut database)
        .await
        .ok()
        .and_then(|mut rows| rows.pop())
}

fn parse_release_id(raw: &str) -> Option<u64> {
    raw.parse::<u64>().ok()
}

async fn require_releases_manage(cx: &Cx) -> Result<()> {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.releases_manage {
        return Err(capability_denied().into());
    }
    Ok(())
}

#[page]
async fn admin_releases_edit_page(cx: &Cx) -> Result {
    let raw = path_param::<ReleaseId>(cx);
    require_releases_manage(cx).await?;

    let Some(id) = parse_release_id(raw) else {
        return Err(not_found().into());
    };
    let Some(rel) = load_release_by_id(cx, id).await else {
        return Err(not_found().into());
    };

    let mut database = db(cx);
    let orgs = Organization::all()
        .filter(
            Organization::fields()
                .slug()
                .ne(crate::models::RESERVED_ORG_SLUG.to_owned()),
        )
        .order_by(Organization::fields().name().asc())
        .exec(&mut database)
        .await
        .unwrap_or_default();

    let action = format!("/admin/releases/{id}");
    let org_id = rel.organization_id;
    let ga_selected = org_id == RELEASE_GA_ORG_ID;
    // Precompute outside view!: avoid string selected="" on every option (browser
    // keeps the last marked channel) and make comparisons borrow-stable.
    let channel_lts = rel.channel == "LTS";
    let channel_stable = rel.channel == "Stable";
    let channel_eol = rel.channel == "EOL";

    view! {
        <div>
            <a
                class="vb-back"
                href="/admin/releases"
                style="margin-bottom: 16px; margin-top: 0;"
            >
                "Release manager"
            </a>
            <h1 class="vb-title">"Edit release"</h1>
            <p class="vb-lead">
                "Update channel metadata and notes. Binary upload ships later."
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
                                value=(rel.version.clone())
                            >
                        </div>
                        <div>
                            <label for="channel">"Channel"</label>
                            <select id="channel" name="channel">
                                <option value="LTS" selected=(channel_lts)>"LTS"</option>
                                <option value="Stable" selected=(channel_stable)>
                                    "Stable"
                                </option>
                                <option value="EOL" selected=(channel_eol)>"EOL"</option>
                            </select>
                        </div>
                        <div>
                            <label for="date">"Date"</label>
                            <input
                                id="date"
                                name="date"
                                type="date"
                                value=(rel.released_on.clone())
                            >
                        </div>
                    </div>
                    <label for="organization_id">"Target organization"</label>
                    <select id="organization_id" name="organization_id">
                        <option value="" selected=(ga_selected)>
                            "Generally available (all orgs)"
                        </option>
                        for org in orgs {
                            let value = org.id.to_string();
                            let label = format!("{} ({})", org.name, org.slug);
                            // Boolean attrs only: string "" still emits selected="" and
                            // the browser keeps the *last* marked option (wrong org).
                            <option value=(value) selected=(org.id == org_id)>
                                (label)
                            </option>
                        }
                    </select>
                    <p class="vb-form-hint">
                        "Leave empty for a GA build visible to every organization. Pick an org for a private hotfix."
                    </p>
                    <label for="notes">"Release notes (TAG: text)"</label>
                    <textarea id="notes" name="notes" style="min-height: 120px;">
                        (rel.notes.clone())
                    </textarea>
                    <div style="display: flex; gap: 12px; margin-top: 18px;">
                        <button class="vb-btn" type="submit">"Save"</button>
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

#[route(POST "/admin/releases/{release_id}")]
async fn admin_releases_update(cx: &Cx, Form(form): Form<UpdateReleaseForm>) -> Result<SeeOther> {
    let raw = path_param::<ReleaseId>(cx);
    require_releases_manage(cx).await?;

    let Some(id) = parse_release_id(raw) else {
        return Err(not_found().into());
    };
    let Some(mut rel) = load_release_by_id(cx, id).await else {
        return Err(not_found().into());
    };

    let version = form.version.trim().to_owned();
    if version.is_empty() {
        return Ok(see_other(&format!("/admin/releases/{id}")));
    }
    let channel = form.channel.trim().to_owned();
    let released_on = {
        let d = form.date.trim();
        if d.is_empty() {
            rel.released_on.clone()
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

    let sort = crate::release_pkg::version_sort_fields(&version);
    let mut database = db(cx);
    let _ = rel
        .update()
        .version(version)
        .channel(channel)
        .released_on(released_on)
        .notes(notes)
        .organization_id(organization_id)
        .v_major(sort.v_major)
        .v_minor(sort.v_minor)
        .v_patch(sort.v_patch)
        .has_client_suffix(sort.has_client_suffix)
        .client_suffix(sort.client_suffix)
        .exec(&mut database)
        .await;

    Ok(see_other("/admin/releases"))
}

#[route(POST "/admin/releases/{release_id}/publish")]
async fn admin_releases_publish(cx: &Cx) -> Result<SeeOther> {
    let raw = path_param::<ReleaseId>(cx);
    require_releases_manage(cx).await?;

    let Some(id) = parse_release_id(raw) else {
        return Err(not_found().into());
    };
    let Some(mut rel) = load_release_by_id(cx, id).await else {
        return Err(not_found().into());
    };

    let mut database = db(cx);
    if find_release_object(&mut database, id).await.is_none() {
        // No storage row: refuse publish (capability-safe — no chatty error).
        return Ok(see_other("/admin/releases"));
    }

    let _ = rel
        .update()
        .status(RELEASE_STATUS_PUBLISHED.to_owned())
        .exec(&mut database)
        .await;

    Ok(see_other("/admin/releases"))
}

#[route(POST "/admin/releases/{release_id}/unpublish")]
async fn admin_releases_unpublish(cx: &Cx) -> Result<SeeOther> {
    set_release_status(cx, RELEASE_STATUS_HIDDEN).await
}

#[route(POST "/admin/releases/{release_id}/delete")]
async fn admin_releases_delete(cx: &Cx, Form(form): Form<DeleteReleaseForm>) -> Result<SeeOther> {
    let raw = path_param::<ReleaseId>(cx);
    require_releases_manage(cx).await?;

    let Some(id) = parse_release_id(raw) else {
        return Err(not_found().into());
    };
    let Some(rel) = load_release_by_id(cx, id).await else {
        return Err(not_found().into());
    };

    if !is_delete_confirm(&form.confirm) {
        return Ok(see_other(&format!(
            "/admin/releases?delete={id}&err=confirm"
        )));
    }

    let store = storage(cx);
    let _ = store.delete_release(id);

    let mut database = db(cx);
    let _ = delete_release_object(&mut database, id).await;
    let _ = rel.delete().exec(&mut database).await;

    Ok(see_other("/admin/releases"))
}

async fn set_release_status(cx: &Cx, status: &str) -> Result<SeeOther> {
    let raw = path_param::<ReleaseId>(cx);
    require_releases_manage(cx).await?;

    let Some(id) = parse_release_id(raw) else {
        return Err(not_found().into());
    };
    let Some(mut rel) = load_release_by_id(cx, id).await else {
        return Err(not_found().into());
    };

    let mut database = db(cx);
    let _ = rel
        .update()
        .status(status.to_owned())
        .exec(&mut database)
        .await;

    Ok(see_other("/admin/releases"))
}
