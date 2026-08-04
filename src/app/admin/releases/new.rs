//! Admin publish release at `/admin/releases/new`.

use std::io::Cursor;

use topcoat::{
    Result,
    context::Cx,
    router::{
        content::multipart::Multipart,
        error::{SeeOther, see_other},
        page, route,
    },
    view::view,
};

use crate::{
    auth::{capability_denied, db, require_staff, storage},
    models::{
        Organization, RELEASE_GA_ORG_ID, RELEASE_STATUS_HIDDEN, RELEASE_STATUS_PUBLISHED, Release,
    },
    perms::perms_for_user,
    storage::{upsert_release_object, write_and_hash},
};

#[page]
async fn admin_releases_new_page(cx: &Cx) -> Result {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.releases_manage {
        return Err(capability_denied().into());
    }

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

    view! {
        <div>
            <a
                class="vb-back"
                href="/admin/releases"
                style="margin-bottom: 16px; margin-top: 0;"
            >
                "Release manager"
            </a>
            <h1 class="vb-title">"Publish release"</h1>
            <p class="vb-lead">
                "Channel metadata, notes, and optional package upload. Releases without a package stay hidden."
            </p>
            <div class="vb-panel" style="padding: 24px;">
                <form
                    class="vb-form"
                    method="POST"
                    action="/admin/releases/new"
                    enctype="multipart/form-data"
                >
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
                    <label for="package" style="margin-top: 18px;">
                        "Package (.pkg)"
                    </label>
                    <input id="package" name="package" type="file">
                    <p class="vb-form-hint">
                        "Optional. When provided, the binary is stored and the release is published. SHA-256 is computed server-side."
                    </p>
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

struct CreateReleaseFields {
    version: String,
    channel: String,
    date: String,
    notes: String,
    organization_id: String,
    package: Option<Vec<u8>>,
}

async fn parse_create_multipart(mut multipart: Multipart) -> Result<CreateReleaseFields> {
    let mut version = String::new();
    let mut channel = String::new();
    let mut date = String::new();
    let mut notes = String::new();
    let mut organization_id = String::new();
    let mut package: Option<Vec<u8>> = None;

    while let Some(field) = multipart.next_field().await? {
        match field.name() {
            Some("version") => version = field.text().await?,
            Some("channel") => channel = field.text().await?,
            Some("date") => date = field.text().await?,
            Some("notes") => notes = field.text().await?,
            Some("organization_id") => organization_id = field.text().await?,
            Some("package") => {
                let data = field.bytes().await?;
                if !data.is_empty() {
                    package = Some(data.to_vec());
                }
            }
            _ => {
                let _ = field.bytes().await?;
            }
        }
    }

    Ok(CreateReleaseFields {
        version,
        channel,
        date,
        notes,
        organization_id,
        package,
    })
}

#[route(POST "/admin/releases/new")]
async fn admin_releases_create(cx: &Cx, multipart: Multipart) -> Result<SeeOther> {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.releases_manage {
        return Err(capability_denied().into());
    }

    let form = parse_create_multipart(multipart).await?;

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

    let sort = crate::release_pkg::version_sort_fields(&version);
    let mut database = db(cx);
    let Ok(mut created) = toasty::create!(Release {
        version,
        channel,
        released_on,
        status: RELEASE_STATUS_HIDDEN.to_owned(),
        notes,
        organization_id,
        v_major: sort.v_major,
        v_minor: sort.v_minor,
        v_patch: sort.v_patch,
        has_client_suffix: sort.has_client_suffix,
        client_suffix: sort.client_suffix,
    })
    .exec(&mut database)
    .await
    else {
        return Ok(see_other("/admin/releases"));
    };

    if let Some(package) = form.package {
        let store = storage(cx);
        if let Ok((upload_id, mut file)) = store.put_begin_release(created.id, package.len() as u64)
        {
            match write_and_hash(&mut file, Cursor::new(package.as_slice())) {
                Ok((_written, sha)) if store.webauthn_required() => {
                    match store.put_prepare_release(&upload_id, created.id, &sha) {
                        Ok(prep) => {
                            let token = store.stash_pending_release(
                                crate::storage::PendingReleaseCeremony {
                                    upload_id,
                                    release_id: created.id,
                                    sha256: sha,
                                    summary: prep.summary,
                                    challenge_id: prep.challenge_id,
                                    challenge: prep.challenge,
                                    rp_id: prep.rp_id,
                                    allow_credentials: prep.allow_credentials,
                                    expires_at: crate::storage::StorageClient::ceremony_ttl_unix(
                                        300,
                                    ),
                                },
                            );
                            return Ok(see_other(&format!(
                                "/admin/releases/confirm?token={token}"
                            )));
                        }
                        Err(_) => {
                            let _ = store.put_abort(&upload_id);
                        }
                    }
                }
                Ok((_written, sha)) => {
                    if let Ok((size_bytes, sha256)) =
                        store.put_commit_release(&upload_id, created.id, &sha)
                        && upsert_release_object(&mut database, created.id, &sha256, size_bytes)
                            .await
                            .is_ok()
                    {
                        let _ = created
                            .update()
                            .status(RELEASE_STATUS_PUBLISHED.to_owned())
                            .exec(&mut database)
                            .await;
                    }
                }
                Err(_) => {
                    let _ = store.put_abort(&upload_id);
                }
            }
        }
    }

    Ok(see_other("/admin/releases"))
}
