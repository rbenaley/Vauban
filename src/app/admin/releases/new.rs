//! Admin publish release at `/admin/releases/new`.

use std::io::Cursor;

use topcoat::{
    Result,
    context::Cx,
    router::{
        Body, Response, StatusCode,
        content::multipart::Multipart,
        error::{SeeOther, see_other},
        header, page, query_params, route,
    },
    runtime::Event,
    view::view,
};

use super::staging::{STAGING_TTL_SECS, rollback_staged_release, sweep_staged_releases};
use crate::{
    auth::{capability_denied, db, require_staff, storage},
    freebsd_pkg,
    models::{
        Organization, RELEASE_GA_ORG_ID, RELEASE_STATUS_PUBLISHED, RELEASE_STATUS_STAGING, Release,
    },
    perms::perms_for_user,
    storage::{StorageClient, upsert_release_object, write_and_hash},
};

/// Stable JSON body when validate-pkg rejects a non-FreeBSD upload.
const NOT_PKG_JSON: &str = r#"{"ok":false,"code":"not_pkg"}"#;

#[query_params]
struct NewReleaseQuery {
    err: Option<String>,
}

/// Compose-page banner for a create that was rolled back or refused.
///
/// `not_pkg` is raised as a Concept confirm modal instead (same pattern as
/// the Builds download-unavailable dialog).
fn create_error_message(err: Option<&str>) -> Option<&'static str> {
    match err? {
        "identity" => Some(
            "The package manifeste has no usable Version. Publish was refused — use a real \
             Vauban .pkg.",
        ),
        "package" => Some("A package is required: a release is never created without its binary."),
        "not_pkg" => None,
        "upload" => Some(
            "Upload was not completed, so nothing was published. The release was rolled back \
             — try again.",
        ),
        _ => None,
    }
}

fn is_not_pkg_error(err: Option<&str>) -> bool {
    err == Some("not_pkg")
}

fn not_pkg_response() -> Result<Response> {
    Ok(Response::builder()
        .status(StatusCode::UNPROCESSABLE_ENTITY)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(NOT_PKG_JSON))?)
}

#[page]
async fn admin_releases_new_page(cx: &Cx) -> Result {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.releases_manage {
        return Err(capability_denied().into());
    }

    let q = query_params::<NewReleaseQuery>(cx).ok();
    let err_code = q.as_ref().and_then(|q| q.err.as_deref());
    let create_err = create_error_message(err_code);
    let show_not_pkg = is_not_pkg_error(err_code);

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

    let not_pkg_init = show_not_pkg;

    view! {
        cx =>
        signal not_pkg_open = not_pkg_init;

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
                "Notes, target org, and the signed FreeBSD package. Version and channel (LTS or Stable) are read from the package manifeste. Publishing is all-or-nothing: an interrupted signature publishes nothing."
            </p>
            if let Some(message) = create_err {
                <p style="color: #b5403a; margin-bottom: 14px;">(message)</p>
            }
            <button
                type="button"
                id="vcp-not-pkg-open"
                style="display: none"
                @click=$(|_e| not_pkg_open.set(true))
            ></button>
            <div
                class="vb-confirm-root"
                role="dialog"
                aria-modal="true"
                aria-label="Not a FreeBSD package"
                :style=$(if not_pkg_open.get() { "" } else { "display: none" })
            >
                <div class="vb-confirm">
                    <h2>"Not a FreeBSD package"</h2>
                    <p>
                        "The uploaded file is not a FreeBSD package. Publish was refused and nothing was created."
                        <br />
                        "Choose a real .pkg produced by pkg create, then try again."
                    </p>
                    <div class="vb-confirm-actions">
                        <a
                            class="vb-btn muted compact"
                            href="/admin/releases/new"
                            @click=$(|e: Event| {
                                e.prevent_default();
                                not_pkg_open.set(false);
                            })
                        >
                            "Close"
                        </a>
                    </div>
                </div>
            </div>
            <div class="vb-panel" style="padding: 24px;">
                <form
                    id="vcp-release-create"
                    class="vb-form"
                    method="POST"
                    action="/admin/releases/new"
                    enctype="multipart/form-data"
                    @submit="(async (e) => { e.prevent_default(); const form = e.current_target.inner; const input = form.querySelector('#package'); const file = input && input.files && input.files[0]; if (!file) { form.reportValidity(); return; } const fd = new FormData(); fd.append('package', file, file.name || 'upload.pkg'); const res = await fetch('/admin/releases/new/validate-pkg', { method: 'POST', body: fd, credentials: 'same-origin' }); if (res.status === 204) { HTMLFormElement.prototype.submit.call(form); return; } input.value = ''; const bridge = document.getElementById('vcp-not-pkg-open'); if (bridge) { bridge.click(); } })"
                >
                    <div
                        style="display: flex; flex-wrap: wrap; gap: 16px; align-items: flex-end;"
                    >
                        <div style="width: 11rem;">
                            <label for="date">"Date"</label>
                            <input
                                id="date"
                                name="date"
                                type="date"
                                style="width: 11rem;"
                            >
                        </div>
                        <div style="width: 20rem; max-width: 100%;">
                            <label for="organization_id">"Target organization"</label>
                            <select
                                id="organization_id"
                                name="organization_id"
                                style="width: 20rem; max-width: 100%;"
                            >
                                <option value="">"Generally available (all orgs)"</option>
                                for org in orgs {
                                    let value = org.id.to_string();
                                    let label = format!("{} ({})", org.name, org.slug);
                                    <option value=(value)>(label)</option>
                                }
                            </select>
                        </div>
                    </div>
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
                    <input id="package" name="package" type="file" required="">
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
    date: String,
    notes: String,
    organization_id: String,
    package: Option<Vec<u8>>,
}

/// Read the `package` field from a multipart body (ignore other parts).
async fn parse_package_only(mut multipart: Multipart) -> Result<Option<Vec<u8>>> {
    let mut package: Option<Vec<u8>> = None;
    while let Some(field) = multipart.next_field().await? {
        match field.name() {
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
    Ok(package)
}

async fn parse_create_multipart(mut multipart: Multipart) -> Result<CreateReleaseFields> {
    let mut date = String::new();
    let mut notes = String::new();
    let mut organization_id = String::new();
    let mut package: Option<Vec<u8>> = None;

    while let Some(field) = multipart.next_field().await? {
        match field.name() {
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
        date,
        notes,
        organization_id,
        package,
    })
}

/// Preflight: is this upload a FreeBSD package? Never stages or opens helper I/O.
#[route(POST "/admin/releases/new/validate-pkg")]
async fn admin_releases_validate_pkg(cx: &Cx, multipart: Multipart) -> Result<Response> {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.releases_manage {
        return Err(capability_denied().into());
    }

    let Some(package) = parse_package_only(multipart).await? else {
        return not_pkg_response();
    };
    if freebsd_pkg::inspect(&package).is_err() {
        return not_pkg_response();
    }

    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::from(""))?)
}

#[route(POST "/admin/releases/new")]
async fn admin_releases_create(cx: &Cx, multipart: Multipart) -> Result<SeeOther> {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.releases_manage {
        return Err(capability_denied().into());
    }

    let form = parse_create_multipart(multipart).await?;

    // A release without its binary is never worth a row: refuse before any
    // write so the compose form stays the only place to retry.
    let Some(package) = form.package else {
        return Ok(see_other("/admin/releases/new?err=package"));
    };
    // Fail closed before STAGING / put_begin: only a real FreeBSD package may
    // open an upload ceremony.
    let pkg_info = match freebsd_pkg::inspect(&package) {
        Ok(info) => info,
        Err(_) => return Ok(see_other("/admin/releases/new?err=not_pkg")),
    };
    // Version + LTS/Stable come from the manifeste — never from form fields.
    let Some(identity) = crate::release_pkg::derive_release_identity(&pkg_info.version) else {
        return Ok(see_other("/admin/releases/new?err=identity"));
    };
    let version = identity.version;
    let channel = identity.channel.to_owned();
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

    sweep_staged_releases(cx).await;

    let store = storage(cx);
    let create_guard = store.begin_staging_create();

    let sort = crate::release_pkg::version_sort_fields(&version);
    let mut database = db(cx);
    let Ok(mut created) = toasty::create!(Release {
        version,
        channel,
        released_on,
        status: RELEASE_STATUS_STAGING.to_owned(),
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
        return Ok(see_other("/admin/releases/new?err=upload"));
    };

    // From here the row is staged: every failure path below must roll it back.
    store.mark_staged_release(
        created.id,
        StorageClient::ceremony_ttl_unix(STAGING_TTL_SECS),
    );
    drop(create_guard);

    let Ok((upload_id, mut file)) = store.put_begin_release(created.id, package.len() as u64)
    else {
        rollback_staged_release(cx, created.id, None, false).await;
        return Ok(see_other("/admin/releases/new?err=upload"));
    };
    let Ok((_written, sha)) = write_and_hash(&mut file, Cursor::new(package.as_slice())) else {
        rollback_staged_release(cx, created.id, Some(&upload_id), false).await;
        return Ok(see_other("/admin/releases/new?err=upload"));
    };

    if store.webauthn_required() {
        let Ok(prep) = store.put_prepare_release(&upload_id, created.id, &sha) else {
            rollback_staged_release(cx, created.id, Some(&upload_id), false).await;
            return Ok(see_other("/admin/releases/new?err=upload"));
        };
        let token = store.stash_pending_release(crate::storage::PendingReleaseCeremony {
            upload_id,
            release_id: created.id,
            sha256: sha,
            summary: prep.summary,
            challenge_id: prep.challenge_id,
            challenge: prep.challenge,
            rp_id: prep.rp_id,
            allow_credentials: prep.allow_credentials,
            expires_at: StorageClient::ceremony_ttl_unix(STAGING_TTL_SECS),
            pkg_info,
        });
        return Ok(see_other(&format!("/admin/releases/confirm?token={token}")));
    }

    let Ok((size_bytes, sha256)) = store.put_commit_release(&upload_id, created.id, &sha) else {
        rollback_staged_release(cx, created.id, Some(&upload_id), false).await;
        return Ok(see_other("/admin/releases/new?err=upload"));
    };
    if upsert_release_object(&mut database, created.id, &sha256, size_bytes)
        .await
        .is_err()
    {
        rollback_staged_release(cx, created.id, None, true).await;
        return Ok(see_other("/admin/releases/new?err=upload"));
    }
    if created
        .update()
        .status(RELEASE_STATUS_PUBLISHED.to_owned())
        .exec(&mut database)
        .await
        .is_err()
    {
        rollback_staged_release(cx, created.id, None, true).await;
        return Ok(see_other("/admin/releases/new?err=upload"));
    }
    store.unmark_staged_release(created.id);

    Ok(see_other("/admin/releases"))
}

#[cfg(test)]
mod tests {
    use super::{NOT_PKG_JSON, is_not_pkg_error};

    #[test]
    fn not_pkg_json_is_stable() {
        assert!(NOT_PKG_JSON.contains(r#""code":"not_pkg""#));
        assert!(NOT_PKG_JSON.contains(r#""ok":false"#));
    }

    #[test]
    fn validate_submit_source_pins_preflight() {
        let src = include_str!("new.rs");
        assert!(src.contains("validate-pkg"));
        assert!(src.contains("@submit=\"(async (e)"));
        assert!(src.contains("FormData"));
        assert!(src.contains("HTMLFormElement.prototype.submit"));
        assert!(src.contains("vcp-not-pkg-open"));
        assert!(src.contains("id=\"vcp-release-create\""));
    }

    #[test]
    fn not_pkg_error_code_detection() {
        assert!(is_not_pkg_error(Some("not_pkg")));
        assert!(!is_not_pkg_error(Some("package")));
        assert!(!is_not_pkg_error(None));
    }
}
