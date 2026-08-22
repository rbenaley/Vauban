//! Admin publish release at `/admin/releases/new`.

use std::io::Cursor;

use topcoat::{
    Result,
    context::Cx,
    router::{
        Body, StatusCode,
        content::multipart::Multipart,
        error::{SeeOther, see_other},
        header, href, page, query_params,
        response::Response,
        route,
    },
    runtime::{Event, procedure},
    view::view,
};

use super::staging::{STAGING_TTL_SECS, rollback_staged_release, sweep_staged_releases};
use crate::app::admin::releases::admin_releases_page;
use crate::app::hrefs::ErrQ;
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

/// `require_active_key` procedure: ACTIVE key present / WebAuthn not required.
const REQUIRE_KEY_OK: f64 = 1.0;
/// `require_active_key` procedure: WebAuthn required and vcp-store has no ACTIVE key.
const REQUIRE_KEY_MISSING: f64 = 0.0;

#[query_params]
struct NewReleaseQuery {
    err: Option<String>,
}

/// Compose-page banner for a create that was rolled back or refused.
///
/// `not_pkg` and `no_active_key` use Concept confirm modals instead (same
/// pattern as the Builds download-unavailable dialog).
fn create_error_message(err: Option<&str>) -> Option<&'static str> {
    match err? {
        "identity" => Some(
            "The package manifeste has no usable Version. Publish was refused — use a real \
             Vauban .pkg.",
        ),
        "date" => Some("A release date is required (YYYY-MM-DD). Publish was refused."),
        "package" => Some("A package is required: a release is never created without its binary."),
        "not_pkg" | "no_active_key" => None,
        "upload" => Some(
            "Upload was not completed, so nothing was published. The release was rolled back \
             — try again.",
        ),
        _ => None,
    }
}

/// Parse a required calendar release date (`YYYY-MM-DD`). Empty / invalid -> `None`.
fn parse_released_on(raw: &str) -> Option<String> {
    let d = raw.trim();
    if d.is_empty() {
        return None;
    }
    chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d")
        .ok()
        .map(|date| date.format("%Y-%m-%d").to_string())
}

fn is_not_pkg_error(err: Option<&str>) -> bool {
    err == Some("not_pkg")
}

fn is_no_active_key_error(err: Option<&str>) -> bool {
    err == Some("no_active_key")
}

fn not_pkg_response() -> Result<Response> {
    Ok(Response::builder()
        .status(StatusCode::UNPROCESSABLE_ENTITY)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(NOT_PKG_JSON))?)
}

/// Fail closed when WebAuthn is required and vcp-store has no ACTIVE key.
fn missing_active_key_for_publish(store: &StorageClient) -> bool {
    if !store.webauthn_required() {
        return false;
    }
    !store.has_active_key().unwrap_or(false)
}

#[page]
pub(crate) async fn admin_releases_new_page(cx: &Cx) -> Result {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.releases_manage {
        return Err(capability_denied().into());
    }

    let q = query_params::<NewReleaseQuery>(cx).ok();
    let err_code = q.as_ref().and_then(|q| q.err.as_deref());
    let create_err = create_error_message(err_code);
    let show_not_pkg = is_not_pkg_error(err_code);
    let show_no_key = is_no_active_key_error(err_code);

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
    let no_key_init = show_no_key;
    let validate_href = href!(admin_releases_validate_pkg).resolve(cx);

    view! {
        cx =>
        signal not_pkg_open = not_pkg_init;
        signal no_key_open = no_key_init;
        signal pkg_go = false;

        <div>
            <a
                class="vb-back"
                href=(href!(admin_releases_page))
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
                id="vcp-pkg-tick"
                aria-hidden="true"
                :style=$(if pkg_go.get() {
                    "position:absolute;width:1px;height:1px;opacity:0;pointer-events:none;animation:vb-pkg-kick 80ms linear 1 forwards"
                } else {
                    "position:absolute;width:1px;height:1px;opacity:0;pointer-events:none"
                })
                @animationend="(async (_e) => { const form = document.getElementById('vcp-release-create'); if (!form || !form.reportValidity()) { return; } const input = form.querySelector('#package'); const file = input && input.files && input.files[0]; if (!file) { return; } const fd = new FormData(); fd.append('package', file, file.name || 'upload.pkg'); const url = form.getAttribute('data-validate-pkg'); const res = await fetch(url, { method: 'POST', body: fd, credentials: 'same-origin' }); if (res.status === 204) { HTMLFormElement.prototype.submit.call(form); return; } input.value = ''; const bridge = document.getElementById('vcp-not-pkg-open'); if (bridge) { bridge.click(); } })"
            ></div>
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
                            href=(href!(admin_releases_new_page))
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
            <div
                class="vb-confirm-root"
                role="dialog"
                aria-modal="true"
                aria-label="No active security key"
                :style=$(if no_key_open.get() { "" } else { "display: none" })
            >
                <div class="vb-confirm">
                    <h2>"No active security key"</h2>
                    <p>
                        "Publishing a release requires at least one active security key in vcp-store. WebAuthn was not started and nothing was created."
                        <br />
                        "Enrol a key under Admin -> Security keys, approve it with "
                        <code>"vcp-store approve-key"</code>
                        ", then try again."
                    </p>
                    <div class="vb-confirm-actions">
                        <a
                            class="vb-btn muted compact"
                            href=(href!(admin_releases_new_page))
                            @click=$(|e: Event| {
                                e.prevent_default();
                                no_key_open.set(false);
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
                    action=(href!(admin_releases_create))
                    enctype="multipart/form-data"
                    data-validate-pkg=(validate_href.clone())
                    @submit=$(async |e: Event| {
                        e.prevent_default();
                        pkg_go.set(false);
                        if require_active_key().await < 1.0 {
                            no_key_open.set(true);
                        } else {
                            pkg_go.set(true);
                        }
                    })
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
                                required=""
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
                            href=(href!(admin_releases_page))
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
pub(crate) async fn admin_releases_validate_pkg(cx: &Cx, multipart: Multipart) -> Result<Response> {
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

/// Preflight: when WebAuthn is required, vcp-store must have ≥1 ACTIVE key.
///
/// Runs on Publish click before validate-pkg / WebAuthn so the browser never
/// opens a passkey prompt against an empty allowCredentials list.
#[procedure]
async fn require_active_key(cx: &Cx) -> Result<f64> {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.releases_manage {
        return Err(capability_denied().into());
    }

    let store = storage(cx);
    if missing_active_key_for_publish(store.as_ref()) {
        return Ok(REQUIRE_KEY_MISSING);
    }
    Ok(REQUIRE_KEY_OK)
}

#[route(POST "/admin/releases/new")]
pub(crate) async fn admin_releases_create(cx: &Cx, multipart: Multipart) -> Result<SeeOther> {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.releases_manage {
        return Err(capability_denied().into());
    }

    let store = storage(cx);
    if missing_active_key_for_publish(store.as_ref()) {
        return Ok(see_other(
            href!(admin_releases_new_page)
                .query(ErrQ {
                    err: Some("no_active_key"),
                })
                .resolve(cx),
        ));
    }

    let form = parse_create_multipart(multipart).await?;

    // Date is mandatory — never invent a default (no Unix-epoch placeholder).
    let Some(released_on) = parse_released_on(&form.date) else {
        return Ok(see_other(
            href!(admin_releases_new_page)
                .query(ErrQ { err: Some("date") })
                .resolve(cx),
        ));
    };
    // A release without its binary is never worth a row: refuse before any
    // write so the compose form stays the only place to retry.
    let Some(package) = form.package else {
        return Ok(see_other(
            href!(admin_releases_new_page)
                .query(ErrQ {
                    err: Some("package"),
                })
                .resolve(cx),
        ));
    };
    // Fail closed before STAGING / put_begin: only a real FreeBSD package may
    // open an upload ceremony.
    let pkg_info = match freebsd_pkg::inspect(&package) {
        Ok(info) => info,
        Err(_) => {
            return Ok(see_other(
                href!(admin_releases_new_page)
                    .query(ErrQ {
                        err: Some("not_pkg"),
                    })
                    .resolve(cx),
            ));
        }
    };
    // Version + LTS/Stable come from the manifeste — never from form fields.
    let Some(identity) = crate::release_pkg::derive_release_identity(&pkg_info.version) else {
        return Ok(see_other(
            href!(admin_releases_new_page)
                .query(ErrQ {
                    err: Some("identity"),
                })
                .resolve(cx),
        ));
    };
    let version = identity.version;
    let channel = identity.channel.to_owned();
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

    let create_guard = store.begin_staging_create();

    let (sort, track) = crate::release_pkg::release_write_keys(&version, &channel);
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
        is_industrial: sort.is_industrial,
        has_client_suffix: sort.has_client_suffix,
        client_suffix: sort.client_suffix,
        product_track: track.to_owned(),
    })
    .exec(&mut database)
    .await
    else {
        return Ok(see_other(
            href!(admin_releases_new_page)
                .query(ErrQ {
                    err: Some("upload"),
                })
                .resolve(cx),
        ));
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
        return Ok(see_other(
            href!(admin_releases_new_page)
                .query(ErrQ {
                    err: Some("upload"),
                })
                .resolve(cx),
        ));
    };
    let Ok((_written, sha)) = write_and_hash(&mut file, Cursor::new(package.as_slice())) else {
        rollback_staged_release(cx, created.id, Some(&upload_id), false).await;
        return Ok(see_other(
            href!(admin_releases_new_page)
                .query(ErrQ {
                    err: Some("upload"),
                })
                .resolve(cx),
        ));
    };

    if store.webauthn_required() {
        let Ok(prep) = store.put_prepare_release(&upload_id, created.id, &sha) else {
            rollback_staged_release(cx, created.id, Some(&upload_id), false).await;
            return Ok(see_other(
                href!(admin_releases_new_page)
                    .query(ErrQ {
                        err: Some("upload"),
                    })
                    .resolve(cx),
            ));
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
        return Ok(see_other(
            href!(crate::app::admin::releases::confirm::admin_releases_confirm_page)
                .query(crate::app::hrefs::TokenQ { token: &token })
                .resolve(cx),
        ));
    }

    let Ok((size_bytes, sha256)) = store.put_commit_release(&upload_id, created.id, &sha) else {
        rollback_staged_release(cx, created.id, Some(&upload_id), false).await;
        return Ok(see_other(
            href!(admin_releases_new_page)
                .query(ErrQ {
                    err: Some("upload"),
                })
                .resolve(cx),
        ));
    };
    if upsert_release_object(&mut database, created.id, &sha256, size_bytes)
        .await
        .is_err()
    {
        rollback_staged_release(cx, created.id, None, true).await;
        return Ok(see_other(
            href!(admin_releases_new_page)
                .query(ErrQ {
                    err: Some("upload"),
                })
                .resolve(cx),
        ));
    }
    if created
        .update()
        .status(RELEASE_STATUS_PUBLISHED.to_owned())
        .exec(&mut database)
        .await
        .is_err()
    {
        rollback_staged_release(cx, created.id, None, true).await;
        return Ok(see_other(
            href!(admin_releases_new_page)
                .query(ErrQ {
                    err: Some("upload"),
                })
                .resolve(cx),
        ));
    }
    store.unmark_staged_release(created.id);

    Ok(see_other(href!(admin_releases_page).resolve(cx)))
}

#[cfg(test)]
mod tests {
    use super::{
        NOT_PKG_JSON, create_error_message, is_no_active_key_error, is_not_pkg_error,
        parse_released_on,
    };
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn not_pkg_json_is_stable() {
        assert!(NOT_PKG_JSON.contains(r#""code":"not_pkg""#));
        assert!(NOT_PKG_JSON.contains(r#""ok":false"#));
    }

    #[test]
    fn validate_submit_source_pins_preflight() {
        let src = include_str!("new.rs");
        assert!(src.contains("validate-pkg"));
        assert!(src.contains("#[procedure]"));
        assert!(src.contains("fn require_active_key"));
        assert!(src.contains("@submit=$("));
        assert!(src.contains("require_active_key().await"));
        assert!(src.contains("no_key_open.set(true)"));
        assert!(src.contains("form.reportValidity()"));
        assert!(src.contains("FormData"));
        assert!(src.contains("HTMLFormElement.prototype.submit"));
        assert!(src.contains("data-validate-pkg"));
        // One-shot CSS (`linear 1`) never fires animationiteration — only
        // animationend. A dead tick looks like "Publish does nothing".
        assert!(src.contains("@animationend"));
        assert!(src.contains("vb-pkg-kick"));
        assert!(src.contains("id=\"vcp-pkg-tick\""));
        let view = src.split_once("#[cfg(test)]").expect("tests").0;
        assert!(
            !view.contains("@animationiteration"),
            "validate-pkg must not sit on a one-shot animationiteration"
        );
        assert!(
            !view.contains("0.01s"),
            "sub-frame one-shot animations are skipped; use vb-pkg-kick (~80ms + opacity)"
        );
        let submit = src.split_once("@submit=$(").expect("submit").1;
        assert!(
            submit.contains("else"),
            "$() early return after await is compiled into a nested IIFE; pkg_go must be in else"
        );
        assert!(src.contains("vcp-not-pkg-open"));
        assert!(src.contains("signal no_key_open"));
        assert!(!src.contains("GET \"/admin/releases/new/require-active-key\""));
        assert!(src.contains("id=\"vcp-release-create\""));
        assert!(src.contains("name=\"date\""));
        assert!(src.contains("type=\"date\""));
        assert!(src.contains("required=\"\""));
        assert!(!src.contains("\"1970-01-01\".to_owned()"));
        let submit = src.split_once("@submit=$(").expect("submit").1;
        let key_at = submit.find("require_active_key").expect("key preflight");
        let pkg_go_at = submit.find("pkg_go.set(true)").expect("pkg preflight kick");
        assert!(key_at < pkg_go_at);
    }

    #[test]
    fn not_pkg_error_code_detection() {
        assert!(is_not_pkg_error(Some("not_pkg")));
        assert!(!is_not_pkg_error(Some("package")));
        assert!(!is_not_pkg_error(None));
    }

    #[test]
    fn no_active_key_error_code_detection() {
        assert!(is_no_active_key_error(Some("no_active_key")));
        assert!(!is_no_active_key_error(Some("not_pkg")));
        assert!(create_error_message(Some("no_active_key")).is_none());
    }

    #[test]
    fn parse_released_on_requires_calendar_date() {
        assert_eq!(
            parse_released_on("2026-07-01"),
            Some("2026-07-01".to_owned())
        );
        assert_eq!(
            parse_released_on(" 2026-07-01\n"),
            Some("2026-07-01".to_owned())
        );
        assert_eq!(parse_released_on(""), None);
        assert_eq!(parse_released_on("   "), None);
        assert_eq!(parse_released_on("07/01/2026"), None);
        assert_eq!(parse_released_on("2026-13-01"), None);
        assert_eq!(parse_released_on("not-a-date"), None);
    }

    #[test]
    fn create_error_message_covers_missing_date() {
        assert!(
            create_error_message(Some("date"))
                .unwrap()
                .contains("date is required")
        );
    }

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(crate::proptest_util::cases(48))]
        fn parse_released_on_round_trips_valid_naive_dates(
            y in 1971i32..2100,
            m in 1u32..=12,
            d in 1u32..=28,
        ) {
            let raw = format!("{y:04}-{m:02}-{d:02}");
            let parsed = parse_released_on(&raw);
            prop_assert_eq!(parsed, Some(raw));
        }

        fn parse_released_on_rejects_non_iso(
            s in prop::sample::select(vec![
                "".to_string(),
                " ".to_string(),
                "1970-01-01T00:00:00Z".to_string(),
                "01/01/1970".to_string(),
                "2026-13-40".to_string(),
                "not-a-date".to_string(),
                "2026/07/01".to_string(),
            ]),
        ) {
            prop_assert_eq!(parse_released_on(&s), None);
        }
    }

    #[test]
    fn battle_parse_released_on_under_contention() {
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..200 {
                    assert_eq!(parse_released_on(""), None);
                    assert_eq!(
                        parse_released_on("2026-08-01"),
                        Some("2026-08-01".to_owned())
                    );
                }
            }));
        }
        for h in handles {
            h.join().expect("battle thread");
        }
    }
}
