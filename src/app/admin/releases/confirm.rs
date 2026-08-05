//! C1 WebAuthn confirm step after release `put_prepare`.

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{
        content::Form,
        error::{SeeOther, redirect, see_other},
        page, query_params, route,
    },
    view::view,
};

use crate::{
    app::VCP_WEBAUTHN_JS,
    auth::{capability_denied, db, require_staff, storage},
    models::{RELEASE_STATUS_PUBLISHED, Release},
    perms::perms_for_user,
    storage::upsert_release_object,
};

#[query_params]
struct ConfirmQuery {
    token: Option<String>,
}

#[page]
async fn admin_releases_confirm_page(cx: &Cx) -> Result {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.releases_manage {
        return Err(capability_denied().into());
    }
    let q = query_params::<ConfirmQuery>(cx).ok();
    let Some(token) = q
        .as_ref()
        .and_then(|q| q.token.as_deref())
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
    else {
        return Err(redirect("/admin/releases").into());
    };
    let store = storage(cx);
    let Some(pending) = store.peek_pending_release(&token) else {
        return Err(redirect("/admin/releases").into());
    };

    let summary = pending.summary.clone();
    let challenge = pending.challenge.clone();
    let rp_id = pending.rp_id.clone();
    let allow = serde_json::to_string(&pending.allow_credentials).unwrap_or_else(|_| "[]".into());
    let token_hidden = token;

    view! {
        <div>
            <a
                class="vb-back"
                href="/admin/releases"
                style="margin-bottom: 16px; margin-top: 0;"
            >
                "Release manager"
            </a>
            <h1 class="vb-title">"Confirm release publish"</h1>
            <p class="vb-lead">
                "Review the helper-issued summary, then complete WebAuthn user verification."
            </p>
            <div class="vb-panel" style="padding: 24px;">
                <p class="vb-form-hint" style="margin-bottom: 8px;">
                    "Operation summary (from vcp-store). Cross-check with "
                    <code>"vcp-store key pending"</code>
                    " on the helper host when needed:"
                </p>
                <pre
                    id="vcp-webauthn-summary"
                    style="padding: 12px; background: var(--panel-2, #f4f4f5); border-radius: 6px; font-size: 14px;"
                >
                    (summary)
                </pre>
                <div
                    id="vcp-webauthn-root"
                    data-mode="get"
                    data-challenge=(challenge)
                    data-rp-id=(rp_id)
                    data-allow=(allow)
                    style="margin-top: 18px;"
                >
                    <form
                        id="vcp-webauthn-form"
                        method="POST"
                        action="/admin/releases/confirm"
                    >
                        <input type="hidden" name="token" value=(token_hidden)>
                        <input
                            id="vcp-webauthn-assertion"
                            type="hidden"
                            name="assertion"
                            value=""
                        >
                        <button id="vcp-webauthn-btn" class="vb-btn" type="button">
                            "Authenticate and publish"
                        </button>
                    </form>
                </div>
            </div>
            <script src=(VCP_WEBAUTHN_JS) defer=""></script>
        </div>
    }
}

#[derive(Debug, Deserialize)]
struct ConfirmForm {
    token: String,
    assertion: String,
}

#[route(POST "/admin/releases/confirm")]
async fn admin_releases_confirm_post(cx: &Cx, Form(form): Form<ConfirmForm>) -> Result<SeeOther> {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.releases_manage {
        return Err(capability_denied().into());
    }
    let store = storage(cx);
    let Some(pending) = store.take_pending_release(form.token.trim()) else {
        return Ok(see_other("/admin/releases"));
    };
    if form.assertion.trim().is_empty() {
        let t = store.stash_pending_release(pending);
        return Ok(see_other(&format!("/admin/releases/confirm?token={t}")));
    }
    match store.put_commit_release_asserted(
        &pending.upload_id,
        pending.release_id,
        &pending.sha256,
        Some(form.assertion.trim()),
    ) {
        Ok((size_bytes, sha256)) => {
            let mut database = db(cx);
            if upsert_release_object(&mut database, pending.release_id, &sha256, size_bytes)
                .await
                .is_ok()
            {
                let rows = Release::all()
                    .filter(Release::fields().id().eq(pending.release_id))
                    .exec(&mut database)
                    .await
                    .unwrap_or_default();
                if let Some(mut rel) = rows.into_iter().next() {
                    let _ = rel
                        .update()
                        .status(RELEASE_STATUS_PUBLISHED.to_owned())
                        .exec(&mut database)
                        .await;
                }
            }
        }
        Err(_) => {
            let _ = store.put_abort(&pending.upload_id);
        }
    }
    Ok(see_other("/admin/releases"))
}
