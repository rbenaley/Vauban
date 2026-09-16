//! C1 WebAuthn confirm for digest-bound release delete.

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{
        content::Form,
        error::{SeeOther, redirect, see_other},
        href, page, query_params, route,
    },
    view::{View, view},
};

use crate::app::admin::releases::admin_releases_page;
use crate::{
    app::VCP_WEBAUTHN_JS,
    auth::{capability_denied, db, require_staff, storage},
    models::Release,
    perms::perms_for_user,
    storage::delete_release_object,
};

#[query_params]
struct DeleteConfirmQuery {
    token: Option<String>,
}

#[page]
pub(crate) async fn admin_releases_delete_confirm_page(cx: &Cx) -> Result<impl View> {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.releases_manage {
        return Err(capability_denied().into());
    }
    let q = query_params::<DeleteConfirmQuery>(cx).ok();
    let Some(token) = q
        .as_ref()
        .and_then(|q| q.token.as_deref())
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
    else {
        return Err(redirect(href!(admin_releases_page).resolve(cx)).into());
    };
    let store = storage(cx);
    let Some(pending) = store.peek_pending_delete(&token) else {
        return Err(redirect(href!(admin_releases_page).resolve(cx)).into());
    };
    let summary = pending.summary.clone();
    let challenge = pending.challenge.clone();
    let rp_id = pending.rp_id.clone();
    let allow = serde_json::to_string(&pending.allow_credentials).unwrap_or_else(|_| "[]".into());
    let token_hidden = token;

    Ok(view! {
        <div>
            <h1 class="vb-title">"Confirm release delete"</h1>
            <p class="vb-lead">
                "Helper-issued summary (verify with "
                <code>"vcp-store pending-ops"</code>
                "):"
            </p>
            <div class="vb-panel" style="padding: 24px;">
                <pre
                    id="vcp-webauthn-summary"
                    style="padding: 12px; background: var(--panel-2, #f4f4f5); border-radius: 6px; font-size: 14px; white-space: pre-wrap; overflow-wrap: anywhere;"
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
                        action=(href!(admin_releases_delete_confirm_post))
                    >
                        <input type="hidden" name="token" value=(token_hidden)>
                        <input
                            id="vcp-webauthn-assertion"
                            type="hidden"
                            name="assertion"
                            value=""
                        >
                        <button id="vcp-webauthn-btn" class="vb-btn" type="button">
                            "Authenticate and delete"
                        </button>
                    </form>
                </div>
            </div>
            <script src=(VCP_WEBAUTHN_JS) defer=""></script>
        </div>
    })
}

#[derive(Debug, Deserialize)]
struct DeleteConfirmForm {
    token: String,
    assertion: String,
}

#[route(POST)]
pub(crate) async fn admin_releases_delete_confirm_post(
    cx: &Cx,
    Form(form): Form<DeleteConfirmForm>,
) -> Result<SeeOther> {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.releases_manage {
        return Err(capability_denied().into());
    }
    let store = storage(cx);
    let Some(pending) = store.take_pending_delete(form.token.trim()) else {
        return Ok(see_other(href!(admin_releases_page).resolve(cx)));
    };
    let Some(id) = pending.release_id else {
        return Ok(see_other(href!(admin_releases_page).resolve(cx)));
    };
    if form.assertion.trim().is_empty() {
        let t = store.stash_pending_delete(pending);
        return Ok(see_other(
            href!(admin_releases_delete_confirm_page)
                .query(crate::app::hrefs::TokenQ { token: &t })
                .resolve(cx),
        ));
    }
    if store
        .delete_release_asserted(id, Some(form.assertion.trim()))
        .is_ok()
    {
        let mut database = db(cx);
        let _ = delete_release_object(&mut database, id).await;
        let rows = Release::all()
            .filter(Release::fields().id().eq(id))
            .exec(&mut database)
            .await
            .unwrap_or_default();
        if let Some(rel) = rows.into_iter().next() {
            let _ = rel.delete().exec(&mut database).await;
        }
    }
    Ok(see_other(href!(admin_releases_page).resolve(cx)))
}
