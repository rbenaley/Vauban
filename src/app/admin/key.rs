//! Admin KEY security-key dashboard (`/admin/key`) — architecture 1.2 §6.5, ADR 003.
//!
//! Two-phase enrolment: E1 stages a PENDING credential here (fingerprint shown,
//! recorded out-of-band); E2 activates it via `vcp-store approve-key` on the
//! helper host. Revocation is dashboard-driven (IPC `key_revoke`).

use serde::Deserialize;
use serde_json::Value;
use topcoat::{
    Result,
    context::Cx,
    router::{
        content::Form,
        error::{SeeOther, see_other},
        href, page, query_params, route,
    },
    view::view,
};

use crate::app::hrefs::ErrQ;
use crate::{
    app::_components::{ico_key, list_toolbar},
    app::VCP_WEBAUTHN_JS,
    auth::{capability_denied, config, require_staff, storage},
    list_page::{KEY_PAGE_SIZE, PagerLinks, clamp_page, page_count, parse_page},
    perms::perms_for_user,
    storage::webauthn::extract_attested_credential,
};

#[derive(Debug, Clone)]
struct CredRow {
    fingerprint: String,
    admin_label: String,
    user_handle: String,
    credential_id_hex: String,
    is_soft: bool,
}

fn parse_cred_row(v: &Value) -> Option<CredRow> {
    Some(CredRow {
        fingerprint: v.get("fingerprint")?.as_str()?.to_owned(),
        admin_label: v
            .get("admin_label")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_owned(),
        user_handle: v
            .get("user_handle")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_owned(),
        credential_id_hex: v.get("credential_id_hex")?.as_str()?.to_owned(),
        is_soft: v.get("is_soft").and_then(|x| x.as_bool()).unwrap_or(false),
    })
}

fn parse_cred_list(raw: &str) -> Vec<CredRow> {
    let Ok(arr) = serde_json::from_str::<Vec<Value>>(raw) else {
        return Vec::new();
    };
    arr.iter().filter_map(parse_cred_row).collect()
}

/// Accept only a SHA-256 hex fingerprint for the E1 success banner (no reflected HTML).
fn sanitize_enrolled_fingerprint(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(t.to_ascii_lowercase())
    } else {
        None
    }
}

fn key_list_href(cx: &Cx, pending_page: usize, active_page: usize) -> String {
    href!(admin_key_page)
        .query(crate::app::hrefs::KeyPagesQ {
            pending_page,
            active_page,
        })
        .resolve(cx)
}

fn key_revoke_href(
    cx: &Cx,
    pending_page: usize,
    active_page: usize,
    credential_id_hex: &str,
) -> String {
    href!(admin_key_page)
        .query(crate::app::hrefs::KeyRevokeListQ {
            pending_page,
            active_page,
            revoke: credential_id_hex,
        })
        .resolve(cx)
}

/// Compact fingerprint for table cells; full value stays in `title` + CLI command.
fn short_fingerprint(fp: &str) -> String {
    if fp.len() <= 20 {
        fp.to_owned()
    } else {
        format!("{}…{}", &fp[..12], &fp[fp.len() - 6..])
    }
}

/// CLI line copied from the PENDING table (same wording in every environment).
fn approve_command(fp: &str) -> String {
    format!("vcp-store approve-key --fingerprint {fp}")
}

#[query_params]
struct AdminKeyQuery {
    /// Fingerprint of a freshly staged (E1) credential — success feedback.
    enrolled: Option<String>,
    /// credential_id_hex targeted by the revoke confirmation overlay.
    revoke: Option<String>,
    err: Option<String>,
    pending_page: Option<u32>,
    active_page: Option<u32>,
}

#[page]
pub(crate) async fn admin_key_page(cx: &Cx) -> Result {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.key_manage {
        return Err(capability_denied().into());
    }
    let store = storage(cx);
    let q = query_params::<AdminKeyQuery>(cx).ok();

    let pending_page_raw = parse_page(q.as_ref().and_then(|q| q.pending_page));
    let active_page_raw = parse_page(q.as_ref().and_then(|q| q.active_page));

    let (pending_json, pending_total) = store
        .key_list_page("pending", pending_page_raw, KEY_PAGE_SIZE)
        .unwrap_or_else(|_| ("[]".into(), 0));
    let pending_pages = page_count(pending_total, KEY_PAGE_SIZE);
    let pending_page = clamp_page(pending_page_raw, pending_pages);
    let (pending_json, _) = if pending_page != pending_page_raw {
        store
            .key_list_page("pending", pending_page, KEY_PAGE_SIZE)
            .unwrap_or_else(|_| ("[]".into(), pending_total))
    } else {
        (pending_json, pending_total)
    };
    let pending = parse_cred_list(&pending_json);

    let (active_json, active_total) = store
        .key_list_page("active", active_page_raw, KEY_PAGE_SIZE)
        .unwrap_or_else(|_| ("[]".into(), 0));
    let active_pages = page_count(active_total, KEY_PAGE_SIZE);
    let active_page = clamp_page(active_page_raw, active_pages);
    let (active_json, _) = if active_page != active_page_raw {
        store
            .key_list_page("active", active_page, KEY_PAGE_SIZE)
            .unwrap_or_else(|_| ("[]".into(), active_total))
    } else {
        (active_json, active_total)
    };
    let active = parse_cred_list(&active_json);

    let pending_pager = PagerLinks::from_hrefs(pending_page, pending_pages, |n| {
        key_list_href(cx, n, active_page)
    });
    let active_pager = PagerLinks::from_hrefs(active_page, active_pages, |n| {
        key_list_href(cx, pending_page, n)
    });

    // Hex-only fingerprint (E1 banner). Not tied to the current pending page.
    let enrolled_fp = q
        .as_ref()
        .and_then(|q| q.enrolled.as_deref())
        .and_then(sanitize_enrolled_fingerprint);
    // Resolve revoke target by id so the overlay works off-page.
    let revoke_target = q.as_ref().and_then(|q| {
        let hexid = q.revoke.as_deref()?;
        if !hexid.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let cred = hex::decode(hexid).ok()?;
        let raw = store.key_get(&cred).ok().flatten()?;
        let v: Value = serde_json::from_str(&raw).ok()?;
        if v.get("status").and_then(|s| s.as_str()) != Some("active") {
            return None;
        }
        let row = parse_cred_row(&v)?;
        (row.credential_id_hex == hexid).then_some(row)
    });
    let err = q.as_ref().and_then(|q| q.err.clone()).unwrap_or_default();
    let confirm_err = err == "confirm";
    let banner = match err.as_str() {
        "attestation" => Some(
            "The WebAuthn ceremony did not return a usable attestation. \
             Retry from a browser with an authenticator attached.",
        ),
        "label" => Some("Key label is required (non-empty after trimming whitespace)."),
        "enrol" => Some("The storage helper rejected the enrolment. Check helper logs."),
        "revoke" => Some("Revocation failed. The key may already be revoked — reload this page."),
        _ => None,
    };

    let cfg = config(cx);
    let rp_id = cfg.storage.webauthn_rp_id.clone();
    // E1 registration challenge is portal-local (attestation = "none");
    // trust anchoring happens at E2 via the out-of-band fingerprint match.
    let reg_challenge = {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes())
    };
    let user_handle = staff.user.id.to_string();
    let user_name = staff.user.email.clone();
    let pending_page_for_links = pending_page;
    let active_page_for_links = active_page;

    view! {
        cx =>
        <div style="margin-bottom: 18px;">
            <h1 class="vb-title">"Security keys"</h1>
        </div>

        if let Some(msg) = banner {
            <div
                class="vb-callout"
                style="background: #faeeed; border-color: #eccfcc; color: #b5403a;"
            >
                <div>(msg)</div>
            </div>
        }

        <div class="vb-callout">
            (ico_key(cx, 16).await?)
            <div>
                "Record its fingerprint out-of-band, then you will have to "
                "activate it from the server with "
                <span
                    class="vb-mono"
                    style="display: inline-block; max-width: 100%; box-sizing: border-box; margin: 0; padding: 4px 10px; background: #f7f8f6; border: 1px solid #e0e2de; border-radius: 4px; font-size: 12.5px; line-height: 1.5; color: #14171c; vertical-align: middle;"
                >
                    "vcp-store approve-key"
                </span>
            </div>
        </div>

        if let Some(fp) = enrolled_fp {
            <div
                class="vb-panel"
                style="padding: 20px 22px; margin-bottom: 18px; border-color: #cfe2d6; background: #f7fbf8;"
            >
                <div class="vb-section-label" style="color: #2f7d52;">
                    "KEY STAGED — PHASE E1 COMPLETE"
                </div>
                <div
                    id="vcp-key-fingerprint"
                    class="vb-mono"
                    style="display: inline-block; max-width: 100%; box-sizing: border-box; margin: 0; padding: 10px 12px; background: #f7f8f6; border: 1px solid #e0e2de; border-radius: 4px; font-size: 12.5px; line-height: 1.5; color: #14171c; overflow-x: auto; white-space: nowrap;"
                >
                    (fp)
                </div>
            </div>
        }

        <div class="vb-panel" style="padding: 20px 22px; margin-bottom: 24px;">
            <div class="vb-section-label">"ENROL AUTHENTICATOR — PHASE E1 (WEB)"</div>
            <div
                id="vcp-webauthn-root"
                data-mode="create"
                data-challenge=(reg_challenge)
                data-rp-id=(rp_id)
                data-user-id=(user_handle)
                data-user-name=(user_name)
            >
                <form
                    id="vcp-webauthn-form"
                    class="vb-form"
                    method="POST"
                    action=(href!(admin_key_enrol))
                    style="max-width: 560px;"
                >
                    <label for="admin_label">"Key label"</label>
                    <div
                        style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;"
                    >
                        <input
                            id="admin_label"
                            name="admin_label"
                            required=""
                            minlength="1"
                            pattern=".*\\S.*"
                            title="Label must contain a non-whitespace character"
                            placeholder="yubikey-alice-1"
                            autocomplete="off"
                            style="flex: 1; min-width: 180px; margin: 0;"
                        >
                        <input
                            id="vcp-webauthn-assertion"
                            type="hidden"
                            name="attestation"
                            value=""
                        >
                        <button
                            id="vcp-webauthn-btn"
                            class="vb-btn vb-mono"
                            type="button"
                        >
                            "Create key"
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <div
            style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 8px;"
        >
            <div class="vb-section-label" style="margin: 0;">
                "PENDING — AWAITING CLI APPROVAL (E2)"
            </div>
            list_toolbar(links: &pending_pager)
        </div>
        <div class="vb-table-wrap" style="margin-bottom: 24px;">
            <table class="vb-table vb-table-key">
                <colgroup>
                    <col class="vb-key-c-key">
                    <col class="vb-key-c-by">
                    <col class="vb-key-c-fp">
                    <col class="vb-key-c-status">
                    <col class="vb-key-c-actions">
                </colgroup>
                <thead>
                    <tr>
                        <th>"KEY"</th>
                        <th>"ENROLLED BY"</th>
                        <th>"FINGERPRINT"</th>
                        <th>"STATUS"</th>
                        <th class="vb-col-actions">"ACTIONS"</th>
                    </tr>
                </thead>
                <tbody>
                    if pending.is_empty() {
                        <tr>
                            <td colspan="5">
                                <div class="vb-empty">"No pending keys."</div>
                            </td>
                        </tr>
                    } else {
                        for row in pending {
                            let fp_full = row.fingerprint.clone();
                            let fp_short = short_fingerprint(&row.fingerprint);
                            let cmd = approve_command(&row.fingerprint);
                            let key_label = if row.admin_label.trim().is_empty() {
                                "—".to_owned()
                            } else {
                                row.admin_label.clone()
                            };
                            <tr>
                                <td style="font-weight: 700;">(key_label)</td>
                                <td>(row.user_handle.clone())</td>
                                <td><span title=(fp_full)>(fp_short)</span></td>
                                <td>
                                    <span class="vb-badge status-hidden">"PENDING"</span>
                                </td>
                                <td class="vb-col-actions">
                                    <div class="vb-row-actions">
                                        <button
                                            type="button"
                                            class="vb-btn ghost"
                                            style="padding: 6px 12px; font-size: 12px;"
                                            title=(cmd.clone())
                                            aria-label="Copy approve command"
                                            data-copy=(cmd)
                                            @click="(e) => { const el = e.current_target.inner; navigator.clipboard.writeText(el.getAttribute('data-copy')); el.textContent = 'Copied'; }"
                                        >
                                            "Copy"
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        }
                    }
                </tbody>
            </table>
        </div>

        <div
            style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 8px;"
        >
            <div class="vb-section-label" style="margin: 0;">
                "ACTIVE — AUTHORIZE HELPER MUTATIONS"
            </div>
            list_toolbar(links: &active_pager)
        </div>
        <div class="vb-table-wrap">
            <table class="vb-table vb-table-key">
                <colgroup>
                    <col class="vb-key-c-key">
                    <col class="vb-key-c-by">
                    <col class="vb-key-c-fp">
                    <col class="vb-key-c-status">
                    <col class="vb-key-c-actions">
                </colgroup>
                <thead>
                    <tr>
                        <th>"KEY"</th>
                        <th>"ENROLLED BY"</th>
                        <th>"FINGERPRINT"</th>
                        <th>"STATUS"</th>
                        <th class="vb-col-actions">"ACTIONS"</th>
                    </tr>
                </thead>
                <tbody>
                    if active.is_empty() {
                        <tr>
                            <td colspan="5">
                                <div class="vb-empty">
                                    "No active keys. Gated operations stay locked until "
                                    "a key completes E1 + E2."
                                </div>
                            </td>
                        </tr>
                    } else {
                        for row in active {
                            let fp_full = row.fingerprint.clone();
                            let fp_short = short_fingerprint(&row.fingerprint);
                            let revoke_href = key_revoke_href(
                                cx,
                                pending_page_for_links,
                                active_page_for_links,
                                &row.credential_id_hex,
                            );
                            let key_label = if row.admin_label.trim().is_empty() {
                                "—".to_owned()
                            } else {
                                row.admin_label.clone()
                            };
                            <tr>
                                <td style="font-weight: 700;">(key_label)</td>
                                <td>(row.user_handle.clone())</td>
                                <td><span title=(fp_full)>(fp_short)</span></td>
                                <td>
                                    <span class="vb-badge status-published">"ACTIVE"</span>
                                    if row.is_soft {
                                        " "
                                        <span class="vb-badge soft">"SOFT"</span>
                                    }
                                </td>
                                <td class="vb-col-actions">
                                    <div class="vb-row-actions">
                                        <a class="vb-btn danger" href=(revoke_href)>"Revoke"</a>
                                    </div>
                                </td>
                            </tr>
                        }
                    }
                </tbody>
            </table>
        </div>

        if let Some(target) = revoke_target {
            let cred = target.credential_id_hex.clone();
            <div
                class="vb-confirm-root"
                role="dialog"
                aria-modal="true"
                aria-label="Revoke security key"
            >
                <div class="vb-confirm">
                    <h2>"Revoke this security key?"</h2>
                    <p>
                        "This immediately disables "
                        <strong>(target.admin_label.clone())</strong>
                        " for helper-gated operations. Re-activation requires a full "
                        "E1 + E2 re-enrolment. Type "
                        <span class="vb-mono">"revoke"</span>
                        " to confirm."
                    </p>
                    if confirm_err {
                        <p style="color: #b5403a; margin-bottom: 14px;">
                            "Confirmation text must be exactly "
                            <span class="vb-mono">"revoke"</span>
                            "."
                        </p>
                    }
                    <form
                        class="vb-form"
                        method="POST"
                        action=(href!(admin_key_revoke))
                    >
                        <input type="hidden" name="credential_id_hex" value=(cred)>
                        <label for="confirm">"Confirm"</label>
                        <input
                            id="confirm"
                            name="confirm"
                            required=""
                            placeholder="revoke"
                            autocomplete="off"
                        >
                        <div class="vb-confirm-actions">
                            <a
                                class="vb-btn muted compact"
                                href=(href!(admin_key_page))
                            >
                                "Cancel"
                            </a>
                            <button
                                class="vb-btn danger"
                                type="submit"
                                style="padding: 10px 18px; font-size: 13px;"
                            >
                                "Revoke key"
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        }
        <script src=(VCP_WEBAUTHN_JS) defer=""></script>
    }
}

#[derive(Debug, Deserialize)]
struct EnrolForm {
    admin_label: String,
    attestation: String,
}

#[route(POST "/admin/key/enrol")]
pub(crate) async fn admin_key_enrol(cx: &Cx, Form(form): Form<EnrolForm>) -> Result<SeeOther> {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.key_manage {
        return Err(capability_denied().into());
    }
    // Label before attestation: same order as the ceremony JS, and keeps the
    // empty-label denial path testable without a real WebAuthn payload.
    let Some(label) = crate::storage::normalize_admin_label(&form.admin_label) else {
        return Ok(see_other(
            href!(admin_key_page)
                .query(ErrQ { err: Some("label") })
                .resolve(cx),
        ));
    };
    let Ok(att) = serde_json::from_str::<Value>(form.attestation.trim()) else {
        return Ok(see_other(
            href!(admin_key_page)
                .query(ErrQ {
                    err: Some("attestation"),
                })
                .resolve(cx),
        ));
    };
    let att_obj = att
        .pointer("/response/attestationObject")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Ok((cred_id, cose)) = extract_attested_credential(att_obj) else {
        return Ok(see_other(
            href!(admin_key_page)
                .query(ErrQ {
                    err: Some("attestation"),
                })
                .resolve(cx),
        ));
    };
    let store = storage(cx);
    match store.key_enrol_stage(&cred_id, &cose, &staff.user.id.to_string(), label, false) {
        Ok(fp) => Ok(see_other(
            href!(admin_key_page)
                .query(crate::app::hrefs::EnrolledQ { enrolled: &fp })
                .resolve(cx),
        )),
        Err(err) => {
            crate::storage::log::portal_storage_failed("admin_key_enrol", &err);
            Ok(see_other(
                href!(admin_key_page)
                    .query(ErrQ { err: Some("enrol") })
                    .resolve(cx),
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
struct RevokeForm {
    credential_id_hex: String,
    confirm: String,
}

#[route(POST "/admin/key/revoke")]
pub(crate) async fn admin_key_revoke(cx: &Cx, Form(form): Form<RevokeForm>) -> Result<SeeOther> {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.key_manage {
        return Err(capability_denied().into());
    }
    let hexid = form.credential_id_hex.trim();
    if form.confirm.trim() != "revoke" {
        // Only hex reaches the redirect (decode gate below re-validates on POST).
        if hexid.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(see_other(
                href!(admin_key_page)
                    .query(crate::app::hrefs::KeyRevokeQ {
                        revoke: hexid,
                        err: "confirm",
                    })
                    .resolve(cx),
            ));
        }
        return Ok(see_other(
            href!(admin_key_page)
                .query(ErrQ {
                    err: Some("revoke"),
                })
                .resolve(cx),
        ));
    }
    let Ok(cred) = hex::decode(hexid) else {
        return Ok(see_other(
            href!(admin_key_page)
                .query(ErrQ {
                    err: Some("revoke"),
                })
                .resolve(cx),
        ));
    };
    let store = storage(cx);
    match store.key_revoke(&cred) {
        Ok(()) => Ok(see_other(href!(admin_key_page).resolve(cx))),
        Err(_) => Ok(see_other(
            href!(admin_key_page)
                .query(ErrQ {
                    err: Some("revoke"),
                })
                .resolve(cx),
        )),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{approve_command, parse_cred_list, short_fingerprint};

    #[test]
    fn parse_cred_list_happy_and_sad() {
        let raw = r#"[
            {"fingerprint":"abcd","admin_label":"k1","user_handle":"7",
             "credential_id_hex":"0a0b","status":"pending","is_soft":false},
            {"admin_label":"missing fingerprint"}
        ]"#;
        let rows = parse_cred_list(raw);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].fingerprint, "abcd");
        assert_eq!(rows[0].admin_label, "k1");
        assert_eq!(rows[0].user_handle, "7");
        assert_eq!(rows[0].credential_id_hex, "0a0b");
        assert!(!rows[0].is_soft);

        assert!(parse_cred_list("not json").is_empty());
        assert!(parse_cred_list("{}").is_empty());
    }

    #[test]
    fn short_fingerprint_truncates_sha256_hex() {
        let fp = "a".repeat(64);
        let short = short_fingerprint(&fp);
        assert!(short.starts_with(&"a".repeat(12)));
        assert!(short.contains('…'));
        assert_eq!(short_fingerprint("deadbeef"), "deadbeef");
    }

    #[test]
    fn approve_command_matches_cli_contract() {
        assert_eq!(
            approve_command("ff00"),
            "vcp-store approve-key --fingerprint ff00"
        );
        assert!(
            !approve_command("aabb").contains("VCP_ENVIRONMENT"),
            "UI must not prefix env/path onto the approve command"
        );
    }

    proptest! {
        /// Short form is bounded and keeps prefix/suffix of the real value.
        #[test]
        fn prop_short_fingerprint_bounded(fp in "[0-9a-f]{0,128}") {
            let short = short_fingerprint(&fp);
            prop_assert!(short.chars().count() <= 20);
            if fp.len() > 20 {
                prop_assert!(short.starts_with(&fp[..12]));
                prop_assert!(short.ends_with(&fp[fp.len() - 6..]));
            } else {
                prop_assert_eq!(short, fp);
            }
        }
    }
}
