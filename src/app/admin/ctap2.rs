//! Admin CTAP2 security-key dashboard (`/admin/ctap2`) — architecture 1.2 §6.5, ADR 003.
//!
//! Two-phase enrolment: E1 stages a PENDING credential here (fingerprint shown,
//! recorded out-of-band); E2 activates it via `vcp-store ctap2 approve` on the
//! helper host. Revocation is dashboard-driven (IPC `ctap2_revoke`).

use serde::Deserialize;
use serde_json::Value;
use topcoat::{
    Result,
    context::Cx,
    router::{
        content::Form,
        error::{SeeOther, see_other},
        page, query_params, route,
    },
    view::view,
};

use crate::{
    app::_components::ico_key,
    app::VCP_WEBAUTHN_JS,
    auth::{capability_denied, config, require_staff, storage},
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

fn parse_cred_list(raw: &str) -> Vec<CredRow> {
    let Ok(arr) = serde_json::from_str::<Vec<Value>>(raw) else {
        return Vec::new();
    };
    arr.into_iter()
        .filter_map(|v| {
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
        })
        .collect()
}

/// Compact fingerprint for table cells; full value stays in `title` + CLI command.
fn short_fingerprint(fp: &str) -> String {
    if fp.len() <= 20 {
        fp.to_owned()
    } else {
        format!("{}…{}", &fp[..12], &fp[fp.len() - 6..])
    }
}

/// CLI line shown after E1. Production helper hosts load `vcp-store.conf`;
/// local spawn needs the same blob root as `just run` (portal `[storage]`).
fn approve_command(fp: &str, blob_path: &str) -> String {
    if blob_path.trim().is_empty() {
        format!("vcp-store ctap2 approve --fingerprint {fp}")
    } else {
        format!(
            "VCP_ENVIRONMENT=development ./target/debug/vcp-store ctap2 approve --fingerprint {fp}"
        )
    }
}

#[query_params]
struct AdminCtap2Query {
    /// Fingerprint of a freshly staged (E1) credential — success feedback.
    enrolled: Option<String>,
    /// credential_id_hex targeted by the revoke confirmation overlay.
    revoke: Option<String>,
    err: Option<String>,
}

#[page]
async fn admin_ctap2_page(cx: &Cx) -> Result {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.ctap2_manage {
        return Err(capability_denied().into());
    }
    let store = storage(cx);
    let pending = parse_cred_list(&store.ctap2_list("pending").unwrap_or_else(|_| "[]".into()));
    let active = parse_cred_list(&store.ctap2_list("active").unwrap_or_else(|_| "[]".into()));

    let q = query_params::<AdminCtap2Query>(cx).ok();
    // Only echo values that resolve to a real helper row (no reflected input).
    let enrolled = q
        .as_ref()
        .and_then(|q| q.enrolled.as_deref())
        .and_then(|fp| pending.iter().find(|r| r.fingerprint == fp).cloned());
    let revoke_target = q
        .as_ref()
        .and_then(|q| q.revoke.as_deref())
        .and_then(|hexid| active.iter().find(|r| r.credential_id_hex == hexid))
        .cloned();
    let err = q.as_ref().and_then(|q| q.err.clone()).unwrap_or_default();
    let confirm_err = err == "confirm";
    let banner = match err.as_str() {
        "attestation" => Some(
            "The WebAuthn ceremony did not return a usable attestation. \
             Retry from a browser with an authenticator attached.",
        ),
        "enrol" => Some("The storage helper rejected the enrolment. Check helper logs."),
        "revoke" => Some("Revocation failed. The key may already be revoked — reload this page."),
        _ => None,
    };

    let cfg = config(cx);
    let rp_id = cfg.storage.webauthn_rp_id.clone();
    // Non-empty in spawn/inline (dev); empty in production portal conf.
    let blob_path_for_cli = cfg.storage.blob_path.clone();
    // E1 registration challenge is portal-local (attestation = "none");
    // trust anchoring happens at E2 via the out-of-band fingerprint match.
    let reg_challenge = {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes())
    };
    let user_handle = staff.user.id.to_string();
    let user_name = staff.user.email.clone();

    view! {
        cx =>
        <div
            style="display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap; margin-bottom: 18px;"
        >
            <div>
                <h1 class="vb-title">"Security keys"</h1>
                <p class="vb-lead" style="margin-bottom: 0;">
                    "Per-admin CTAP2 / WebAuthn keys, verified inside the "
                    <span class="vb-mono">"vcp-store"</span>
                    " helper. Release publishes and deletes require an assertion from an ACTIVE key."
                </p>
            </div>
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
                <strong>"Two-phase enrolment (ADR 003)."</strong>
                " Creating a passkey here only stages it as PENDING. Record its fingerprint "
                "out-of-band, then activate it on the helper host with "
                <span class="vb-mono">"vcp-store ctap2 approve"</span>
                ". On the helper host, "
                <span class="vb-mono">"vcp-store ctap2 pending"</span>
                " lists PENDING keys (for E2) and in-flight ceremony challenges."
            </div>
        </div>

        if let Some(row) = enrolled {
            let fp = row.fingerprint.clone();
            let cmd = approve_command(&row.fingerprint, &blob_path_for_cli);
            let cmd_copy = cmd.clone();
            <div
                class="vb-panel"
                style="padding: 20px 22px; margin-bottom: 18px; border-color: #cfe2d6; background: #f7fbf8;"
            >
                <div class="vb-section-label" style="color: #2f7d52;">
                    "KEY STAGED — PHASE E1 COMPLETE"
                </div>
                <p style="margin: 0 0 10px; font-size: 14px;">
                    <strong>(row.admin_label.clone())</strong>
                    " is PENDING. Record this fingerprint out-of-band, then approve on the helper host:"
                </p>
                <div id="vcp-ctap2-fingerprint" class="vb-pre" style="margin-bottom: 10px;">
                    (fp)
                </div>
                <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                    <span class="vb-mono" style="font-size: 12.5px;">(cmd)</span>
                    <button
                        type="button"
                        class="vb-btn ghost"
                        style="padding: 6px 12px; font-size: 12px;"
                        data-copy=(cmd_copy)
                        @click="(e) => { const el = e.current_target.inner; navigator.clipboard.writeText(el.getAttribute('data-copy')); el.textContent = 'Copied'; }"
                    >
                        "Copy command"
                    </button>
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
                    action="/admin/ctap2/enrol"
                    style="max-width: 460px;"
                >
                    <label for="admin_label">"Key label"</label>
                    <input
                        id="admin_label"
                        name="admin_label"
                        required=""
                        placeholder="yubikey-alice-1"
                        autocomplete="off"
                    >
                    <p class="vb-form-hint">
                        "User verification (PIN or biometric) is required. The key stays "
                        "PENDING and cannot authorize anything until CLI approval. "
                        "In development, open this page as "
                        <span class="vb-mono">"https://localhost:3000"</span>
                        " — WebAuthn rejects IP hosts such as "
                        <span class="vb-mono">"127.0.0.1"</span>
                        "."
                    </p>
                    <input
                        id="vcp-webauthn-assertion"
                        type="hidden"
                        name="attestation"
                        value=""
                    >
                    <button
                        id="vcp-webauthn-btn"
                        class="vb-btn"
                        type="button"
                        style="margin-top: 12px;"
                    >
                        "Create passkey (PENDING)"
                    </button>
                </form>
            </div>
        </div>

        <div class="vb-section-label">"PENDING — AWAITING CLI APPROVAL (E2)"</div>
        <div class="vb-table-wrap" style="margin-bottom: 24px;">
            <table class="vb-table">
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
                            let cmd = approve_command(&row.fingerprint, &blob_path_for_cli);
                            <tr>
                                <td style="font-weight: 700;">(row.admin_label.clone())</td>
                                <td>(row.user_handle.clone())</td>
                                <td>
                                    <span title=(fp_full)>(fp_short)</span>
                                </td>
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
                                            data-copy=(cmd)
                                            @click="(e) => { const el = e.current_target.inner; navigator.clipboard.writeText(el.getAttribute('data-copy')); el.textContent = 'Copied'; }"
                                        >
                                            "Copy approve command"
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        }
                    }
                </tbody>
            </table>
        </div>

        <div class="vb-section-label">"ACTIVE — AUTHORIZE HELPER MUTATIONS"</div>
        <div class="vb-table-wrap">
            <table class="vb-table">
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
                            let revoke_href = format!(
                                "/admin/ctap2?revoke={}", row.credential_id_hex
                            );
                            <tr>
                                <td style="font-weight: 700;">(row.admin_label.clone())</td>
                                <td>(row.user_handle.clone())</td>
                                <td>
                                    <span title=(fp_full)>(fp_short)</span>
                                </td>
                                <td>
                                    <span class="vb-badge status-published">"ACTIVE"</span>
                                    if row.is_soft {
                                        " "
                                        <span class="vb-badge soft">"SOFT"</span>
                                    }
                                </td>
                                <td class="vb-col-actions">
                                    <div class="vb-row-actions">
                                        <a class="vb-btn danger" href=(revoke_href)>
                                            "Revoke"
                                        </a>
                                    </div>
                                </td>
                            </tr>
                        }
                    }
                </tbody>
            </table>
        </div>
        <p class="vb-muted" style="margin-top: 14px;">
            "Enrolments, approvals and revocations are appended to the helper audit log "
            "(" <span class="vb-mono">"blob_path/audit/webauthn.log"</span> "); "
            "ops alert on revoke bursts."
        </p>

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
                    <form class="vb-form" method="POST" action="/admin/ctap2/revoke">
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
                            <a class="vb-btn muted compact" href="/admin/ctap2">"Cancel"</a>
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

#[route(POST "/admin/ctap2/enrol")]
async fn admin_ctap2_enrol(cx: &Cx, Form(form): Form<EnrolForm>) -> Result<SeeOther> {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.ctap2_manage {
        return Err(capability_denied().into());
    }
    let Ok(att) = serde_json::from_str::<Value>(form.attestation.trim()) else {
        return Ok(see_other("/admin/ctap2?err=attestation"));
    };
    let att_obj = att
        .pointer("/response/attestationObject")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Ok((cred_id, cose)) = extract_attested_credential(att_obj) else {
        return Ok(see_other("/admin/ctap2?err=attestation"));
    };
    let store = storage(cx);
    match store.ctap2_enrol_stage(
        &cred_id,
        &cose,
        &staff.user.id.to_string(),
        form.admin_label.trim(),
        false,
    ) {
        Ok(fp) => Ok(see_other(&format!("/admin/ctap2?enrolled={fp}"))),
        Err(_) => Ok(see_other("/admin/ctap2?err=enrol")),
    }
}

#[derive(Debug, Deserialize)]
struct RevokeForm {
    credential_id_hex: String,
    confirm: String,
}

#[route(POST "/admin/ctap2/revoke")]
async fn admin_ctap2_revoke(cx: &Cx, Form(form): Form<RevokeForm>) -> Result<SeeOther> {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.ctap2_manage {
        return Err(capability_denied().into());
    }
    let hexid = form.credential_id_hex.trim();
    if form.confirm.trim() != "revoke" {
        // Only hex reaches the redirect (decode gate below re-validates on POST).
        if hexid.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(see_other(&format!(
                "/admin/ctap2?revoke={hexid}&err=confirm"
            )));
        }
        return Ok(see_other("/admin/ctap2?err=revoke"));
    }
    let Ok(cred) = hex::decode(hexid) else {
        return Ok(see_other("/admin/ctap2?err=revoke"));
    };
    let store = storage(cx);
    match store.ctap2_revoke(&cred) {
        Ok(()) => Ok(see_other("/admin/ctap2")),
        Err(_) => Ok(see_other("/admin/ctap2?err=revoke")),
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
            approve_command("ff00", ""),
            "vcp-store ctap2 approve --fingerprint ff00"
        );
        assert!(
            approve_command("ff00", "/tmp/vcp-storage").contains("VCP_ENVIRONMENT=development")
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
