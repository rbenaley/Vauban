//! MCP HITL approvals queue (Phase 4.3) — HTMX list + approve/deny.

use super::*;
use crate::error::AppResult;
use crate::ipc::McpHitlPendingEntry;
use crate::models::session::ProxySession;
use crate::schema::{assets, proxy_sessions, users};
use crate::templates::sessions::mcp_hitl_list::{
    McpHitlContractStep, McpHitlListItem, McpHitlListTemplate, McpHitlStory,
};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl};
use diesel_async::RunQueryDsl;
use uuid::Uuid;

#[derive(Debug, serde::Deserialize)]
pub struct McpHitlDecideForm {
    pub csrf_token: String,
}

/// GET `/sessions/mcp`
pub async fn mcp_hitl_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    browser_tz: BrowserTz,
) -> Response {
    let flash = incoming_flash.flash();
    if !perms.sessions_supervise {
        let dest = if perms.access_rules_read {
            "/sessions/mcp/access"
        } else {
            "/sessions"
        };
        return flash_redirect(
            flash.error("You need sessions:supervise to review MCP tool approvals"),
            dest,
        );
    }

    let Some(ref proxy) = state.proxy_mcp else {
        return flash_redirect(flash.error("vauban-proxy-mcp unavailable"), "/sessions");
    };

    let raw = proxy.list_hitl_pendings();
    let (pendings, own_pendings) =
        match enrich_pendings(&state, &auth_user.uuid, raw, browser_tz.0).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "MCP HITL list enrich failed");
                return flash_redirect(flash.error("Failed to load HITL queue"), "/sessions");
            }
        };

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("MCP tool approvals".into(), user.clone(), browser_tz.0)
        .with_current_path("/sessions/mcp");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = McpHitlListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        pendings,
        own_pendings,
        mcp_nav: "hitl".into(),
        mcp_can_supervise: true,
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "MCP HITL template render failed");
            flash_redirect(flash.error("Failed to render HITL queue"), "/sessions")
        }
    }
}

fn hitl_expires_utc(expires_at: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(expires_at)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

async fn enrich_pendings(
    state: &AppState,
    viewer_uuid: &str,
    mut raw: Vec<McpHitlPendingEntry>,
    tz: chrono_tz::Tz,
) -> AppResult<(Vec<McpHitlListItem>, Vec<McpHitlListItem>)> {
    raw.sort_by(|a, b| {
        match (
            hitl_expires_utc(&a.expires_at),
            hitl_expires_utc(&b.expires_at),
        ) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.expires_at.cmp(&b.expires_at),
        }
    });

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| crate::error::AppError::Internal(anyhow::anyhow!("DB pool: {e}")))?;

    let mut decidable = Vec::new();
    let mut own = Vec::new();
    for entry in raw {
        let asset_name = match Uuid::parse_str(&entry.session_id) {
            Ok(su) => {
                let sess: Option<ProxySession> = proxy_sessions::table
                    .filter(proxy_sessions::uuid.eq(su))
                    .first(&mut conn)
                    .await
                    .optional()?;
                if let Some(s) = sess {
                    assets::table
                        .filter(assets::id.eq(s.asset_id))
                        .select(assets::name)
                        .first::<String>(&mut conn)
                        .await
                        .unwrap_or_else(|_| "MCP asset".into())
                } else {
                    "MCP session".into()
                }
            }
            Err(_) => "MCP session".into(),
        };

        let requester_label = if let Ok(ru) = Uuid::parse_str(&entry.requester_user_id) {
            users::table
                .filter(users::uuid.eq(ru))
                .select(users::username)
                .first::<String>(&mut conn)
                .await
                .unwrap_or_else(|_| entry.requester_user_id.clone())
        } else {
            entry.requester_user_id.clone()
        };

        let is_own = entry.requester_user_id == viewer_uuid;
        let contract_steps = parse_contract_steps(&entry.plan_contract_json);
        let story = parse_story(&entry.plan_story_json);
        let item = McpHitlListItem {
            session_id: entry.session_id,
            pending_id: entry.pending_id,
            tool: entry.tool,
            args_blake3: entry.args_blake3,
            expires_at: super::access_rules::format_rfc3339_str_to_display(&entry.expires_at, tz),
            requester_user_id: entry.requester_user_id,
            requester_label,
            asset_name,
            is_own,
            mandate_id: entry.mandate_id,
            sealed_digest: entry.sealed_digest,
            story,
            contract_steps,
        };
        if is_own {
            own.push(item);
        } else {
            decidable.push(item);
        }
    }
    Ok((decidable, own))
}

/// POST `/sessions/mcp-hitl/{session}/{pending}/approve`
pub async fn mcp_hitl_approve_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path((session_id, pending_id)): axum::extract::Path<(String, String)>,
    Form(form): Form<McpHitlDecideForm>,
) -> Response {
    if !perms.sessions_supervise {
        return flash_redirect(
            incoming_flash
                .flash()
                .error("You need sessions:supervise to review MCP tool approvals"),
            "/sessions",
        );
    }
    decide_web(
        state,
        auth_user,
        perms,
        incoming_flash,
        jar,
        session_id,
        pending_id,
        "approve",
        form,
    )
    .await
}

/// POST `/sessions/mcp-hitl/{session}/{pending}/deny`
pub async fn mcp_hitl_deny_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path((session_id, pending_id)): axum::extract::Path<(String, String)>,
    Form(form): Form<McpHitlDecideForm>,
) -> Response {
    decide_web(
        state,
        auth_user,
        perms,
        incoming_flash,
        jar,
        session_id,
        pending_id,
        "deny",
        form,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn decide_web(
    state: AppState,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    session_id: String,
    pending_id: String,
    decision: &str,
    form: McpHitlDecideForm,
) -> Response {
    let flash = incoming_flash.flash();
    let list_url = "/sessions/mcp";

    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(flash.error("Invalid CSRF token"), list_url);
    }

    if !perms.sessions_supervise {
        return flash_redirect(
            flash.error("You need sessions:supervise to decide MCP HITL"),
            list_url,
        );
    }

    let Some(ref proxy) = state.proxy_mcp else {
        return flash_redirect(flash.error("vauban-proxy-mcp unavailable"), list_url);
    };

    let Some(pending) = proxy.get_hitl_pending(&pending_id) else {
        return flash_redirect(flash.error("HITL pending not found"), list_url);
    };
    if pending.session_id != session_id {
        return flash_redirect(flash.error("HITL pending not found"), list_url);
    }
    if pending.requester_user_id == auth_user.uuid {
        return flash_redirect(
            flash.error("Separation of duties: you cannot decide your own pending"),
            list_url,
        );
    }

    if let Err(e) = crate::services::mcp_control::hitl_decide(
        proxy,
        &session_id,
        &pending_id,
        decision,
        &auth_user.uuid,
    ) {
        return flash_redirect(flash.error(format!("HITL decision failed: {e}")), list_url);
    }

    let _ = state
        .broadcast
        .send(
            &crate::services::broadcast::WsChannel::Notifications,
            crate::services::broadcast::WsMessage::new(
                "jit-notification",
                serde_json::json!({
                    "type": "mcp_hitl_decided",
                    "session_uuid": session_id,
                    "pending_id": pending_id,
                    "decision": decision,
                })
                .to_string(),
            ),
        )
        .await;
    crate::handlers::web::broadcast_mcp_hitl_badge(&state).await;
    if let Err(e) = crate::services::mcp_mail::queue_hitl_decided(
        &state,
        &session_id,
        &pending_id,
        &pending.tool,
        &pending.requester_user_id,
        decision,
        &auth_user.username,
    )
    .await
    {
        tracing::warn!(
            session_id = %session_id,
            pending_id = %pending_id,
            error = %e,
            "Failed to queue mcp.hitl_decided email"
        );
    }

    flash_redirect(flash.success(format!("HITL {decision} recorded")), list_url)
}

fn sanitize_story_field(raw: &str) -> String {
    match shared::json_redact::redact_sensitive_json(&serde_json::Value::String(raw.to_string())) {
        serde_json::Value::String(s) => s,
        other => other.to_string(),
    }
}

fn parse_story(plan_story_json: &str) -> Option<McpHitlStory> {
    if plan_story_json.trim().is_empty() {
        return None;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(plan_story_json) else {
        return None;
    };
    let summary = sanitize_story_field(v.get("summary")?.as_str()?.trim());
    let context = sanitize_story_field(v.get("context")?.as_str()?.trim());
    let objective = sanitize_story_field(v.get("objective")?.as_str()?.trim());
    let risks = sanitize_story_field(v.get("risks")?.as_str()?.trim());
    if summary.is_empty() {
        return None;
    }
    Some(McpHitlStory {
        summary,
        context,
        objective,
        risks,
    })
}

fn parse_contract_steps(plan_contract_json: &str) -> Vec<McpHitlContractStep> {
    if plan_contract_json.trim().is_empty() {
        return Vec::new();
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(plan_contract_json) else {
        return Vec::new();
    };
    let Some(steps) = v.get("steps").and_then(|s| s.as_array()) else {
        return Vec::new();
    };
    steps
        .iter()
        .filter_map(|s| {
            let args = s.get("arguments").cloned().unwrap_or(serde_json::json!({}));
            let redacted = shared::json_redact::redact_sensitive_json(&args);
            let arguments_redacted =
                serde_json::to_string(&redacted).unwrap_or_else(|_| "{}".into());
            Some(McpHitlContractStep {
                step_id: s.get("step_id")?.as_str()?.to_string(),
                operation: s.get("operation")?.as_str()?.to_string(),
                mode: s
                    .get("mode")
                    .and_then(|m| m.as_str())
                    .unwrap_or("literal")
                    .to_string(),
                intent: s.get("intent")?.as_str()?.to_string(),
                arguments_redacted,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::hitl_expires_utc;

    #[test]
    fn hitl_queue_sorts_soonest_expiry_first() {
        let mut raw = [
            "2026-09-05T14:30:53Z",
            "2026-09-05T14:27:29Z",
            "2026-09-05T14:28:44Z",
        ];
        raw.sort_by_key(|a| hitl_expires_utc(a));
        assert_eq!(
            raw,
            [
                "2026-09-05T14:27:29Z",
                "2026-09-05T14:28:44Z",
                "2026-09-05T14:30:53Z",
            ]
        );
    }

    #[test]
    fn hitl_expiry_renders_in_browser_tz_not_raw_zulu() {
        let shown = crate::handlers::web::access_rules::format_rfc3339_str_to_display(
            "2026-09-05T14:28:53Z",
            chrono_tz::Tz::Europe__Paris,
        );
        assert!(
            shown.contains("16:28") && shown.contains("CEST"),
            "14:28Z must display as 16:28 CEST, got {shown}"
        );
        assert!(!shown.contains('Z'), "operator list must not dump raw …Z");
    }

    #[test]
    fn decide_web_broadcasts_sidebar_badge() {
        let src = include_str!("mcp_hitl.rs");
        let start = src
            .find("async fn decide_web")
            .expect("decide_web must exist");
        let body = &src[start..];
        assert!(
            body.contains("broadcast_mcp_hitl_badge"),
            "HITL decide must push the sidebar badge"
        );
        assert!(
            body.contains("queue_hitl_decided"),
            "HITL decide must queue mcp.hitl_decided"
        );
    }
}
