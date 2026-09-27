//! TRUSTED R1 — access contestation queue (open / claim / uphold / overturn).

use super::*;
use crate::models::access_contestation::{STATUS_OPEN, STATUS_UNDER_REVIEW};
use crate::services::access_contestation as contest_svc;
use crate::templates::sessions::contestation_detail::{
    ContestationDetailTemplate, ContestationView,
};
use crate::templates::sessions::contestation_list::{
    ContestationListItem, ContestationListTemplate,
};
use uuid::Uuid;

#[derive(Debug, serde::Deserialize)]
pub struct ContestationOpenForm {
    pub csrf_token: String,
    pub open_reason: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct ContestationClaimForm {
    pub csrf_token: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct ContestationUpholdForm {
    pub csrf_token: String,
    #[serde(default)]
    pub resolution_note: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct ContestationOverturnForm {
    pub csrf_token: String,
    #[serde(default)]
    pub resolution_note: String,
}

/// GET `/sessions/mcp/contestations`
pub async fn contestation_list(
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
            flash.error("You need sessions:supervise to review access contestations"),
            dest,
        );
    }

    let rows = match contest_svc::list_recent(&state).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "contestation list failed");
            return flash_redirect(flash.error("Failed to load contestations"), "/sessions");
        }
    };

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let subject = contest_svc::username_for_id(&state, row.subject_user_id).await;
        let opened_by = contest_svc::username_for_id(&state, row.opened_by_id).await;
        let is_own_open = {
            if let Ok(uid) = contest_svc::resolve_user_db_id(&state, &auth_user.uuid).await {
                row.opened_by_id == uid
            } else {
                false
            }
        };
        items.push(ContestationListItem {
            uuid: row.uuid.to_string(),
            decision_id: row.decision_id.clone(),
            session_uuid: row.session_uuid.to_string(),
            status: row.status.clone(),
            status_label: row.status_label().to_string(),
            subject_username: subject,
            opened_by_username: opened_by,
            opened_at: crate::utils::format_local(row.opened_at, browser_tz.0),
            open_reason_preview: truncate_reason(&row.open_reason, 120),
            is_own_open,
            is_open_queue: row.is_open_queue(),
        });
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Access contestations".into(), user.clone(), browser_tz.0)
        .with_current_path("/sessions/mcp/contestations");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = ContestationListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        items,
        mcp_nav: "contestations".into(),
        mcp_can_supervise: true,
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "contestation list template failed");
            flash_redirect(flash.error("Failed to render contestations"), "/sessions")
        }
    }
}

/// GET `/sessions/mcp/contestations/{uuid}` (review queue, MCP nest).
pub async fn contestation_detail(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    browser_tz: BrowserTz,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    if !perms.sessions_supervise && !perms.access_rules_read {
        return flash_redirect(
            incoming_flash
                .flash()
                .error("You need sessions:supervise or access_rules:read"),
            "/sessions",
        );
    }
    contestation_detail_inner(
        state,
        auth_user,
        perms,
        incoming_flash,
        browser_tz,
        uuid_str,
        false,
    )
    .await
}

/// GET `/sessions/contestations/{uuid}` (User Zone: subject / opener, read-only).
pub async fn contestation_detail_user_zone(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    browser_tz: BrowserTz,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    contestation_detail_inner(
        state,
        auth_user,
        perms,
        incoming_flash,
        browser_tz,
        uuid_str,
        true,
    )
    .await
}

async fn contestation_detail_inner(
    state: AppState,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    browser_tz: BrowserTz,
    uuid_str: String,
    user_zone: bool,
) -> Response {
    let flash = incoming_flash.flash();
    let fail = if user_zone {
        "/sessions/my-requests"
    } else {
        "/sessions/mcp/contestations"
    };
    // User Zone: one dest + one copy for unknown / forbidden (anti-enum).
    let user_zone_miss = "Contestation not found";
    let Ok(cuuid) = Uuid::parse_str(&uuid_str) else {
        let msg = if user_zone {
            user_zone_miss
        } else {
            "Invalid contestation id"
        };
        return flash_redirect(flash.error(msg), fail);
    };

    let row = match contest_svc::get_by_uuid(&state, cuuid).await {
        Ok(r) => r,
        Err(AppError::NotFound(_)) => {
            return flash_redirect(flash.error("Contestation not found"), fail);
        }
        Err(e) => {
            tracing::error!(error = %e, "contestation detail load failed");
            return flash_redirect(flash.error("Failed to load contestation"), fail);
        }
    };

    let viewer_id = match contest_svc::resolve_user_db_id(&state, &auth_user.uuid).await {
        Ok(id) => id,
        Err(_) => {
            return flash_redirect(flash.error("User not found"), fail);
        }
    };

    let is_subject = row.subject_user_id == viewer_id;
    let is_opener = row.opened_by_id == viewer_id;
    if !perms.sessions_supervise && !is_subject && !is_opener {
        let msg = if user_zone {
            user_zone_miss
        } else {
            "You are not allowed to view this contestation"
        };
        return flash_redirect(flash.error(msg), fail);
    }

    // Review actions stay on the MCP nest. User Zone is status-only,
    // even if the viewer also holds sessions:supervise.
    let can_review = !user_zone && perms.sessions_supervise && !is_opener && row.is_open_queue();
    let can_claim = can_review && row.status == STATUS_OPEN;
    let can_resolve =
        can_review && (row.status == STATUS_OPEN || row.status == STATUS_UNDER_REVIEW);

    let (can_overturn, restore_group_name) = if can_resolve {
        match contest_svc::load_session_by_uuid(&state, row.session_uuid).await {
            Ok(session) => {
                match contest_svc::resolve_restore_group_for_session(&state, &session).await {
                    Ok((_, name)) => (true, Some(name)),
                    Err(_) => (false, None),
                }
            }
            Err(_) => (false, None),
        }
    } else {
        (false, None)
    };

    let view = ContestationView {
        uuid: row.uuid.to_string(),
        decision_id: row.decision_id.clone(),
        session_uuid: row.session_uuid.to_string(),
        status: row.status.clone(),
        status_label: row.status_label().to_string(),
        subject_username: contest_svc::username_for_id(&state, row.subject_user_id).await,
        opened_by_username: contest_svc::username_for_id(&state, row.opened_by_id).await,
        opened_at: crate::utils::format_local(row.opened_at, browser_tz.0),
        open_reason: row.open_reason.clone(),
        claimed_by_username: match row.claimed_by_id {
            Some(id) => Some(contest_svc::username_for_id(&state, id).await),
            None => None,
        },
        claimed_at: row
            .claimed_at
            .map(|t| crate::utils::format_local(t, browser_tz.0)),
        resolved_by_username: match row.resolved_by_id {
            Some(id) => Some(contest_svc::username_for_id(&state, id).await),
            None => None,
        },
        resolved_at: row
            .resolved_at
            .map(|t| crate::utils::format_local(t, browser_tz.0)),
        resolution_note: row.resolution_note.clone(),
        restore_group_id: row.restore_group_id,
        restore_applied_at: row
            .restore_applied_at
            .map(|t| crate::utils::format_local(t, browser_tz.0)),
        can_claim,
        can_resolve,
        is_opener,
        can_overturn,
        restore_group_name,
    };

    let user = Some(user_context_from_auth(&auth_user));
    let current_path = if user_zone {
        "/sessions/my-requests"
    } else {
        "/sessions/mcp/contestations"
    };
    let base = BaseTemplate::new("Contestation".into(), user.clone(), browser_tz.0)
        .with_current_path(current_path);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = ContestationDetailTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        c: view,
        mcp_nav: "contestations".into(),
        mcp_can_supervise: !user_zone && perms.sessions_supervise,
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "contestation detail template failed");
            flash_redirect(flash.error("Failed to render contestation"), fail)
        }
    }
}

/// POST `/sessions/{session_uuid}/contest`
pub async fn contestation_open_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(session_uuid_str): axum::extract::Path<String>,
    Form(form): Form<ContestationOpenForm>,
) -> Response {
    let flash = incoming_flash.flash();
    let Ok(session_uuid) = Uuid::parse_str(&session_uuid_str) else {
        return flash_redirect(flash.error("Invalid session id"), "/sessions");
    };
    let back = format!("/sessions/{session_uuid}");

    if !csrf_ok(&state, &jar, &form.csrf_token) {
        return flash_redirect(flash.error("Invalid CSRF token"), &back);
    }

    let session = match contest_svc::load_session_by_uuid(&state, session_uuid).await {
        Ok(s) => s,
        Err(_) => return flash_redirect(flash.error("Session not found"), "/sessions"),
    };

    let opener_id = match contest_svc::resolve_user_db_id(&state, &auth_user.uuid).await {
        Ok(id) => id,
        Err(_) => return flash_redirect(flash.error("User not found"), &back),
    };

    if session.user_id != opener_id && !perms.sessions_supervise {
        return flash_redirect(
            flash.error(
                "You can only contest your own session decisions (or need sessions:supervise)",
            ),
            &back,
        );
    }

    match contest_svc::open_contestation(&state, &session, opener_id, &form.open_reason).await {
        Ok(created) => {
            notify_contestation(
                &state,
                "mcp_contestation_opened",
                &created.uuid.to_string(),
                &created.decision_id,
                &created.status,
            )
            .await;
            crate::handlers::web::broadcast_contestation_badge(&state).await;
            if let Err(e) = crate::services::mcp_mail::queue_contestation_opened(
                &state,
                &created,
                &auth_user.username,
            )
            .await
            {
                tracing::warn!(
                    contestation = %created.uuid,
                    error = %e,
                    "Failed to queue mcp.contestation_opened emails"
                );
            }
            flash_redirect(
                flash.success(format!("Contestation opened for {}", created.decision_id)),
                &format!("/sessions/contestations/{}", created.uuid),
            )
        }
        Err(e) => flash_redirect(flash.error(e.to_string()), &back),
    }
}

/// POST `/sessions/mcp/contestations/{uuid}/claim`
pub async fn contestation_claim_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<ContestationClaimForm>,
) -> Response {
    let flash = incoming_flash.flash();
    let detail = format!("/sessions/mcp/contestations/{uuid_str}");
    if !perms.sessions_supervise {
        return flash_redirect(
            flash.error("You need sessions:supervise to claim contestations"),
            &detail,
        );
    }
    if !csrf_ok(&state, &jar, &form.csrf_token) {
        return flash_redirect(flash.error("Invalid CSRF token"), &detail);
    }
    let Ok(cuuid) = Uuid::parse_str(&uuid_str) else {
        return flash_redirect(
            flash.error("Invalid contestation id"),
            "/sessions/mcp/contestations",
        );
    };
    let actor = match contest_svc::resolve_user_db_id(&state, &auth_user.uuid).await {
        Ok(id) => id,
        Err(_) => return flash_redirect(flash.error("User not found"), &detail),
    };
    match contest_svc::claim_contestation(&state, cuuid, actor).await {
        Ok(row) => {
            notify_contestation(
                &state,
                "mcp_contestation_claimed",
                &row.uuid.to_string(),
                &row.decision_id,
                &row.status,
            )
            .await;
            crate::handlers::web::broadcast_contestation_badge(&state).await;
            flash_redirect(flash.success("Contestation claimed for review"), &detail)
        }
        Err(e) => flash_redirect(flash.error(e.to_string()), &detail),
    }
}

/// POST `/sessions/mcp/contestations/{uuid}/uphold`
pub async fn contestation_uphold_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<ContestationUpholdForm>,
) -> Response {
    let flash = incoming_flash.flash();
    let detail = format!("/sessions/mcp/contestations/{uuid_str}");
    if !perms.sessions_supervise {
        return flash_redirect(
            flash.error("You need sessions:supervise to resolve contestations"),
            &detail,
        );
    }
    if !csrf_ok(&state, &jar, &form.csrf_token) {
        return flash_redirect(flash.error("Invalid CSRF token"), &detail);
    }
    let Ok(cuuid) = Uuid::parse_str(&uuid_str) else {
        return flash_redirect(
            flash.error("Invalid contestation id"),
            "/sessions/mcp/contestations",
        );
    };
    let actor = match contest_svc::resolve_user_db_id(&state, &auth_user.uuid).await {
        Ok(id) => id,
        Err(_) => return flash_redirect(flash.error("User not found"), &detail),
    };
    match contest_svc::uphold_contestation(&state, cuuid, actor, &form.resolution_note).await {
        Ok(row) => {
            notify_contestation(
                &state,
                "mcp_contestation_resolved",
                &row.uuid.to_string(),
                &row.decision_id,
                &row.status,
            )
            .await;
            crate::handlers::web::broadcast_contestation_badge(&state).await;
            if let Err(e) = crate::services::mcp_mail::queue_contestation_resolved(
                &state,
                &row,
                &auth_user.username,
                "upheld",
            )
            .await
            {
                tracing::warn!(
                    contestation = %row.uuid,
                    error = %e,
                    "Failed to queue mcp.contestation_resolved email"
                );
            }
            flash_redirect(
                flash.success("Decision upheld — contestation closed"),
                &detail,
            )
        }
        Err(e) => flash_redirect(flash.error(e.to_string()), &detail),
    }
}

/// POST `/sessions/mcp/contestations/{uuid}/overturn`
pub async fn contestation_overturn_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<ContestationOverturnForm>,
) -> Response {
    let flash = incoming_flash.flash();
    let detail = format!("/sessions/mcp/contestations/{uuid_str}");
    if !perms.sessions_supervise {
        return flash_redirect(
            flash.error("You need sessions:supervise to resolve contestations"),
            &detail,
        );
    }
    if !csrf_ok(&state, &jar, &form.csrf_token) {
        return flash_redirect(flash.error("Invalid CSRF token"), &detail);
    }
    let Ok(cuuid) = Uuid::parse_str(&uuid_str) else {
        return flash_redirect(
            flash.error("Invalid contestation id"),
            "/sessions/mcp/contestations",
        );
    };
    let actor = match contest_svc::resolve_user_db_id(&state, &auth_user.uuid).await {
        Ok(id) => id,
        Err(_) => return flash_redirect(flash.error("User not found"), &detail),
    };
    match contest_svc::overturn_contestation(&state, cuuid, actor, &form.resolution_note).await {
        Ok(row) => {
            notify_contestation(
                &state,
                "mcp_contestation_resolved",
                &row.uuid.to_string(),
                &row.decision_id,
                &row.status,
            )
            .await;
            crate::handlers::web::broadcast_contestation_badge(&state).await;
            if let Err(e) = crate::services::mcp_mail::queue_contestation_resolved(
                &state,
                &row,
                &auth_user.username,
                "overturned",
            )
            .await
            {
                tracing::warn!(
                    contestation = %row.uuid,
                    error = %e,
                    "Failed to queue mcp.contestation_resolved email"
                );
            }
            flash_redirect(
                flash.success(
                    "Decision overturned — group membership restored; subject must Connect again",
                ),
                &detail,
            )
        }
        Err(e) => flash_redirect(flash.error(e.to_string()), &detail),
    }
}

fn csrf_ok(state: &AppState, jar: &CookieJar, token: &str) -> bool {
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        token,
    )
}

async fn notify_contestation(
    state: &AppState,
    event_type: &str,
    contestation_id: &str,
    decision_id: &str,
    status: &str,
) {
    let _ = state
        .broadcast
        .send(
            &crate::services::broadcast::WsChannel::Notifications,
            crate::services::broadcast::WsMessage::new(
                "jit-notification",
                format!(
                    r#"{{"type":"{event_type}","contestation_id":"{contestation_id}","decision_id":"{decision_id}","status":"{status}"}}"#
                ),
            ),
        )
        .await;
}

fn truncate_reason(s: &str, max: usize) -> String {
    let t = s.trim();
    if t.chars().count() <= max {
        t.to_string()
    } else {
        let truncated: String = t.chars().take(max.saturating_sub(1)).collect();
        format!("{truncated}…")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn contestation_mutations_broadcast_sidebar_badge() {
        let src = include_str!("access_contestation.rs");
        for needle in [
            "contestation_open_web",
            "contestation_claim_web",
            "contestation_uphold_web",
            "contestation_overturn_web",
        ] {
            let start = src
                .find(needle)
                .unwrap_or_else(|| panic!("{needle} must exist"));
            let rest = &src[start..];
            let end = rest.find("\npub async fn ").unwrap_or(rest.len());
            assert!(
                rest[..end].contains("broadcast_contestation_badge"),
                "{needle} must push the sidebar contestation badge"
            );
        }
    }

    #[test]
    fn claim_emits_contestation_claimed_event() {
        let src = include_str!("access_contestation.rs");
        let start = src
            .find("contestation_claim_web")
            .expect("contestation_claim_web must exist");
        let rest = &src[start..];
        let end = rest.find("\npub async fn ").unwrap_or(rest.len());
        assert!(
            rest[..end].contains("mcp_contestation_claimed"),
            "claim must notify so the contestation list can live-refresh"
        );
    }

    #[test]
    fn open_web_redirects_to_user_zone_detail() {
        let src = include_str!("access_contestation.rs");
        let start = src
            .find("contestation_open_web")
            .expect("contestation_open_web must exist");
        let rest = &src[start..];
        let end = rest.find("\npub async fn ").unwrap_or(rest.len());
        let body = &rest[..end];
        assert!(
            body.contains("/sessions/contestations/{}"),
            "open must land on the User Zone status page"
        );
        assert!(
            !body.contains("/sessions/mcp/contestations/{}"),
            "open must not bounce the subject into the MCP nest"
        );
    }

    #[test]
    fn user_zone_detail_is_read_only() {
        let src = include_str!("access_contestation.rs");
        let start = src
            .find("async fn contestation_detail_inner")
            .expect("contestation_detail_inner must exist");
        let rest = &src[start..];
        let end = rest.find("\npub async fn ").unwrap_or(rest.len());
        let body = &rest[..end];
        assert!(
            body.contains("user_zone") && body.contains("mcp_can_supervise"),
            "detail must derive mcp_can_supervise from zone + permission"
        );
        assert!(
            !body.contains("mcp_can_supervise: true"),
            "detail must not hardcode MCP nav as supervise"
        );
        assert!(
            body.contains("!user_zone && perms.sessions_supervise"),
            "claim/resolve stay on the nest; User Zone is status-only"
        );
        assert!(
            body.contains("user_zone_miss") && body.contains("Contestation not found"),
            "User Zone must use one miss copy for unknown and forbidden"
        );
    }
}
