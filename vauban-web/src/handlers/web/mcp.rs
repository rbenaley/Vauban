//! MCP asset connect — Lot 1a control plane.
//!
//! Opens a time-boxed MCP session: mints `vbw_`, persists `proxy_sessions`,
//! registers the session on `vauban-proxy-mcp` (HTTP bridge in local/dev),
//! and shows the operator the one-time bearer + gateway URL.

use super::*;
use crate::auth::permissions::PermissionContext;
use crate::error::AppError;
use crate::models::asset::{Asset, AssetType};
use crate::models::session::{NewProxySession, SessionType};
use crate::services::mcp_session::{
    MCP_PROTOCOL_VERSIONS, clamp_ttl_capped, open_on_proxy, resolve_effective_allowed_tools,
};
use askama::Template;
use axum::http::HeaderMap;
use chrono::{Duration, Utc};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct ConnectMcpForm {
    pub csrf_token: String,
    pub justification: Option<String>,
    pub requested_duration_seconds: Option<i64>,
}

#[derive(Template)]
#[template(path = "assets/mcp_session.html")]
struct McpSessionTemplate {
    title: String,
    user: Option<UserContext>,
    vauban: crate::templates::base::VaubanConfig,
    messages: Vec<crate::templates::base::FlashMessage>,
    language_code: String,
    sidebar_content: Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    header_user: Option<UserContext>,
    session_id: String,
    url: String,
    bearer: String,
    expires_at: String,
    asset_name: String,
    mcp_protocol_versions: Vec<&'static str>,
    allowed_tools: Vec<String>,
}

/// HTMX error toast — same contract as `connect_ssh` / `connect_rdp`
/// (`200` + `HX-Trigger: showToast`). A non-2xx body is invisible when
/// the client uses `hx-swap="none"` (justification modal / asset list).
fn htmx_toast_error(message: &str) -> Response {
    let escaped_message = message.replace('\\', r"\\").replace('"', r#"\""#);
    let trigger_json = format!(
        r#"{{"showToast": {{"message": "{}", "type": "error"}}}}"#,
        escaped_message
    );
    (
        axum::http::StatusCode::OK,
        [
            ("HX-Trigger", trigger_json),
            ("Content-Type", "text/html".to_string()),
        ],
        "",
    )
        .into_response()
}

fn fail_connect(
    is_htmx: bool,
    flash: crate::middleware::flash::Flash,
    msg: impl Into<String>,
) -> Response {
    let msg = msg.into();
    if is_htmx {
        return htmx_toast_error(&msg);
    }
    flash_redirect(flash.error(msg), "/assets")
}

/// Prefer the root cause for operator toasts (TCP refused, access deny),
/// not the `Internal server error:` Display wrapper.
fn operator_message(err: &AppError) -> String {
    match err {
        AppError::Internal(inner) => inner.to_string(),
        AppError::Validation(m)
        | AppError::Authorization(m)
        | AppError::NotFound(m)
        | AppError::Auth(m)
        | AppError::Conflict(m)
        | AppError::NotImplemented(m)
        | AppError::Config(m)
        | AppError::Ipc(m) => m.clone(),
        other => other.to_string(),
    }
}

/// POST `/assets/{uuid}/connect-mcp`
#[allow(clippy::too_many_arguments)] // axum extractors, not a data clump
pub async fn connect_mcp(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: PermissionContext,
    browser_tz: BrowserTz,
    flash: IncomingFlash,
    headers: HeaderMap,
    jar: CookieJar,
    client_addr: crate::middleware::ClientAddr,
    axum::extract::Path(asset_uuid): axum::extract::Path<Uuid>,
    Form(form): Form<ConnectMcpForm>,
) -> Response {
    let is_htmx = headers.get("HX-Request").is_some();
    let flash = flash.flash();

    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return fail_connect(is_htmx, flash, "Invalid CSRF token");
    }

    if !perms.assets_connect_mcp {
        return fail_connect(
            is_htmx,
            flash,
            "You do not have permission to open MCP sessions",
        );
    }

    // Always required for MCP (agents); length matches SSH/RDP SEC-03
    // modal (min 10 / max 1000), independent of require_justification flag.
    let justification = form.justification.unwrap_or_default().trim().to_string();
    if justification.len() < 10 || justification.len() > 1000 {
        return fail_connect(
            is_htmx,
            flash,
            "Justification is required for MCP sessions (10..1000 characters)",
        );
    }

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "DB pool for connect_mcp");
            return fail_connect(is_htmx, flash, "Database unavailable");
        }
    };

    let asset: Asset = match crate::schema::assets::table
        .filter(crate::schema::assets::uuid.eq(asset_uuid))
        .filter(crate::schema::assets::is_deleted.eq(false))
        .first(&mut conn)
        .await
    {
        Ok(a) => a,
        Err(_) => return fail_connect(is_htmx, flash, "Asset not found"),
    };

    if asset.asset_type != AssetType::Mcp {
        return fail_connect(
            is_htmx,
            flash,
            format!("Asset type '{}' is not MCP", asset.asset_type),
        );
    }

    let user_uuid = match Uuid::parse_str(&auth_user.uuid) {
        Ok(u) => u,
        Err(_) => return fail_connect(is_htmx, flash, "Invalid user"),
    };
    let (user_id, is_active): (i32, bool) = match crate::schema::users::table
        .filter(crate::schema::users::uuid.eq(user_uuid))
        .select((crate::schema::users::id, crate::schema::users::is_active))
        .first(&mut conn)
        .await
    {
        Ok(row) => row,
        Err(_) => return fail_connect(is_htmx, flash, "User not found"),
    };
    if !is_active {
        return fail_connect(is_htmx, flash, "Account deactivated");
    }

    let access_result = match crate::services::access::can_access_asset(
        &state.access_client,
        &mut conn,
        user_id,
        asset.id,
        "mcp",
    )
    .await
    {
        Ok(r) if r.allowed => r,
        Ok(_) => {
            return fail_connect(
                is_htmx,
                flash,
                "No access rule grants you MCP access to this asset",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "access check failed for MCP");
            return fail_connect(is_htmx, flash, "Access check failed");
        }
    };
    if access_result.require_mfa && !auth_user.mfa_verified {
        return fail_connect(is_htmx, flash, "MFA verification required for this asset");
    }

    let ttl = clamp_ttl_capped(
        form.requested_duration_seconds,
        access_result.max_session_duration,
        Some(state.config.mcp.session_ttl_clamped()),
    );
    let expires_at = Utc::now() + Duration::seconds(ttl);
    let allowed_tools = match resolve_effective_allowed_tools(&mut conn, user_id, &asset).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "resolve MCP allowed_tools failed");
            return fail_connect(is_htmx, flash, "Failed to resolve MCP tool whitelist");
        }
    };
    if allowed_tools.as_ref().is_some_and(|t| t.is_empty()) {
        return fail_connect(
            is_htmx,
            flash,
            format!(
                "No MCP tools granted for asset '{}': access-rule allow-list ∩ this asset's approved catalogue is empty (Off tools are not granted)",
                asset.name
            ),
        );
    }

    let trusted = state.config.security.parsed_trusted_proxies();
    let client_ip_network =
        crate::middleware::extract_client_ip(&headers, client_addr.addr(), &trusted);

    let session_uuid = Uuid::new_v4();
    let new_session = NewProxySession {
        uuid: session_uuid,
        user_id,
        asset_id: asset.id,
        credential_id: "mcp".to_string(),
        credential_username: "mcp".to_string(),
        session_type: SessionType::Mcp,
        status: "active".to_string(),
        client_ip: client_ip_network,
        client_user_agent: None,
        proxy_instance: Some("proxy_mcp".to_string()),
        justification: Some(justification.clone()),
        is_recorded: true,
        metadata: serde_json::json!({
            "mcp_protocol_versions": MCP_PROTOCOL_VERSIONS,
            // Connect UI: no API token — omit api_key_id (M7).
        }),
        max_session_duration: Some(ttl as i32),
        expires_at: Some(expires_at),
        industrial_protocol: None,
        ews_uuid: None,
        tunnel_target_addr: None,
    };

    if let Err(e) = diesel::insert_into(crate::schema::proxy_sessions::table)
        .values(&new_session)
        .execute(&mut conn)
        .await
    {
        tracing::error!(error = %e, "insert MCP proxy_session failed");
        return fail_connect(is_htmx, flash, "Failed to create session");
    }

    let gateway_url = std::env::var("VAUBAN_MCP_PROXY_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:19443/mcp".to_string());

    let bearer = match open_on_proxy(
        &state,
        &auth_user.uuid,
        None, // Connect UI: human JWT, no api_key_id (M7)
        &asset,
        session_uuid,
        expires_at,
        &justification,
        allowed_tools.clone(),
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "connect_mcp: failed to open session on proxy-mcp");
            let _ = diesel::delete(
                crate::schema::proxy_sessions::table
                    .filter(crate::schema::proxy_sessions::uuid.eq(session_uuid)),
            )
            .execute(&mut conn)
            .await;
            // Surface supervisor TCP detail verbatim (SSH parity), e.g.
            // "Connection to 127.0.0.1:19001 failed: Connection refused …".
            return fail_connect(is_htmx, flash, operator_message(&e));
        }
    };

    let base = BaseTemplate::new(
        "MCP session".to_string(),
        Some(user_context_from_auth(&auth_user)),
        browser_tz.0,
    )
    .with_current_path("/assets");
    let (title, user, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let tools_for_ui = allowed_tools.unwrap_or_default();
    let tmpl = McpSessionTemplate {
        title,
        user,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        session_id: session_uuid.to_string(),
        url: gateway_url,
        bearer,
        expires_at: expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        asset_name: asset.name,
        mcp_protocol_versions: MCP_PROTOCOL_VERSIONS.to_vec(),
        allowed_tools: tools_for_ui,
    };

    match tmpl.render() {
        Ok(html) => {
            if is_htmx {
                // Justification modal uses `htmx.ajax(..., {swap:'none'})`;
                // asset-list MCP form may also use swap none. Override so
                // the one-time bearer page still replaces the document.
                return (
                    axum::http::StatusCode::OK,
                    [
                        ("HX-Retarget", "body"),
                        ("HX-Reswap", "outerHTML"),
                        ("Content-Type", "text/html; charset=utf-8"),
                    ],
                    html,
                )
                    .into_response();
            }
            Html(html).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "render mcp_session.html");
            fail_connect(is_htmx, flash, "Session opened but page render failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn htmx_toast_error_emits_show_toast_trigger() {
        let resp = htmx_toast_error(r#"Connection to 127.0.0.1:19001 failed: "refused""#);
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let trigger = resp
            .headers()
            .get("HX-Trigger")
            .expect("HX-Trigger")
            .to_str()
            .unwrap();
        assert!(trigger.contains("showToast"));
        assert!(trigger.contains("Connection to 127.0.0.1:19001 failed"));
        assert!(trigger.contains(r#"\"refused\""#) || trigger.contains("refused"));
    }

    #[test]
    fn operator_message_strips_internal_wrapper() {
        let err = AppError::Internal(anyhow::anyhow!(
            "Connection to 127.0.0.1:19001 failed: Connection refused (os error 61)"
        ));
        let msg = operator_message(&err);
        assert!(msg.starts_with("Connection to 127.0.0.1:19001"));
        assert!(!msg.contains("Internal server error"));
    }

    #[test]
    fn connect_always_evaluates_access_rules() {
        let src = include_str!("mcp.rs");
        let start = src.find("pub async fn connect_mcp").expect("connect_mcp");
        let rest = &src[start..];
        let end = rest.find("\n#[cfg(test)]").unwrap_or(rest.len());
        let body = &rest[..end];
        assert!(body.contains("can_access_asset"));
        assert!(body.contains("assets_connect_mcp"));
        assert!(
            body.contains("require_mfa") && body.contains("mfa_verified"),
            "connect-mcp must apply the same per-asset MFA gate as /api/v1/sessions"
        );
        assert!(
            body.contains("clamp_ttl_capped") && body.contains("max_session_duration"),
            "connect-mcp must honour the access-rule session cap"
        );
        assert!(
            body.contains("validate_double_submit"),
            "connect-mcp must validate CSRF like connect_ssh"
        );
        assert!(!body.contains("is_superuser"));
        assert!(!body.contains("sessions_bypass_access_rules"));
        assert!(justification_bounds_match_sec03());
    }

    fn justification_bounds_match_sec03() -> bool {
        let src = include_str!("mcp.rs");
        src.contains("justification.len() < 10 || justification.len() > 1000")
    }
}
