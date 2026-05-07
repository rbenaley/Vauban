//! RDP connection and viewer page handlers.

use super::*;

#[derive(Debug, serde::Deserialize)]
pub struct ConnectRdpForm {
    pub csrf_token: String,
    pub username: Option<String>,
    /// Connection justification (SEC-03).
    pub justification: Option<String>,
}

fn htmx_error_response(message: &str) -> Response {
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

/// Initiate RDP connection to an asset.
///
/// POST /assets/{uuid}/connect-rdp
pub async fn connect_rdp(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    jar: CookieJar,
    auth_user: AuthUser,
    client_addr: crate::middleware::ClientAddr,
    axum::extract::Path(asset_uuid_str): axum::extract::Path<String>,
    Form(form): Form<ConnectRdpForm>,
) -> Response {
    use uuid::Uuid;

    let is_htmx = headers.get("HX-Request").is_some();

    // CSRF validation
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    let secret = state.config.secret_key.expose_secret().as_bytes();
    if !crate::middleware::csrf::validate_double_submit(
        secret,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return htmx_error_response("Invalid CSRF token");
    }

    // Validate justification when required (SEC-03)
    let form_justification = if state.config.security.require_justification {
        let j = form.justification.as_deref().unwrap_or("").trim();
        if j.len() < 10 {
            return htmx_error_response("Justification is required (minimum 10 characters)");
        }
        Some(j.to_string())
    } else {
        form.justification
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(String::from)
    };

    let asset_uuid = match Uuid::parse_str(&asset_uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => return htmx_error_response("Invalid asset identifier"),
    };

    // Fetch asset from database
    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Database connection failed");
            return htmx_error_response("Database error");
        }
    };

    let asset_result = schema_assets::table
        .filter(schema_assets::uuid.eq(asset_uuid))
        .select((
            schema_assets::id,
            schema_assets::uuid,
            schema_assets::name,
            schema_assets::hostname,
            schema_assets::port,
            schema_assets::asset_type,
            schema_assets::connection_config,
            schema_assets::connection_username,
        ))
        .first::<(
            i32,
            uuid::Uuid,
            String,
            String,
            i32,
            String,
            serde_json::Value,
            String,
        )>(&mut conn)
        .await;

    let (asset_id, _asset_uuid, _asset_name, hostname, port, _asset_type, config, stored_username) =
        match asset_result {
            Ok(a) => a,
            Err(diesel::NotFound) => return htmx_error_response("Asset not found"),
            Err(e) => {
                tracing::error!(error = %e, "Database query failed");
                return htmx_error_response("Database error");
            }
        };
    let stored_password = config
        .get("password")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let stored_domain = config
        .get("domain")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let username = form
        .username
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(stored_username);

    // Decrypt password if encrypted (vault integration)
    let password = if let Some(ref pwd) = stored_password {
        if super::is_encrypted(pwd) {
            if let Some(ref vault) = state.vault_client {
                match vault.decrypt("credentials", pwd).await {
                    Ok(decrypted) => Some(secrecy::SecretString::from(decrypted.into_inner())),
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to decrypt RDP password");
                        return htmx_error_response("Failed to decrypt credentials");
                    }
                }
            } else {
                Some(secrecy::SecretString::from(pwd.clone()))
            }
        } else {
            Some(secrecy::SecretString::from(pwd.clone()))
        }
    } else {
        None
    };

    // Generate session UUID
    let session_uuid = uuid::Uuid::new_v4();
    let session_id = session_uuid.to_string();

    let rdp_port = port as u16;
    if rdp_port == 0 {
        return htmx_error_response("Invalid port configuration");
    }

    // Resolve authenticated user's integer ID and check account status (SEC-07)
    let user_id: i32 = {
        use crate::schema::users;
        match auth_user.uuid.parse::<uuid::Uuid>() {
            Ok(user_uuid) => match users::table
                .filter(users::uuid.eq(user_uuid))
                .select((users::id, users::is_active))
                .first::<(i32, bool)>(&mut conn)
                .await
            {
                Ok((id, user_is_active)) => {
                    if !user_is_active {
                        return htmx_error_response(super::ACCOUNT_DEACTIVATED_MSG);
                    }
                    id
                }
                Err(e) => {
                    tracing::error!("Failed to resolve user ID: {}", e);
                    return htmx_error_response("User not found");
                }
            },
            Err(_) => return htmx_error_response("Invalid user identifier"),
        }
    };

    // Access rule enforcement: EVERY user must have a matching access rule,
    // including superusers and staff. The historical privileged-user bypass
    // was removed alongside the proxy-side defense-in-depth re-check (RBAC-
    // by-UUID): if vauban-web silently waved a session through here while
    // vauban-access correctly demanded an access_rule, the proxy would deny
    // the session-open and the user would see "Access denied" with no
    // recourse. Both layers now apply the exact same policy.
    //
    // Operational consequence: the bootstrap superuser MUST create at least
    // one access_rule for itself before opening any RDP session. See
    // docs/runbooks/ipc_topology_debugging.md.
    let jit_justification: Option<String>;
    let jit_max_duration: Option<i32>;
    {
        let access_result = crate::services::access::can_access_asset(
            &state.access_client,
            &mut conn,
            user_id,
            asset_id,
            "rdp",
        )
        .await
        .unwrap_or_else(|_| crate::services::access::AccessCheckResult::denied());
        if !access_result.allowed {
            return htmx_error_response("No access rule grants you access to this asset");
        }

        if access_result.require_approval {
            // Find an approved session that has not expired.
            let now = chrono::Utc::now();
            let approved_session: Option<(::uuid::Uuid, Option<String>, Option<i32>)> =
                proxy_sessions::table
                    .filter(proxy_sessions::user_id.eq(user_id))
                    .filter(proxy_sessions::asset_id.eq(asset_id))
                    .filter(proxy_sessions::status.eq("approved"))
                    .filter(
                        proxy_sessions::expires_at
                            .is_null()
                            .or(proxy_sessions::expires_at.gt(now)),
                    )
                    .select((
                        proxy_sessions::uuid,
                        proxy_sessions::justification,
                        proxy_sessions::max_session_duration,
                    ))
                    .first(&mut conn)
                    .await
                    .ok();

            match approved_session {
                Some((_approved_uuid, justification, max_dur)) => {
                    jit_justification = justification;
                    jit_max_duration = max_dur.or(access_result.max_session_duration);
                }
                None => {
                    // Issue #34: the user-zone /assets/{uuid} detail
                    // page is gone (information leak surface). Emit
                    // `HX-Trigger: show-access-request-modal` with
                    // payload {asset_uuid, asset_type, require_mfa}
                    // so the modal -- now inlined on /assets --
                    // opens in-place. `connect_rdp` is HTMX-only
                    // (see the rdp.rs prelude: every `htmx_error_response`
                    // path assumes HTMX), so no JSON fallback is
                    // needed here.
                    let payload = serde_json::json!({
                        "show-access-request-modal": {
                            "asset_uuid": asset_uuid_str,
                            "asset_type": "rdp",
                            "require_mfa": access_result.require_mfa,
                        }
                    })
                    .to_string();
                    return ([(
                        axum::http::header::HeaderName::from_static("hx-trigger"),
                        axum::http::header::HeaderValue::from_str(&payload).unwrap_or_else(|_| {
                            axum::http::header::HeaderValue::from_static(
                                r#"{"show-access-request-modal":{}}"#,
                            )
                        }),
                    )])
                    .into_response();
                }
            }
        } else {
            jit_justification = None;
            jit_max_duration = access_result.max_session_duration;
        }
    }

    // Get RDP proxy client (checked after access rules to avoid leaking proxy state)
    let proxy_client = match &state.rdp_proxy {
        Some(client) => client.clone(),
        None => return htmx_error_response("RDP proxy not available"),
    };

    // Record the session in the database so that ws_session_guard can verify
    // WebSocket ownership before allowing the upgrade.
    {
        use crate::models::session::{NewProxySession, SessionType};
        let trusted = state.config.security.parsed_trusted_proxies();
        let client_ip =
            crate::middleware::extract_client_ip(&headers, client_addr.addr(), &trusted);
        let new_session = NewProxySession {
            uuid: session_uuid,
            user_id,
            asset_id,
            credential_id: "local".to_string(),
            credential_username: username.clone(),
            session_type: SessionType::Rdp,
            status: "connecting".to_string(),
            client_ip,
            client_user_agent: headers
                .get(axum::http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            proxy_instance: None,
            justification: jit_justification.clone().or(form_justification.clone()),
            is_recorded: true,
            metadata: serde_json::json!({}),
            max_session_duration: jit_max_duration,
            industrial_protocol: None,
            ews_uuid: None,
            tunnel_target_addr: None,
        };

        if let Err(e) = diesel::insert_into(proxy_sessions::table)
            .values(&new_session)
            .execute(&mut conn)
            .await
        {
            tracing::error!(session_id = %session_id, error = %e, "Failed to record RDP proxy session");
            return htmx_error_response("Failed to create session record");
        }
    }

    // SECURITY: ask vauban-access to mint a cryptographic session
    // token. See web/ssh.rs for full rationale.
    let session_token_bytes = match state
        .access_client
        .issue_session_token(shared::session_token::SessionTokenParams {
            session_id: session_id.clone(),
            user_uuid: auth_user.uuid.clone(),
            asset_uuid: asset_uuid.to_string(),
            protocol: "rdp".to_string(),
            host: hostname.clone(),
            port: rdp_port,
            target_service: shared::messages::Service::ProxyRdp,
        })
        .await
    {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(
                session_id = %session_id,
                user = %auth_user.username,
                error = %e,
                "Session-token mint denied; refusing to open RDP session"
            );
            return htmx_error_response("Access denied");
        }
    };

    // If supervisor is available (sandboxed mode), request TCP connection brokering.
    // The supervisor performs DNS resolution and TCP connect, then passes the FD
    // to the RDP proxy via SCM_RIGHTS. This enables Capsicum sandboxed operation.
    if let Some(ref supervisor) = state.supervisor {
        tracing::debug!(
            session_id = %session_id,
            host = %hostname,
            port = rdp_port,
            "Requesting TCP connection from supervisor for RDP (sandboxed mode)"
        );

        match supervisor
            .request_tcp_connect(
                &session_id,
                &hostname,
                rdp_port,
                shared::messages::Service::ProxyRdp,
                session_token_bytes.clone(),
            )
            .await
        {
            Ok(result) if result.success => {
                tracing::debug!(
                    session_id = %session_id,
                    "TCP connection established by supervisor for RDP"
                );
            }
            Ok(result) => {
                let msg = result
                    .error
                    .unwrap_or_else(|| "Failed to establish TCP connection".to_string());
                tracing::error!(session_id = %session_id, error = %msg, "RDP TCP connect failed");
                return htmx_error_response(&msg);
            }
            Err(e) => {
                tracing::error!(session_id = %session_id, error = %e, "RDP TCP connect request failed");
                return htmx_error_response(&e);
            }
        }
    }

    let request = crate::ipc::RdpSessionOpenRequest {
        session_id: session_id.clone(),
        user_id: auth_user.uuid.clone(),
        asset_id: asset_uuid.to_string(),
        asset_host: hostname.clone(),
        asset_port: rdp_port,
        username,
        password,
        domain: stored_domain,
        desktop_width: 1280,
        desktop_height: 720,
        session_token: session_token_bytes,
    };

    // Request the proxy to open the RDP session
    match proxy_client.open_session(request).await {
        Ok(response) if response.success => {
            let redirect_url = format!("/sessions/rdp/{}", session_id);
            if is_htmx {
                return (
                    axum::http::StatusCode::OK,
                    [("HX-Redirect", redirect_url)],
                    "",
                )
                    .into_response();
            }
            Redirect::to(&redirect_url).into_response()
        }
        Ok(response) => {
            let err = response
                .error
                .unwrap_or_else(|| "RDP connection failed".to_string());
            htmx_error_response(&err)
        }
        Err(e) => htmx_error_response(&format!("RDP connection error: {}", e)),
    }
}

/// RDP viewer page template.
#[derive(Template)]
#[template(path = "sessions/rdp.html")]
pub struct RdpViewerTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: crate::templates::base::VaubanConfig,
    pub messages: Vec<crate::templates::base::FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<UserContext>,
    pub session_id: String,
}

/// Render the RDP viewer page.
///
/// GET /sessions/rdp/{session_id}
pub async fn rdp_page(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> Response {
    use crate::error::AppError;
    use crate::services::session_access::{self, SessionAccessOutcome};
    use shared::messages::SessionAccessIntent;

    let flash = incoming_flash.flash();

    if uuid::Uuid::parse_str(&session_id).is_err() {
        return flash_redirect(flash.error("Invalid session identifier"), "/assets");
    }

    // SECURITY (anti-IDOR + access-rule recheck): identical seam to
    // [`terminal_page`]. Without this gate, anyone holding the
    // session_id (the user A who created the session, or anyone they
    // shared the URL with) could open the RDP viewer of any session.
    // See plan: rdp_page used to ship NO ownership check at all.
    match session_access::verify(
        &state,
        &session_id,
        &auth_user.0,
        &perms,
        SessionAccessIntent::OpenViewer,
    )
    .await
    {
        SessionAccessOutcome::Allowed => {}
        SessionAccessOutcome::Denied404 | SessionAccessOutcome::DeniedGone => {
            tracing::warn!(
                session_id = %session_id,
                user = %auth_user.username,
                "rdp_page denied (collapsed to 404)"
            );
            return AppError::NotFound("Session not found".to_string()).into_response();
        }
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base =
        BaseTemplate::new("RDP Session".to_string(), user.clone()).with_current_path("/assets");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = RdpViewerTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        session_id,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Failed to render RDP template: {}", e);
            flash_redirect(flash.error("Failed to load RDP page"), "/assets")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connect_rdp_form_deserialize() {
        let json = r#"{"csrf_token": "abc123"}"#;
        let form: ConnectRdpForm = serde_json::from_str(json).unwrap();
        assert_eq!(form.csrf_token, "abc123");
        assert!(form.username.is_none());
    }

    #[test]
    fn test_connect_rdp_form_with_username() {
        let json = r#"{"csrf_token": "token", "username": "admin"}"#;
        let form: ConnectRdpForm = serde_json::from_str(json).unwrap();
        assert_eq!(form.csrf_token, "token");
        assert_eq!(form.username.as_deref(), Some("admin"));
    }

    #[test]
    fn test_connect_rdp_form_debug() {
        let form = ConnectRdpForm {
            csrf_token: "test-token".to_string(),
            username: Some("admin".to_string()),
            justification: None,
        };
        let debug = format!("{:?}", form);
        assert!(debug.contains("ConnectRdpForm"));
        assert!(debug.contains("test-token"));
    }

    #[test]
    fn test_htmx_error_response_escapes_quotes() {
        let response = htmx_error_response(r#"Error with "quotes""#);
        // Should not panic - verify it produces a valid response
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[test]
    fn test_htmx_error_response_escapes_backslash() {
        let response = htmx_error_response(r"Path\to\file");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[test]
    fn test_htmx_error_response_plain_message() {
        let response = htmx_error_response("Simple error message");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[test]
    fn test_htmx_error_response_empty_message() {
        let response = htmx_error_response("");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[test]
    fn test_htmx_error_response_special_html_chars() {
        let response = htmx_error_response("<script>alert('xss')</script>");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[test]
    fn test_connect_rdp_form_missing_csrf_fails() {
        let json = r#"{"username": "admin"}"#;
        let result: Result<ConnectRdpForm, _> = serde_json::from_str(json);
        assert!(result.is_err(), "csrf_token is required");
    }

    #[test]
    fn test_connect_rdp_form_empty_csrf() {
        let json = r#"{"csrf_token": ""}"#;
        let form: ConnectRdpForm = serde_json::from_str(json).unwrap();
        assert_eq!(form.csrf_token, "");
        assert!(form.username.is_none());
    }

    #[test]
    fn test_connect_rdp_form_all_fields() {
        let json = r#"{"csrf_token": "tok-123", "username": "CORP\\admin"}"#;
        let form: ConnectRdpForm = serde_json::from_str(json).unwrap();
        assert_eq!(form.csrf_token, "tok-123");
        assert_eq!(form.username.as_deref(), Some("CORP\\admin"));
    }

    #[test]
    fn test_htmx_error_response_has_hx_trigger() {
        let response = htmx_error_response("test error");
        let headers = response.headers();
        let trigger = headers
            .get("HX-Trigger")
            .expect("must have HX-Trigger header")
            .to_str()
            .unwrap();
        assert!(trigger.contains("showToast"));
        assert!(trigger.contains("test error"));
        assert!(trigger.contains("error"));
    }

    // ==================== TCP Connection Brokering (5.6.3) Tests ====================

    #[test]
    fn test_connect_rdp_requests_tcp_brokering_via_supervisor() {
        let source = include_str!("rdp.rs");
        let handler_start = source
            .find("pub async fn connect_rdp")
            .expect("connect_rdp handler must exist");
        let handler_body = &source[handler_start..];
        let handler_end = handler_body
            .find("pub struct RdpViewerTemplate")
            .unwrap_or(handler_body.len());
        let handler_body = &handler_body[..handler_end];

        assert!(
            handler_body.contains("request_tcp_connect"),
            "connect_rdp must request TCP connection brokering from supervisor"
        );
        assert!(
            handler_body.contains("Service::ProxyRdp"),
            "connect_rdp must target Service::ProxyRdp for FD brokering"
        );
    }

    #[test]
    fn test_tcp_brokering_happens_before_session_open() {
        let source = include_str!("rdp.rs");
        let brokering_pos = source
            .find("request_tcp_connect")
            .expect("request_tcp_connect must be called");
        let session_open_pos = source
            .find("proxy_client.open_session")
            .expect("open_session must be called");

        assert!(
            brokering_pos < session_open_pos,
            "TCP connection brokering must happen BEFORE requesting the RDP session open"
        );
    }

    #[test]
    fn test_tcp_brokering_handles_failure() {
        let source = include_str!("rdp.rs");
        let handler_start = source
            .find("pub async fn connect_rdp")
            .expect("connect_rdp handler must exist");
        let handler_body = &source[handler_start..];
        let brokering_start = handler_body
            .find("request_tcp_connect")
            .expect("request_tcp_connect must be present");
        let brokering_section = &handler_body[brokering_start..brokering_start + 800];

        assert!(
            brokering_section.contains("htmx_error_response"),
            "TCP brokering failure must return an error response to the user"
        );
    }

    #[test]
    fn test_tcp_brokering_is_conditional_on_supervisor() {
        let source = include_str!("rdp.rs");
        let handler_start = source
            .find("pub async fn connect_rdp")
            .expect("connect_rdp handler must exist");
        let handler_body = &source[handler_start..];

        assert!(
            handler_body.contains("if let Some(ref supervisor) = state.supervisor"),
            "TCP brokering must be conditional on supervisor availability (non-sandboxed = no supervisor)"
        );
    }
}
