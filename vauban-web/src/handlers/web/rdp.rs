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

    // VAU-001 -- mandatory RDP server-certificate pin pre-flight.
    //
    // Mirrors the SSH host-key pre-flight (web/ssh.rs). Runs AFTER the
    // access-rule check (so a user without access hears "No access rule"
    // first, least-info-leak) and BEFORE any session-creation work
    // (proxy_sessions insert, token mint, supervisor TCP broker, IPC).
    // Two refusal cases, both fail-closed:
    //
    // 1. `connection_config.rdp_server_cert_mismatch == true`: a previous
    //    connection saw the live server present a SPKI disagreeing with the
    //    stored pin. Until an admin re-fetches and pins, every new
    //    connection is suspect (rotation vs MITM is indistinguishable).
    //
    // 2. `connection_config.rdp_server_cert_fingerprint` absent / empty: the
    //    asset has no pinned certificate. Pre-fix the proxy accepted ANY
    //    certificate (NoCertificateVerification -- trivial MITM). Pinning is
    //    now mandatory; the admin must trigger
    //    `/assets/manage/{uuid}/fetch-rdp-cert` first.
    //
    // The two literals below are pinned by
    // `scripts/check_rdp_cert_paths.sh` and
    // `tests/web/rdp_cert_no_silent_green_test.rs`.
    let stored_cert_fingerprint = config
        .get("rdp_server_cert_fingerprint")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let stored_cert_mismatch = config
        .get("rdp_server_cert_mismatch")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if stored_cert_mismatch {
        tracing::warn!(
            user = %auth_user.username,
            asset_uuid = %asset_uuid,
            "Refusing RDP connection: server certificate mismatch detected on \
             previous connection. Admin must re-fetch and pin the new certificate."
        );
        return htmx_error_response(
            "RDP server certificate mismatch detected on previous connection. \
             An admin must re-fetch and pin the new certificate before new \
             sessions are allowed.",
        );
    }

    let expected_cert_fingerprint = match stored_cert_fingerprint {
        Some(fp) => fp.to_string(),
        None => {
            tracing::warn!(
                user = %auth_user.username,
                asset_uuid = %asset_uuid,
                "Refusing RDP connection: no server certificate pinned for this asset. \
                 Admin must fetch and pin the certificate first."
            );
            return htmx_error_response(
                "No RDP server certificate pinned for this asset. An admin must \
                 fetch and pin the certificate before sessions can be opened.",
            );
        }
    };

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
        expected_cert_fingerprint: Some(expected_cert_fingerprint),
        session_token: session_token_bytes,
    };

    // Request the proxy to open the RDP session
    match proxy_client.open_session(request).await {
        Ok(response) if response.success => {
            crate::services::emit_audit(
                &state,
                crate::ipc::AuditEvent::new(
                    shared::messages::AuditEventType::SessionRequested,
                    format!(r#"{{"protocol":"rdp","asset":"{}"}}"#, asset_uuid),
                )
                .user(auth_user.uuid.to_string())
                .session(session_id.clone())
                .ip(Some(client_addr.addr().ip())),
            );
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

            // VAU-001: detect a server-certificate mismatch reported by the
            // proxy's PinningServerCertVerifier and persist the flag so the
            // asset detail page shows the red warning state and subsequent
            // connections are refused fail-closed (mirror web/ssh.rs).
            maybe_flag_rdp_cert_mismatch(&mut conn, asset_uuid, &config, &err).await;

            htmx_error_response(&err)
        }
        Err(e) => {
            let msg = format!("RDP connection error: {}", e);
            maybe_flag_rdp_cert_mismatch(&mut conn, asset_uuid, &config, &msg).await;
            htmx_error_response(&msg)
        }
    }
}

/// VAU-001: if `error` indicates the proxy refused the TLS handshake on a
/// server-certificate mismatch (possible MITM), set
/// `connection_config.rdp_server_cert_mismatch = true` so the asset detail
/// page surfaces the red warning and the connect pre-flight refuses new
/// sessions until an admin re-pins. Best-effort: a DB failure is logged but
/// not surfaced (the connection already failed). Mirrors the SSH path.
async fn maybe_flag_rdp_cert_mismatch(
    conn: &mut diesel_async::AsyncPgConnection,
    asset_uuid: uuid::Uuid,
    config: &serde_json::Value,
    error: &str,
) {
    use crate::schema::assets::dsl;

    let is_cert_mismatch = error.contains("certificate mismatch") || error.contains("MITM");
    if !is_cert_mismatch {
        return;
    }

    tracing::warn!(
        asset_uuid = %asset_uuid,
        "Marking RDP asset as server-certificate mismatch after failed connection"
    );
    let mut updated = config.clone();
    updated["rdp_server_cert_mismatch"] = serde_json::Value::Bool(true);
    if let Err(db_err) = diesel::update(dsl::assets.filter(dsl::uuid.eq(asset_uuid)))
        .set(dsl::connection_config.eq(&updated))
        .execute(conn)
        .await
    {
        tracing::error!(
            asset_uuid = %asset_uuid,
            error = %db_err,
            "Failed to persist RDP server-certificate mismatch flag"
        );
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
    browser_tz: BrowserTz,
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
    let base = BaseTemplate::new("RDP Session".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/assets");
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

/// VAU-001: fetch (or refresh) the RDP server certificate SPKI for an asset.
///
/// POST /assets/manage/{uuid}/fetch-rdp-cert
///
/// Admin-only (gated on `assets:manage`). Performs a minimal RDP/X.224 + TLS
/// handshake (accept-any, TOFU) to retrieve the server's SPKI. If a cert was
/// already pinned and the new SPKI differs, returns a mismatch warning
/// fragment (unless `?confirm=true` force-accepts the new cert). Strictly
/// mirrors `fetch_ssh_host_key`.
pub async fn fetch_rdp_server_cert(
    State(state): State<AppState>,
    auth_user: AuthUser,
    perms: crate::auth::PermissionContext,
    axum::extract::Path(asset_uuid_str): axum::extract::Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    use uuid::Uuid;

    if !perms.assets_manage {
        return htmx_error_response("Insufficient privileges: assets:manage required");
    }

    // caller_has_assets_manage is structurally true here (just gated). We
    // forward it so the IPC layer picks the diagnostic-token verb (bypasses
    // the access-rule re-check; admins typically have no explicit rule).
    let assets_manage = perms.assets_manage;

    let confirm = params.get("confirm").map(|v| v == "true").unwrap_or(false);

    let asset_uuid = match Uuid::parse_str(&asset_uuid_str) {
        Ok(u) => u,
        Err(_) => return htmx_error_response("Invalid asset identifier"),
    };

    let proxy_client = match &state.rdp_proxy {
        Some(client) => client.clone(),
        None => return htmx_error_response("RDP proxy not available"),
    };

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return htmx_error_response("Database connection failed");
        }
    };

    use crate::models::asset::{Asset, AssetType};
    use crate::schema::assets::dsl;

    let asset: Asset = match dsl::assets
        .filter(dsl::uuid.eq(asset_uuid))
        .first(&mut conn)
        .await
    {
        Ok(a) => a,
        Err(diesel::result::Error::NotFound) => {
            return htmx_error_response("Asset not found");
        }
        Err(e) => {
            tracing::error!("Failed to fetch asset: {}", e);
            return htmx_error_response("Failed to fetch asset");
        }
    };

    if asset.asset_type != AssetType::Rdp {
        return htmx_error_response("Certificate fetch is only available for RDP assets");
    }

    let stored_spki = asset
        .connection_config
        .get("rdp_server_cert_spki")
        .and_then(|v| v.as_str())
        .map(String::from);

    let stored_fingerprint = asset
        .connection_config
        .get("rdp_server_cert_fingerprint")
        .and_then(|v| v.as_str())
        .map(String::from);

    let supervisor_ref = state.supervisor.as_deref();
    let asset_uuid_str_for_token = asset_uuid.to_string();
    let identity = crate::ipc::CertFetchIdentity {
        access_client: state.access_client.as_ref(),
        user_uuid: &auth_user.uuid,
        asset_uuid: &asset_uuid_str_for_token,
        caller_has_assets_manage: assets_manage,
    };
    let (server_spki, fingerprint) = match proxy_client
        .fetch_server_cert(
            &asset.hostname,
            asset.port as u16,
            supervisor_ref,
            Some(identity),
        )
        .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::error!(
                asset_uuid = %asset_uuid,
                error = %e,
                "Failed to fetch RDP server certificate"
            );
            return htmx_error_response(&format!("Failed to fetch server certificate: {}", e));
        }
    };

    // Detect certificate change: if a SPKI was previously pinned and the
    // newly fetched SPKI differs, warn unless the admin explicitly confirmed.
    if let Some(ref old_spki) = stored_spki
        && old_spki != &server_spki
        && !confirm
    {
        let old_fp = stored_fingerprint.as_deref().unwrap_or("unknown");

        tracing::warn!(
            asset_uuid = %asset_uuid,
            old_fingerprint = %old_fp,
            new_fingerprint = %fingerprint,
            "RDP server certificate CHANGED on remote server - possible MITM attack"
        );

        let html =
            include_str!("../../../templates/assets/_rdp_server_cert_mismatch_fragment.html")
                .replace("__OLD_FINGERPRINT__", old_fp)
                .replace("__NEW_FINGERPRINT__", &fingerprint)
                .replace("__ASSET_UUID__", &asset_uuid.to_string());

        return axum::response::Html(html).into_response();
    }

    // Persist the fingerprint + SPKI and clear any previous mismatch flag.
    let mut config = asset.connection_config.clone();
    config["rdp_server_cert_fingerprint"] = serde_json::Value::String(fingerprint.clone());
    config["rdp_server_cert_spki"] = serde_json::Value::String(server_spki.clone());
    config
        .as_object_mut()
        .map(|m| m.remove("rdp_server_cert_mismatch"));

    let actor_id =
        crate::services::audit_authors::resolve_actor_id(&mut conn, &auth_user.uuid).await;

    use chrono::Utc;
    if let Err(e) = diesel::update(dsl::assets.filter(dsl::uuid.eq(asset_uuid)))
        .set((
            dsl::connection_config.eq(&config),
            dsl::updated_at.eq(Utc::now()),
            dsl::updated_by_id.eq(actor_id),
        ))
        .execute(&mut conn)
        .await
    {
        tracing::error!(
            asset_uuid = %asset_uuid,
            error = %e,
            "Failed to store RDP server certificate"
        );
        return htmx_error_response("Failed to store server certificate");
    }

    tracing::info!(
        asset_uuid = %asset_uuid,
        fingerprint = %fingerprint,
        "RDP server certificate fetched and stored"
    );

    let html = include_str!("../../../templates/assets/_rdp_server_cert_fragment.html")
        .replace("__FINGERPRINT__", &fingerprint)
        .replace("__ASSET_UUID__", &asset_uuid.to_string());

    axum::response::Html(html).into_response()
}

/// VAU-001: verify the pinned RDP server certificate against the live server.
///
/// GET /assets/{uuid}/verify-rdp-cert
///
/// Called via HTMX `hx-trigger="load"` on the asset detail page. Performs a
/// lightweight TLS handshake to retrieve the server's current SPKI and
/// compares it with the stored one. Strictly mirrors `verify_ssh_host_key`,
/// including the "no silent green" invariant: the verified (green) fragment
/// is returned ONLY in the branch where `old_spki == remote_spki`.
pub async fn verify_rdp_server_cert(
    State(state): State<AppState>,
    auth_user: AuthUser,
    perms: crate::auth::PermissionContext,
    axum::extract::Path(asset_uuid_str): axum::extract::Path<String>,
) -> Response {
    use uuid::Uuid;

    // Gate on assets:read BEFORE the UUID parse so a malformed UUID does not
    // leak a different error than an unknown asset (anti-enumeration).
    if !perms.assets_read {
        return htmx_error_response("Insufficient privileges: assets:read required");
    }

    // Capture assets:manage so the IPC layer can pick the diagnostic-token
    // verb (bypasses the access-rule re-check for admins). Mirrors SSH.
    let assets_manage = perms.assets_manage;

    let asset_uuid = match Uuid::parse_str(&asset_uuid_str) {
        Ok(u) => u,
        Err(_) => return htmx_error_response("Invalid asset identifier"),
    };

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return htmx_error_response("Database connection failed");
        }
    };

    use crate::models::asset::{Asset, AssetType};
    use crate::schema::assets::dsl;

    let asset: Asset = match dsl::assets
        .filter(dsl::uuid.eq(asset_uuid))
        .first(&mut conn)
        .await
    {
        Ok(a) => a,
        Err(_) => return htmx_error_response("Asset not found"),
    };

    if asset.asset_type != AssetType::Rdp {
        return htmx_error_response("Not an RDP asset");
    }

    let stored_spki = asset
        .connection_config
        .get("rdp_server_cert_spki")
        .and_then(|v| v.as_str())
        .map(String::from);

    let stored_fingerprint = asset
        .connection_config
        .get("rdp_server_cert_fingerprint")
        .and_then(|v| v.as_str())
        .map(String::from);

    let stored_mismatch = asset
        .connection_config
        .get("rdp_server_cert_mismatch")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let uuid_str = asset_uuid.to_string();

    // No cert pinned yet -> no-key fragment (no point contacting the server).
    if stored_spki.is_none() {
        let html = include_str!("../../../templates/assets/_rdp_server_cert_no_key_fragment.html")
            .replace("__ASSET_UUID__", &uuid_str);
        return axum::response::Html(html).into_response();
    }

    // Mismatch flag already set (from a failed connection) -> stored mismatch
    // state immediately. The admin must click Refresh to re-check.
    if stored_mismatch {
        let fp = stored_fingerprint.as_deref().unwrap_or("unknown");
        let html = include_str!(
            "../../../templates/assets/_rdp_server_cert_stored_mismatch_fragment.html"
        )
        .replace("__FINGERPRINT__", fp)
        .replace("__ASSET_UUID__", &uuid_str);
        return axum::response::Html(html).into_response();
    }

    let proxy_client = match &state.rdp_proxy {
        Some(client) => client.clone(),
        None => {
            // Proxy unavailable: we CANNOT confirm the live cert matches the
            // stored pin. Returning the green "Verified" fragment here would
            // be a silent regression. Return the amber "Could not verify"
            // fragment instead (no silent green).
            tracing::debug!(
                asset_uuid = %asset_uuid,
                "RDP proxy not available; returning unverified-fallback fragment"
            );
            let fp = stored_fingerprint.as_deref().unwrap_or("unknown");
            let html =
                include_str!("../../../templates/assets/_rdp_server_cert_unverified_fragment.html")
                    .replace("__FINGERPRINT__", fp)
                    .replace("__ASSET_UUID__", &uuid_str);
            return axum::response::Html(html).into_response();
        }
    };

    let supervisor_ref = state.supervisor.as_deref();
    let uuid_str_for_token = asset_uuid.to_string();
    let identity = crate::ipc::CertFetchIdentity {
        access_client: state.access_client.as_ref(),
        user_uuid: &auth_user.uuid,
        asset_uuid: &uuid_str_for_token,
        caller_has_assets_manage: assets_manage,
    };
    match proxy_client
        .fetch_server_cert(
            &asset.hostname,
            asset.port as u16,
            supervisor_ref,
            Some(identity),
        )
        .await
    {
        Ok((remote_spki, remote_fingerprint)) => {
            let old_spki = stored_spki.as_deref().unwrap_or("");

            if old_spki == remote_spki {
                // Certs match - return verified (green) fragment. This is the
                // ONLY place the green fragment is produced (no silent green).
                let html = include_str!("../../../templates/assets/_rdp_server_cert_fragment.html")
                    .replace("__FINGERPRINT__", &remote_fingerprint)
                    .replace("__ASSET_UUID__", &uuid_str);
                axum::response::Html(html).into_response()
            } else {
                // Certs DIFFER - set mismatch flag in DB and return red fragment.
                let old_fp = stored_fingerprint.as_deref().unwrap_or("unknown");

                tracing::warn!(
                    asset_uuid = %asset_uuid,
                    old_fingerprint = %old_fp,
                    new_fingerprint = %remote_fingerprint,
                    "RDP server certificate CHANGED on remote server (detected during page load verification)"
                );

                let mut config = asset.connection_config.clone();
                config["rdp_server_cert_mismatch"] = serde_json::Value::Bool(true);
                if let Err(db_err) = diesel::update(dsl::assets.filter(dsl::uuid.eq(asset_uuid)))
                    .set(dsl::connection_config.eq(&config))
                    .execute(&mut conn)
                    .await
                {
                    tracing::error!(
                        asset_uuid = %asset_uuid,
                        error = %db_err,
                        "Failed to persist RDP server-certificate mismatch flag"
                    );
                }

                let html = include_str!(
                    "../../../templates/assets/_rdp_server_cert_mismatch_fragment.html"
                )
                .replace("__OLD_FINGERPRINT__", old_fp)
                .replace("__NEW_FINGERPRINT__", &remote_fingerprint)
                .replace("__ASSET_UUID__", &uuid_str);
                axum::response::Html(html).into_response()
            }
        }
        Err(e) => {
            // Connection failed: we CANNOT confirm the live cert. Returning
            // the green fragment would be a silent regression. Return the
            // amber "Could not verify" fragment (no silent green).
            tracing::debug!(
                asset_uuid = %asset_uuid,
                error = %e,
                "Could not verify RDP server certificate against remote server; \
                 returning unverified-fallback fragment"
            );
            let fp = stored_fingerprint.as_deref().unwrap_or("unknown");
            let html =
                include_str!("../../../templates/assets/_rdp_server_cert_unverified_fragment.html")
                    .replace("__FINGERPRINT__", fp)
                    .replace("__ASSET_UUID__", &uuid_str);
            axum::response::Html(html).into_response()
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
