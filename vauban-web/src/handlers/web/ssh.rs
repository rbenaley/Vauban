//! SSH connection and terminal page handlers.

use super::*;

// ============================================================================
// SSH Connection Handler
// ============================================================================

/// Request form for SSH connection.
#[derive(Debug, serde::Deserialize)]
pub struct ConnectSshForm {
    pub csrf_token: String,
    /// Optional username override.
    pub username: Option<String>,
    /// Connection justification (SEC-03).
    pub justification: Option<String>,
}

/// Response for SSH connection request.
#[derive(Debug, serde::Serialize)]
pub struct ConnectSshResponse {
    /// Whether the connection was initiated successfully.
    pub success: bool,
    /// Session UUID for WebSocket connection.
    pub session_id: Option<String>,
    /// Terminal page URL to redirect to.
    pub redirect_url: Option<String>,
    /// Error message if connection failed.
    pub error: Option<String>,
}

/// Helper to create an HTMX error response (toast notification).
fn htmx_error_response(message: &str) -> Response {
    // Return an HX-Trigger header that shows a toast notification
    // Escape message for JSON
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

/// Initiate SSH connection to an asset.
///
/// POST /assets/{uuid}/connect
///
/// For HTMX requests: Returns HX-Redirect header on success, HX-Trigger toast on error.
/// For non-HTMX requests: Returns JSON response.
// allow-ungated: session-open path; authorization delegated to the access-rule pipeline (vauban-access CheckAssetAccess + MFA + JIT)
pub async fn connect_ssh(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    jar: CookieJar,
    auth_user: AuthUser,
    client_addr: crate::middleware::ClientAddr,
    axum::extract::Path(asset_uuid_str): axum::extract::Path<String>,
    Form(form): Form<ConnectSshForm>,
) -> Response {
    use axum::Json;
    use uuid::Uuid;

    // Check if this is an HTMX request
    let is_htmx = headers.get("HX-Request").is_some();

    // CSRF validation
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    let secret = state.config.secret_key.expose_secret().as_bytes();
    if !crate::middleware::csrf::validate_double_submit(
        secret,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        let msg = "Invalid CSRF token";
        if is_htmx {
            return htmx_error_response(msg);
        }
        return Json(ConnectSshResponse {
            success: false,
            session_id: None,
            redirect_url: None,
            error: Some(msg.to_string()),
        })
        .into_response();
    }

    // Validate justification when required (SEC-03)
    let form_justification = if state.config.security.require_justification {
        let j = form.justification.as_deref().unwrap_or("").trim();
        if j.len() < 10 {
            let msg = "Justification is required (minimum 10 characters)";
            if is_htmx {
                return htmx_error_response(msg);
            }
            return Json(ConnectSshResponse {
                success: false,
                session_id: None,
                redirect_url: None,
                error: Some(msg.to_string()),
            })
            .into_response();
        }
        Some(j.to_string())
    } else {
        form.justification
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(String::from)
    };

    // Parse asset UUID
    let asset_uuid = match Uuid::parse_str(&asset_uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            let msg = "Invalid asset identifier";
            if is_htmx {
                return htmx_error_response(msg);
            }
            return Json(ConnectSshResponse {
                success: false,
                session_id: None,
                redirect_url: None,
                error: Some(msg.to_string()),
            })
            .into_response();
        }
    };

    // Fetch asset from database
    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!("Database connection error: {}", e);
            let msg = "Database connection failed";
            if is_htmx {
                return htmx_error_response(msg);
            }
            return Json(ConnectSshResponse {
                success: false,
                session_id: None,
                redirect_url: None,
                error: Some(msg.to_string()),
            })
            .into_response();
        }
    };

    use crate::models::asset::{Asset, AssetType};
    use crate::schema::assets::dsl;

    let asset: Asset = match dsl::assets
        .filter(dsl::uuid.eq(asset_uuid))
        .first(&mut conn)
        .await
    {
        Ok(asset) => asset,
        Err(diesel::result::Error::NotFound) => {
            let msg = "Asset not found";
            if is_htmx {
                return htmx_error_response(msg);
            }
            return Json(ConnectSshResponse {
                success: false,
                session_id: None,
                redirect_url: None,
                error: Some(msg.to_string()),
            })
            .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to fetch asset: {}", e);
            let msg = "Failed to fetch asset";
            if is_htmx {
                return htmx_error_response(msg);
            }
            return Json(ConnectSshResponse {
                success: false,
                session_id: None,
                redirect_url: None,
                error: Some("Failed to fetch asset".to_string()),
            })
            .into_response();
        }
    };

    // Verify asset type is SSH
    if asset.asset_type != AssetType::Ssh {
        let msg = format!("Asset type '{}' is not SSH", asset.asset_type);
        if is_htmx {
            return htmx_error_response(&msg);
        }
        return Json(ConnectSshResponse {
            success: false,
            session_id: None,
            redirect_url: None,
            error: Some(msg),
        })
        .into_response();
    }

    // Generate session UUID
    let session_uuid = Uuid::new_v4();
    let session_id = session_uuid.to_string();

    // Resolve authenticated user's integer ID and check account status (SEC-07)
    let user_id: i32 = {
        use crate::schema::users;
        match auth_user.uuid.parse::<Uuid>() {
            Ok(user_uuid) => match users::table
                .filter(users::uuid.eq(user_uuid))
                .select((users::id, users::is_active))
                .first::<(i32, bool)>(&mut conn)
                .await
            {
                Ok((id, user_is_active)) => {
                    if !user_is_active {
                        let msg = super::ACCOUNT_DEACTIVATED_MSG;
                        if is_htmx {
                            return htmx_error_response(msg);
                        }
                        return Json(ConnectSshResponse {
                            success: false,
                            session_id: None,
                            redirect_url: None,
                            error: Some(msg.to_string()),
                        })
                        .into_response();
                    }
                    id
                }
                Err(e) => {
                    tracing::error!("Failed to resolve user ID: {}", e);
                    let msg = "User not found";
                    if is_htmx {
                        return htmx_error_response(msg);
                    }
                    return Json(ConnectSshResponse {
                        success: false,
                        session_id: None,
                        redirect_url: None,
                        error: Some(msg.to_string()),
                    })
                    .into_response();
                }
            },
            Err(_) => {
                let msg = "Invalid user identifier";
                if is_htmx {
                    return htmx_error_response(msg);
                }
                return Json(ConnectSshResponse {
                    success: false,
                    session_id: None,
                    redirect_url: None,
                    error: Some(msg.to_string()),
                })
                .into_response();
            }
        }
    };

    // Access rule enforcement: EVERY user must have a matching access rule,
    // including superusers and staff. The historical privileged-user bypass
    // was removed alongside the proxy-ssh defense-in-depth re-check (RBAC-by-
    // UUID): if vauban-web silently waved a session through here while
    // vauban-access correctly demanded an access_rule, the proxy would deny
    // the SshSessionOpen and the user would see "Access denied" with no
    // recourse. Both layers now apply the exact same policy.
    //
    // Policy eval 3→2: mint the session token here (IssueSessionToken
    // re-runs CheckAccessByUuid and returns MFA/JIT/duration constraints)
    // instead of a preceding CheckAccessMulti trip.
    // session_uuid is already known; AccessGuard remains the proxy-side
    // re-check. See docs/runbooks/policy_eval_session_open_smoke_test.md.
    //
    // Operational consequence: the bootstrap superuser MUST create at least
    // one access_rule for itself before opening any SSH session. See
    // docs/runbooks/ipc_topology_debugging.md for the rationale and the
    // recommended bootstrap rule.
    let jit_justification: Option<String>;
    let jit_max_duration: Option<i32>;
    let session_token_bytes: Vec<u8>;
    {
        let issued = match state
            .access_client
            .issue_session_token(shared::session_token::SessionTokenParams {
                session_id: session_id.clone(),
                user_uuid: auth_user.uuid.clone(),
                asset_uuid: asset.uuid.to_string(),
                protocol: "ssh".to_string(),
                host: asset.hostname.clone(),
                port: asset.port as u16,
                target_service: shared::messages::Service::ProxySsh,
            })
            .await
        {
            Ok(issued) => issued,
            Err(e) => {
                tracing::warn!(
                    session_id = %session_id,
                    user = %auth_user.username,
                    asset = %asset.name,
                    error = %e,
                    "Session-token mint denied; refusing to open SSH session"
                );
                let msg = "No access rule grants you access to this asset";
                if is_htmx {
                    return htmx_error_response(msg);
                }
                return Json(ConnectSshResponse {
                    success: false,
                    session_id: None,
                    redirect_url: None,
                    error: Some(msg.to_string()),
                })
                .into_response();
            }
        };
        session_token_bytes = issued.token;

        // SECURITY (issue #34) -- mandatory host-key pin pre-flight.
        //
        // Runs AFTER the access-rule check so a user without access
        // hears "No access rule" first (least-info-leak), and BEFORE
        // any session-creation work (approval lookup, JIT request,
        // `proxy_sessions` insert, supervisor TCP broker, IPC to
        // vauban-access). Two refusal cases:
        //
        // 1. `connection_config.ssh_host_key_mismatch == true`: a
        //    previous connection attempt detected the live server
        //    presented a key that disagreed with the stored pin.
        //    Until an admin re-fetches and pins the new key, every
        //    new connection is suspect (we cannot tell whether the
        //    operator rotated the key or whether we are facing a
        //    MITM). Refuse rather than re-attempt.
        //
        // 2. `connection_config.ssh_host_key` is absent or empty: the
        //    asset has no pinned key. Pre-#34 the code passed
        //    `expected_host_key = None` to vauban-proxy-ssh, which
        //    logged "INSECURE - accepting server key" and opened the
        //    session against whatever key the server presented (TOFU
        //    window indefinitely). Combined with the silent green
        //    "Verified" fallback in `verify_ssh_host_key` (also
        //    fixed in this issue), the operator never knew the pin
        //    was missing. We close that window here: pinning is
        //    mandatory, the admin must trigger
        //    `/assets/manage/{uuid}/fetch-host-key` first.
        //
        // The forbidden phrases pinned by
        // `tests/web/ssh_host_key_no_silent_green_test.rs` AND by
        // `scripts/check_ssh_host_key_paths.sh` MUST appear here:
        //   - "SSH host key mismatch detected on previous connection"
        //   - "No SSH host key pinned"
        let stored_host_key_preflight = asset
            .connection_config
            .get("ssh_host_key")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        let stored_mismatch_preflight = asset
            .connection_config
            .get("ssh_host_key_mismatch")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if stored_mismatch_preflight {
            tracing::warn!(
                user = %auth_user.username,
                asset = %asset.name,
                asset_uuid = %asset_uuid,
                "Refusing SSH connection: SSH host key mismatch detected on \
                 previous connection. Admin must re-fetch and pin the new key."
            );
            let msg = "SSH host key mismatch detected on previous connection. \
                       An admin must re-fetch and pin the new key before new \
                       sessions are allowed.";
            if is_htmx {
                return htmx_error_response(msg);
            }
            return Json(ConnectSshResponse {
                success: false,
                session_id: None,
                redirect_url: None,
                error: Some(msg.to_string()),
            })
            .into_response();
        }

        if stored_host_key_preflight.is_none() {
            tracing::warn!(
                user = %auth_user.username,
                asset = %asset.name,
                asset_uuid = %asset_uuid,
                "Refusing SSH connection: No SSH host key pinned for this asset. \
                 Admin must fetch and pin the host key first."
            );
            let msg = "No SSH host key pinned for this asset. An admin must \
                       fetch and pin the host key before sessions can be opened.";
            if is_htmx {
                return htmx_error_response(msg);
            }
            return Json(ConnectSshResponse {
                success: false,
                session_id: None,
                redirect_url: None,
                error: Some(msg.to_string()),
            })
            .into_response();
        }

        if issued.require_approval {
            // Find an approved session that has not expired.
            // Only consider approvals whose expires_at is still in the future
            // (or has no expiry set, for legacy rows).
            let now = chrono::Utc::now();
            let approved_session: Option<(::uuid::Uuid, Option<String>, Option<i32>)> =
                proxy_sessions::table
                    .filter(proxy_sessions::user_id.eq(user_id))
                    .filter(proxy_sessions::asset_id.eq(asset.id))
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
                    jit_max_duration = max_dur.or(issued.max_session_duration);
                }
                None => {
                    // Issue #34: the user-zone /assets/{uuid} detail page is
                    // gone (information leak: description / dates / ssh-host-
                    // key fingerprint were rendered for any caller with
                    // `assets:read`).  We no longer redirect there.
                    //
                    // For HTMX clients we emit `HX-Trigger:
                    // show-access-request-modal` whose JSON payload carries
                    // the three fields the inlined modal needs (asset_uuid,
                    // asset_type, require_mfa); the user is already on
                    // /assets so the modal opens in-place.
                    //
                    // For non-HTMX clients (CLI / API) we point them at the
                    // catalogue with a plain message; opening the request
                    // is now a UI-only flow.
                    //
                    // Token was minted above and is discarded here (no INSERT).
                    if is_htmx {
                        let payload = serde_json::json!({
                            "show-access-request-modal": {
                                "asset_uuid": asset_uuid_str,
                                "asset_type": "ssh",
                                "require_mfa": issued.require_mfa,
                            }
                        })
                        .to_string();
                        return ([(
                            axum::http::header::HeaderName::from_static("hx-trigger"),
                            axum::http::header::HeaderValue::from_str(&payload).unwrap_or_else(
                                |_| {
                                    axum::http::header::HeaderValue::from_static(
                                        r#"{"show-access-request-modal":{}}"#,
                                    )
                                },
                            ),
                        )])
                        .into_response();
                    }
                    return Json(ConnectSshResponse {
                        success: false,
                        session_id: None,
                        redirect_url: Some("/assets".to_string()),
                        error: Some(
                            "Access requires approval. Please submit an access \
                             request from the /assets catalogue."
                                .to_string(),
                        ),
                    })
                    .into_response();
                }
            }
        } else {
            jit_justification = None;
            jit_max_duration = issued.max_session_duration;
        }
    }

    // Get SSH proxy client (checked after access rules to avoid leaking proxy state)
    let proxy_client = match &state.ssh_proxy {
        Some(client) => client.clone(),
        None => {
            let msg = "SSH proxy not available";
            if is_htmx {
                return htmx_error_response(msg);
            }
            return Json(ConnectSshResponse {
                success: false,
                session_id: None,
                redirect_url: None,
                error: Some(msg.to_string()),
            })
            .into_response();
        }
    };

    // Extract connection details from asset's connection_config
    let config = &asset.connection_config;

    // Determine username from:
    // 1. Form override
    // 2. connection_username column (dedicated DB column)
    // 3. Default "root"
    let username = form
        .username
        .filter(|u| !u.is_empty())
        .unwrap_or(asset.connection_username.clone());

    // Extract authentication credentials from connection_config
    let auth_type = config
        .get("auth_type")
        .and_then(|v| v.as_str())
        .unwrap_or("password")
        .to_string();

    // SECURITY (#4 - zero clear-text credentials on the web->proxy IPC):
    // vauban-web NO LONGER decrypts here. The credential fields in
    // `connection_config` hold vault ciphertexts (`"v1:..."`), and we
    // ship them verbatim to vauban-proxy-ssh, which materialises the
    // plaintext via its own decrypt-only `VaultDecryptClient` moments
    // before building the russh credential. The vault never round-trips
    // the secret through vauban-web's address space on the hot path.
    let password_ciphertext = config
        .get("password")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);

    let private_key_ciphertext = config
        .get("private_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);

    let passphrase_ciphertext = config
        .get("passphrase")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);

    // Extract stored SSH host key for verification
    let expected_host_key = config
        .get("ssh_host_key")
        .and_then(|v| v.as_str())
        .map(String::from);

    // VAU-012: enforce session-creation rate limits and concurrency quotas
    // BEFORE allocating any backend resource (INSERT + TCP + IPC).
    // Token was already minted above (policy eval 3→2). Placed AFTER
    // authorization so a denial cannot be used to enumerate assets
    // (anti-enumeration).
    match crate::services::session_limits::enforce_session_creation(
        &state,
        &mut conn,
        user_id,
        asset.id,
        client_addr.addr().ip(),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(denied)) => {
            return crate::services::session_limits::connect_limit_response(
                &headers,
                &denied.message,
            );
        }
        Err(e) => {
            tracing::error!("Failed to evaluate session-creation limits: {}", e);
            let msg = "Unable to start session";
            if is_htmx {
                return htmx_error_response(msg);
            }
            return Json(ConnectSshResponse {
                success: false,
                session_id: None,
                redirect_url: None,
                error: Some(msg.to_string()),
            })
            .into_response();
        }
    }

    // Record the session in the database for ownership tracking.
    // This allows the ws_session_guard middleware to verify that the
    // WebSocket client owns the session before allowing the upgrade.
    {
        use crate::models::session::{NewProxySession, SessionType};
        let trusted = state.config.security.parsed_trusted_proxies();
        let client_ip =
            crate::middleware::extract_client_ip(&headers, client_addr.addr(), &trusted);
        let new_session = NewProxySession {
            uuid: session_uuid,
            user_id,
            asset_id: asset.id,
            credential_id: "local".to_string(),
            credential_username: username.clone(),
            session_type: SessionType::Ssh,
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
            tracing::error!(session_id = %session_id, error = %e, "Failed to record proxy session");
            let msg = "Failed to create session record";
            if is_htmx {
                return htmx_error_response(msg);
            }
            return Json(ConnectSshResponse {
                success: false,
                session_id: None,
                redirect_url: None,
                error: Some(msg.to_string()),
            })
            .into_response();
        }
    }

    // Session token was minted before JIT/INSERT (policy eval 3→2).
    // Build SSH session open request
    let request = crate::ipc::SshSessionOpenRequest {
        session_id: session_id.clone(),
        user_id: auth_user.uuid.clone(),
        asset_id: asset.uuid.to_string(),
        asset_host: asset.hostname.clone(),
        asset_port: asset.port as u16,
        username,
        terminal_cols: 120,
        terminal_rows: 30,
        auth_type,
        password_ciphertext,
        private_key_ciphertext,
        passphrase_ciphertext,
        expected_host_key,
        session_token: session_token_bytes.clone(),
    };

    // If supervisor is available (sandboxed mode), request TCP connection brokering.
    // The supervisor performs DNS resolution and TCP connect, then passes the FD
    // to the SSH proxy via SCM_RIGHTS. This enables Capsicum sandboxed operation.
    if let Some(ref supervisor) = state.supervisor {
        tracing::debug!(
            session_id = %session_id,
            host = %asset.hostname,
            port = asset.port,
            "Requesting TCP connection from supervisor (sandboxed mode)"
        );

        match supervisor
            .request_tcp_connect(
                &session_id,
                &asset.hostname,
                asset.port as u16,
                shared::messages::Service::ProxySsh,
                session_token_bytes.clone(),
            )
            .await
        {
            Ok(result) if result.success => {
                tracing::debug!(
                    session_id = %session_id,
                    "TCP connection established by supervisor"
                );
            }
            Ok(result) => {
                let msg = result
                    .error
                    .unwrap_or_else(|| "Failed to establish TCP connection".to_string());
                tracing::error!(session_id = %session_id, error = %msg, "TCP connect failed");
                if is_htmx {
                    return htmx_error_response(&msg);
                }
                return Json(ConnectSshResponse {
                    success: false,
                    session_id: None,
                    redirect_url: None,
                    error: Some(msg),
                })
                .into_response();
            }
            Err(e) => {
                tracing::error!(session_id = %session_id, error = %e, "TCP connect request failed");
                if is_htmx {
                    return htmx_error_response(&e);
                }
                return Json(ConnectSshResponse {
                    success: false,
                    session_id: None,
                    redirect_url: None,
                    error: Some(e),
                })
                .into_response();
            }
        }
    }

    // Send request to SSH proxy
    match proxy_client.open_session(request).await {
        Ok(response) => {
            if response.success {
                tracing::debug!(
                    user = %auth_user.username,
                    asset = %asset.name,
                    session_id = %session_id,
                    "SSH session initiated"
                );

                crate::services::emit_audit(
                    &state,
                    crate::ipc::AuditEvent::new(
                        shared::messages::AuditEventType::SessionRequested,
                        format!(r#"{{"protocol":"ssh","asset":"{}"}}"#, asset.name),
                    )
                    .user(auth_user.uuid.to_string())
                    .session(session_id.clone())
                    .ip(Some(client_addr.addr().ip())),
                );

                let redirect_url = format!("/sessions/terminal/{}", session_id);

                if is_htmx {
                    // Use HX-Redirect header for client-side navigation.
                    // This is a built-in HTMX feature that performs a full page
                    // redirect without requiring any custom JavaScript handler.
                    return (
                        axum::http::StatusCode::OK,
                        [("HX-Redirect", redirect_url.as_str())],
                        "",
                    )
                        .into_response();
                }

                Json(ConnectSshResponse {
                    success: true,
                    session_id: Some(session_id.clone()),
                    redirect_url: Some(redirect_url),
                    error: None,
                })
                .into_response()
            } else {
                let msg = response
                    .error
                    .unwrap_or_else(|| "Connection failed".to_string());

                // Detect host key mismatch errors and persist the
                // mismatch flag in connection_config so that the asset
                // detail page can display the warning state.
                let is_host_key_mismatch = msg.contains("host key")
                    || msg.contains("MITM")
                    || msg.contains("Host key verification failed");
                if is_host_key_mismatch {
                    tracing::warn!(
                        asset_uuid = %asset_uuid,
                        "Marking asset as host key mismatch after failed connection"
                    );
                    let mut config = asset.connection_config.clone();
                    config["ssh_host_key_mismatch"] = serde_json::Value::Bool(true);
                    if let Err(db_err) =
                        diesel::update(dsl::assets.filter(dsl::uuid.eq(asset_uuid)))
                            .set(dsl::connection_config.eq(&config))
                            .execute(&mut conn)
                            .await
                    {
                        tracing::error!(
                            asset_uuid = %asset_uuid,
                            error = %db_err,
                            "Failed to persist host key mismatch flag"
                        );
                    }
                }

                if is_htmx {
                    return htmx_error_response(&msg);
                }
                Json(ConnectSshResponse {
                    success: false,
                    session_id: None,
                    redirect_url: None,
                    error: Some(msg),
                })
                .into_response()
            }
        }
        Err(e) => {
            let error_str = format!("{}", e);
            tracing::error!(
                user = %auth_user.username,
                asset = %asset.name,
                error = %error_str,
                "SSH session initiation failed"
            );

            // Also detect mismatch in transport-level errors
            let is_host_key_mismatch = error_str.contains("host key")
                || error_str.contains("MITM")
                || error_str.contains("Host key verification failed");
            if is_host_key_mismatch {
                tracing::warn!(
                    asset_uuid = %asset_uuid,
                    "Marking asset as host key mismatch after failed connection"
                );
                let mut config = asset.connection_config.clone();
                config["ssh_host_key_mismatch"] = serde_json::Value::Bool(true);
                if let Err(db_err) = diesel::update(dsl::assets.filter(dsl::uuid.eq(asset_uuid)))
                    .set(dsl::connection_config.eq(&config))
                    .execute(&mut conn)
                    .await
                {
                    tracing::error!(
                        asset_uuid = %asset_uuid,
                        error = %db_err,
                        "Failed to persist host key mismatch flag"
                    );
                }
            }

            let msg = format!("Failed to initiate SSH connection: {}", e);
            if is_htmx {
                return htmx_error_response(&msg);
            }

            Json(ConnectSshResponse {
                success: false,
                session_id: None,
                redirect_url: None,
                error: Some(msg),
            })
            .into_response()
        }
    }
}

/// Fetch (or refresh) the SSH host key for an asset.
///
/// POST /assets/{uuid}/fetch-host-key
///
/// Performs a minimal SSH handshake to retrieve the server's host key.
/// If a key was already stored and the new key differs, returns a
/// mismatch warning fragment (unless `?confirm=true` is passed to
/// force-accept the new key).
/// Returns an HTMX fragment for dynamic update.
pub async fn fetch_ssh_host_key(
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

    // Issue #34: caller_has_assets_manage is structurally true here
    // (we just gated on it). We forward it explicitly so the IPC layer
    // can pick the diagnostic-token verb (which bypasses the access-
    // rule re-check). Pre-#34 the host-key path used the session-token
    // verb, silently denying admins without an explicit rule.
    let assets_manage = perms.assets_manage;

    let confirm = params.get("confirm").map(|v| v == "true").unwrap_or(false);

    // Parse UUID
    let asset_uuid = match Uuid::parse_str(&asset_uuid_str) {
        Ok(u) => u,
        Err(_) => return htmx_error_response("Invalid asset identifier"),
    };

    // Get proxy client
    let proxy_client = match &state.ssh_proxy {
        Some(client) => client.clone(),
        None => return htmx_error_response("SSH proxy not available"),
    };

    // Fetch asset from database
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

    // Verify asset type is SSH
    if asset.asset_type != AssetType::Ssh {
        return htmx_error_response("Host key fetch is only available for SSH assets");
    }

    // Retrieve the previously stored host key (if any)
    let stored_host_key = asset
        .connection_config
        .get("ssh_host_key")
        .and_then(|v| v.as_str())
        .map(String::from);

    let stored_fingerprint = asset
        .connection_config
        .get("ssh_host_key_fingerprint")
        .and_then(|v| v.as_str())
        .map(String::from);

    // Fetch host key via proxy.
    // In sandboxed mode (Capsicum), the supervisor brokers the TCP
    // connection and passes the FD to the SSH proxy via SCM_RIGHTS.
    // The supervisor's TCP broker is crypto-gated; see
    // `HostKeyFetchIdentity` in `vauban_web::ipc::proxy_ssh`.
    let supervisor_ref = state.supervisor.as_deref();
    let asset_uuid_str_for_token = asset_uuid.to_string();
    let identity = crate::ipc::HostKeyFetchIdentity {
        access_client: state.access_client.as_ref(),
        user_uuid: &auth_user.uuid,
        asset_uuid: &asset_uuid_str_for_token,
        caller_has_assets_manage: assets_manage,
    };
    let (host_key, fingerprint) = match proxy_client
        .fetch_host_key(
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
                "Failed to fetch SSH host key"
            );
            return htmx_error_response(&format!("Failed to fetch host key: {}", e));
        }
    };

    // Detect host key change: if a key was previously stored and the
    // newly fetched key differs, warn the user unless they explicitly
    // confirmed acceptance of the new key.
    if let Some(ref old_key) = stored_host_key
        && old_key != &host_key
        && !confirm
    {
        let old_fp = stored_fingerprint.as_deref().unwrap_or("unknown");

        tracing::warn!(
            asset_uuid = %asset_uuid,
            old_fingerprint = %old_fp,
            new_fingerprint = %fingerprint,
            "SSH host key CHANGED on remote server - possible MITM attack"
        );

        // Return the mismatch warning fragment (no DB update yet)
        let html = include_str!("../../../templates/assets/_ssh_host_key_mismatch_fragment.html")
            .replace("__OLD_FINGERPRINT__", old_fp)
            .replace("__NEW_FINGERPRINT__", &fingerprint)
            .replace("__ASSET_UUID__", &asset_uuid.to_string());

        return axum::response::Html(html).into_response();
    }

    // Update the asset's connection_config with the host key and clear
    // any previous mismatch status.
    let mut config = asset.connection_config.clone();
    config["ssh_host_key"] = serde_json::Value::String(host_key.clone());
    config["ssh_host_key_fingerprint"] = serde_json::Value::String(fingerprint.clone());
    // Remove mismatch flag if it was set by a failed connection attempt
    config
        .as_object_mut()
        .map(|m| m.remove("ssh_host_key_mismatch"));

    // Issue #22 — re-stamp the audit actor: persisting a fetched
    // host key mutates `connection_config`, so the operator that
    // pressed "Fetch Host Key" must show up as the last
    // `Updated by` on `/assets/manage/{uuid}`. Best-effort: a
    // `None` collapses to the muted em-dash on render.
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
            "Failed to store SSH host key"
        );
        return htmx_error_response("Failed to store host key");
    }

    tracing::info!(
        asset_uuid = %asset_uuid,
        fingerprint = %fingerprint,
        "SSH host key fetched and stored"
    );

    // Return HTMX fragment with the fingerprint
    let html = include_str!("../../../templates/assets/_ssh_host_key_fragment.html")
        .replace("__FINGERPRINT__", &fingerprint)
        .replace("__ASSET_UUID__", &asset_uuid.to_string());

    axum::response::Html(html).into_response()
}

/// Minimal HTML-entity escape for interpolating server-derived strings
/// into an HTMX fragment text node (defence-in-depth; the values here
/// are OpenSSH-formatted and operator-controlled).
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Form for the "Push public key" modal (one-shot password).
#[derive(Debug, serde::Deserialize)]
pub struct PushPublicKeyForm {
    pub csrf_token: String,
    /// One-shot password used to authenticate while appending the key
    /// to the target's `authorized_keys`. Never stored.
    pub password: String,
}

/// Form for the "Test key-based authentication" button (CSRF only).
#[derive(Debug, serde::Deserialize)]
pub struct TestKeyAuthForm {
    pub csrf_token: String,
}

/// Resolve the effective SSH username for a one-shot admin operation.
fn resolve_ssh_username(asset: &crate::models::asset::Asset) -> String {
    asset
        .connection_config
        .get("username")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            let cu = asset.connection_username.trim();
            if cu.is_empty() {
                "root".to_string()
            } else {
                cu.to_string()
            }
        })
}

/// POST /assets/manage/{uuid}/push-public-key
///
/// Installs the asset's stored OpenSSH public key into the target's
/// `~/.ssh/authorized_keys` via a one-shot password-authenticated
/// session (the password is typed in a modal, encrypted via the vault,
/// and decrypted proxy-side -- it never crosses the IPC in clear). Host
/// key pinning is mandatory: we authenticate with a password, so we
/// refuse to talk to an unpinned/mismatched server. Returns an HTMX
/// fragment.
pub async fn push_ssh_public_key(
    State(state): State<AppState>,
    auth_user: AuthUser,
    perms: crate::auth::PermissionContext,
    axum::extract::Path(asset_uuid_str): axum::extract::Path<String>,
    jar: CookieJar,
    Form(form): Form<PushPublicKeyForm>,
) -> Response {
    use uuid::Uuid;

    if !perms.assets_manage {
        return htmx_error_response("Insufficient privileges: assets:manage required");
    }

    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return htmx_error_response("Invalid CSRF token");
    }

    if form.password.is_empty() {
        return htmx_error_response("A password is required to push the public key");
    }

    let asset_uuid = match Uuid::parse_str(&asset_uuid_str) {
        Ok(u) => u,
        Err(_) => return htmx_error_response("Invalid asset identifier"),
    };

    let proxy_client = match &state.ssh_proxy {
        Some(client) => client.clone(),
        None => return htmx_error_response("SSH proxy not available"),
    };
    let vault = match &state.vault_client {
        Some(v) => v,
        None => return htmx_error_response("Vault not available; cannot secure the password"),
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
        Err(diesel::result::Error::NotFound) => return htmx_error_response("Asset not found"),
        Err(e) => {
            tracing::error!("Failed to fetch asset: {}", e);
            return htmx_error_response("Failed to fetch asset");
        }
    };

    if asset.asset_type != AssetType::Ssh {
        return htmx_error_response("Public key push is only available for SSH assets");
    }

    let public_key = match asset
        .connection_config
        .get("ssh_public_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
    {
        Some(k) => k.trim().to_string(),
        None => {
            return htmx_error_response(
                "This asset has no SSH public key to push. Generate or import a key pair first.",
            );
        }
    };

    // Host-key pinning is MANDATORY: we authenticate by password, so an
    // unpinned/mismatched host could phish the one-shot password.
    let expected_host_key = match asset
        .connection_config
        .get("ssh_host_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
    {
        Some(k) => k.to_string(),
        None => {
            return htmx_error_response(
                "Pin the SSH host key first (Fetch Host Key) before pushing a public key.",
            );
        }
    };

    let password_ciphertext = match vault.encrypt("credentials", &form.password).await {
        Ok(ct) => ct,
        Err(e) => {
            tracing::error!("Failed to encrypt one-shot password: {}", e);
            return htmx_error_response("Failed to secure the password");
        }
    };

    let username = resolve_ssh_username(&asset);
    let supervisor_ref = state.supervisor.as_deref();
    let asset_uuid_str_for_token = asset_uuid.to_string();
    let identity = crate::ipc::HostKeyFetchIdentity {
        access_client: state.access_client.as_ref(),
        user_uuid: &auth_user.uuid,
        asset_uuid: &asset_uuid_str_for_token,
        caller_has_assets_manage: perms.assets_manage,
    };

    if let Err(e) = proxy_client
        .push_public_key(
            &asset.hostname,
            asset.port as u16,
            &username,
            &public_key,
            &password_ciphertext,
            Some(expected_host_key),
            supervisor_ref,
            Some(identity),
        )
        .await
    {
        tracing::warn!(asset_uuid = %asset_uuid, error = %e, "Failed to push SSH public key");
        return htmx_error_response(&format!("Failed to push public key: {}", e));
    }

    // Mark the key as pushed so the UI can reflect the new state.
    let mut config = asset.connection_config.clone();
    if let Some(obj) = config.as_object_mut() {
        obj.insert(
            "ssh_pubkey_pushed".to_string(),
            serde_json::Value::Bool(true),
        );
    }
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
        tracing::error!(asset_uuid = %asset_uuid, error = %e, "Failed to persist ssh_pubkey_pushed");
        // The key was pushed; surface success but note the flag did not persist.
    }

    tracing::info!(asset_uuid = %asset_uuid, "SSH public key pushed to target");

    let html = include_str!("../../../templates/assets/_ssh_push_result_fragment.html")
        .replace("__FINGERPRINT__", &html_escape(&public_key));
    axum::response::Html(html).into_response()
}

/// POST /assets/manage/{uuid}/test-key-auth
///
/// Dry-run key-based authentication against the target using the asset's
/// stored (vault-sealed) private key: connect, `authenticate_publickey`,
/// then disconnect. The private key/passphrase travel as vault
/// ciphertexts and are decrypted proxy-side. Host key pinning is
/// mandatory. Returns an HTMX fragment.
pub async fn test_ssh_key_auth(
    State(state): State<AppState>,
    auth_user: AuthUser,
    perms: crate::auth::PermissionContext,
    axum::extract::Path(asset_uuid_str): axum::extract::Path<String>,
    jar: CookieJar,
    Form(form): Form<TestKeyAuthForm>,
) -> Response {
    use uuid::Uuid;

    if !perms.assets_manage {
        return htmx_error_response("Insufficient privileges: assets:manage required");
    }

    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return htmx_error_response("Invalid CSRF token");
    }

    let asset_uuid = match Uuid::parse_str(&asset_uuid_str) {
        Ok(u) => u,
        Err(_) => return htmx_error_response("Invalid asset identifier"),
    };

    let proxy_client = match &state.ssh_proxy {
        Some(client) => client.clone(),
        None => return htmx_error_response("SSH proxy not available"),
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
        Err(diesel::result::Error::NotFound) => return htmx_error_response("Asset not found"),
        Err(e) => {
            tracing::error!("Failed to fetch asset: {}", e);
            return htmx_error_response("Failed to fetch asset");
        }
    };

    if asset.asset_type != AssetType::Ssh {
        return htmx_error_response("Key-based auth test is only available for SSH assets");
    }

    let private_key_ciphertext = match asset
        .connection_config
        .get("private_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        Some(c) => c.to_string(),
        None => {
            return htmx_error_response(
                "This asset has no SSH private key to test. Import or generate a key pair first.",
            );
        }
    };
    let passphrase_ciphertext = asset
        .connection_config
        .get("passphrase")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);

    let expected_host_key = match asset
        .connection_config
        .get("ssh_host_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
    {
        Some(k) => k.to_string(),
        None => {
            return htmx_error_response(
                "Pin the SSH host key first (Fetch Host Key) before testing authentication.",
            );
        }
    };

    let username = resolve_ssh_username(&asset);
    let supervisor_ref = state.supervisor.as_deref();
    let asset_uuid_str_for_token = asset_uuid.to_string();
    let identity = crate::ipc::HostKeyFetchIdentity {
        access_client: state.access_client.as_ref(),
        user_uuid: &auth_user.uuid,
        asset_uuid: &asset_uuid_str_for_token,
        caller_has_assets_manage: perms.assets_manage,
    };

    if let Err(e) = proxy_client
        .test_key_auth(
            &asset.hostname,
            asset.port as u16,
            &username,
            &private_key_ciphertext,
            passphrase_ciphertext,
            Some(expected_host_key),
            supervisor_ref,
            Some(identity),
        )
        .await
    {
        tracing::info!(asset_uuid = %asset_uuid, error = %e, "SSH key-based auth test failed");
        return htmx_error_response(&format!("Key-based authentication test failed: {}", e));
    }

    tracing::info!(asset_uuid = %asset_uuid, "SSH key-based auth test succeeded");

    let html = include_str!("../../../templates/assets/_ssh_test_result_fragment.html").replace(
        "__FINGERPRINT__",
        &format!(
            "{}@{}",
            html_escape(&username),
            html_escape(&asset.hostname)
        ),
    );
    axum::response::Html(html).into_response()
}

/// Verify the SSH host key for an asset against the remote server.
///
/// GET /assets/{uuid}/verify-host-key
///
/// Called automatically via HTMX `hx-trigger="load"` when the asset
/// detail page loads.  Performs a lightweight SSH handshake to retrieve
/// the server's current host key and compares it with the stored one.
///
/// Returns the appropriate HTMX fragment:
///   - Verified (green)  if keys match
///   - Mismatch (red)    if keys differ  (also sets the DB flag)
///   - No key  (amber)   if no key was ever stored
///
/// If the proxy is unavailable or the connection fails, the handler
/// falls back to the stored state so the page is never broken.
pub async fn verify_ssh_host_key(
    State(state): State<AppState>,
    _auth_user: AuthUser,
    perms: crate::auth::PermissionContext,
    axum::extract::Path(asset_uuid_str): axum::extract::Path<String>,
) -> Response {
    use uuid::Uuid;

    // Issue #27: this HTMX endpoint stays in the user zone (it powers
    // the live mismatch indicator on the user-facing list / connect
    // page) but now requires `assets_read` so an unauthenticated or
    // unauthorised caller cannot probe asset existence by UUID. The
    // gate runs BEFORE the UUID parse so a malformed UUID does not
    // leak a different error than an unknown asset.
    if !perms.assets_read {
        return htmx_error_response("Insufficient privileges: assets:read required");
    }

    // Issue #34: capture `assets:manage` so the IPC layer can pick the
    // diagnostic-token verb (which bypasses the access-rule re-check).
    // Pre-#34 every caller went through the session-token verb, which
    // silently denied admins without an explicit access rule for the
    // asset; the verify endpoint then fell back to a green "Verified"
    // fragment on `Err`, hiding the missing live verification.
    let assets_manage = perms.assets_manage;

    let asset_uuid = match Uuid::parse_str(&asset_uuid_str) {
        Ok(u) => u,
        Err(_) => return htmx_error_response("Invalid asset identifier"),
    };

    // Fetch asset from database
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

    // Only SSH assets
    if asset.asset_type != AssetType::Ssh {
        return htmx_error_response("Not an SSH asset");
    }

    let stored_host_key = asset
        .connection_config
        .get("ssh_host_key")
        .and_then(|v| v.as_str())
        .map(String::from);

    let stored_fingerprint = asset
        .connection_config
        .get("ssh_host_key_fingerprint")
        .and_then(|v| v.as_str())
        .map(String::from);

    let stored_mismatch = asset
        .connection_config
        .get("ssh_host_key_mismatch")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let uuid_str = asset_uuid.to_string();

    // If no key is stored, return the no-key fragment right away
    // (no point contacting the server).
    if stored_host_key.is_none() {
        let html = include_str!("../../../templates/assets/_ssh_host_key_no_key_fragment.html")
            .replace("__ASSET_UUID__", &uuid_str);
        return axum::response::Html(html).into_response();
    }

    // If the mismatch flag is already set (from a failed connection),
    // return the stored mismatch state immediately.  The user must
    // explicitly click Refresh to re-check.
    if stored_mismatch {
        let fp = stored_fingerprint.as_deref().unwrap_or("unknown");
        let html =
            include_str!("../../../templates/assets/_ssh_host_key_stored_mismatch_fragment.html")
                .replace("__FINGERPRINT__", fp)
                .replace("__ASSET_UUID__", &uuid_str);
        return axum::response::Html(html).into_response();
    }

    // Try to verify against the remote server
    let proxy_client = match &state.ssh_proxy {
        Some(client) => client.clone(),
        None => {
            // Proxy unavailable - we CANNOT confirm the live key
            // matches what we have stored. The previous behaviour of
            // returning the green "Verified" fragment was a security
            // regression: a user / admin reading the page would have
            // no way to tell live verification did not actually run.
            // Return the amber "Could not verify" fragment instead.
            tracing::debug!(
                asset_uuid = %asset_uuid,
                "SSH proxy not available; returning unverified-fallback fragment"
            );
            let fp = stored_fingerprint.as_deref().unwrap_or("unknown");
            let html =
                include_str!("../../../templates/assets/_ssh_host_key_unverified_fragment.html")
                    .replace("__FINGERPRINT__", fp)
                    .replace("__ASSET_UUID__", &uuid_str);
            return axum::response::Html(html).into_response();
        }
    };

    let supervisor_ref = state.supervisor.as_deref();
    let uuid_str_for_token = asset_uuid.to_string();
    let identity = crate::ipc::HostKeyFetchIdentity {
        access_client: state.access_client.as_ref(),
        user_uuid: &_auth_user.uuid,
        asset_uuid: &uuid_str_for_token,
        caller_has_assets_manage: assets_manage,
    };
    match proxy_client
        .fetch_host_key(
            &asset.hostname,
            asset.port as u16,
            supervisor_ref,
            Some(identity),
        )
        .await
    {
        Ok((remote_key, remote_fingerprint)) => {
            let old_key = stored_host_key.as_deref().unwrap_or("");

            if old_key == remote_key {
                // Keys match - return verified fragment
                let html = include_str!("../../../templates/assets/_ssh_host_key_fragment.html")
                    .replace("__FINGERPRINT__", &remote_fingerprint)
                    .replace("__ASSET_UUID__", &uuid_str);
                axum::response::Html(html).into_response()
            } else {
                // Keys DIFFER - set mismatch flag in DB
                let old_fp = stored_fingerprint.as_deref().unwrap_or("unknown");

                tracing::warn!(
                    asset_uuid = %asset_uuid,
                    old_fingerprint = %old_fp,
                    new_fingerprint = %remote_fingerprint,
                    "SSH host key CHANGED on remote server (detected during page load verification)"
                );

                let mut config = asset.connection_config.clone();
                config["ssh_host_key_mismatch"] = serde_json::Value::Bool(true);
                if let Err(db_err) = diesel::update(dsl::assets.filter(dsl::uuid.eq(asset_uuid)))
                    .set(dsl::connection_config.eq(&config))
                    .execute(&mut conn)
                    .await
                {
                    tracing::error!(
                        asset_uuid = %asset_uuid,
                        error = %db_err,
                        "Failed to persist host key mismatch flag"
                    );
                }

                // Return mismatch fragment with both fingerprints
                let html =
                    include_str!("../../../templates/assets/_ssh_host_key_mismatch_fragment.html")
                        .replace("__OLD_FINGERPRINT__", old_fp)
                        .replace("__NEW_FINGERPRINT__", &remote_fingerprint)
                        .replace("__ASSET_UUID__", &uuid_str);
                axum::response::Html(html).into_response()
            }
        }
        Err(e) => {
            // Connection to remote server failed (network down,
            // AccessGuard refused the diagnostic token, supervisor
            // unreachable, ...). We CANNOT confirm the live key
            // matches what we have stored: returning the green
            // "Verified" fragment here would be a silent regression
            // (the operator would think verification ran when it
            // didn't). Return the amber "Could not verify" fragment.
            tracing::debug!(
                asset_uuid = %asset_uuid,
                error = %e,
                "Could not verify host key against remote server; \
                 returning unverified-fallback fragment"
            );
            let fp = stored_fingerprint.as_deref().unwrap_or("unknown");
            let html =
                include_str!("../../../templates/assets/_ssh_host_key_unverified_fragment.html")
                    .replace("__FINGERPRINT__", fp)
                    .replace("__ASSET_UUID__", &uuid_str);
            axum::response::Html(html).into_response()
        }
    }
}

/// Terminal page for SSH sessions.
///
/// GET /sessions/terminal/{session_id}
///
/// SECURITY: Verifies session ownership against the database before rendering
/// the HTML wrapper. Any failure (unknown session, terminated session, session
/// owned by another user, database error) collapses to a single `404 Not
/// Found` response so an attacker cannot distinguish "session does not exist"
/// from "session exists but belongs to someone else" by probing the URL space.
/// The underlying `terminal_ws` handler also enforces ownership via
/// `ws_session_guard`, so this is a defense-in-depth check at the HTML layer.
// allow-ungated: viewer page; instance authorization via services::session_access::verify
pub async fn terminal_page(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> Response {
    use crate::error::AppError;
    use crate::templates::base::BaseTemplate;
    use crate::templates::sessions::TerminalTemplate;

    let flash = incoming_flash.flash();

    // Validate session_id format (should be a UUID). Invalid UUIDs are user
    // input errors, not access control violations, so we keep the original
    // flash redirect (no information disclosure here: the format is checked
    // before any database lookup).
    if uuid::Uuid::parse_str(&session_id).is_err() {
        return flash_redirect(flash.error("Invalid session identifier"), "/assets");
    }

    // SECURITY (anti-IDOR + access-rule recheck): delegate to the
    // single session_access seam. It calls vauban-access::
    // VerifySessionAccess (status + ownership + access-rule re-check)
    // and applies the Casbin OR-overrides (sessions:supervise here).
    // Every denial that is not "Gone" collapses to a generic 404 so a
    // probe cannot enumerate session UUIDs by status code.
    use crate::services::session_access::{self, SessionAccessOutcome};
    use shared::messages::SessionAccessIntent;
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
        SessionAccessOutcome::Denied404 => {
            tracing::warn!(
                session_id = %session_id,
                user = %auth_user.username,
                "terminal_page denied (collapsed to 404)"
            );
            return AppError::NotFound("Session not found".to_string()).into_response();
        }
        SessionAccessOutcome::DeniedGone => {
            tracing::info!(
                session_id = %session_id,
                user = %auth_user.username,
                "terminal_page denied: session is gone (collapsed to 404)"
            );
            // The terminal HTML wrapper does not have a meaningful
            // 410 rendering; collapse to 404 so the rest of the
            // anti-enum surface stays consistent.
            return AppError::NotFound("Session not found".to_string()).into_response();
        }
    }

    let user = Some(user_context_from_auth(&auth_user));

    // Build base template with sidebar
    let base = BaseTemplate::new("SSH Terminal".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/assets");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = TerminalTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        session_id,
        websocket_url: String::new(), // Will be constructed client-side
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Failed to render terminal template: {}", e);
            flash_redirect(flash.error("Failed to load terminal page"), "/assets")
        }
    }
}
