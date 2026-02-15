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
pub async fn connect_ssh(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    jar: CookieJar,
    auth_user: AuthUser,
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

    // Get SSH proxy client
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

    // Resolve authenticated user's integer ID for database insertion
    let user_id: i32 = {
        use crate::schema::users;
        match auth_user.uuid.parse::<Uuid>() {
            Ok(user_uuid) => match users::table
                .filter(users::uuid.eq(user_uuid))
                .select(users::id)
                .first(&mut conn)
                .await
            {
                Ok(id) => id,
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

    // Extract connection details from asset's connection_config
    let config = &asset.connection_config;

    // Determine username from:
    // 1. Form override
    // 2. connection_config.username (if present in JSON)
    // 3. Default "root"
    let config_username = config
        .get("username")
        .and_then(|v| v.as_str())
        .map(String::from);

    let username = form
        .username
        .filter(|u| !u.is_empty())
        .or(config_username)
        .unwrap_or_else(|| "root".to_string());

    // Extract authentication credentials from connection_config
    let auth_type = config
        .get("auth_type")
        .and_then(|v| v.as_str())
        .unwrap_or("password")
        .to_string();

    // C-2 + H-10: Decrypt credentials via vault if encrypted, then wrap in SecretString.
    // Helper closure for vault-aware credential extraction.
    let vault_ref = state.vault_client.as_ref();

    let password = match config.get("password").and_then(|v| v.as_str()) {
        Some(val) if !val.is_empty() => {
            if is_encrypted(val) {
                if let Some(vault) = vault_ref {
                    match vault.decrypt("credentials", val).await {
                        Ok(decrypted) => Some(secrecy::SecretString::from(decrypted.into_inner())),
                        Err(e) => {
                            tracing::error!("Failed to decrypt password: {}", e);
                            let msg = "Failed to decrypt credentials";
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
                } else {
                    tracing::warn!("Encrypted credential found but vault not available");
                    None
                }
            } else {
                Some(secrecy::SecretString::from(val.to_string()))
            }
        }
        _ => None,
    };

    let private_key = match config.get("private_key").and_then(|v| v.as_str()) {
        Some(val) if !val.is_empty() => {
            if is_encrypted(val) {
                if let Some(vault) = vault_ref {
                    match vault.decrypt("credentials", val).await {
                        Ok(decrypted) => Some(secrecy::SecretString::from(decrypted.into_inner())),
                        Err(e) => {
                            tracing::error!("Failed to decrypt private_key: {}", e);
                            let msg = "Failed to decrypt credentials";
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
                } else {
                    tracing::warn!("Encrypted credential found but vault not available");
                    None
                }
            } else {
                Some(secrecy::SecretString::from(val.to_string()))
            }
        }
        _ => None,
    };

    let passphrase = match config.get("passphrase").and_then(|v| v.as_str()) {
        Some(val) if !val.is_empty() => {
            if is_encrypted(val) {
                if let Some(vault) = vault_ref {
                    match vault.decrypt("credentials", val).await {
                        Ok(decrypted) => Some(secrecy::SecretString::from(decrypted.into_inner())),
                        Err(e) => {
                            tracing::error!("Failed to decrypt passphrase: {}", e);
                            let msg = "Failed to decrypt credentials";
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
                } else {
                    tracing::warn!("Encrypted credential found but vault not available");
                    None
                }
            } else {
                Some(secrecy::SecretString::from(val.to_string()))
            }
        }
        _ => None,
    };

    // Extract stored SSH host key for verification (H-9)
    let expected_host_key = config
        .get("ssh_host_key")
        .and_then(|v| v.as_str())
        .map(String::from);

    // Record the session in the database for ownership tracking.
    // This allows the ws_session_guard middleware to verify that the
    // WebSocket client owns the session before allowing the upgrade.
    {
        use crate::models::session::{NewProxySession, SessionType};
        // SAFETY: "0.0.0.0/0" is a valid CIDR; if parse() somehow fails,
    // fall back to the equivalent IpNetwork constructed from Ipv4Addr.
    let client_ip: ipnetwork::IpNetwork = "0.0.0.0/0".parse().unwrap_or_else(
        |_| ipnetwork::IpNetwork::V4(ipnetwork::Ipv4Network::from(std::net::Ipv4Addr::UNSPECIFIED)),
    );
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
            justification: None,
            is_recorded: true,
            metadata: serde_json::json!({}),
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
        password,
        private_key,
        passphrase,
        expected_host_key,
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
                let msg = response.error.unwrap_or_else(|| "Connection failed".to_string());

                // Detect host key mismatch errors and persist the
                // mismatch flag in connection_config so that the asset
                // detail page can display the warning state (H-9).
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
                    if let Err(db_err) = diesel::update(
                        dsl::assets.filter(dsl::uuid.eq(asset_uuid)),
                    )
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
                if let Err(db_err) = diesel::update(
                    dsl::assets.filter(dsl::uuid.eq(asset_uuid)),
                )
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
    axum::extract::Path(asset_uuid_str): axum::extract::Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    use uuid::Uuid;

    // Require staff/superuser
    if !auth_user.is_staff && !auth_user.is_superuser {
        return htmx_error_response("Insufficient privileges: staff or superuser required");
    }

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
    let supervisor_ref = state.supervisor.as_deref();
    let (host_key, fingerprint) =
        match proxy_client
            .fetch_host_key(&asset.hostname, asset.port as u16, supervisor_ref)
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
    config.as_object_mut().map(|m| m.remove("ssh_host_key_mismatch"));

    use chrono::Utc;
    if let Err(e) = diesel::update(dsl::assets.filter(dsl::uuid.eq(asset_uuid)))
        .set((
            dsl::connection_config.eq(&config),
            dsl::updated_at.eq(Utc::now()),
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
    axum::extract::Path(asset_uuid_str): axum::extract::Path<String>,
) -> Response {
    use uuid::Uuid;

    // Parse UUID
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
        let html = include_str!("../../../templates/assets/_ssh_host_key_stored_mismatch_fragment.html")
            .replace("__FINGERPRINT__", fp)
            .replace("__ASSET_UUID__", &uuid_str);
        return axum::response::Html(html).into_response();
    }

    // Try to verify against the remote server
    let proxy_client = match &state.ssh_proxy {
        Some(client) => client.clone(),
        None => {
            // Proxy unavailable - fall back to stored state
            tracing::debug!(asset_uuid = %asset_uuid, "SSH proxy not available, returning stored state");
            let fp = stored_fingerprint.as_deref().unwrap_or("unknown");
            let html = include_str!("../../../templates/assets/_ssh_host_key_fragment.html")
                .replace("__FINGERPRINT__", fp)
                .replace("__ASSET_UUID__", &uuid_str);
            return axum::response::Html(html).into_response();
        }
    };

    let supervisor_ref = state.supervisor.as_deref();
    match proxy_client.fetch_host_key(&asset.hostname, asset.port as u16, supervisor_ref).await {
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
                if let Err(db_err) = diesel::update(
                    dsl::assets.filter(dsl::uuid.eq(asset_uuid)),
                )
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
                let html = include_str!("../../../templates/assets/_ssh_host_key_mismatch_fragment.html")
                    .replace("__OLD_FINGERPRINT__", old_fp)
                    .replace("__NEW_FINGERPRINT__", &remote_fingerprint)
                    .replace("__ASSET_UUID__", &uuid_str);
                axum::response::Html(html).into_response()
            }
        }
        Err(e) => {
            // Connection to remote server failed - fall back to stored state
            tracing::debug!(
                asset_uuid = %asset_uuid,
                error = %e,
                "Could not verify host key against remote server, using stored state"
            );
            let fp = stored_fingerprint.as_deref().unwrap_or("unknown");
            let html = include_str!("../../../templates/assets/_ssh_host_key_fragment.html")
                .replace("__FINGERPRINT__", fp)
                .replace("__ASSET_UUID__", &uuid_str);
            axum::response::Html(html).into_response()
        }
    }
}

/// Terminal page for SSH sessions.
///
/// GET /sessions/terminal/{session_id}
pub async fn terminal_page(
    State(_state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> Response {
    use crate::templates::base::BaseTemplate;
    use crate::templates::sessions::TerminalTemplate;

    let flash = incoming_flash.flash();

    // Validate session_id format (should be a UUID)
    if uuid::Uuid::parse_str(&session_id).is_err() {
        return flash_redirect(flash.error("Invalid session identifier"), "/assets");
    }

    // TODO: Verify session exists and belongs to user via IPC or database

    let user = Some(user_context_from_auth(&auth_user));

    // Build base template with sidebar
    let base = BaseTemplate::new("SSH Terminal".to_string(), user.clone())
        .with_current_path("/assets");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

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
