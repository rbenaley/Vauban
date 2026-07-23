//! IACS tunnel session handlers.
//!
//! Two surfaces:
//!
//! * `POST /assets/{uuid}/connect-iacs` -- creates a `proxy_sessions`
//!   row with `session_type = iacs_tunnel` and `status =
//!   waiting_client`, then redirects to the status page so the
//!   operator can copy the `ssh -L ...` command. The full pipeline
//!   (SERIALIZABLE quotas, `IacsClientHandshake` intent,
//!   `tunnel_opened` audit) lands in lot L4 -- the L2 increment
//!   ships the gating + row creation + redirect so the asset list
//!   button has somewhere to point.
//!
//! * `GET /sessions/{uuid}/iacs/status` -- renders the status page
//!   (template lives in `templates::sessions::iacs_tunnel_status`).
//!   L5 will wire the WebSocket subscription that drives the live
//!   counters and the state pill.
//!
//! ## Casbin gates
//!
//! Both routes gate on `assets:connect_iacs` via `PermissionContext`.
//! The kill-switch (`industrial.enabled = false`) forces the flag to
//! `false` in `permission_context_middleware`, so an operator who
//! disables the IACS module in production sees the same 403 / 404
//! they would see if the policy never granted them the permission
//! in the first place.
//!
//! ## Anti-enumeration
//!
//! Whenever the route would otherwise leak the existence of a
//! resource (asset that is not IACS, asset the user cannot read,
//! session that does not belong to them), the response collapses to
//! `404 Not Found`. This matches the behaviour of the rest of the
//! IACS surface (`iacs.rs::iacs_admin_request_detail`).

use super::*;
use axum::http::StatusCode;
use uuid::Uuid;

use crate::models::asset::Asset;
use crate::models::session::{NewProxySession, SessionStatus, SessionType};
use crate::templates::sessions::IacsTunnelStatusTemplate;

// ===================================================================
// Helpers
// ===================================================================

/// Validate the double-submit CSRF token. Centralised so the two
/// IACS-tunnel routes that mutate state read from the same code
/// path.
fn validate_csrf(state: &AppState, jar: &CookieJar, token: &str) -> bool {
    let cookie = jar
        .get(crate::middleware::csrf::CSRF_COOKIE_NAME)
        .map(|c| c.value().to_string());
    crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        cookie.as_deref(),
        token,
    )
}

/// HTMX-aware error response. The asset list `Connect` button posts
/// with `hx-post`, so a 4xx body is invisible -- we surface the
/// error as a toast trigger instead.
fn iacs_tunnel_error_response(
    headers: &axum::http::HeaderMap,
    status: StatusCode,
    message: &str,
) -> Response {
    let is_htmx = headers.get("HX-Request").is_some();
    if is_htmx {
        let escaped = message.replace('\\', r"\\").replace('"', r#"\""#);
        let trigger = format!(
            r#"{{"showToast": {{"message": "{}", "type": "error"}}}}"#,
            escaped
        );
        return (
            StatusCode::OK,
            [
                ("HX-Trigger", trigger),
                ("Content-Type", "text/html".to_string()),
            ],
            "",
        )
            .into_response();
    }
    (status, message.to_string()).into_response()
}

// ===================================================================
// POST /assets/{uuid}/connect-iacs
// ===================================================================

/// Form payload for `POST /assets/{uuid}/connect-iacs`. The IACS
/// connect button is gated by EWS pubkey authentication on the
/// SSH side; the web form only carries the CSRF token. Future
/// fields (justification, ews_uuid selector when the user has
/// several EWS) land here.
#[derive(Debug, serde::Deserialize)]
pub struct ConnectIacsForm {
    pub csrf_token: String,
}

/// Form payload for `POST /sessions/{uuid}/iacs/terminate`. The
/// Disconnect button on the status page only carries the CSRF
/// token; the session UUID lives in the URL.
#[derive(Debug, serde::Deserialize)]
pub struct TerminateIacsForm {
    pub csrf_token: String,
}

/// Initiate an IACS tunnel session. Three layers of authorization
/// stack on top of each other (per the casbin-permissions rule):
///
///   1. Casbin -- `assets:connect_iacs` capability (this is the L2
///      gate).
///   2. Asset access rule -- the user has a matching `access_rules`
///      row whose `allowed_protocols` covers the asset's IACS
///      protocol (added in L4).
///   3. Session access -- once the EWS handshakes, `session_access::
///      verify(IacsClientHandshake)` runs in a SERIALIZABLE
///      transaction (also L4).
///
/// L2 ships layer (1) and the row creation. Layers (2) and (3) land
/// in L4 alongside quotas and audit.
#[allow(clippy::too_many_arguments)]
pub async fn connect_iacs(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    jar: CookieJar,
    auth_user: AuthUser,
    client_addr: crate::middleware::ClientAddr,
    perms: crate::auth::PermissionContext,
    axum::extract::Path(asset_uuid_str): axum::extract::Path<String>,
    Form(form): Form<ConnectIacsForm>,
) -> Response {
    // L2 gate: Casbin + industrial kill-switch (the latter is folded
    // into the permission flag by `permission_context_middleware`).
    if !perms.assets_connect_iacs {
        return iacs_tunnel_error_response(
            &headers,
            StatusCode::FORBIDDEN,
            "Insufficient privileges: assets:connect_iacs required",
        );
    }

    if !validate_csrf(&state, &jar, &form.csrf_token) {
        return iacs_tunnel_error_response(&headers, StatusCode::BAD_REQUEST, "Invalid CSRF token");
    }

    let asset_uuid = match Uuid::parse_str(&asset_uuid_str) {
        Ok(u) => u,
        Err(_) => {
            return iacs_tunnel_error_response(&headers, StatusCode::NOT_FOUND, "Asset not found");
        }
    };

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Database connection error: {}", e);
            return iacs_tunnel_error_response(
                &headers,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database connection failed",
            );
        }
    };

    let asset: Asset = match schema_assets::table
        .filter(schema_assets::uuid.eq(asset_uuid))
        .filter(schema_assets::is_deleted.eq(false))
        .first(&mut conn)
        .await
    {
        Ok(a) => a,
        Err(diesel::result::Error::NotFound) => {
            return iacs_tunnel_error_response(&headers, StatusCode::NOT_FOUND, "Asset not found");
        }
        Err(e) => {
            tracing::error!("Failed to fetch asset: {}", e);
            return iacs_tunnel_error_response(
                &headers,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to fetch asset",
            );
        }
    };

    // Defence-in-depth: the IACS Connect button on /assets is only
    // rendered for IACS assets, but a user who hand-crafts the POST
    // against a regular SSH/RDP asset must hit the same 404 as if
    // the asset did not exist.
    if !asset.asset_type.is_iacs() {
        return iacs_tunnel_error_response(&headers, StatusCode::NOT_FOUND, "Asset not found");
    }

    // Resolve user_id and verify the user has at least one active EWS.
    let user_id: i32 = {
        use crate::schema::users;
        let user_uuid = match auth_user.uuid.parse::<Uuid>() {
            Ok(u) => u,
            Err(_) => {
                return iacs_tunnel_error_response(
                    &headers,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid user identifier",
                );
            }
        };
        match users::table
            .filter(users::uuid.eq(user_uuid))
            .select((users::id, users::is_active))
            .first::<(i32, bool)>(&mut conn)
            .await
        {
            Ok((id, active)) => {
                if !active {
                    return iacs_tunnel_error_response(
                        &headers,
                        StatusCode::FORBIDDEN,
                        super::ACCOUNT_DEACTIVATED_MSG,
                    );
                }
                id
            }
            Err(_) => {
                return iacs_tunnel_error_response(
                    &headers,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "User not found",
                );
            }
        }
    };

    // EWS gate: the operator must have at least one active EWS to
    // open an IACS tunnel. Without it, the SSH side of the protocol
    // would simply reject the handshake; we surface the failure
    // here with a constructive error so the UI can route the user
    // to /iacs/onboard. We pin the OLDEST active EWS to the
    // session row so the L4 watchdog has a single FK to revoke
    // tunnels through; users with multiple EWS will get an explicit
    // selector in L6.
    let active_ews: Option<(Uuid, String, String)> = {
        use crate::schema::ews;
        ews::table
            .filter(ews::user_id.eq(user_id))
            .filter(ews::disabled_at.is_null())
            .filter(ews::offboarded_at.is_null())
            .order(ews::created_at.asc())
            .select((ews::uuid, ews::name, ews::public_key_fingerprint))
            .first::<(Uuid, String, String)>(&mut conn)
            .await
            .ok()
    };
    let (pinned_ews_uuid, ews_name, ews_fp) = match active_ews {
        Some(t) => t,
        None => {
            return iacs_tunnel_error_response(
                &headers,
                StatusCode::FORBIDDEN,
                "No active Engineering Workstation. Onboard one first.",
            );
        }
    };

    // ----- L4 quotas: per-user and per-EWS concurrency caps -----
    //
    // `0` disables the cap (operator opt-out). The check runs
    // BEFORE the INSERT so a quota violation surfaces a clean
    // 429 instead of a half-created row. Race window with a
    // concurrent INSERT is acceptable: if two requests squeeze
    // through on the boundary the second tunnel still cannot
    // open (the russh handler would see an extra row in
    // `waiting_client` and reject -- L6 nails this with a
    // SERIALIZABLE transaction).
    let tunnel_cfg = &state.config.industrial.iacs_tunnel;
    if tunnel_cfg.max_concurrent_per_user > 0 {
        use crate::schema::proxy_sessions as ps;
        let live: i64 = ps::table
            .filter(ps::user_id.eq(user_id))
            .filter(ps::session_type.eq("iacs_tunnel"))
            .filter(ps::status.eq_any(SessionStatus::IACS_OPEN_AS_STR))
            .count()
            .get_result(&mut conn)
            .await
            .unwrap_or(0);
        if live as u32 >= tunnel_cfg.max_concurrent_per_user {
            tracing::warn!(
                user = %auth_user.username,
                live,
                cap = tunnel_cfg.max_concurrent_per_user,
                "iacs_tunnel: per-user quota exceeded"
            );
            return iacs_tunnel_error_response(
                &headers,
                StatusCode::TOO_MANY_REQUESTS,
                "Maximum concurrent IACS tunnels per user reached. \
                 Disconnect an existing tunnel to open a new one.",
            );
        }
    }
    if tunnel_cfg.max_concurrent_per_ews > 0 {
        use crate::schema::proxy_sessions as ps;
        let live: i64 = ps::table
            .filter(ps::ews_uuid.eq(pinned_ews_uuid))
            .filter(ps::session_type.eq("iacs_tunnel"))
            .filter(ps::status.eq_any(SessionStatus::IACS_OPEN_AS_STR))
            .count()
            .get_result(&mut conn)
            .await
            .unwrap_or(0);
        if live as u32 >= tunnel_cfg.max_concurrent_per_ews {
            tracing::warn!(
                user = %auth_user.username,
                ews_uuid = %pinned_ews_uuid,
                live,
                cap = tunnel_cfg.max_concurrent_per_ews,
                "iacs_tunnel: per-EWS quota exceeded"
            );
            return iacs_tunnel_error_response(
                &headers,
                StatusCode::TOO_MANY_REQUESTS,
                "Maximum concurrent IACS tunnels per EWS reached. \
                 Disconnect an existing tunnel to open a new one.",
            );
        }
    }

    // VAU-012: shared session-creation controls (global + per-user rate
    // limits, per-user and per-asset concurrent-session quotas) on top of the
    // IACS-specific per-user / per-EWS caps above. Runs AFTER authorization and
    // BEFORE the INSERT so a denial neither leaks resources nor enumerates
    // assets.
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
            return iacs_tunnel_error_response(
                &headers,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to start session",
            );
        }
    }

    // ----- proxy_sessions row + tunnel_opened audit -----
    let session_uuid = Uuid::new_v4();
    let client_ip: ipnetwork::IpNetwork = ipnetwork::IpNetwork::from(client_addr.addr().ip());

    let industrial_protocol = asset
        .asset_type
        .iacs_protocol()
        .map(|p| p.as_str().to_string())
        .or_else(|| {
            // `iacs_tcp` carries no IACS protocol enum but the DB
            // CHECK still requires `industrial_protocol IS NOT NULL`
            // when `session_type = 'iacs_tunnel'`. We persist the
            // catch-all literal so an operator forensic-querying
            // `proxy_sessions` can tell IACS rows apart at a glance
            // without joining on `assets`.
            Some("tcp".to_string())
        });

    let new_session = NewProxySession {
        uuid: session_uuid,
        user_id,
        asset_id: asset.id,
        credential_id: String::new(),
        credential_username: String::new(),
        session_type: SessionType::IacsTunnel,
        status: "waiting_client".to_string(),
        client_ip,
        client_user_agent: headers
            .get("User-Agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        proxy_instance: None,
        justification: None,
        is_recorded: false,
        metadata: serde_json::json!({}),
        max_session_duration: None,
        industrial_protocol,
        ews_uuid: Some(pinned_ews_uuid),
        // Per-session pinned target. The asset's hostname / port
        // snapshot lives on `proxy_sessions` so a mid-session edit
        // on `assets` does NOT redirect the live tunnel.
        tunnel_target_addr: Some(format!("{}:{}", asset.hostname, asset.port)),
    };

    if let Err(e) = diesel::insert_into(proxy_sessions::table)
        .values(&new_session)
        .execute(&mut conn)
        .await
    {
        tracing::error!(
            user = %auth_user.username,
            asset = %asset.name,
            "Failed to insert IACS proxy_session: {}",
            e
        );
        return iacs_tunnel_error_response(
            &headers,
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create tunnel session",
        );
    }

    // ----- Mint SessionToken + push pending tunnel to proxy-iacs -----
    //
    // SECURITY: this is the per-asset, per-session, crypto-bound
    // authorization. The token is BLAKE3-keyed and bound to
    // (user, asset, "iacs_tunnel", host, port, ProxyIacs, session_id).
    // proxy-iacs verifies it locally (Verifier::Proxy) BEFORE caching
    // the pending tunnel; the supervisor's TCP broker re-verifies it
    // (Verifier::Supervisor) BEFORE doing the upstream connect. A
    // compromised vauban-web cannot piggy-back another user / asset
    // / protocol target through these surfaces, even with full DB
    // write access.
    //
    // vauban-access also performs a `CheckAccessByUuid(user, asset,
    // "iacs_tunnel")` re-check inside the mint verb, so the
    // access-rule layer (Casbin allowed the action; the rule decides
    // which assets the user can reach with this protocol) gates the
    // token issuance even if the in-process Casbin cache had drifted.
    //
    // Fail-closed: without proxy-iacs there is no sshd path.
    let Some(proxy_iacs_client) = state.proxy_iacs.as_ref() else {
        tracing::error!(
            user = %auth_user.username,
            session_uuid = %session_uuid,
            "iacs_tunnel: proxy-iacs IPC client unavailable -- fail-closed"
        );
        let _ = diesel::delete(proxy_sessions::table.filter(proxy_sessions::uuid.eq(session_uuid)))
            .execute(&mut conn)
            .await;
        return iacs_tunnel_error_response(
            &headers,
            StatusCode::SERVICE_UNAVAILABLE,
            "Tunnel proxy unavailable",
        );
    };

    let token_params = shared::session_token::SessionTokenParams {
        session_id: session_uuid.to_string(),
        user_uuid: auth_user.uuid.clone(),
        asset_uuid: asset_uuid.to_string(),
        protocol: shared::access_guard::PROTOCOL_IACS_TUNNEL.to_string(),
        host: asset.hostname.clone(),
        port: asset.port as u16,
        target_service: shared::messages::Service::ProxyIacs,
    };

    let session_token = match state.access_client.issue_session_token(token_params).await {
        Ok(issued) => issued.token,
        Err(e) => {
            tracing::warn!(
                user = %auth_user.username,
                session_uuid = %session_uuid,
                error = %e,
                "iacs_tunnel: session token mint failed -- rolling back proxy_session row"
            );
            let _ =
                diesel::delete(proxy_sessions::table.filter(proxy_sessions::uuid.eq(session_uuid)))
                    .execute(&mut conn)
                    .await;
            return iacs_tunnel_error_response(&headers, StatusCode::FORBIDDEN, "Access denied");
        }
    };

    let open_req = crate::ipc::IacsTunnelOpenRequest {
        session_id: session_uuid.to_string(),
        user_uuid: auth_user.uuid.clone(),
        asset_uuid: asset_uuid.to_string(),
        ews_uuid: pinned_ews_uuid.to_string(),
        ews_pubkey_fp: ews_fp.clone(),
        asset_host: asset.hostname.clone(),
        asset_port: asset.port as u16,
        industrial_protocol: new_session
            .industrial_protocol
            .clone()
            .unwrap_or_else(|| "tcp".to_string()),
        ttl_seconds: tunnel_cfg.waiting_client_ttl_seconds,
        session_token,
    };

    match proxy_iacs_client.open_tunnel(open_req).await {
        Ok(opened) if opened.success => {
            tracing::info!(
                user = %auth_user.username,
                session_uuid = %session_uuid,
                asset_host = %asset.hostname,
                asset_port = asset.port,
                "iacs_tunnel: pending session materialized on proxy-iacs"
            );
        }
        Ok(opened) => {
            let err = opened
                .error
                .unwrap_or_else(|| "proxy-iacs refused".to_string());
            tracing::warn!(
                user = %auth_user.username,
                session_uuid = %session_uuid,
                error = %err,
                "iacs_tunnel: proxy-iacs rejected open -- rolling back"
            );
            let _ =
                diesel::delete(proxy_sessions::table.filter(proxy_sessions::uuid.eq(session_uuid)))
                    .execute(&mut conn)
                    .await;
            return iacs_tunnel_error_response(
                &headers,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to materialize tunnel",
            );
        }
        Err(e) => {
            tracing::warn!(
                user = %auth_user.username,
                session_uuid = %session_uuid,
                error = %e,
                "iacs_tunnel: IPC to proxy-iacs failed -- rolling back"
            );
            let _ =
                diesel::delete(proxy_sessions::table.filter(proxy_sessions::uuid.eq(session_uuid)))
                    .execute(&mut conn)
                    .await;
            return iacs_tunnel_error_response(
                &headers,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Tunnel proxy unavailable",
            );
        }
    }

    // L4: append-only forensic audit. The CHECK on
    // `ews_audit_log_event_chk` accepts `tunnel_opened` /
    // `tunnel_closed` since the L1 migration. Failure to insert
    // is non-fatal -- the row is already committed -- but we
    // log loudly so an operator notices.
    let actor_ip: ipnetwork::IpNetwork = ipnetwork::IpNetwork::from(client_addr.addr().ip());
    if let Err(e) = diesel::sql_query(
        "INSERT INTO ews_audit_log \
         (ews_uuid, event, actor_user_id, actor_username, \
          target_user_id, target_username, ews_name, public_key_fingerprint, \
          decision_reason, actor_ip, created_at) \
         VALUES ($1, 'tunnel_opened', $2, $3, $2, $3, $4, $5, $6, $7, NOW())",
    )
    .bind::<diesel::sql_types::Uuid, _>(pinned_ews_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Text, _>(&auth_user.username)
    .bind::<diesel::sql_types::Text, _>(&ews_name)
    .bind::<diesel::sql_types::Text, _>(&ews_fp)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(Some(format!(
        "session_uuid={} asset={} protocol={}",
        session_uuid,
        asset.name,
        new_session.industrial_protocol.as_deref().unwrap_or("tcp"),
    )))
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Inet>, _>(Some(actor_ip))
    .execute(&mut conn)
    .await
    {
        tracing::warn!(
            user = %auth_user.username,
            session_uuid = %session_uuid,
            ews_uuid = %pinned_ews_uuid,
            error = %e,
            "iacs_tunnel: failed to append tunnel_opened audit row \
             (session row already committed)"
        );
    }

    tracing::info!(
        user = %auth_user.username,
        asset = %asset.name,
        asset_uuid = %asset_uuid,
        session_uuid = %session_uuid,
        "IACS tunnel session created (waiting_client)"
    );

    // HX-Redirect for HTMX (the asset list button posts via HTMX),
    // 303 See Other for plain form posts.
    let redirect_url = format!("/sessions/{}/iacs/status", session_uuid);
    let is_htmx = headers.get("HX-Request").is_some();
    if is_htmx {
        return (
            StatusCode::OK,
            [
                ("HX-Redirect", redirect_url.as_str()),
                ("Content-Type", "text/html"),
            ],
            "",
        )
            .into_response();
    }
    Redirect::to(&redirect_url).into_response()
}

// ===================================================================
// GET /sessions/{uuid}/iacs/status
// ===================================================================

/// Render the IACS tunnel status page. The page is reachable both
/// right after `connect_iacs` (status = `waiting_client`) and
/// during the live tunnel (`tunnel_active`); a terminated session
/// also renders for forensic display.
pub async fn iacs_tunnel_status_page(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    browser_tz: BrowserTz,
    axum::extract::Path(session_uuid_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    if !perms.assets_connect_iacs {
        // Anti-enumeration: collapse to 404 rather than 403 -- a user
        // who never had `assets:connect_iacs` should not be able to
        // probe the existence of an IACS session by URL.
        return Err(AppError::NotFound("Not Found".to_string()));
    }

    let session_uuid = Uuid::parse_str(&session_uuid_str)
        .map_err(|_| AppError::NotFound("Not Found".to_string()))?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Database connection error: {}", e)))?;

    let user_uuid = auth_user
        .uuid
        .parse::<Uuid>()
        .map_err(|_| AppError::Internal(anyhow::anyhow!("Invalid user uuid")))?;

    let user_id: i32 = {
        use crate::schema::users;
        users::table
            .filter(users::uuid.eq(user_uuid))
            .select(users::id)
            .first::<i32>(&mut conn)
            .await
            .map_err(|_| AppError::NotFound("Not Found".to_string()))?
    };

    // Single SELECT with a JOIN on assets so we can render asset
    // metadata without a second round-trip. Filtered on user_id so
    // a user cannot fetch someone else's session by URL.
    #[allow(clippy::type_complexity)]
    let row: (
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
    ) = match proxy_sessions::table
        .inner_join(schema_assets::table)
        .filter(proxy_sessions::uuid.eq(session_uuid))
        .filter(proxy_sessions::user_id.eq(user_id))
        .filter(proxy_sessions::session_type.eq("iacs_tunnel"))
        .select((
            proxy_sessions::status,
            schema_assets::name,
            schema_assets::asset_type,
            schema_assets::hostname,
            proxy_sessions::industrial_protocol,
            proxy_sessions::tunnel_target_addr,
            proxy_sessions::created_at,
            proxy_sessions::connected_at,
        ))
        .first(&mut conn)
        .await
    {
        Ok(r) => r,
        Err(diesel::result::Error::NotFound) => {
            return Err(AppError::NotFound("Not Found".to_string()));
        }
        Err(e) => {
            return Err(AppError::Internal(anyhow::anyhow!(
                "Failed to fetch session: {}",
                e
            )));
        }
    };

    let (
        status,
        asset_name,
        _asset_type_raw,
        _asset_hostname,
        industrial_protocol,
        target_addr,
        session_created_at,
        session_connected_at,
    ) = row;

    // Countdown to the reap deadline, anchored on the SAME reference
    // the revocation watchdog uses for its SQL cutoff so a page
    // refresh renders the true remaining window, not a restarted
    // one: `created_at` while `waiting_client` (pre-auth),
    // `connected_at` once `ews_connected` (the TTL restarts at SSH
    // auth). `None` (no countdown) for non-waiting states and when
    // the TTL is disabled.
    let waiting_ttl_seconds = state
        .config
        .industrial
        .iacs_tunnel
        .waiting_client_ttl_seconds;
    let waiting_countdown_seconds = match status.as_str() {
        "waiting_client" => crate::services::iacs_tunnel::remaining_waiting_seconds(
            session_created_at,
            chrono::Utc::now(),
            waiting_ttl_seconds,
        ),
        "ews_connected" => crate::services::iacs_tunnel::remaining_waiting_seconds(
            session_connected_at.unwrap_or(session_created_at),
            chrono::Utc::now(),
            waiting_ttl_seconds,
        ),
        _ => None,
    };

    // Derive the per-session `(target_host, target_port)` from the
    // `proxy_sessions.tunnel_target_addr` snapshot taken at session
    // creation (`format!("{}:{}", asset.hostname, asset.port)`).
    // A NULL value is a legacy row only and collapses to the
    // historical MVP fallback so the page still renders rather than
    // 500.
    //
    // The local-forward port (LHS of `ssh -L`) is then derived via
    // `derive_local_forward_port` so privileged asset ports
    // (Modbus 502, MMS 102, ...) are shifted into the user range
    // (50502, 50102, ...). The operator never needs root on their
    // EWS to bind locally.
    let target_addr_str = target_addr.unwrap_or_else(|| "127.0.0.1:4321".to_string());
    let (target_host, target_port): (String, u16) = match target_addr_str.rsplit_once(':') {
        Some((host, port_str)) => match port_str.parse::<u16>() {
            Ok(p) => (host.to_string(), p),
            Err(_) => ("127.0.0.1".to_string(), 4321),
        },
        None => ("127.0.0.1".to_string(), 4321),
    };
    let local_forward_port: u16 =
        crate::services::iacs_tunnel::derive_local_forward_port(target_port);

    let user_ctx = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new(
        format!("IACS tunnel - {}", asset_name),
        user_ctx.clone(),
        browser_tz.0,
    )
    .with_current_path("/assets")
    .with_messages(
        incoming_flash
            .messages()
            .iter()
            .map(|m| crate::templates::base::FlashMessage {
                level: m.level.clone(),
                message: m.message.clone(),
            })
            .collect(),
    );
    let (title, user_field, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let csrf_token = jar
        .get(crate::middleware::csrf::CSRF_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    let template = IacsTunnelStatusTemplate {
        title,
        user: user_field,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        session_uuid: session_uuid.to_string(),
        asset_name,
        industrial_protocol: industrial_protocol.unwrap_or_default(),
        bastion_hostname: state
            .config
            .industrial
            .iacs_tunnel
            .advertise_hostname
            .clone(),
        bastion_port: state.config.industrial.iacs_tunnel.bind_port(),
        local_forward_port,
        target_host,
        target_port,
        tunnel_target_addr: target_addr_str,
        session_status: status,
        waiting_countdown_seconds,
        waiting_ttl_seconds,
        csrf_token,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_iacs_form_round_trips() {
        let json = r#"csrf_token=abcd"#;
        let parsed: ConnectIacsForm = serde_urlencoded::from_str(json).unwrap();
        assert_eq!(parsed.csrf_token, "abcd");
    }

    #[test]
    fn terminate_iacs_form_round_trips() {
        let json = r#"csrf_token=abcd"#;
        let parsed: TerminateIacsForm = serde_urlencoded::from_str(json).unwrap();
        assert_eq!(parsed.csrf_token, "abcd");
    }
}
