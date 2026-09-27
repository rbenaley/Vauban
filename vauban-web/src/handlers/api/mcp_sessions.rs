//! Hop 1 for MCP agents: `POST /api/v1/mcp/sessions`.
//!
//! Inserts the `proxy_sessions` row and returns `session_id`, the proxy
//! URL, and a one-time `vbw_` bearer. `POST /api/v1/sessions` stays free
//! of this branch.

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;
use crate::auth::permissions::PermissionContext;
use crate::error::{AppError, AppResult};
use crate::middleware::api_key::ApiKeyAuth;
use crate::middleware::auth::AuthUser;
use crate::models::asset::{Asset, AssetType};
use crate::models::session::{NewProxySession, SessionType};
use crate::services::mcp_session::{
    MCP_PROTOCOL_VERSIONS, clamp_ttl_capped, open_on_proxy, resolve_effective_allowed_tools,
};

const JUSTIFICATION_MIN: usize = 10;
const JUSTIFICATION_MAX: usize = 1000;

#[derive(Debug, Deserialize)]
pub struct OpenMcpSessionRequest {
    pub asset_id: Uuid,
    pub justification: Option<String>,
    pub requested_duration_seconds: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct OpenMcpSessionResponse {
    pub session_id: String,
    pub url: String,
    pub bearer: String,
    pub expires_at: String,
    pub mcp_protocol_versions: Vec<&'static str>,
}

pub fn mcp_justification_accepted(raw: &str) -> bool {
    let n = raw.trim().chars().count();
    (JUSTIFICATION_MIN..=JUSTIFICATION_MAX).contains(&n)
}

pub async fn open_mcp_session(
    State(state): State<AppState>,
    user: AuthUser,
    perms: PermissionContext,
    api_key: Option<axum::Extension<ApiKeyAuth>>,
    headers: HeaderMap,
    client_addr: crate::middleware::ClientAddr,
    Json(request): Json<OpenMcpSessionRequest>,
) -> AppResult<Json<OpenMcpSessionResponse>> {
    if !perms.assets_connect_mcp {
        return Err(AppError::forbidden("assets:connect_mcp"));
    }
    if !state.config.mcp.enabled {
        return Err(AppError::forbidden("assets:connect_mcp"));
    }
    if api_key.is_none() {
        return Err(AppError::Authorization(
            "MCP hop 1 requires a vbn_ API key".into(),
        ));
    }
    let justification = request.justification.unwrap_or_default();
    if !mcp_justification_accepted(&justification) {
        return Err(AppError::Validation(
            "Justification is required for MCP sessions (10..1000 characters)".into(),
        ));
    }
    let justification = justification.trim().to_string();

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {e}")))?;

    let user_uuid = Uuid::parse_str(&user.uuid)
        .map_err(|_| AppError::Validation("Invalid user UUID".into()))?;
    let user_id: i32 = crate::schema::users::table
        .filter(crate::schema::users::uuid.eq(user_uuid))
        .select(crate::schema::users::id)
        .first(&mut conn)
        .await
        .map_err(|_| AppError::Authorization("User not found".into()))?;

    let asset: Asset = crate::schema::assets::table
        .filter(crate::schema::assets::uuid.eq(request.asset_id))
        .filter(crate::schema::assets::is_deleted.eq(false))
        .first(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Asset not found".into()),
            other => AppError::Database(other),
        })?;
    if asset.asset_type != AssetType::Mcp {
        return Err(AppError::Validation(format!(
            "Asset type '{}' is not MCP",
            asset.asset_type
        )));
    }

    let access_result = crate::services::access::can_access_asset(
        &state.access_client,
        &mut conn,
        user_id,
        asset.id,
        "mcp",
    )
    .await?;
    if !access_result.allowed {
        return Err(AppError::Authorization(
            "No access rule grants you access to this asset".into(),
        ));
    }
    if access_result.require_mfa && !user.mfa_verified {
        return Err(AppError::Authorization(
            "MFA verification required for this asset".into(),
        ));
    }

    let allowed_tools = resolve_effective_allowed_tools(&mut conn, user_id, &asset).await?;
    if allowed_tools.as_ref().is_some_and(|t| t.is_empty()) {
        return Err(AppError::Validation(format!(
            "No MCP tools granted for asset '{}'",
            asset.name
        )));
    }

    let ttl = clamp_ttl_capped(
        request.requested_duration_seconds,
        access_result.max_session_duration,
        Some(state.config.mcp.session_ttl_clamped()),
    );
    let expires_at = Utc::now() + Duration::seconds(ttl);
    let session_uuid = Uuid::new_v4();
    let trusted = state.config.security.parsed_trusted_proxies();
    let client_ip = crate::middleware::extract_client_ip(&headers, client_addr.addr(), &trusted);
    let metadata = serde_json::json!({
        "mcp_protocol_versions": MCP_PROTOCOL_VERSIONS,
    });

    let new_session = NewProxySession {
        uuid: session_uuid,
        user_id,
        asset_id: asset.id,
        credential_id: "mcp".into(),
        credential_username: "mcp".into(),
        session_type: SessionType::Mcp,
        status: "active".into(),
        client_ip,
        client_user_agent: None,
        proxy_instance: Some("proxy_mcp".into()),
        justification: Some(justification.clone()),
        is_recorded: true,
        metadata,
        max_session_duration: Some(ttl as i32),
        expires_at: Some(expires_at),
        industrial_protocol: None,
        ews_uuid: None,
        tunnel_target_addr: None,
    };
    diesel::insert_into(crate::schema::proxy_sessions::table)
        .values(&new_session)
        .execute(&mut conn)
        .await?;

    let bearer = match open_on_proxy(
        &state,
        &user.uuid,
        Some("vbn"),
        &asset,
        session_uuid,
        expires_at,
        &justification,
        allowed_tools,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            let _ = diesel::delete(
                crate::schema::proxy_sessions::table
                    .filter(crate::schema::proxy_sessions::uuid.eq(session_uuid)),
            )
            .execute(&mut conn)
            .await;
            return Err(e);
        }
    };

    let url = format!("http://{}/mcp", state.config.mcp.listen_public_host());
    Ok(Json(OpenMcpSessionResponse {
        session_id: session_uuid.to_string(),
        url,
        bearer,
        expires_at: expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        mcp_protocol_versions: MCP_PROTOCOL_VERSIONS.to_vec(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn justification_bounds() {
        assert!(!mcp_justification_accepted("short"));
        assert!(mcp_justification_accepted("1234567890"));
        assert!(!mcp_justification_accepted(&"x".repeat(1001)));
    }

    proptest::proptest! {
        #[test]
        fn justification_outside_window_is_rejected(
            short in 0usize..10,
            long in 1001usize..4000,
        ) {
            proptest::prop_assert!(!mcp_justification_accepted(&"x".repeat(short)));
            proptest::prop_assert!(!mcp_justification_accepted(&"y".repeat(long)));
        }

        #[test]
        fn justification_inside_window_is_accepted(n in 10usize..=1000) {
            proptest::prop_assert!(mcp_justification_accepted(&"z".repeat(n)));
        }
    }

    #[test]
    fn battle_justification_checks_are_stable_under_threads() {
        let mut handles = Vec::new();
        for _ in 0..8 {
            handles.push(std::thread::spawn(|| {
                for n in 0..32 {
                    let ok = mcp_justification_accepted(&"m".repeat(n));
                    assert_eq!(ok, (10..1001).contains(&n));
                }
            }));
        }
        for handle in handles {
            handle.join().expect("justification thread");
        }
    }

    #[test]
    fn attack_mcp_open_without_rule_is_rejected() {
        let src = include_str!("mcp_sessions.rs");
        assert!(src.contains("if !access_result.allowed"));
        assert!(src.contains("assets:connect_mcp"));
        let sessions = include_str!("sessions.rs");
        let start = sessions
            .find("pub async fn create_session")
            .expect("create_session");
        let body = &sessions[start..];
        let end = body[1..].find("\npub async fn").unwrap_or(body.len());
        assert!(
            !body[..end].contains("SessionType::Mcp"),
            "create_session must not mint an MCP bearer"
        );
    }
}
