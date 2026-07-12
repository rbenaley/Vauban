//! Vault Secrets M2M API — read-only surface (`/api/v1/vault/secrets`).
//!
//! Organisation-owned secrets, governed exclusively by group-to-group
//! `secret_access_rules` evaluated by vauban-access. Three GET endpoints
//! only; every mutation lives in the web admin zone (`/vault/secrets`).
//!
//! Security posture:
//! - Scope: the whole `/api/v1/vault/*` sub-tree requires the dedicated
//!   `secrets` API-key scope (outside the read/write/admin hierarchy),
//!   enforced by `middleware::api_key::api_scope_enforcement`.
//! - Casbin: every handler gates on `perms.vault_secrets_read`.
//! - Provenance: BEFORE the access oracle runs, the caller's resolved
//!   source IP must match a known asset that actively proves its pinned
//!   host identity (`services::vault_provenance`). A caller that is not
//!   a verified asset gets a canonical 403 on EVERY endpoint — the
//!   list included (no `200 []` oracle).
//! - NO bypass: there is no `read_all` equivalent — even a superuser
//!   must be covered by an explicit rule to see or read a secret.
//! - Honest statuses (`services::api_response_invariants`): the M2M
//!   zone is authenticated by API keys, so there is no anti-enumeration
//!   collapse. 400 = malformed UUID, 403 = the caller is not authorized
//!   (provenance not verified, no covering secret access rule), 404 =
//!   the secret does not exist or is inactive, 502 = the rule oracle is
//!   unavailable.
//! - The value endpoint replies with `Cache-Control: no-store` and
//!   emits a critical (durably acked) `VaultSecretRead` audit event
//!   BEFORE the plaintext leaves the process.
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serde::Serialize;

use crate::AppState;
use crate::auth::PermissionContext;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthUser;
use crate::middleware::client_addr::ClientAddr;
use crate::models::vault_secret::VaultSecret;
use crate::services::api_response_invariants::ApiDenial;
use crate::services::vault_provenance::VerifiedAsset;

/// Secret metadata exposed by the API. The ciphertext/value NEVER
/// appears here; the value has its own endpoint with its own audit.
#[derive(Debug, Serialize)]
pub struct SecretMetadata {
    pub uuid: String,
    pub name: String,
    pub description: Option<String>,
    pub version: i32,
    pub updated_at: DateTime<Utc>,
}

impl From<&VaultSecret> for SecretMetadata {
    fn from(s: &VaultSecret) -> Self {
        Self {
            uuid: s.uuid.to_string(),
            name: s.name.clone(),
            description: s.description.clone(),
            version: s.version,
            updated_at: s.updated_at,
        }
    }
}

/// Value payload for `GET /api/v1/vault/secrets/{uuid}/value`.
#[derive(Debug, Serialize)]
pub struct SecretValueResponse {
    pub uuid: String,
    pub name: String,
    pub version: i32,
    pub value: String,
}

/// Mandatory provenance gate, run BEFORE the access oracle on every
/// vault endpoint (the list included). Resolves the client IP through
/// the same trusted-proxy seam as the global ACL, then requires an
/// identity-verified asset match.
///
/// Denial is the canonical 403 (`ApiDenial::ProvenanceDenied`,
/// INV-API-3: the caller holds a valid API key but is not authorized),
/// plus a non-blocking `VaultProvenanceDenied` audit event (warn
/// level: the deny already happened, the audit is best-effort).
async fn require_provenance(
    state: &AppState,
    headers: &HeaderMap,
    client_addr: ClientAddr,
    user: &AuthUser,
) -> AppResult<VerifiedAsset> {
    let trusted = state.config.security.parsed_trusted_proxies();
    let source_ip =
        crate::middleware::resolve_client_ip(headers, client_addr.addr().ip(), &trusted);

    match crate::services::vault_provenance::resolve_caller_asset(state, source_ip, &user.uuid)
        .await
    {
        Some(asset) => Ok(asset),
        None => {
            tracing::warn!(
                source_ip = %source_ip, user = %user.uuid,
                "vault API call denied: caller is not a verified asset (provenance)"
            );
            crate::services::emit_audit(
                state,
                crate::ipc::AuditEvent::new(
                    shared::messages::AuditEventType::VaultProvenanceDenied,
                    format!(r#"{{"source_ip":"{source_ip}"}}"#),
                )
                .user(user.uuid.clone()),
            );
            Err(ApiDenial::ProvenanceDenied.into())
        }
    }
}

/// Resolve the caller's internal DB id from the JWT/API-key UUID claim.
///
/// The caller is authenticated, so a missing row is an internal
/// inconsistency (500), not an authorization decision.
async fn resolve_user_internal_id(
    conn: &mut diesel_async::AsyncPgConnection,
    user_uuid: &str,
) -> AppResult<i32> {
    use crate::schema::users;
    users::table
        .filter(users::uuid.eq(uuid::Uuid::parse_str(user_uuid).unwrap_or_default()))
        .select(users::id)
        .first(conn)
        .await
        .map_err(|e| {
            AppError::Internal(anyhow::anyhow!(
                "authenticated user {user_uuid} not resolvable: {e}"
            ))
        })
}

/// `GET /api/v1/vault/secrets` — list the metadata of every active
/// secret the caller can access via a secret access rule covering the
/// verified provenance asset.
///
/// Provenance failure is the canonical 403, NOT an empty list. An IPC
/// failure of the rule oracle is an honest 502 (INV-API-6), never a
/// misleading `200 []` the caller could mistake for absence-of-grant.
pub async fn list_vault_secrets(
    State(state): State<AppState>,
    user: AuthUser,
    perms: PermissionContext,
    client_addr: ClientAddr,
    headers: HeaderMap,
) -> AppResult<Json<Vec<SecretMetadata>>> {
    use crate::schema::vault_secrets;

    if !perms.vault_secrets_read {
        return Err(AppError::forbidden("vault_secrets:read"));
    }

    // Provenance BEFORE the oracle: no DB/IPC evaluation for a caller
    // that is not a verified asset.
    let source_asset = require_provenance(&state, &headers, client_addr, &user).await?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let user_internal_id = resolve_user_internal_id(&mut conn, &user.uuid).await?;

    let accessible_ids = crate::services::secret_access::list_accessible_secret_ids(
        &state.access_client,
        &mut conn,
        user_internal_id,
        source_asset.id,
    )
    .await?;

    let rows: Vec<VaultSecret> = vault_secrets::table
        .filter(vault_secrets::id.eq_any(accessible_ids))
        .filter(vault_secrets::is_active.eq(true))
        .order(vault_secrets::name.asc())
        .load(&mut conn)
        .await
        .map_err(AppError::Database)?;

    Ok(Json(rows.iter().map(SecretMetadata::from).collect()))
}

/// Shared lookup for the two single-secret endpoints. Honest statuses
/// (INV-API-3/4/5): existence is decided first (a secret that does not
/// exist or is inactive is a 404 regardless of rules), then the access
/// oracle decides authorization (403 when the caller is not covered by
/// a rule).
async fn load_authorized_secret(
    state: &AppState,
    user: &AuthUser,
    secret_uuid_raw: &str,
    source_asset: &VerifiedAsset,
) -> AppResult<VaultSecret> {
    use crate::schema::vault_secrets;

    // INV-API-5: malformed UUIDs are a 400 (no phantom 404).
    let secret_uuid =
        uuid::Uuid::parse_str(secret_uuid_raw).map_err(|_| ApiDenial::MalformedIdentifier)?;

    // INV-API-4: existence first. Inactive secrets are hidden
    // everywhere in the product, so they are a 404 too.
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let secret = vault_secrets::table
        .filter(vault_secrets::uuid.eq(secret_uuid))
        .filter(vault_secrets::is_active.eq(true))
        .first::<VaultSecret>(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::from(ApiDenial::NotFound("Secret")),
            other => AppError::Database(other),
        })?;
    drop(conn);

    // INV-API-3: single authorization oracle. vauban-access evaluates
    // active rules in their validity window, injects the virtual "All
    // secrets" group, filters on the provenance asset group and
    // requires the secret row to be active. Fail-closed bool: an IPC
    // error denies (403), it never fabricates a grant.
    let allowed = crate::services::secret_access::can_access_secret(
        &state.access_client,
        &user.uuid,
        &secret_uuid.to_string(),
        source_asset.id,
    )
    .await;
    if !allowed {
        return Err(ApiDenial::NotAuthorized("secret").into());
    }

    Ok(secret)
}

/// `GET /api/v1/vault/secrets/{uuid}` — metadata of one secret.
pub async fn get_vault_secret(
    State(state): State<AppState>,
    user: AuthUser,
    perms: PermissionContext,
    client_addr: ClientAddr,
    headers: HeaderMap,
    Path(secret_uuid): Path<String>,
) -> AppResult<Json<SecretMetadata>> {
    if !perms.vault_secrets_read {
        return Err(AppError::forbidden("vault_secrets:read"));
    }
    let source_asset = require_provenance(&state, &headers, client_addr, &user).await?;
    let secret = load_authorized_secret(&state, &user, &secret_uuid, &source_asset).await?;
    Ok(Json(SecretMetadata::from(&secret)))
}

/// `GET /api/v1/vault/secrets/{uuid}/value` — reveal the secret value.
///
/// The plaintext is decrypted through the dedicated `"secrets"` vault
/// domain and never cached (`Cache-Control: no-store`). A critical
/// `VaultSecretRead` audit event is durably acked BEFORE the value is
/// returned; if the audit trail is unavailable the request fails closed.
pub async fn get_vault_secret_value(
    State(state): State<AppState>,
    user: AuthUser,
    perms: PermissionContext,
    client_addr: ClientAddr,
    headers: HeaderMap,
    Path(secret_uuid): Path<String>,
) -> AppResult<Response> {
    if !perms.vault_secrets_read {
        return Err(AppError::forbidden("vault_secrets:read"));
    }
    let source_asset = require_provenance(&state, &headers, client_addr, &user).await?;
    let secret = load_authorized_secret(&state, &user, &secret_uuid, &source_asset).await?;

    // Same storage contract as `encrypt_connection_config`: a `vN:`
    // envelope is EXCLUSIVELY decrypted by vauban-vault; anything else
    // was stored as-is by a dev/test instance without a vault and
    // round-trips unchanged.
    let plaintext: String = if crate::handlers::web::is_encrypted(&secret.ciphertext) {
        match &state.vault_client {
            Some(vault) => vault
                .decrypt("secrets", &secret.ciphertext)
                .await?
                .into_inner(),
            None => {
                return Err(AppError::Internal(anyhow::anyhow!(
                    "vault unavailable: cannot decrypt enveloped secret"
                )));
            }
        }
    } else {
        secret.ciphertext.clone()
    };

    // Critical audit: durable ack required before the plaintext leaves
    // the process. Fail closed if the WORM chain cannot record the read.
    crate::services::emit_audit_critical(
        &state,
        crate::ipc::AuditEvent::new(
            shared::messages::AuditEventType::VaultSecretRead,
            format!(
                r#"{{"secret":"{}","name":"{}","version":{},"source_asset":"{}"}}"#,
                secret.uuid,
                secret.name.replace('"', ""),
                secret.version,
                source_asset.uuid
            ),
        )
        .user(user.uuid.clone()),
    )
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("audit emit failed: {e}")))?;

    let body = SecretValueResponse {
        uuid: secret.uuid.to_string(),
        name: secret.name.clone(),
        version: secret.version,
        value: plaintext,
    };

    Ok(([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_metadata_from_model_never_carries_ciphertext() {
        let now = Utc::now();
        let secret = VaultSecret {
            id: 1,
            uuid: uuid::Uuid::new_v4(),
            name: "db-password".to_string(),
            description: Some("Prod".to_string()),
            ciphertext: "v1:SUPERSECRET".to_string(),
            version: 3,
            is_active: true,
            created_by_id: None,
            updated_by_id: None,
            created_at: now,
            updated_at: now,
        };
        let meta = SecretMetadata::from(&secret);
        let json = serde_json::to_string(&meta).expect("serialize");
        assert!(!json.contains("SUPERSECRET"));
        assert!(json.contains("db-password"));
        assert!(json.contains("\"version\":3"));
    }

    #[test]
    fn test_denial_messages_are_canonical() {
        // Honest-status contract: 404 is reserved for non-existent /
        // inactive secrets, 403 carries the authorization reason.
        assert_eq!(ApiDenial::NotFound("Secret").message(), "Secret not found");
        assert_eq!(
            ApiDenial::NotAuthorized("secret").message(),
            "Not authorized to access this secret"
        );
        assert_eq!(
            ApiDenial::ProvenanceDenied.message(),
            "Caller is not an identity-verified asset (vault provenance)"
        );
    }
}
