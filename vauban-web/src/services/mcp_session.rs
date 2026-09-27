//! Shared MCP session-open logic (Lot 1a, `docs/specs/vauban-mcp`).
//!
//! Used by both the human web connect handler
//! ([`crate::handlers::web::mcp::connect_mcp`]) and the agent-facing
//! `POST /api/v1/sessions` MCP branch
//! ([`crate::handlers::api::sessions::create_session`]) so the two
//! surfaces mint the bearer, freeze the whitelist, and push the
//! authorization envelope to `vauban-proxy-mcp` through exactly one
//! code path.
//!
//! Two proxy-registration strategies are supported, mirroring how
//! every other proxy family (SSH/RDP/IACS) is wired:
//!
//! - **Supervisor / IPC** (`state.proxy_mcp` is `Some`): the
//!   production path. A `SessionToken` is minted via vauban-access
//!   and a `McpSessionOpen` IPC pushes the frozen envelope to
//!   `vauban-proxy-mcp`. Fail-closed: without this client, MCP
//!   sessions cannot open.
//! - **Dev HTTP fallback** (`state.proxy_mcp` is `None`): used only
//!   when vauban-web runs outside the supervisor (`local-tools`
//!   demo / `cargo run` without Capsicum sandboxing). Calls the
//!   plaintext `POST /session/register` bridge on
//!   `vauban-proxy-mcp`'s dev HTTP gateway. This path is NOT
//!   fail-closed against a compromised web and MUST NOT be reachable
//!   in production (the supervisor always wires `proxy_mcp`).

use crate::AppState;
use crate::error::{AppError, AppResult};
use crate::ipc::McpSessionOpenRequest;
use crate::models::asset::Asset;
use crate::schema::{access_rules, asset_asset_groups, asset_groups, user_groups};
use crate::services::mcp_discover::{catalog_from_asset, tool_constraints_json_for_session_extra};
use base64::Engine;
use chrono::{DateTime, Utc};
use diesel::OptionalExtension;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use shared::mcp_policy::mcp_rule_callable_tools;
use std::collections::BTreeSet;
use uuid::Uuid;

/// Virtual "All assets" group (migration 20260424000000).
const VIRTUAL_ALL_ASSETS_UUID: &str = "00000000-0000-0000-0000-000000000a11";

/// Contract §1: `min(demande, règle, appliance_max)` with
/// `appliance_max` from `[mcp].session_ttl_seconds` (default 3600).
pub const DEFAULT_MCP_SESSION_SECS: i64 = 3600;
pub const TOKEN_CAP_SECS: i64 = 28800;
pub const MCP_SESSION_TTL_FLOOR_SECS: i64 = 30;
pub const MAX_BODY_BYTES: u64 = 1_048_576;
pub const ENVELOPE_MAX_CALLS: u32 = 120;
pub const ENVELOPE_WINDOW_SECONDS: u32 = 60;
pub const MCP_PROTOCOL_VERSIONS: &[&str] = &["2024-11-05", "2025-03-26"];

/// Normative data-plane bearer (04 §5): `vbw_` + base64url(SessionToken wire).
pub fn bearer_from_session_token(token: &[u8]) -> String {
    format!(
        "vbw_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token)
    )
}

/// Legacy random mint — kept only for HTTP-fallback lab when Access mint
/// is unavailable. Prefer [`bearer_from_session_token`].
#[cfg(test)]
pub fn mint_bearer() -> String {
    use rand::RngCore;
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    format!("vbw_{}", hex_encode(&raw))
}

#[cfg(test)]
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Clamp `[mcp].session_ttl_seconds` to `[30s, 8h]`.
pub fn clamp_appliance_max(appliance_max: i64) -> i64 {
    appliance_max.clamp(MCP_SESSION_TTL_FLOOR_SECS, TOKEN_CAP_SECS)
}

/// Clamp a caller-requested TTL using the compiled default appliance max.
/// Prefer [`clamp_ttl_capped`] with the live `[mcp].session_ttl_seconds`.
pub fn clamp_ttl(requested: Option<i64>) -> i64 {
    clamp_ttl_capped(requested, None, None)
}

/// `min(demande, règle, appliance_max)`.
///
/// `appliance_max` defaults to [`DEFAULT_MCP_SESSION_SECS`]. A positive
/// rule cap shorter than 30s is honoured (rule wins).
pub fn clamp_ttl_capped(
    requested: Option<i64>,
    rule_cap_secs: Option<i32>,
    appliance_max: Option<i64>,
) -> i64 {
    let appliance = clamp_appliance_max(appliance_max.unwrap_or(DEFAULT_MCP_SESSION_SECS));
    let mut ttl = requested
        .unwrap_or(appliance)
        .clamp(MCP_SESSION_TTL_FLOOR_SECS, appliance);
    if let Some(cap) = rule_cap_secs.filter(|c| *c > 0) {
        let cap = i64::from(cap);
        ttl = ttl.min(cap);
        if ttl < 1 {
            ttl = 1;
        }
    }
    ttl
}

/// Read the asset catalog whitelist off `assets.connection_config`
/// (contract §7). `None` = catalog unrestricted (proxy treats as all
/// approved); `Some(list)` = max set for this MCP asset.
pub fn resolve_asset_catalog(asset: &Asset) -> Option<Vec<String>> {
    asset
        .connection_config
        .get("allowed_tools")
        .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
}

/// Legacy alias — prefer [`resolve_effective_allowed_tools`].
pub fn resolve_allowed_tools(asset: &Asset) -> Option<Vec<String>> {
    resolve_asset_catalog(asset)
}

/// Effective session whitelist = ∩(applicable access rules) ∩ asset catalog
/// (contract §7).
///
/// - Rule `mcp_allowed_tools IS NULL` and no HITL/plan → that rule does not shrink
/// - HITL / require_plan names join the callable set (else `-32001` before the gate)
/// - Rule `mcp_allowed_tools = {}` and no gates → deny-all
/// - Multiple rules → intersection of their lists (NULL rules skipped)
/// - Then intersect with the asset catalog when present
pub async fn resolve_effective_allowed_tools(
    conn: &mut crate::db::DbConnection,
    user_id: i32,
    asset: &Asset,
) -> AppResult<Option<Vec<String>>> {
    let catalog = resolve_asset_catalog(asset);

    let group_ids: Vec<i32> = user_groups::table
        .filter(user_groups::user_id.eq(user_id))
        .select(user_groups::group_id)
        .load::<i32>(conn)
        .await?;

    if group_ids.is_empty() {
        // No group → no applicable rule (V-3 deny).
        return Ok(Some(Vec::new()));
    }

    let virtual_uuid = Uuid::parse_str(VIRTUAL_ALL_ASSETS_UUID)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("virtual all-assets uuid: {e}")))?;
    let virtual_all_id: Option<i32> = asset_groups::table
        .filter(asset_groups::uuid.eq(virtual_uuid))
        .select(asset_groups::id)
        .first::<i32>(conn)
        .await
        .optional()?;

    let direct_group_ids: Vec<i32> = asset_asset_groups::table
        .filter(asset_asset_groups::asset_id.eq(asset.id))
        .select(asset_asset_groups::asset_group_id)
        .load::<i32>(conn)
        .await?;

    let mut asset_group_ids = direct_group_ids;
    if let Some(vid) = virtual_all_id
        && !asset_group_ids.contains(&vid)
    {
        asset_group_ids.push(vid);
    }

    if asset_group_ids.is_empty() {
        // V-3: no asset group → no applicable rule. Catalogue is not a grant.
        return Ok(Some(Vec::new()));
    }

    let now = Utc::now();
    type McpRuleColumns = (
        Option<Vec<Option<String>>>,
        Option<Vec<Option<String>>>,
        Option<Vec<Option<String>>>,
    );
    let rows: Vec<McpRuleColumns> = access_rules::table
        .filter(access_rules::user_group_id.eq_any(&group_ids))
        .filter(access_rules::asset_group_id.eq_any(&asset_group_ids))
        .filter(access_rules::is_active.eq(true))
        .filter(
            access_rules::valid_from
                .is_null()
                .or(access_rules::valid_from.le(now)),
        )
        .filter(
            access_rules::valid_until
                .is_null()
                .or(access_rules::valid_until.ge(now)),
        )
        // protocol mcp present (postgres array contains)
        .filter(access_rules::allowed_protocols.contains(vec![Some("mcp".to_string())]))
        .select((
            access_rules::mcp_allowed_tools,
            access_rules::mcp_hitl_tools,
            access_rules::mcp_require_plan_tools,
        ))
        .load(conn)
        .await?;

    // V-3: zero applicable MCP rules → empty whitelist (caller denies).
    // Never fall back to the bare asset catalogue.
    if rows.is_empty() {
        return Ok(Some(Vec::new()));
    }

    let mut effective: Option<BTreeSet<String>> = None;
    for (allow, hitl, plan) in rows {
        let Some(set) = mcp_rule_callable_tools(allow, hitl, plan) else {
            continue;
        };
        effective = Some(match effective {
            None => set,
            Some(prev) => prev.intersection(&set).cloned().collect(),
        });
    }

    let merged = match (effective, catalog) {
        // All rules NULL → catalogue only (approved set). No catalogue → deny.
        (None, cat) => cat
            .map(|c| c.into_iter().collect::<Vec<_>>())
            .unwrap_or_default(),
        (Some(rule_set), None) => rule_set.into_iter().collect(),
        (Some(rule_set), Some(cat)) => {
            let cat_set: BTreeSet<_> = cat.into_iter().collect();
            rule_set.intersection(&cat_set).cloned().collect::<Vec<_>>()
        }
    };

    let mut v = merged;
    v.sort();
    Ok(Some(v))
}

/// Union of `mcp_hitl_tools` across applicable MCP access rules (09 §5.1).
/// NULL rows contribute nothing; results are add-only onto catalogue HITL.
pub async fn resolve_rule_hitl_tools(
    conn: &mut crate::db::DbConnection,
    user_id: i32,
    asset: &Asset,
) -> AppResult<BTreeSet<String>> {
    let group_ids: Vec<i32> = user_groups::table
        .filter(user_groups::user_id.eq(user_id))
        .select(user_groups::group_id)
        .load::<i32>(conn)
        .await?;

    if group_ids.is_empty() {
        return Ok(BTreeSet::new());
    }

    let virtual_uuid = Uuid::parse_str(VIRTUAL_ALL_ASSETS_UUID)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("virtual all-assets uuid: {e}")))?;
    let virtual_all_id: Option<i32> = asset_groups::table
        .filter(asset_groups::uuid.eq(virtual_uuid))
        .select(asset_groups::id)
        .first::<i32>(conn)
        .await
        .optional()?;

    let direct_group_ids: Vec<i32> = asset_asset_groups::table
        .filter(asset_asset_groups::asset_id.eq(asset.id))
        .select(asset_asset_groups::asset_group_id)
        .load::<i32>(conn)
        .await?;

    let mut asset_group_ids = direct_group_ids;
    if let Some(vid) = virtual_all_id
        && !asset_group_ids.contains(&vid)
    {
        asset_group_ids.push(vid);
    }

    if asset_group_ids.is_empty() {
        return Ok(BTreeSet::new());
    }

    let now = Utc::now();
    let rows: Vec<Option<Vec<Option<String>>>> = access_rules::table
        .filter(access_rules::user_group_id.eq_any(&group_ids))
        .filter(access_rules::asset_group_id.eq_any(&asset_group_ids))
        .filter(access_rules::is_active.eq(true))
        .filter(
            access_rules::valid_from
                .is_null()
                .or(access_rules::valid_from.le(now)),
        )
        .filter(
            access_rules::valid_until
                .is_null()
                .or(access_rules::valid_until.ge(now)),
        )
        .filter(access_rules::allowed_protocols.contains(vec![Some("mcp".to_string())]))
        .select(access_rules::mcp_hitl_tools)
        .load(conn)
        .await?;

    let mut out = BTreeSet::new();
    for tools in rows.into_iter().flatten() {
        for name in tools.into_iter().flatten() {
            let t = name.trim();
            if !t.is_empty() {
                out.insert(t.to_string());
            }
        }
    }
    Ok(out)
}

/// Union of `mcp_require_plan_tools` across applicable MCP access rules.
/// Policy SoT for Mission Seal — not the asset catalogue.
pub async fn resolve_rule_require_plan_tools(
    conn: &mut crate::db::DbConnection,
    user_id: i32,
    asset: &Asset,
) -> AppResult<BTreeSet<String>> {
    let group_ids: Vec<i32> = user_groups::table
        .filter(user_groups::user_id.eq(user_id))
        .select(user_groups::group_id)
        .load::<i32>(conn)
        .await?;

    if group_ids.is_empty() {
        return Ok(BTreeSet::new());
    }

    let virtual_uuid = Uuid::parse_str(VIRTUAL_ALL_ASSETS_UUID)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("virtual all-assets uuid: {e}")))?;
    let virtual_all_id: Option<i32> = asset_groups::table
        .filter(asset_groups::uuid.eq(virtual_uuid))
        .select(asset_groups::id)
        .first::<i32>(conn)
        .await
        .optional()?;

    let direct_group_ids: Vec<i32> = asset_asset_groups::table
        .filter(asset_asset_groups::asset_id.eq(asset.id))
        .select(asset_asset_groups::asset_group_id)
        .load::<i32>(conn)
        .await?;

    let mut asset_group_ids = direct_group_ids;
    if let Some(vid) = virtual_all_id
        && !asset_group_ids.contains(&vid)
    {
        asset_group_ids.push(vid);
    }

    if asset_group_ids.is_empty() {
        return Ok(BTreeSet::new());
    }

    let now = Utc::now();
    let rows: Vec<Option<Vec<Option<String>>>> = access_rules::table
        .filter(access_rules::user_group_id.eq_any(&group_ids))
        .filter(access_rules::asset_group_id.eq_any(&asset_group_ids))
        .filter(access_rules::is_active.eq(true))
        .filter(
            access_rules::valid_from
                .is_null()
                .or(access_rules::valid_from.le(now)),
        )
        .filter(
            access_rules::valid_until
                .is_null()
                .or(access_rules::valid_until.ge(now)),
        )
        .filter(access_rules::allowed_protocols.contains(vec![Some("mcp".to_string())]))
        .select(access_rules::mcp_require_plan_tools)
        .load(conn)
        .await?;

    let mut out = BTreeSet::new();
    for tools in rows.into_iter().flatten() {
        for name in tools.into_iter().flatten() {
            let t = name.trim();
            if !t.is_empty() {
                out.insert(t.to_string());
            }
        }
    }
    Ok(out)
}

/// Push a freshly-minted MCP session to `vauban-proxy-mcp`.
///
/// Returns the normative data-plane bearer (`vbw_` + base64url(token)).
///
/// Order (04 §4): IssueSessionToken → supervisor TcpConnect (FD to proxy)
/// → McpSessionOpen (proxy verifies token + claims FD + AccessGuard).
#[allow(clippy::too_many_arguments)]
pub async fn open_on_proxy(
    state: &AppState,
    user_uuid: &str,
    api_key_id: Option<&str>,
    asset: &Asset,
    session_uuid: Uuid,
    expires_at: DateTime<Utc>,
    justification: &str,
    allowed_tools: Option<Vec<String>>,
) -> AppResult<String> {
    if let Some(ref proxy) = state.proxy_mcp {
        open_via_ipc(
            state,
            proxy,
            user_uuid,
            api_key_id,
            asset,
            session_uuid,
            expires_at,
            justification,
            allowed_tools,
        )
        .await
    } else {
        Err(AppError::Internal(anyhow::anyhow!(
            "MCP open requires proxy_mcp IPC (session token on a brokered FD)"
        )))
    }
}

#[allow(clippy::too_many_arguments)]
async fn open_via_ipc(
    state: &AppState,
    proxy: &crate::ipc::ProxyMcpClient,
    user_uuid: &str,
    api_key_id: Option<&str>,
    asset: &Asset,
    session_uuid: Uuid,
    expires_at: DateTime<Utc>,
    justification: &str,
    allowed_tools: Option<Vec<String>>,
) -> AppResult<String> {
    let _ = allowed_tools; // Access mint supplies the authoritative list below.
    let token_params = shared::session_token::SessionTokenParams {
        session_id: session_uuid.to_string(),
        user_uuid: user_uuid.to_string(),
        asset_uuid: asset.uuid.to_string(),
        protocol: shared::access_guard::PROTOCOL_MCP.to_string(),
        host: asset.hostname.clone(),
        port: asset.port as u16,
        target_service: shared::messages::Service::ProxyMcp,
    };

    let issued = state
        .access_client
        .issue_session_token(token_params)
        .await
        .map_err(|e| AppError::Authorization(format!("session token mint failed: {e}")))?;

    // Lot M2: Access is the source of truth for the tool ∩ whitelist.
    let allowed_tools = match issued.effective_tools {
        Some(tools) if !tools.is_empty() => Some(tools),
        Some(_) => {
            return Err(AppError::Authorization(
                "No MCP tools granted by access rules (empty whitelist)".to_string(),
            ));
        }
        None => {
            return Err(AppError::Authorization(
                "Access did not return MCP effective_tools".to_string(),
            ));
        }
    };
    let session_token = issued.token;
    let bearer = bearer_from_session_token(&session_token);
    let vbw_hash: [u8; 32] = *blake3::hash(bearer.as_bytes()).as_bytes();

    // Contexte / 04 §4: supervisor brokers upstream TCP → SCM_RIGHTS to
    // proxy BEFORE McpSessionOpen (same order as SSH/RDP).
    if let Some(ref supervisor) = state.supervisor {
        match supervisor
            .request_tcp_connect(
                &session_uuid.to_string(),
                &asset.hostname,
                asset.port as u16,
                shared::messages::Service::ProxyMcp,
                session_token.clone(),
            )
            .await
        {
            Ok(result) if result.success => {
                tracing::debug!(
                    session_id = %session_uuid,
                    host = %asset.hostname,
                    port = asset.port,
                    "MCP upstream TcpConnect brokered by supervisor"
                );
            }
            Ok(result) => {
                let msg = result
                    .error
                    .unwrap_or_else(|| "Failed to establish MCP upstream TCP".to_string());
                return Err(AppError::Internal(anyhow::anyhow!(msg)));
            }
            Err(e) => {
                return Err(AppError::Internal(anyhow::anyhow!(
                    "MCP TcpConnect request failed: {e}"
                )));
            }
        }
    } else {
        tracing::warn!(
            session_id = %session_uuid,
            "No supervisor client — MCP open without FD broker (lab only)"
        );
    }

    // Règle d'or (Phase 1): ship vault ciphertext only — proxy VaultDecrypts.
    // Empty password = no upstream Bearer (local-tools / auth none).
    let credential_blob = credential_ciphertext_blob(asset)?;

    let forward_identity_headers = asset
        .connection_config
        .get("forward_identity_headers")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let upstream_tls_spki_pin = asset
        .connection_config
        .get("mcp_upstream_tls_spki")
        .or_else(|| asset.connection_config.get("tls_spki_pin"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    // RDP parity: pin format `SHA256:<standard-base64>` of SPKI DER.
    if let Some(ref pin) = upstream_tls_spki_pin
        && !pin.starts_with("SHA256:")
    {
        return Err(AppError::Validation(
            "MCP TLS pin must be SHA256:<base64> (same format as RDP rdp_server_cert_fingerprint)"
                .into(),
        ));
    }
    if asset
        .hostname
        .trim()
        .to_ascii_lowercase()
        .starts_with("https://")
        || asset
            .hostname
            .trim()
            .to_ascii_lowercase()
            .starts_with("http://")
    {
        return Err(AppError::Validation(
            "MCP asset hostname must be bare (no URL scheme); pin selects HTTPS vs HTTP on FD"
                .into(),
        ));
    }

    let tool_constraints_json = {
        let mut conn = state
            .db_pool
            .get()
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("DB pool: {e}")))?;
        let user_id: i32 = crate::schema::users::table
            .filter(
                crate::schema::users::uuid.eq(Uuid::parse_str(user_uuid)
                    .map_err(|e| AppError::Validation(format!("invalid user uuid: {e}")))?),
            )
            .select(crate::schema::users::id)
            .first(&mut conn)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("lookup user for HITL union: {e}")))?;
        let rule_hitl = resolve_rule_hitl_tools(&mut conn, user_id, asset).await?;
        let rule_plan = resolve_rule_require_plan_tools(&mut conn, user_id, asset).await?;
        tool_constraints_json_for_session_extra(&catalog_from_asset(asset), &rule_hitl, &rule_plan)
    };

    let envelope_on_exceed = asset
        .connection_config
        .get("envelope_on_exceed")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| matches!(*s, "throttle" | "alert" | "suspend"))
        .unwrap_or("throttle")
        .to_string();

    let open_req = McpSessionOpenRequest {
        session_id: session_uuid.to_string(),
        asset_id: asset.uuid.to_string(),
        user_id: user_uuid.to_string(),
        api_key_id: api_key_id.unwrap_or("").to_string(),
        expires_at: expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        vbw_hash,
        allowed_tools,
        tool_constraints_json,
        envelope_max_calls: ENVELOPE_MAX_CALLS,
        envelope_window_seconds: ENVELOPE_WINDOW_SECONDS,
        envelope_on_exceed,
        upstream_host: asset.hostname.clone(),
        upstream_port: asset.port as u16,
        upstream_tls_spki_pin,
        forward_identity_headers,
        credential_blob,
        justification: justification.to_string(),
        max_body_bytes: MAX_BODY_BYTES,
        session_token,
    };

    match proxy.open_session(open_req).await {
        Ok(opened) if opened.success => Ok(bearer),
        Ok(opened) => Err(AppError::Internal(anyhow::anyhow!(
            "proxy-mcp refused open: {}",
            opened.error.unwrap_or_else(|| "unknown".to_string())
        ))),
        Err(e) => Err(e),
    }
}

/// Vault ciphertext bytes for `McpSessionOpen.credential_blob`.
///
/// Fail-closed: a non-empty `connection_config.password` that is not a
/// vault envelope is refused (web must never ship plaintext on IPC).
fn credential_ciphertext_blob(asset: &Asset) -> AppResult<Vec<u8>> {
    let pw = asset
        .connection_config
        .get("password")
        .and_then(|v| v.as_str());
    credential_ciphertext_from_password(pw)
}

pub(crate) fn credential_ciphertext_from_password(password: Option<&str>) -> AppResult<Vec<u8>> {
    let Some(pw) = password.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(Vec::new());
    };
    if !shared::vault_envelope::is_vault_envelope(pw) {
        return Err(AppError::Validation(
            "MCP upstream bearer must be vault-encrypted (re-save the asset under supervisor)"
                .into(),
        ));
    }
    Ok(pw.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bearer_from_session_token_shape() {
        let token = b"wire-token-bytes-example!!!!";
        let b = bearer_from_session_token(token);
        assert!(b.starts_with("vbw_"));
        assert!(!b.contains('+') && !b.contains('/'));
    }

    #[test]
    fn test_bearer_from_session_token_stable() {
        let token = b"same-bytes";
        assert_eq!(
            bearer_from_session_token(token),
            bearer_from_session_token(token)
        );
    }

    #[test]
    fn test_mint_bearer_shape() {
        let b = mint_bearer();
        assert!(b.starts_with("vbw_"));
        assert_eq!(b.len(), "vbw_".len() + 64);
    }

    #[test]
    fn test_mint_bearer_unique() {
        assert_ne!(mint_bearer(), mint_bearer());
    }

    #[test]
    fn test_clamp_ttl_default() {
        assert_eq!(clamp_ttl(None), DEFAULT_MCP_SESSION_SECS);
    }

    #[test]
    fn test_clamp_ttl_floor() {
        assert_eq!(clamp_ttl(Some(1)), 30);
    }

    #[test]
    fn test_clamp_ttl_ceiling() {
        assert_eq!(clamp_ttl(Some(999_999)), DEFAULT_MCP_SESSION_SECS);
    }

    #[test]
    fn test_clamp_ttl_honours_rule_cap() {
        assert_eq!(clamp_ttl_capped(None, Some(900), None), 900);
        assert_eq!(clamp_ttl_capped(Some(3600), Some(120), None), 120);
        assert_eq!(
            clamp_ttl_capped(Some(999_999), Some(7200), None),
            DEFAULT_MCP_SESSION_SECS,
            "appliance default still caps when the rule is wider"
        );
        assert_eq!(
            clamp_ttl_capped(Some(3600), Some(10), None),
            10,
            "rule cap below the 30s floor is still honoured"
        );
    }

    #[test]
    fn test_clamp_ttl_appliance_max_replaces_hidden_3600() {
        assert_eq!(clamp_ttl_capped(Some(999_999), None, Some(7200)), 7200);
        assert_eq!(clamp_ttl_capped(None, None, Some(7200)), 7200);
        assert_eq!(clamp_ttl_capped(None, Some(7200), Some(3600)), 3600);
        assert_eq!(clamp_ttl_capped(None, Some(7200), Some(7200)), 7200);
        assert_eq!(clamp_ttl_capped(None, Some(900), Some(7200)), 900);
        assert_eq!(clamp_appliance_max(10), 30);
        assert_eq!(clamp_appliance_max(99_999), TOKEN_CAP_SECS);
    }

    /// Phase C: `suspend` is a valid `envelope_on_exceed` when Resume is shipped.
    #[test]
    fn suspend_literal_allowed_for_envelope() {
        let src = include_str!("mcp_session.rs");
        assert!(
            src.contains("\"suspend\""),
            "Phase C must allow envelope_on_exceed=suspend from asset config"
        );
    }

    #[test]
    fn credential_ciphertext_empty_ok() {
        assert!(
            credential_ciphertext_from_password(None)
                .unwrap()
                .is_empty()
        );
        assert!(
            credential_ciphertext_from_password(Some(""))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn credential_ciphertext_plaintext_refused() {
        let err = credential_ciphertext_from_password(Some("sk-live-plain"))
            .expect_err("plaintext must fail");
        assert!(matches!(err, AppError::Validation(_)), "got: {err:?}");
    }

    #[test]
    fn credential_ciphertext_envelope_ok() {
        let blob = credential_ciphertext_from_password(Some("v1:SGVsbG8=")).unwrap();
        assert_eq!(blob, b"v1:SGVsbG8=");
    }
}
