//! Admin MCP tool discovery + TOFU catalogue (M6 / Droits).
//!
//! Phase 2.1: discovery goes through `vauban-proxy-mcp` on a supervisor-
//! brokered FD (`McpDiscover`). Web never dials the asset host directly
//! (SSRF class closed). Lab without `proxy_mcp` IPC refuses discover.

use crate::AppState;
use crate::error::{AppError, AppResult};
use crate::ipc::McpDiscoverRequest;
use crate::models::asset::{Asset, AssetType};
use crate::services::mcp_session::credential_ciphertext_from_password;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

const MAX_TOOLS: usize = 500;

/// TOFU catalogue status (docs/specs/vauban-mcp/03 §2, 05 §6).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ToolCatalogStatus {
    Approved,
    #[default]
    Pending,
    Tombstone,
}

impl ToolCatalogStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Pending => "pending",
            Self::Tombstone => "tombstone",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DiscoveredTool {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Absent on legacy catalogs → treated as [`ToolCatalogStatus::Approved`]
    /// so existing lab assets keep working.
    #[serde(default)]
    pub status: Option<ToolCatalogStatus>,
    /// Admin/catalogue flag (03 §5). Suggest from name on discover.
    #[serde(default)]
    pub destructive: bool,
    /// Admin/catalogue HITL flag (09 §5). Never auto-set on discover.
    #[serde(default)]
    pub hitl: bool,
    /// Legacy catalogue field. Ignored — policy SoT is
    /// `access_rules.mcp_require_plan_tools`. Kept so old
    /// `connection_config` still deserializes.
    #[serde(default, skip_serializing)]
    pub require_plan: bool,
    /// Upstream `inputSchema` (JSON Schema subset) when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,
    /// Keys forbidden at any depth (case-insensitive).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbidden_keys: Vec<String>,
    /// BLAKE3 hex of canonical `{name, description, inputSchema}` (Phase 3.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_fingerprint: Option<String>,
}

impl DiscoveredTool {
    pub fn status_or_legacy_approved(&self) -> ToolCatalogStatus {
        self.status.unwrap_or(ToolCatalogStatus::Approved)
    }

    pub fn is_approved(&self) -> bool {
        self.status_or_legacy_approved() == ToolCatalogStatus::Approved
    }

    /// Recompute fingerprint from current fields (call after schema changes).
    pub fn with_computed_fingerprint(mut self) -> Self {
        self.schema_fingerprint = Some(schema_fingerprint(
            &self.name,
            &self.description,
            self.input_schema.as_ref(),
        ));
        self
    }
}

/// Canonical BLAKE3 hex for tool schema drift detection (05 §6 / Phase 3.2).
pub fn schema_fingerprint(name: &str, description: &str, input_schema: Option<&Value>) -> String {
    let schema_bytes = input_schema
        .map(|v| serde_json::to_vec(v).unwrap_or_default())
        .unwrap_or_default();
    let mut hasher = blake3::Hasher::new();
    hasher.update(name.as_bytes());
    hasher.update(&[0]);
    hasher.update(description.as_bytes());
    hasher.update(&[0]);
    hasher.update(&schema_bytes);
    hasher.finalize().to_hex().to_string()
}

/// Build the upstream MCP URL from an asset row (display / logs only).
pub fn upstream_mcp_url(asset: &Asset) -> String {
    format!("http://{}:{}/mcp", asset.hostname.trim(), asset.port)
}

/// Parse `tools/list` result.tools into pending catalogue entries.
pub fn tools_from_list_result(listed: &Value) -> AppResult<Vec<DiscoveredTool>> {
    let tools = listed
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::Validation("MCP tools/list missing result.tools".into()))?;

    if tools.len() > MAX_TOOLS {
        return Err(AppError::Validation(format!(
            "MCP catalogue too large ({} > {MAX_TOOLS})",
            tools.len()
        )));
    }

    let mut out = Vec::with_capacity(tools.len());
    for t in tools {
        let name = t
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AppError::Validation("MCP tool missing name".into()))?;
        let description = t
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let input_schema = t.get("inputSchema").cloned().filter(|v| !v.is_null());
        let destructive = suggest_destructive(name);
        out.push(
            DiscoveredTool {
                name: name.to_string(),
                description,
                status: Some(ToolCatalogStatus::Pending),
                destructive,
                hitl: false,
                require_plan: false,
                input_schema,
                forbidden_keys: Vec::new(),
                schema_fingerprint: None,
            }
            .with_computed_fingerprint(),
        );
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out.dedup_by(|a, b| a.name == b.name);
    Ok(out)
}

/// Discover tools via proxy-mcp on a brokered FD (Phase 2.1).
pub async fn discover_tools_from_upstream(
    state: &AppState,
    asset: &Asset,
    admin_user_uuid: &str,
) -> AppResult<Vec<DiscoveredTool>> {
    if asset.asset_type != AssetType::Mcp {
        return Err(AppError::Validation(
            "Tool discovery is only available for MCP assets".into(),
        ));
    }

    let proxy = state.proxy_mcp.as_ref().ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "MCP discover requires proxy_mcp IPC (run under supervisor — no free web reqwest)"
        ))
    })?;
    let supervisor = state.supervisor.as_ref().ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "MCP discover requires supervisor TcpConnect (brokered FD)"
        ))
    })?;

    let discover_id = Uuid::new_v4();
    let session_id = format!("mcp-discover-{discover_id}");

    let token_params = shared::session_token::SessionTokenParams {
        session_id: session_id.clone(),
        user_uuid: admin_user_uuid.to_string(),
        asset_uuid: asset.uuid.to_string(),
        protocol: shared::access_guard::PROTOCOL_MCP.to_string(),
        host: asset.hostname.clone(),
        port: asset.port as u16,
        target_service: shared::messages::Service::ProxyMcp,
    };
    let session_token = state
        .access_client
        .issue_diagnostic_token(token_params, true)
        .await
        .map_err(|e| AppError::Authorization(format!("discover diagnostic token: {e}")))?;

    match supervisor
        .request_tcp_connect(
            &session_id,
            &asset.hostname,
            asset.port as u16,
            shared::messages::Service::ProxyMcp,
            session_token.clone(),
        )
        .await
    {
        Ok(result) if result.success => {}
        Ok(result) => {
            return Err(AppError::Internal(anyhow::anyhow!(
                result
                    .error
                    .unwrap_or_else(|| "TcpConnect failed for MCP discover".into())
            )));
        }
        Err(e) => {
            return Err(AppError::Internal(anyhow::anyhow!(
                "MCP discover TcpConnect: {e}"
            )));
        }
    }

    let credential_blob = credential_ciphertext_from_password(
        asset
            .connection_config
            .get("password")
            .and_then(|v| v.as_str()),
    )?;

    let upstream_tls_spki_pin = asset
        .connection_config
        .get("mcp_upstream_tls_spki")
        .or_else(|| asset.connection_config.get("tls_spki_pin"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    if let Some(ref pin) = upstream_tls_spki_pin
        && !pin.starts_with("SHA256:")
    {
        return Err(AppError::Validation(
            "MCP TLS pin must be SHA256:<base64> (same format as RDP rdp_server_cert_fingerprint)"
                .into(),
        ));
    }

    let discovered = proxy
        .discover_tools(McpDiscoverRequest {
            session_id: session_id.clone(),
            asset_id: asset.uuid.to_string(),
            user_id: admin_user_uuid.to_string(),
            upstream_host: asset.hostname.clone(),
            upstream_port: asset.port as u16,
            credential_blob,
            session_token,
            upstream_tls_spki_pin,
        })
        .await?;

    if !discovered.success {
        return Err(AppError::Validation(
            discovered
                .error
                .unwrap_or_else(|| "MCP discover failed".into()),
        ));
    }
    let tools_json = discovered
        .tools_json
        .ok_or_else(|| AppError::Validation("MCP discover returned no tools_json".into()))?;
    let listed: Value = serde_json::from_str(&tools_json)
        .map_err(|e| AppError::Validation(format!("invalid tools_json: {e}")))?;
    tools_from_list_result(&listed)
}

/// Names matching delete|drop|destroy|remove|write|update → suggest destructive.
pub fn suggest_destructive(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["delete", "drop", "destroy", "remove", "write", "update"]
        .iter()
        .any(|needle| lower.contains(needle))
}

/// Build `tool_constraints_json` for `McpSessionOpen`.
///
/// Every non-tombstone catalogue tool is included so the proxy can emit
/// `-32002` for pending/drift (Phase 3.2). Destructive/HITL tools also
/// carry `input_schema` / `forbidden_keys` / `hitl` for `-32602` / HITL.
///
/// `rule_hitl` is the **only** source for HITL in frozen constraints
/// (same as `require_plan`). Catalogue `DiscoveredTool.hitl` is a
/// suggestion on the asset page; it must not keep a tool in HITL after
/// the access-rule checkbox is cleared.
///
/// `rule_require_plan` is the **only** source for Mission Seal
/// (`require_plan` in frozen constraints). Catalogue
/// `DiscoveredTool.require_plan` is ignored.
pub fn tool_constraints_json_for_session(tools: &[DiscoveredTool]) -> String {
    tool_constraints_json_for_session_extra(
        tools,
        &std::collections::BTreeSet::new(),
        &std::collections::BTreeSet::new(),
    )
}

pub fn tool_constraints_json_for_session_extra(
    tools: &[DiscoveredTool],
    rule_hitl: &std::collections::BTreeSet<String>,
    rule_require_plan: &std::collections::BTreeSet<String>,
) -> String {
    let mut map = serde_json::Map::new();
    for t in tools {
        let status = t.status_or_legacy_approved();
        if status == ToolCatalogStatus::Tombstone {
            // Still record tombstones so tools/call can return -32002.
            map.insert(
                t.name.clone(),
                json!({
                    "status": "tombstone",
                    "schema_fingerprint": t.schema_fingerprint,
                }),
            );
            continue;
        }
        let hitl = rule_hitl.contains(&t.name);
        let require_plan = rule_require_plan.contains(&t.name);
        let mut entry = serde_json::Map::new();
        entry.insert("status".into(), json!(status.as_str()));
        if let Some(ref fp) = t.schema_fingerprint {
            entry.insert("schema_fingerprint".into(), json!(fp));
        } else {
            entry.insert(
                "schema_fingerprint".into(),
                json!(schema_fingerprint(
                    &t.name,
                    &t.description,
                    t.input_schema.as_ref()
                )),
            );
        }
        if status == ToolCatalogStatus::Approved && (t.destructive || hitl || require_plan) {
            let schema = t
                .input_schema
                .clone()
                .unwrap_or_else(|| json!({"type": "object"}));
            entry.insert("input_schema".into(), schema);
            entry.insert("forbidden_keys".into(), json!(t.forbidden_keys));
            entry.insert("hitl".into(), json!(hitl || require_plan));
            if require_plan {
                entry.insert("require_plan".into(), json!(true));
            }
        } else if hitl || require_plan {
            entry.insert("hitl".into(), json!(true));
            if require_plan {
                entry.insert("require_plan".into(), json!(true));
            }
        }
        map.insert(t.name.clone(), Value::Object(entry));
    }
    Value::Object(map).to_string()
}

/// Names with catalogue status `approved` (session ∩ / Access source).
pub fn approved_tool_names(tools: &[DiscoveredTool]) -> Vec<String> {
    let mut names: Vec<String> = tools
        .iter()
        .filter(|t| t.is_approved())
        .map(|t| t.name.clone())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Merge a fresh discover result into the existing TOFU catalogue.
///
/// - New upstream tools → `pending`
/// - Still present + was `approved` + same schema fingerprint → stay `approved`
/// - Still present + was `approved` + **fingerprint drift** → `pending` (Phase 3.2)
/// - Still present + was `pending` → stay `pending`
/// - Was `tombstone` and reappears → `pending`
/// - Missing from upstream → `tombstone`
///
/// `allowed_tools` is rewritten to **approved** names only.
pub fn apply_discovered_catalog(
    mut config: serde_json::Value,
    discovered: &[DiscoveredTool],
) -> serde_json::Value {
    let existing = catalog_from_config(&config);
    let mut by_name: BTreeMap<String, DiscoveredTool> =
        existing.into_iter().map(|t| (t.name.clone(), t)).collect();

    let discovered_names: BTreeSet<String> = discovered.iter().map(|t| t.name.clone()).collect();

    for d in discovered {
        let new_fp = d.schema_fingerprint.clone().unwrap_or_else(|| {
            schema_fingerprint(&d.name, &d.description, d.input_schema.as_ref())
        });
        match by_name.get(&d.name) {
            Some(prev) => {
                let prev_fp = prev.schema_fingerprint.clone().unwrap_or_else(|| {
                    schema_fingerprint(&prev.name, &prev.description, prev.input_schema.as_ref())
                });
                let status = match prev.status_or_legacy_approved() {
                    ToolCatalogStatus::Approved if prev_fp == new_fp => ToolCatalogStatus::Approved,
                    ToolCatalogStatus::Approved => {
                        // Schema/description drift → re-TOFU.
                        ToolCatalogStatus::Pending
                    }
                    ToolCatalogStatus::Pending | ToolCatalogStatus::Tombstone => {
                        ToolCatalogStatus::Pending
                    }
                };
                by_name.insert(
                    d.name.clone(),
                    DiscoveredTool {
                        name: d.name.clone(),
                        description: d.description.clone(),
                        status: Some(status),
                        destructive: d.destructive,
                        hitl: prev.hitl,
                        require_plan: false,
                        input_schema: d.input_schema.clone(),
                        forbidden_keys: prev.forbidden_keys.clone(),
                        schema_fingerprint: Some(new_fp),
                    },
                );
            }
            None => {
                by_name.insert(
                    d.name.clone(),
                    DiscoveredTool {
                        schema_fingerprint: Some(new_fp),
                        ..d.clone()
                    },
                );
            }
        }
    }

    for (name, prev) in by_name.clone() {
        if !discovered_names.contains(&name) {
            by_name.insert(
                name.clone(),
                DiscoveredTool {
                    status: Some(ToolCatalogStatus::Tombstone),
                    ..prev
                },
            );
        }
    }

    let catalog: Vec<DiscoveredTool> = by_name.into_values().collect();
    let approved = approved_tool_names(&catalog);
    if let Some(obj) = config.as_object_mut() {
        obj.insert("allowed_tools".to_string(), json!(approved));
        obj.insert(
            "mcp_tool_catalog".to_string(),
            serde_json::to_value(&catalog).unwrap_or(json!([])),
        );
    }
    config
}

pub fn approve_pending_catalog(mut config: serde_json::Value) -> serde_json::Value {
    let mut catalog = catalog_from_config(&config);
    for t in &mut catalog {
        if t.status_or_legacy_approved() == ToolCatalogStatus::Pending {
            t.status = Some(ToolCatalogStatus::Approved);
            if t.schema_fingerprint.is_none() {
                t.schema_fingerprint = Some(schema_fingerprint(
                    &t.name,
                    &t.description,
                    t.input_schema.as_ref(),
                ));
            }
        }
    }
    let approved = approved_tool_names(&catalog);
    if let Some(obj) = config.as_object_mut() {
        obj.insert("allowed_tools".to_string(), json!(approved));
        obj.insert(
            "mcp_tool_catalog".to_string(),
            serde_json::to_value(&catalog).unwrap_or(json!([])),
        );
    }
    config
}

pub fn approve_tool_in_catalog(
    mut config: serde_json::Value,
    tool_name: &str,
) -> serde_json::Value {
    let mut catalog = catalog_from_config(&config);
    for t in &mut catalog {
        if t.name == tool_name {
            t.status = Some(ToolCatalogStatus::Approved);
            if t.schema_fingerprint.is_none() {
                t.schema_fingerprint = Some(schema_fingerprint(
                    &t.name,
                    &t.description,
                    t.input_schema.as_ref(),
                ));
            }
        }
    }
    let approved = approved_tool_names(&catalog);
    if let Some(obj) = config.as_object_mut() {
        obj.insert("allowed_tools".to_string(), json!(approved));
        obj.insert(
            "mcp_tool_catalog".to_string(),
            serde_json::to_value(&catalog).unwrap_or(json!([])),
        );
    }
    config
}

pub fn catalog_from_config(connection_config: &serde_json::Value) -> Vec<DiscoveredTool> {
    if let Some(arr) = connection_config.get("mcp_tool_catalog")
        && let Ok(tools) = serde_json::from_value::<Vec<DiscoveredTool>>(arr.clone())
    {
        return tools;
    }
    // Legacy: flat allowed_tools → approved entries.
    connection_config
        .get("allowed_tools")
        .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
        .map(|names| {
            names
                .into_iter()
                .map(|name| DiscoveredTool {
                    name,
                    status: Some(ToolCatalogStatus::Approved),
                    ..Default::default()
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn catalog_from_asset(asset: &Asset) -> Vec<DiscoveredTool> {
    catalog_from_config(&asset.connection_config)
}

/// Approved tool name as seen on one or more MCP assets in a group.
/// Policy is still **one mode per name**; `asset_names` is display-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupCatalogTool {
    pub name: String,
    pub description: String,
    pub descriptions_diverge: bool,
    pub asset_names: Vec<String>,
}

#[derive(Default)]
struct NameAcc {
    descriptions: BTreeSet<String>,
    asset_names: BTreeSet<String>,
}

/// Union approved catalogues by tool name. First non-empty description
/// wins (sorted set). Pending / tombstone names are dropped.
pub fn merge_approved_group_catalog(
    assets: &[(String, Vec<DiscoveredTool>)],
) -> Vec<GroupCatalogTool> {
    let mut by_name: BTreeMap<String, NameAcc> = BTreeMap::new();
    for (asset_name, tools) in assets {
        let label = asset_name.trim();
        let label = if label.is_empty() {
            "Unnamed asset"
        } else {
            label
        };
        for tool in tools {
            if tool.status_or_legacy_approved() != ToolCatalogStatus::Approved {
                continue;
            }
            let acc = by_name.entry(tool.name.clone()).or_default();
            acc.asset_names.insert(label.to_string());
            acc.descriptions.insert(tool.description.clone());
        }
    }
    by_name
        .into_iter()
        .map(|(name, acc)| {
            let descriptions_diverge = acc.descriptions.len() > 1;
            let description = acc
                .descriptions
                .iter()
                .find(|d| !d.is_empty())
                .cloned()
                .or_else(|| acc.descriptions.iter().next().cloned())
                .unwrap_or_default();
            GroupCatalogTool {
                name,
                description,
                descriptions_diverge,
                asset_names: acc.asset_names.into_iter().collect(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tools_from_list_parses_pending() {
        let listed = json!({
            "result": {
                "tools": [
                    {"name": "echo", "description": "E"},
                    {"name": "delete_file", "description": "D", "inputSchema": {"type": "object"}}
                ]
            }
        });
        let tools = tools_from_list_result(&listed).unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "delete_file");
        assert!(tools[0].destructive);
        assert_eq!(tools[0].status, Some(ToolCatalogStatus::Pending));
        assert_eq!(tools[1].name, "echo");
    }

    #[test]
    fn apply_discovered_marks_new_pending() {
        let cfg = apply_discovered_catalog(
            json!({}),
            &[
                DiscoveredTool {
                    name: "a".into(),
                    status: Some(ToolCatalogStatus::Pending),
                    ..Default::default()
                },
                DiscoveredTool {
                    name: "b".into(),
                    status: Some(ToolCatalogStatus::Pending),
                    ..Default::default()
                },
            ],
        );
        assert_eq!(cfg["allowed_tools"], json!([]));
        assert_eq!(cfg["mcp_tool_catalog"][0]["status"], json!("pending"));
    }

    #[test]
    fn approve_pending_fills_allowed_tools() {
        let cfg = apply_discovered_catalog(
            json!({}),
            &[DiscoveredTool {
                name: "echo".into(),
                status: Some(ToolCatalogStatus::Pending),
                ..Default::default()
            }
            .with_computed_fingerprint()],
        );
        let cfg = approve_pending_catalog(cfg);
        assert_eq!(cfg["allowed_tools"], json!(["echo"]));
        assert_eq!(cfg["mcp_tool_catalog"][0]["status"], json!("approved"));
        assert!(cfg["mcp_tool_catalog"][0]["schema_fingerprint"].is_string());
    }

    #[test]
    fn schema_drift_demotes_approved_to_pending() {
        let approved = DiscoveredTool {
            name: "echo".into(),
            description: "old".into(),
            status: Some(ToolCatalogStatus::Approved),
            input_schema: Some(json!({"type": "object"})),
            ..Default::default()
        }
        .with_computed_fingerprint();
        let cfg = apply_discovered_catalog(json!({}), std::slice::from_ref(&approved));
        let cfg = approve_pending_catalog(cfg); // no-op if already approved path
        // Force approved in catalog
        let mut cfg = cfg;
        if let Some(arr) = cfg
            .get_mut("mcp_tool_catalog")
            .and_then(|v| v.as_array_mut())
        {
            arr.clear();
            arr.push(serde_json::to_value(&approved).unwrap());
        }
        cfg["allowed_tools"] = json!(["echo"]);

        let drifted = DiscoveredTool {
            name: "echo".into(),
            description: "new".into(),
            status: Some(ToolCatalogStatus::Pending),
            input_schema: Some(json!({"type": "object", "properties": {"x": {}}})),
            ..Default::default()
        }
        .with_computed_fingerprint();
        let cfg = apply_discovered_catalog(cfg, &[drifted]);
        assert_eq!(cfg["mcp_tool_catalog"][0]["status"], json!("pending"));
        assert_eq!(cfg["allowed_tools"], json!([]));
    }

    #[test]
    fn schema_fingerprint_stable() {
        let a = schema_fingerprint("echo", "E", Some(&json!({"type": "object"})));
        let b = schema_fingerprint("echo", "E", Some(&json!({"type": "object"})));
        assert_eq!(a, b);
        let c = schema_fingerprint("echo", "E2", Some(&json!({"type": "object"})));
        assert_ne!(a, c);
    }

    #[test]
    fn session_hitl_follows_rule_not_catalogue() {
        let echo = DiscoveredTool {
            name: "echo".into(),
            status: Some(ToolCatalogStatus::Approved),
            hitl: true,
            ..Default::default()
        };
        let empty = BTreeSet::new();
        let raw =
            tool_constraints_json_for_session_extra(std::slice::from_ref(&echo), &empty, &empty);
        let v: Value = serde_json::from_str(&raw).unwrap();
        assert_ne!(
            v["echo"].get("hitl").and_then(Value::as_bool),
            Some(true),
            "catalogue hitl must not freeze HITL when the rule left the box unchecked"
        );

        let mut rule = BTreeSet::new();
        rule.insert("echo".into());
        let raw = tool_constraints_json_for_session_extra(&[echo], &rule, &empty);
        let v: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["echo"]["hitl"], json!(true));
    }

    #[test]
    fn merge_group_catalog_unions_names_and_flags_description_drift() {
        let demo = vec![
            DiscoveredTool {
                name: "echo".into(),
                description: "Echo a message back".into(),
                status: Some(ToolCatalogStatus::Approved),
                ..Default::default()
            },
            DiscoveredTool {
                name: "pending_only".into(),
                status: Some(ToolCatalogStatus::Pending),
                ..Default::default()
            },
        ];
        let ops = vec![
            DiscoveredTool {
                name: "echo".into(),
                description: "Ops echo".into(),
                status: Some(ToolCatalogStatus::Approved),
                ..Default::default()
            },
            DiscoveredTool {
                name: "ping_ops".into(),
                description: "Ping".into(),
                status: Some(ToolCatalogStatus::Approved),
                ..Default::default()
            },
        ];
        let merged =
            merge_approved_group_catalog(&[("MCP SERVER".into(), demo), ("MCP OPS".into(), ops)]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].name, "echo");
        assert_eq!(merged[0].asset_names, vec!["MCP OPS", "MCP SERVER"]);
        assert!(merged[0].descriptions_diverge);
        assert_eq!(merged[0].description, "Echo a message back");
        assert_eq!(merged[1].name, "ping_ops");
        assert_eq!(merged[1].asset_names, vec!["MCP OPS"]);
        assert!(!merged[1].descriptions_diverge);
    }

    #[test]
    fn merge_group_catalog_skips_pending_and_keeps_legacy_approved() {
        let tools = vec![DiscoveredTool {
            name: "legacy".into(),
            description: "old".into(),
            status: None,
            ..Default::default()
        }];
        let merged = merge_approved_group_catalog(&[("A".into(), tools)]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].name, "legacy");
    }
}
