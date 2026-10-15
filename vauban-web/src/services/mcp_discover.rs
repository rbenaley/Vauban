//! Admin MCP tool discovery + TOFU catalogue (M6 / Droits).
//!
//! Phase 2.1: discovery goes through `vauban-proxy-mcp` on a supervisor-
//! brokered FD (`McpDiscover`). Web never dials the asset host directly
//! (SSRF class closed). Lab without `proxy_mcp` IPC refuses discover.

use crate::AppState;
use crate::error::{AppError, AppResult};
use crate::ipc::McpDiscoverRequest;
use crate::models::asset::{Asset, AssetType};
use crate::services::mcp_session::{credential_ciphertext_from_password, mcp_upstream_tls_pin};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub use shared::mcp_tool_fingerprint::{INSTRUCTIONS_KEY, schema_fingerprint};
use shared::mcp_tool_fingerprint::{RESERVED_PREFIX, ToolDefinition, instructions_fingerprint};
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

/// Why a catalogue entry waits for (re-)approval (CIS MCP 4.1.1 / 1.3).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PendingReason {
    NewTool,
    DefinitionChanged,
}

pub const CHANGED_DESCRIPTION: &str = "description";
pub const CHANGED_INPUT_SCHEMA: &str = "input_schema";
pub const CHANGED_INSTRUCTIONS: &str = "instructions";

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
    /// Set while `pending`; cleared on approve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_reason: Option<PendingReason>,
    /// RFC 3339 time the new tool or the drift was detected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drift_detected_at: Option<String>,
    /// `description` and/or `input_schema` (definition_changed only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed_fields: Vec<String>,
    /// Previously approved description (definition_changed only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_description: Option<String>,
    /// Previously approved `inputSchema` (definition_changed only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_input_schema: Option<Value>,
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

    fn fingerprint(&self) -> String {
        self.schema_fingerprint.clone().unwrap_or_else(|| {
            schema_fingerprint(&self.name, &self.description, self.input_schema.as_ref())
        })
    }

    fn clear_pending_reason(&mut self) {
        self.pending_reason = None;
        self.drift_detected_at = None;
        self.changed_fields.clear();
        self.approved_description = None;
        self.approved_input_schema = None;
    }

    /// Approved → pending because the upstream definition changed.
    /// Keeps the first approved version when it drifts again before review.
    fn mark_definition_changed(&mut self, prev: &DiscoveredTool, now: &str) {
        let (old_desc, old_schema) = match prev.pending_reason {
            Some(PendingReason::DefinitionChanged) => (
                prev.approved_description.clone().unwrap_or_default(),
                prev.approved_input_schema.clone(),
            ),
            _ => (prev.description.clone(), prev.input_schema.clone()),
        };
        self.changed_fields = changed_fields(
            &old_desc,
            old_schema.as_ref(),
            &self.description,
            self.input_schema.as_ref(),
        );
        self.status = Some(ToolCatalogStatus::Pending);
        self.pending_reason = Some(PendingReason::DefinitionChanged);
        self.drift_detected_at = Some(
            prev.drift_detected_at
                .clone()
                .filter(|_| prev.pending_reason == Some(PendingReason::DefinitionChanged))
                .unwrap_or_else(|| now.to_string()),
        );
        self.approved_description = Some(old_desc);
        self.approved_input_schema = old_schema;
    }
}

fn changed_fields(
    old_desc: &str,
    old_schema: Option<&Value>,
    new_desc: &str,
    new_schema: Option<&Value>,
) -> Vec<String> {
    let mut out = Vec::new();
    if old_desc != new_desc {
        out.push(CHANGED_DESCRIPTION.to_string());
    }
    if old_schema != new_schema {
        out.push(CHANGED_INPUT_SCHEMA.to_string());
    }
    out
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Upstream `initialize.instructions`, pinned like a tool definition
/// (`connection_config.mcp_upstream_instructions`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UpstreamInstructionsEntry {
    pub text: String,
    pub fingerprint: String,
    #[serde(default)]
    pub status: ToolCatalogStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_reason: Option<PendingReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drift_detected_at: Option<String>,
    /// Previously approved text (definition_changed only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_text: Option<String>,
}

pub const INSTRUCTIONS_CONFIG_KEY: &str = "mcp_upstream_instructions";

/// Discover result: catalogue entries plus the upstream instructions.
#[derive(Debug, Clone, Default)]
pub struct DiscoveredCatalog {
    pub tools: Vec<DiscoveredTool>,
    pub instructions: Option<String>,
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
    let mut folded: BTreeMap<String, &str> = BTreeMap::new();
    for t in tools {
        let name = t
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AppError::Validation("MCP tool missing name".into()))?;
        if name.starts_with(RESERVED_PREFIX) {
            return Err(AppError::Validation(format!(
                "MCP tool name uses the reserved prefix {RESERVED_PREFIX}"
            )));
        }
        if !name.bytes().all(|c| c.is_ascii_graphic()) {
            return Err(AppError::Validation(format!(
                "MCP tool name {name:?} must be printable ASCII without spaces"
            )));
        }
        if let Some(other) = folded.insert(name.to_ascii_lowercase(), name) {
            return Err(AppError::Validation(format!(
                "MCP tool names {other:?} and {name:?} differ only by case"
            )));
        }
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
                pending_reason: Some(PendingReason::NewTool),
                ..Default::default()
            }
            .with_computed_fingerprint(),
        );
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out.dedup_by(|a, b| a.name == b.name);
    Ok(out)
}

/// Upstream instructions carried by proxy-mcp under [`INSTRUCTIONS_KEY`].
pub fn instructions_from_list_result(listed: &Value) -> Option<String> {
    listed
        .get(INSTRUCTIONS_KEY)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Discover tools via proxy-mcp on a brokered FD (Phase 2.1).
pub async fn discover_tools_from_upstream(
    state: &AppState,
    asset: &Asset,
    admin_user_uuid: &str,
) -> AppResult<DiscoveredCatalog> {
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

    let upstream_tls_spki_pin = Some(mcp_upstream_tls_pin(&asset.connection_config)?);

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
    Ok(DiscoveredCatalog {
        tools: tools_from_list_result(&listed)?,
        instructions: instructions_from_list_result(&listed),
    })
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
        // Legacy names-only catalogues froze no definition: the proxy cannot
        // detect drift on them, and a synthesized fingerprint would quarantine
        // every tool.
        if let Some(ref fp) = t.schema_fingerprint {
            entry.insert("schema_fingerprint".into(), json!(fp));
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

/// [`tool_constraints_json_for_session_extra`] for an asset, plus the
/// approved upstream instructions fingerprint under [`INSTRUCTIONS_KEY`]
/// (the proxy omits instructions that do not match it).
pub fn tool_constraints_json_for_asset(
    connection_config: &Value,
    rule_hitl: &BTreeSet<String>,
    rule_require_plan: &BTreeSet<String>,
) -> String {
    let raw = tool_constraints_json_for_session_extra(
        &catalog_from_config(connection_config),
        rule_hitl,
        rule_require_plan,
    );
    let Some(fp) = approved_instructions_fingerprint(connection_config) else {
        return raw;
    };
    let mut v: Value = serde_json::from_str(&raw).unwrap_or_else(|_| json!({}));
    if let Some(obj) = v.as_object_mut() {
        obj.insert(INSTRUCTIONS_KEY.into(), json!({ "fingerprint": fp }));
    }
    v.to_string()
}

pub fn instructions_from_config(connection_config: &Value) -> Option<UpstreamInstructionsEntry> {
    connection_config
        .get(INSTRUCTIONS_CONFIG_KEY)
        .and_then(|v| serde_json::from_value(v.clone()).ok())
}

pub fn approved_instructions_fingerprint(connection_config: &Value) -> Option<String> {
    instructions_from_config(connection_config)
        .filter(|e| e.status == ToolCatalogStatus::Approved)
        .map(|e| e.fingerprint)
}

fn store_instructions(config: &mut Value, entry: Option<UpstreamInstructionsEntry>) {
    if let Some(obj) = config.as_object_mut() {
        match entry {
            Some(e) => {
                obj.insert(
                    INSTRUCTIONS_CONFIG_KEY.into(),
                    serde_json::to_value(e).unwrap_or(Value::Null),
                );
            }
            None => {
                obj.remove(INSTRUCTIONS_CONFIG_KEY);
            }
        }
    }
}

/// Next instructions entry for a live `text`. `None` when unchanged.
fn next_instructions(
    prev: Option<UpstreamInstructionsEntry>,
    text: &str,
    now: &str,
) -> Option<UpstreamInstructionsEntry> {
    let fingerprint = instructions_fingerprint(text);
    match prev {
        Some(p) if p.fingerprint == fingerprint => None,
        Some(p) if p.status == ToolCatalogStatus::Approved => Some(UpstreamInstructionsEntry {
            text: text.to_string(),
            fingerprint,
            status: ToolCatalogStatus::Pending,
            pending_reason: Some(PendingReason::DefinitionChanged),
            drift_detected_at: Some(now.to_string()),
            approved_text: Some(p.text),
        }),
        Some(p) => Some(UpstreamInstructionsEntry {
            text: text.to_string(),
            fingerprint,
            status: ToolCatalogStatus::Pending,
            pending_reason: p.pending_reason.or(Some(PendingReason::NewTool)),
            drift_detected_at: p.drift_detected_at.or_else(|| Some(now.to_string())),
            approved_text: p.approved_text,
        }),
        None => Some(UpstreamInstructionsEntry {
            text: text.to_string(),
            fingerprint,
            status: ToolCatalogStatus::Pending,
            pending_reason: Some(PendingReason::NewTool),
            drift_detected_at: Some(now.to_string()),
            approved_text: None,
        }),
    }
}

/// Merge discovered upstream instructions: same fingerprint keeps its
/// status, a change goes back to pending, absence drops the entry.
pub fn apply_discovered_instructions_at(
    mut config: Value,
    instructions: Option<&str>,
    now: &str,
) -> Value {
    let prev = instructions_from_config(&config);
    match instructions {
        None => store_instructions(&mut config, None),
        Some(text) => {
            if let Some(next) = next_instructions(prev, text, now) {
                store_instructions(&mut config, Some(next));
            }
        }
    }
    config
}

/// Live drift reported by proxy-mcp for the upstream instructions.
/// `None` when the catalogue already reflects `text` (no new notice).
pub fn apply_live_instructions_drift(
    mut config: Value,
    text: &str,
    live_fp: &str,
    now: &str,
) -> Option<Value> {
    if instructions_fingerprint(text) != live_fp {
        return None;
    }
    let next = next_instructions(instructions_from_config(&config), text, now)?;
    store_instructions(&mut config, Some(next));
    Some(config)
}

/// Live drift reported by proxy-mcp for an approved tool. The live
/// definition replaces the stored one when it matches `live_fp`, so
/// Approve pins what the upstream serves now. `None` when the tool is
/// unknown or no longer approved (already handled).
pub fn apply_live_tool_drift(
    config: Value,
    tool_name: &str,
    live_fp: &str,
    live_definition_json: &str,
    now: &str,
) -> Option<Value> {
    let mut catalog = catalog_from_config(&config);
    let idx = catalog.iter().position(|t| t.name == tool_name)?;
    let prev = catalog[idx].clone();
    if !prev.is_approved() || prev.fingerprint() == live_fp {
        return None;
    }
    let live = serde_json::from_str::<Value>(live_definition_json)
        .ok()
        .and_then(|v| ToolDefinition::from_tool(&v))
        .filter(|d| d.name == tool_name && d.fingerprint() == live_fp);
    let mut next = prev.clone();
    if let Some(d) = live {
        next.description = d.description;
        next.input_schema = d.input_schema;
        next.schema_fingerprint = Some(live_fp.to_string());
    }
    next.mark_definition_changed(&prev, now);
    catalog[idx] = next;
    Some(store_catalog(config, catalog))
}

fn store_catalog(mut config: Value, catalog: Vec<DiscoveredTool>) -> Value {
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
/// - New upstream tools → `pending` (`new_tool`)
/// - Still present + was `approved` + same schema fingerprint → stay `approved`
/// - Still present + was `approved` + **fingerprint drift** → `pending`
///   (`definition_changed`, previous version kept for review)
/// - Still present + was `pending` → stay `pending`
/// - Was `tombstone` and reappears → `pending` (`new_tool`)
/// - Missing from upstream → `tombstone`
///
/// `allowed_tools` is rewritten to **approved** names only.
pub fn apply_discovered_catalog(config: Value, discovered: &[DiscoveredTool]) -> Value {
    apply_discovered_catalog_at(config, discovered, &now_rfc3339())
}

pub fn apply_discovered_catalog_at(
    config: Value,
    discovered: &[DiscoveredTool],
    now: &str,
) -> Value {
    let existing = catalog_from_config(&config);
    let mut by_name: BTreeMap<String, DiscoveredTool> =
        existing.into_iter().map(|t| (t.name.clone(), t)).collect();

    let discovered_names: BTreeSet<String> = discovered.iter().map(|t| t.name.clone()).collect();

    for d in discovered {
        let new_fp = d.fingerprint();
        let mut next = DiscoveredTool {
            schema_fingerprint: Some(new_fp.clone()),
            status: Some(ToolCatalogStatus::Pending),
            ..d.clone()
        };
        next.clear_pending_reason();
        match by_name.get(&d.name) {
            Some(prev) => {
                next.hitl = prev.hitl;
                next.forbidden_keys = prev.forbidden_keys.clone();
                next.require_plan = false;
                match prev.status_or_legacy_approved() {
                    ToolCatalogStatus::Approved if prev.fingerprint() == new_fp => {
                        next.status = Some(ToolCatalogStatus::Approved);
                    }
                    ToolCatalogStatus::Approved => next.mark_definition_changed(prev, now),
                    ToolCatalogStatus::Pending
                        if prev.pending_reason == Some(PendingReason::DefinitionChanged) =>
                    {
                        next.mark_definition_changed(prev, now);
                    }
                    ToolCatalogStatus::Pending => {
                        next.pending_reason = Some(PendingReason::NewTool);
                        next.drift_detected_at = prev
                            .drift_detected_at
                            .clone()
                            .or_else(|| Some(now.to_string()));
                    }
                    ToolCatalogStatus::Tombstone => {
                        next.pending_reason = Some(PendingReason::NewTool);
                        next.drift_detected_at = Some(now.to_string());
                    }
                }
            }
            None => {
                next.pending_reason = Some(PendingReason::NewTool);
                next.drift_detected_at = Some(now.to_string());
            }
        }
        by_name.insert(d.name.clone(), next);
    }

    for (name, prev) in by_name.clone() {
        if !discovered_names.contains(&name) {
            let mut t = DiscoveredTool {
                status: Some(ToolCatalogStatus::Tombstone),
                ..prev
            };
            t.clear_pending_reason();
            by_name.insert(name, t);
        }
    }

    store_catalog(config, by_name.into_values().collect())
}

fn approve_tool(t: &mut DiscoveredTool) {
    t.status = Some(ToolCatalogStatus::Approved);
    if t.schema_fingerprint.is_none() {
        t.schema_fingerprint = Some(t.fingerprint());
    }
    t.clear_pending_reason();
}

fn approve_instructions(config: &mut Value) {
    if let Some(mut e) = instructions_from_config(config) {
        e.status = ToolCatalogStatus::Approved;
        e.pending_reason = None;
        e.drift_detected_at = None;
        e.approved_text = None;
        store_instructions(config, Some(e));
    }
}

/// Approve every pending tool and the upstream instructions.
pub fn approve_pending_catalog(mut config: Value) -> Value {
    let mut catalog = catalog_from_config(&config);
    for t in &mut catalog {
        if t.status_or_legacy_approved() == ToolCatalogStatus::Pending {
            approve_tool(t);
        }
    }
    approve_instructions(&mut config);
    store_catalog(config, catalog)
}

/// Approve one tool, or the upstream instructions for [`INSTRUCTIONS_KEY`].
pub fn approve_tool_in_catalog(mut config: Value, tool_name: &str) -> Value {
    if tool_name == INSTRUCTIONS_KEY {
        approve_instructions(&mut config);
        return config;
    }
    let mut catalog = catalog_from_config(&config);
    for t in &mut catalog {
        if t.name == tool_name {
            approve_tool(t);
        }
    }
    store_catalog(config, catalog)
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
    fn legacy_catalogue_sends_no_fingerprint() {
        let legacy = json!({"allowed_tools": ["echo"]});
        let c: Value = serde_json::from_str(&tool_constraints_json_for_session(
            &catalog_from_config(&legacy),
        ))
        .unwrap();
        assert_eq!(c["echo"], json!({"status": "approved"}));

        let fp = schema_fingerprint("echo", "E", None);
        let frozen = json!({"mcp_tool_catalog": [
            {"name": "echo", "description": "E", "status": "approved", "schema_fingerprint": fp}
        ]});
        let c: Value = serde_json::from_str(&tool_constraints_json_for_session(
            &catalog_from_config(&frozen),
        ))
        .unwrap();
        assert_eq!(c["echo"]["schema_fingerprint"], json!(fp));
    }

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

    const T0: &str = "2026-10-03T14:02:00Z";
    const T1: &str = "2026-10-04T09:00:00Z";

    fn tool(name: &str, desc: &str, schema: Value) -> DiscoveredTool {
        DiscoveredTool {
            name: name.into(),
            description: desc.into(),
            input_schema: Some(schema),
            ..Default::default()
        }
    }

    #[test]
    fn web_and_shared_fingerprints_match() {
        let schema = json!({"type": "object", "properties": {"b": {}, "a": {}}});
        let def = ToolDefinition {
            name: "x".into(),
            description: "d".into(),
            input_schema: Some(schema.clone()),
        };
        assert_eq!(
            tool("x", "d", schema)
                .with_computed_fingerprint()
                .schema_fingerprint,
            Some(def.fingerprint())
        );
    }

    #[test]
    fn reserved_tool_name_is_refused() {
        let listed = json!({"result": {"tools": [{"name": "__vauban_upstream_instructions"}]}});
        assert!(tools_from_list_result(&listed).is_err());
    }

    /// Homoglyph and case variants are refused at discovery.
    #[test]
    fn non_ascii_or_case_duplicate_tool_names_are_refused() {
        let err = |names: &[&str]| {
            let tools: Vec<Value> = names.iter().map(|n| json!({"name": n})).collect();
            match tools_from_list_result(&json!({"result": {"tools": tools}})) {
                Err(AppError::Validation(m)) => m,
                other => panic!("expected validation error, got {other:?}"),
            }
        };
        assert!(err(&["read_file", "rеad_file"]).contains("printable ASCII"));
        assert!(err(&["read file"]).contains("printable ASCII"));
        assert!(err(&["tab\tname"]).contains("printable ASCII"));
        let dup = err(&["Read_File", "list", "read_file"]);
        assert!(
            dup.contains("\"Read_File\"") && dup.contains("\"read_file\""),
            "{dup}"
        );

        let ok = json!({"result": {"tools": [
            {"name": "read_file"}, {"name": "read-file"}, {"name": "ns.read_file"}
        ]}});
        assert_eq!(tools_from_list_result(&ok).unwrap().len(), 3);
    }

    #[test]
    fn instructions_read_from_reserved_key() {
        assert_eq!(
            instructions_from_list_result(&json!({INSTRUCTIONS_KEY: "hi"})).as_deref(),
            Some("hi")
        );
        assert!(instructions_from_list_result(&json!({INSTRUCTIONS_KEY: ""})).is_none());
        assert!(instructions_from_list_result(&json!({})).is_none());
    }

    #[test]
    fn discover_records_reasons_and_approve_clears_them() {
        let cfg = apply_discovered_catalog_at(json!({}), &[tool("t", "v1", json!({}))], T0);
        let t = &catalog_from_config(&cfg)[0];
        assert_eq!(t.pending_reason, Some(PendingReason::NewTool));
        assert_eq!(t.drift_detected_at.as_deref(), Some(T0));

        // Rediscovering a still-pending new tool keeps the first detection time.
        let cfg = apply_discovered_catalog_at(cfg, &[tool("t", "v1", json!({}))], T1);
        assert_eq!(
            catalog_from_config(&cfg)[0].drift_detected_at.as_deref(),
            Some(T0)
        );

        let cfg = approve_pending_catalog(cfg);
        let t = &catalog_from_config(&cfg)[0];
        assert!(t.is_approved());
        assert!(t.pending_reason.is_none() && t.drift_detected_at.is_none());

        // Same definition stays approved.
        let cfg = apply_discovered_catalog_at(cfg, &[tool("t", "v1", json!({}))], T1);
        assert!(catalog_from_config(&cfg)[0].is_approved());

        // Drift → pending with the approved version kept.
        let drifted = tool("t", "v2", json!({"type": "object"}));
        let cfg = apply_discovered_catalog_at(cfg, std::slice::from_ref(&drifted), T1);
        let t = &catalog_from_config(&cfg)[0];
        assert_eq!(t.pending_reason, Some(PendingReason::DefinitionChanged));
        assert_eq!(t.changed_fields, vec!["description", "input_schema"]);
        assert_eq!(t.approved_description.as_deref(), Some("v1"));
        assert_eq!(t.approved_input_schema, Some(json!({})));
        assert_eq!(t.drift_detected_at.as_deref(), Some(T1));

        // Drifting again before review keeps the first approved version and time.
        let cfg = apply_discovered_catalog_at(cfg, &[tool("t", "v3", json!({}))], T0);
        let t = &catalog_from_config(&cfg)[0];
        assert_eq!(t.approved_description.as_deref(), Some("v1"));
        assert_eq!(t.changed_fields, vec!["description"]);
        assert_eq!(t.drift_detected_at.as_deref(), Some(T1));

        let cfg = approve_tool_in_catalog(cfg, "t");
        let t = &catalog_from_config(&cfg)[0];
        assert!(t.is_approved() && t.approved_description.is_none() && t.changed_fields.is_empty());
        assert_eq!(cfg["allowed_tools"], json!(["t"]));

        // Disappears → tombstone without reason; reappears → new tool.
        let cfg = apply_discovered_catalog_at(cfg, &[], T1);
        let t = &catalog_from_config(&cfg)[0];
        assert_eq!(t.status, Some(ToolCatalogStatus::Tombstone));
        assert!(t.pending_reason.is_none());
        let cfg = apply_discovered_catalog_at(cfg, &[tool("t", "v3", json!({}))], T0);
        assert_eq!(
            catalog_from_config(&cfg)[0].pending_reason,
            Some(PendingReason::NewTool)
        );
    }

    #[test]
    fn legacy_pending_without_reason_becomes_new_tool() {
        let cfg = json!({"mcp_tool_catalog": [{"name": "t", "status": "pending"}]});
        let cfg = apply_discovered_catalog_at(cfg, &[tool("t", "", json!({}))], T1);
        let t = &catalog_from_config(&cfg)[0];
        assert_eq!(t.pending_reason, Some(PendingReason::NewTool));
        assert_eq!(t.drift_detected_at.as_deref(), Some(T1));
    }

    #[test]
    fn live_tool_drift_paths() {
        let cfg = approve_pending_catalog(apply_discovered_catalog_at(
            json!({}),
            &[tool("t", "v1", json!({}))],
            T0,
        ));
        let live = json!({"name": "t", "description": "v2", "inputSchema": {}});
        let fp = ToolDefinition::from_tool(&live).unwrap().fingerprint();
        assert!(apply_live_tool_drift(cfg.clone(), "nope", &fp, &live.to_string(), T1).is_none());
        let approved_fp = catalog_from_config(&cfg)[0]
            .schema_fingerprint
            .clone()
            .unwrap();
        assert!(
            apply_live_tool_drift(cfg.clone(), "t", &approved_fp, &live.to_string(), T1).is_none()
        );

        // Unverifiable live definition ("{}" from the proxy cap): pending,
        // stored definition kept.
        let next = apply_live_tool_drift(cfg.clone(), "t", &fp, "{}", T1).unwrap();
        let t = &catalog_from_config(&next)[0];
        assert_eq!(t.status, Some(ToolCatalogStatus::Pending));
        assert_eq!(t.description, "v1");
        assert!(t.changed_fields.is_empty());

        let next = apply_live_tool_drift(cfg, "t", &fp, &live.to_string(), T1).unwrap();
        let t = &catalog_from_config(&next)[0];
        assert_eq!(t.description, "v2");
        assert_eq!(t.schema_fingerprint.as_deref(), Some(fp.as_str()));
        assert!(apply_live_tool_drift(next, "t", &fp, &live.to_string(), T1).is_none());
    }

    #[test]
    fn instructions_lifecycle_and_session_pin() {
        let empty = BTreeSet::new();
        let cfg = apply_discovered_instructions_at(json!({}), Some("v1"), T0);
        let e = instructions_from_config(&cfg).unwrap();
        assert_eq!(e.status, ToolCatalogStatus::Pending);
        assert_eq!(e.pending_reason, Some(PendingReason::NewTool));
        assert!(approved_instructions_fingerprint(&cfg).is_none());
        let raw: Value =
            serde_json::from_str(&tool_constraints_json_for_asset(&cfg, &empty, &empty)).unwrap();
        assert!(raw.get(INSTRUCTIONS_KEY).is_none());

        // Changed while still pending: keeps reason and first time.
        let cfg = apply_discovered_instructions_at(cfg, Some("v1b"), T1);
        let e = instructions_from_config(&cfg).unwrap();
        assert_eq!(e.text, "v1b");
        assert_eq!(e.drift_detected_at.as_deref(), Some(T0));
        // Unchanged: no-op.
        assert_eq!(
            apply_discovered_instructions_at(cfg.clone(), Some("v1b"), T1),
            cfg
        );

        let cfg = approve_tool_in_catalog(cfg, INSTRUCTIONS_KEY);
        let fp = instructions_fingerprint("v1b");
        assert_eq!(
            approved_instructions_fingerprint(&cfg).as_deref(),
            Some(fp.as_str())
        );
        let raw: Value =
            serde_json::from_str(&tool_constraints_json_for_asset(&cfg, &empty, &empty)).unwrap();
        assert_eq!(raw[INSTRUCTIONS_KEY]["fingerprint"], json!(fp));

        let cfg = apply_discovered_instructions_at(cfg, Some("v2"), T1);
        let e = instructions_from_config(&cfg).unwrap();
        assert_eq!(e.pending_reason, Some(PendingReason::DefinitionChanged));
        assert_eq!(e.approved_text.as_deref(), Some("v1b"));

        let cfg = approve_pending_catalog(cfg);
        let e = instructions_from_config(&cfg).unwrap();
        assert_eq!(e.status, ToolCatalogStatus::Approved);
        assert!(e.approved_text.is_none() && e.pending_reason.is_none());

        // Live drift: wrong fingerprint ignored, same text no-op, change applied.
        assert!(apply_live_instructions_drift(cfg.clone(), "v3", "bad", T1).is_none());
        assert!(
            apply_live_instructions_drift(cfg.clone(), "v2", &instructions_fingerprint("v2"), T1)
                .is_none()
        );
        let next =
            apply_live_instructions_drift(cfg.clone(), "v3", &instructions_fingerprint("v3"), T1)
                .unwrap();
        assert_eq!(
            instructions_from_config(&next).unwrap().status,
            ToolCatalogStatus::Pending
        );

        // Upstream stops sending instructions: entry dropped.
        let cfg = apply_discovered_instructions_at(cfg, None, T1);
        assert!(instructions_from_config(&cfg).is_none());
        // Approving with no entry is harmless.
        assert_eq!(approve_tool_in_catalog(cfg.clone(), INSTRUCTIONS_KEY), cfg);
    }

    #[test]
    fn approve_fills_missing_fingerprint() {
        let cfg =
            json!({"mcp_tool_catalog": [{"name": "t", "description": "d", "status": "pending"}]});
        let cfg = approve_tool_in_catalog(cfg, "t");
        assert_eq!(
            catalog_from_config(&cfg)[0].schema_fingerprint,
            Some(schema_fingerprint("t", "d", None))
        );
    }

    #[test]
    fn store_helpers_ignore_non_object_config() {
        let mut v = json!([]);
        store_instructions(&mut v, None);
        assert_eq!(v, json!([]));
        assert_eq!(store_catalog(json!(null), Vec::new()), json!(null));
        let raw = tool_constraints_json_for_asset(
            &json!({"mcp_upstream_instructions": {"text": "x", "fingerprint": "f", "status": "approved"}}),
            &BTreeSet::new(),
            &BTreeSet::new(),
        );
        assert!(raw.contains(INSTRUCTIONS_KEY));
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
