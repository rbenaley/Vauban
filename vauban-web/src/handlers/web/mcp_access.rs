//! MCP access-rule CRUD (`/sessions/mcp/access`).
//!
//! Same `access_rules` + `access_client` as PAM SSH/RDP. Create writes
//! `allowed_protocols = ["mcp"]`. Update mutates MCP tool columns and
//! common fields only — never strips ssh/rdp/iacs on a mixed rule.

use super::*;
use crate::handlers::web::access_rules::{
    format_rfc3339_to_display, format_rfc3339_to_local, parse_datetime, to_rfc3339_opt,
};
use crate::handlers::web::{
    load_mcp_group_catalog, load_mcp_live_tool_names, load_mcp_tools_for_asset_group,
};
use crate::services::mcp_discover::GroupCatalogTool;
use crate::templates::assets::access_rule_create::GroupOption;
use crate::templates::mcp::{
    McpAccessCreateTemplate, McpAccessDetailTemplate, McpAccessEditTemplate, McpAccessListTemplate,
    McpAccessRuleForm, McpAccessRuleItem, McpMatrixSection, McpMatrixTool,
};
use shared::messages::{
    ASSET_GROUP_KIND_ALL, AccessRuleData, AccessRuleInfo, GroupOption as IpcGroupOption,
};

#[derive(Debug, serde::Deserialize)]
pub struct McpAccessDeleteForm {
    pub csrf_token: String,
}

struct McpAccessFormFields {
    csrf_token: String,
    name: String,
    description: Option<String>,
    user_group_id: i32,
    asset_group_id: i32,
    valid_from: Option<String>,
    valid_until: Option<String>,
    is_active: Option<String>,
    priority: Option<String>,
    /// One mode per tool (`mcp_tool_mode[echo]=hitl`). Last value wins.
    mcp_tool_modes: Vec<(String, String)>,
    mcp_drift_iam: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum McpToolMode {
    Off,
    Allow,
    Hitl,
    RequirePlan,
}

fn parse_mcp_tool_mode(raw: &str) -> McpToolMode {
    match raw.trim() {
        "allow" => McpToolMode::Allow,
        "hitl" => McpToolMode::Hitl,
        "require_plan" => McpToolMode::RequirePlan,
        _ => McpToolMode::Off,
    }
}

fn parse_mcp_tool_mode_key(key: &str) -> Option<&str> {
    key.strip_prefix("mcp_tool_mode[")
        .and_then(|rest| rest.strip_suffix(']'))
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

fn parse_mcp_access_form(bytes: &[u8]) -> McpAccessFormFields {
    let mut f = McpAccessFormFields {
        csrf_token: String::new(),
        name: String::new(),
        description: None,
        user_group_id: 0,
        asset_group_id: 0,
        valid_from: None,
        valid_until: None,
        is_active: None,
        priority: None,
        mcp_tool_modes: Vec::new(),
        mcp_drift_iam: String::new(),
    };
    for (key, value) in url::form_urlencoded::parse(bytes) {
        let v = value.into_owned();
        match key.as_ref() {
            "csrf_token" => f.csrf_token = v,
            "name" => f.name = v,
            "description" => f.description = Some(v),
            "user_group_id" => f.user_group_id = v.parse().unwrap_or(0),
            "asset_group_id" => f.asset_group_id = v.parse().unwrap_or(0),
            "valid_from" => f.valid_from = Some(v),
            "valid_until" => f.valid_until = Some(v),
            "is_active" => f.is_active = Some(v),
            "priority" => f.priority = Some(v),
            "mcp_drift_iam" => f.mcp_drift_iam = v,
            other => {
                if let Some(tool) = parse_mcp_tool_mode_key(other) {
                    f.mcp_tool_modes.push((tool.to_string(), v));
                }
            }
        }
    }
    f
}

/// Missing / blank → `suspend_group`. Unknown token → HTTP 400.
fn mcp_drift_iam_from_form(raw: &str) -> Result<String, &'static str> {
    match shared::mcp_drift_iam::parse_mcp_drift_iam(raw) {
        Ok(v) => Ok(v.as_str().to_string()),
        Err(_) => Err("Invalid mcp_drift_iam"),
    }
}

fn unique_tools(tools: &[String]) -> Option<Vec<String>> {
    let mut out: Vec<String> = tools
        .iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    if out.is_empty() {
        return None;
    }
    out.sort();
    out.dedup();
    Some(out)
}

/// Drop names that are not catalogue-approved for the asset group.
/// Pending / seed leftovers must not appear as **new** policy.
fn keep_approved_names(
    names: Option<Vec<String>>,
    approved: &std::collections::HashSet<String>,
) -> Option<Vec<String>> {
    keep_approved_or_existing(names, approved, None, None)
}

/// Like [`keep_approved_names`], but names already stored on the rule
/// stay (catalogue Approve must not strip a saved mode) **while a
/// live MCP asset in the group still lists the name**. Tombstoned
/// assets must not leave a grant that a new asset could inherit.
fn keep_approved_or_existing(
    names: Option<Vec<String>>,
    approved: &std::collections::HashSet<String>,
    existing: Option<&[String]>,
    live: Option<&std::collections::HashSet<String>>,
) -> Option<Vec<String>> {
    let existing: std::collections::HashSet<&str> =
        existing.unwrap_or(&[]).iter().map(String::as_str).collect();
    let v = names?;
    let kept: Vec<String> = v
        .into_iter()
        .filter(|n| {
            if approved.contains(n) {
                return true;
            }
            if !existing.contains(n.as_str()) {
                return false;
            }
            match live {
                None => true,
                Some(live) => live.contains(n),
            }
        })
        .collect();
    if kept.is_empty() { None } else { Some(kept) }
}

fn flatten_rule_names(lists: &[Option<&[String]>]) -> Vec<String> {
    let mut names = std::collections::BTreeSet::new();
    for v in lists.iter().copied().flatten() {
        for n in v {
            let t = n.trim();
            if !t.is_empty() {
                names.insert(t.to_string());
            }
        }
    }
    names.into_iter().collect()
}

/// Names the form did not post keep their stored mode (no silent wipe),
/// unless `live` says no non-deleted MCP asset still exposes the name.
fn with_unposted_modes(
    form_modes: &[(String, String)],
    before_allow: Option<&[String]>,
    before_hitl: Option<&[String]>,
    before_plan: Option<&[String]>,
    live: Option<&std::collections::HashSet<String>>,
) -> Vec<(String, String)> {
    let mut out = form_modes.to_vec();
    let posted: std::collections::HashSet<String> = form_modes
        .iter()
        .map(|(n, _)| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .collect();
    let restrict = before_allow.is_some();
    let allowed_set: std::collections::HashSet<&str> = before_allow
        .unwrap_or(&[])
        .iter()
        .map(String::as_str)
        .collect();
    let hitl_set: std::collections::HashSet<&str> = before_hitl
        .unwrap_or(&[])
        .iter()
        .map(String::as_str)
        .collect();
    let plan_set: std::collections::HashSet<&str> = before_plan
        .unwrap_or(&[])
        .iter()
        .map(String::as_str)
        .collect();
    for name in flatten_rule_names(&[before_allow, before_hitl, before_plan]) {
        if posted.contains(&name) {
            continue;
        }
        if live.is_some_and(|l| !l.contains(&name)) {
            continue;
        }
        out.push((
            name.clone(),
            matrix_mode(&name, restrict, &allowed_set, &hitl_set, &plan_set).to_string(),
        ));
    }
    out
}

async fn live_names_for_group(
    state: &AppState,
    asset_group_id: i32,
) -> Option<std::collections::HashSet<String>> {
    let mut conn = state.db_pool.get().await.ok()?;
    load_mcp_live_tool_names(&mut conn, asset_group_id)
        .await
        .ok()
}

async fn approved_names_for_group(
    state: &AppState,
    asset_group_id: i32,
) -> std::collections::HashSet<String> {
    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(_) => return std::collections::HashSet::new(),
    };
    load_mcp_tools_for_asset_group(&mut conn, asset_group_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|t| t.name)
        .collect()
}

/// Derive the three SQL columns from one select per tool.
/// All Off = unrestricted (`None` allow-list). HITL / Require plan
/// are written onto the allow-list (`-32001` is before those gates).
/// Require plan is stored in `mcp_require_plan_tools` only (HITL is
/// implied at the proxy).
type McpToolColumns = (
    Option<Vec<String>>,
    Option<Vec<String>>,
    Option<Vec<String>>,
);

fn columns_from_modes(modes: &[(String, String)]) -> McpToolColumns {
    let mut last: std::collections::BTreeMap<String, McpToolMode> =
        std::collections::BTreeMap::new();
    for (name, raw) in modes {
        let n = name.trim();
        if n.is_empty() {
            continue;
        }
        last.insert(n.to_string(), parse_mcp_tool_mode(raw));
    }
    let mut allow = Vec::new();
    let mut hitl = Vec::new();
    let mut plan = Vec::new();
    for (name, mode) in last {
        match mode {
            McpToolMode::Off => {}
            McpToolMode::Allow => allow.push(name),
            McpToolMode::Hitl => {
                allow.push(name.clone());
                hitl.push(name);
            }
            McpToolMode::RequirePlan => {
                allow.push(name.clone());
                plan.push(name);
            }
        }
    }
    if allow.is_empty() {
        (None, None, None)
    } else {
        (Some(allow), unique_tools(&hitl), unique_tools(&plan))
    }
}

/// Plan > HITL > Allow > Off. Unrestricted rules (`allowed` is None)
/// render every tool Off unless a gate column still lists it (legacy).
fn matrix_mode(
    name: &str,
    restrict: bool,
    allowed: &std::collections::HashSet<&str>,
    hitl: &std::collections::HashSet<&str>,
    plan: &std::collections::HashSet<&str>,
) -> &'static str {
    if plan.contains(name) {
        "require_plan"
    } else if hitl.contains(name) {
        "hitl"
    } else if restrict && allowed.contains(name) {
        "allow"
    } else {
        "off"
    }
}

fn allows_mcp(protocols: &[String]) -> bool {
    protocols.iter().any(|p| p == "mcp")
}

fn is_mixed(protocols: &[String]) -> bool {
    protocols.iter().any(|p| p != "mcp")
}

fn other_protocols_label(protocols: &[String]) -> String {
    let mut v: Vec<&str> = protocols
        .iter()
        .filter(|p| p.as_str() != "mcp")
        .map(|p| p.as_str())
        .collect();
    v.sort();
    v.join(", ")
}

#[cfg(test)]
fn tools_label(tools: Option<&[String]>, empty: &str) -> String {
    match tools {
        None => empty.to_string(),
        Some([]) => "(empty)".to_string(),
        Some(list) => list.join(", "),
    }
}

fn map_groups(opts: Vec<IpcGroupOption>) -> Vec<GroupOption> {
    let mut mapped: Vec<GroupOption> = opts
        .into_iter()
        .map(|g| {
            let is_virtual = g.kind == ASSET_GROUP_KIND_ALL;
            GroupOption {
                id: g.id,
                name: g.name,
                is_virtual,
                virtual_asset_count: None,
            }
        })
        .collect();
    mapped.sort_by(|a, b| match (a.is_virtual, b.is_virtual) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });
    mapped
}

async fn load_groups(state: &AppState) -> Result<(Vec<GroupOption>, Vec<GroupOption>), AppError> {
    let (user_groups, asset_groups) = state.access_client.get_group_options_with_virtual().await?;
    Ok((map_groups(user_groups), map_groups(asset_groups)))
}

const SHARED_HEADING: &str = "Same name on several assets";
const SHARED_HINT: &str = "One mode applies to every asset that exposes this name. A session only offers the tool if the opened asset has it.";

#[cfg(test)]
fn sections_from_group_catalog(
    catalog: Vec<GroupCatalogTool>,
    allowed: Option<&[String]>,
    hitl: Option<&[String]>,
    plan: Option<&[String]>,
) -> Vec<McpMatrixSection> {
    sections_from_group_catalog_filtered(catalog, allowed, hitl, plan, None)
}

fn sections_from_group_catalog_filtered(
    catalog: Vec<GroupCatalogTool>,
    allowed: Option<&[String]>,
    hitl: Option<&[String]>,
    plan: Option<&[String]>,
    live_names: Option<&std::collections::HashSet<String>>,
) -> Vec<McpMatrixSection> {
    let allowed_set: std::collections::HashSet<&str> =
        allowed.unwrap_or(&[]).iter().map(String::as_str).collect();
    let hitl_set: std::collections::HashSet<&str> =
        hitl.unwrap_or(&[]).iter().map(String::as_str).collect();
    let plan_set: std::collections::HashSet<&str> =
        plan.unwrap_or(&[]).iter().map(String::as_str).collect();
    let restrict = allowed.is_some();

    let mut shared = Vec::new();
    let mut by_asset: std::collections::BTreeMap<String, Vec<McpMatrixTool>> =
        std::collections::BTreeMap::new();
    let mut catalog_names: std::collections::HashSet<String> = std::collections::HashSet::new();

    for t in catalog {
        catalog_names.insert(t.name.clone());
        let mode = matrix_mode(
            t.name.as_str(),
            restrict,
            &allowed_set,
            &hitl_set,
            &plan_set,
        )
        .to_string();
        let shared_name = t.asset_names.len() > 1;
        let asset_label = t.asset_names.join(" · ");
        let tool = McpMatrixTool {
            name: t.name,
            description: t.description,
            mode,
            asset_label,
            shared: shared_name,
            descriptions_diverge: t.descriptions_diverge,
        };
        if shared_name {
            shared.push(tool);
        } else {
            let heading = t
                .asset_names
                .as_slice()
                .first()
                .cloned()
                .unwrap_or_else(|| "Unnamed asset".into());
            by_asset.entry(heading).or_default().push(tool);
        }
    }

    let mut sections = Vec::new();
    if !shared.is_empty() {
        sections.push(McpMatrixSection {
            heading: SHARED_HEADING.into(),
            hint: SHARED_HINT.into(),
            badge_label: String::new(),
            tools: shared,
        });
    }
    for (heading, tools) in by_asset {
        sections.push(McpMatrixSection {
            heading,
            hint: String::new(),
            badge_label: "MCP".into(),
            tools,
        });
    }

    let mut seen: std::collections::HashSet<String> = catalog_names;
    let mut orphans = Vec::new();
    for name in flatten_rule_names(&[allowed, hitl, plan]) {
        if live_names.is_some_and(|live| !live.contains(&name)) {
            continue;
        }
        if seen.insert(name.clone()) {
            orphans.push(McpMatrixTool {
                name: name.clone(),
                description: String::new(),
                mode: matrix_mode(name.as_str(), restrict, &allowed_set, &hitl_set, &plan_set)
                    .to_string(),
                asset_label: String::new(),
                shared: false,
                descriptions_diverge: false,
            });
        }
    }
    if !orphans.is_empty() {
        sections.push(McpMatrixSection {
            heading: "On this rule (not in the approved catalogue)".into(),
            hint: "Saved on this access rule. Catalogue Approve does not change these modes."
                .into(),
            badge_label: String::new(),
            tools: orphans,
        });
    }
    sections
}

async fn matrix_sections(
    state: &AppState,
    asset_group_id: i32,
    allowed: Option<&[String]>,
    hitl: Option<&[String]>,
    plan: Option<&[String]>,
) -> Vec<McpMatrixSection> {
    let Ok(mut conn) = state.db_pool.get().await else {
        return Vec::new();
    };
    let catalog = load_mcp_group_catalog(&mut conn, asset_group_id)
        .await
        .unwrap_or_default();
    let live = load_mcp_live_tool_names(&mut conn, asset_group_id)
        .await
        .ok();
    sections_from_group_catalog_filtered(catalog, allowed, hitl, plan, live.as_ref())
}

/// Counts **modes**, not SQL array lengths. HITL / Require plan names
/// also live in `mcp_allowed_tools` so they must not inflate Allow.
fn tools_summary_from_columns(
    allowed: Option<&[String]>,
    hitl: Option<&[String]>,
    plan: Option<&[String]>,
) -> String {
    let hitl_set: std::collections::HashSet<&str> =
        hitl.unwrap_or(&[]).iter().map(String::as_str).collect();
    let plan_set: std::collections::HashSet<&str> =
        plan.unwrap_or(&[]).iter().map(String::as_str).collect();
    let allow_part = match allowed {
        None => "does not restrict".to_string(),
        Some(v) => {
            let n = v
                .iter()
                .filter(|n| {
                    let s = n.as_str();
                    !hitl_set.contains(s) && !plan_set.contains(s)
                })
                .count();
            format!("allow {n}")
        }
    };
    format!(
        "{allow_part} · HITL {} · plan {}",
        hitl_set.len(),
        plan_set.len()
    )
}

fn rule_item(info: &AccessRuleInfo) -> McpAccessRuleItem {
    McpAccessRuleItem {
        uuid: info.uuid.clone(),
        name: info.name.clone(),
        user_group_name: info.user_group_name.clone(),
        asset_group_name: info.asset_group_name.clone(),
        is_active: info.is_active,
        tools_summary: tools_summary_from_columns(
            info.mcp_allowed_tools.as_deref(),
            info.mcp_hitl_tools.as_deref(),
            info.mcp_require_plan_tools.as_deref(),
        ),
        mixed: is_mixed(&info.allowed_protocols),
    }
}

fn csrf_ok(state: &AppState, jar: &CookieJar, token: &str) -> bool {
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        token,
    )
}

pub async fn mcp_access_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    browser_tz: BrowserTz,
) -> Response {
    let flash = incoming_flash.flash();
    if !perms.access_rules_read {
        return flash_redirect(
            flash.error("You need access_rules:read to view MCP access rules"),
            "/sessions/mcp",
        );
    }
    let infos = match state.access_client.list_access_rules().await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "MCP access list failed");
            return flash_redirect(
                flash.error("Failed to load MCP access rules"),
                "/sessions/mcp",
            );
        }
    };
    let mut rules: Vec<McpAccessRuleItem> = infos
        .iter()
        .filter(|r| allows_mcp(&r.allowed_protocols))
        .map(rule_item)
        .collect();
    rules.sort_by_key(|a| a.name.to_lowercase());

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("MCP access rules".into(), user.clone(), browser_tz.0)
        .with_current_path("/sessions/mcp/access");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();
    let template = McpAccessListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        mcp_nav: "access".into(),
        mcp_can_supervise: perms.sessions_supervise,
        rules,
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "MCP access list render failed");
            flash_redirect(
                flash.error("Failed to render MCP access rules"),
                "/sessions/mcp",
            )
        }
    }
}

pub async fn mcp_access_create_form(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    browser_tz: BrowserTz,
) -> Response {
    let flash = incoming_flash.flash();
    if !perms.access_rules_write {
        return flash_redirect(
            flash.error("You need access_rules:write to create MCP access rules"),
            "/sessions/mcp/access",
        );
    }
    let (user_groups, asset_groups) = match load_groups(&state).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "MCP access groups failed");
            return flash_redirect(flash.error("Failed to load groups"), "/sessions/mcp/access");
        }
    };
    let asset_group_id = asset_groups.as_slice().first().map(|g| g.id).unwrap_or(0);
    let sections = matrix_sections(&state, asset_group_id, None, None, None).await;

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("New MCP access rule".into(), user.clone(), browser_tz.0)
        .with_current_path("/sessions/mcp/access");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();
    let template = McpAccessCreateTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        mcp_nav: "access".into(),
        mcp_can_supervise: perms.sessions_supervise,
        form: McpAccessRuleForm {
            is_active: true,
            priority: "0".into(),
            ..Default::default()
        },
        user_groups,
        asset_groups,
        sections,
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "MCP access create render failed");
            flash_redirect(flash.error("Failed to render form"), "/sessions/mcp/access")
        }
    }
}

pub async fn create_mcp_access_rule_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    browser_tz: BrowserTz,
    body: axum::body::Bytes,
) -> Response {
    let flash = incoming_flash.flash();
    let form = parse_mcp_access_form(&body);
    if !csrf_ok(&state, &jar, &form.csrf_token) {
        return flash_redirect(
            flash.error("Invalid CSRF token"),
            "/sessions/mcp/access/new",
        );
    }
    if !perms.access_rules_write {
        return flash_redirect(
            flash.error("You need access_rules:write to create MCP access rules"),
            "/sessions/mcp/access",
        );
    }
    if form.name.trim().is_empty() {
        return flash_redirect(
            flash.error("Rule name is required"),
            "/sessions/mcp/access/new",
        );
    }
    let mcp_drift_iam = match mcp_drift_iam_from_form(&form.mcp_drift_iam) {
        Ok(v) => v,
        Err(msg) => return (axum::http::StatusCode::BAD_REQUEST, msg).into_response(),
    };
    let approved = approved_names_for_group(&state, form.asset_group_id).await;
    let (mcp_allowed_tools, mcp_hitl_tools, mcp_require_plan_tools) = {
        let (a, h, p) = columns_from_modes(&form.mcp_tool_modes);
        (
            keep_approved_names(a, &approved),
            keep_approved_names(h, &approved),
            keep_approved_names(p, &approved),
        )
    };
    let data = AccessRuleData {
        name: sanitize(form.name.trim()),
        description: sanitize_opt(form.description.filter(|s| !s.trim().is_empty())),
        user_group_id: form.user_group_id,
        asset_group_id: form.asset_group_id,
        allowed_protocols: vec!["mcp".into()],
        valid_from: to_rfc3339_opt(&parse_datetime(&form.valid_from, browser_tz.0)),
        valid_until: to_rfc3339_opt(&parse_datetime(&form.valid_until, browser_tz.0)),
        require_mfa: false,
        require_approval: false,
        max_session_duration: None,
        is_active: form.is_active.is_some(),
        priority: form
            .priority
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        mcp_allowed_tools,
        mcp_hitl_tools,
        mcp_require_plan_tools,
        mcp_drift_iam,
    };
    match state
        .access_client
        .create_access_rule(data, Some(auth_user.uuid.clone()))
        .await
    {
        Ok(info) => {
            crate::services::mcp_recheck::notify_policy_changed(&state).await;
            flash_redirect(
                flash.success(format!("MCP access rule '{}' created", info.name)),
                &format!("/sessions/mcp/access/{}", info.uuid),
            )
        }
        Err(AppError::Ipc(ref msg))
            if msg.to_lowercase().contains("unique")
                || msg.to_lowercase().contains("already exists") =>
        {
            flash_redirect(
                flash.error("A rule for this user group / asset group combination already exists"),
                "/sessions/mcp/access/new",
            )
        }
        Err(e) => {
            tracing::error!(error = %e, "MCP access create failed");
            flash_redirect(
                flash.error("Failed to create MCP access rule"),
                "/sessions/mcp/access/new",
            )
        }
    }
}

async fn load_mcp_rule(state: &AppState, uuid_str: &str) -> Result<AccessRuleInfo, String> {
    let info = state
        .access_client
        .get_access_rule(uuid_str)
        .await
        .map_err(|_| "Access rule not found".to_string())?;
    if !allows_mcp(&info.allowed_protocols) {
        return Err("Not an MCP access rule".to_string());
    }
    Ok(info)
}

pub async fn mcp_access_detail(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    browser_tz: BrowserTz,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    let flash = incoming_flash.flash();
    if !perms.access_rules_read {
        return flash_redirect(
            flash.error("You need access_rules:read to view MCP access rules"),
            "/sessions/mcp",
        );
    }
    let info = match load_mcp_rule(&state, &uuid_str).await {
        Ok(v) => v,
        Err(msg) => return flash_redirect(flash.error(msg), "/sessions/mcp/access"),
    };
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new(info.name.clone(), user.clone(), browser_tz.0)
        .with_current_path("/sessions/mcp/access");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();
    let sections = matrix_sections(
        &state,
        info.asset_group_id,
        info.mcp_allowed_tools.as_deref(),
        info.mcp_hitl_tools.as_deref(),
        info.mcp_require_plan_tools.as_deref(),
    )
    .await;
    let template = McpAccessDetailTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        mcp_nav: "access".into(),
        mcp_can_supervise: perms.sessions_supervise,
        uuid: info.uuid,
        name: info.name,
        description: info.description,
        user_group_name: info.user_group_name,
        asset_group_name: info.asset_group_name,
        is_active: info.is_active,
        priority: info.priority,
        valid_from: format_rfc3339_to_display(&info.valid_from, browser_tz.0),
        valid_until: format_rfc3339_to_display(&info.valid_until, browser_tz.0),
        mixed: is_mixed(&info.allowed_protocols),
        other_protocols_label: other_protocols_label(&info.allowed_protocols),
        sections,
        mcp_drift_iam: info.mcp_drift_iam.clone(),
        mcp_drift_iam_label: shared::mcp_drift_iam::McpDriftIam::parse_or_default(
            &info.mcp_drift_iam,
        )
        .label()
        .to_string(),
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "MCP access detail render failed");
            flash_redirect(flash.error("Failed to render rule"), "/sessions/mcp/access")
        }
    }
}

pub async fn mcp_access_edit_form(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    browser_tz: BrowserTz,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    let flash = incoming_flash.flash();
    if !perms.access_rules_write {
        return flash_redirect(
            flash.error("You need access_rules:write to edit MCP access rules"),
            "/sessions/mcp/access",
        );
    }
    let info = match load_mcp_rule(&state, &uuid_str).await {
        Ok(v) => v,
        Err(msg) => return flash_redirect(flash.error(msg), "/sessions/mcp/access"),
    };
    let (user_groups, asset_groups) = match load_groups(&state).await {
        Ok(v) => v,
        Err(_) => {
            return flash_redirect(flash.error("Failed to load groups"), "/sessions/mcp/access");
        }
    };
    let sections = matrix_sections(
        &state,
        info.asset_group_id,
        info.mcp_allowed_tools.as_deref(),
        info.mcp_hitl_tools.as_deref(),
        info.mcp_require_plan_tools.as_deref(),
    )
    .await;
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new(format!("Edit {}", info.name), user.clone(), browser_tz.0)
        .with_current_path("/sessions/mcp/access");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();
    let template = McpAccessEditTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        mcp_nav: "access".into(),
        mcp_can_supervise: perms.sessions_supervise,
        uuid: info.uuid,
        form: McpAccessRuleForm {
            name: info.name,
            description: info.description.unwrap_or_default(),
            user_group_id: info.user_group_id.to_string(),
            asset_group_id: info.asset_group_id.to_string(),
            valid_from: format_rfc3339_to_local(&info.valid_from, browser_tz.0),
            valid_until: format_rfc3339_to_local(&info.valid_until, browser_tz.0),
            is_active: info.is_active,
            priority: info.priority.to_string(),
            mcp_drift_iam: shared::mcp_drift_iam::normalize_mcp_drift_iam(&info.mcp_drift_iam),
        },
        user_groups,
        asset_groups,
        sections,
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "MCP access edit render failed");
            flash_redirect(flash.error("Failed to render form"), "/sessions/mcp/access")
        }
    }
}

#[allow(clippy::too_many_arguments)] // axum extractors, not a data clump
pub async fn update_mcp_access_rule_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    browser_tz: BrowserTz,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let flash = incoming_flash.flash();
    let edit_url = format!("/sessions/mcp/access/{uuid_str}/edit");
    let form = parse_mcp_access_form(&body);
    if !csrf_ok(&state, &jar, &form.csrf_token) {
        return flash_redirect(flash.error("Invalid CSRF token"), &edit_url);
    }
    if !perms.access_rules_write {
        return flash_redirect(
            flash.error("You need access_rules:write to edit MCP access rules"),
            "/sessions/mcp/access",
        );
    }
    let before = match load_mcp_rule(&state, &uuid_str).await {
        Ok(v) => v,
        Err(msg) => return flash_redirect(flash.error(msg), "/sessions/mcp/access"),
    };
    if form.name.trim().is_empty() {
        return flash_redirect(flash.error("Rule name is required"), &edit_url);
    }
    let mcp_drift_iam = match mcp_drift_iam_from_form(&form.mcp_drift_iam) {
        Ok(v) => v,
        Err(msg) => return (axum::http::StatusCode::BAD_REQUEST, msg).into_response(),
    };
    let approved = approved_names_for_group(&state, form.asset_group_id).await;
    let (mcp_allowed_tools, mcp_hitl_tools, mcp_require_plan_tools) = {
        let live = live_names_for_group(&state, form.asset_group_id).await;
        let modes = with_unposted_modes(
            &form.mcp_tool_modes,
            before.mcp_allowed_tools.as_deref(),
            before.mcp_hitl_tools.as_deref(),
            before.mcp_require_plan_tools.as_deref(),
            live.as_ref(),
        );
        let (a, h, p) = columns_from_modes(&modes);
        (
            keep_approved_or_existing(
                a,
                &approved,
                before.mcp_allowed_tools.as_deref(),
                live.as_ref(),
            ),
            keep_approved_or_existing(
                h,
                &approved,
                before.mcp_hitl_tools.as_deref(),
                live.as_ref(),
            ),
            keep_approved_or_existing(
                p,
                &approved,
                before.mcp_require_plan_tools.as_deref(),
                live.as_ref(),
            ),
        )
    };
    let data = AccessRuleData {
        name: sanitize(form.name.trim()),
        description: sanitize_opt(form.description.filter(|s| !s.trim().is_empty())),
        user_group_id: form.user_group_id,
        asset_group_id: form.asset_group_id,
        allowed_protocols: before.allowed_protocols.clone(),
        valid_from: to_rfc3339_opt(&parse_datetime(&form.valid_from, browser_tz.0)),
        valid_until: to_rfc3339_opt(&parse_datetime(&form.valid_until, browser_tz.0)),
        require_mfa: before.require_mfa,
        require_approval: before.require_approval,
        max_session_duration: before.max_session_duration,
        is_active: form.is_active.is_some(),
        priority: form
            .priority
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(before.priority),
        mcp_allowed_tools,
        mcp_hitl_tools,
        mcp_require_plan_tools,
        mcp_drift_iam,
    };
    match state
        .access_client
        .update_access_rule(&uuid_str, data.clone(), Some(auth_user.uuid.clone()))
        .await
    {
        Ok(_) => {
            let changes = crate::services::mcp_attribute_diff::mcp_rule_tool_changes(
                before.mcp_allowed_tools.as_deref(),
                data.mcp_allowed_tools.as_deref(),
                before.mcp_hitl_tools.as_deref(),
                data.mcp_hitl_tools.as_deref(),
                before.mcp_require_plan_tools.as_deref(),
                data.mcp_require_plan_tools.as_deref(),
            );
            let details = crate::services::mcp_attribute_diff::access_rule_updated_details(
                &uuid_str, &data.name, &changes,
            );
            crate::services::emit_audit(
                &state,
                crate::ipc::AuditEvent::new(
                    shared::messages::AuditEventType::AccessRuleUpdated,
                    details,
                )
                .user(auth_user.uuid.clone()),
            );
            crate::services::mcp_recheck::notify_policy_changed(&state).await;
            flash_redirect(
                flash.success(format!("MCP access rule '{}' updated", data.name)),
                &format!("/sessions/mcp/access/{uuid_str}"),
            )
        }
        Err(e) => {
            tracing::error!(error = %e, "MCP access update failed");
            flash_redirect(flash.error("Failed to update MCP access rule"), &edit_url)
        }
    }
}

pub async fn delete_mcp_access_rule_web(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<McpAccessDeleteForm>,
) -> Response {
    let flash = incoming_flash.flash();
    if !csrf_ok(&state, &jar, &form.csrf_token) {
        return flash_redirect(
            flash.error("Invalid CSRF token"),
            &format!("/sessions/mcp/access/{uuid_str}"),
        );
    }
    if !perms.access_rules_write {
        return flash_redirect(
            flash.error("You need access_rules:write to delete MCP access rules"),
            "/sessions/mcp/access",
        );
    }
    if let Err(msg) = load_mcp_rule(&state, &uuid_str).await {
        return flash_redirect(flash.error(msg), "/sessions/mcp/access");
    }
    match state.access_client.delete_access_rule(&uuid_str).await {
        Ok(()) => {
            crate::services::mcp_recheck::notify_policy_changed(&state).await;
            flash_redirect(
                flash.success("MCP access rule deleted"),
                "/sessions/mcp/access",
            )
        }
        Err(e) => {
            tracing::error!(error = %e, "MCP access delete failed");
            flash_redirect(
                flash.error("Failed to delete MCP access rule"),
                &format!("/sessions/mcp/access/{uuid_str}"),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_rule_data_json_defaults_mcp_drift_iam() {
        let json = r#"{
            "name": "r",
            "user_group_id": 1,
            "asset_group_id": 2,
            "allowed_protocols": ["mcp"],
            "require_mfa": false,
            "require_approval": false,
            "is_active": true,
            "priority": 0
        }"#;
        let data: AccessRuleData = serde_json::from_str(json).expect("AccessRuleData");
        assert_eq!(data.mcp_drift_iam, "suspend_group");
    }

    #[test]
    fn parse_form_missing_drift_iam_is_blank() {
        let body = b"csrf_token=x&name=r&user_group_id=1&asset_group_id=2";
        let f = parse_mcp_access_form(body);
        assert!(f.mcp_drift_iam.is_empty());
        assert_eq!(
            mcp_drift_iam_from_form(&f.mcp_drift_iam).ok().as_deref(),
            Some("suspend_group")
        );
    }

    #[test]
    fn parse_form_unknown_drift_iam_is_rejected() {
        let body = b"mcp_drift_iam=999";
        let f = parse_mcp_access_form(body);
        assert_eq!(f.mcp_drift_iam, "999");
        assert!(mcp_drift_iam_from_form(&f.mcp_drift_iam).is_err());
    }

    #[test]
    fn parse_form_all_off_writes_no_allow_list() {
        let body = b"csrf_token=x&name=r&user_group_id=1&asset_group_id=2&mcp_tool_mode%5Becho%5D=off&mcp_tool_mode%5Bwrite%5D=off";
        let f = parse_mcp_access_form(body);
        assert_eq!(
            f.mcp_tool_modes,
            vec![
                ("echo".into(), "off".into()),
                ("write".into(), "off".into())
            ]
        );
        assert_eq!(columns_from_modes(&f.mcp_tool_modes), (None, None, None));
    }

    #[test]
    fn parse_form_ignores_legacy_checkbox_fields() {
        let body = b"mcp_tools=echo&mcp_hitl_tools=echo&mcp_require_plan_tools=write";
        let f = parse_mcp_access_form(body);
        assert!(f.mcp_tool_modes.is_empty());
        assert_eq!(columns_from_modes(&f.mcp_tool_modes), (None, None, None));
    }

    #[test]
    fn parse_form_collects_one_mode_per_tool() {
        let body = b"mcp_tool_mode%5Becho%5D=hitl&mcp_tool_mode%5Bwrite%5D=require_plan&mcp_tool_mode%5Becho%5D=allow";
        let f = parse_mcp_access_form(body);
        let (allow, hitl, plan) = columns_from_modes(&f.mcp_tool_modes);
        assert_eq!(allow, Some(vec!["echo".into(), "write".into()]));
        assert_eq!(hitl, None, "last echo=allow must drop HITL");
        assert_eq!(plan, Some(vec!["write".into()]));
    }

    #[test]
    fn unique_tools_trims_sorts_dedups() {
        assert_eq!(unique_tools(&[]), None);
        assert_eq!(unique_tools(&["".into(), "  ".into()]), None);
        assert_eq!(
            unique_tools(&[" write ".into(), "echo".into(), "echo".into()]),
            Some(vec!["echo".into(), "write".into()])
        );
    }

    #[test]
    fn keep_approved_names_drops_pending() {
        let approved = ["add_ticket_comment".to_string()]
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(
            keep_approved_names(
                Some(vec![
                    "add_ticket_comment".into(),
                    "restart_service".into(),
                    "deploy_release".into()
                ]),
                &approved
            ),
            Some(vec!["add_ticket_comment".into()])
        );
        assert_eq!(
            keep_approved_names(Some(vec!["restart_service".into()]), &approved),
            None
        );
        assert_eq!(keep_approved_names(None, &approved), None);
    }

    #[test]
    fn columns_from_modes_derives_sql_without_impossible_combos() {
        assert_eq!(columns_from_modes(&[]), (None, None, None));
        assert_eq!(
            columns_from_modes(&[("echo".into(), "off".into())]),
            (None, None, None)
        );
        assert_eq!(
            columns_from_modes(&[("echo".into(), "allow".into())]),
            (Some(vec!["echo".into()]), None, None)
        );
        assert_eq!(
            columns_from_modes(&[("echo".into(), "hitl".into())]),
            (Some(vec!["echo".into()]), Some(vec!["echo".into()]), None)
        );
        assert_eq!(
            columns_from_modes(&[("echo".into(), "require_plan".into())]),
            (Some(vec!["echo".into()]), None, Some(vec!["echo".into()]))
        );
        assert_eq!(
            columns_from_modes(&[
                ("echo".into(), "allow".into()),
                ("hitl_demo".into(), "hitl".into()),
                ("read_demo_file".into(), "require_plan".into()),
                ("write_secret".into(), "off".into()),
            ]),
            (
                Some(vec![
                    "echo".into(),
                    "hitl_demo".into(),
                    "read_demo_file".into()
                ]),
                Some(vec!["hitl_demo".into()]),
                Some(vec!["read_demo_file".into()])
            )
        );
    }

    #[test]
    fn matrix_mode_plan_wins_and_catalogue_is_not_consulted() {
        let allowed: std::collections::HashSet<&str> = ["echo", "write"].into_iter().collect();
        let hitl: std::collections::HashSet<&str> = ["echo"].into_iter().collect();
        let plan: std::collections::HashSet<&str> = ["echo"].into_iter().collect();
        assert_eq!(
            matrix_mode("echo", true, &allowed, &hitl, &plan),
            "require_plan"
        );
        assert_eq!(matrix_mode("write", true, &allowed, &hitl, &plan), "allow");
        assert_eq!(matrix_mode("other", true, &allowed, &hitl, &plan), "off");
        let empty = std::collections::HashSet::new();
        assert_eq!(
            matrix_mode("echo", false, &empty, &empty, &empty),
            "off",
            "unrestricted rule shows Off"
        );
        assert_eq!(
            matrix_mode("echo", false, &empty, &hitl, &empty),
            "hitl",
            "legacy HITL column still renders HITL"
        );
    }

    #[test]
    fn sections_group_unique_tools_and_share_colliding_names() {
        let catalog = vec![
            GroupCatalogTool {
                name: "echo".into(),
                description: "Echo a message".into(),
                descriptions_diverge: true,
                asset_names: vec!["MCP OPS".into(), "MCP SERVER".into()],
            },
            GroupCatalogTool {
                name: "ping_ops".into(),
                description: "Ping".into(),
                descriptions_diverge: false,
                asset_names: vec!["MCP OPS".into()],
            },
            GroupCatalogTool {
                name: "read_demo_file".into(),
                description: "Read a file".into(),
                descriptions_diverge: false,
                asset_names: vec!["MCP SERVER".into()],
            },
        ];
        let sections = sections_from_group_catalog(catalog, Some(&["echo".into()]), None, None);
        assert_eq!(sections.len(), 3);
        assert_eq!(sections[0].heading, SHARED_HEADING);
        assert!(!sections[0].hint.is_empty());
        assert_eq!(sections[0].tools.len(), 1);
        assert_eq!(sections[0].tools[0].name, "echo");
        assert!(sections[0].tools[0].shared);
        assert_eq!(sections[0].tools[0].asset_label, "MCP OPS · MCP SERVER");
        assert!(sections[0].tools[0].descriptions_diverge);
        assert_eq!(sections[0].tools[0].mode, "allow");

        assert_eq!(sections[1].heading, "MCP OPS");
        assert_eq!(sections[1].badge_label, "MCP");
        assert_eq!(sections[1].tools[0].name, "ping_ops");
        assert!(!sections[1].tools[0].shared);
        assert_eq!(sections[1].tools[0].mode, "off");

        assert_eq!(sections[2].heading, "MCP SERVER");
        assert_eq!(sections[2].badge_label, "MCP");
        assert_eq!(sections[2].tools[0].name, "read_demo_file");
        assert!(sections[0].badge_label.is_empty());
    }

    #[test]
    fn matrix_never_invents_require_plan_from_catalogue_only_tools() {
        let catalog = vec![GroupCatalogTool {
            name: "add_ticket_comment".into(),
            description: "Intended for HITL".into(),
            descriptions_diverge: false,
            asset_names: vec!["MCP OPS".into()],
        }];
        let sections = sections_from_group_catalog(catalog, Some(&[]), None, None);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].tools[0].name, "add_ticket_comment");
        assert_eq!(
            sections[0].tools[0].mode, "off",
            "Approve on the asset must not display HITL / Require plan"
        );
    }

    #[test]
    fn matrix_keeps_saved_rule_names_missing_from_catalogue() {
        let live = ["read_demo_file".to_string()]
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        let sections = sections_from_group_catalog_filtered(
            Vec::new(),
            Some(&["read_demo_file".into()]),
            None,
            Some(&["read_demo_file".into()]),
            Some(&live),
        );
        assert_eq!(sections.len(), 1);
        assert!(
            sections[0]
                .heading
                .contains("not in the approved catalogue")
        );
        assert_eq!(sections[0].tools[0].name, "read_demo_file");
        assert_eq!(sections[0].tools[0].mode, "require_plan");
    }

    #[test]
    fn matrix_hides_rule_names_after_asset_delete() {
        let live = std::collections::HashSet::new();
        let sections = sections_from_group_catalog_filtered(
            Vec::new(),
            Some(&["add_ticket_comment".into(), "deploy_release".into()]),
            None,
            None,
            Some(&live),
        );
        assert!(
            sections.is_empty(),
            "names with no live MCP asset must leave the matrix"
        );
        let kept = keep_approved_or_existing(
            Some(vec!["add_ticket_comment".into(), "echo".into()]),
            &["echo".into()].into_iter().collect(),
            Some(&["add_ticket_comment".into(), "echo".into()]),
            Some(&["echo".to_string()].into_iter().collect()),
        );
        assert_eq!(kept, Some(vec!["echo".into()]));
    }

    #[test]
    fn unposted_modes_keep_saved_require_plan() {
        let form = vec![("add_ticket_comment".into(), "off".into())];
        let allow = vec!["echo".into(), "read_demo_file".into()];
        let plan = vec!["read_demo_file".into()];
        let merged = with_unposted_modes(&form, Some(&allow), None, Some(&plan), None);
        let (a, h, p) = columns_from_modes(&merged);
        assert_eq!(h, None);
        assert_eq!(p, Some(vec!["read_demo_file".into()]));
        assert_eq!(a, Some(vec!["echo".into(), "read_demo_file".into()]));
    }

    #[test]
    fn keep_approved_or_existing_does_not_strip_saved_names() {
        let approved = ["add_ticket_comment".to_string()]
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        let existing = vec!["read_demo_file".to_string()];
        assert_eq!(
            keep_approved_or_existing(
                Some(vec!["read_demo_file".into(), "ghost".into()]),
                &approved,
                Some(&existing),
                None
            ),
            Some(vec!["read_demo_file".into()])
        );
    }

    #[test]
    fn tools_summary_counts_allow_mode_only() {
        let allow = vec![
            "echo".to_string(),
            "hitl_demo".to_string(),
            "read_demo_file".to_string(),
        ];
        let hitl = vec!["hitl_demo".to_string()];
        let plan = vec!["read_demo_file".to_string()];
        assert_eq!(
            tools_summary_from_columns(Some(&allow), Some(&hitl), Some(&plan)),
            "allow 1 · HITL 1 · plan 1"
        );
        assert_eq!(
            tools_summary_from_columns(None, None, None),
            "does not restrict · HITL 0 · plan 0"
        );
    }

    #[test]
    fn allows_mcp_and_mixed_labels() {
        assert!(allows_mcp(&["mcp".into()]));
        assert!(allows_mcp(&["ssh".into(), "mcp".into()]));
        assert!(!allows_mcp(&["ssh".into()]));
        assert!(!is_mixed(&["mcp".into()]));
        assert!(is_mixed(&["mcp".into(), "rdp".into()]));
        assert_eq!(other_protocols_label(&["rdp".into(), "mcp".into()]), "rdp");
        assert_eq!(tools_label(None, "all"), "all");
        assert_eq!(tools_label(Some(&[]), "all"), "(empty)");
        assert_eq!(
            tools_label(Some(&["echo".into(), "write".into()]), "all"),
            "echo, write"
        );
    }
}
