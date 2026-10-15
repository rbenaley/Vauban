/// VAUBAN Web - Asset edit template.
use askama::Template;

use crate::services::mcp_discover::{
    CHANGED_DESCRIPTION, CHANGED_INPUT_SCHEMA, DiscoveredTool, INSTRUCTIONS_KEY, PendingReason,
    UpstreamInstructionsEntry,
};
use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// RFC 3339 timestamp in the browser timezone; raw text if unparsable.
fn display_time(rfc3339: Option<&str>, tz: chrono_tz::Tz) -> String {
    match rfc3339 {
        Some(s) => chrono::DateTime::parse_from_rfc3339(s)
            .map(|t| crate::utils::format_local(t.with_timezone(&chrono::Utc), tz))
            .unwrap_or_else(|_| s.to_string()),
        None => "an unknown date".to_string(),
    }
}

fn pending_message(
    reason: Option<PendingReason>,
    at: Option<&str>,
    fields: &[&str],
    tz: chrono_tz::Tz,
) -> String {
    let at = display_time(at, tz);
    match reason {
        Some(PendingReason::DefinitionChanged) if fields.is_empty() => format!(
            "Definition changed on the upstream server on {at}. Review the change before approving again."
        ),
        Some(PendingReason::DefinitionChanged) => format!(
            "Definition changed on the upstream server on {at} ({}). Review the change before approving again.",
            fields.join(", ")
        ),
        _ => format!("New on the upstream server since {at}. Review it before approving."),
    }
}

/// One catalogue row of the "Discovered tools" panel.
#[derive(Debug, Clone, Default)]
pub struct McpToolRow {
    pub name: String,
    pub description: String,
    pub status: String,
    pub hitl: bool,
    /// Reason shown next to the pending badge.
    pub pending_message: Option<String>,
    /// Before/after shown under "View change" (definition_changed only).
    pub approved_description: Option<String>,
    pub schema_changed: bool,
    pub approved_schema: String,
    pub current_schema: String,
}

impl McpToolRow {
    pub fn from_tool(t: &DiscoveredTool, tz: chrono_tz::Tz) -> Self {
        let status = t.status_or_legacy_approved().as_str().to_string();
        let pending = status == "pending";
        let changed = pending && t.pending_reason == Some(PendingReason::DefinitionChanged);
        let fields: Vec<&str> = t
            .changed_fields
            .iter()
            .map(|f| match f.as_str() {
                CHANGED_DESCRIPTION => "description",
                CHANGED_INPUT_SCHEMA => "input schema",
                other => other,
            })
            .collect();
        let pretty = |v: Option<&serde_json::Value>| {
            v.map(|v| serde_json::to_string_pretty(v).unwrap_or_default())
                .unwrap_or_else(|| "(none)".to_string())
        };
        Self {
            name: t.name.clone(),
            description: t.description.clone(),
            status,
            hitl: t.hitl,
            pending_message: pending.then(|| {
                pending_message(
                    t.pending_reason,
                    t.drift_detected_at.as_deref(),
                    &fields,
                    tz,
                )
            }),
            approved_description: changed
                .then(|| t.approved_description.clone().unwrap_or_default()),
            schema_changed: changed && t.changed_fields.iter().any(|f| f == CHANGED_INPUT_SCHEMA),
            approved_schema: pretty(t.approved_input_schema.as_ref()),
            current_schema: pretty(t.input_schema.as_ref()),
        }
    }
}

/// Upstream `initialize.instructions` row of the panel.
#[derive(Debug, Clone, Default)]
pub struct McpInstructionsRow {
    /// `approve-mcp-tools` `tool_name` value for this row.
    pub approve_key: String,
    pub status: String,
    pub text: String,
    pub pending_message: Option<String>,
    pub approved_text: Option<String>,
}

impl McpInstructionsRow {
    pub fn from_entry(e: &UpstreamInstructionsEntry, tz: chrono_tz::Tz) -> Self {
        let status = e.status.as_str().to_string();
        let pending = status == "pending";
        let changed = pending && e.pending_reason == Some(PendingReason::DefinitionChanged);
        Self {
            approve_key: INSTRUCTIONS_KEY.to_string(),
            status,
            text: e.text.clone(),
            pending_message: pending.then(|| {
                pending_message(
                    e.pending_reason,
                    e.drift_detected_at.as_deref(),
                    if changed { &["instructions"] } else { &[] },
                    tz,
                )
            }),
            approved_text: changed.then(|| e.approved_text.clone().unwrap_or_default()),
        }
    }
}

/// Asset data for editing.
#[derive(Debug, Clone)]
pub struct AssetEdit {
    pub uuid: String,
    pub name: String,
    pub hostname: String,
    pub port: i32,
    pub asset_type: String,
    /// True when the row is an IACS applicative variant.
    pub is_iacs: bool,
    /// Compact 3-char label used by the square header tile so the
    /// long IACS variants ("iacs_modbus", ...) do not overflow the
    /// `h-10 w-10` square (see `AssetType::badge_label`).
    pub badge_label: String,
    pub status: String,
    pub description: Option<String>,
    // SSH credentials extracted from connection_config.
    //
    // Note: secret values (password, private key, passphrase) are
    // intentionally NOT exposed to the template. Surfacing the stored
    // ciphertext into a `<input type="password">` would (a) leak it
    // into browser DOM/autofill/history and (b) confuse operators with
    // a 200+ dot field that has nothing to do with their original
    // password length. We only expose presence booleans so the form
    // can render "Leave blank to keep current ..." hints when an
    // existing secret is on file.
    pub ssh_username: String,
    pub ssh_auth_type: String,
    pub has_password: bool,
    pub has_private_key: bool,
    pub has_passphrase: bool,
    /// SSH key source: `generated` | `existing` (empty when not an
    /// `ssh_key` asset). Drives which edit-form block is shown.
    pub ssh_key_source: String,
    /// Stored OpenSSH public key (clear text, the ONLY key half ever
    /// shown back to the UI). `None` when no key pair is on file.
    pub ssh_public_key: Option<String>,
    /// True when the generated public key has already been pushed to the
    /// target (UX state of the "Push public key" button).
    pub ssh_pubkey_pushed: bool,
    /// SSH host key fingerprint (read-only, from connection_config).
    pub ssh_host_key_fingerprint: Option<String>,
    /// VAU-001: pinned RDP server-certificate fingerprint (read-only, from
    /// connection_config). `None` when no certificate has been pinned yet.
    pub rdp_server_cert_fingerprint: Option<String>,
    /// Windows AD domain extracted from connection_config (RDP only).
    pub rdp_domain: String,
    /// NLA auth mode (`ntlm` | `kerberos_restricted_admin`) extracted from
    /// connection_config (RDP only), normalised to the closed set.
    pub rdp_auth_mode: String,
    /// MCP upstream SPKI pin (`mcp_upstream_tls_spki`, MCP only).
    pub mcp_tls_spki: Option<String>,
    /// Stored hop-2 transport (`direct` | `tunnel`, MCP only).
    pub mcp_transport: String,
    /// TOFU catalogue rows (MCP only).
    pub mcp_tools: Vec<McpToolRow>,
    /// Pinned upstream instructions (MCP only, when the upstream sends any).
    pub mcp_instructions: Option<McpInstructionsRow>,
}

#[derive(Template)]
#[template(path = "assets/asset_edit.html")]
pub struct AssetEditTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub asset: AssetEdit,
    /// Industrial protocol choices for IACS asset edit (five variants).
    pub iacs_asset_types: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::asset::AssetType;

    fn create_test_asset_edit() -> AssetEdit {
        AssetEdit {
            uuid: "asset-uuid-123".to_string(),
            name: "Production Server".to_string(),
            hostname: "prod-01.example.com".to_string(),
            port: 22,
            asset_type: "ssh".to_string(),
            is_iacs: false,
            badge_label: "SSH".to_string(),
            status: "online".to_string(),
            description: Some("Main production server".to_string()),
            ssh_username: "root".to_string(),
            ssh_auth_type: "password".to_string(),
            has_password: false,
            has_private_key: false,
            has_passphrase: false,
            ssh_key_source: String::new(),
            ssh_public_key: None,
            ssh_pubkey_pushed: false,
            ssh_host_key_fingerprint: None,
            rdp_server_cert_fingerprint: None,
            rdp_domain: String::new(),
            rdp_auth_mode: "ntlm".to_string(),
            mcp_tls_spki: None,
            mcp_transport: "direct".to_string(),
            mcp_tools: Vec::new(),
            mcp_instructions: None,
        }
    }

    fn create_test_vauban_config() -> VaubanConfig {
        VaubanConfig {
            brand_name: "VAUBAN".to_string(),
            brand_logo: None,
            theme: "dark".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_asset_edit_creation() {
        let asset = create_test_asset_edit();
        assert_eq!(asset.name, "Production Server");
        assert_eq!(asset.hostname, "prod-01.example.com");
        assert_eq!(asset.port, 22);
    }

    #[test]
    fn test_asset_edit_without_description() {
        let mut asset = create_test_asset_edit();
        asset.description = None;
        assert!(asset.description.is_none());
    }

    #[test]
    fn test_asset_edit_clone() {
        let asset = create_test_asset_edit();
        let cloned = asset.clone();
        assert_eq!(asset.uuid, cloned.uuid);
        assert_eq!(asset.name, cloned.name);
        assert_eq!(asset.hostname, cloned.hostname);
    }

    #[test]
    fn test_asset_edit_debug() {
        let asset = create_test_asset_edit();
        let debug_str = format!("{:?}", asset);
        assert!(debug_str.contains("Production Server"));
        assert!(debug_str.contains("ssh"));
    }

    #[test]
    fn test_asset_edit_template_creation() {
        let template = AssetEditTemplate {
            title: "Edit Asset".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            asset: create_test_asset_edit(),
            iacs_asset_types: AssetType::iacs_select_options(),
        };
        assert_eq!(template.title, "Edit Asset");
        assert_eq!(template.asset.name, "Production Server");
    }

    #[test]
    fn edit_form_keeps_the_stored_mcp_transport() {
        use askama::Template;
        let mut asset = create_test_asset_edit();
        asset.asset_type = "mcp".to_string();
        asset.mcp_transport = "tunnel".to_string();
        let html = AssetEditTemplate {
            title: "Edit Asset".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            asset,
            iacs_asset_types: AssetType::iacs_select_options(),
        }
        .render()
        .unwrap();
        assert!(
            html.contains(r#"<option value="tunnel" selected>"#),
            "tunnel not preselected"
        );
        assert!(!html.contains(r#"<option value="direct" selected>"#));
    }

    #[test]
    fn test_asset_edit_template_with_user() {
        let user = UserContext {
            uuid: "user-uuid".to_string(),
            username: "admin".to_string(),
            display_name: "Admin User".to_string(),
            is_superuser: true,
            is_staff: true,
        };

        let template = AssetEditTemplate {
            title: "Edit Asset".to_string(),
            user: Some(user.clone()),
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: Some(user),
            asset: create_test_asset_edit(),
            iacs_asset_types: AssetType::iacs_select_options(),
        };

        assert!(template.user.is_some());
        assert_eq!(unwrap_some!(template.user.as_ref()).username, "admin");
    }

    #[test]
    fn test_asset_edit_template_renders() {
        let template = AssetEditTemplate {
            title: "Edit Asset".to_string(),
            user: Some(UserContext {
                uuid: "test".to_string(),
                username: "testuser".to_string(),
                display_name: "Test User".to_string(),
                is_superuser: true,
                is_staff: true,
            }),
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            asset: create_test_asset_edit(),
            iacs_asset_types: AssetType::iacs_select_options(),
        };

        let result = template.render();
        assert!(
            result.is_ok(),
            "AssetEditTemplate should render successfully"
        );
    }

    #[test]
    fn mcp_rows_explain_pending_and_render_diff() {
        use crate::services::mcp_discover::{ToolCatalogStatus, UpstreamInstructionsEntry};
        let changed = DiscoveredTool {
            name: "update_task".into(),
            description: "new desc".into(),
            status: Some(ToolCatalogStatus::Pending),
            input_schema: Some(serde_json::json!({"type": "object"})),
            pending_reason: Some(PendingReason::DefinitionChanged),
            drift_detected_at: Some("2026-10-03T14:02:00Z".into()),
            changed_fields: vec!["description".into(), "input_schema".into(), "x".into()],
            approved_description: Some("old desc".into()),
            ..Default::default()
        };
        let row = McpToolRow::from_tool(&changed, chrono_tz::UTC);
        assert_eq!(
            row.pending_message.as_deref(),
            Some(
                "Definition changed on the upstream server on 2026-10-03 14:02 UTC (description, input schema, x). Review the change before approving again."
            )
        );
        assert_eq!(row.approved_description.as_deref(), Some("old desc"));
        assert!(row.schema_changed);
        assert_eq!(row.approved_schema, "(none)");

        let unknown_fields = McpToolRow::from_tool(
            &DiscoveredTool {
                changed_fields: Vec::new(),
                approved_description: None,
                drift_detected_at: Some("not a date".into()),
                ..changed.clone()
            },
            chrono_tz::UTC,
        );
        assert_eq!(
            unknown_fields.pending_message.as_deref(),
            Some(
                "Definition changed on the upstream server on not a date. Review the change before approving again."
            )
        );
        assert_eq!(unknown_fields.approved_description.as_deref(), Some(""));

        let new_tool = McpToolRow::from_tool(
            &DiscoveredTool {
                name: "n".into(),
                status: Some(ToolCatalogStatus::Pending),
                ..Default::default()
            },
            chrono_tz::UTC,
        );
        assert_eq!(
            new_tool.pending_message.as_deref(),
            Some("New on the upstream server since an unknown date. Review it before approving.")
        );
        assert!(new_tool.approved_description.is_none() && !new_tool.schema_changed);

        let approved = McpToolRow::from_tool(
            &DiscoveredTool {
                name: "a".into(),
                ..Default::default()
            },
            chrono_tz::UTC,
        );
        assert_eq!(approved.status, "approved");
        assert!(approved.pending_message.is_none());

        let ins = McpInstructionsRow::from_entry(
            &UpstreamInstructionsEntry {
                text: "evil".into(),
                fingerprint: "f".into(),
                status: ToolCatalogStatus::Pending,
                pending_reason: Some(PendingReason::DefinitionChanged),
                drift_detected_at: Some("2026-10-03T14:02:00Z".into()),
                approved_text: Some("good".into()),
            },
            chrono_tz::UTC,
        );
        assert!(
            ins.pending_message
                .as_deref()
                .unwrap()
                .contains("(instructions)")
        );
        assert_eq!(ins.approved_text.as_deref(), Some("good"));
        assert_eq!(ins.approve_key, INSTRUCTIONS_KEY);
        let ins_new = McpInstructionsRow::from_entry(
            &UpstreamInstructionsEntry {
                pending_reason: Some(PendingReason::NewTool),
                approved_text: None,
                ..Default::default()
            },
            chrono_tz::UTC,
        );
        assert!(
            ins_new
                .pending_message
                .as_deref()
                .unwrap()
                .starts_with("New on")
        );
        assert!(ins_new.approved_text.is_none());
        let ins_ok = McpInstructionsRow::from_entry(
            &UpstreamInstructionsEntry {
                status: ToolCatalogStatus::Approved,
                ..Default::default()
            },
            chrono_tz::UTC,
        );
        assert!(ins_ok.pending_message.is_none());

        let mut asset = create_test_asset_edit();
        asset.asset_type = "mcp".into();
        asset.mcp_tools = vec![row, new_tool, approved];
        asset.mcp_instructions = Some(ins);
        let html = AssetEditTemplate {
            title: "Edit".into(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".into(),
            sidebar_content: None,
            header_user: None,
            asset,
            iacs_asset_types: AssetType::iacs_select_options(),
        }
        .render()
        .unwrap();
        assert!(html.contains("data-testid=\"mcp-tools-card\""));
        assert!(html.contains("data-testid=\"mcp-tool-pending-reason\""));
        assert!(html.contains("Review the change before approving again."));
        assert!(html.contains("data-testid=\"mcp-tool-diff\""));
        assert!(html.contains("old desc") && html.contains("new desc"));
        assert!(html.contains("data-testid=\"mcp-tool-schema-changed\""));
        assert!(html.contains("data-testid=\"mcp-instructions-diff\""));
        assert!(html.contains("value=\"__vauban_upstream_instructions\""));
    }

    #[test]
    fn test_asset_edit_rdp_type() {
        let mut asset = create_test_asset_edit();
        asset.asset_type = "rdp".to_string();
        asset.port = 3389;
        assert_eq!(asset.asset_type, "rdp");
        assert_eq!(asset.port, 3389);
    }

    #[test]
    fn test_asset_edit_all_statuses() {
        let mut asset = create_test_asset_edit();

        for status in ["online", "offline", "maintenance", "unknown"] {
            asset.status = status.to_string();
            assert_eq!(asset.status, status);
        }
    }
}
