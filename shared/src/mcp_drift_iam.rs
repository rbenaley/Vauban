//! Mission Seal first-drift IAM knob (access-rule column `mcp_drift_iam`).
//!
//! The proxy PEP is unchanged: `-32033`, no upstream, JSONL/WORM,
//! `McpMandateDriftNotify`. Only the web IAM mutation varies.

pub const DEFAULT_MCP_DRIFT_IAM: &str = "suspend_group";

pub fn default_mcp_drift_iam() -> String {
    DEFAULT_MCP_DRIFT_IAM.to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum McpDriftIam {
    Terminate,
    SuspendGroup,
    RevokeOpenerKey,
    SoftDeleteUser,
}

impl McpDriftIam {
    pub const ALL: [Self; 4] = [
        Self::Terminate,
        Self::SuspendGroup,
        Self::RevokeOpenerKey,
        Self::SoftDeleteUser,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Terminate => "terminate",
            Self::SuspendGroup => "suspend_group",
            Self::RevokeOpenerKey => "revoke_opener_key",
            Self::SoftDeleteUser => "soft_delete_user",
        }
    }

    /// Missing / blank → product default (fail-closed, current IAM).
    #[must_use]
    pub fn parse_or_default(raw: &str) -> Self {
        match parse_mcp_drift_iam(raw) {
            Ok(v) => v,
            Err(McpDriftIamParseError) => Self::SuspendGroup,
        }
    }

    /// Operator-facing label for the MCP access form and detail page.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Terminate => "Cut visit only",
            Self::SuspendGroup => "Suspend group",
            Self::RevokeOpenerKey => "Revoke opener key",
            Self::SoftDeleteUser => "Soft-delete user",
        }
    }

    /// Mail / HTML consequence sentence (EN product).
    #[must_use]
    pub fn mail_consequence(self) -> &'static str {
        match self {
            Self::Terminate => "The visit was cut. Group membership and API keys were not changed.",
            Self::SuspendGroup => {
                "The user was removed from the access group. Overturn restores eligibility only — a new Connect and a new plan are required."
            }
            Self::RevokeOpenerKey => {
                "The hop-1 API key that opened this visit was deactivated. An administrator must reactivate it or issue another key."
            }
            Self::SoftDeleteUser => {
                "The user account was soft-deleted. There is no automatic restore."
            }
        }
    }
}

impl std::fmt::Display for McpDriftIam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Unknown `mcp_drift_iam` token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpDriftIamParseError;

/// Strict parse: empty → default; unknown → `Err`.
pub fn parse_mcp_drift_iam(raw: &str) -> Result<McpDriftIam, McpDriftIamParseError> {
    match raw.trim() {
        "" => Ok(McpDriftIam::SuspendGroup),
        "terminate" => Ok(McpDriftIam::Terminate),
        "suspend_group" => Ok(McpDriftIam::SuspendGroup),
        "revoke_opener_key" => Ok(McpDriftIam::RevokeOpenerKey),
        "soft_delete_user" => Ok(McpDriftIam::SoftDeleteUser),
        _ => Err(McpDriftIamParseError),
    }
}

/// Persist path: never write a value the SQL CHECK would reject.
#[must_use]
pub fn normalize_mcp_drift_iam(raw: &str) -> String {
    McpDriftIam::parse_or_default(raw).as_str().to_string()
}

#[must_use]
pub fn max_severity(values: impl IntoIterator<Item = McpDriftIam>) -> McpDriftIam {
    values
        .into_iter()
        .max()
        .unwrap_or(McpDriftIam::SuspendGroup)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_and_known() {
        assert_eq!(parse_mcp_drift_iam(""), Ok(McpDriftIam::SuspendGroup));
        assert_eq!(parse_mcp_drift_iam("  "), Ok(McpDriftIam::SuspendGroup));
        assert_eq!(parse_mcp_drift_iam("terminate"), Ok(McpDriftIam::Terminate));
        assert_eq!(
            parse_mcp_drift_iam("suspend_group"),
            Ok(McpDriftIam::SuspendGroup)
        );
        assert_eq!(
            parse_mcp_drift_iam("revoke_opener_key"),
            Ok(McpDriftIam::RevokeOpenerKey)
        );
        assert_eq!(
            parse_mcp_drift_iam("soft_delete_user"),
            Ok(McpDriftIam::SoftDeleteUser)
        );
    }

    #[test]
    fn parse_rejects_unknown() {
        assert_eq!(parse_mcp_drift_iam("999"), Err(McpDriftIamParseError));
        assert_eq!(parse_mcp_drift_iam("off"), Err(McpDriftIamParseError));
        assert_eq!(parse_mcp_drift_iam("explode"), Err(McpDriftIamParseError));
        assert_eq!(
            McpDriftIam::parse_or_default("999"),
            McpDriftIam::SuspendGroup
        );
    }

    #[test]
    fn severity_max_order() {
        assert!(McpDriftIam::SoftDeleteUser > McpDriftIam::RevokeOpenerKey);
        assert!(McpDriftIam::RevokeOpenerKey > McpDriftIam::SuspendGroup);
        assert!(McpDriftIam::SuspendGroup > McpDriftIam::Terminate);
        assert_eq!(
            max_severity([McpDriftIam::Terminate, McpDriftIam::RevokeOpenerKey]),
            McpDriftIam::RevokeOpenerKey
        );
        assert_eq!(
            max_severity([McpDriftIam::SoftDeleteUser, McpDriftIam::SuspendGroup]),
            McpDriftIam::SoftDeleteUser
        );
        assert_eq!(max_severity([]), McpDriftIam::SuspendGroup);
    }

    #[test]
    fn normalize_never_emits_unknown() {
        assert_eq!(normalize_mcp_drift_iam(""), "suspend_group");
        assert_eq!(
            normalize_mcp_drift_iam("soft_delete_user"),
            "soft_delete_user"
        );
        assert_eq!(normalize_mcp_drift_iam("not-a-knob"), "suspend_group");
    }
}
