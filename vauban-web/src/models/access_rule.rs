/// VAUBAN Web - Access rule model.
///
/// Access rules link user groups (vauban_groups) to asset groups (asset_groups)
/// with protocol constraints and temporal validity. They control which specific
/// assets a user can see and connect to.
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::access_rules;

/// Access rule database model.
#[derive(Debug, Clone, Queryable, Selectable, Identifiable, Serialize)]
#[diesel(table_name = access_rules)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AccessRule {
    pub id: i32,
    pub uuid: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub user_group_id: i32,
    pub asset_group_id: i32,
    pub allowed_protocols: Vec<Option<String>>,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
    pub require_mfa: bool,
    pub require_approval: bool,
    pub max_session_duration: Option<i32>,
    pub is_active: bool,
    pub priority: i32,
    pub created_by_id: Option<i32>,
    pub updated_by_id: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AccessRule {
    /// Return allowed protocols as a flat list without None values.
    pub fn protocols(&self) -> Vec<&str> {
        self.allowed_protocols
            .iter()
            .filter_map(|p| p.as_deref())
            .collect()
    }

    /// Check if a specific protocol is allowed by this rule.
    pub fn allows_protocol(&self, protocol: &str) -> bool {
        self.allowed_protocols
            .iter()
            .any(|p| p.as_deref() == Some(protocol))
    }

    /// Check if this rule is currently valid based on time constraints.
    pub fn is_temporally_valid(&self, now: DateTime<Utc>) -> bool {
        if !self.is_active {
            return false;
        }
        if let Some(from) = self.valid_from
            && now < from
        {
            return false;
        }
        if let Some(until) = self.valid_until
            && now > until
        {
            return false;
        }
        true
    }
}

/// New access rule for insertion.
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = access_rules)]
pub struct NewAccessRule {
    pub uuid: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub user_group_id: i32,
    pub asset_group_id: i32,
    pub allowed_protocols: Vec<Option<String>>,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
    pub require_mfa: bool,
    pub require_approval: bool,
    pub max_session_duration: Option<i32>,
    pub is_active: bool,
    pub priority: i32,
    pub created_by_id: Option<i32>,
}

/// Access rule creation request (API).
#[derive(Debug, Clone, Deserialize, validator::Validate)]
pub struct CreateAccessRuleRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub description: Option<String>,
    pub user_group_uuid: String,
    pub asset_group_uuid: String,
    pub allowed_protocols: Option<Vec<String>>,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(default)]
    pub require_mfa: bool,
    #[serde(default)]
    pub require_approval: bool,
    pub max_session_duration: Option<i32>,
    #[serde(default = "default_priority")]
    pub priority: i32,
}

/// Access rule update request (API).
#[derive(Debug, Clone, Deserialize, validator::Validate)]
pub struct UpdateAccessRuleRequest {
    #[validate(length(max = 100))]
    pub name: Option<String>,
    pub description: Option<String>,
    pub allowed_protocols: Option<Vec<String>>,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
    pub require_mfa: Option<bool>,
    pub require_approval: Option<bool>,
    pub max_session_duration: Option<i32>,
    pub is_active: Option<bool>,
    pub priority: Option<i32>,
}

fn default_priority() -> i32 {
    0
}

/// Response DTO enriched with group names.
#[derive(Debug, Clone, Serialize)]
pub struct AccessRuleResponse {
    pub uuid: String,
    pub name: String,
    pub description: Option<String>,
    pub user_group_uuid: String,
    pub user_group_name: String,
    pub asset_group_uuid: String,
    pub asset_group_name: String,
    pub allowed_protocols: Vec<String>,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
    pub require_mfa: bool,
    pub require_approval: bool,
    pub max_session_duration: Option<i32>,
    pub is_active: bool,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule() -> AccessRule {
        AccessRule {
            id: 1,
            uuid: Uuid::new_v4(),
            name: "devops-to-production".to_string(),
            description: Some("DevOps access to production servers".to_string()),
            user_group_id: 10,
            asset_group_id: 20,
            allowed_protocols: vec![Some("ssh".to_string()), Some("rdp".to_string())],
            valid_from: None,
            valid_until: None,
            require_mfa: true,
            require_approval: false,
            max_session_duration: Some(3600),
            is_active: true,
            priority: 0,
            created_by_id: Some(1),
            updated_by_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // ==================== Serialization ====================

    #[test]
    fn test_access_rule_serialization() {
        let rule = make_rule();
        let json = unwrap_ok!(serde_json::to_string(&rule));
        assert!(json.contains("devops-to-production"));
        assert!(json.contains("ssh"));
        assert!(json.contains("rdp"));
    }

    #[test]
    fn test_access_rule_response_serialization() {
        let resp = AccessRuleResponse {
            uuid: Uuid::new_v4().to_string(),
            name: "test-rule".to_string(),
            description: None,
            user_group_uuid: Uuid::new_v4().to_string(),
            user_group_name: "devops".to_string(),
            asset_group_uuid: Uuid::new_v4().to_string(),
            asset_group_name: "production".to_string(),
            allowed_protocols: vec!["ssh".to_string()],
            valid_from: None,
            valid_until: None,
            require_mfa: false,
            require_approval: false,
            max_session_duration: None,
            is_active: true,
            priority: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = unwrap_ok!(serde_json::to_string(&resp));
        assert!(json.contains("user_group_name"));
        assert!(json.contains("asset_group_name"));
        assert!(json.contains("devops"));
        assert!(json.contains("production"));
    }

    // ==================== protocols() ====================

    #[test]
    fn test_protocols_returns_flat_list() {
        let rule = make_rule();
        let protos = rule.protocols();
        assert_eq!(protos, vec!["ssh", "rdp"]);
    }

    #[test]
    fn test_protocols_filters_none_values() {
        let mut rule = make_rule();
        rule.allowed_protocols = vec![Some("ssh".to_string()), None, Some("rdp".to_string())];
        let protos = rule.protocols();
        assert_eq!(protos, vec!["ssh", "rdp"]);
    }

    #[test]
    fn test_protocols_empty() {
        let mut rule = make_rule();
        rule.allowed_protocols = vec![];
        assert!(rule.protocols().is_empty());
    }

    // ==================== allows_protocol() ====================

    #[test]
    fn test_allows_protocol_ssh() {
        let rule = make_rule();
        assert!(rule.allows_protocol("ssh"));
    }

    #[test]
    fn test_allows_protocol_rdp() {
        let rule = make_rule();
        assert!(rule.allows_protocol("rdp"));
    }

    #[test]
    fn test_allows_protocol_vnc_denied() {
        let rule = make_rule();
        assert!(!rule.allows_protocol("vnc"));
    }

    #[test]
    fn test_allows_protocol_empty_string() {
        let rule = make_rule();
        assert!(!rule.allows_protocol(""));
    }

    #[test]
    fn test_allows_protocol_case_sensitive() {
        let rule = make_rule();
        assert!(!rule.allows_protocol("SSH"));
    }

    // ==================== is_temporally_valid() ====================

    #[test]
    fn test_temporally_valid_no_constraints() {
        let rule = make_rule();
        assert!(rule.is_temporally_valid(Utc::now()));
    }

    #[test]
    fn test_temporally_valid_inactive_rule() {
        let mut rule = make_rule();
        rule.is_active = false;
        assert!(!rule.is_temporally_valid(Utc::now()));
    }

    #[test]
    fn test_temporally_valid_future_valid_from() {
        let mut rule = make_rule();
        rule.valid_from = Some(Utc::now() + chrono::Duration::hours(1));
        assert!(!rule.is_temporally_valid(Utc::now()));
    }

    #[test]
    fn test_temporally_valid_past_valid_until() {
        let mut rule = make_rule();
        rule.valid_until = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(!rule.is_temporally_valid(Utc::now()));
    }

    #[test]
    fn test_temporally_valid_within_window() {
        let mut rule = make_rule();
        rule.valid_from = Some(Utc::now() - chrono::Duration::hours(1));
        rule.valid_until = Some(Utc::now() + chrono::Duration::hours(1));
        assert!(rule.is_temporally_valid(Utc::now()));
    }

    #[test]
    fn test_temporally_valid_past_valid_from_no_until() {
        let mut rule = make_rule();
        rule.valid_from = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(rule.is_temporally_valid(Utc::now()));
    }

    #[test]
    fn test_temporally_valid_no_from_future_until() {
        let mut rule = make_rule();
        rule.valid_until = Some(Utc::now() + chrono::Duration::hours(1));
        assert!(rule.is_temporally_valid(Utc::now()));
    }

    // ==================== Validation ====================

    #[test]
    fn test_create_request_valid() {
        let req = CreateAccessRuleRequest {
            name: "valid-rule".to_string(),
            description: None,
            user_group_uuid: Uuid::new_v4().to_string(),
            asset_group_uuid: Uuid::new_v4().to_string(),
            allowed_protocols: Some(vec!["ssh".to_string()]),
            valid_from: None,
            valid_until: None,
            require_mfa: false,
            require_approval: false,
            max_session_duration: None,
            priority: 0,
        };
        assert!(validator::Validate::validate(&req).is_ok());
    }

    #[test]
    fn test_create_request_empty_name_fails() {
        let req = CreateAccessRuleRequest {
            name: "".to_string(),
            description: None,
            user_group_uuid: Uuid::new_v4().to_string(),
            asset_group_uuid: Uuid::new_v4().to_string(),
            allowed_protocols: None,
            valid_from: None,
            valid_until: None,
            require_mfa: false,
            require_approval: false,
            max_session_duration: None,
            priority: 0,
        };
        assert!(validator::Validate::validate(&req).is_err());
    }

    #[test]
    fn test_create_request_name_too_long_fails() {
        let req = CreateAccessRuleRequest {
            name: "x".repeat(101),
            description: None,
            user_group_uuid: Uuid::new_v4().to_string(),
            asset_group_uuid: Uuid::new_v4().to_string(),
            allowed_protocols: None,
            valid_from: None,
            valid_until: None,
            require_mfa: false,
            require_approval: false,
            max_session_duration: None,
            priority: 0,
        };
        assert!(validator::Validate::validate(&req).is_err());
    }

    #[test]
    fn test_create_request_deserialization() {
        let json = r#"{
            "name": "test-rule",
            "user_group_uuid": "00000000-0000-0000-0000-000000000001",
            "asset_group_uuid": "00000000-0000-0000-0000-000000000002",
            "allowed_protocols": ["ssh", "rdp"],
            "require_mfa": true
        }"#;
        let req: CreateAccessRuleRequest = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(req.name, "test-rule");
        assert!(req.require_mfa);
        assert!(!req.require_approval);
        assert_eq!(req.priority, 0);
        assert_eq!(
            req.allowed_protocols,
            Some(vec!["ssh".to_string(), "rdp".to_string()])
        );
    }

    #[test]
    fn test_create_request_defaults() {
        let json = r#"{
            "name": "minimal",
            "user_group_uuid": "00000000-0000-0000-0000-000000000001",
            "asset_group_uuid": "00000000-0000-0000-0000-000000000002"
        }"#;
        let req: CreateAccessRuleRequest = unwrap_ok!(serde_json::from_str(json));
        assert!(!req.require_mfa);
        assert!(!req.require_approval);
        assert_eq!(req.priority, 0);
        assert!(req.allowed_protocols.is_none());
    }

    #[test]
    fn test_update_request_partial() {
        let json = r#"{"name": "new-name", "is_active": false}"#;
        let req: UpdateAccessRuleRequest = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(req.name, Some("new-name".to_string()));
        assert_eq!(req.is_active, Some(false));
        assert!(req.description.is_none());
        assert!(req.allowed_protocols.is_none());
    }

    #[test]
    fn test_update_request_name_too_long_fails() {
        let req = UpdateAccessRuleRequest {
            name: Some("x".repeat(101)),
            description: None,
            allowed_protocols: None,
            valid_from: None,
            valid_until: None,
            require_mfa: None,
            require_approval: None,
            max_session_duration: None,
            is_active: None,
            priority: None,
        };
        assert!(validator::Validate::validate(&req).is_err());
    }
}
