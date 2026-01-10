/// VAUBAN Web - API key model.
///
/// API keys for programmatic access to VAUBAN.
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

use crate::schema::api_keys;

/// API key database model.
#[derive(Debug, Clone, Queryable, Selectable, Identifiable, Serialize)]
#[diesel(table_name = api_keys)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ApiKey {
    pub id: i32,
    pub uuid: Uuid,
    pub user_id: i32,
    pub name: String,
    pub key_prefix: String,
    #[serde(skip_serializing)]
    pub key_hash: String,
    pub scopes: serde_json::Value,
    pub last_used_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing)]
    pub last_used_ip: Option<IpNetwork>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// New API key for insertion.
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = api_keys)]
pub struct NewApiKey {
    pub uuid: Uuid,
    pub user_id: i32,
    pub name: String,
    pub key_prefix: String,
    pub key_hash: String,
    pub scopes: serde_json::Value,
    pub expires_at: Option<DateTime<Utc>>,
}

/// API key creation result (includes the raw key, only returned once).
#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyCreated {
    pub uuid: Uuid,
    pub name: String,
    pub key: String,
    pub key_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// API key scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyScope {
    Read,
    Write,
    Admin,
}

impl ApiKeyScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
}

impl ApiKey {
    /// Generate a new API key.
    /// Returns (prefix, full_key, hash) tuple.
    pub fn generate_key() -> (String, String, String) {
        use rand::RngCore;
        let mut rng = rand::thread_rng();

        // Generate random bytes for the key
        let mut random_bytes = [0u8; 32];
        rng.fill_bytes(&mut random_bytes);
        let key_body = hex::encode(random_bytes);

        // Create prefix (first 8 chars for identification)
        let prefix = format!("vbn_{}", &key_body[..4]);

        // Full key
        let full_key = format!("vbn_{}", key_body);

        // Hash for storage
        let hash = Self::hash_key(&full_key);

        (prefix, full_key, hash)
    }

    /// Hash an API key for storage.
    pub fn hash_key(key: &str) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(key.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verify a key against a stored hash.
    pub fn verify_key(key: &str, hash: &str) -> bool {
        Self::hash_key(key) == hash
    }

    /// Check if the key has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            expires_at < Utc::now()
        } else {
            false
        }
    }

    /// Check if the key is valid (active and not expired).
    pub fn is_valid(&self) -> bool {
        self.is_active && !self.is_expired()
    }

    /// Get scopes as a vector of strings.
    pub fn scopes_vec(&self) -> Vec<String> {
        if let Some(arr) = self.scopes.as_array() {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        } else {
            vec!["read".to_string()]
        }
    }

    /// Check if the key has a specific scope.
    pub fn has_scope(&self, scope: &str) -> bool {
        if let Some(arr) = self.scopes.as_array() {
            arr.iter().any(|v| v.as_str() == Some(scope))
        } else {
            false
        }
    }

    /// Get a human-readable description of last use.
    pub fn last_used_display(&self) -> String {
        match self.last_used_at {
            Some(dt) => {
                let duration = Utc::now().signed_duration_since(dt);
                if duration.num_days() > 0 {
                    format!("{} days ago", duration.num_days())
                } else if duration.num_hours() > 0 {
                    format!("{} hours ago", duration.num_hours())
                } else if duration.num_minutes() > 0 {
                    format!("{} minutes ago", duration.num_minutes())
                } else {
                    "Just now".to_string()
                }
            }
            None => "Never used".to_string(),
        }
    }

    /// Get expiration status display.
    pub fn expires_display(&self) -> String {
        match self.expires_at {
            Some(dt) if dt < Utc::now() => "Expired".to_string(),
            Some(dt) => {
                let duration = dt.signed_duration_since(Utc::now());
                if duration.num_days() > 30 {
                    format!("Expires in {} months", duration.num_days() / 30)
                } else if duration.num_days() > 0 {
                    format!("Expires in {} days", duration.num_days())
                } else if duration.num_hours() > 0 {
                    format!("Expires in {} hours", duration.num_hours())
                } else {
                    "Expires soon".to_string()
                }
            }
            None => "Never expires".to_string(),
        }
    }
}

/// Request to create a new API key.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub expires_in_days: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_format() {
        let (prefix, full_key, hash) = ApiKey::generate_key();

        assert!(prefix.starts_with("vbn_"));
        assert_eq!(prefix.len(), 8);
        assert!(full_key.starts_with("vbn_"));
        assert!(full_key.len() > 20);
        assert_eq!(hash.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_verify_key() {
        let (_, full_key, hash) = ApiKey::generate_key();
        assert!(ApiKey::verify_key(&full_key, &hash));
        assert!(!ApiKey::verify_key("wrong_key", &hash));
    }

    #[test]
    fn test_hash_key_deterministic() {
        let key = "vbn_test123";
        let hash1 = ApiKey::hash_key(key);
        let hash2 = ApiKey::hash_key(key);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_api_key_scope_roundtrip() {
        for scope in [ApiKeyScope::Read, ApiKeyScope::Write, ApiKeyScope::Admin] {
            let str_val = scope.as_str();
            let parsed = ApiKeyScope::from_str(str_val);
            assert_eq!(Some(scope), parsed);
        }
    }

    #[test]
    fn test_scopes_vec() {
        let key = ApiKey {
            id: 1,
            uuid: Uuid::new_v4(),
            user_id: 1,
            name: "Test".to_string(),
            key_prefix: "vbn_test".to_string(),
            key_hash: "hash".to_string(),
            scopes: serde_json::json!(["read", "write"]),
            last_used_at: None,
            last_used_ip: None,
            expires_at: None,
            is_active: true,
            created_at: Utc::now(),
        };

        let scopes = key.scopes_vec();
        assert_eq!(scopes, vec!["read", "write"]);
    }

    #[test]
    fn test_has_scope() {
        let key = ApiKey {
            id: 1,
            uuid: Uuid::new_v4(),
            user_id: 1,
            name: "Test".to_string(),
            key_prefix: "vbn_test".to_string(),
            key_hash: "hash".to_string(),
            scopes: serde_json::json!(["read", "write"]),
            last_used_at: None,
            last_used_ip: None,
            expires_at: None,
            is_active: true,
            created_at: Utc::now(),
        };

        assert!(key.has_scope("read"));
        assert!(key.has_scope("write"));
        assert!(!key.has_scope("admin"));
    }

    #[test]
    fn test_is_valid() {
        let key = ApiKey {
            id: 1,
            uuid: Uuid::new_v4(),
            user_id: 1,
            name: "Test".to_string(),
            key_prefix: "vbn_test".to_string(),
            key_hash: "hash".to_string(),
            scopes: serde_json::json!(["read"]),
            last_used_at: None,
            last_used_ip: None,
            expires_at: None,
            is_active: true,
            created_at: Utc::now(),
        };

        assert!(key.is_valid());
    }

    #[test]
    fn test_is_valid_inactive() {
        let key = ApiKey {
            id: 1,
            uuid: Uuid::new_v4(),
            user_id: 1,
            name: "Test".to_string(),
            key_prefix: "vbn_test".to_string(),
            key_hash: "hash".to_string(),
            scopes: serde_json::json!(["read"]),
            last_used_at: None,
            last_used_ip: None,
            expires_at: None,
            is_active: false,
            created_at: Utc::now(),
        };

        assert!(!key.is_valid());
    }

    #[test]
    fn test_is_expired() {
        let mut key = ApiKey {
            id: 1,
            uuid: Uuid::new_v4(),
            user_id: 1,
            name: "Test".to_string(),
            key_prefix: "vbn_test".to_string(),
            key_hash: "hash".to_string(),
            scopes: serde_json::json!(["read"]),
            last_used_at: None,
            last_used_ip: None,
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
            is_active: true,
            created_at: Utc::now(),
        };

        assert!(key.is_expired());
        assert!(!key.is_valid());

        key.expires_at = Some(Utc::now() + chrono::Duration::hours(1));
        assert!(!key.is_expired());
    }

    #[test]
    fn test_last_used_display_never() {
        let key = ApiKey {
            id: 1,
            uuid: Uuid::new_v4(),
            user_id: 1,
            name: "Test".to_string(),
            key_prefix: "vbn_test".to_string(),
            key_hash: "hash".to_string(),
            scopes: serde_json::json!(["read"]),
            last_used_at: None,
            last_used_ip: None,
            expires_at: None,
            is_active: true,
            created_at: Utc::now(),
        };

        assert_eq!(key.last_used_display(), "Never used");
    }
}
