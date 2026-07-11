/// VAUBAN Web - Organisational vault secret model.
///
/// A `VaultSecret` is an organisation-owned secret stored encrypted at
/// rest (domain `"secrets"` of vauban-vault). Access is governed by
/// group-to-group `secret_access_rules` evaluated by vauban-access —
/// there is NO owner and NO `read_all`-style bypass.
///
/// SECURITY: this struct deliberately does NOT derive `Serialize`. The
/// `ciphertext` column must never leak into a JSON response; API and web
/// handlers build explicit metadata DTOs instead.
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use uuid::Uuid;

use crate::schema::vault_secrets;

/// Vault secret database model (never serialized as-is).
#[derive(Debug, Clone, Queryable, Selectable, Identifiable)]
#[diesel(table_name = vault_secrets)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct VaultSecret {
    pub id: i32,
    pub uuid: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub ciphertext: String,
    pub version: i32,
    pub is_active: bool,
    pub created_by_id: Option<i32>,
    pub updated_by_id: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// New vault secret for insertion.
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = vault_secrets)]
pub struct NewVaultSecret {
    pub uuid: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub ciphertext: String,
    pub is_active: bool,
    pub created_by_id: Option<i32>,
    pub updated_by_id: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_secret_debug_and_clone() {
        let now = Utc::now();
        let secret = VaultSecret {
            id: 1,
            uuid: Uuid::new_v4(),
            name: "db-password".to_string(),
            description: Some("Prod DB".to_string()),
            ciphertext: "v1:AAAA".to_string(),
            version: 1,
            is_active: true,
            created_by_id: Some(1),
            updated_by_id: None,
            created_at: now,
            updated_at: now,
        };
        let cloned = secret.clone();
        assert_eq!(cloned.name, secret.name);
        assert!(format!("{:?}", secret).contains("db-password"));
    }

    #[test]
    fn test_new_vault_secret_fields() {
        let new = NewVaultSecret {
            uuid: Uuid::new_v4(),
            name: "api-token".to_string(),
            description: None,
            ciphertext: "v1:BBBB".to_string(),
            is_active: true,
            created_by_id: None,
            updated_by_id: None,
        };
        assert!(new.is_active);
        assert!(new.description.is_none());
    }
}
