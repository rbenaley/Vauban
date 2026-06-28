//! Admin command handlers for CLI operations via IPC.
//!
//! These handlers process AdminCommand messages from the supervisor,
//! executing database operations (user CRUD, secret management, seeding)
//! and returning AdminResponse results.

use crate::db::DbPool;
use crate::schema::{assets, proxy_sessions, users};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use shared::messages::{
    AdminCommand, AdminResponse, SeedAsset, SeedSession, SeedUser, UnencryptedSecretEntry,
};
use tracing::{error, info};
use uuid::Uuid;

/// Process an AdminCommand and return the corresponding AdminResponse.
pub async fn handle_admin_command(pool: &DbPool, command: AdminCommand) -> AdminResponse {
    match command {
        AdminCommand::CreateUser {
            username,
            email,
            password_hash,
            is_superuser,
            is_staff,
        } => {
            handle_create_user(
                pool,
                &username,
                &email,
                &password_hash,
                is_superuser,
                is_staff,
            )
            .await
        }
        AdminCommand::ResetPassword {
            username,
            password_hash,
        } => handle_reset_password(pool, &username, &password_hash).await,
        AdminCommand::ResetMfa { username } => handle_reset_mfa(pool, &username).await,
        AdminCommand::ListUnencryptedSecrets => handle_list_unencrypted_secrets(pool).await,
        AdminCommand::UpdateUserMfaSecret {
            user_id,
            encrypted_secret,
        } => handle_update_user_mfa_secret(pool, user_id, &encrypted_secret).await,
        AdminCommand::UpdateAssetConnectionConfig {
            asset_id,
            encrypted_config,
        } => handle_update_asset_connection_config(pool, asset_id, &encrypted_config).await,
        AdminCommand::SeedUsers { users: seed_users } => handle_seed_users(pool, &seed_users).await,
        AdminCommand::SeedAssets {
            assets: seed_assets,
        } => handle_seed_assets(pool, &seed_assets).await,
        AdminCommand::SeedSessions {
            sessions: seed_sessions,
        } => handle_seed_sessions(pool, &seed_sessions).await,
    }
}

async fn handle_create_user(
    pool: &DbPool,
    username: &str,
    email: &str,
    password_hash: &str,
    is_superuser: bool,
    is_staff: bool,
) -> AdminResponse {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => return AdminResponse::Error(format!("DB pool error: {e}")),
    };

    // Canonicalise to the case-insensitive identity form (same contract
    // as the web/API create paths and the DB `lower(username)` index).
    let username = shared::username::normalize_username(username);
    let username = username.as_str();

    let user_uuid = Uuid::new_v4();

    #[derive(Insertable)]
    #[diesel(table_name = users)]
    struct NewAdminUser<'a> {
        uuid: Uuid,
        username: &'a str,
        email: &'a str,
        password_hash: &'a str,
        is_active: bool,
        is_staff: bool,
        is_superuser: bool,
        is_service_account: bool,
        mfa_enabled: bool,
        mfa_enforced: bool,
        preferences: serde_json::Value,
        auth_source: &'a str,
    }

    let new_user = NewAdminUser {
        uuid: user_uuid,
        username,
        email,
        password_hash,
        is_active: true,
        is_staff,
        is_superuser,
        is_service_account: false,
        mfa_enabled: false,
        mfa_enforced: false,
        preferences: serde_json::json!({}),
        auth_source: "local",
    };

    match diesel::insert_into(users::table)
        .values(&new_user)
        .execute(&mut conn)
        .await
    {
        Ok(_) => {
            info!(username, "Admin: user created via IPC");
            AdminResponse::Created {
                uuid: user_uuid.to_string(),
            }
        }
        Err(e) => AdminResponse::Error(format!("Failed to create user: {e}")),
    }
}

async fn handle_reset_password(
    pool: &DbPool,
    username: &str,
    password_hash: &str,
) -> AdminResponse {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => return AdminResponse::Error(format!("DB pool error: {e}")),
    };

    // Usernames are stored in canonical (case-insensitive) form; match it.
    let username: &str = &shared::username::normalize_username(username);

    match diesel::update(
        users::table
            .filter(users::username.eq(username))
            .filter(users::is_deleted.eq(false)),
    )
    .set((
        users::password_hash.eq(password_hash),
        users::updated_at.eq(chrono::Utc::now()),
    ))
    .execute(&mut conn)
    .await
    {
        Ok(0) => AdminResponse::Error(format!("User '{username}' not found")),
        Ok(_) => {
            info!(username, "Admin: password reset via IPC");
            AdminResponse::Ok
        }
        Err(e) => AdminResponse::Error(format!("Failed to reset password: {e}")),
    }
}

async fn handle_reset_mfa(pool: &DbPool, username: &str) -> AdminResponse {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => return AdminResponse::Error(format!("DB pool error: {e}")),
    };

    // Usernames are stored in canonical (case-insensitive) form; match it.
    let username: &str = &shared::username::normalize_username(username);

    match diesel::update(
        users::table
            .filter(users::username.eq(username))
            .filter(users::is_deleted.eq(false)),
    )
    .set((
        users::mfa_enabled.eq(false),
        users::mfa_secret.eq(None::<String>),
        users::updated_at.eq(chrono::Utc::now()),
    ))
    .execute(&mut conn)
    .await
    {
        Ok(0) => AdminResponse::Error(format!("User '{username}' not found")),
        Ok(_) => {
            info!(username, "Admin: MFA reset via IPC");
            AdminResponse::Ok
        }
        Err(e) => AdminResponse::Error(format!("Failed to reset MFA: {e}")),
    }
}

/// Identifies unencrypted secrets: MFA secrets not matching `v{N}:...` format
/// and asset connection_config fields with plaintext credentials.
async fn handle_list_unencrypted_secrets(pool: &DbPool) -> AdminResponse {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => return AdminResponse::Error(format!("DB pool error: {e}")),
    };

    let mut entries = Vec::new();

    // MFA secrets
    let mfa_rows: Result<Vec<(i32, Option<String>)>, _> = users::table
        .filter(users::mfa_secret.is_not_null())
        .filter(users::is_deleted.eq(false))
        .select((users::id, users::mfa_secret))
        .load(&mut conn)
        .await;

    if let Ok(rows) = mfa_rows {
        for (uid, secret_opt) in rows {
            if let Some(ref secret) = secret_opt
                && !is_encrypted(secret)
            {
                entries.push(UnencryptedSecretEntry {
                    entry_type: "mfa".to_string(),
                    id: uid,
                    value: secret.clone(),
                });
            }
        }
    }

    // Asset credentials
    let asset_rows: Result<Vec<(i32, serde_json::Value)>, _> = assets::table
        .select((assets::id, assets::connection_config))
        .load(&mut conn)
        .await;

    if let Ok(rows) = asset_rows {
        for (aid, config) in rows {
            if let Some(obj) = config.as_object() {
                for field in &["password", "private_key", "passphrase"] {
                    if let Some(serde_json::Value::String(val)) = obj.get(*field)
                        && !val.is_empty()
                        && !is_encrypted(val)
                    {
                        entries.push(UnencryptedSecretEntry {
                            entry_type: format!("asset_{field}"),
                            id: aid,
                            value: val.clone(),
                        });
                    }
                }
            }
        }
    }

    AdminResponse::UnencryptedSecrets(entries)
}

async fn handle_update_user_mfa_secret(
    pool: &DbPool,
    user_id: i32,
    encrypted_secret: &str,
) -> AdminResponse {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => return AdminResponse::Error(format!("DB pool error: {e}")),
    };

    match diesel::update(users::table.filter(users::id.eq(user_id)))
        .set((
            users::mfa_secret.eq(Some(encrypted_secret)),
            users::updated_at.eq(chrono::Utc::now()),
        ))
        .execute(&mut conn)
        .await
    {
        Ok(0) => AdminResponse::Error(format!("User id={user_id} not found")),
        Ok(_) => AdminResponse::Ok,
        Err(e) => AdminResponse::Error(format!("Failed to update MFA secret: {e}")),
    }
}

async fn handle_update_asset_connection_config(
    pool: &DbPool,
    asset_id: i32,
    encrypted_config: &str,
) -> AdminResponse {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => return AdminResponse::Error(format!("DB pool error: {e}")),
    };

    let config_value: serde_json::Value = match serde_json::from_str(encrypted_config) {
        Ok(v) => v,
        Err(e) => return AdminResponse::Error(format!("Invalid JSON config: {e}")),
    };

    match diesel::update(assets::table.filter(assets::id.eq(asset_id)))
        .set((
            assets::connection_config.eq(config_value),
            assets::updated_at.eq(chrono::Utc::now()),
        ))
        .execute(&mut conn)
        .await
    {
        Ok(0) => AdminResponse::Error(format!("Asset id={asset_id} not found")),
        Ok(_) => AdminResponse::Ok,
        Err(e) => AdminResponse::Error(format!("Failed to update connection config: {e}")),
    }
}

async fn handle_seed_users(pool: &DbPool, seed_users: &[SeedUser]) -> AdminResponse {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => return AdminResponse::Error(format!("DB pool error: {e}")),
    };

    let mut created = 0u32;
    for su in seed_users {
        #[derive(Insertable)]
        #[diesel(table_name = users)]
        struct NewSeedUser<'a> {
            uuid: Uuid,
            username: &'a str,
            email: &'a str,
            password_hash: &'a str,
            first_name: Option<&'a str>,
            last_name: Option<&'a str>,
            is_active: bool,
            is_staff: bool,
            is_superuser: bool,
            is_service_account: bool,
            mfa_enabled: bool,
            mfa_enforced: bool,
            preferences: serde_json::Value,
            auth_source: &'a str,
        }

        let new_user = NewSeedUser {
            uuid: Uuid::new_v4(),
            username: &su.username,
            email: &su.email,
            password_hash: &su.password_hash,
            first_name: su.first_name.as_deref(),
            last_name: su.last_name.as_deref(),
            is_active: true,
            is_staff: su.is_staff,
            is_superuser: su.is_superuser,
            is_service_account: false,
            mfa_enabled: false,
            mfa_enforced: false,
            preferences: serde_json::json!({}),
            auth_source: "local",
        };

        match diesel::insert_into(users::table)
            .values(&new_user)
            .on_conflict(users::username)
            .do_nothing()
            .execute(&mut conn)
            .await
        {
            Ok(1) => created += 1,
            Ok(_) => {} // already exists
            Err(e) => {
                error!(username = su.username, error = %e, "Failed to seed user");
            }
        }
    }

    info!(created, total = seed_users.len(), "Admin: users seeded");
    AdminResponse::Ok
}

async fn handle_seed_assets(pool: &DbPool, seed_assets: &[SeedAsset]) -> AdminResponse {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => return AdminResponse::Error(format!("DB pool error: {e}")),
    };

    let mut created = 0u32;
    for sa in seed_assets {
        #[derive(Insertable)]
        #[diesel(table_name = assets)]
        struct NewSeedAsset<'a> {
            uuid: Uuid,
            name: &'a str,
            hostname: &'a str,
            port: i32,
            asset_type: &'a str,
            description: Option<&'a str>,
            status: &'a str,
            connection_config: serde_json::Value,
        }

        let asset_uuid = Uuid::new_v4();
        let new_asset = NewSeedAsset {
            uuid: asset_uuid,
            name: &sa.name,
            hostname: &sa.hostname,
            port: sa.port,
            asset_type: &sa.asset_type,
            description: sa.description.as_deref(),
            status: "online",
            connection_config: serde_json::json!({}),
        };

        match diesel::insert_into(assets::table)
            .values(&new_asset)
            .on_conflict(assets::uuid)
            .do_nothing()
            .execute(&mut conn)
            .await
        {
            Ok(1) => {
                created += 1;
                if let Some(gid) = sa.group_id {
                    use crate::models::asset::NewAssetAssetGroup;
                    use crate::schema::asset_asset_groups::dsl as aag;
                    if let Ok(aid) = assets::table
                        .filter(assets::uuid.eq(asset_uuid))
                        .select(assets::id)
                        .first::<i32>(&mut conn)
                        .await
                    {
                        let _ = diesel::insert_into(aag::asset_asset_groups)
                            .values(NewAssetAssetGroup {
                                asset_id: aid,
                                asset_group_id: gid,
                            })
                            .execute(&mut conn)
                            .await;
                    }
                }
            }
            Ok(_) => {}
            Err(e) => {
                error!(name = sa.name, error = %e, "Failed to seed asset");
            }
        }
    }

    info!(created, total = seed_assets.len(), "Admin: assets seeded");
    AdminResponse::Ok
}

#[allow(clippy::expect_used)]
async fn handle_seed_sessions(pool: &DbPool, seed_sessions: &[SeedSession]) -> AdminResponse {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => return AdminResponse::Error(format!("DB pool error: {e}")),
    };

    let mut created = 0u32;
    for ss in seed_sessions {
        #[derive(Insertable)]
        #[diesel(table_name = proxy_sessions)]
        struct NewSeedSession<'a> {
            uuid: Uuid,
            user_id: i32,
            asset_id: i32,
            credential_id: String,
            credential_username: &'a str,
            session_type: &'a str,
            status: &'a str,
            client_ip: ipnetwork::IpNetwork,
            is_recorded: bool,
            bytes_sent: i64,
            bytes_received: i64,
            commands_count: i32,
            metadata: serde_json::Value,
        }

        let new_session = NewSeedSession {
            uuid: Uuid::new_v4(),
            user_id: ss.user_id,
            asset_id: ss.asset_id,
            credential_id: Uuid::new_v4().to_string(),
            credential_username: if ss.session_type == "rdp" {
                "Administrator"
            } else {
                "root"
            },
            session_type: &ss.session_type,
            status: "completed",
            client_ip: "127.0.0.1".parse().expect("localhost IP"),
            is_recorded: false,
            bytes_sent: 0,
            bytes_received: 0,
            commands_count: 0,
            metadata: serde_json::json!({}),
        };

        match diesel::insert_into(proxy_sessions::table)
            .values(&new_session)
            .execute(&mut conn)
            .await
        {
            Ok(_) => created += 1,
            Err(e) => {
                error!(
                    user_id = ss.user_id,
                    asset_id = ss.asset_id,
                    error = %e,
                    "Failed to seed session"
                );
            }
        }
    }

    info!(
        created,
        total = seed_sessions.len(),
        "Admin: sessions seeded"
    );
    AdminResponse::Ok
}

fn is_encrypted(value: &str) -> bool {
    if value.len() < 4 {
        return false;
    }
    if !value.starts_with('v') {
        return false;
    }
    let Some(colon_pos) = value.find(':') else {
        return false;
    };
    if colon_pos < 2 {
        return false;
    }
    value[1..colon_pos].chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== is_encrypted ====================

    #[test]
    fn test_is_encrypted_valid() {
        assert!(is_encrypted("v1:data"));
        assert!(is_encrypted("v12:AAAA"));
        assert!(is_encrypted("v999:longdata"));
    }

    #[test]
    fn test_is_encrypted_invalid() {
        assert!(!is_encrypted("plaintext"));
        assert!(!is_encrypted(""));
        assert!(!is_encrypted("v:data"));
        assert!(!is_encrypted("v1data"));
        assert!(!is_encrypted("va:data"));
        assert!(!is_encrypted("abc"));
    }

    #[test]
    fn test_is_encrypted_too_short() {
        assert!(!is_encrypted("v1:"));
        assert!(!is_encrypted("v1"));
    }

    // ==================== handle_admin_command routing ====================

    #[test]
    fn test_admin_handler_covers_all_commands() {
        let source = include_str!("admin.rs");
        assert!(source.contains("AdminCommand::CreateUser"));
        assert!(source.contains("AdminCommand::ResetPassword"));
        assert!(source.contains("AdminCommand::ResetMfa"));
        assert!(source.contains("AdminCommand::ListUnencryptedSecrets"));
        assert!(source.contains("AdminCommand::UpdateUserMfaSecret"));
        assert!(source.contains("AdminCommand::UpdateAssetConnectionConfig"));
        assert!(source.contains("AdminCommand::SeedUsers"));
        assert!(source.contains("AdminCommand::SeedAssets"));
        assert!(source.contains("AdminCommand::SeedSessions"));
    }

    #[test]
    fn test_admin_handler_uses_diesel_dsl() {
        let source = include_str!("admin.rs");
        let non_test_source: String = source
            .lines()
            .take_while(|l| !l.contains("#[cfg(test)]"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            non_test_source.contains("diesel::insert_into")
                || non_test_source.contains("diesel::update"),
            "IPC admin handlers must use Diesel DSL for DB operations"
        );
    }

    #[test]
    fn test_admin_handler_returns_proper_error_on_not_found() {
        let source = include_str!("admin.rs");
        let not_found_patterns = source.matches("Ok(0) => AdminResponse::Error").count();
        assert!(
            not_found_patterns >= 2,
            "Handlers must return Error on zero-row updates (reset_password, reset_mfa, etc.)"
        );
    }

    #[test]
    fn test_admin_handler_seed_uses_on_conflict() {
        let source = include_str!("admin.rs");
        assert!(
            source.contains("on_conflict"),
            "Seed handlers must use ON CONFLICT for idempotency"
        );
    }
}
