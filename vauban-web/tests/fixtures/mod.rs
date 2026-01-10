/// VAUBAN Web - Test fixtures.
///
/// Factory functions for creating test data.
use diesel::prelude::*;
use uuid::Uuid;

use vauban_web::models::asset::{Asset, NewAsset};
use vauban_web::models::user::{NewUser, User};
use vauban_web::schema::{assets, users};
use vauban_web::services::auth::AuthService;

/// Test user data.
pub struct TestUser {
    pub user: User,
    pub password: String,
    pub token: String,
}

/// Create a standard test user.
pub fn create_test_user(
    conn: &mut PgConnection,
    auth_service: &AuthService,
    username: &str,
) -> TestUser {
    let password = "TestPassword123!";
    let password_hash = auth_service.hash_password(password).unwrap();
    let user_uuid = Uuid::new_v4();

    let new_user = NewUser {
        uuid: user_uuid,
        username: username.to_string(),
        email: format!("{}@test.vauban.io", username),
        password_hash,
        first_name: Some("Test".to_string()),
        last_name: Some("User".to_string()),
        phone: None,
        is_active: true,
        is_staff: false,
        is_superuser: false,
        is_service_account: false,
        mfa_enabled: false,
        mfa_enforced: false,
        mfa_secret: None,
        preferences: serde_json::json!({}),
        auth_source: "local".to_string(),
        external_id: None,
    };

    let user: User = diesel::insert_into(users::table)
        .values(&new_user)
        .get_result(conn)
        .expect("Failed to create test user");

    let token = auth_service
        .generate_access_token(&user.uuid.to_string(), &user.username, true, false, false)
        .unwrap();

    TestUser {
        user,
        password: password.to_string(),
        token,
    }
}

/// Create an admin test user.
pub fn create_admin_user(
    conn: &mut PgConnection,
    auth_service: &AuthService,
    username: &str,
) -> TestUser {
    let password = "AdminPassword123!";
    let password_hash = auth_service.hash_password(password).unwrap();
    let user_uuid = Uuid::new_v4();

    let new_user = NewUser {
        uuid: user_uuid,
        username: username.to_string(),
        email: format!("{}@test.vauban.io", username),
        password_hash,
        first_name: Some("Admin".to_string()),
        last_name: Some("User".to_string()),
        phone: None,
        is_active: true,
        is_staff: true,
        is_superuser: true,
        is_service_account: false,
        mfa_enabled: false,
        mfa_enforced: false,
        mfa_secret: None,
        preferences: serde_json::json!({}),
        auth_source: "local".to_string(),
        external_id: None,
    };

    let user: User = diesel::insert_into(users::table)
        .values(&new_user)
        .get_result(conn)
        .expect("Failed to create admin user");

    let token = auth_service
        .generate_access_token(&user.uuid.to_string(), &user.username, true, true, true)
        .unwrap();

    TestUser {
        user,
        password: password.to_string(),
        token,
    }
}

/// Create a user with MFA enabled.
pub fn create_mfa_user(
    conn: &mut PgConnection,
    auth_service: &AuthService,
    username: &str,
) -> TestUser {
    let password = "MfaPassword123!";
    let password_hash = auth_service.hash_password(password).unwrap();
    let user_uuid = Uuid::new_v4();
    let (mfa_secret, _) = AuthService::generate_totp_secret(username, "VAUBAN").unwrap();

    let new_user = NewUser {
        uuid: user_uuid,
        username: username.to_string(),
        email: format!("{}@test.vauban.io", username),
        password_hash,
        first_name: Some("MFA".to_string()),
        last_name: Some("User".to_string()),
        phone: None,
        is_active: true,
        is_staff: false,
        is_superuser: false,
        is_service_account: false,
        mfa_enabled: true,
        mfa_enforced: false,
        mfa_secret: Some(mfa_secret),
        preferences: serde_json::json!({}),
        auth_source: "local".to_string(),
        external_id: None,
    };

    let user: User = diesel::insert_into(users::table)
        .values(&new_user)
        .get_result(conn)
        .expect("Failed to create MFA user");

    // Token without MFA verified
    let token = auth_service
        .generate_access_token(&user.uuid.to_string(), &user.username, false, false, false)
        .unwrap();

    TestUser {
        user,
        password: password.to_string(),
        token,
    }
}

/// Test asset data.
pub struct TestAsset {
    pub asset: Asset,
}

/// Create a test SSH asset.
pub fn create_test_ssh_asset(conn: &mut PgConnection, name: &str) -> TestAsset {
    let asset_uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = "192.168.1.100".parse().unwrap();

    let new_asset = NewAsset {
        uuid: asset_uuid,
        name: name.to_string(),
        hostname: format!("{}.test.vauban.io", name.replace("test-", "")),
        ip_address: Some(ip),
        port: 22,
        asset_type: "ssh".to_string(),
        status: "online".to_string(),
        group_id: None,
        description: Some("Test SSH asset".to_string()),
        os_type: Some("Linux".to_string()),
        os_version: Some("Ubuntu 22.04".to_string()),
        connection_config: serde_json::json!({}),
        default_credential_id: None,
        require_mfa: false,
        require_justification: false,
        max_session_duration: 3600,
        created_by_id: None,
    };

    let asset: Asset = diesel::insert_into(assets::table)
        .values(&new_asset)
        .get_result(conn)
        .expect("Failed to create test asset");

    TestAsset { asset }
}

/// Create a test RDP asset.
pub fn create_test_rdp_asset(conn: &mut PgConnection, name: &str) -> TestAsset {
    let asset_uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = "192.168.1.101".parse().unwrap();

    let new_asset = NewAsset {
        uuid: asset_uuid,
        name: name.to_string(),
        hostname: format!("{}.test.vauban.io", name.replace("test-", "")),
        ip_address: Some(ip),
        port: 3389,
        asset_type: "rdp".to_string(),
        status: "online".to_string(),
        group_id: None,
        description: Some("Test RDP asset".to_string()),
        os_type: Some("Windows".to_string()),
        os_version: Some("Server 2022".to_string()),
        connection_config: serde_json::json!({}),
        default_credential_id: None,
        require_mfa: false,
        require_justification: false,
        max_session_duration: 3600,
        created_by_id: None,
    };

    let asset: Asset = diesel::insert_into(assets::table)
        .values(&new_asset)
        .get_result(conn)
        .expect("Failed to create test RDP asset");

    TestAsset { asset }
}

/// Create a test asset group.
pub fn create_test_asset_group(conn: &mut PgConnection, group_name: &str) -> Uuid {
    use vauban_web::schema::asset_groups::dsl;

    let group_uuid = Uuid::new_v4();
    let group_slug = group_name.to_lowercase().replace(" ", "-");

    diesel::insert_into(dsl::asset_groups)
        .values((
            dsl::uuid.eq(group_uuid),
            dsl::name.eq(group_name),
            dsl::slug.eq(&group_slug),
            dsl::color.eq("#10b981"),
            dsl::icon.eq("server"),
        ))
        .execute(conn)
        .expect("Failed to create test asset group");

    group_uuid
}

/// Generate unique test name with timestamp.
pub fn unique_name(prefix: &str) -> String {
    format!(
        "{}_{}",
        prefix,
        Uuid::new_v4().to_string().split('-').next().unwrap()
    )
}

// =============================================================================
// Simplified fixtures for web page tests (return IDs only)
// =============================================================================

/// Create a simple test user and return user_id (no auth service required).
pub fn create_simple_user(conn: &mut PgConnection, username: &str) -> i32 {
    use diesel::sql_query;
    use diesel::sql_types::Int4;
    
    #[derive(QueryableByName)]
    struct UserId {
        #[diesel(sql_type = Int4)]
        id: i32,
    }
    
    let result: UserId = sql_query(format!(
        "INSERT INTO users (uuid, username, email, password_hash, is_active, auth_source, preferences)
         VALUES (uuid_generate_v4(), '{}', '{}@test.vauban.io', 'hash', true, 'local', '{{}}')
         ON CONFLICT (username) DO UPDATE SET updated_at = NOW()
         RETURNING id",
        username, username
    ))
    .get_result(conn)
    .expect("Failed to create test user");
    
    result.id
}

/// Create a test SSH asset and return asset_id.
pub fn create_simple_ssh_asset(conn: &mut PgConnection, name: &str, created_by: i32) -> i32 {
    use diesel::sql_query;
    use diesel::sql_types::Int4;
    
    #[derive(QueryableByName)]
    struct AssetId {
        #[diesel(sql_type = Int4)]
        id: i32,
    }
    
    let result: AssetId = sql_query(format!(
        "INSERT INTO assets (uuid, name, hostname, port, asset_type, status, require_mfa, require_justification, connection_config, created_by_id)
         VALUES (uuid_generate_v4(), '{}', '{}.test.local', 22, 'ssh', 'online', false, false, '{{}}', {})
         ON CONFLICT (hostname, port) DO UPDATE SET updated_at = NOW()
         RETURNING id",
        name, name, created_by
    ))
    .get_result(conn)
    .expect("Failed to create test SSH asset");
    
    result.id
}

/// Create a test session and return session_id.
pub fn create_test_session(
    conn: &mut PgConnection,
    user_id: i32,
    asset_id: i32,
    session_type: &str,
    status: &str,
) -> i32 {
    use diesel::sql_query;
    use diesel::sql_types::Int4;
    
    #[derive(QueryableByName)]
    struct SessionId {
        #[diesel(sql_type = Int4)]
        id: i32,
    }
    
    let connected_at = if status == "active" {
        "NOW()".to_string()
    } else {
        "NOW() - INTERVAL '1 hour'".to_string()
    };
    
    let disconnected_at = if status == "active" {
        "NULL".to_string()
    } else {
        "NOW()".to_string()
    };
    
    let result: SessionId = sql_query(format!(
        "INSERT INTO proxy_sessions (uuid, user_id, asset_id, credential_id, credential_username, session_type, status, client_ip, connected_at, disconnected_at, is_recorded, metadata)
         VALUES (uuid_generate_v4(), {}, {}, 'cred-123', 'testuser', '{}', '{}', '127.0.0.1', {}, {}, false, '{{}}')
         RETURNING id",
        user_id, asset_id, session_type, status, connected_at, disconnected_at
    ))
    .get_result(conn)
    .expect("Failed to create test session");
    
    result.id
}

/// Create a recorded session and return session_id.
pub fn create_recorded_session(conn: &mut PgConnection, user_id: i32, asset_id: i32) -> i32 {
    use diesel::sql_query;
    use diesel::sql_types::Int4;
    
    #[derive(QueryableByName)]
    struct SessionId {
        #[diesel(sql_type = Int4)]
        id: i32,
    }
    
    let result: SessionId = sql_query(format!(
        "INSERT INTO proxy_sessions (uuid, user_id, asset_id, credential_id, credential_username, session_type, status, client_ip, connected_at, disconnected_at, is_recorded, recording_path, metadata)
         VALUES (uuid_generate_v4(), {}, {}, 'cred-123', 'testuser', 'ssh', 'completed', '127.0.0.1', NOW() - INTERVAL '1 hour', NOW(), true, '/recordings/test.cast', '{{}}')
         RETURNING id",
        user_id, asset_id
    ))
    .get_result(conn)
    .expect("Failed to create recorded session");
    
    result.id
}

/// Create an approval request (session with justification) and return session_uuid.
pub fn create_approval_request(conn: &mut PgConnection, user_id: i32, asset_id: i32) -> Uuid {
    use diesel::sql_query;
    
    #[derive(QueryableByName)]
    struct SessionUuid {
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        uuid: Uuid,
    }
    
    let result: SessionUuid = sql_query(format!(
        "INSERT INTO proxy_sessions (uuid, user_id, asset_id, credential_id, credential_username, session_type, status, client_ip, is_recorded, justification, metadata)
         VALUES (uuid_generate_v4(), {}, {}, 'cred-123', 'testuser', 'ssh', 'pending', '127.0.0.1', true, 'Need access for maintenance', '{{\"approval_required\": true}}')
         RETURNING uuid",
        user_id, asset_id
    ))
    .get_result(conn)
    .expect("Failed to create approval request");
    
    result.uuid
}

/// Create a test vauban group (user group) and return group_uuid.
pub fn create_test_vauban_group(conn: &mut PgConnection, name: &str) -> Uuid {
    use diesel::sql_query;
    
    #[derive(QueryableByName)]
    struct GroupUuid {
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        uuid: Uuid,
    }
    
    let result: GroupUuid = sql_query(format!(
        "INSERT INTO vauban_groups (uuid, name, description, source)
         VALUES (uuid_generate_v4(), '{}', 'Test group', 'local')
         ON CONFLICT (name) DO UPDATE SET updated_at = NOW()
         RETURNING uuid",
        name
    ))
    .get_result(conn)
    .expect("Failed to create vauban group");
    
    result.uuid
}

/// Create a test asset in a specific group and return asset_id.
pub fn create_test_asset_in_group(
    conn: &mut PgConnection,
    name: &str,
    created_by: i32,
    group_uuid: &Uuid,
) -> i32 {
    use diesel::sql_query;
    use diesel::sql_types::Int4;
    
    #[derive(QueryableByName)]
    struct AssetId {
        #[diesel(sql_type = Int4)]
        id: i32,
    }
    
    // First get the group_id from uuid
    #[derive(QueryableByName)]
    struct GroupId {
        #[diesel(sql_type = Int4)]
        id: i32,
    }
    
    let group: GroupId = sql_query(format!(
        "SELECT id FROM asset_groups WHERE uuid = '{}'",
        group_uuid
    ))
    .get_result(conn)
    .expect("Failed to find asset group");
    
    let result: AssetId = sql_query(format!(
        "INSERT INTO assets (uuid, name, hostname, port, asset_type, status, group_id, require_mfa, require_justification, connection_config, created_by_id)
         VALUES (uuid_generate_v4(), '{}', '{}.test.local', 22, 'ssh', 'online', {}, false, false, '{{}}', {})
         ON CONFLICT (hostname, port) DO UPDATE SET updated_at = NOW()
         RETURNING id",
        name, name, group.id, created_by
    ))
    .get_result(conn)
    .expect("Failed to create test asset in group");
    
    result.id
}

// =============================================================================
// Auth Sessions and API Keys fixtures
// =============================================================================

/// Create a test auth session and return session_uuid.
pub fn create_test_auth_session(
    conn: &mut PgConnection,
    user_id: i32,
    is_current: bool,
) -> Uuid {
    use chrono::{Duration, Utc};
    use vauban_web::models::NewAuthSession;
    use vauban_web::schema::auth_sessions;

    let session_uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = "127.0.0.1".parse().unwrap();
    let token_hash = format!("hash_{}_{}", user_id, if is_current { "current" } else { "other" });

    let new_session = NewAuthSession {
        uuid: session_uuid,
        user_id,
        token_hash,
        ip_address: ip,
        user_agent: Some("Mozilla/5.0 Test".to_string()),
        device_info: Some("Test Browser".to_string()),
        expires_at: Utc::now() + Duration::hours(24),
        is_current,
    };

    diesel::insert_into(auth_sessions::table)
        .values(&new_session)
        .execute(conn)
        .expect("Failed to create auth session");

    session_uuid
}

/// Create a test API key and return key_uuid.
pub fn create_test_api_key(
    conn: &mut PgConnection,
    user_id: i32,
    name: &str,
    is_active: bool,
) -> Uuid {
    use vauban_web::schema::api_keys;

    let key_uuid = Uuid::new_v4();

    diesel::insert_into(api_keys::table)
        .values((
            api_keys::uuid.eq(key_uuid),
            api_keys::user_id.eq(user_id),
            api_keys::name.eq(name),
            api_keys::key_prefix.eq("vbn_test"),
            api_keys::key_hash.eq(format!("hash_{}", name)),
            api_keys::scopes.eq(serde_json::json!(["read"])),
            api_keys::is_active.eq(is_active),
        ))
        .execute(conn)
        .expect("Failed to create API key");

    key_uuid
}

/// Create an expired test API key and return key_uuid.
pub fn create_expired_api_key(
    conn: &mut PgConnection,
    user_id: i32,
    name: &str,
) -> Uuid {
    use chrono::{Duration, Utc};
    use vauban_web::schema::api_keys;

    let key_uuid = Uuid::new_v4();

    diesel::insert_into(api_keys::table)
        .values((
            api_keys::uuid.eq(key_uuid),
            api_keys::user_id.eq(user_id),
            api_keys::name.eq(name),
            api_keys::key_prefix.eq("vbn_exp"),
            api_keys::key_hash.eq(format!("hash_exp_{}", name)),
            api_keys::scopes.eq(serde_json::json!(["read"])),
            api_keys::is_active.eq(true),
            api_keys::expires_at.eq(Utc::now() - Duration::days(1)),
        ))
        .execute(conn)
        .expect("Failed to create expired API key");

    key_uuid
}
