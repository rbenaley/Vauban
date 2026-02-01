/// VAUBAN Web - Test fixtures.
///
/// Factory functions for creating test data.
use chrono::{Duration, Utc};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

use vauban_web::models::asset::{Asset, NewAsset};
use vauban_web::models::auth_session::NewAuthSession;
use vauban_web::models::user::{NewUser, User};
use vauban_web::schema::{assets, auth_sessions, users};
use vauban_web::services::auth::AuthService;

use crate::common::{unwrap_ok, unwrap_some};

/// Helper to create an auth session for a token in the database.
async fn create_session_for_token(conn: &mut AsyncPgConnection, user_id: i32, token: &str) {
    // Hash the token using SHA3-256
    let mut hasher = Sha3_256::new();
    hasher.update(token.as_bytes());
    let token_hash = format!("{:x}", hasher.finalize());

    let ip: ipnetwork::IpNetwork = unwrap_ok!("127.0.0.1".parse());
    let new_session = NewAuthSession {
        uuid: Uuid::new_v4(),
        user_id,
        token_hash,
        ip_address: ip,
        user_agent: Some("Test Client".to_string()),
        device_info: Some("Test".to_string()),
        expires_at: Utc::now() + Duration::hours(24),
        is_current: true,
    };

    diesel::insert_into(auth_sessions::table)
        .values(&new_session)
        .execute(conn)
        .await
        .ok();
}

/// Test user data.
pub struct TestUser {
    pub user: User,
    pub password: String,
    pub token: String,
}

/// Create a standard test user.
pub async fn create_test_user(
    conn: &mut AsyncPgConnection,
    auth_service: &AuthService,
    username: &str,
) -> TestUser {
    let password = "TestPassword123!";
    let password_hash = unwrap_ok!(auth_service.hash_password(password));
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

    let user: User = unwrap_ok!(
        diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(conn)
            .await
    );

    let token = unwrap_ok!(auth_service.generate_access_token(
        &user.uuid.to_string(),
        &user.username,
        true,
        false,
        false
    ));

    // Create session in database for middleware validation
    create_session_for_token(conn, user.id, &token).await;

    TestUser {
        user,
        password: password.to_string(),
        token,
    }
}

/// Create an admin test user.
pub async fn create_admin_user(
    conn: &mut AsyncPgConnection,
    auth_service: &AuthService,
    username: &str,
) -> TestUser {
    let password = "AdminPassword123!";
    let password_hash = unwrap_ok!(auth_service.hash_password(password));
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

    let user: User = unwrap_ok!(
        diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(conn)
            .await
    );

    let token = unwrap_ok!(auth_service.generate_access_token(
        &user.uuid.to_string(),
        &user.username,
        true,
        true,
        true
    ));

    // Create session in database for middleware validation
    create_session_for_token(conn, user.id, &token).await;

    TestUser {
        user,
        password: password.to_string(),
        token,
    }
}

/// Create a user with MFA enabled.
pub async fn create_mfa_user(
    conn: &mut AsyncPgConnection,
    auth_service: &AuthService,
    username: &str,
) -> TestUser {
    let password = "MfaPassword123!";
    let password_hash = unwrap_ok!(auth_service.hash_password(password));
    let user_uuid = Uuid::new_v4();
    let (mfa_secret, _) = unwrap_ok!(AuthService::generate_totp_secret(username, "VAUBAN"));

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

    let user: User = unwrap_ok!(
        diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(conn)
            .await
    );

    // Token without MFA verified
    let token = unwrap_ok!(auth_service.generate_access_token(
        &user.uuid.to_string(),
        &user.username,
        false,
        false,
        false
    ));

    // Create session in database for middleware validation
    create_session_for_token(conn, user.id, &token).await;

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
pub async fn create_test_ssh_asset(conn: &mut AsyncPgConnection, name: &str) -> TestAsset {
    let asset_uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = unwrap_ok!("192.168.1.100".parse());

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

    let asset: Asset = unwrap_ok!(
        diesel::insert_into(assets::table)
            .values(&new_asset)
            .get_result(conn)
            .await
    );

    TestAsset { asset }
}

/// Create a test RDP asset.
pub async fn create_test_rdp_asset(conn: &mut AsyncPgConnection, name: &str) -> TestAsset {
    let asset_uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = unwrap_ok!("192.168.1.101".parse());

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

    let asset: Asset = unwrap_ok!(
        diesel::insert_into(assets::table)
            .values(&new_asset)
            .get_result(conn)
            .await
    );

    TestAsset { asset }
}

/// Create a test asset group.
pub async fn create_test_asset_group(conn: &mut AsyncPgConnection, group_name: &str) -> Uuid {
    use vauban_web::schema::asset_groups::dsl;

    let group_uuid = Uuid::new_v4();
    let group_slug = group_name.to_lowercase().replace(" ", "-");

    unwrap_ok!(
        diesel::insert_into(dsl::asset_groups)
            .values((
                dsl::uuid.eq(group_uuid),
                dsl::name.eq(group_name),
                dsl::slug.eq(&group_slug),
                dsl::color.eq("#10b981"),
                dsl::icon.eq("server"),
            ))
            .execute(conn)
            .await
    );

    group_uuid
}

/// Generate unique test name with timestamp.
pub fn unique_name(prefix: &str) -> String {
    format!(
        "{}_{}",
        prefix,
        unwrap_some!(Uuid::new_v4().to_string().split('-').next())
    )
}

// =============================================================================
// Simplified fixtures for web page tests (return IDs only)
// =============================================================================

/// Create a simple test user and return user_id (no auth service required).
/// Uses a unique username with UUID suffix to avoid conflicts.
pub async fn create_simple_user(conn: &mut AsyncPgConnection, username: &str) -> i32 {
    let user_uuid = Uuid::new_v4();
    // Create a truly unique username using a UUID suffix
    let unique_username = format!("{}_{}", username, &user_uuid.to_string()[..8]);

    let new_user = NewUser {
        uuid: user_uuid,
        username: unique_username.clone(),
        email: format!("{}@test.vauban.io", unique_username),
        password_hash: "hash".to_string(),
        first_name: None,
        last_name: None,
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

    let user: User = unwrap_ok!(
        diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(conn)
            .await
    );

    user.id
}

/// Create a simple admin user and return user_id (no auth service required).
/// Uses a unique username with UUID suffix to avoid conflicts.
pub async fn create_simple_admin_user(conn: &mut AsyncPgConnection, username: &str) -> i32 {
    let user_uuid = Uuid::new_v4();
    // Create a truly unique username using a UUID suffix
    let unique_username = format!("{}_{}", username, &user_uuid.to_string()[..8]);

    let new_user = NewUser {
        uuid: user_uuid,
        username: unique_username.clone(),
        email: format!("{}@test.vauban.io", unique_username),
        password_hash: "hash".to_string(),
        first_name: None,
        last_name: None,
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

    let user: User = unwrap_ok!(
        diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(conn)
            .await
    );

    user.id
}

/// Create a test SSH asset and return asset_id.
/// Uses a unique hostname (name + UUID suffix) to avoid conflicts.
pub async fn create_simple_ssh_asset(
    conn: &mut AsyncPgConnection,
    name: &str,
    created_by: i32,
) -> i32 {
    let asset_uuid = Uuid::new_v4();
    // Create a truly unique hostname using a UUID suffix
    let unique_hostname = format!("{}-{}.test.local", name, &asset_uuid.to_string()[..8]);

    let new_asset = NewAsset {
        uuid: asset_uuid,
        name: name.to_string(),
        hostname: unique_hostname,
        ip_address: None,
        port: 22,
        asset_type: "ssh".to_string(),
        status: "online".to_string(),
        group_id: None,
        description: None,
        os_type: None,
        os_version: None,
        connection_config: serde_json::json!({}),
        default_credential_id: None,
        require_mfa: false,
        require_justification: false,
        max_session_duration: 3600,
        created_by_id: Some(created_by),
    };

    let asset: Asset = unwrap_ok!(
        diesel::insert_into(assets::table)
            .values(&new_asset)
            .get_result(conn)
            .await
    );

    asset.id
}

/// Get the UUID of an asset by its ID.
pub async fn get_asset_uuid(conn: &mut AsyncPgConnection, asset_id: i32) -> Uuid {
    unwrap_ok!(
        assets::table
            .filter(assets::id.eq(asset_id))
            .select(assets::uuid)
            .first(conn)
            .await
    )
}

/// Create a test session and return session_id.
pub async fn create_test_session(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
    session_type: &str,
    status: &str,
) -> i32 {
    use vauban_web::schema::proxy_sessions;

    let session_uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = unwrap_ok!("127.0.0.1".parse());

    let (connected_at, disconnected_at) = if status == "active" {
        (Some(Utc::now()), None)
    } else {
        (Some(Utc::now() - Duration::hours(1)), Some(Utc::now()))
    };

    let session_id: i32 = unwrap_ok!(
        diesel::insert_into(proxy_sessions::table)
            .values((
                proxy_sessions::uuid.eq(session_uuid),
                proxy_sessions::user_id.eq(user_id),
                proxy_sessions::asset_id.eq(asset_id),
                proxy_sessions::credential_id.eq("cred-123"),
                proxy_sessions::credential_username.eq("testuser"),
                proxy_sessions::session_type.eq(session_type),
                proxy_sessions::status.eq(status),
                proxy_sessions::client_ip.eq(ip),
                proxy_sessions::connected_at.eq(connected_at),
                proxy_sessions::disconnected_at.eq(disconnected_at),
                proxy_sessions::is_recorded.eq(false),
                proxy_sessions::metadata.eq(serde_json::json!({})),
            ))
            .returning(proxy_sessions::id)
            .get_result(conn)
            .await
    );

    session_id
}

/// Create a recorded session and return session_id.
pub async fn create_recorded_session(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
) -> i32 {
    create_recorded_session_with_type(conn, user_id, asset_id, "ssh").await
}

/// Create a recorded session with a specific session type and return session_id.
pub async fn create_recorded_session_with_type(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
    session_type: &str,
) -> i32 {
    use vauban_web::schema::proxy_sessions;

    let session_uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = unwrap_ok!("127.0.0.1".parse());

    let recording_path = match session_type {
        "ssh" => "/recordings/test.cast",
        "rdp" => "/recordings/test.guac",
        "vnc" => "/recordings/test.guac",
        _ => "/recordings/test.cast",
    };

    let session_id: i32 = unwrap_ok!(
        diesel::insert_into(proxy_sessions::table)
            .values((
                proxy_sessions::uuid.eq(session_uuid),
                proxy_sessions::user_id.eq(user_id),
                proxy_sessions::asset_id.eq(asset_id),
                proxy_sessions::credential_id.eq("cred-123"),
                proxy_sessions::credential_username.eq("testuser"),
                proxy_sessions::session_type.eq(session_type),
                proxy_sessions::status.eq("completed"),
                proxy_sessions::client_ip.eq(ip),
                proxy_sessions::connected_at.eq(Utc::now() - Duration::hours(1)),
                proxy_sessions::disconnected_at.eq(Utc::now()),
                proxy_sessions::is_recorded.eq(true),
                proxy_sessions::recording_path.eq(recording_path),
                proxy_sessions::metadata.eq(serde_json::json!({})),
            ))
            .returning(proxy_sessions::id)
            .get_result(conn)
            .await
    );

    session_id
}

/// Create an approval request (session with justification) and return session_uuid.
pub async fn create_approval_request(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
) -> Uuid {
    use vauban_web::schema::proxy_sessions;

    let session_uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = unwrap_ok!("127.0.0.1".parse());

    unwrap_ok!(
        diesel::insert_into(proxy_sessions::table)
            .values((
                proxy_sessions::uuid.eq(session_uuid),
                proxy_sessions::user_id.eq(user_id),
                proxy_sessions::asset_id.eq(asset_id),
                proxy_sessions::credential_id.eq("cred-123"),
                proxy_sessions::credential_username.eq("testuser"),
                proxy_sessions::session_type.eq("ssh"),
                proxy_sessions::status.eq("pending"),
                proxy_sessions::client_ip.eq(ip),
                proxy_sessions::is_recorded.eq(true),
                proxy_sessions::justification.eq("Need access for maintenance"),
                proxy_sessions::metadata.eq(serde_json::json!({"approval_required": true})),
            ))
            .execute(conn)
            .await
    );

    session_uuid
}

/// Create a test vauban group (user group) and return group_uuid.
/// Uses a unique name with UUID suffix to avoid conflicts.
pub async fn create_test_vauban_group(conn: &mut AsyncPgConnection, name: &str) -> Uuid {
    use vauban_web::schema::vauban_groups;

    let group_uuid = Uuid::new_v4();
    // Create a truly unique name using a UUID suffix
    let unique_name = format!("{}_{}", name, &group_uuid.to_string()[..8]);

    unwrap_ok!(
        diesel::insert_into(vauban_groups::table)
            .values((
                vauban_groups::uuid.eq(group_uuid),
                vauban_groups::name.eq(&unique_name),
                vauban_groups::description.eq(Some("Test group")),
                vauban_groups::source.eq("local"),
            ))
            .execute(conn)
            .await
    );

    group_uuid
}

/// Get the internal ID of a vauban group from its UUID.
pub async fn get_vauban_group_id(conn: &mut AsyncPgConnection, group_uuid: &Uuid) -> i32 {
    use vauban_web::schema::vauban_groups;

    unwrap_ok!(
        vauban_groups::table
            .filter(vauban_groups::uuid.eq(group_uuid))
            .select(vauban_groups::id)
            .first(conn)
            .await
    )
}

/// Add a user to a vauban group.
pub async fn add_user_to_vauban_group(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    group_uuid: &Uuid,
) {
    use vauban_web::schema::user_groups;
    use vauban_web::schema::vauban_groups;

    let group_id: i32 = unwrap_ok!(
        vauban_groups::table
            .filter(vauban_groups::uuid.eq(group_uuid))
            .select(vauban_groups::id)
            .first(conn)
            .await
    );

    unwrap_ok!(
        diesel::insert_into(user_groups::table)
            .values((
                user_groups::user_id.eq(user_id),
                user_groups::group_id.eq(group_id),
            ))
            .execute(conn)
            .await
    );
}

/// Count members in a vauban group.
pub async fn count_vauban_group_members(conn: &mut AsyncPgConnection, group_uuid: &Uuid) -> i64 {
    use vauban_web::schema::user_groups;
    use vauban_web::schema::vauban_groups;

    let group_id: i32 = unwrap_ok!(
        vauban_groups::table
            .filter(vauban_groups::uuid.eq(group_uuid))
            .select(vauban_groups::id)
            .first(conn)
            .await
    );

    user_groups::table
        .filter(user_groups::group_id.eq(group_id))
        .count()
        .get_result(conn)
        .await
        .unwrap_or(0)
}

/// Create a test asset in a specific group and return asset_id.
/// Uses a unique hostname with UUID suffix to avoid conflicts.
pub async fn create_test_asset_in_group(
    conn: &mut AsyncPgConnection,
    name: &str,
    created_by: i32,
    group_uuid: &Uuid,
) -> i32 {
    use vauban_web::schema::asset_groups;

    // First get the group_id from uuid
    let group_id: i32 = unwrap_ok!(
        asset_groups::table
            .filter(asset_groups::uuid.eq(group_uuid))
            .select(asset_groups::id)
            .first(conn)
            .await
    );

    let asset_uuid = Uuid::new_v4();
    // Create a truly unique hostname using a UUID suffix
    let unique_hostname = format!("{}-{}.test.local", name, &asset_uuid.to_string()[..8]);

    let new_asset = NewAsset {
        uuid: asset_uuid,
        name: name.to_string(),
        hostname: unique_hostname,
        ip_address: None,
        port: 22,
        asset_type: "ssh".to_string(),
        status: "online".to_string(),
        group_id: Some(group_id),
        description: None,
        os_type: None,
        os_version: None,
        connection_config: serde_json::json!({}),
        default_credential_id: None,
        require_mfa: false,
        require_justification: false,
        max_session_duration: 3600,
        created_by_id: Some(created_by),
    };

    let asset: Asset = unwrap_ok!(
        diesel::insert_into(assets::table)
            .values(&new_asset)
            .get_result(conn)
            .await
    );

    asset.id
}

// =============================================================================
// Auth Sessions and API Keys fixtures
// =============================================================================

/// Create a test auth session and return session_uuid.
pub async fn create_test_auth_session(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    is_current: bool,
) -> Uuid {
    use chrono::{Duration, Utc};
    use vauban_web::models::NewAuthSession;
    use vauban_web::schema::auth_sessions;

    let session_uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = unwrap_ok!("127.0.0.1".parse());
    let token_hash = format!(
        "hash_{}_{}",
        user_id,
        if is_current { "current" } else { "other" }
    );

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

    unwrap_ok!(
        diesel::insert_into(auth_sessions::table)
            .values(&new_session)
            .execute(conn)
            .await
    );

    session_uuid
}

/// Create a test API key and return key_uuid.
pub async fn create_test_api_key(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    name: &str,
    is_active: bool,
) -> Uuid {
    use vauban_web::schema::api_keys;

    let key_uuid = Uuid::new_v4();

    unwrap_ok!(
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
            .await
    );

    key_uuid
}

/// Create an expired test API key and return key_uuid.
pub async fn create_expired_api_key(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    name: &str,
) -> Uuid {
    use chrono::{Duration, Utc};
    use vauban_web::schema::api_keys;

    let key_uuid = Uuid::new_v4();

    unwrap_ok!(
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
            .await
    );

    key_uuid
}

/// Create an auth session with a specific token hash (for testing revocation).
/// Returns the session UUID.
pub async fn create_auth_session_with_token(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    token: &str,
    is_current: bool,
) -> Uuid {
    use chrono::{Duration, Utc};
    use sha3::{Digest, Sha3_256};
    use vauban_web::models::NewAuthSession;
    use vauban_web::schema::auth_sessions;

    let session_uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = unwrap_ok!("127.0.0.1".parse());

    // Hash the token using SHA3-256 (same as production code)
    let mut hasher = Sha3_256::new();
    hasher.update(token.as_bytes());
    let token_hash = format!("{:x}", hasher.finalize());

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

    unwrap_ok!(
        diesel::insert_into(auth_sessions::table)
            .values(&new_session)
            .execute(conn)
            .await
    );

    session_uuid
}

/// Create an expired auth session with a specific token hash.
/// Returns the session UUID.
pub async fn create_expired_auth_session(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    token: &str,
) -> Uuid {
    use chrono::{Duration, Utc};
    use sha3::{Digest, Sha3_256};
    use vauban_web::models::NewAuthSession;
    use vauban_web::schema::auth_sessions;

    let session_uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = unwrap_ok!("127.0.0.1".parse());

    // Hash the token using SHA3-256
    let mut hasher = Sha3_256::new();
    hasher.update(token.as_bytes());
    let token_hash = format!("{:x}", hasher.finalize());

    let new_session = NewAuthSession {
        uuid: session_uuid,
        user_id,
        token_hash,
        ip_address: ip,
        user_agent: Some("Mozilla/5.0 Expired Test".to_string()),
        device_info: Some("Expired Browser".to_string()),
        expires_at: Utc::now() - Duration::hours(1), // Expired 1 hour ago
        is_current: false,
    };

    unwrap_ok!(
        diesel::insert_into(auth_sessions::table)
            .values(&new_session)
            .execute(conn)
            .await
    );

    session_uuid
}
