/// VAUBAN Web - Test fixtures.
///
/// Factory functions for creating test data.
use chrono::{Duration, Utc};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

use vauban_web::models::access_rule::NewAccessRule;
use vauban_web::models::asset::{Asset, AssetType, NewAsset, NewAssetAssetGroup};
use vauban_web::models::auth_session::NewAuthSession;
use vauban_web::models::session::SessionType;
use vauban_web::models::user::{AuthSource, NewUser, User};
use vauban_web::schema::{access_rules, assets, auth_sessions, users};
use vauban_web::services::auth::AuthService;

use crate::common::{unwrap_ok, unwrap_some};

/// Helper to create an auth session for a token in the database.
pub async fn create_session_for_token_pub(conn: &mut AsyncPgConnection, user_id: i32, token: &str) {
    create_session_for_token(conn, user_id, token).await;
}

async fn create_session_for_token(conn: &mut AsyncPgConnection, user_id: i32, token: &str) {
    // Hash the token using SHA3-256
    let mut hasher = Sha3_256::new();
    hasher.update(token.as_bytes());
    let token_hash = format!("{:x}", hasher.finalize());

    let ip: ipnetwork::IpNetwork = unwrap_ok!("127.0.0.1".parse());
    // Issue #8: `auth_sessions` now has a UNIQUE index on
    // (user_id, device_info, ip_address). Tests routinely create several
    // sessions for the same user from 127.0.0.1, so we derive
    // `device_info` from the token hash to keep each fixture row
    // distinct.
    let new_session = NewAuthSession {
        uuid: Uuid::new_v4(),
        user_id,
        token_hash: token_hash.clone(),
        ip_address: ip,
        user_agent: Some("Test Client".to_string()),
        device_info: format!("Test/{}", &token_hash[..8]),
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
        auth_source: AuthSource::Local,
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
        auth_source: AuthSource::Local,
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

/// Create a `is_staff=true, is_superuser=false` user. Designed for the
/// fine-grained Casbin tests that exercise the privilege boundary
/// between staff and superusers (e.g. `groups:write` requires
/// superuser even though staff retains `manage_members`).
pub async fn create_staff_only_user(
    conn: &mut AsyncPgConnection,
    auth_service: &AuthService,
    username: &str,
) -> TestUser {
    let password = "StaffPassword123!";
    let password_hash = unwrap_ok!(auth_service.hash_password(password));
    let user_uuid = Uuid::new_v4();

    let new_user = NewUser {
        uuid: user_uuid,
        username: username.to_string(),
        email: format!("{}@test.vauban.io", username),
        password_hash,
        first_name: Some("Staff".to_string()),
        last_name: Some("Only".to_string()),
        phone: None,
        is_active: true,
        is_staff: true,
        is_superuser: false,
        is_service_account: false,
        mfa_enabled: false,
        mfa_enforced: false,
        mfa_secret: None,
        preferences: serde_json::json!({}),
        auth_source: AuthSource::Local,
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
        true,
    ));

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
        auth_source: AuthSource::Local,
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

/// Test user data with the raw MFA secret exposed so the caller can compute
/// a valid TOTP code at request time.
pub struct TestUserWithMfa {
    pub user: User,
    pub password: String,
    /// JWT with `mfa_verified=true` -- ready for direct API auth.
    pub token: String,
    /// Base32-encoded TOTP secret. Use [`current_totp_for`] to derive the
    /// code that the API login endpoint will accept right now.
    pub mfa_secret: String,
}

/// Create a regular (non-admin) user with MFA enabled and return the raw
/// MFA secret so the caller can drive `/api/v1/auth/login` end-to-end.
///
/// Designed for tests that exercise the API login flow after the
/// "Finding #2" remediation, which refuses API logins for accounts
/// without MFA configured.
pub async fn create_test_user_with_mfa(
    conn: &mut AsyncPgConnection,
    auth_service: &AuthService,
    username: &str,
) -> TestUserWithMfa {
    create_user_with_mfa_internal(conn, auth_service, username, false, false).await
}

/// Create an admin (is_staff + is_superuser) user with MFA enabled.
pub async fn create_admin_user_with_mfa(
    conn: &mut AsyncPgConnection,
    auth_service: &AuthService,
    username: &str,
) -> TestUserWithMfa {
    create_user_with_mfa_internal(conn, auth_service, username, true, true).await
}

async fn create_user_with_mfa_internal(
    conn: &mut AsyncPgConnection,
    auth_service: &AuthService,
    username: &str,
    is_staff: bool,
    is_superuser: bool,
) -> TestUserWithMfa {
    let password = "MfaPassword123!";
    let password_hash = unwrap_ok!(auth_service.hash_password(password));
    let user_uuid = Uuid::new_v4();
    let (mfa_secret, _) = unwrap_ok!(AuthService::generate_totp_secret(username, "VAUBAN-tests"));

    let new_user = NewUser {
        uuid: user_uuid,
        username: username.to_string(),
        email: format!("{}@test.vauban.io", username),
        password_hash,
        first_name: Some("Test".to_string()),
        last_name: Some("WithMfa".to_string()),
        phone: None,
        is_active: true,
        is_staff,
        is_superuser,
        is_service_account: false,
        mfa_enabled: true,
        mfa_enforced: false,
        mfa_secret: Some(mfa_secret.clone()),
        preferences: serde_json::json!({}),
        auth_source: AuthSource::Local,
        external_id: None,
    };

    let user: User = unwrap_ok!(
        diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(conn)
            .await
    );

    // Token with MFA verified -- mirrors what the login endpoint mints
    // after a successful TOTP check.
    let token = unwrap_ok!(auth_service.generate_access_token(
        &user.uuid.to_string(),
        &user.username,
        true,
        is_staff,
        is_superuser,
    ));
    create_session_for_token(conn, user.id, &token).await;

    TestUserWithMfa {
        user,
        password: password.to_string(),
        token,
        mfa_secret,
    }
}

/// Compute the TOTP code that `/api/v1/auth/login` will accept right now
/// for the given base32-encoded shared secret.
pub fn current_totp_for(mfa_secret: &str) -> String {
    unwrap_some!(AuthService::get_current_totp(mfa_secret))
}

/// Test asset data.
pub struct TestAsset {
    pub asset: Asset,
}

/// Create a test SSH asset.
pub async fn create_test_ssh_asset(conn: &mut AsyncPgConnection, name: &str) -> TestAsset {
    let asset_uuid = Uuid::new_v4();

    let new_asset = NewAsset {
        uuid: asset_uuid,
        name: name.to_string(),
        hostname: format!("{}.test.vauban.io", name.replace("test-", "")),
        port: 22,
        asset_type: AssetType::Ssh,
        status: "online".to_string(),
        description: Some("Test SSH asset".to_string()),
        connection_config: serde_json::json!({}),
        created_by_id: None,
        updated_by_id: None,
        connection_username: "root".to_string(),
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

    let new_asset = NewAsset {
        uuid: asset_uuid,
        name: name.to_string(),
        hostname: format!("{}.test.vauban.io", name.replace("test-", "")),
        port: 3389,
        asset_type: AssetType::Rdp,
        status: "online".to_string(),
        description: Some("Test RDP asset".to_string()),
        connection_config: serde_json::json!({}),
        created_by_id: None,
        updated_by_id: None,
        connection_username: "Administrator".to_string(),
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
        auth_source: AuthSource::Local,
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
        auth_source: AuthSource::Local,
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
        port: 22,
        asset_type: AssetType::Ssh,
        status: "online".to_string(),
        description: None,
        connection_config: serde_json::json!({}),
        created_by_id: Some(created_by),
        updated_by_id: Some(created_by),
        connection_username: "root".to_string(),
    };

    let asset: Asset = unwrap_ok!(
        diesel::insert_into(assets::table)
            .values(&new_asset)
            .get_result(conn)
            .await
    );

    asset.id
}

/// Create a simple RDP asset for testing (returns asset ID).
pub async fn create_simple_rdp_asset(
    conn: &mut AsyncPgConnection,
    name: &str,
    created_by: i32,
) -> i32 {
    let asset_uuid = Uuid::new_v4();
    let unique_hostname = format!("{}-{}.test.local", name, &asset_uuid.to_string()[..8]);

    let new_asset = NewAsset {
        uuid: asset_uuid,
        name: name.to_string(),
        hostname: unique_hostname,
        port: 3389,
        asset_type: AssetType::Rdp,
        status: "online".to_string(),
        description: None,
        connection_config: serde_json::json!({}),
        created_by_id: Some(created_by),
        updated_by_id: Some(created_by),
        connection_username: "Administrator".to_string(),
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
                proxy_sessions::session_type.eq(SessionType::parse(session_type)),
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

/// Create a JIT access request session with justification and arbitrary status.
pub async fn create_jit_session(
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
                proxy_sessions::session_type.eq(SessionType::parse(session_type)),
                proxy_sessions::status.eq(status),
                proxy_sessions::client_ip.eq(ip),
                proxy_sessions::connected_at.eq(connected_at),
                proxy_sessions::disconnected_at.eq(disconnected_at),
                proxy_sessions::is_recorded.eq(false),
                proxy_sessions::justification.eq("JIT access request for maintenance"),
                proxy_sessions::metadata.eq(serde_json::json!({"approval_required": true})),
            ))
            .returning(proxy_sessions::id)
            .get_result(conn)
            .await
    );

    session_id
}

/// Create a test session and return both (session_id, session_uuid).
pub async fn create_test_session_with_uuid(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
    session_type: &str,
    status: &str,
) -> (i32, Uuid) {
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
                proxy_sessions::session_type.eq(SessionType::parse(session_type)),
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

    (session_id, session_uuid)
}

/// Like [`create_test_session_with_uuid`], but also provisions a fresh
/// access rule covering the session's protocol so that the new
/// `session_access::verify` gate (which re-checks the access rule on
/// every consumption) does not collapse the request to 404.
///
/// Returns `(session_id, session_uuid, rule_uuid)`.
///
/// Tests that explicitly want to exercise the fail-fast revoke /
/// expire / not-yet-valid paths should still combine
/// [`create_test_session_with_uuid`] + [`grant_user_access_to_asset`]
/// + the corresponding mutator (`deactivate_access_rule`,
///   `set_access_rule_validity`, ...) so they can mutate the rule
///   returned here directly.
pub async fn create_test_session_with_access(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
    session_type: &str,
    status: &str,
) -> (i32, Uuid, Uuid) {
    let (session_id, session_uuid) =
        create_test_session_with_uuid(conn, user_id, asset_id, session_type, status).await;
    let (rule_uuid, _ag) = grant_user_access_to_asset(
        conn,
        user_id,
        asset_id,
        &format!("auto-session-{}", session_uuid.simple()),
        &[session_type],
    )
    .await;
    (session_id, session_uuid, rule_uuid)
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
                proxy_sessions::session_type.eq(SessionType::parse(session_type)),
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
                proxy_sessions::session_type.eq(SessionType::Ssh),
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

/// Create an approval request with a specific max_session_duration.
pub async fn create_approval_request_with_duration(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
    max_duration: Option<i32>,
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
                proxy_sessions::session_type.eq(SessionType::Ssh),
                proxy_sessions::status.eq("pending"),
                proxy_sessions::client_ip.eq(ip),
                proxy_sessions::is_recorded.eq(true),
                proxy_sessions::justification.eq("Need access for maintenance"),
                proxy_sessions::metadata.eq(serde_json::json!({"approval_required": true})),
                proxy_sessions::max_session_duration.eq(max_duration),
            ))
            .execute(conn)
            .await
    );

    session_uuid
}

/// Create a pre-approved session (status = "approved") with expires_at set.
/// Simulates what the approve handler does after admin approval.
///
/// The `approved_by_id` is set to a distinct user to comply with the
/// separation-of-duties CHECK constraint (`approved_by_id <> user_id`).
/// Callers that need to control the approver can use
/// `create_approved_session_by`.
pub async fn create_approved_session(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
    max_duration: Option<i32>,
) -> Uuid {
    let approver_id = ensure_test_approver(conn).await;
    create_approved_session_by(conn, user_id, asset_id, max_duration, approver_id).await
}

/// Like `create_approved_session` but with an explicit approver.
pub async fn create_approved_session_by(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
    max_duration: Option<i32>,
    approver_id: i32,
) -> Uuid {
    use chrono::Utc;
    use vauban_web::schema::proxy_sessions;

    let session_uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = unwrap_ok!("127.0.0.1".parse());
    let now = Utc::now();
    let expires_at = max_duration.map(|secs| now + chrono::Duration::seconds(secs as i64));

    unwrap_ok!(
        diesel::insert_into(proxy_sessions::table)
            .values((
                proxy_sessions::uuid.eq(session_uuid),
                proxy_sessions::user_id.eq(user_id),
                proxy_sessions::asset_id.eq(asset_id),
                proxy_sessions::credential_id.eq("cred-123"),
                proxy_sessions::credential_username.eq("testuser"),
                proxy_sessions::session_type.eq(SessionType::Ssh),
                proxy_sessions::status.eq("approved"),
                proxy_sessions::client_ip.eq(ip),
                proxy_sessions::is_recorded.eq(true),
                proxy_sessions::justification.eq("Approved access"),
                proxy_sessions::metadata.eq(serde_json::json!({"approval_required": true})),
                proxy_sessions::max_session_duration.eq(max_duration),
                proxy_sessions::approved_by_id.eq(Some(approver_id)),
                proxy_sessions::approved_at.eq(Some(now)),
                proxy_sessions::expires_at.eq(expires_at),
            ))
            .execute(conn)
            .await
    );

    session_uuid
}

/// Returns the DB id of a shared "test approver" user, creating it once
/// if it does not exist. This user is distinct from any requester so
/// that the `approval_separation_of_duties` CHECK constraint is satisfied.
async fn ensure_test_approver(conn: &mut AsyncPgConnection) -> i32 {
    use vauban_web::schema::users;

    let existing: Option<i32> = users::table
        .filter(users::username.eq("__test_approver__"))
        .select(users::id)
        .first(conn)
        .await
        .optional()
        .expect("query test_approver");
    if let Some(id) = existing {
        return id;
    }
    create_simple_user(conn, "__test_approver").await
}

/// Wire user + asset into groups with an active access rule that has
/// `require_approval = true`. Needed by approve/reject integration tests
/// so that `vauban-access`'s `load_pending_session_snapshot` can find a
/// matching rule (post-SoD refactoring).
/// Wire user + asset into groups with an active access rule that has
/// `require_approval = true`. Needed by approve/reject integration tests
/// so that `vauban-access`'s `load_pending_session_snapshot` can find a
/// matching rule (post-SoD refactoring).
pub async fn setup_approval_rule(conn: &mut AsyncPgConnection, user_id: i32, asset_id: i32) {
    let ug_uuid = create_test_vauban_group(conn, &unique_name("jit-ug")).await;
    add_user_to_vauban_group(conn, user_id, &ug_uuid).await;

    let ag_uuid = create_test_asset_group(conn, &unique_name("jit-ag")).await;

    use vauban_web::schema::{asset_asset_groups, asset_groups};
    let ag_id: i32 = asset_groups::table
        .filter(asset_groups::uuid.eq(ag_uuid))
        .select(asset_groups::id)
        .first(conn)
        .await
        .expect("get ag_id");
    diesel::insert_into(asset_asset_groups::table)
        .values((
            asset_asset_groups::asset_id.eq(asset_id),
            asset_asset_groups::asset_group_id.eq(ag_id),
        ))
        .execute(conn)
        .await
        .expect("insert asset_asset_groups");

    create_test_access_rule_with_constraints(
        conn,
        &ug_uuid,
        &ag_uuid,
        &["ssh", "rdp"],
        false,
        true,
        None,
    )
    .await;
}

/// Create an already-expired approved session (expires_at in the past).
/// Used to verify that expired approvals are not reused.
pub async fn create_expired_approved_session(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
) -> Uuid {
    use chrono::Utc;
    use vauban_web::schema::proxy_sessions;

    let approver_id = ensure_test_approver(conn).await;
    let session_uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = unwrap_ok!("127.0.0.1".parse());
    let now = Utc::now();
    let expired_at = now - Duration::hours(1);

    unwrap_ok!(
        diesel::insert_into(proxy_sessions::table)
            .values((
                proxy_sessions::uuid.eq(session_uuid),
                proxy_sessions::user_id.eq(user_id),
                proxy_sessions::asset_id.eq(asset_id),
                proxy_sessions::credential_id.eq("cred-123"),
                proxy_sessions::credential_username.eq("testuser"),
                proxy_sessions::session_type.eq(SessionType::Ssh),
                proxy_sessions::status.eq("approved"),
                proxy_sessions::client_ip.eq(ip),
                proxy_sessions::is_recorded.eq(true),
                proxy_sessions::justification.eq("Expired approved access"),
                proxy_sessions::metadata.eq(serde_json::json!({"approval_required": true})),
                proxy_sessions::max_session_duration.eq(Some(900)),
                proxy_sessions::approved_by_id.eq(Some(approver_id)),
                proxy_sessions::approved_at.eq(Some(now - Duration::hours(2))),
                proxy_sessions::expires_at.eq(Some(expired_at)),
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
        port: 22,
        asset_type: AssetType::Ssh,
        status: "online".to_string(),
        description: None,
        connection_config: serde_json::json!({}),
        created_by_id: Some(created_by),
        updated_by_id: Some(created_by),
        connection_username: "root".to_string(),
    };

    let asset: Asset = unwrap_ok!(
        diesel::insert_into(assets::table)
            .values(&new_asset)
            .get_result(conn)
            .await
    );

    use vauban_web::schema::asset_asset_groups::dsl as aag;
    unwrap_ok!(
        diesel::insert_into(aag::asset_asset_groups)
            .values(NewAssetAssetGroup {
                asset_id: asset.id,
                asset_group_id: group_id,
            })
            .execute(conn)
            .await
    );

    asset.id
}

/// Create a test asset in a specific group with a given asset type and return asset_id.
pub async fn create_test_asset_in_group_with_type(
    conn: &mut AsyncPgConnection,
    name: &str,
    created_by: i32,
    group_uuid: &Uuid,
    asset_type: AssetType,
) -> i32 {
    use vauban_web::schema::asset_groups;

    let group_id: i32 = unwrap_ok!(
        asset_groups::table
            .filter(asset_groups::uuid.eq(group_uuid))
            .select(asset_groups::id)
            .first(conn)
            .await
    );

    let asset_uuid = Uuid::new_v4();
    let unique_hostname = format!("{}-{}.test.local", name, &asset_uuid.to_string()[..8]);
    let port = match asset_type {
        AssetType::Ssh => 22,
        AssetType::Rdp => 3389,
    };

    let default_user = match asset_type {
        AssetType::Rdp => "Administrator",
        _ => "root",
    };

    let new_asset = NewAsset {
        uuid: asset_uuid,
        name: name.to_string(),
        hostname: unique_hostname,
        port,
        asset_type,
        status: "online".to_string(),
        description: None,
        connection_config: serde_json::json!({}),
        created_by_id: Some(created_by),
        updated_by_id: Some(created_by),
        connection_username: default_user.to_string(),
    };

    let asset: Asset = unwrap_ok!(
        diesel::insert_into(assets::table)
            .values(&new_asset)
            .get_result(conn)
            .await
    );

    use vauban_web::schema::asset_asset_groups::dsl as aag;
    unwrap_ok!(
        diesel::insert_into(aag::asset_asset_groups)
            .values(NewAssetAssetGroup {
                asset_id: asset.id,
                asset_group_id: group_id,
            })
            .execute(conn)
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
        "hash_{}_{}_{}",
        user_id,
        if is_current { "current" } else { "other" },
        session_uuid.simple()
    );

    // Issue #8: keep `device_info` unique per fixture row to avoid
    // tripping `uniq_auth_sessions_per_device`.
    let new_session = NewAuthSession {
        uuid: session_uuid,
        user_id,
        token_hash,
        ip_address: ip,
        user_agent: Some("Mozilla/5.0 Test".to_string()),
        device_info: format!("Test Browser/{}", session_uuid.simple()),
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

    // Issue #8: derive `device_info` from the token hash so two
    // sessions for the same user (revocation tests) do not collide on
    // `uniq_auth_sessions_per_device`.
    let new_session = NewAuthSession {
        uuid: session_uuid,
        user_id,
        token_hash: token_hash.clone(),
        ip_address: ip,
        user_agent: Some("Mozilla/5.0 Test".to_string()),
        device_info: format!("Test Browser/{}", &token_hash[..8]),
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

    // Issue #8: same per-token uniqueness as the active fixture above.
    let new_session = NewAuthSession {
        uuid: session_uuid,
        user_id,
        token_hash: token_hash.clone(),
        ip_address: ip,
        user_agent: Some("Mozilla/5.0 Expired Test".to_string()),
        device_info: format!("Expired Browser/{}", &token_hash[..8]),
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

// =============================================================================
// Access Rule fixtures
// =============================================================================

/// Bootstrap a fresh user-group + asset-group + (no-MFA, no-approval)
/// access-rule for `user_id` and return the asset-group UUID. Subsequent
/// assets must be inserted with `create_test_asset_in_group` (or its `_type`
/// variant) using the returned UUID for them to be visible to the user.
///
/// Required because the historical "is_superuser / is_staff" listing-bypass
/// was removed: every user (including admins) must now have an access_rule
/// to see / open an asset, mirroring what the proxy enforces.
pub async fn grant_user_full_access_to_new_group(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    name_hint: &str,
    protocols: &[&str],
) -> Uuid {
    let ug = create_test_vauban_group(conn, &format!("{}-ug", name_hint)).await;
    let ag = create_test_asset_group(conn, &format!("{}-ag", name_hint)).await;
    add_user_to_vauban_group(conn, user_id, &ug).await;
    create_test_access_rule(conn, &ug, &ag, protocols).await;
    ag
}

/// Create a test access rule linking a user group to an asset group.
pub async fn create_test_access_rule(
    conn: &mut AsyncPgConnection,
    user_group_uuid: &Uuid,
    asset_group_uuid: &Uuid,
    protocols: &[&str],
) -> Uuid {
    use vauban_web::schema::{asset_groups, vauban_groups};

    let ug_id: i32 = unwrap_ok!(
        vauban_groups::table
            .filter(vauban_groups::uuid.eq(user_group_uuid))
            .select(vauban_groups::id)
            .first(conn)
            .await
    );

    let ag_id: i32 = unwrap_ok!(
        asset_groups::table
            .filter(asset_groups::uuid.eq(asset_group_uuid))
            .select(asset_groups::id)
            .first(conn)
            .await
    );

    let rule_uuid = Uuid::new_v4();
    let allowed: Vec<Option<String>> = protocols.iter().map(|p| Some(p.to_string())).collect();
    let unique_name = format!("test-rule_{}", &rule_uuid.to_string()[..8]);

    let new_rule = NewAccessRule {
        uuid: rule_uuid,
        name: unique_name,
        description: Some("Test access rule".to_string()),
        user_group_id: ug_id,
        asset_group_id: ag_id,
        allowed_protocols: allowed,
        valid_from: None,
        valid_until: None,
        require_mfa: false,
        require_approval: false,
        max_session_duration: None,
        is_active: true,
        priority: 0,
        created_by_id: None,
    };

    unwrap_ok!(
        diesel::insert_into(access_rules::table)
            .values(&new_rule)
            .execute(conn)
            .await
    );

    rule_uuid
}

/// Create an access rule with MFA and justification requirements.
pub async fn create_test_access_rule_with_constraints(
    conn: &mut AsyncPgConnection,
    user_group_uuid: &Uuid,
    asset_group_uuid: &Uuid,
    protocols: &[&str],
    require_mfa: bool,
    require_approval: bool,
    max_duration: Option<i32>,
) -> Uuid {
    use vauban_web::schema::{asset_groups, vauban_groups};

    let ug_id: i32 = unwrap_ok!(
        vauban_groups::table
            .filter(vauban_groups::uuid.eq(user_group_uuid))
            .select(vauban_groups::id)
            .first(conn)
            .await
    );

    let ag_id: i32 = unwrap_ok!(
        asset_groups::table
            .filter(asset_groups::uuid.eq(asset_group_uuid))
            .select(asset_groups::id)
            .first(conn)
            .await
    );

    let rule_uuid = Uuid::new_v4();
    let allowed: Vec<Option<String>> = protocols.iter().map(|p| Some(p.to_string())).collect();
    let unique_name = format!("test-constrained-rule_{}", &rule_uuid.to_string()[..8]);

    let new_rule = NewAccessRule {
        uuid: rule_uuid,
        name: unique_name,
        description: None,
        user_group_id: ug_id,
        asset_group_id: ag_id,
        allowed_protocols: allowed,
        valid_from: None,
        valid_until: None,
        require_mfa,
        require_approval,
        max_session_duration: max_duration,
        is_active: true,
        priority: 0,
        created_by_id: None,
    };

    unwrap_ok!(
        diesel::insert_into(access_rules::table)
            .values(&new_rule)
            .execute(conn)
            .await
    );

    rule_uuid
}

/// Create an expired access rule (valid_until in the past).
pub async fn create_expired_access_rule(
    conn: &mut AsyncPgConnection,
    user_group_uuid: &Uuid,
    asset_group_uuid: &Uuid,
) -> Uuid {
    use vauban_web::schema::{asset_groups, vauban_groups};

    let ug_id: i32 = unwrap_ok!(
        vauban_groups::table
            .filter(vauban_groups::uuid.eq(user_group_uuid))
            .select(vauban_groups::id)
            .first(conn)
            .await
    );

    let ag_id: i32 = unwrap_ok!(
        asset_groups::table
            .filter(asset_groups::uuid.eq(asset_group_uuid))
            .select(asset_groups::id)
            .first(conn)
            .await
    );

    let rule_uuid = Uuid::new_v4();
    let unique_name = format!("test-expired-rule_{}", &rule_uuid.to_string()[..8]);

    let new_rule = NewAccessRule {
        uuid: rule_uuid,
        name: unique_name,
        description: None,
        user_group_id: ug_id,
        asset_group_id: ag_id,
        allowed_protocols: vec![Some("ssh".to_string()), Some("rdp".to_string())],
        valid_from: Some(Utc::now() - Duration::days(30)),
        valid_until: Some(Utc::now() - Duration::hours(1)),
        require_mfa: false,
        require_approval: false,
        max_session_duration: None,
        is_active: true,
        priority: 0,
        created_by_id: None,
    };

    unwrap_ok!(
        diesel::insert_into(access_rules::table)
            .values(&new_rule)
            .execute(conn)
            .await
    );

    rule_uuid
}

/// Create a future access rule (valid_from in the future).
pub async fn create_future_access_rule(
    conn: &mut AsyncPgConnection,
    user_group_uuid: &Uuid,
    asset_group_uuid: &Uuid,
) -> Uuid {
    use vauban_web::schema::{asset_groups, vauban_groups};

    let ug_id: i32 = unwrap_ok!(
        vauban_groups::table
            .filter(vauban_groups::uuid.eq(user_group_uuid))
            .select(vauban_groups::id)
            .first(conn)
            .await
    );

    let ag_id: i32 = unwrap_ok!(
        asset_groups::table
            .filter(asset_groups::uuid.eq(asset_group_uuid))
            .select(asset_groups::id)
            .first(conn)
            .await
    );

    let rule_uuid = Uuid::new_v4();
    let unique_name = format!("test-future-rule_{}", &rule_uuid.to_string()[..8]);

    let new_rule = NewAccessRule {
        uuid: rule_uuid,
        name: unique_name,
        description: None,
        user_group_id: ug_id,
        asset_group_id: ag_id,
        allowed_protocols: vec![Some("ssh".to_string()), Some("rdp".to_string())],
        valid_from: Some(Utc::now() + Duration::hours(24)),
        valid_until: None,
        require_mfa: false,
        require_approval: false,
        max_session_duration: None,
        is_active: true,
        priority: 0,
        created_by_id: None,
    };

    unwrap_ok!(
        diesel::insert_into(access_rules::table)
            .values(&new_rule)
            .execute(conn)
            .await
    );

    rule_uuid
}

/// Create an inactive access rule (is_active = false).
pub async fn create_inactive_access_rule(
    conn: &mut AsyncPgConnection,
    user_group_uuid: &Uuid,
    asset_group_uuid: &Uuid,
) -> Uuid {
    use vauban_web::schema::{asset_groups, vauban_groups};

    let ug_id: i32 = unwrap_ok!(
        vauban_groups::table
            .filter(vauban_groups::uuid.eq(user_group_uuid))
            .select(vauban_groups::id)
            .first(conn)
            .await
    );

    let ag_id: i32 = unwrap_ok!(
        asset_groups::table
            .filter(asset_groups::uuid.eq(asset_group_uuid))
            .select(asset_groups::id)
            .first(conn)
            .await
    );

    let rule_uuid = Uuid::new_v4();
    let unique_name = format!("test-inactive-rule_{}", &rule_uuid.to_string()[..8]);

    let new_rule = NewAccessRule {
        uuid: rule_uuid,
        name: unique_name,
        description: None,
        user_group_id: ug_id,
        asset_group_id: ag_id,
        allowed_protocols: vec![Some("ssh".to_string()), Some("rdp".to_string())],
        valid_from: None,
        valid_until: None,
        require_mfa: false,
        require_approval: false,
        max_session_duration: None,
        is_active: false,
        priority: 0,
        created_by_id: None,
    };

    unwrap_ok!(
        diesel::insert_into(access_rules::table)
            .values(&new_rule)
            .execute(conn)
            .await
    );

    rule_uuid
}

/// SECURITY HELPER: grant `user_id` an active access rule that covers
/// (`asset_id`, `protocols`). Builds the full chain (vauban_group +
/// asset_group + membership + asset link + access_rule) so the
/// vauban-access RPC `VerifySessionAccess` returns `Allowed` for any
/// session opened on this (user, asset, protocol) tuple.
///
/// Returns the (rule_uuid, asset_group_uuid) so callers can later
/// mutate the rule (deactivate / shift validity windows / delete) to
/// exercise the fail-fast access-rule recheck path.
pub async fn grant_user_access_to_asset(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
    name_hint: &str,
    protocols: &[&str],
) -> (Uuid, Uuid) {
    use vauban_web::schema::{asset_asset_groups, asset_groups};

    let ug = create_test_vauban_group(conn, &format!("{}-ug", name_hint)).await;
    let ag = create_test_asset_group(conn, &format!("{}-ag", name_hint)).await;
    add_user_to_vauban_group(conn, user_id, &ug).await;

    let ag_id: i32 = unwrap_ok!(
        asset_groups::table
            .filter(asset_groups::uuid.eq(ag))
            .select(asset_groups::id)
            .first(conn)
            .await
    );
    unwrap_ok!(
        diesel::insert_into(asset_asset_groups::table)
            .values((
                asset_asset_groups::asset_id.eq(asset_id),
                asset_asset_groups::asset_group_id.eq(ag_id),
            ))
            .on_conflict_do_nothing()
            .execute(conn)
            .await
    );

    let rule_uuid = create_test_access_rule(conn, &ug, &ag, protocols).await;
    (rule_uuid, ag)
}

/// SECURITY HELPER: deactivate an access rule by UUID. Used by tests
/// that exercise the fail-fast revocation behaviour.
pub async fn deactivate_access_rule(conn: &mut AsyncPgConnection, rule_uuid: Uuid) {
    unwrap_ok!(
        diesel::update(access_rules::table.filter(access_rules::uuid.eq(rule_uuid)))
            .set(access_rules::is_active.eq(false))
            .execute(conn)
            .await
    );
}

/// SECURITY HELPER: shift an access rule's validity window. Used by
/// tests that exercise expired / not-yet-valid rejection paths.
pub async fn set_access_rule_validity(
    conn: &mut AsyncPgConnection,
    rule_uuid: Uuid,
    valid_from: Option<chrono::DateTime<Utc>>,
    valid_until: Option<chrono::DateTime<Utc>>,
) {
    unwrap_ok!(
        diesel::update(access_rules::table.filter(access_rules::uuid.eq(rule_uuid)))
            .set((
                access_rules::valid_from.eq(valid_from),
                access_rules::valid_until.eq(valid_until),
            ))
            .execute(conn)
            .await
    );
}
