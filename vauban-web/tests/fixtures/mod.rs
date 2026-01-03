/// VAUBAN Web - Test fixtures.
///
/// Factory functions for creating test data.

use diesel::prelude::*;
use uuid::Uuid;
use chrono::Utc;

use vauban_web::models::user::{User, NewUser};
use vauban_web::models::asset::{Asset, NewAsset};
use vauban_web::schema::{users, assets, asset_groups, user_groups};
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
    format!("{}_{}", prefix, Uuid::new_v4().to_string().split('-').next().unwrap())
}

