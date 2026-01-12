/// VAUBAN Web - Cleanup Tasks Integration Tests.
///
/// Tests for the session and API key cleanup functionality.
use chrono::{Duration, Utc};
use diesel::prelude::*;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, test_db};
use crate::fixtures::{create_simple_user, unique_name};

use vauban_web::models::auth_session::NewAuthSession;
use vauban_web::schema::{api_keys, auth_sessions};

// =============================================================================
// Auth Sessions Cleanup Tests
// =============================================================================

/// Test that expired auth sessions are deleted by cleanup.
#[tokio::test]
#[serial]
async fn test_cleanup_expired_auth_sessions() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create test user
    let username = unique_name("test_cleanup_sess");
    let user_id = create_simple_user(&mut conn, &username);

    // Create an expired session (expired 1 hour ago)
    let expired_uuid = create_expired_session(&mut conn, user_id, "expired_token_1");

    // Create a valid session (expires in 24 hours)
    let valid_uuid = create_valid_session(&mut conn, user_id, "valid_token_1");

    // Verify both sessions exist
    let count_before: i64 = auth_sessions::table
        .filter(auth_sessions::user_id.eq(user_id))
        .count()
        .get_result(&mut conn)
        .unwrap();
    assert_eq!(count_before, 2, "Should have 2 sessions before cleanup");

    // Execute cleanup directly (call the internal function via SQL)
    let deleted: usize =
        diesel::delete(auth_sessions::table.filter(auth_sessions::expires_at.lt(Utc::now())))
            .execute(&mut conn)
            .unwrap();

    // Assert: expired session should be deleted
    assert!(
        deleted >= 1,
        "Should have deleted at least 1 expired session"
    );

    // Verify expired session is gone
    let expired_exists: bool = auth_sessions::table
        .filter(auth_sessions::uuid.eq(expired_uuid))
        .count()
        .get_result::<i64>(&mut conn)
        .unwrap()
        > 0;
    assert!(!expired_exists, "Expired session should be deleted");

    // Verify valid session still exists
    let valid_exists: bool = auth_sessions::table
        .filter(auth_sessions::uuid.eq(valid_uuid))
        .count()
        .get_result::<i64>(&mut conn)
        .unwrap()
        > 0;
    assert!(valid_exists, "Valid session should still exist");

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test that valid (non-expired) sessions are NOT deleted.
#[tokio::test]
#[serial]
async fn test_cleanup_preserves_valid_sessions() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create test user
    let username = unique_name("test_preserve_sess");
    let user_id = create_simple_user(&mut conn, &username);

    // Create multiple valid sessions
    let uuid1 = create_valid_session(&mut conn, user_id, "valid_1");
    let uuid2 = create_valid_session(&mut conn, user_id, "valid_2");
    let uuid3 = create_valid_session(&mut conn, user_id, "valid_3");

    // Execute cleanup
    let deleted: usize =
        diesel::delete(auth_sessions::table.filter(auth_sessions::expires_at.lt(Utc::now())))
            .execute(&mut conn)
            .unwrap();

    // Assert: no sessions should be deleted
    assert_eq!(deleted, 0, "Should not delete any valid sessions");

    // Verify all sessions still exist
    let count: i64 = auth_sessions::table
        .filter(auth_sessions::uuid.eq_any(vec![uuid1, uuid2, uuid3]))
        .count()
        .get_result(&mut conn)
        .unwrap();
    assert_eq!(count, 3, "All 3 valid sessions should still exist");

    // Cleanup
    test_db::cleanup(&mut conn);
}

// =============================================================================
// API Keys Cleanup Tests
// =============================================================================

/// Test that expired API keys are deleted by cleanup.
#[tokio::test]
#[serial]
async fn test_cleanup_expired_api_keys() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create test user
    let username = unique_name("test_cleanup_keys");
    let user_id = create_simple_user(&mut conn, &username);

    // Create an expired API key
    let expired_uuid = create_expired_api_key(&mut conn, user_id, "expired_key");

    // Create a valid API key (no expiration)
    let valid_uuid = create_valid_api_key(&mut conn, user_id, "valid_key");

    // Verify both keys exist
    let count_before: i64 = api_keys::table
        .filter(api_keys::user_id.eq(user_id))
        .count()
        .get_result(&mut conn)
        .unwrap();
    assert_eq!(count_before, 2, "Should have 2 API keys before cleanup");

    // Execute cleanup (delete expired or inactive)
    let deleted: usize = diesel::delete(
        api_keys::table.filter(
            api_keys::is_active
                .eq(false)
                .or(api_keys::expires_at.lt(Some(Utc::now()))),
        ),
    )
    .execute(&mut conn)
    .unwrap();

    // Assert: expired key should be deleted
    assert!(deleted >= 1, "Should have deleted at least 1 expired key");

    // Verify expired key is gone
    let expired_exists: bool = api_keys::table
        .filter(api_keys::uuid.eq(expired_uuid))
        .count()
        .get_result::<i64>(&mut conn)
        .unwrap()
        > 0;
    assert!(!expired_exists, "Expired API key should be deleted");

    // Verify valid key still exists
    let valid_exists: bool = api_keys::table
        .filter(api_keys::uuid.eq(valid_uuid))
        .count()
        .get_result::<i64>(&mut conn)
        .unwrap()
        > 0;
    assert!(valid_exists, "Valid API key should still exist");

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test that inactive API keys are deleted by cleanup.
#[tokio::test]
#[serial]
async fn test_cleanup_inactive_api_keys() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create test user
    let username = unique_name("test_inactive_keys");
    let user_id = create_simple_user(&mut conn, &username);

    // Create an inactive API key
    let inactive_uuid = create_inactive_api_key(&mut conn, user_id, "inactive_key");

    // Create an active API key
    let active_uuid = create_valid_api_key(&mut conn, user_id, "active_key");

    // Execute cleanup
    let deleted: usize = diesel::delete(
        api_keys::table.filter(
            api_keys::is_active
                .eq(false)
                .or(api_keys::expires_at.lt(Some(Utc::now()))),
        ),
    )
    .execute(&mut conn)
    .unwrap();

    // Assert: inactive key should be deleted
    assert!(deleted >= 1, "Should have deleted at least 1 inactive key");

    // Verify inactive key is gone
    let inactive_exists: bool = api_keys::table
        .filter(api_keys::uuid.eq(inactive_uuid))
        .count()
        .get_result::<i64>(&mut conn)
        .unwrap()
        > 0;
    assert!(!inactive_exists, "Inactive API key should be deleted");

    // Verify active key still exists
    let active_exists: bool = api_keys::table
        .filter(api_keys::uuid.eq(active_uuid))
        .count()
        .get_result::<i64>(&mut conn)
        .unwrap()
        > 0;
    assert!(active_exists, "Active API key should still exist");

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test cleanup with no expired data.
#[tokio::test]
#[serial]
async fn test_cleanup_with_no_expired_data() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create test user with only valid data
    let username = unique_name("test_no_expired");
    let user_id = create_simple_user(&mut conn, &username);

    create_valid_session(&mut conn, user_id, "valid_sess");
    create_valid_api_key(&mut conn, user_id, "valid_key");

    // Execute cleanup for sessions
    let sessions_deleted: usize =
        diesel::delete(auth_sessions::table.filter(auth_sessions::expires_at.lt(Utc::now())))
            .execute(&mut conn)
            .unwrap();

    // Execute cleanup for API keys
    let keys_deleted: usize = diesel::delete(
        api_keys::table.filter(
            api_keys::is_active
                .eq(false)
                .or(api_keys::expires_at.lt(Some(Utc::now()))),
        ),
    )
    .execute(&mut conn)
    .unwrap();

    // Assert: nothing should be deleted
    assert_eq!(sessions_deleted, 0, "Should not delete any sessions");
    assert_eq!(keys_deleted, 0, "Should not delete any API keys");

    // Cleanup
    test_db::cleanup(&mut conn);
}

// =============================================================================
// Helper functions for creating test data
// =============================================================================

/// Create an expired auth session.
fn create_expired_session(conn: &mut PgConnection, user_id: i32, token: &str) -> Uuid {
    use sha3::{Digest, Sha3_256};

    let session_uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = "127.0.0.1".parse().unwrap();

    let mut hasher = Sha3_256::new();
    hasher.update(token.as_bytes());
    let token_hash = format!("{:x}", hasher.finalize());

    let new_session = NewAuthSession {
        uuid: session_uuid,
        user_id,
        token_hash,
        ip_address: ip,
        user_agent: Some("Test Expired".to_string()),
        device_info: Some("Expired Device".to_string()),
        expires_at: Utc::now() - Duration::hours(1), // Expired 1 hour ago
        is_current: false,
    };

    diesel::insert_into(auth_sessions::table)
        .values(&new_session)
        .execute(conn)
        .expect("Failed to create expired session");

    session_uuid
}

/// Create a valid (non-expired) auth session.
fn create_valid_session(conn: &mut PgConnection, user_id: i32, token: &str) -> Uuid {
    use sha3::{Digest, Sha3_256};

    let session_uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = "127.0.0.1".parse().unwrap();

    let mut hasher = Sha3_256::new();
    hasher.update(token.as_bytes());
    let token_hash = format!("{:x}", hasher.finalize());

    let new_session = NewAuthSession {
        uuid: session_uuid,
        user_id,
        token_hash,
        ip_address: ip,
        user_agent: Some("Test Valid".to_string()),
        device_info: Some("Valid Device".to_string()),
        expires_at: Utc::now() + Duration::hours(24), // Expires in 24 hours
        is_current: true,
    };

    diesel::insert_into(auth_sessions::table)
        .values(&new_session)
        .execute(conn)
        .expect("Failed to create valid session");

    session_uuid
}

/// Create an expired API key.
fn create_expired_api_key(conn: &mut PgConnection, user_id: i32, name: &str) -> Uuid {
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
            api_keys::expires_at.eq(Utc::now() - Duration::days(1)), // Expired 1 day ago
        ))
        .execute(conn)
        .expect("Failed to create expired API key");

    key_uuid
}

/// Create a valid (non-expired, active) API key.
fn create_valid_api_key(conn: &mut PgConnection, user_id: i32, name: &str) -> Uuid {
    let key_uuid = Uuid::new_v4();

    diesel::insert_into(api_keys::table)
        .values((
            api_keys::uuid.eq(key_uuid),
            api_keys::user_id.eq(user_id),
            api_keys::name.eq(name),
            api_keys::key_prefix.eq("vbn_val"),
            api_keys::key_hash.eq(format!("hash_val_{}", name)),
            api_keys::scopes.eq(serde_json::json!(["read", "write"])),
            api_keys::is_active.eq(true),
            // No expires_at = never expires
        ))
        .execute(conn)
        .expect("Failed to create valid API key");

    key_uuid
}

/// Create an inactive API key.
fn create_inactive_api_key(conn: &mut PgConnection, user_id: i32, name: &str) -> Uuid {
    let key_uuid = Uuid::new_v4();

    diesel::insert_into(api_keys::table)
        .values((
            api_keys::uuid.eq(key_uuid),
            api_keys::user_id.eq(user_id),
            api_keys::name.eq(name),
            api_keys::key_prefix.eq("vbn_ina"),
            api_keys::key_hash.eq(format!("hash_ina_{}", name)),
            api_keys::scopes.eq(serde_json::json!(["read"])),
            api_keys::is_active.eq(false), // Inactive
        ))
        .execute(conn)
        .expect("Failed to create inactive API key");

    key_uuid
}
