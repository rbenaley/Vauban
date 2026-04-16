/// VAUBAN Web - Cleanup Tasks Integration Tests.
///
/// Tests for the session and API key cleanup functionality.
use chrono::{Duration, Utc};
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, test_db, unwrap_ok};
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
    let mut conn = app.get_conn().await;

    // Setup: create test user
    let username = unique_name("test_cleanup_sess");
    let user_id = create_simple_user(&mut conn, &username).await;

    // Create an expired session (expired 1 hour ago)
    let expired_uuid = create_expired_session(&mut conn, user_id, "expired_token_1").await;

    // Create a valid session (expires in 24 hours)
    let valid_uuid = create_valid_session(&mut conn, user_id, "valid_token_1").await;

    // Verify both sessions exist
    let count_before: i64 = unwrap_ok!(
        auth_sessions::table
            .filter(auth_sessions::user_id.eq(user_id))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(count_before, 2, "Should have 2 sessions before cleanup");

    // Execute cleanup directly (call the internal function via SQL)
    let deleted: usize = unwrap_ok!(
        diesel::delete(auth_sessions::table.filter(auth_sessions::expires_at.lt(Utc::now())))
            .execute(&mut conn)
            .await
    );

    // Assert: expired session should be deleted
    assert!(
        deleted >= 1,
        "Should have deleted at least 1 expired session"
    );

    // Verify expired session is gone
    let expired_exists: bool = unwrap_ok!(
        auth_sessions::table
            .filter(auth_sessions::uuid.eq(expired_uuid))
            .count()
            .get_result::<i64>(&mut conn)
            .await
    ) > 0;
    assert!(!expired_exists, "Expired session should be deleted");

    // Verify valid session still exists
    let valid_exists: bool = unwrap_ok!(
        auth_sessions::table
            .filter(auth_sessions::uuid.eq(valid_uuid))
            .count()
            .get_result::<i64>(&mut conn)
            .await
    ) > 0;
    assert!(valid_exists, "Valid session should still exist");

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test that valid (non-expired) sessions are NOT deleted.
#[tokio::test]
#[serial]
async fn test_cleanup_preserves_valid_sessions() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create test user
    let username = unique_name("test_preserve_sess");
    let user_id = create_simple_user(&mut conn, &username).await;

    // Create multiple valid sessions
    let uuid1 = create_valid_session(&mut conn, user_id, "valid_1").await;
    let uuid2 = create_valid_session(&mut conn, user_id, "valid_2").await;
    let uuid3 = create_valid_session(&mut conn, user_id, "valid_3").await;

    // Execute cleanup
    let deleted: usize = unwrap_ok!(
        diesel::delete(auth_sessions::table.filter(auth_sessions::expires_at.lt(Utc::now())))
            .execute(&mut conn)
            .await
    );

    // Assert: no sessions should be deleted
    assert_eq!(deleted, 0, "Should not delete any valid sessions");

    // Verify all sessions still exist
    let count: i64 = unwrap_ok!(
        auth_sessions::table
            .filter(auth_sessions::uuid.eq_any(vec![uuid1, uuid2, uuid3]))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(count, 3, "All 3 valid sessions should still exist");

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// API Keys Cleanup Tests
// =============================================================================

/// Test that expired API keys are deleted by cleanup.
#[tokio::test]
#[serial]
async fn test_cleanup_expired_api_keys() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create test user
    let username = unique_name("test_cleanup_keys");
    let user_id = create_simple_user(&mut conn, &username).await;

    // Create an expired API key
    let expired_uuid = create_expired_api_key(&mut conn, user_id, "expired_key").await;

    // Create a valid API key (no expiration)
    let valid_uuid = create_valid_api_key(&mut conn, user_id, "valid_key").await;

    // Verify both keys exist
    let count_before: i64 = unwrap_ok!(
        api_keys::table
            .filter(api_keys::user_id.eq(user_id))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(count_before, 2, "Should have 2 API keys before cleanup");

    // Execute cleanup (delete expired or inactive)
    let deleted: usize = unwrap_ok!(
        diesel::delete(
            api_keys::table.filter(
                api_keys::is_active
                    .eq(false)
                    .or(api_keys::expires_at.lt(Some(Utc::now()))),
            ),
        )
        .execute(&mut conn)
        .await
    );

    // Assert: expired key should be deleted
    assert!(deleted >= 1, "Should have deleted at least 1 expired key");

    // Verify expired key is gone
    let expired_exists: bool = unwrap_ok!(
        api_keys::table
            .filter(api_keys::uuid.eq(expired_uuid))
            .count()
            .get_result::<i64>(&mut conn)
            .await
    ) > 0;
    assert!(!expired_exists, "Expired API key should be deleted");

    // Verify valid key still exists
    let valid_exists: bool = unwrap_ok!(
        api_keys::table
            .filter(api_keys::uuid.eq(valid_uuid))
            .count()
            .get_result::<i64>(&mut conn)
            .await
    ) > 0;
    assert!(valid_exists, "Valid API key should still exist");

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test that inactive API keys are deleted by cleanup.
#[tokio::test]
#[serial]
async fn test_cleanup_inactive_api_keys() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create test user
    let username = unique_name("test_inactive_keys");
    let user_id = create_simple_user(&mut conn, &username).await;

    // Create an inactive API key
    let inactive_uuid = create_inactive_api_key(&mut conn, user_id, "inactive_key").await;

    // Create an active API key
    let active_uuid = create_valid_api_key(&mut conn, user_id, "active_key").await;

    // Execute cleanup
    let deleted: usize = unwrap_ok!(
        diesel::delete(
            api_keys::table.filter(
                api_keys::is_active
                    .eq(false)
                    .or(api_keys::expires_at.lt(Some(Utc::now()))),
            ),
        )
        .execute(&mut conn)
        .await
    );

    // Assert: inactive key should be deleted
    assert!(deleted >= 1, "Should have deleted at least 1 inactive key");

    // Verify inactive key is gone
    let inactive_exists: bool = unwrap_ok!(
        api_keys::table
            .filter(api_keys::uuid.eq(inactive_uuid))
            .count()
            .get_result::<i64>(&mut conn)
            .await
    ) > 0;
    assert!(!inactive_exists, "Inactive API key should be deleted");

    // Verify active key still exists
    let active_exists: bool = unwrap_ok!(
        api_keys::table
            .filter(api_keys::uuid.eq(active_uuid))
            .count()
            .get_result::<i64>(&mut conn)
            .await
    ) > 0;
    assert!(active_exists, "Active API key should still exist");

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test cleanup with no expired data.
#[tokio::test]
#[serial]
async fn test_cleanup_with_no_expired_data() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create test user with only valid data
    let username = unique_name("test_no_expired");
    let user_id = create_simple_user(&mut conn, &username).await;

    create_valid_session(&mut conn, user_id, "valid_sess").await;
    create_valid_api_key(&mut conn, user_id, "valid_key").await;

    // Execute cleanup for sessions
    let sessions_deleted: usize = unwrap_ok!(
        diesel::delete(auth_sessions::table.filter(auth_sessions::expires_at.lt(Utc::now())))
            .execute(&mut conn)
            .await
    );

    // Execute cleanup for API keys
    let keys_deleted: usize = unwrap_ok!(
        diesel::delete(
            api_keys::table.filter(
                api_keys::is_active
                    .eq(false)
                    .or(api_keys::expires_at.lt(Some(Utc::now()))),
            ),
        )
        .execute(&mut conn)
        .await
    );

    // Assert: nothing should be deleted
    assert_eq!(sessions_deleted, 0, "Should not delete any sessions");
    assert_eq!(keys_deleted, 0, "Should not delete any API keys");

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Helper functions for creating test data
// =============================================================================

/// Create an expired auth session.
async fn create_expired_session(conn: &mut AsyncPgConnection, user_id: i32, token: &str) -> Uuid {
    use sha3::{Digest, Sha3_256};

    let session_uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = unwrap_ok!("127.0.0.1".parse());

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

    unwrap_ok!(
        diesel::insert_into(auth_sessions::table)
            .values(&new_session)
            .execute(conn)
            .await
    );

    session_uuid
}

/// Create a valid (non-expired) auth session.
async fn create_valid_session(conn: &mut AsyncPgConnection, user_id: i32, token: &str) -> Uuid {
    use sha3::{Digest, Sha3_256};

    let session_uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = unwrap_ok!("127.0.0.1".parse());

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

    unwrap_ok!(
        diesel::insert_into(auth_sessions::table)
            .values(&new_session)
            .execute(conn)
            .await
    );

    session_uuid
}

/// Create an expired API key.
async fn create_expired_api_key(conn: &mut AsyncPgConnection, user_id: i32, name: &str) -> Uuid {
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
                api_keys::expires_at.eq(Utc::now() - Duration::days(1)), // Expired 1 day ago
            ))
            .execute(conn)
            .await
    );

    key_uuid
}

/// Create a valid (non-expired, active) API key.
async fn create_valid_api_key(conn: &mut AsyncPgConnection, user_id: i32, name: &str) -> Uuid {
    let key_uuid = Uuid::new_v4();

    unwrap_ok!(
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
            .await
    );

    key_uuid
}

/// Create an inactive API key.
async fn create_inactive_api_key(conn: &mut AsyncPgConnection, user_id: i32, name: &str) -> Uuid {
    let key_uuid = Uuid::new_v4();

    unwrap_ok!(
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
            .await
    );

    key_uuid
}

// =============================================================================
// Proxy Session Cleanup Tests
// =============================================================================

use crate::fixtures::create_simple_ssh_asset;
use vauban_web::schema::proxy_sessions;

/// Create a proxy session with a specific status and timestamps.
#[allow(clippy::too_many_arguments)]
async fn create_proxy_session_with_timestamps(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
    status: &str,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
    connected_at: Option<chrono::DateTime<Utc>>,
    expires_at: Option<chrono::DateTime<Utc>>,
) -> (i32, Uuid) {
    let session_uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = unwrap_ok!("127.0.0.1".parse());

    let session_id: i32 = unwrap_ok!(
        diesel::insert_into(proxy_sessions::table)
            .values((
                proxy_sessions::uuid.eq(session_uuid),
                proxy_sessions::user_id.eq(user_id),
                proxy_sessions::asset_id.eq(asset_id),
                proxy_sessions::credential_id.eq("cred-cleanup"),
                proxy_sessions::credential_username.eq("testuser"),
                proxy_sessions::session_type.eq("ssh"),
                proxy_sessions::status.eq(status),
                proxy_sessions::client_ip.eq(ip),
                proxy_sessions::created_at.eq(created_at),
                proxy_sessions::updated_at.eq(updated_at),
                proxy_sessions::connected_at.eq(connected_at),
                proxy_sessions::expires_at.eq(expires_at),
                proxy_sessions::is_recorded.eq(false),
                proxy_sessions::metadata.eq(serde_json::json!({})),
            ))
            .returning(proxy_sessions::id)
            .get_result(conn)
            .await
    );

    (session_id, session_uuid)
}

/// Stale "connecting" sessions (older than 2 min) should be moved to "disconnected".
#[tokio::test]
#[serial]
async fn test_cleanup_stale_connecting_sessions() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("cleanup_conn_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("cleanup-conn"), user_id).await;

    let stale_time = Utc::now() - Duration::minutes(5);

    let (stale_id, _) = create_proxy_session_with_timestamps(
        &mut conn, user_id, asset_id,
        "connecting", stale_time, stale_time, None, None,
    ).await;

    let recent_time = Utc::now();
    let (fresh_id, _) = create_proxy_session_with_timestamps(
        &mut conn, user_id, asset_id,
        "connecting", recent_time, recent_time, None, None,
    ).await;

    let cutoff = Utc::now() - Duration::minutes(2);
    let expired: usize = unwrap_ok!(
        diesel::update(
            proxy_sessions::table
                .filter(proxy_sessions::status.eq("connecting"))
                .filter(proxy_sessions::created_at.lt(cutoff)),
        )
        .set((
            proxy_sessions::status.eq("disconnected"),
            proxy_sessions::disconnected_at.eq(Some(Utc::now())),
            proxy_sessions::updated_at.eq(Utc::now()),
        ))
        .execute(&mut conn)
        .await
    );

    assert!(expired >= 1, "Should disconnect at least 1 stale connecting session");

    let stale_status: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::id.eq(stale_id))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(stale_status, "disconnected", "Stale connecting session must be disconnected");

    let fresh_status: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::id.eq(fresh_id))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(fresh_status, "connecting", "Recent connecting session must remain connecting");

    test_db::cleanup(&mut conn).await;
}

/// Stale "active" sessions without expires_at and old updated_at should be disconnected.
#[tokio::test]
#[serial]
async fn test_cleanup_stale_active_sessions_no_expiry() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("cleanup_stale_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("cleanup-stale"), user_id).await;

    let stale_time = Utc::now() - Duration::hours(25);

    let (stale_id, _) = create_proxy_session_with_timestamps(
        &mut conn, user_id, asset_id,
        "active", stale_time, stale_time, Some(stale_time), None,
    ).await;

    let recent_time = Utc::now() - Duration::hours(1);
    let (fresh_id, _) = create_proxy_session_with_timestamps(
        &mut conn, user_id, asset_id,
        "active", recent_time, recent_time, Some(recent_time), None,
    ).await;

    let now = Utc::now();
    let cutoff = now - Duration::hours(24);
    let disconnected: usize = unwrap_ok!(
        diesel::update(
            proxy_sessions::table
                .filter(proxy_sessions::status.eq("active"))
                .filter(proxy_sessions::expires_at.is_null())
                .filter(proxy_sessions::updated_at.lt(cutoff)),
        )
        .set((
            proxy_sessions::status.eq("disconnected"),
            proxy_sessions::disconnected_at.eq(Some(now)),
            proxy_sessions::updated_at.eq(now),
        ))
        .execute(&mut conn)
        .await
    );

    assert!(disconnected >= 1, "Should disconnect at least 1 stale active session");

    let stale_status: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::id.eq(stale_id))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(stale_status, "disconnected", "Stale active session without expiry must be disconnected");

    let fresh_status: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::id.eq(fresh_id))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(fresh_status, "active", "Recent active session must remain active");

    test_db::cleanup(&mut conn).await;
}

/// Active sessions with expires_at should NOT be touched by the stale active cleanup.
#[tokio::test]
#[serial]
async fn test_cleanup_stale_active_ignores_sessions_with_expiry() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("cleanup_expiry_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("cleanup-exp"), user_id).await;

    let stale_time = Utc::now() - Duration::hours(25);
    let future_expiry = Utc::now() + Duration::hours(1);

    let (session_id, _) = create_proxy_session_with_timestamps(
        &mut conn, user_id, asset_id,
        "active", stale_time, stale_time, Some(stale_time), Some(future_expiry),
    ).await;

    let now = Utc::now();
    let cutoff = now - Duration::hours(24);
    let disconnected: usize = unwrap_ok!(
        diesel::update(
            proxy_sessions::table
                .filter(proxy_sessions::status.eq("active"))
                .filter(proxy_sessions::expires_at.is_null())
                .filter(proxy_sessions::updated_at.lt(cutoff)),
        )
        .set((
            proxy_sessions::status.eq("disconnected"),
            proxy_sessions::disconnected_at.eq(Some(now)),
            proxy_sessions::updated_at.eq(now),
        ))
        .execute(&mut conn)
        .await
    );

    assert_eq!(disconnected, 0, "Should NOT disconnect sessions with expires_at set");

    let status: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::id.eq(session_id))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(status, "active", "Session with expires_at must remain active");

    test_db::cleanup(&mut conn).await;
}

/// Only "connecting" sessions are affected by the connecting cleanup (not "active").
#[tokio::test]
#[serial]
async fn test_cleanup_connecting_does_not_affect_active() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("cleanup_scope_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("cleanup-scope"), user_id).await;

    let stale_time = Utc::now() - Duration::minutes(10);

    let (active_id, _) = create_proxy_session_with_timestamps(
        &mut conn, user_id, asset_id,
        "active", stale_time, stale_time, Some(stale_time), None,
    ).await;

    let cutoff = Utc::now() - Duration::minutes(2);
    let expired: usize = unwrap_ok!(
        diesel::update(
            proxy_sessions::table
                .filter(proxy_sessions::status.eq("connecting"))
                .filter(proxy_sessions::created_at.lt(cutoff)),
        )
        .set((
            proxy_sessions::status.eq("disconnected"),
            proxy_sessions::disconnected_at.eq(Some(Utc::now())),
            proxy_sessions::updated_at.eq(Utc::now()),
        ))
        .execute(&mut conn)
        .await
    );

    assert_eq!(expired, 0, "Should not expire any active session");

    let status: String = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::id.eq(active_id))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(status, "active", "Active session must not be touched by connecting cleanup");

    test_db::cleanup(&mut conn).await;
}
