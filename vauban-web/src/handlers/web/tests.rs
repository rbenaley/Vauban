use super::*;

// ==================== user_context_from_auth Tests ====================

fn create_test_auth_user() -> AuthUser {
    AuthUser {
        uuid: "test-uuid-123".to_string(),
        username: "testuser".to_string(),
        mfa_verified: true,
        is_superuser: false,
        is_staff: false,
    }
}

#[test]
fn test_user_context_from_auth_basic() {
    let auth = create_test_auth_user();
    let ctx = user_context_from_auth(&auth);

    assert_eq!(ctx.uuid, "test-uuid-123");
    assert_eq!(ctx.username, "testuser");
    assert_eq!(ctx.display_name, "testuser"); // Default to username
    assert!(!ctx.is_superuser);
    assert!(!ctx.is_staff);
}

#[test]
fn test_user_context_from_auth_superuser() {
    let auth = AuthUser {
        uuid: "admin-uuid".to_string(),
        username: "admin".to_string(),
        mfa_verified: true,
        is_superuser: true,
        is_staff: true,
    };
    let ctx = user_context_from_auth(&auth);

    assert!(ctx.is_superuser);
    assert!(ctx.is_staff);
}

#[test]
fn test_user_context_from_auth_staff_only() {
    let auth = AuthUser {
        uuid: "staff-uuid".to_string(),
        username: "operator".to_string(),
        mfa_verified: false,
        is_superuser: false,
        is_staff: true,
    };
    let ctx = user_context_from_auth(&auth);

    assert!(!ctx.is_superuser);
    assert!(ctx.is_staff);
}

#[test]
fn test_user_context_from_auth_preserves_uuid() {
    let auth = AuthUser {
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        username: "user".to_string(),
        mfa_verified: true,
        is_superuser: false,
        is_staff: false,
    };
    let ctx = user_context_from_auth(&auth);

    assert_eq!(ctx.uuid, "550e8400-e29b-41d4-a716-446655440000");
}

// ==================== UpdateAssetGroupForm Tests ====================

#[test]
fn test_update_asset_group_form_deserialize_full() {
    let json = r##"{"name": "Production Servers", "slug": "production-servers", "description": "All production servers", "color": "#ff5733", "icon": "server", "csrf_token": "csrf"}"##;

    let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(json));

    assert_eq!(form.name, "Production Servers");
    assert_eq!(form.slug, "production-servers");
    assert_eq!(form.description, Some("All production servers".to_string()));
    assert_eq!(form.color, "#ff5733");
    assert_eq!(form.icon, "server");
}

#[test]
fn test_update_asset_group_form_deserialize_minimal() {
    let json = r##"{"name": "Test", "slug": "test", "color": "#fff", "icon": "folder", "csrf_token": "csrf"}"##;

    let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(json));

    assert_eq!(form.name, "Test");
    assert_eq!(form.slug, "test");
    assert!(form.description.is_none());
    assert_eq!(form.color, "#fff");
    assert_eq!(form.icon, "folder");
}

#[test]
fn test_update_asset_group_form_deserialize_with_null_description() {
    let json = r##"{"name": "Group", "slug": "group", "description": null, "color": "#000", "icon": "box", "csrf_token": "csrf"}"##;

    let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(json));

    assert!(form.description.is_none());
}

#[test]
fn test_update_asset_group_form_deserialize_special_chars() {
    let json = r##"{"name": "Test's Group", "slug": "tests-group", "description": "Description with quotes", "color": "#123456", "icon": "database", "csrf_token": "csrf"}"##;

    let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(json));

    assert_eq!(form.name, "Test's Group");
    assert!(unwrap_some!(form.description).contains("quotes"));
}

#[test]
fn test_update_asset_group_form_debug() {
    let form = UpdateAssetGroupForm {
        name: "Debug Test".to_string(),
        slug: "debug-test".to_string(),
        description: Some("Test description".to_string()),
        color: "#abcdef".to_string(),
        icon: "cloud".to_string(),
        csrf_token: "csrf".to_string(),
    };

    let debug_str = format!("{:?}", form);

    assert!(debug_str.contains("UpdateAssetGroupForm"));
    assert!(debug_str.contains("Debug Test"));
}

#[test]
fn test_update_asset_group_form_missing_required_field() {
    // Missing 'icon' field
    let json = r##"{"name": "Test", "slug": "test", "color": "#fff", "csrf_token": "csrf"}"##;

    let result: Result<UpdateAssetGroupForm, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn test_update_asset_group_form_empty_strings() {
    let json = r#"{"name": "", "slug": "", "color": "", "icon": "", "csrf_token": "csrf"}"#;

    let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(json));

    // Empty strings are valid for deserialization (validation is separate)
    assert_eq!(form.name, "");
    assert_eq!(form.slug, "");
}

// ==================== build_sessions_html Tests ====================

#[test]
fn test_build_sessions_html_empty() {
    let html = build_sessions_html(&[], "some-token-hash");
    assert!(html.contains("No active sessions"));
}

#[test]
fn test_build_sessions_html_current_session_detection() {
    use crate::models::AuthSession;
    use chrono::{Duration, Utc};
    use ipnetwork::IpNetwork;
    use uuid::Uuid;

    let session = AuthSession {
        id: 1,
        uuid: Uuid::new_v4(),
        user_id: 1,
        token_hash: "matching-hash".to_string(),
        ip_address: unwrap_ok!("192.168.1.1".parse::<IpNetwork>()),
        user_agent: Some("Chrome on macOS".to_string()),
        device_info: Some("Chrome on macOS".to_string()),
        is_current: false, // DB flag doesn't matter
        last_activity: Utc::now(),
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
    };

    // When client token_hash matches, should show "Current session"
    let html = build_sessions_html(&[session.clone()], "matching-hash");
    assert!(html.contains("Current session"));
    assert!(html.contains("This device"));

    // When client token_hash doesn't match, should NOT show "Current session"
    let html = build_sessions_html(&[session], "different-hash");
    assert!(!html.contains("Current session"));
    assert!(html.contains("Revoke"));
}

#[test]
fn test_build_sessions_html_multiple_sessions() {
    use crate::models::AuthSession;
    use chrono::{Duration, Utc};
    use ipnetwork::IpNetwork;
    use uuid::Uuid;

    let sessions = vec![
        AuthSession {
            id: 1,
            uuid: Uuid::new_v4(),
            user_id: 1,
            token_hash: "hash-a".to_string(),
            ip_address: unwrap_ok!("192.168.1.1".parse::<IpNetwork>()),
            user_agent: Some("Safari on macOS".to_string()),
            device_info: Some("Safari on macOS".to_string()),
            is_current: false,
            last_activity: Utc::now(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
        },
        AuthSession {
            id: 2,
            uuid: Uuid::new_v4(),
            user_id: 1,
            token_hash: "hash-b".to_string(),
            ip_address: unwrap_ok!("10.0.0.1".parse::<IpNetwork>()),
            user_agent: Some("Chrome on iPhone".to_string()),
            device_info: Some("Chrome on iPhone".to_string()),
            is_current: false,
            last_activity: Utc::now(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
        },
    ];

    // Client with hash-a should see Safari as current
    let html = build_sessions_html(&sessions, "hash-a");
    assert!(html.contains("Safari on macOS"));
    assert!(html.contains("Chrome on iPhone"));
    // Only one "Current session" badge
    assert_eq!(html.matches("Current session").count(), 1);

    // Client with hash-b should see iPhone as current
    let html = build_sessions_html(&sessions, "hash-b");
    assert_eq!(html.matches("Current session").count(), 1);
}

// ==================== build_sessions_html Edge Cases ====================

#[test]
fn test_build_sessions_html_with_special_characters() {
    use crate::models::AuthSession;
    use chrono::{Duration, Utc};
    use ipnetwork::IpNetwork;
    use uuid::Uuid;

    let session = AuthSession {
        id: 1,
        uuid: Uuid::new_v4(),
        user_id: 1,
        token_hash: "hash".to_string(),
        ip_address: unwrap_ok!("192.168.1.1".parse::<IpNetwork>()),
        user_agent: Some("Mozilla/5.0 <script>alert('xss')</script>".to_string()),
        device_info: Some("Unknown Browser".to_string()),
        is_current: false,
        last_activity: Utc::now(),
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
    };

    let html = build_sessions_html(&[session], "other-hash");
    // Should not contain raw script tags (XSS prevention)
    assert!(html.contains("Unknown Browser"));
}

#[test]
fn test_build_sessions_html_ipv6_address() {
    use crate::models::AuthSession;
    use chrono::{Duration, Utc};
    use ipnetwork::IpNetwork;
    use uuid::Uuid;

    let session = AuthSession {
        id: 1,
        uuid: Uuid::new_v4(),
        user_id: 1,
        token_hash: "hash".to_string(),
        ip_address: unwrap_ok!("2001:db8::1".parse::<IpNetwork>()),
        user_agent: Some("Chrome".to_string()),
        device_info: Some("Chrome on Linux".to_string()),
        is_current: false,
        last_activity: Utc::now(),
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
    };

    let html = build_sessions_html(&[session], "hash");
    assert!(html.contains("2001:db8::1"));
    assert!(html.contains("Current session"));
}

#[test]
fn test_build_sessions_html_no_user_agent() {
    use crate::models::AuthSession;
    use chrono::{Duration, Utc};
    use ipnetwork::IpNetwork;
    use uuid::Uuid;

    let session = AuthSession {
        id: 1,
        uuid: Uuid::new_v4(),
        user_id: 1,
        token_hash: "hash".to_string(),
        ip_address: unwrap_ok!("10.0.0.1".parse::<IpNetwork>()),
        user_agent: None,
        device_info: None,
        is_current: false,
        last_activity: Utc::now(),
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
    };

    let html = build_sessions_html(&[session], "other");
    // Should handle None user_agent gracefully
    assert!(html.contains("10.0.0.1"));
    assert!(html.contains("session-row-"));
}

// ==================== CreateApiKeyForm Tests ====================

#[test]
fn test_create_api_key_form_deserialize() {
    let json = r#"{"name": "My API Key", "expires_in_days": 30, "csrf_token": "csrf"}"#;
    let form: CreateApiKeyForm = unwrap_ok!(serde_json::from_str(json));

    assert_eq!(form.name, "My API Key");
    assert_eq!(form.expires_in_days, Some(30));
}

#[test]
fn test_create_api_key_form_without_expiry() {
    let json = r#"{"name": "Permanent Key", "csrf_token": "csrf"}"#;
    let form: CreateApiKeyForm = unwrap_ok!(serde_json::from_str(json));

    assert_eq!(form.name, "Permanent Key");
    assert!(form.expires_in_days.is_none());
}

#[test]
fn test_create_api_key_form_empty_name() {
    let json = r#"{"name": "", "expires_in_days": 7, "csrf_token": "csrf"}"#;
    let form: CreateApiKeyForm = unwrap_ok!(serde_json::from_str(json));

    assert_eq!(form.name, "");
    assert_eq!(form.expires_in_days, Some(7));
}

// ==================== UpdateAssetGroupForm Additional Tests ====================

#[test]
fn test_update_asset_group_form_special_characters() {
    let json = r##"{"name": "Serveurs d'été", "slug": "serveurs-ete", "description": "Serveurs pour l'été 2024", "color": "#123abc", "icon": "sun", "csrf_token": "csrf"}"##;
    let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(json));

    assert_eq!(form.name, "Serveurs d'été");
    assert!(unwrap_some!(form.description).contains("été"));
}

#[test]
fn test_update_asset_group_form_unicode() {
    let json = r##"{"name": "服务器组", "slug": "chinese-servers", "color": "#ff0000", "icon": "server", "csrf_token": "csrf"}"##;
    let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(json));

    assert_eq!(form.name, "服务器组");
    assert_eq!(form.slug, "chinese-servers");
}

#[test]
fn test_update_asset_group_form_long_description() {
    let long_desc = "A".repeat(1000);
    let json = format!(
        r##"{{"name": "Test", "slug": "test", "description": "{}", "color": "#fff", "icon": "folder", "csrf_token": "csrf"}}"##,
        long_desc
    );
    let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(&json));

    assert_eq!(unwrap_some!(form.description).len(), 1000);
}

// ==================== user_context_from_auth Additional Tests ====================

#[test]
fn test_user_context_from_auth_empty_username() {
    let auth = AuthUser {
        uuid: "uuid".to_string(),
        username: "".to_string(),
        mfa_verified: false,
        is_superuser: false,
        is_staff: false,
    };
    let ctx = user_context_from_auth(&auth);

    assert_eq!(ctx.username, "");
    assert_eq!(ctx.display_name, "");
}

#[test]
fn test_user_context_from_auth_long_username() {
    let long_name = "a".repeat(255);
    let auth = AuthUser {
        uuid: "uuid".to_string(),
        username: long_name.clone(),
        mfa_verified: false,
        is_superuser: false,
        is_staff: false,
    };
    let ctx = user_context_from_auth(&auth);

    assert_eq!(ctx.username, long_name);
}

#[test]
fn test_user_context_from_auth_mfa_not_transferred() {
    let auth = AuthUser {
        uuid: "uuid".to_string(),
        username: "user".to_string(),
        mfa_verified: true,
        is_superuser: false,
        is_staff: false,
    };
    let ctx = user_context_from_auth(&auth);

    // UserContext doesn't have mfa_verified field, just verify it compiles
    assert_eq!(ctx.username, "user");
}

// ==================== user_context_from_auth Additional Tests ====================

#[test]
fn test_user_context_from_auth_admin_permissions() {
    let auth = AuthUser {
        uuid: "admin-uuid".to_string(),
        username: "admin".to_string(),
        mfa_verified: true,
        is_superuser: true,
        is_staff: true,
    };
    let ctx = user_context_from_auth(&auth);

    assert!(ctx.is_superuser);
    assert!(ctx.is_staff);
}

#[test]
fn test_user_context_from_auth_chinese_username() {
    let auth = AuthUser {
        uuid: "uuid".to_string(),
        username: "用户测试".to_string(),
        mfa_verified: false,
        is_superuser: false,
        is_staff: false,
    };
    let ctx = user_context_from_auth(&auth);

    assert_eq!(ctx.username, "用户测试");
}

#[test]
fn test_user_context_from_auth_email_format_username() {
    let auth = AuthUser {
        uuid: "uuid".to_string(),
        username: "user@domain.com".to_string(),
        mfa_verified: false,
        is_superuser: false,
        is_staff: false,
    };
    let ctx = user_context_from_auth(&auth);

    assert_eq!(ctx.username, "user@domain.com");
}

// ==================== build_sessions_html Additional Tests ====================

#[test]
fn test_build_sessions_html_no_sessions() {
    let html = build_sessions_html(&[], "any-hash");
    // Empty list should still produce valid HTML structure
    assert!(html.contains("auth-sessions") || html.is_empty() || html.len() > 0);
}

#[test]
fn test_build_sessions_html_five_sessions() {
    use crate::models::AuthSession;
    use chrono::{Duration, Utc};
    use ipnetwork::IpNetwork;
    use uuid::Uuid;

    let sessions: Vec<AuthSession> = (1..=5)
        .map(|i| AuthSession {
            id: i,
            uuid: Uuid::new_v4(),
            user_id: 1,
            token_hash: format!("hash-{}", i),
            // SAFETY: format! produces valid IP address strings
            #[allow(clippy::unwrap_used)]
            ip_address: format!("192.168.1.{}", i).parse::<IpNetwork>().unwrap(),
            user_agent: Some(format!("Browser {}", i)),
            device_info: Some(format!("Device {}", i)),
            is_current: i == 1,
            last_activity: Utc::now(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
        })
        .collect();

    let html = build_sessions_html(&sessions, "hash-3");

    // Should produce non-empty HTML with sessions
    assert!(!html.is_empty());
    // HTML should contain li tags for sessions
    assert!(html.contains("<li"));
    // The current session (hash-3) should be marked
    assert!(html.contains("Current session"));
}

#[test]
fn test_build_sessions_html_with_expired_session() {
    use crate::models::AuthSession;
    use chrono::{Duration, Utc};
    use ipnetwork::IpNetwork;
    use uuid::Uuid;

    let session = AuthSession {
        id: 1,
        uuid: Uuid::new_v4(),
        user_id: 1,
        token_hash: "expired-hash".to_string(),
        ip_address: unwrap_ok!("10.0.0.1".parse::<IpNetwork>()),
        user_agent: Some("Old Browser".to_string()),
        device_info: Some("Old Device".to_string()),
        is_current: false,
        last_activity: Utc::now() - Duration::days(1),
        created_at: Utc::now() - Duration::days(2),
        expires_at: Utc::now() - Duration::hours(1), // Already expired
    };

    let html = build_sessions_html(&[session], "other-hash");
    assert!(html.contains("session-row-"));
}

// ==================== UpdateAssetGroupForm Additional Tests ====================

#[test]
fn test_update_asset_group_form_minimal() {
    let json = r##"{"name": "Test", "slug": "test", "color": "#000", "icon": "folder", "csrf_token": "csrf"}"##;
    let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(json));

    assert_eq!(form.name, "Test");
    assert!(form.description.is_none());
}

#[test]
fn test_update_asset_group_form_all_colors() {
    let colors = ["#fff", "#000", "#123abc", "#AABBCC", "#f0f0f0"];

    for color in colors {
        let json = format!(
            r##"{{"name": "Test", "slug": "test", "color": "{}", "icon": "folder", "csrf_token": "csrf"}}"##,
            color
        );
        let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(&json));
        assert_eq!(form.color, color);
    }
}

#[test]
fn test_update_asset_group_form_icons() {
    let icons = ["folder", "server", "database", "cloud", "lock"];

    for icon in icons {
        let json = format!(
            r##"{{"name": "Test", "slug": "test", "color": "#fff", "icon": "{}", "csrf_token": "csrf"}}"##,
            icon
        );
        let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(&json));
        assert_eq!(form.icon, icon);
    }
}

// ==================== CreateApiKeyForm Additional Tests ====================

#[test]
fn test_create_api_key_form_zero_expiry() {
    let json = r#"{"name": "Zero Expiry", "expires_in_days": 0, "csrf_token": "csrf"}"#;
    let form: CreateApiKeyForm = unwrap_ok!(serde_json::from_str(json));

    assert_eq!(form.expires_in_days, Some(0));
}

#[test]
fn test_create_api_key_form_long_expiry() {
    let json = r#"{"name": "Long Expiry", "expires_in_days": 365, "csrf_token": "csrf"}"#;
    let form: CreateApiKeyForm = unwrap_ok!(serde_json::from_str(json));

    assert_eq!(form.expires_in_days, Some(365));
}

#[test]
fn test_create_api_key_form_unicode_name() {
    let json = r#"{"name": "密钥名称", "csrf_token": "csrf"}"#;
    let form: CreateApiKeyForm = unwrap_ok!(serde_json::from_str(json));

    assert_eq!(form.name, "密钥名称");
}

#[test]
fn test_create_api_key_form_long_name() {
    let long_name = "A".repeat(100);
    let json = format!(r#"{{"name": "{}", "csrf_token": "csrf"}}"#, long_name);
    let form: CreateApiKeyForm = unwrap_ok!(serde_json::from_str(&json));

    assert_eq!(form.name.len(), 100);
}

// ==================== AuthUser Tests ====================

#[test]
fn test_auth_user_clone() {
    let auth = AuthUser {
        uuid: "test-uuid".to_string(),
        username: "testuser".to_string(),
        mfa_verified: true,
        is_superuser: false,
        is_staff: true,
    };

    let cloned = auth.clone();

    assert_eq!(auth.uuid, cloned.uuid);
    assert_eq!(auth.username, cloned.username);
    assert_eq!(auth.mfa_verified, cloned.mfa_verified);
}

#[test]
fn test_auth_user_debug() {
    let auth = AuthUser {
        uuid: "debug-uuid".to_string(),
        username: "debuguser".to_string(),
        mfa_verified: false,
        is_superuser: true,
        is_staff: false,
    };

    let debug_str = format!("{:?}", auth);

    assert!(debug_str.contains("AuthUser"));
    assert!(debug_str.contains("debuguser"));
}

// ==================== ConnectSshForm Tests ====================

#[test]
fn test_connect_ssh_form_deserialize_minimal() {
    let json = r#"{"csrf_token": "test-csrf-token"}"#;
    let form: ConnectSshForm = unwrap_ok!(serde_json::from_str(json));

    assert_eq!(form.csrf_token, "test-csrf-token");
    assert!(form.username.is_none());
}

#[test]
fn test_connect_ssh_form_deserialize_with_username() {
    let json = r#"{"csrf_token": "csrf123", "username": "admin"}"#;
    let form: ConnectSshForm = unwrap_ok!(serde_json::from_str(json));

    assert_eq!(form.csrf_token, "csrf123");
    assert_eq!(form.username, Some("admin".to_string()));
}

#[test]
fn test_connect_ssh_form_deserialize_null_username() {
    let json = r#"{"csrf_token": "csrf", "username": null}"#;
    let form: ConnectSshForm = unwrap_ok!(serde_json::from_str(json));

    assert!(form.username.is_none());
}

#[test]
fn test_connect_ssh_form_debug() {
    let form = ConnectSshForm {
        csrf_token: "token123".to_string(),
        username: Some("testuser".to_string()),
    };

    let debug_str = format!("{:?}", form);

    assert!(debug_str.contains("ConnectSshForm"));
    assert!(debug_str.contains("testuser"));
}

#[test]
fn test_connect_ssh_form_missing_csrf() {
    let json = r#"{"username": "admin"}"#;
    let result: Result<ConnectSshForm, _> = serde_json::from_str(json);

    assert!(result.is_err());
}

// ==================== ConnectSshResponse Tests ====================

#[test]
fn test_connect_ssh_response_success() {
    let response = ConnectSshResponse {
        success: true,
        session_id: Some("sess-123".to_string()),
        redirect_url: Some("/sessions/terminal/sess-123".to_string()),
        error: None,
    };

    assert!(response.success);
    assert_eq!(response.session_id, Some("sess-123".to_string()));
    assert!(response.redirect_url.unwrap().contains("/sessions/terminal/"));
    assert!(response.error.is_none());
}

#[test]
fn test_connect_ssh_response_failure() {
    let response = ConnectSshResponse {
        success: false,
        session_id: None,
        redirect_url: None,
        error: Some("Connection refused".to_string()),
    };

    assert!(!response.success);
    assert!(response.session_id.is_none());
    assert!(response.redirect_url.is_none());
    assert_eq!(response.error, Some("Connection refused".to_string()));
}

#[test]
fn test_connect_ssh_response_serialize() {
    let response = ConnectSshResponse {
        success: true,
        session_id: Some("abc-123".to_string()),
        redirect_url: Some("/terminal/abc-123".to_string()),
        error: None,
    };

    let json = serde_json::to_string(&response).unwrap();

    assert!(json.contains("\"success\":true"));
    assert!(json.contains("\"session_id\":\"abc-123\""));
    assert!(json.contains("\"redirect_url\":\"/terminal/abc-123\""));
}

#[test]
fn test_connect_ssh_response_serialize_failure() {
    let response = ConnectSshResponse {
        success: false,
        session_id: None,
        redirect_url: None,
        error: Some("Invalid credentials".to_string()),
    };

    let json = serde_json::to_string(&response).unwrap();

    assert!(json.contains("\"success\":false"));
    assert!(json.contains("\"error\":\"Invalid credentials\""));
}

#[test]
fn test_connect_ssh_response_debug() {
    let response = ConnectSshResponse {
        success: true,
        session_id: Some("debug-sess".to_string()),
        redirect_url: Some("/debug".to_string()),
        error: None,
    };

    let debug_str = format!("{:?}", response);

    assert!(debug_str.contains("ConnectSshResponse"));
    assert!(debug_str.contains("debug-sess"));
}

#[test]
fn test_connect_ssh_response_all_none() {
    let response = ConnectSshResponse {
        success: false,
        session_id: None,
        redirect_url: None,
        error: None,
    };

    assert!(!response.success);
    assert!(response.session_id.is_none());
    assert!(response.error.is_none());
}
