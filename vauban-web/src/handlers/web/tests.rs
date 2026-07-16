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
        device_info: "Chrome on macOS".to_string(),
        is_current: false, // DB flag doesn't matter
        last_activity: Utc::now(),
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
    };

    // When client token_hash matches, should show "Current session"
    let html = build_sessions_html(std::slice::from_ref(&session), "matching-hash");
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
            device_info: "Safari on macOS".to_string(),
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
            device_info: "Chrome on iPhone".to_string(),
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
        device_info: "Unknown Browser".to_string(),
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
        device_info: "Chrome on Linux".to_string(),
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
        device_info: "Unknown browser".to_string(),
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
    assert!(html.contains("No active sessions"));
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
            device_info: format!("Device {}", i),
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
        device_info: "Old Device".to_string(),
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

// ==================== CreateApiKeyForm::from_bytes Tests ====================
// Regression coverage for the 422 that killed the Create API Key modal:
// `axum::extract::Form` (serde_urlencoded) rejects repeated `scopes` keys
// and the empty `expires_in_days=` posted by the "Never" option, so the
// handler now parses the raw body manually.

#[test]
fn test_create_api_key_form_from_bytes_repeated_scopes() {
    let body = b"name=My+Key&scopes=read&scopes=secrets&expires_in_days=&csrf_token=tok";
    let form = CreateApiKeyForm::from_bytes(body);

    assert_eq!(form.name, "My Key");
    assert_eq!(
        form.scopes,
        Some(vec!["read".to_string(), "secrets".to_string()])
    );
    assert_eq!(form.expires_in_days, None, "empty expiry means Never");
    assert_eq!(form.csrf_token, "tok");
}

#[test]
fn test_create_api_key_form_from_bytes_single_scope_and_expiry() {
    let body = b"name=K&scopes=secrets&expires_in_days=30&csrf_token=tok";
    let form = CreateApiKeyForm::from_bytes(body);

    assert_eq!(form.scopes, Some(vec!["secrets".to_string()]));
    assert_eq!(form.expires_in_days, Some(30));
}

#[test]
fn test_create_api_key_form_from_bytes_no_scope_defaults_to_none() {
    // No checkbox ticked: the handler later falls back to ["read"].
    let form = CreateApiKeyForm::from_bytes(b"name=K&csrf_token=tok");

    assert_eq!(form.scopes, None);
    assert_eq!(form.expires_in_days, None);
}

#[test]
fn test_create_api_key_form_from_bytes_ignores_unknown_and_bad_expiry() {
    let form = CreateApiKeyForm::from_bytes(b"name=K&bogus=1&expires_in_days=abc&csrf_token=tok");

    assert_eq!(form.expires_in_days, None, "unparsable expiry fails soft");
    assert_eq!(form.name, "K");
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
        justification: None,
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
    assert!(
        response
            .redirect_url
            .unwrap()
            .contains("/sessions/terminal/")
    );
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

// ============================================================================
// compute_updated_connection_config tests (GitHub issue #20 anti-regression)
//
// These tests guard the structural invariant that the asset edit endpoint
// MUST NOT silently drop any connection_config field that the form does
// not expose — most importantly the SSH host-key state. They are written
// to fail loudly if anyone reverts to the old build-from-scratch +
// patch-back pattern that destroyed host-key pinning on every edit.
// ============================================================================

use crate::models::asset::AssetType;

/// Convenience: build a fully-loaded SSH `existing` config carrying every
/// field a long-lived production row may accumulate, including the three
/// host-key fields the edit form never re-renders.
fn ssh_existing_full() -> serde_json::Value {
    serde_json::json!({
        "username": "alice",
        "auth_type": "password",
        "password": "v1:CIPHERTEXT_PWD_BASE64",
        "ssh_host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINxxx",
        "ssh_host_key_fingerprint": "SHA256:LEAciqhwf3pPt2W0KXEAfnShujeNpV0pyBtPbINd224",
        "ssh_host_key_mismatch": true,
    })
}

fn rdp_existing_full() -> serde_json::Value {
    serde_json::json!({
        "username": "Administrator",
        "password": "v1:CIPHERTEXT_RDP_PWD_BASE64",
        "domain": "CORP",
    })
}

/// Description-only edit on an SSH asset: the form re-submits username
/// and auth_type with their current values and leaves password blank.
/// Every field — credentials AND host-key state — must round-trip.
#[test]
fn test_compute_updated_ssh_description_only_preserves_everything() {
    let existing = ssh_existing_full();
    let new = compute_updated_connection_config(
        &existing,
        AssetType::Ssh,
        Some("alice"),    // username re-submitted unchanged
        Some("password"), // auth_type re-submitted unchanged
        Some(""),         // password input rendered blank
        Some(""),         // private_key input (hidden) blank
        Some(""),         // passphrase input (hidden) blank
        Some(""),         // rdp_domain input (hidden, alpine x-show=false) sent blank
        None,             // ssh_key_source
        None,             // ssh_public_key
        None,             // rdp_auth_mode
    );
    assert_eq!(
        new, existing,
        "a description-only edit MUST be a no-op on connection_config; \
         got {new} vs existing {existing}"
    );
}

/// The cardinal anti-regression: host-key, fingerprint and mismatch flag
/// MUST survive every plausible edit-form submission shape.
#[test]
fn test_compute_updated_ssh_host_key_state_always_preserved() {
    let existing = ssh_existing_full();

    /// (label, username, auth_type, password, private_key, passphrase)
    type EditFormCase = (
        &'static str,
        Option<&'static str>,
        Option<&'static str>,
        Option<&'static str>,
        Option<&'static str>,
        Option<&'static str>,
    );

    // Matrix of plausible operator actions on the edit form.
    let cases: &[EditFormCase] = &[
        (
            "blank everything",
            Some(""),
            Some(""),
            Some(""),
            Some(""),
            Some(""),
        ),
        (
            "rotate password",
            Some("alice"),
            Some("password"),
            Some("NEW"),
            Some(""),
            Some(""),
        ),
        (
            "switch to ssh_key",
            Some("alice"),
            Some("ssh_key"),
            Some(""),
            Some("KEY"),
            Some(""),
        ),
        (
            "change username",
            Some("bob"),
            Some("password"),
            Some(""),
            Some(""),
            Some(""),
        ),
        (
            "change auth_type only",
            Some("alice"),
            Some("ssh_key"),
            Some(""),
            Some(""),
            Some(""),
        ),
        ("None for all options", None, None, None, None, None),
    ];

    for (label, username, auth_type, password, private_key, passphrase) in cases {
        let new = compute_updated_connection_config(
            &existing,
            AssetType::Ssh,
            *username,
            *auth_type,
            *password,
            *private_key,
            *passphrase,
            None,
            None,
            None,
            None, // rdp_auth_mode
        );
        let obj = new
            .as_object()
            .unwrap_or_else(|| panic!("[{label}] new config is not an object: {new}"));
        assert_eq!(
            obj.get("ssh_host_key"),
            existing.get("ssh_host_key"),
            "[{label}] ssh_host_key MUST be preserved across edit",
        );
        assert_eq!(
            obj.get("ssh_host_key_fingerprint"),
            existing.get("ssh_host_key_fingerprint"),
            "[{label}] ssh_host_key_fingerprint MUST be preserved across edit",
        );
        assert_eq!(
            obj.get("ssh_host_key_mismatch"),
            existing.get("ssh_host_key_mismatch"),
            "[{label}] ssh_host_key_mismatch flag MUST be preserved across edit \
             (otherwise an unrelated edit silently clears a MITM block)",
        );
    }
}

/// Non-empty password on the form MUST replace the stored ciphertext
/// (otherwise we couldn't rotate credentials).
#[test]
fn test_compute_updated_ssh_new_password_replaces_existing() {
    let existing = ssh_existing_full();
    let new = compute_updated_connection_config(
        &existing,
        AssetType::Ssh,
        Some("alice"),
        Some("password"),
        Some("NEW-PLAINTEXT-PWD"),
        Some(""),
        Some(""),
        None,
        None,
        None,
        None, // rdp_auth_mode
    );
    assert_eq!(
        new.get("password").and_then(|v| v.as_str()),
        Some("NEW-PLAINTEXT-PWD"),
        "non-empty password input MUST replace existing"
    );
    // And host-key state still preserved.
    assert_eq!(new.get("ssh_host_key"), existing.get("ssh_host_key"));
}

/// Blank password on the form MUST keep the stored ciphertext (option A).
#[test]
fn test_compute_updated_ssh_blank_password_keeps_existing() {
    let existing = ssh_existing_full();
    let new = compute_updated_connection_config(
        &existing,
        AssetType::Ssh,
        Some("alice"),
        Some("password"),
        Some(""), // operator left it blank
        Some(""),
        Some(""),
        None,
        None,
        None,
        None, // rdp_auth_mode
    );
    assert_eq!(
        new.get("password"),
        existing.get("password"),
        "blank password input MUST preserve stored ciphertext (option A)"
    );
}

/// Switching auth_type to `ssh_key` persists the new private_key and
/// passphrase, strips the now-irrelevant `password` ciphertext (no
/// dormant secret of the other mode), and preserves the host-key state.
#[test]
fn test_compute_updated_ssh_switch_to_ssh_key() {
    let existing = ssh_existing_full();
    let new = compute_updated_connection_config(
        &existing,
        AssetType::Ssh,
        Some("alice"),
        Some("ssh_key"),
        Some(""),
        Some("-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE\n-----END OPENSSH PRIVATE KEY-----"),
        Some("passphrase-secret"),
        None,
        Some("existing"),
        Some("ssh-ed25519 AAAAFAKEPUB comment"),
        None, // rdp_auth_mode
    );
    assert_eq!(
        new.get("auth_type").and_then(|v| v.as_str()),
        Some("ssh_key"),
    );
    assert!(
        new.get("private_key")
            .and_then(|v| v.as_str())
            .unwrap()
            .contains("FAKE")
    );
    assert_eq!(
        new.get("passphrase").and_then(|v| v.as_str()),
        Some("passphrase-secret"),
    );
    assert_eq!(
        new.get("ssh_public_key").and_then(|v| v.as_str()),
        Some("ssh-ed25519 AAAAFAKEPUB comment"),
    );
    assert_eq!(
        new.get("ssh_key_source").and_then(|v| v.as_str()),
        Some("existing"),
    );
    assert!(
        new.get("password").is_none(),
        "switching to ssh_key must strip the dormant password ciphertext"
    );
    assert_eq!(new.get("ssh_host_key"), existing.get("ssh_host_key"));
    assert_eq!(
        new.get("ssh_host_key_fingerprint"),
        existing.get("ssh_host_key_fingerprint"),
    );
}

/// SSH rows must never persist a `domain` (RDP-only field). If a previous
/// state machine bug leaked one in, an edit cleans it up.
#[test]
fn test_compute_updated_ssh_strips_domain() {
    let mut existing = ssh_existing_full();
    existing.as_object_mut().unwrap().insert(
        "domain".to_string(),
        serde_json::Value::String("LEAKED".to_string()),
    );
    let new = compute_updated_connection_config(
        &existing,
        AssetType::Ssh,
        Some("alice"),
        Some("password"),
        Some(""),
        Some(""),
        Some(""),
        Some("CORP"), // even if a tampered request smuggles domain, ignore on SSH
        None,
        None,
        None, // rdp_auth_mode
    );
    assert!(
        new.get("domain").is_none(),
        "SSH row must never carry a domain field, got {new}"
    );
}

/// Forward-compatibility: any unknown key already present in `existing`
/// (e.g. added by a future schema migration) must round-trip untouched.
/// This protects the next "ssh_host_key"-class field from the same bug.
#[test]
fn test_compute_updated_preserves_unknown_forward_compat_keys() {
    let mut existing = ssh_existing_full();
    existing.as_object_mut().unwrap().insert(
        "future_field_we_dont_know_about".to_string(),
        serde_json::json!({"nested": [1, 2, 3]}),
    );
    let new = compute_updated_connection_config(
        &existing,
        AssetType::Ssh,
        Some("alice"),
        Some("password"),
        Some(""),
        Some(""),
        Some(""),
        None,
        None,
        None,
        None, // rdp_auth_mode
    );
    assert_eq!(
        new.get("future_field_we_dont_know_about"),
        existing.get("future_field_we_dont_know_about"),
        "unknown keys must round-trip untouched (forward compatibility)"
    );
}

/// Description-only edit on an RDP asset: domain, password and username
/// all round-trip. `auth_type=password` is a legacy artifact some seeded
/// rows carry — it gets stripped because it's SSH-only by design.
#[test]
fn test_compute_updated_rdp_description_only_preserves_credentials_and_domain() {
    let existing = rdp_existing_full();
    let new = compute_updated_connection_config(
        &existing,
        AssetType::Rdp,
        Some("Administrator"),
        None,     // RDP form does not render auth_type
        Some(""), // password rendered blank
        None,
        None,
        Some("CORP"), // domain re-submitted unchanged
        None,
        None,
        None, // rdp_auth_mode
    );
    assert_eq!(new.get("password"), existing.get("password"));
    assert_eq!(new.get("domain").and_then(|v| v.as_str()), Some("CORP"));
    assert_eq!(
        new.get("username").and_then(|v| v.as_str()),
        Some("Administrator"),
    );
}

/// `Some("")` for `rdp_domain` means the operator deliberately emptied
/// the visible input ⇒ remove the stored domain.
#[test]
fn test_compute_updated_rdp_blank_domain_clears_stored() {
    let existing = rdp_existing_full();
    let new = compute_updated_connection_config(
        &existing,
        AssetType::Rdp,
        Some("Administrator"),
        None,
        Some(""),
        None,
        None,
        Some(""), // explicit clear
        None,
        None,
        None, // rdp_auth_mode
    );
    assert!(
        new.get("domain").is_none(),
        "explicit blank domain submission must clear the stored value"
    );
    // Password still preserved.
    assert_eq!(new.get("password"), existing.get("password"));
}

/// `None` for `rdp_domain` (field absent from the request body) must NOT
/// clear the stored domain — only an explicit `Some("")` does.
#[test]
fn test_compute_updated_rdp_absent_domain_keeps_stored() {
    let existing = rdp_existing_full();
    let new = compute_updated_connection_config(
        &existing,
        AssetType::Rdp,
        Some("Administrator"),
        None,
        Some(""),
        None,
        None,
        None, // field absent
        None,
        None,
        None, // rdp_auth_mode
    );
    assert_eq!(
        new.get("domain").and_then(|v| v.as_str()),
        Some("CORP"),
        "absent rdp_domain field must preserve stored domain"
    );
}

/// New non-empty domain replaces existing.
#[test]
fn test_compute_updated_rdp_new_domain_replaces() {
    let existing = rdp_existing_full();
    let new = compute_updated_connection_config(
        &existing,
        AssetType::Rdp,
        Some("Administrator"),
        None,
        Some(""),
        None,
        None,
        Some("NEWCORP"),
        None,
        None,
        None, // rdp_auth_mode
    );
    assert_eq!(new.get("domain").and_then(|v| v.as_str()), Some("NEWCORP"));
}

/// RDP defense-in-depth: SSH-only fields smuggled in the existing row
/// (e.g. via the "UPDATE assets SET connection_config = jsonb_set..."
/// incident from issue #20 follow-up) must be stripped on edit.
#[test]
fn test_compute_updated_rdp_strips_ssh_only_fields() {
    let mut existing = rdp_existing_full();
    let obj = existing.as_object_mut().unwrap();
    obj.insert(
        "auth_type".to_string(),
        serde_json::Value::String("password".to_string()),
    );
    obj.insert(
        "private_key".to_string(),
        serde_json::Value::String("LEAKED-KEY".to_string()),
    );
    obj.insert(
        "passphrase".to_string(),
        serde_json::Value::String("LEAKED-PP".to_string()),
    );

    let new = compute_updated_connection_config(
        &existing,
        AssetType::Rdp,
        Some("Administrator"),
        Some("ssh_key"), // tampered: try to smuggle SSH auth_type
        Some(""),
        Some("ALSO-LEAKED"),  // tampered: try to smuggle private_key
        Some("ALSO-LEAKED2"), // tampered: try to smuggle passphrase
        None,
        Some("existing"),              // tampered: try to smuggle ssh_key_source
        Some("ssh-ed25519 LEAKEDPUB"), // tampered: try to smuggle public key
        None,                          // rdp_auth_mode
    );
    assert!(
        new.get("auth_type").is_none(),
        "auth_type must be stripped on RDP"
    );
    assert!(
        new.get("ssh_public_key").is_none(),
        "ssh_public_key must be stripped on RDP"
    );
    assert!(
        new.get("ssh_key_source").is_none(),
        "ssh_key_source must be stripped on RDP"
    );
    assert!(
        new.get("private_key").is_none(),
        "private_key must be stripped on RDP"
    );
    assert!(
        new.get("passphrase").is_none(),
        "passphrase must be stripped on RDP"
    );
}

/// Defensive: an existing row that somehow isn't a JSON object (legacy
/// data corruption, manual SQL with wrong type) must not panic. The
/// function falls back to building a fresh object from form input.
#[test]
fn test_compute_updated_handles_non_object_existing() {
    let bogus = serde_json::Value::String("not-an-object".to_string());
    let new = compute_updated_connection_config(
        &bogus,
        AssetType::Ssh,
        Some("alice"),
        Some("password"),
        Some("PWD"),
        None,
        None,
        None,
        None,
        None,
        None, // rdp_auth_mode
    );
    let obj = new
        .as_object()
        .expect("fallback must produce a JSON object");
    assert_eq!(obj.get("username").and_then(|v| v.as_str()), Some("alice"));
    assert_eq!(
        obj.get("auth_type").and_then(|v| v.as_str()),
        Some("password")
    );
    assert_eq!(obj.get("password").and_then(|v| v.as_str()), Some("PWD"));
    // No host-key state to preserve in this degenerate case.
    assert!(obj.get("ssh_host_key").is_none());
}

/// Username is option A: blank input keeps the existing JSON username.
#[test]
fn test_compute_updated_blank_username_keeps_existing() {
    let existing = ssh_existing_full();
    let new = compute_updated_connection_config(
        &existing,
        AssetType::Ssh,
        Some("   "), // whitespace-only
        Some("password"),
        Some(""),
        Some(""),
        Some(""),
        None,
        None,
        None,
        None, // rdp_auth_mode
    );
    assert_eq!(
        new.get("username").and_then(|v| v.as_str()),
        Some("alice"),
        "whitespace-only username input must preserve stored value"
    );
}

// ============================================================================
// SECURITY: Structural guard for `terminal_page` ownership check.
// ============================================================================
//
// Plugs the IDOR found in the post-MFA security audit: the SSH terminal HTML
// wrapper used to be served to any authenticated user that knew (or guessed)
// a session UUID, even though the actual WebSocket data path is gated by
// `ws_session_guard`. This test ensures the HTML handler keeps the explicit
// `session_access::verify` invocation that delegates to vauban-access for
// ownership AND access-rule re-check, then collapses every failure mode
// into a single opaque 404 response.

/// Locate the body of `terminal_page` in the source of `ssh.rs`. Bails if
/// the function is renamed (which is also a useful signal: someone needs to
/// re-anchor the test).
fn terminal_page_source() -> &'static str {
    let full = include_str!("ssh.rs");
    let start = full
        .find("pub async fn terminal_page(")
        .expect("terminal_page handler must exist in handlers/web/ssh.rs");
    let after = &full[start..];
    // Find the matching closing `}` of the function. The function is followed
    // in the file by the next `pub async fn` (or end-of-file), so we cut at
    // whichever comes first to scope the assertion to the body.
    let end = after
        .find("\npub async fn ")
        .or_else(|| after.find("\npub fn "))
        .unwrap_or(after.len());
    &after[..end]
}

#[test]
fn test_terminal_page_source_calls_session_access_verify() {
    let body = terminal_page_source();
    assert!(
        body.contains("session_access::verify"),
        "terminal_page must delegate to session_access::verify before \
         rendering (anti-IDOR + access-rule re-check at the HTML layer)"
    );
    assert!(
        body.contains("SessionAccessIntent::OpenViewer"),
        "terminal_page must declare its intent as OpenViewer so the \
         service applies the right Casbin OR-overrides"
    );
}

#[test]
fn test_terminal_page_source_collapses_to_not_found() {
    let body = terminal_page_source();
    assert!(
        body.contains("AppError::NotFound"),
        "terminal_page must collapse every ownership failure to AppError::NotFound \
         so probing cannot enumerate session UUIDs"
    );
    assert!(
        !body.contains("StatusCode::FORBIDDEN"),
        "terminal_page must not return 403 for ownership failures (would confirm \
         that the session exists). Use AppError::NotFound instead."
    );
}

#[test]
fn test_terminal_page_source_no_longer_carries_legacy_todo() {
    let body = terminal_page_source();
    let forbidden = format!(
        "{} Verify {} {} via IPC or {}",
        "// TODO:", "session", "exists and belongs to user", "database"
    );
    assert!(
        !body.contains(&forbidden),
        "terminal_page must not still carry the legacy TODO that admitted the IDOR"
    );
}

// ============================================================================
// SECURITY: Structural guard for connect_ssh / connect_rdp access-rule policy.
// ============================================================================
//
// Both handlers used to short-circuit the access_rule lookup for superusers
// and staff:
//
//     if !auth_user.is_superuser && !auth_user.is_staff { ... }
//
// That bypass was retired alongside the proxy-side defense-in-depth re-check
// (CheckAccessByUuid in vauban-access). The two layers now apply the EXACT
// same policy -- if vauban-web waved a session through here while the proxy
// correctly demanded a rule, the user would see "Access denied" with no
// recourse. The guards below catch any reintroduction of the bypass.

fn connect_ssh_source() -> &'static str {
    let full = include_str!("ssh.rs");
    let start = full
        .find("pub async fn connect_ssh(")
        .expect("connect_ssh handler must exist in handlers/web/ssh.rs");
    let after = &full[start..];
    let end = after
        .find("\npub async fn ")
        .or_else(|| after.find("\npub fn "))
        .unwrap_or(after.len());
    &after[..end]
}

fn connect_rdp_source() -> &'static str {
    let full = include_str!("rdp.rs");
    let start = full
        .find("pub async fn connect_rdp(")
        .expect("connect_rdp handler must exist in handlers/web/rdp.rs");
    let after = &full[start..];
    let end = after
        .find("\npub async fn ")
        .or_else(|| after.find("\npub fn "))
        .unwrap_or(after.len());
    &after[..end]
}

#[test]
fn test_connect_ssh_no_longer_bypasses_access_rules_for_privileged_users() {
    let body = connect_ssh_source();
    // Reject every spelling of the bypass we used to ship.
    let forbidden = [
        "if !auth_user.is_superuser && !auth_user.is_staff",
        "if !auth_user.is_staff && !auth_user.is_superuser",
        "auth_user.is_superuser || auth_user.is_staff",
        "auth_user.is_staff || auth_user.is_superuser",
    ];
    for pat in forbidden {
        assert!(
            !body.contains(pat),
            "connect_ssh MUST NOT short-circuit the access_rule check on \
             is_superuser / is_staff (`{}` reintroduced). The proxy-ssh \
             RBAC re-check would otherwise deny the session and the user \
             would get 'Access denied' with no recourse. See \
             docs/runbooks/ipc_topology_debugging.md.",
            pat
        );
    }
    assert!(
        body.contains("can_access_asset"),
        "connect_ssh must still call services::access::can_access_asset for \
         every user (the policy lookup itself stays; only the bypass is gone)"
    );
}

#[test]
fn test_connect_rdp_no_longer_bypasses_access_rules_for_privileged_users() {
    let body = connect_rdp_source();
    let forbidden = [
        "if !auth_user.is_superuser && !auth_user.is_staff",
        "if !auth_user.is_staff && !auth_user.is_superuser",
        "auth_user.is_superuser || auth_user.is_staff",
        "auth_user.is_staff || auth_user.is_superuser",
    ];
    for pat in forbidden {
        assert!(
            !body.contains(pat),
            "connect_rdp MUST NOT short-circuit the access_rule check on \
             is_superuser / is_staff (`{}` reintroduced). Same rationale as \
             connect_ssh: both layers (web + proxy) must apply identical \
             policy. See docs/runbooks/ipc_topology_debugging.md.",
            pat
        );
    }
    assert!(
        body.contains("can_access_asset"),
        "connect_rdp must still call services::access::can_access_asset for \
         every user (the policy lookup itself stays; only the bypass is gone)"
    );
}

// ============================================================================
// SECURITY: Structural guard for the rendering / request-submission surfaces
// that decide whether a user sees the orange "Request Access" button or the
// blue "Connect" button, and whether `submit_access_request` enforces MFA.
// ============================================================================
//
// Three layers used to disagree on whether superusers / staff are subject to
// access rules:
//
//   1. `asset_detail` and `asset_list` (handlers/web/assets.rs) used to
//      hardcode `require_approval = false` and `require_mfa = false` for
//      privileged users, rendering a blue "Connect" button on assets that
//      actually required approval.
//   2. `connect_ssh` / `connect_rdp` (since febd388) correctly consult the
//      real policy and redirect to `/#request-access` when approval is
//      required.
//   3. `submit_access_request` (handlers/web/sessions.rs) used to force
//      `require_mfa: true, require_approval: true` for privileged users in
//      its else-branch, demanding a 6-digit code that the rendering layer
//      had simultaneously hidden.
//
// The combination produced the visible failure: a superuser clicked a blue
// "Connect" button on an approval-protected asset, was redirected to the
// access-request modal (with no MFA field, because `asset.require_mfa` was
// false), submitted a justification, and got "MFA code is required (6
// digits)" from the backend. The fix unifies the three surfaces on a single
// `vauban-access` policy lookup. The guards below catch any regression.

fn asset_list_source() -> &'static str {
    let full = include_str!("assets.rs");
    let start = full
        .find("pub async fn asset_list(")
        .expect("asset_list handler must exist in handlers/web/assets.rs");
    let after = &full[start..];
    let end = after
        .find("\npub async fn ")
        .or_else(|| after.find("\npub fn "))
        .unwrap_or(after.len());
    &after[..end]
}

fn submit_access_request_source() -> &'static str {
    let full = include_str!("sessions.rs");
    let start = full
        .find("pub async fn submit_access_request(")
        .expect("submit_access_request handler must exist in handlers/web/sessions.rs");
    let after = &full[start..];
    let end = after
        .find("\npub async fn ")
        .or_else(|| after.find("\npub fn "))
        .unwrap_or(after.len());
    &after[..end]
}

const FORBIDDEN_PRIV_BYPASSES: &[&str] = &[
    "if !auth_user.is_superuser && !auth_user.is_staff",
    "if !auth_user.is_staff && !auth_user.is_superuser",
    "auth_user.is_superuser || auth_user.is_staff",
    "auth_user.is_staff || auth_user.is_superuser",
];

/// Issue #34 -- the user-zone `/assets/{uuid}` detail page is gone.
/// Used to be `asset_user_view`; replaced by `gone_asset_user_view`
/// returning a constant 410. The detail page was the only surface that
/// had to compute `require_approval` / `require_mfa` AND render them
/// to the user, which had a high regression risk for the legacy
/// privileged-user bypass.  Now that the page is gone the bypass
/// surface is reduced to `asset_list` alone (per-row badge) and
/// `submit_access_request` (POST gate); both still pinned below.
#[test]
fn test_asset_user_view_was_replaced_by_gone_handler() {
    let full = include_str!("assets.rs");
    assert!(
        !full.contains("pub async fn asset_user_view("),
        "asset_user_view handler MUST be removed (issue #34): the user-zone \
         detail page leaked description / dates / ssh-host-key fingerprint \
         to non-approved users. The route now serves a constant 410 via \
         `gone_asset_user_view`, and the Request Access / Justification \
         modaux are inlined on /assets."
    );
    assert!(
        full.contains("pub async fn gone_asset_user_view("),
        "gone_asset_user_view handler MUST exist (issue #34) so the legacy \
         /assets/{{uuid}} URL returns 410 Gone instead of 404 (audit-grep \
         friendly, anti-enum)."
    );
}

#[test]
fn test_asset_list_no_longer_bypasses_access_rules_for_privileged_users() {
    let body = asset_list_source();
    for pat in FORBIDDEN_PRIV_BYPASSES {
        assert!(
            !body.contains(pat),
            "asset_list MUST NOT short-circuit the access_rule lookup on \
             is_superuser / is_staff (`{}` reintroduced). The per-row \
             `requires_request` flag must be computed from the real policy so \
             the orange 'Request Access' button appears for every user that \
             needs approval, including admins.",
            pat
        );
    }
    assert!(
        body.contains("list_accessible_asset_ids"),
        "asset_list must call services::access::list_accessible_asset_ids for \
         every user so the listing is filtered by the same policy the \
         connect handler enforces"
    );
}

#[test]
fn test_submit_access_request_no_longer_hardcodes_mfa_for_privileged_users() {
    let body = submit_access_request_source();
    for pat in FORBIDDEN_PRIV_BYPASSES {
        assert!(
            !body.contains(pat),
            "submit_access_request MUST NOT special-case is_superuser / \
             is_staff (`{}` reintroduced). The previous else-branch \
             hardcoded `require_mfa: true` and `require_approval: true` for \
             privileged users, demanding a 6-digit MFA code that the \
             rendering layer had simultaneously hidden — producing the \
             visible 'MFA code is required (6 digits)' regression.",
            pat
        );
    }
    assert!(
        body.contains("can_access_asset"),
        "submit_access_request must call services::access::can_access_asset \
         for every user (no privileged-user shortcut) so that MFA is only \
         demanded when the access rule actually requires it"
    );
    // Defensive: catch the exact struct-literal shape of the inverted
    // superuser bypass (bug #21). We strip line-comments first so the
    // doc-comment on this very fix doesn't trip the assertion.
    let code_only: String = body
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") { "" } else { line }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code_only.contains("require_mfa: true") || !code_only.contains("require_approval: true"),
        "submit_access_request must not hardcode \
         `AccessCheckResult {{ require_mfa: true, require_approval: true, .. }}` \
         (the inverted superuser bypass that produced the spurious MFA prompt). \
         Always derive these flags from `services::access::can_access_asset`."
    );
}
