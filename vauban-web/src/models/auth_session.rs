/// VAUBAN Web - Auth session model.
///
/// Tracks active user login sessions (JWT tokens) for session management.
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use ipnetwork::IpNetwork;
use serde::Serialize;
use uuid::Uuid;

use crate::schema::auth_sessions;

/// Auth session database model.
#[derive(Debug, Clone, Queryable, Selectable, Identifiable)]
#[diesel(table_name = auth_sessions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AuthSession {
    pub id: i32,
    pub uuid: Uuid,
    pub user_id: i32,
    pub token_hash: String,
    pub ip_address: IpNetwork,
    pub user_agent: Option<String>,
    pub device_info: Option<String>,
    pub last_activity: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_current: bool,
    pub created_at: DateTime<Utc>,
}

/// Auth session DTO for templates (serializable).
#[derive(Debug, Clone, Serialize)]
pub struct AuthSessionDto {
    pub uuid: Uuid,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub device_info: Option<String>,
    pub last_activity: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_current: bool,
    pub created_at: DateTime<Utc>,
}

/// New auth session for insertion.
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = auth_sessions)]
pub struct NewAuthSession {
    pub uuid: Uuid,
    pub user_id: i32,
    pub token_hash: String,
    pub ip_address: IpNetwork,
    pub user_agent: Option<String>,
    pub device_info: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub is_current: bool,
}

impl AuthSession {
    /// Convert to DTO for templates.
    pub fn to_dto(&self) -> AuthSessionDto {
        AuthSessionDto {
            uuid: self.uuid,
            ip_address: self.ip_address.ip().to_string(),
            user_agent: self.user_agent.clone(),
            device_info: self.device_info.clone(),
            last_activity: self.last_activity,
            expires_at: self.expires_at,
            is_current: self.is_current,
            created_at: self.created_at,
        }
    }

    /// Check if the session has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    /// Get a human-readable description of the session age.
    pub fn age_display(&self) -> String {
        let duration = Utc::now().signed_duration_since(self.created_at);
        if duration.num_days() > 0 {
            format!("{} days ago", duration.num_days())
        } else if duration.num_hours() > 0 {
            format!("{} hours ago", duration.num_hours())
        } else if duration.num_minutes() > 0 {
            format!("{} minutes ago", duration.num_minutes())
        } else {
            "Just now".to_string()
        }
    }

    /// Get a human-readable description of last activity.
    pub fn last_activity_display(&self) -> String {
        let duration = Utc::now().signed_duration_since(self.last_activity);
        if duration.num_days() > 0 {
            format!("{} days ago", duration.num_days())
        } else if duration.num_hours() > 0 {
            format!("{} hours ago", duration.num_hours())
        } else if duration.num_minutes() > 0 {
            format!("{} minutes ago", duration.num_minutes())
        } else {
            "Just now".to_string()
        }
    }

    /// Parse user agent to get device info.
    pub fn parse_device_info(user_agent: &str) -> String {
        // Simple parsing - in production, use a proper UA parser
        if user_agent.contains("Safari") && !user_agent.contains("Chrome") {
            if user_agent.contains("iPhone") {
                "Safari on iPhone".to_string()
            } else if user_agent.contains("iPad") {
                "Safari on iPad".to_string()
            } else if user_agent.contains("Macintosh") {
                "Safari on macOS".to_string()
            } else {
                "Safari".to_string()
            }
        } else if user_agent.contains("Chrome") {
            if user_agent.contains("Android") {
                "Chrome on Android".to_string()
            } else if user_agent.contains("Windows") {
                "Chrome on Windows".to_string()
            } else if user_agent.contains("Macintosh") {
                "Chrome on macOS".to_string()
            } else if user_agent.contains("Linux") {
                "Chrome on Linux".to_string()
            } else {
                "Chrome".to_string()
            }
        } else if user_agent.contains("Firefox") {
            if user_agent.contains("Windows") {
                "Firefox on Windows".to_string()
            } else if user_agent.contains("Macintosh") {
                "Firefox on macOS".to_string()
            } else if user_agent.contains("Linux") {
                "Firefox on Linux".to_string()
            } else {
                "Firefox".to_string()
            }
        } else if user_agent.contains("Edge") {
            "Microsoft Edge".to_string()
        } else {
            "Unknown browser".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    

    fn create_test_session() -> AuthSession {
        AuthSession {
            id: 1,
            uuid: Uuid::new_v4(),
            user_id: 1,
            token_hash: "abc123".to_string(),
            ip_address: unwrap_ok!(IpNetwork::new(IpAddr::from([127, 0, 0, 1]), 32)),
            user_agent: Some("Mozilla/5.0".to_string()),
            device_info: Some("Chrome on macOS".to_string()),
            last_activity: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
            is_current: true,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_session_not_expired() {
        let session = create_test_session();
        assert!(!session.is_expired());
    }

    #[test]
    fn test_session_expired() {
        let mut session = create_test_session();
        session.expires_at = Utc::now() - chrono::Duration::hours(1);
        assert!(session.is_expired());
    }

    #[test]
    fn test_parse_device_info_safari_macos() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";
        assert_eq!(AuthSession::parse_device_info(ua), "Safari on macOS");
    }

    #[test]
    fn test_parse_device_info_chrome_windows() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        assert_eq!(AuthSession::parse_device_info(ua), "Chrome on Windows");
    }

    #[test]
    fn test_parse_device_info_firefox_linux() {
        let ua = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0";
        assert_eq!(AuthSession::parse_device_info(ua), "Firefox on Linux");
    }

    #[test]
    fn test_age_display_just_now() {
        let session = create_test_session();
        assert_eq!(session.age_display(), "Just now");
    }

    // ==================== AuthSession Additional Tests ====================

    #[test]
    fn test_auth_session_clone() {
        let session = create_test_session();
        let cloned = session.clone();
        assert_eq!(session.uuid, cloned.uuid);
        assert_eq!(session.token_hash, cloned.token_hash);
    }

    #[test]
    fn test_auth_session_debug() {
        let session = create_test_session();
        let debug_str = format!("{:?}", session);
        assert!(debug_str.contains("AuthSession"));
    }

    // ==================== to_dto Tests ====================

    #[test]
    fn test_to_dto_fields() {
        let session = create_test_session();
        let dto = session.to_dto();

        assert_eq!(dto.uuid, session.uuid);
        assert_eq!(dto.ip_address, "127.0.0.1");
        assert_eq!(dto.user_agent, session.user_agent);
        assert_eq!(dto.device_info, session.device_info);
        assert_eq!(dto.is_current, session.is_current);
    }

    #[test]
    fn test_to_dto_ipv6() {
        let mut session = create_test_session();
        session.ip_address = unwrap_ok!(IpNetwork::new(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]), 128));

        let dto = session.to_dto();
        assert_eq!(dto.ip_address, "::1");
    }

    // ==================== age_display Tests ====================

    #[test]
    fn test_age_display_minutes() {
        let mut session = create_test_session();
        session.created_at = Utc::now() - chrono::Duration::minutes(30);

        assert!(session.age_display().contains("minutes ago"));
    }

    #[test]
    fn test_age_display_hours() {
        let mut session = create_test_session();
        session.created_at = Utc::now() - chrono::Duration::hours(5);

        assert!(session.age_display().contains("hours ago"));
    }

    #[test]
    fn test_age_display_days() {
        let mut session = create_test_session();
        session.created_at = Utc::now() - chrono::Duration::days(3);

        assert!(session.age_display().contains("days ago"));
    }

    // ==================== last_activity_display Tests ====================

    #[test]
    fn test_last_activity_display_just_now() {
        let session = create_test_session();
        assert_eq!(session.last_activity_display(), "Just now");
    }

    #[test]
    fn test_last_activity_display_minutes() {
        let mut session = create_test_session();
        session.last_activity = Utc::now() - chrono::Duration::minutes(15);

        assert!(session.last_activity_display().contains("minutes ago"));
    }

    #[test]
    fn test_last_activity_display_hours() {
        let mut session = create_test_session();
        session.last_activity = Utc::now() - chrono::Duration::hours(2);

        assert!(session.last_activity_display().contains("hours ago"));
    }

    #[test]
    fn test_last_activity_display_days() {
        let mut session = create_test_session();
        session.last_activity = Utc::now() - chrono::Duration::days(7);

        assert!(session.last_activity_display().contains("days ago"));
    }

    // ==================== parse_device_info Additional Tests ====================

    #[test]
    fn test_parse_device_info_safari_iphone() {
        let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
        assert_eq!(AuthSession::parse_device_info(ua), "Safari on iPhone");
    }

    #[test]
    fn test_parse_device_info_safari_ipad() {
        let ua = "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
        assert_eq!(AuthSession::parse_device_info(ua), "Safari on iPad");
    }

    #[test]
    fn test_parse_device_info_safari_generic() {
        let ua = "Mozilla/5.0 (Unknown; Safari) AppleWebKit/605.1.15 Safari/605.1.15";
        assert_eq!(AuthSession::parse_device_info(ua), "Safari");
    }

    #[test]
    fn test_parse_device_info_chrome_android() {
        let ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36";
        assert_eq!(AuthSession::parse_device_info(ua), "Chrome on Android");
    }

    #[test]
    fn test_parse_device_info_chrome_macos() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        assert_eq!(AuthSession::parse_device_info(ua), "Chrome on macOS");
    }

    #[test]
    fn test_parse_device_info_chrome_linux() {
        let ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        assert_eq!(AuthSession::parse_device_info(ua), "Chrome on Linux");
    }

    #[test]
    fn test_parse_device_info_chrome_generic() {
        let ua = "Mozilla/5.0 (Unknown) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0";
        assert_eq!(AuthSession::parse_device_info(ua), "Chrome");
    }

    #[test]
    fn test_parse_device_info_firefox_windows() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0";
        assert_eq!(AuthSession::parse_device_info(ua), "Firefox on Windows");
    }

    #[test]
    fn test_parse_device_info_firefox_macos() {
        let ua =
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0";
        assert_eq!(AuthSession::parse_device_info(ua), "Firefox on macOS");
    }

    #[test]
    fn test_parse_device_info_firefox_generic() {
        let ua = "Mozilla/5.0 (Unknown; rv:121.0) Gecko/20100101 Firefox/121.0";
        assert_eq!(AuthSession::parse_device_info(ua), "Firefox");
    }

    #[test]
    fn test_parse_device_info_edge() {
        // Edge is detected only if UA contains "Edge" but not Safari/Chrome/Firefox
        // This is a simplified test case that matches the current implementation
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0.0.0";
        assert_eq!(AuthSession::parse_device_info(ua), "Microsoft Edge");
    }

    #[test]
    fn test_parse_device_info_unknown() {
        let ua = "Some/Unknown/Browser/1.0";
        assert_eq!(AuthSession::parse_device_info(ua), "Unknown browser");
    }

    #[test]
    fn test_parse_device_info_empty() {
        let ua = "";
        assert_eq!(AuthSession::parse_device_info(ua), "Unknown browser");
    }

    // ==================== is_expired Edge Cases ====================

    #[test]
    fn test_is_expired_exactly_now() {
        let mut session = create_test_session();
        // Set expires_at to a time in the past
        session.expires_at = Utc::now() - chrono::Duration::seconds(1);
        assert!(session.is_expired());
    }

    // ==================== AuthSessionDto Tests ====================

    #[test]
    fn test_auth_session_dto_debug() {
        let session = create_test_session();
        let dto = session.to_dto();

        let debug_str = format!("{:?}", dto);
        assert!(debug_str.contains("AuthSessionDto"));
    }

    #[test]
    fn test_auth_session_dto_clone() {
        let session = create_test_session();
        let dto = session.to_dto();
        let cloned = dto.clone();

        assert_eq!(dto.uuid, cloned.uuid);
    }

    #[test]
    fn test_auth_session_dto_serialize() {
        let session = create_test_session();
        let dto = session.to_dto();

        let json = unwrap_ok!(serde_json::to_string(&dto));
        assert!(json.contains("127.0.0.1"));
    }

    // ==================== NewAuthSession Tests ====================

    #[test]
    fn test_new_auth_session_debug() {
        let new_session = NewAuthSession {
            uuid: Uuid::new_v4(),
            user_id: 1,
            token_hash: "newhash".to_string(),
            ip_address: unwrap_ok!(IpNetwork::new(IpAddr::from([192, 168, 1, 1]), 32)),
            user_agent: Some("Test/1.0".to_string()),
            device_info: Some("Test Device".to_string()),
            expires_at: Utc::now() + chrono::Duration::hours(24),
            is_current: true,
        };

        let debug_str = format!("{:?}", new_session);
        assert!(debug_str.contains("NewAuthSession"));
    }

    #[test]
    fn test_new_auth_session_clone() {
        let new_session = NewAuthSession {
            uuid: Uuid::new_v4(),
            user_id: 2,
            token_hash: "clonehash".to_string(),
            ip_address: unwrap_ok!(IpNetwork::new(IpAddr::from([10, 0, 0, 1]), 32)),
            user_agent: None,
            device_info: None,
            expires_at: Utc::now() + chrono::Duration::hours(48),
            is_current: false,
        };

        let cloned = new_session.clone();
        assert_eq!(new_session.token_hash, cloned.token_hash);
    }
}
