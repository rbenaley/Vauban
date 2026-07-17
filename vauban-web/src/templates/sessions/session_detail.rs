use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - Session detail template.
use askama::Template;
use chrono::{DateTime, Utc};

/// Session detail data.
#[derive(Debug, Clone)]
pub struct SessionDetail {
    pub id: i32,
    pub uuid: String,
    pub username: String,
    pub user_uuid: String,
    pub asset_name: String,
    pub asset_hostname: String,
    pub asset_uuid: String,
    pub asset_type: String,
    pub session_type: String,
    pub status: String,
    pub credential_id: String,
    pub credential_username: String,
    pub tunnel_target_addr: Option<String>,
    pub client_ip: String,
    pub client_user_agent: Option<String>,
    pub proxy_instance: Option<String>,
    pub connected_at: Option<String>,
    pub disconnected_at: Option<String>,
    pub duration: Option<String>,
    pub justification: Option<String>,
    pub is_recorded: bool,
    pub recording_path: Option<String>,
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub commands_count: i32,
    pub created_at: String,
    pub created_at_raw: DateTime<Utc>,
    pub connected_at_raw: Option<DateTime<Utc>>,
    pub disconnected_at_raw: Option<DateTime<Utc>>,
}

impl SessionDetail {
    fn presentation_input(&self) -> super::presentation::SessionPresentationInput<'_> {
        super::presentation::SessionPresentationInput {
            credential_id: &self.credential_id,
            credential_username: &self.credential_username,
            requester_username: &self.username,
            session_type: &self.session_type,
            tunnel_target_addr: self.tunnel_target_addr.as_deref(),
            status: &self.status,
            created_at: self.created_at_raw,
            connected_at: self.connected_at_raw,
            disconnected_at: self.disconnected_at_raw,
            recording_path: self.recording_path.as_deref(),
            is_recorded: self.is_recorded,
        }
    }

    pub fn credential_display(&self) -> String {
        super::presentation::credential_label(&self.presentation_input())
    }

    pub fn is_jit_grant(&self) -> bool {
        super::presentation::is_jit_grant(&self.credential_id)
    }

    pub fn recording_display(&self) -> &'static str {
        match super::presentation::recording_state(&self.presentation_input()) {
            super::presentation::RecordingState::NotRecorded => "Not recorded",
            super::presentation::RecordingState::Enabled => "Recording enabled",
            super::presentation::RecordingState::Recorded => "Recorded",
        }
    }

    pub fn has_recording_evidence(&self) -> bool {
        !matches!(
            super::presentation::recording_state(&self.presentation_input()),
            super::presentation::RecordingState::NotRecorded
        )
    }

    /// Get status badge class.
    pub fn status_class(&self) -> &str {
        super::session_status_class(&self.status)
    }

    /// Human-friendly status label for the header badge. Mirrors
    /// `SessionListItem::status_display` so the same status renders
    /// the same way across `/sessions`, `/sessions/active`, and the
    /// detail page (the previous `{{ status|capitalize }}` filter
    /// produced the awkward "Tunnel_active" string with a trailing
    /// underscore).
    pub fn status_display(&self) -> String {
        match self.status.as_str() {
            "active" | "tunnel_active" => "Active".to_string(),
            "waiting_client" => "Waiting client".to_string(),
            "disconnected" => "Disconnected".to_string(),
            "completed" => "Completed".to_string(),
            "terminated" => "Terminated".to_string(),
            "pending" => "Pending".to_string(),
            "failed" => "Failed".to_string(),
            "connecting" => "Connecting".to_string(),
            "expired" => "Expired".to_string(),
            "approved" => "Approved".to_string(),
            "consumed" => "Consumed".to_string(),
            other => {
                let mut chars = other.chars();
                match chars.next() {
                    Some(c) => format!("{}{}", c.to_uppercase(), chars.as_str()),
                    None => String::new(),
                }
            }
        }
    }

    /// Get session type badge class.
    pub fn type_class(&self) -> &str {
        match self.session_type.as_str() {
            "ssh" => "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
            "rdp" => "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300",
            "iacs_tunnel" => "bg-amber-100 text-amber-800 dark:bg-amber-900/50 dark:text-amber-300",
            _ => "bg-gray-100 text-gray-800 dark:bg-gray-900/50 dark:text-gray-300",
        }
    }

    /// Short, badge-friendly label for the session type. Mirrors
    /// `SessionListItem::session_type_display` and
    /// `ActiveSessionItem::session_type_label` so the same session
    /// renders with the same token everywhere. Crucially, it
    /// collapses `iacs_tunnel` to `IACS` (the long form overflowed
    /// the fixed-width `h-10 w-10` header badge and visually
    /// overlapped the page title -- the regression we fix here).
    pub fn session_type_display(&self) -> &str {
        match self.session_type.as_str() {
            "ssh" => "SSH",
            "rdp" => "RDP",
            "iacs_tunnel" => "IACS",
            other => other,
        }
    }

    /// Format bytes to human-readable size.
    pub fn format_bytes(bytes: i64) -> String {
        const KB: i64 = 1024;
        const MB: i64 = KB * 1024;
        const GB: i64 = MB * 1024;

        if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} B", bytes)
        }
    }

    /// Get formatted bytes sent.
    pub fn bytes_sent_display(&self) -> String {
        Self::format_bytes(self.bytes_sent)
    }

    /// Get formatted bytes received.
    pub fn bytes_received_display(&self) -> String {
        Self::format_bytes(self.bytes_received)
    }
}

#[derive(Template)]
#[template(path = "sessions/session_detail.html")]
pub struct SessionDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub session: SessionDetail,
    /// Whether to show the "Play Recording" button (only for admin users).
    pub show_play_recording: bool,
    /// Approval detail is admin-only; owners must not receive a dead link.
    pub show_approval_link: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_session_detail(status: &str, session_type: &str) -> SessionDetail {
        SessionDetail {
            id: 1,
            uuid: "session-uuid".to_string(),
            username: "testuser".to_string(),
            user_uuid: "user-uuid".to_string(),
            asset_name: "Test Server".to_string(),
            asset_hostname: "test.example.com".to_string(),
            asset_uuid: "asset-uuid".to_string(),
            asset_type: "linux".to_string(),
            session_type: session_type.to_string(),
            status: status.to_string(),
            credential_id: "local".to_string(),
            credential_username: "admin".to_string(),
            tunnel_target_addr: None,
            client_ip: "192.168.1.100".to_string(),
            client_user_agent: Some("Mozilla/5.0".to_string()),
            proxy_instance: Some("proxy-01".to_string()),
            connected_at: Some("2026-01-03 10:00:00".to_string()),
            disconnected_at: Some("2026-01-03 11:00:00".to_string()),
            duration: Some("1h 0m".to_string()),
            justification: Some("Maintenance".to_string()),
            is_recorded: true,
            recording_path: Some("/recordings/session.cast".to_string()),
            bytes_sent: 10240,
            bytes_received: 20480,
            commands_count: 50,
            created_at: "2026-01-03 09:50:00".to_string(),
            created_at_raw: DateTime::parse_from_rfc3339("2026-01-03T09:50:00Z")
                .unwrap()
                .with_timezone(&Utc),
            connected_at_raw: Some(
                DateTime::parse_from_rfc3339("2026-01-03T10:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
            disconnected_at_raw: Some(
                DateTime::parse_from_rfc3339("2026-01-03T11:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
        }
    }

    // Tests for status_class()
    #[test]
    fn test_status_class_pending() {
        let detail = create_test_session_detail("pending", "ssh");
        assert!(detail.status_class().contains("yellow"));
    }

    #[test]
    fn test_status_class_approved() {
        let detail = create_test_session_detail("approved", "ssh");
        assert!(detail.status_class().contains("green"));
    }

    #[test]
    fn test_status_class_rejected() {
        let detail = create_test_session_detail("rejected", "ssh");
        assert!(detail.status_class().contains("red"));
    }

    #[test]
    fn test_status_class_expired() {
        let detail = create_test_session_detail("expired", "ssh");
        assert!(detail.status_class().contains("gray"));
    }

    #[test]
    fn test_status_class_active() {
        let detail = create_test_session_detail("active", "ssh");
        assert!(detail.status_class().contains("blue"));
    }

    #[test]
    fn test_status_class_consumed() {
        let detail = create_test_session_detail("consumed", "ssh");
        assert!(detail.status_class().contains("blue"));
    }

    #[test]
    fn test_status_class_connecting() {
        let detail = create_test_session_detail("connecting", "ssh");
        assert!(detail.status_class().contains("blue"));
    }

    #[test]
    fn test_status_class_disconnected() {
        let detail = create_test_session_detail("disconnected", "ssh");
        assert!(detail.status_class().contains("indigo"));
    }

    #[test]
    fn test_status_class_completed() {
        let detail = create_test_session_detail("completed", "ssh");
        assert!(detail.status_class().contains("indigo"));
    }

    #[test]
    fn test_status_class_terminated() {
        let detail = create_test_session_detail("terminated", "ssh");
        assert!(detail.status_class().contains("orange"));
    }

    #[test]
    fn test_status_class_unknown() {
        let detail = create_test_session_detail("unknown", "ssh");
        assert!(detail.status_class().contains("gray"));
    }

    // Tests for type_class()
    #[test]
    fn test_type_class_ssh() {
        let detail = create_test_session_detail("active", "ssh");
        assert!(detail.type_class().contains("green"));
    }

    #[test]
    fn test_type_class_rdp() {
        let detail = create_test_session_detail("active", "rdp");
        assert!(detail.type_class().contains("blue"));
    }

    #[test]
    fn test_type_class_unknown() {
        let detail = create_test_session_detail("active", "telnet");
        assert!(detail.type_class().contains("gray"));
    }

    #[test]
    fn test_type_class_iacs_uses_amber() {
        let detail = create_test_session_detail("tunnel_active", "iacs_tunnel");
        assert!(
            detail.type_class().contains("amber"),
            "iacs_tunnel detail badge MUST use the amber palette \
             (consistent with the active list / sessions history)"
        );
    }

    #[test]
    fn test_status_display_tunnel_active_renders_active() {
        let detail = create_test_session_detail("tunnel_active", "iacs_tunnel");
        assert_eq!(detail.status_display(), "Active");
    }

    #[test]
    fn test_status_display_waiting_client_renders_human_friendly() {
        let detail = create_test_session_detail("waiting_client", "iacs_tunnel");
        assert_eq!(
            detail.status_display(),
            "Waiting client",
            "waiting_client must render without the trailing underscore"
        );
    }

    #[test]
    fn test_session_detail_header_collapses_iacs_tunnel_to_short_label() {
        use askama::Template;

        let detail = create_test_session_detail("tunnel_active", "iacs_tunnel");
        let template = SessionDetailTemplate {
            title: "Session #573".to_string(),
            user: Some(UserContext {
                uuid: "u".to_string(),
                username: "alice".to_string(),
                display_name: "Alice".to_string(),
                is_superuser: true,
                is_staff: true,
            }),
            vauban: VaubanConfig {
                brand_name: "VAUBAN".to_string(),
                brand_logo: None,
                theme: "dark".to_string(),
                ..Default::default()
            },
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            session: detail,
            show_play_recording: false,
            show_approval_link: false,
        };
        let html = template.render().expect("render");
        assert!(
            !html.contains("IACS_TUNNEL"),
            "the fixed-width h-10 w-10 badge MUST collapse the long \
             `IACS_TUNNEL` token to the short `IACS` label, otherwise \
             the text overflows onto the page title (issue: visual \
             overlap on /sessions/573)"
        );
        assert!(
            html.contains("IACS"),
            "the badge MUST render the short `IACS` token"
        );
        assert!(
            !html.contains("Tunnel_active"),
            "the status pill MUST NOT show the awkward \
             `Tunnel_active` text from `|capitalize`; use \
             `status_display()` so it reads `Active` instead"
        );
    }

    // Tests for format_bytes()
    #[test]
    fn test_format_bytes_bytes() {
        assert_eq!(SessionDetail::format_bytes(500), "500 B");
    }

    #[test]
    fn test_format_bytes_kilobytes() {
        assert_eq!(SessionDetail::format_bytes(1024), "1.00 KB");
        assert_eq!(SessionDetail::format_bytes(2048), "2.00 KB");
    }

    #[test]
    fn test_format_bytes_megabytes() {
        assert_eq!(SessionDetail::format_bytes(1048576), "1.00 MB");
        assert_eq!(SessionDetail::format_bytes(5242880), "5.00 MB");
    }

    #[test]
    fn test_format_bytes_gigabytes() {
        assert_eq!(SessionDetail::format_bytes(1073741824), "1.00 GB");
    }

    // Tests for bytes_sent_display() and bytes_received_display()
    #[test]
    fn test_bytes_sent_display() {
        let detail = create_test_session_detail("active", "ssh");
        assert_eq!(detail.bytes_sent_display(), "10.00 KB");
    }

    #[test]
    fn test_bytes_received_display() {
        let detail = create_test_session_detail("active", "ssh");
        assert_eq!(detail.bytes_received_display(), "20.00 KB");
    }

    // Tests for SessionDetail struct
    #[test]
    fn test_session_detail_creation() {
        let detail = create_test_session_detail("active", "ssh");
        assert_eq!(detail.id, 1);
        assert!(detail.is_recorded);
    }

    #[test]
    fn test_session_detail_clone() {
        let detail = create_test_session_detail("completed", "rdp");
        let cloned = detail.clone();
        assert_eq!(detail.uuid, cloned.uuid);
    }

    #[test]
    fn test_session_detail_template_renders() {
        let template = SessionDetailTemplate {
            title: "Session Detail".to_string(),
            user: Some(UserContext {
                uuid: "test".to_string(),
                username: "testuser".to_string(),
                display_name: "Test User".to_string(),
                is_superuser: false,
                is_staff: false,
            }),
            vauban: VaubanConfig {
                brand_name: "VAUBAN".to_string(),
                brand_logo: None,
                theme: "dark".to_string(),
                ..Default::default()
            },
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            session: create_test_session_detail("active", "ssh"),
            show_play_recording: true,
            show_approval_link: false,
        };

        let result = template.render();
        assert!(result.is_ok(), "SessionDetailTemplate should render");
    }

    #[test]
    fn test_session_detail_template_renders_without_play_button() {
        let template = SessionDetailTemplate {
            title: "Session Detail".to_string(),
            user: Some(UserContext {
                uuid: "test".to_string(),
                username: "testuser".to_string(),
                display_name: "Test User".to_string(),
                is_superuser: false,
                is_staff: false,
            }),
            vauban: VaubanConfig {
                brand_name: "VAUBAN".to_string(),
                brand_logo: None,
                theme: "dark".to_string(),
                ..Default::default()
            },
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            session: create_test_session_detail("active", "ssh"),
            show_play_recording: false,
            show_approval_link: false,
        };

        assert!(!template.show_play_recording);
        let result = template.render();
        assert!(
            result.is_ok(),
            "SessionDetailTemplate should render without play button"
        );
    }
}
