use crate::templates::accounts::user_list::Pagination;
use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - Session list template.
use askama::Template;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// Make the `local` / `local_opt` Askama filters resolvable from the
// templates that embed this module's structs (the partial reads
// `{{ connected|local(tz) }}`).
#[allow(unused_imports)]
use crate::utils::filters;

/// Session item for list display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionListItem {
    pub id: i32,
    pub uuid: String,
    pub asset_name: String,
    pub asset_hostname: String,
    pub session_type: String,
    pub status: String,
    pub credential_username: String,
    /// Snapshot of `proxy_sessions.tunnel_target_addr`. For IACS
    /// tunnels this is `host:port` of the industrial asset captured
    /// at session creation. SSH / RDP rows leave it `None`. The
    /// list template uses [`Self::display_identity`] to fall back
    /// to this field when `credential_username` is empty (the IACS
    /// tunnel session by design carries no `credential_username`,
    /// so without this fallback the row collapsed to "iacs_tunnel
    /// &bull; " with no actionable identity).
    pub tunnel_target_addr: Option<String>,
    /// Raw connection timestamp, rendered in the viewer's browser
    /// timezone at the last moment (page render or per-connection
    /// WebSocket render) via the `local` filter. `None` for rows that
    /// never reached the connected state.
    pub connected_at: Option<DateTime<Utc>>,
    pub duration_seconds: Option<i64>,
    pub is_recorded: bool,
}

impl SessionListItem {
    /// Get display name for session type.
    pub fn session_type_display(&self) -> &str {
        match self.session_type.as_str() {
            "ssh" => "SSH",
            "rdp" => "RDP",
            "iacs_tunnel" => "IACS",
            _ => &self.session_type,
        }
    }

    /// Identity to render in the session row metadata. For SSH /
    /// RDP this is the credential username (e.g. `admin`). For IACS
    /// tunnels there is no per-session credential (the `EWS`
    /// authenticates with its own pubkey), so we surface the
    /// industrial endpoint snapshot from `tunnel_target_addr`. Falls
    /// back to a placeholder dash so the row never renders an empty
    /// `&bull; &bull;` sequence even on a malformed legacy entry.
    pub fn display_identity(&self) -> &str {
        if !self.credential_username.is_empty() {
            return self.credential_username.as_str();
        }
        if let Some(addr) = self.tunnel_target_addr.as_deref()
            && !addr.is_empty()
        {
            return addr;
        }
        "-"
    }

    /// Get status badge CSS class.
    pub fn status_class(&self) -> &str {
        super::session_status_class(&self.status)
    }

    /// Get display name for status.
    pub fn status_display(&self) -> String {
        match self.status.as_str() {
            "active" => "Active".to_string(),
            "tunnel_active" => "Active".to_string(),
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

    /// Format duration for display.
    pub fn duration_display(&self) -> String {
        match self.duration_seconds {
            Some(secs) if secs >= 3600 => format!("{}h {}m", secs / 3600, (secs % 3600) / 60),
            Some(secs) if secs >= 60 => format!("{}m {}s", secs / 60, secs % 60),
            Some(secs) => format!("{}s", secs),
            None => "-".to_string(),
        }
    }
}

#[derive(Template)]
#[template(path = "sessions/session_list.html")]
pub struct SessionListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub sessions: Vec<SessionListItem>,
    pub status_filter: Option<String>,
    pub type_filter: Option<String>,
    pub asset_filter: Option<String>,
    /// Whether to show the "View" link (only for admin users).
    pub show_view_link: bool,
    pub pagination: Option<Pagination>,
    /// Whether WebSocket real-time updates are enabled (admin-only, page 1, no filters).
    pub ws_enabled: bool,
    /// Industrial kill-switch (`industrial.enabled`). When `false`,
    /// the IACS option is stripped from the type filter `<select>`
    /// (layer 5) -- the matching DB filter (layer 2) already drops
    /// IACS rows so the affordance would be dead anyway.
    pub industrial_enabled: bool,
    /// Viewer's browser timezone (IANA), used to render `connected_at`
    /// in local time in the embedded `session_list_content.html`
    /// partial. Resolved from the `vbn_tz` cookie via `BrowserTz`.
    pub tz: chrono_tz::Tz,
}

/// Partial widget for the session list content (used for WS pushes).
#[derive(Template)]
#[template(path = "sessions/session_list_content.html")]
pub struct SessionListContentWidget {
    pub sessions: Vec<SessionListItem>,
    pub show_view_link: bool,
    /// Viewer's browser timezone, set per-connection by the WebSocket
    /// handler so the live-pushed `connected_at` renders in local time.
    pub tz: chrono_tz::Tz,
}

/// Serializable payload broadcast on the `SessionsList` channel. The
/// realtime task computes the session rows ONCE per tick and
/// broadcasts this raw data; each subscribed WebSocket connection
/// deserializes it and re-renders the content widget in its own
/// browser timezone (per-connection rendering).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionListPayload {
    pub sessions: Vec<SessionListItem>,
    pub show_view_link: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_session_item(
        session_type: &str,
        status: &str,
        duration: Option<i64>,
    ) -> SessionListItem {
        SessionListItem {
            id: 1,
            uuid: "test-uuid".to_string(),
            asset_name: "Test Asset".to_string(),
            asset_hostname: "test.example.com".to_string(),
            session_type: session_type.to_string(),
            status: status.to_string(),
            credential_username: "testuser".to_string(),
            tunnel_target_addr: None,
            connected_at: Some(
                DateTime::parse_from_rfc3339("2026-01-03T10:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
            duration_seconds: duration,
            is_recorded: true,
        }
    }

    // Tests for session_type_display()
    #[test]
    fn test_session_type_display_ssh() {
        let item = create_test_session_item("ssh", "active", None);
        assert_eq!(item.session_type_display(), "SSH");
    }

    #[test]
    fn test_session_type_display_rdp() {
        let item = create_test_session_item("rdp", "active", None);
        assert_eq!(item.session_type_display(), "RDP");
    }

    #[test]
    fn test_session_type_display_unknown() {
        let item = create_test_session_item("telnet", "active", None);
        assert_eq!(item.session_type_display(), "telnet");
    }

    #[test]
    fn test_session_type_display_iacs_maps_to_short_label() {
        let item = create_test_session_item("iacs_tunnel", "tunnel_active", None);
        assert_eq!(
            item.session_type_display(),
            "IACS",
            "iacs_tunnel must collapse to the short `IACS` label so \
             the row metadata stays compact"
        );
    }

    #[test]
    fn test_status_display_tunnel_active_renders_active() {
        let item = create_test_session_item("iacs_tunnel", "tunnel_active", None);
        assert_eq!(item.status_display(), "Active");
    }

    #[test]
    fn test_status_display_waiting_client_renders_human_friendly() {
        let item = create_test_session_item("iacs_tunnel", "waiting_client", None);
        assert_eq!(
            item.status_display(),
            "Waiting client",
            "waiting_client must render as `Waiting client` (no underscore)"
        );
    }

    #[test]
    fn test_display_identity_falls_back_to_tunnel_target_for_iacs() {
        let mut item = create_test_session_item("iacs_tunnel", "tunnel_active", Some(60));
        item.credential_username = String::new();
        item.tunnel_target_addr = Some("10.42.0.7:502".to_string());
        assert_eq!(
            item.display_identity(),
            "10.42.0.7:502",
            "IACS rows have no credential_username; the row identity \
             must fall back to the tunnel_target_addr snapshot"
        );
    }

    #[test]
    fn test_display_identity_keeps_credential_for_ssh() {
        let item = create_test_session_item("ssh", "active", None);
        assert_eq!(
            item.display_identity(),
            "testuser",
            "SSH rows must keep showing credential_username; IACS \
             fallback only kicks in when credential_username is empty"
        );
    }

    #[test]
    fn test_display_identity_dashes_when_both_missing() {
        let mut item = create_test_session_item("iacs_tunnel", "waiting_client", None);
        item.credential_username = String::new();
        item.tunnel_target_addr = None;
        assert_eq!(
            item.display_identity(),
            "-",
            "Legacy / malformed rows must collapse to `-` so the \
             template never renders an empty bullet sequence"
        );
    }

    // Tests for status_display()
    #[test]
    fn test_status_display_active() {
        let item = create_test_session_item("ssh", "active", None);
        assert_eq!(item.status_display(), "Active");
    }

    #[test]
    fn test_status_display_disconnected() {
        let item = create_test_session_item("ssh", "disconnected", None);
        assert_eq!(item.status_display(), "Disconnected");
    }

    #[test]
    fn test_status_display_completed() {
        let item = create_test_session_item("ssh", "completed", None);
        assert_eq!(item.status_display(), "Completed");
    }

    #[test]
    fn test_status_display_terminated() {
        let item = create_test_session_item("ssh", "terminated", None);
        assert_eq!(item.status_display(), "Terminated");
    }

    #[test]
    fn test_status_display_pending() {
        let item = create_test_session_item("ssh", "pending", None);
        assert_eq!(item.status_display(), "Pending");
    }

    #[test]
    fn test_status_display_failed() {
        let item = create_test_session_item("ssh", "failed", None);
        assert_eq!(item.status_display(), "Failed");
    }

    #[test]
    fn test_status_display_unknown() {
        let item = create_test_session_item("ssh", "unknown_status", None);
        assert_eq!(item.status_display(), "Unknown_status");
    }

    #[test]
    fn test_status_display_connecting() {
        let item = create_test_session_item("ssh", "connecting", None);
        assert_eq!(item.status_display(), "Connecting");
    }

    #[test]
    fn test_status_display_expired() {
        let item = create_test_session_item("ssh", "expired", None);
        assert_eq!(item.status_display(), "Expired");
    }

    #[test]
    fn test_status_display_approved() {
        let item = create_test_session_item("ssh", "approved", None);
        assert_eq!(item.status_display(), "Approved");
    }

    #[test]
    fn test_status_display_consumed() {
        let item = create_test_session_item("ssh", "consumed", None);
        assert_eq!(item.status_display(), "Consumed");
    }

    // Tests for duration_display()
    #[test]
    fn test_duration_display_hours() {
        let item = create_test_session_item("ssh", "active", Some(3661)); // 1h 1m 1s
        assert_eq!(item.duration_display(), "1h 1m");
    }

    #[test]
    fn test_duration_display_minutes() {
        let item = create_test_session_item("ssh", "active", Some(125)); // 2m 5s
        assert_eq!(item.duration_display(), "2m 5s");
    }

    #[test]
    fn test_duration_display_seconds() {
        let item = create_test_session_item("ssh", "active", Some(45));
        assert_eq!(item.duration_display(), "45s");
    }

    #[test]
    fn test_duration_display_none() {
        let item = create_test_session_item("ssh", "active", None);
        assert_eq!(item.duration_display(), "-");
    }

    #[test]
    fn test_duration_display_zero() {
        let item = create_test_session_item("ssh", "active", Some(0));
        assert_eq!(item.duration_display(), "0s");
    }

    // Tests for SessionListItem struct
    #[test]
    fn test_session_list_item_creation() {
        let item = create_test_session_item("ssh", "active", Some(100));
        assert_eq!(item.id, 1);
        assert_eq!(item.uuid, "test-uuid");
        assert_eq!(item.asset_name, "Test Asset");
        assert!(item.is_recorded);
    }

    #[test]
    fn test_session_list_item_clone() {
        let item = create_test_session_item("rdp", "completed", Some(500));
        let cloned = item.clone();
        assert_eq!(item.id, cloned.id);
        assert_eq!(item.session_type, cloned.session_type);
    }

    #[test]
    fn test_session_list_template_renders() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = SessionListTemplate {
            title: "Sessions".to_string(),
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
            sessions: vec![create_test_session_item("ssh", "active", Some(100))],
            status_filter: None,
            type_filter: None,
            asset_filter: None,
            show_view_link: true,
            pagination: None,
            ws_enabled: false,
            industrial_enabled: true,
            tz: chrono_tz::Tz::UTC,
        };

        let result = template.render();
        assert!(result.is_ok(), "SessionListTemplate should render");
    }

    #[test]
    fn test_session_list_template_renders_empty() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = SessionListTemplate {
            title: "Sessions".to_string(),
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
            sessions: Vec::new(),
            status_filter: None,
            type_filter: None,
            asset_filter: None,
            show_view_link: false,
            pagination: None,
            ws_enabled: false,
            industrial_enabled: true,
            tz: chrono_tz::Tz::UTC,
        };

        let result = template.render();
        assert!(result.is_ok(), "Empty SessionListTemplate should render");
    }

    #[test]
    fn test_session_list_show_view_link_admin() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = SessionListTemplate {
            title: "Sessions".to_string(),
            user: Some(UserContext {
                uuid: "admin".to_string(),
                username: "admin".to_string(),
                display_name: "Admin User".to_string(),
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
            sessions: vec![create_test_session_item("ssh", "active", Some(100))],
            status_filter: None,
            type_filter: None,
            asset_filter: None,
            show_view_link: true,
            pagination: None,
            ws_enabled: true,
            industrial_enabled: true,
            tz: chrono_tz::Tz::UTC,
        };

        assert!(template.show_view_link);
        let result = template.render();
        assert!(result.is_ok());
    }

    #[test]
    fn test_session_list_hide_view_link_normal_user() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = SessionListTemplate {
            title: "Sessions".to_string(),
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
            sessions: vec![create_test_session_item("ssh", "active", Some(100))],
            status_filter: None,
            type_filter: None,
            asset_filter: None,
            show_view_link: false,
            pagination: None,
            ws_enabled: false,
            industrial_enabled: true,
            tz: chrono_tz::Tz::UTC,
        };

        assert!(!template.show_view_link);
        let result = template.render();
        assert!(result.is_ok());
    }

    #[test]
    fn test_session_list_content_widget_renders() {
        let widget = SessionListContentWidget {
            sessions: vec![create_test_session_item("ssh", "active", Some(100))],
            show_view_link: true,
            tz: chrono_tz::Tz::UTC,
        };
        let result = widget.render();
        assert!(result.is_ok(), "SessionListContentWidget should render");
        let html = result.unwrap();
        assert!(html.contains("Test Asset"));
        assert!(html.contains("Active"));
    }

    /// Per-connection live rendering: the WebSocket handler re-renders
    /// this content widget with the subscriber's `BrowserTz`. A winter
    /// timestamp (DST-stable) must surface in the connection's zone, not
    /// UTC. Pins the core of the P3 list-broadcast refactor (raw data
    /// broadcast -> per-connection render in local time).
    #[test]
    fn test_session_list_content_widget_localizes_connected_at_per_tz() {
        let widget = SessionListContentWidget {
            // connected_at is pinned to 2026-01-03T10:00:00Z.
            sessions: vec![create_test_session_item("ssh", "active", Some(100))],
            show_view_link: true,
            tz: chrono_tz::Tz::Europe__Paris,
        };
        let html = widget.render().unwrap();
        // 2026-01-03 10:00 UTC -> 11:00 CET (Paris, winter, UTC+01:00).
        assert!(
            html.contains("2026-01-03 11:00 CET"),
            "Paris widget must render connected_at as `2026-01-03 11:00 CET`, got: {html}"
        );
        assert!(
            !html.contains("10:00 UTC") && !html.contains("10:00 CET"),
            "Paris widget must not leak the UTC wall clock for connected_at"
        );
    }

    #[test]
    fn test_session_list_content_no_terminate_button() {
        let widget = SessionListContentWidget {
            sessions: vec![create_test_session_item("ssh", "active", Some(100))],
            show_view_link: true,
            tz: chrono_tz::Tz::UTC,
        };
        let html = widget.render().unwrap();
        assert!(
            !html.contains("Terminate"),
            "Session list must NOT contain a Terminate button (use /sessions/active instead)"
        );
        assert!(
            !html.contains("hx-post"),
            "Session list must NOT contain any hx-post form for termination"
        );
    }

    #[test]
    fn test_session_list_content_widget_renders_empty() {
        let widget = SessionListContentWidget {
            sessions: Vec::new(),
            show_view_link: false,
            tz: chrono_tz::Tz::UTC,
        };
        let result = widget.render();
        assert!(result.is_ok());
        let html = result.unwrap();
        assert!(html.contains("No sessions"));
    }

    #[test]
    fn test_session_list_ws_enabled_renders_ws_connect() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = SessionListTemplate {
            title: "Sessions".to_string(),
            user: Some(UserContext {
                uuid: "admin".to_string(),
                username: "admin".to_string(),
                display_name: "Admin".to_string(),
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
            sessions: Vec::new(),
            status_filter: None,
            type_filter: None,
            asset_filter: None,
            show_view_link: true,
            pagination: None,
            ws_enabled: true,
            industrial_enabled: true,
            tz: chrono_tz::Tz::UTC,
        };

        let html = template.render().unwrap();
        assert!(
            html.contains("ws-connect=\"/ws/sessions/list\""),
            "WS-enabled template must include ws-connect"
        );
        assert!(
            html.contains("Live"),
            "WS-enabled template must show Live badge"
        );
    }

    #[test]
    fn test_session_list_ws_disabled_no_ws_connect() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = SessionListTemplate {
            title: "Sessions".to_string(),
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
            sessions: Vec::new(),
            status_filter: None,
            type_filter: None,
            asset_filter: None,
            show_view_link: false,
            pagination: None,
            ws_enabled: false,
            industrial_enabled: true,
            tz: chrono_tz::Tz::UTC,
        };

        let html = template.render().unwrap();
        assert!(
            !html.contains("ws-connect=\"/ws/sessions/list\""),
            "WS-disabled template must NOT include session list ws-connect"
        );
    }
}
