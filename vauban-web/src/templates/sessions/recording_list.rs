use crate::templates::accounts::user_list::Pagination;
use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - Recording list template.
use askama::Template;

/// Recording item for list display.
#[derive(Debug, Clone)]
pub struct RecordingListItem {
    pub id: i32,
    pub session_id: i32,
    /// UUID of the parent session, used by the new "Recording Details"
    /// route (`/sessions/recordings/{uuid}`). Populated alongside the
    /// integer `id` for backward compatibility with the legacy
    /// `/sessions/recordings/{id}/play` route.
    pub session_uuid: String,
    pub asset_name: String,
    pub session_type: String,
    /// Raw `proxy_sessions.credential_username` snapshot (may be
    /// empty for IACS PCAP bundles). Rendering goes through
    /// [`Self::identity_display`], never through this field directly.
    pub credential_username: String,
    /// VAUBAN username of the initiating user (joined from `users`).
    pub requester_username: String,
    pub connected_at: Option<String>,
    pub duration_seconds: Option<i64>,
    /// Populated after hydrator finalization; None while pending.
    pub size_human: Option<String>,
    pub recording_path: String,
    pub status: String, // "ready", "recording", "processing"
    /// False for IACS PCAP bundles (download-only).
    pub show_play_recording: bool,
    /// True for IACS PCAP bundles. Surfaces the per-row "Inspect"
    /// link in `recording_list.html`.
    pub show_inspect_capture: bool,
}

impl RecordingListItem {
    pub fn is_iacs_tunnel(&self) -> bool {
        self.session_type == "iacs_tunnel"
    }

    fn identity_pair(&self) -> super::presentation::IdentityPair {
        super::presentation::recording_identity_pair(
            &self.requester_username,
            &self.credential_username,
        )
    }

    /// Whether the row renders the full `requester &rarr; credential`
    /// identity pair (UX-02). False when either side is missing.
    pub fn show_requester_arrow(&self) -> bool {
        self.identity_pair().arrow_requester().is_some()
    }

    /// Trimmed VAUBAN requester username for the arrow rendering.
    /// Empty when [`Self::show_requester_arrow`] is false.
    pub fn requester_display(&self) -> String {
        self.identity_pair()
            .arrow_requester()
            .unwrap_or_default()
            .to_string()
    }

    /// Right-hand identity of the row: the credential username when
    /// present; otherwise the VAUBAN requester alone (IACS PCAP
    /// bundles carry no credential); otherwise the legacy placeholder
    /// (`Not authenticated (IACS tunnel)` / `Unavailable`).
    pub fn identity_display(&self) -> String {
        let pair = self.identity_pair();
        match pair.target {
            super::presentation::DisplayIdentity::Credential(credential) => credential,
            _ => match pair.requester {
                Some(requester) => requester,
                None => super::recording_detail::credential_display(
                    &self.credential_username,
                    &self.session_type,
                ),
            },
        }
    }

    /// Get display name for session type.
    pub fn session_type_display(&self) -> &str {
        match self.session_type.as_str() {
            "ssh" => "SSH",
            "rdp" => "RDP",
            "iacs_tunnel" => "IACS",
            _ => &self.session_type,
        }
    }

    /// Get format based on session type.
    pub fn format(&self) -> &str {
        match self.session_type.as_str() {
            "ssh" => "asciinema",
            "rdp" => "h264-avc",
            "iacs_tunnel" => "pcap-bundle",
            _ => "raw",
        }
    }

    /// Get format display name.
    pub fn format_display(&self) -> &str {
        match self.session_type.as_str() {
            "ssh" => "Asciinema",
            "rdp" => "H.264/AVC",
            "iacs_tunnel" => "PCAP bundle",
            _ => "Raw",
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
#[template(path = "sessions/recording_list.html")]
pub struct RecordingListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub recordings: Vec<RecordingListItem>,
    pub format_filter: Option<String>,
    pub asset_filter: Option<String>,
    pub pagination: Option<Pagination>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_recording_item(session_type: &str, duration: Option<i64>) -> RecordingListItem {
        RecordingListItem {
            id: 1,
            session_id: 100,
            session_uuid: "00000000-0000-0000-0000-000000000100".to_string(),
            asset_name: "Test Asset".to_string(),
            session_type: session_type.to_string(),
            credential_username: "testuser".to_string(),
            requester_username: "alice".to_string(),
            connected_at: Some("2026-01-03 10:00:00".to_string()),
            duration_seconds: duration,
            size_human: None,
            recording_path: "/recordings/test.cast".to_string(),
            status: "ready".to_string(),
            show_play_recording: session_type != "iacs_tunnel",
            show_inspect_capture: session_type == "iacs_tunnel",
        }
    }

    // Tests for session_type_display()
    #[test]
    fn test_session_type_display_ssh() {
        let item = create_test_recording_item("ssh", None);
        assert_eq!(item.session_type_display(), "SSH");
    }

    #[test]
    fn test_session_type_display_rdp() {
        let item = create_test_recording_item("rdp", None);
        assert_eq!(item.session_type_display(), "RDP");
    }

    #[test]
    fn test_session_type_display_iacs() {
        let item = create_test_recording_item("iacs_tunnel", Some(13));
        assert_eq!(item.session_type_display(), "IACS");
        assert_eq!(item.format_display(), "PCAP bundle");
        assert!(!item.show_play_recording);
    }

    #[test]
    fn test_credential_display_iacs_placeholder() {
        assert_eq!(
            crate::templates::sessions::recording_detail::credential_display("", "iacs_tunnel"),
            "Not authenticated (IACS tunnel)"
        );
    }

    #[test]
    fn test_session_type_display_unknown() {
        let item = create_test_recording_item("telnet", None);
        assert_eq!(item.session_type_display(), "telnet");
    }

    // Tests for format()
    #[test]
    fn test_format_ssh() {
        let item = create_test_recording_item("ssh", None);
        assert_eq!(item.format(), "asciinema");
    }

    #[test]
    fn test_format_rdp() {
        let item = create_test_recording_item("rdp", None);
        assert_eq!(item.format(), "h264-avc");
    }

    #[test]
    fn test_format_unknown() {
        let item = create_test_recording_item("telnet", None);
        assert_eq!(item.format(), "raw");
    }

    // Tests for format_display()
    #[test]
    fn test_format_display_ssh() {
        let item = create_test_recording_item("ssh", None);
        assert_eq!(item.format_display(), "Asciinema");
    }

    #[test]
    fn test_format_display_rdp() {
        let item = create_test_recording_item("rdp", None);
        assert_eq!(item.format_display(), "H.264/AVC");
    }

    #[test]
    fn test_format_display_unknown() {
        let item = create_test_recording_item("telnet", None);
        assert_eq!(item.format_display(), "Raw");
    }

    // Tests for duration_display()
    #[test]
    fn test_duration_display_hours() {
        let item = create_test_recording_item("ssh", Some(7265)); // 2h 1m 5s
        assert_eq!(item.duration_display(), "2h 1m");
    }

    #[test]
    fn test_duration_display_minutes() {
        let item = create_test_recording_item("ssh", Some(185)); // 3m 5s
        assert_eq!(item.duration_display(), "3m 5s");
    }

    #[test]
    fn test_duration_display_seconds() {
        let item = create_test_recording_item("ssh", Some(30));
        assert_eq!(item.duration_display(), "30s");
    }

    #[test]
    fn test_duration_display_none() {
        let item = create_test_recording_item("ssh", None);
        assert_eq!(item.duration_display(), "-");
    }

    #[test]
    fn test_duration_display_zero() {
        let item = create_test_recording_item("ssh", Some(0));
        assert_eq!(item.duration_display(), "0s");
    }

    // Tests for RecordingListItem struct
    #[test]
    fn test_recording_list_item_creation() {
        let item = create_test_recording_item("ssh", Some(100));
        assert_eq!(item.id, 1);
        assert_eq!(item.session_id, 100);
        assert_eq!(item.asset_name, "Test Asset");
        assert_eq!(item.status, "ready");
    }

    #[test]
    fn test_recording_list_item_clone() {
        let item = create_test_recording_item("rdp", Some(500));
        let cloned = item.clone();
        assert_eq!(item.id, cloned.id);
        assert_eq!(item.session_type, cloned.session_type);
        assert_eq!(item.recording_path, cloned.recording_path);
    }

    #[test]
    fn test_recording_list_template_renders() {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = RecordingListTemplate {
            title: "Recordings".to_string(),
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
            recordings: vec![create_test_recording_item("ssh", Some(100))],
            format_filter: None,
            asset_filter: None,
            pagination: None,
        };

        let result = template.render();
        assert!(result.is_ok(), "RecordingListTemplate should render");
    }

    fn render_recording_list(
        recordings: Vec<RecordingListItem>,
        format_filter: Option<String>,
        asset_filter: Option<String>,
    ) -> String {
        use crate::templates::base::{UserContext, VaubanConfig};

        let template = RecordingListTemplate {
            title: "Recordings".to_string(),
            user: Some(UserContext {
                uuid: "test".to_string(),
                username: "testuser".to_string(),
                display_name: "Test User".to_string(),
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
            recordings,
            format_filter,
            asset_filter,
            pagination: None,
        };
        template.render().expect("template should render")
    }

    // ============================================================
    // UX-02: requester -> credential identity pair rendering.
    // ============================================================

    #[test]
    fn test_recording_row_renders_requester_arrow_pair() {
        let html = render_recording_list(
            vec![create_test_recording_item("ssh", Some(60))],
            None,
            None,
        );
        assert!(
            html.contains("alice &rarr; testuser"),
            "recording row must render the full `requester &rarr; credential` pair, got: {html}"
        );
        assert!(
            html.contains("VAUBAN user alice connected as testuser"),
            "the pair span must carry the accessible title attribute"
        );
    }

    #[test]
    fn test_recording_row_iacs_without_credential_shows_requester_alone() {
        let mut item = create_test_recording_item("iacs_tunnel", Some(13));
        item.credential_username = String::new();
        let html = render_recording_list(vec![item], None, None);
        assert!(
            !html.contains("&rarr;"),
            "IACS PCAP row without credential must not render the arrow"
        );
        assert!(
            html.contains("alice"),
            "IACS PCAP row must surface the VAUBAN requester alone, got: {html}"
        );
    }

    #[test]
    fn test_recording_row_empty_requester_renders_credential_alone() {
        let mut item = create_test_recording_item("ssh", Some(60));
        item.requester_username = String::new();
        let html = render_recording_list(vec![item], None, None);
        assert!(
            !html.contains("&rarr;"),
            "without a requester the arrow must not render"
        );
        assert!(
            html.contains("testuser"),
            "the credential must still render alone"
        );
    }

    #[test]
    fn test_recording_row_both_missing_falls_back_to_iacs_placeholder() {
        let mut item = create_test_recording_item("iacs_tunnel", Some(13));
        item.credential_username = String::new();
        item.requester_username = String::new();
        let html = render_recording_list(vec![item], None, None);
        assert!(
            html.contains("Not authenticated (IACS tunnel)"),
            "orphan IACS row must keep the legacy placeholder, got: {html}"
        );
    }

    #[test]
    fn test_recording_identity_display_prefers_credential() {
        let item = create_test_recording_item("ssh", None);
        assert_eq!(item.identity_display(), "testuser");
        assert!(item.show_requester_arrow());
        assert_eq!(item.requester_display(), "alice");
    }

    #[test]
    fn test_recording_list_has_ws_trigger_element() {
        let html = render_recording_list(vec![], None, None);
        assert!(
            html.contains("recording-ws-trigger"),
            "rendered recording list must contain recording-ws-trigger element"
        );
    }

    #[test]
    fn test_recording_list_has_container_id() {
        let html = render_recording_list(vec![], None, None);
        assert!(
            html.contains("recordings-list-container"),
            "rendered recording list must contain recordings-list-container"
        );
    }

    #[test]
    fn test_recording_list_trigger_listens_for_recording_ready() {
        let html = render_recording_list(vec![], None, None);
        assert!(
            html.contains("recording_ready"),
            "WS trigger must listen for recording_ready events"
        );
    }

    #[test]
    fn test_recording_list_trigger_targets_container() {
        let html = render_recording_list(vec![], None, None);
        assert!(
            html.contains(r##"hx-target="#recordings-list-container""##),
            "WS trigger must target recordings-list-container"
        );
    }

    #[test]
    fn test_recording_list_trigger_selects_container() {
        let html = render_recording_list(vec![], None, None);
        assert!(
            html.contains(r##"hx-select="#recordings-list-container""##),
            "WS trigger must select recordings-list-container"
        );
    }

    #[test]
    fn test_recording_list_trigger_has_throttle() {
        let html = render_recording_list(vec![], None, None);
        assert!(
            html.contains("throttle:"),
            "WS trigger must have a throttle to avoid excessive refreshes"
        );
    }

    #[test]
    fn test_recording_list_has_periodic_polling() {
        let html = render_recording_list(vec![], None, None);
        assert!(
            html.contains("every 30s"),
            "WS trigger must include periodic polling fallback (every 30s)"
        );
    }

    #[test]
    fn test_recording_list_trigger_uses_outer_html_swap() {
        let html = render_recording_list(vec![], None, None);
        assert!(
            html.contains(r#"hx-swap="outerHTML""#),
            "WS trigger must use outerHTML swap"
        );
    }

    #[test]
    fn test_recording_list_trigger_hidden() {
        let html = render_recording_list(vec![], None, None);
        let trigger_pos = html
            .find("recording-ws-trigger")
            .expect("trigger must exist");
        let surrounding =
            &html[trigger_pos.saturating_sub(200)..std::cmp::min(trigger_pos + 200, html.len())];
        assert!(
            surrounding.contains("hidden"),
            "WS trigger element must be hidden"
        );
    }

    #[test]
    fn test_recording_list_trigger_preserves_format_filter() {
        let html = render_recording_list(vec![], Some("ssh".to_string()), None);
        assert!(
            html.contains("format=ssh"),
            "WS trigger hx-get must preserve format filter, got: {}",
            html.lines()
                .find(|l| l.contains("recording-ws-trigger"))
                .unwrap_or("(not found)")
        );
    }

    #[test]
    fn test_recording_list_trigger_preserves_asset_filter() {
        let html = render_recording_list(vec![], None, Some("prod-server".to_string()));
        assert!(
            html.contains("asset=prod-server"),
            "WS trigger hx-get must preserve asset filter"
        );
    }

    #[test]
    fn test_recording_list_trigger_preserves_both_filters() {
        let html =
            render_recording_list(vec![], Some("rdp".to_string()), Some("myasset".to_string()));
        assert!(
            html.contains("format=rdp") && html.contains("asset=myasset"),
            "WS trigger hx-get must preserve both filters"
        );
    }

    #[test]
    fn test_recording_list_trigger_no_filters_clean_url() {
        let html = render_recording_list(vec![], None, None);
        let trigger_line = html
            .lines()
            .find(|l| l.contains("hx-get") && l.contains("recordings"))
            .expect("hx-get line must exist");
        assert!(
            !trigger_line.contains("format=") && !trigger_line.contains("asset="),
            "without filters, hx-get URL must not contain filter params"
        );
    }

    #[test]
    fn test_recording_list_with_data_shows_items() {
        let items = vec![
            create_test_recording_item("ssh", Some(120)),
            create_test_recording_item("rdp", Some(300)),
        ];
        let html = render_recording_list(items, None, None);
        assert!(
            html.contains("Test Asset"),
            "recording items must appear in rendered output"
        );
        assert!(
            html.contains("recordings-list-container"),
            "container must exist even with data"
        );
        assert!(
            html.contains("recording-ws-trigger"),
            "WS trigger must exist even with data"
        );
    }

    #[test]
    fn test_recording_list_empty_shows_no_recordings() {
        let html = render_recording_list(vec![], None, None);
        assert!(
            html.contains("No recordings"),
            "empty list must show 'No recordings' message"
        );
        assert!(
            html.contains("recordings-list-container"),
            "container must exist even when empty"
        );
    }
}
