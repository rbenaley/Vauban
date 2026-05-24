/// VAUBAN Web - Recording detail template.
///
/// Recording-centric page (issue #29 / UX-28). Replaces the old
/// "View" button on the recordings list which jumped to a
/// session-centric page and broke the sidebar breadcrumb.
///
/// Authorization: gated by `admin_view`, same as the rest of the
/// recording family. Anti-enumeration: any 404-class denial returns
/// the same generic 404 from the handler (see
/// [`crate::handlers::web::recording_detail`]).
use askama::Template;

use crate::auth::PermissionContext;
use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Approval / rejection narrative for the Session Context card.
///
/// Only one variant is rendered at a time, driven by the row's
/// `status`/`approved_by_id`/`rejected_by_id` columns. `Awaiting`
/// keeps the layout balanced when a session is recorded but the
/// approval row was created before the SoD migration backfilled.
#[derive(Debug, Clone)]
pub enum ApprovalNarrative {
    Approved {
        approver_username: String,
        approved_at_utc: String,
    },
    Rejected {
        rejecter_username: String,
        rejected_at_utc: String,
        reason: Option<String>,
    },
    Awaiting,
}

/// Integrity bundle as exposed to the template. Mirrors
/// [`crate::services::recording_hydrator::IntegrityBundle`] with
/// pre-formatted strings so the template stays logic-free.
#[derive(Debug, Clone)]
pub struct IntegrityViewModel {
    pub blake3_hex: String,
    pub blake3_truncated: String,
    pub size_human: String,
    pub duration_human: String,
    pub format: String,
    pub format_label: String,
    pub width: i16,
    pub height: i16,
    pub event_count: Option<i32>,
    pub segment_count: Option<i32>,
    pub codec: Option<String>,
    pub finalized_at_utc: String,
}

impl IntegrityViewModel {
    pub fn is_ssh_format(&self) -> bool {
        self.format == "asciicast-v2"
    }

    pub fn is_rdp_format(&self) -> bool {
        self.format == "fmp4-dash" || self.format == "fmp4-flat"
    }

    pub fn is_pcap_bundle(&self) -> bool {
        self.format == "pcap-bundle"
    }
}

/// Top-level view-model for the Recording Details page.
#[derive(Debug, Clone)]
pub struct RecordingDetailViewModel {
    pub session_uuid: String,
    pub session_id: i32,
    pub session_type: String,
    pub session_type_label: String,
    pub status: String,
    pub status_label: String,
    pub status_pill_class: String,

    pub asset_name: String,
    pub asset_hostname: String,
    pub source_ip: String,

    pub credential_username: String,
    pub requester_username: String,

    pub connected_at_utc: Option<String>,
    pub disconnected_at_utc: Option<String>,
    pub duration_human: Option<String>,

    pub justification: Option<String>,
    pub approval: ApprovalNarrative,
    /// Pre-formatted "alice at 2026-04-30 09:11:45 UTC" if approved.
    pub approver_line: Option<String>,
    /// Pre-formatted "carol at ... UTC" if rejected.
    pub rejecter_line: Option<String>,
    /// Rejection reason, only populated when `approval` is `Rejected`.
    pub rejection_reason: Option<String>,

    pub integrity: Option<IntegrityViewModel>,
    pub corrupt_integrity: bool,

    pub play_url: String,
    pub download_url: String,
    pub back_url: String,
    pub list_url: String,
    /// False for IACS PCAP bundles (download-only, no in-browser player).
    pub show_play_recording: bool,
    /// True for IACS PCAP bundles -- surfaces the "Inspect Capture"
    /// button alongside Download.
    pub show_inspect_capture: bool,
    /// `/sessions/recordings/{uuid}/inspect`. Empty when
    /// `show_inspect_capture` is false.
    pub inspect_url: String,
}

impl RecordingDetailViewModel {
    pub fn has_approval_decision(&self) -> bool {
        !matches!(self.approval, ApprovalNarrative::Awaiting)
    }

    pub fn is_approved(&self) -> bool {
        matches!(self.approval, ApprovalNarrative::Approved { .. })
    }

    pub fn is_rejected(&self) -> bool {
        matches!(self.approval, ApprovalNarrative::Rejected { .. })
    }

    pub fn integrity_is_pending(&self) -> bool {
        self.integrity.is_none() && !self.corrupt_integrity
    }
}

#[derive(Template)]
#[template(path = "sessions/recording_detail.html")]
pub struct RecordingDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<UserContext>,
    pub perms: PermissionContext,
    pub recording: RecordingDetailViewModel,
}

/// Format an i64 byte count as a human-readable string ("92 KiB", etc.).
pub fn format_bytes_human(bytes: i64) -> String {
    if bytes < 0 {
        return format!("{} B", bytes);
    }
    const KB: i64 = 1024;
    const MB: i64 = KB * 1024;
    const GB: i64 = MB * 1024;
    if bytes >= GB {
        format!("{:.2} GiB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MiB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{} KiB", bytes / KB)
    } else {
        format!("{} B", bytes)
    }
}

/// Format a duration in milliseconds as `Hh Mm Ss`, dropping leading
/// zero components.
pub fn format_duration_human(duration_ms: i64) -> String {
    let total_secs = duration_ms.max(0) / 1000;
    let h = total_secs / 3600;
    let m = (total_secs % 3600) / 60;
    let s = total_secs % 60;
    if h > 0 {
        format!("{}h {}m {}s", h, m, s)
    } else if m > 0 {
        format!("{}m {}s", m, s)
    } else {
        format!("{}s", s)
    }
}

/// Truncate a 64-char hex hash to `prefix...suffix` shape for compact
/// display next to the copy button. Keeps 8 chars on each side.
pub fn truncate_blake3(hex: &str) -> String {
    if hex.len() <= 20 {
        return hex.to_string();
    }
    format!("{}...{}", &hex[..8], &hex[hex.len() - 8..])
}

/// Credential label for the Session Context card. IACS tunnels have no
/// asset-level login today; show an explicit placeholder instead of blank.
pub fn credential_display(username: &str, session_type: &str) -> String {
    if session_type == "iacs_tunnel" && username.trim().is_empty() {
        "Not authenticated (IACS tunnel)".to_string()
    } else {
        username.to_string()
    }
}

/// Map a `recording_format` enum value to a human label.
pub fn format_label(format: &str) -> &'static str {
    match format {
        "asciicast-v2" => "asciicast v2",
        "fmp4-dash" => "fragmented MP4 (DASH)",
        "fmp4-flat" => "MP4 (legacy)",
        "pcap-bundle" => "PCAP bundle",
        _ => "unknown",
    }
}

/// Map a session status value to (label, Tailwind pill classes).
pub fn status_pill(status: &str) -> (&'static str, &'static str) {
    match status {
        "approved" | "active" | "connecting" => (
            "Ready",
            "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
        ),
        "disconnected" | "terminated" => (
            "Terminated",
            "bg-gray-200 text-gray-800 dark:bg-gray-700 dark:text-gray-200",
        ),
        "rejected" => (
            "Rejected",
            "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300",
        ),
        "expired" => (
            "Expired",
            "bg-amber-100 text-amber-800 dark:bg-amber-900/50 dark:text-amber-300",
        ),
        "failed" => (
            "Failed",
            "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300",
        ),
        _ => (
            "Unknown",
            "bg-gray-200 text-gray-800 dark:bg-gray-700 dark:text-gray-200",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vauban_config() -> VaubanConfig {
        VaubanConfig {
            brand_name: "VAUBAN".to_string(),
            brand_logo: None,
            theme: "dark".to_string(),
            ..Default::default()
        }
    }

    fn make_recording(integrity: Option<IntegrityViewModel>) -> RecordingDetailViewModel {
        RecordingDetailViewModel {
            session_uuid: "00000000-0000-0000-0000-000000000001".to_string(),
            session_id: 42,
            session_type: "ssh".to_string(),
            session_type_label: "SSH (port 22)".to_string(),
            status: "terminated".to_string(),
            status_label: "Terminated".to_string(),
            status_pill_class: "bg-gray-200".to_string(),
            asset_name: "web-prod-01.example.com".to_string(),
            asset_hostname: "10.42.7.18".to_string(),
            source_ip: "192.168.1.42".to_string(),
            credential_username: "ssh-deploy-key-rsa".to_string(),
            requester_username: "alice".to_string(),
            connected_at_utc: Some("2026-04-30 09:12:08 UTC".to_string()),
            disconnected_at_utc: Some("2026-04-30 09:26:31 UTC".to_string()),
            duration_human: Some("14m 23s".to_string()),
            justification: Some("Routine post-deploy log inspection".to_string()),
            approval: ApprovalNarrative::Approved {
                approver_username: "bob".to_string(),
                approved_at_utc: "2026-04-30 09:11:45 UTC".to_string(),
            },
            approver_line: Some("bob at 2026-04-30 09:11:45 UTC".to_string()),
            rejecter_line: None,
            rejection_reason: None,
            integrity,
            corrupt_integrity: false,
            play_url: "/sessions/recordings/42/play".to_string(),
            download_url: "/sessions/recordings/00000000-0000-0000-0000-000000000001/download"
                .to_string(),
            back_url: "/sessions/recordings".to_string(),
        list_url: "/sessions/recordings".to_string(),
        show_play_recording: true,
        show_inspect_capture: false,
        inspect_url: String::new(),
    }
    }

    fn make_ssh_integrity() -> IntegrityViewModel {
        let hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string();
        IntegrityViewModel {
            blake3_truncated: truncate_blake3(&hex),
            blake3_hex: hex,
            size_human: "92 KiB".to_string(),
            duration_human: "14m 23s".to_string(),
            format: "asciicast-v2".to_string(),
            format_label: "asciicast v2".to_string(),
            width: 132,
            height: 43,
            event_count: Some(1847),
            segment_count: None,
            codec: None,
            finalized_at_utc: "2026-04-30 09:27:01 UTC".to_string(),
        }
    }

    #[test]
    fn test_format_bytes_human() {
        assert_eq!(format_bytes_human(0), "0 B");
        assert_eq!(format_bytes_human(512), "512 B");
        assert_eq!(format_bytes_human(2048), "2 KiB");
        assert_eq!(format_bytes_human(2 * 1024 * 1024), "2.0 MiB");
        assert_eq!(format_bytes_human(3 * 1024 * 1024 * 1024), "3.00 GiB");
    }

    #[test]
    fn test_format_duration_human() {
        assert_eq!(format_duration_human(0), "0s");
        assert_eq!(format_duration_human(1500), "1s");
        assert_eq!(format_duration_human(60_000), "1m 0s");
        assert_eq!(format_duration_human(125_000), "2m 5s");
        assert_eq!(format_duration_human(3_661_000), "1h 1m 1s");
    }

    #[test]
    fn test_truncate_blake3() {
        let h = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(truncate_blake3(h), "01234567...89abcdef");
        assert_eq!(truncate_blake3("short"), "short");
    }

    #[test]
    fn test_format_label() {
        assert_eq!(format_label("asciicast-v2"), "asciicast v2");
        assert_eq!(format_label("fmp4-dash"), "fragmented MP4 (DASH)");
        assert_eq!(format_label("fmp4-flat"), "MP4 (legacy)");
        assert_eq!(format_label("nope"), "unknown");
    }

    #[test]
    fn test_status_pill_known_states() {
        let (label, _) = status_pill("approved");
        assert_eq!(label, "Ready");
        let (label, _) = status_pill("rejected");
        assert_eq!(label, "Rejected");
        let (label, _) = status_pill("terminated");
        assert_eq!(label, "Terminated");
    }

    #[test]
    fn test_view_model_helpers() {
        let vm = make_recording(Some(make_ssh_integrity()));
        assert!(vm.is_approved());
        assert!(!vm.is_rejected());
        assert!(vm.has_approval_decision());
        assert!(!vm.integrity_is_pending());
    }

    #[test]
    fn test_view_model_pending_integrity() {
        let vm = make_recording(None);
        assert!(vm.integrity_is_pending());
    }

    #[test]
    fn test_view_model_corrupt_integrity_is_not_pending() {
        let mut vm = make_recording(None);
        vm.corrupt_integrity = true;
        assert!(!vm.integrity_is_pending());
    }

    #[test]
    fn test_template_renders_with_ssh_integrity() {
        let template = RecordingDetailTemplate {
            title: "Recording Details".to_string(),
            user: None,
            vauban: make_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            perms: PermissionContext::default(),
            recording: make_recording(Some(make_ssh_integrity())),
        };
        let r = template.render();
        assert!(r.is_ok(), "template should render: {:?}", r.err());
    }

    #[test]
    fn test_template_renders_with_pending_integrity() {
        let template = RecordingDetailTemplate {
            title: "Recording Details".to_string(),
            user: None,
            vauban: make_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            perms: PermissionContext::default(),
            recording: make_recording(None),
        };
        let r = template.render();
        assert!(r.is_ok(), "template should render: {:?}", r.err());
    }

    #[test]
    fn test_template_renders_with_rejection_narrative() {
        let mut vm = make_recording(None);
        vm.status = "rejected".to_string();
        vm.approval = ApprovalNarrative::Rejected {
            rejecter_username: "carol".to_string(),
            rejected_at_utc: "2026-04-30 10:00:00 UTC".to_string(),
            reason: Some("Out of business hours".to_string()),
        };
        vm.approver_line = None;
        vm.rejecter_line = Some("carol at 2026-04-30 10:00:00 UTC".to_string());
        vm.rejection_reason = Some("Out of business hours".to_string());
        let template = RecordingDetailTemplate {
            title: "Recording Details".to_string(),
            user: None,
            vauban: make_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            perms: PermissionContext::default(),
            recording: vm,
        };
        let r = template.render();
        assert!(r.is_ok(), "template should render: {:?}", r.err());
    }
}
