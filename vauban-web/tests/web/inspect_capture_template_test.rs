//! Template / view-model contract pins for IACS Inspect Capture.
//!
//! These tests render the Askama templates directly (no DB, no HTTP)
//! and grep the resulting HTML to pin:
//!
//! - HTMX wiring (hx-get / hx-target / hx-swap / hx-include / hx-push-url
//!   + 300ms search debounce).
//! - Brand-aligned Tailwind classes (amber for cmd, rose for exception,
//!   emerald/amber border for direction, vauban-* for selection).
//! - No inline `<script>` tag in the inspect templates (CSP).
//! - Responsive breakpoints (`grid-cols-1 lg:grid-cols-12`,
//!   `hidden sm:`, ...).
//! - Tree<->hex contract: every byte cell carries the matching
//!   `data-field=` attribute.
//! - Persistent replay-safety banner.

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use askama::Template;

use vauban_web::auth::PermissionContext;
use vauban_web::services::iacs_packet_analyzer::types::{
    Direction, FieldNode, PacketDetail, PacketKind, PacketSummary,
};
use vauban_web::templates::base::{UserContext, VaubanConfig};
use vauban_web::templates::sessions::inspect_capture::{
    ChannelOption, InspectCaptureTemplate, InspectCaptureViewModel, InspectFilterViewModel,
    PacketDetailPartial, PacketDetailViewModel, PacketListPartial, PacketListViewModel,
    PacketRowViewModel,
};

const SHELL_HTML: &str = include_str!("../../templates/sessions/inspect/shell.html");
const PACKET_LIST_HTML: &str = include_str!("../../templates/sessions/inspect/_packet_list.html");
const PACKET_DETAIL_HTML: &str =
    include_str!("../../templates/sessions/inspect/_packet_detail.html");
const HEX_DUMP_HTML: &str = include_str!("../../templates/sessions/inspect/_hex_dump.html");
const FILTER_CHIPS_HTML: &str = include_str!("../../templates/sessions/inspect/_filter_chips.html");
const CHANNEL_SELECTOR_HTML: &str =
    include_str!("../../templates/sessions/inspect/_channel_selector.html");
const RECORDING_DETAIL_HTML: &str = include_str!("../../templates/sessions/recording_detail.html");
const RECORDING_LIST_HTML: &str = include_str!("../../templates/sessions/recording_list.html");

fn make_vauban() -> VaubanConfig {
    VaubanConfig {
        brand_name: "VAUBAN".into(),
        brand_logo: None,
        theme: "dark".into(),
        ..Default::default()
    }
}

fn make_user() -> Option<UserContext> {
    Some(UserContext {
        uuid: "u".into(),
        username: "alice".into(),
        display_name: "Alice".into(),
        is_superuser: true,
        is_staff: true,
    })
}

fn sample_summary(idx: usize, kind: PacketKind, dir: Direction) -> PacketSummary {
    PacketSummary {
        frame_idx: idx,
        timestamp_us: idx as u64 * 1_000,
        timestamp_human: format!("00:00:00.{:06}", idx),
        direction: dir,
        kind,
        summary: match kind {
            PacketKind::Cmd => "FC06 Write Register".into(),
            PacketKind::Read => "FC03 Read Holding".into(),
            PacketKind::Exception => "Exception 0x83".into(),
            PacketKind::Tcp => "[ACK]".into(),
        },
        payload_len: 12,
        src_port: 49_152,
        dst_port: 502,
    }
}

fn sample_list(uuid: &str, channel: u32) -> PacketListViewModel {
    let items: Vec<PacketRowViewModel> = (1..=3)
        .map(|i| {
            let kind = match i {
                1 => PacketKind::Read,
                2 => PacketKind::Cmd,
                _ => PacketKind::Exception,
            };
            let dir = if i % 2 == 0 {
                Direction::EwsToAsset
            } else {
                Direction::AssetToEws
            };
            PacketRowViewModel::from_summary(&sample_summary(i, kind, dir), uuid, channel)
        })
        .collect();
    PacketListViewModel {
        session_uuid: uuid.into(),
        channel,
        items,
        total: 3,
        page: 1,
        page_size: 100,
        total_pages: 1,
        has_prev: false,
        has_next: false,
        filter: InspectFilterViewModel::default(),
        first_frame_idx: Some(1),
    }
}

fn sample_view() -> InspectCaptureViewModel {
    InspectCaptureViewModel {
        session_uuid: "00000000-0000-0000-0000-000000000001".into(),
        asset_name: "PLC-East".into(),
        asset_hostname: "10.0.0.5".into(),
        industrial_protocol: "modbus".into(),
        industrial_protocol_label: "Modbus/TCP".into(),
        channels: vec![ChannelOption {
            index: 1,
            label: "ch001".into(),
            target: "10.0.0.5:502".into(),
            packets: 42,
        }],
        selected_channel: 1,
        back_url: "/sessions/recordings/00000000-0000-0000-0000-000000000001".into(),
        list_url: "/sessions/recordings".into(),
        recording_detail_url: "/sessions/recordings/00000000-0000-0000-0000-000000000001".into(),
        initial_list: sample_list("00000000-0000-0000-0000-000000000001", 1),
    }
}

fn render_shell() -> String {
    let template = InspectCaptureTemplate {
        title: "Inspect Capture".into(),
        user: make_user(),
        vauban: make_vauban(),
        messages: Vec::new(),
        language_code: "en".into(),
        sidebar_content: None,
        header_user: None,
        perms: PermissionContext::default(),
        view: sample_view(),
    };
    template.render().expect("shell renders")
}

fn render_packet_list() -> String {
    let template = PacketListPartial {
        list: sample_list("00000000-0000-0000-0000-000000000001", 1),
    };
    template.render().expect("packet list renders")
}

fn render_packet_detail() -> String {
    let detail = PacketDetail {
        summary: sample_summary(4, PacketKind::Cmd, Direction::EwsToAsset),
        tree: vec![FieldNode::leaf(
            "Function Code",
            "0x06".into(),
            "modbus.function",
            47,
            1,
        )],
        hex: vec![0u8; 48],
        byte_field_ids: {
            let mut v = vec![String::new(); 48];
            v[47] = "modbus.function".into();
            v
        },
    };
    let vm = PacketDetailViewModel::from_detail(detail, "00000000-0000-0000-0000-000000000001", 1);
    let template = PacketDetailPartial { detail: vm };
    template.render().expect("detail renders")
}

#[test]
fn shell_extends_base_html_and_carries_replay_banner() {
    let html = render_shell();
    assert!(
        html.contains("Forensic view"),
        "replay-safety banner present"
    );
    assert!(html.contains("border-amber-500"), "banner has amber accent");
    assert!(html.contains("Inspect Capture"), "page title present");
}

#[test]
fn shell_uses_responsive_grid_lg_12_cols() {
    let html = render_shell();
    assert!(
        html.contains("grid-cols-1") && html.contains("lg:grid-cols-12"),
        "shell layout must use the responsive 12-col grid"
    );
}

#[test]
fn packet_list_renders_color_classes_for_each_kind() {
    let html = render_packet_list();
    // Cmd row has amber background; Exception row has rose;
    // direction borders use amber-400 / emerald-400.
    assert!(html.contains("border-amber-400"), "EWS->Asset border");
    assert!(html.contains("border-emerald-400"), "Asset->EWS border");
    assert!(html.contains("bg-amber-50"), "Cmd row tint");
    assert!(html.contains("bg-rose-50"), "Exception row tint");
}

#[test]
fn packet_list_partial_carries_target_id_and_pagination_footer() {
    let html = render_packet_list();
    assert!(
        html.contains("id=\"inspect-packet-list\""),
        "partial wraps in #inspect-packet-list"
    );
    assert!(html.contains("Page 1 of"), "pagination footer present");
}

#[test]
fn packet_detail_carries_data_field_attributes_on_tree_and_hex() {
    let html = render_packet_detail();
    // Tree node carries data-field
    assert!(
        html.contains("data-field=\"modbus.function\""),
        "tree leaf must carry data-field"
    );
    // Hex pane stamps the same field id on the matching byte
    assert!(
        html.matches("data-field=\"modbus.function\"").count() >= 2,
        "tree<->hex contract: data-field must appear in BOTH the tree \
         (1) and the hex pane (1+) for the same field, got {} occurrences",
        html.matches("data-field=\"modbus.function\"").count()
    );
}

#[test]
fn packet_detail_uses_alpine_x_data_for_highlight() {
    let html = render_packet_detail();
    assert!(
        html.contains("x-data=\"{ highlight: null }\""),
        "Alpine x-data must drive the tree<->hex highlight"
    );
    assert!(
        html.contains("@mouseenter=\"highlight = 'modbus.function'\""),
        "hover binds highlight"
    );
}

#[test]
fn packet_detail_keeps_replay_safety_reminder() {
    let html = render_packet_detail();
    assert!(
        html.contains("Forensic frame"),
        "every detail panel must keep a replay-safety reminder"
    );
}

#[test]
fn no_inline_script_in_inspect_templates() {
    let templates = [
        ("shell.html", SHELL_HTML),
        ("_packet_list.html", PACKET_LIST_HTML),
        ("_packet_detail.html", PACKET_DETAIL_HTML),
        ("_hex_dump.html", HEX_DUMP_HTML),
        ("_filter_chips.html", FILTER_CHIPS_HTML),
        ("_channel_selector.html", CHANNEL_SELECTOR_HTML),
    ];
    for (name, body) in templates {
        assert!(
            !body.contains("<script"),
            "inspect/{} must not contain <script> (CSP, Alpine handles client side declaratively)",
            name
        );
    }
}

#[test]
fn search_input_has_300ms_debounce() {
    let html = render_shell();
    assert!(
        html.contains("input changed delay:300ms"),
        "search must debounce at 300ms"
    );
}

#[test]
fn htmx_target_is_inspect_packet_list_on_filter_changes() {
    let html = render_shell();
    let target_count = html.matches("hx-target=\"#inspect-packet-list\"").count();
    assert!(
        target_count >= 5,
        "filter / channel / search / pagination must all target #inspect-packet-list (got {} occurrences)",
        target_count
    );
}

#[test]
fn htmx_uses_outer_html_swap_and_propagates_filters() {
    let html = render_shell();
    assert!(html.contains("hx-swap=\"outerHTML\""), "outerHTML swap");
    assert!(
        html.contains("hx-include=\"[name='direction'], [name='kind'], [name='search']\""),
        "filter propagation via hx-include"
    );
    assert!(
        html.contains("hx-push-url=\"true\""),
        "push URL on filter change"
    );
}

#[test]
fn recording_detail_template_renders_inspect_button_for_iacs() {
    assert!(
        RECORDING_DETAIL_HTML.contains("recording.show_inspect_capture"),
        "recording_detail.html must gate the Inspect button on show_inspect_capture"
    );
    assert!(
        RECORDING_DETAIL_HTML.contains("Inspect Capture"),
        "Inspect Capture button label present"
    );
    assert!(
        RECORDING_DETAIL_HTML.contains("recording.inspect_url"),
        "Inspect button targets recording.inspect_url"
    );
}

#[test]
fn recording_list_template_renders_inspect_link_for_iacs() {
    assert!(
        RECORDING_LIST_HTML.contains("recording.show_inspect_capture"),
        "recording_list.html must gate the Inspect link on show_inspect_capture"
    );
    assert!(
        RECORDING_LIST_HTML.contains("/inspect"),
        "Inspect link points at the inspect URL"
    );
}

// =====================================================================
// Recording Details + List end-to-end render tests for the Inspect
// Capture button. Mirror the recording_detail unit-test pattern but
// flip `show_inspect_capture` to assert presence/absence in the
// rendered HTML.
// =====================================================================

mod recording_visibility {
    use super::*;
    use vauban_web::auth::PermissionContext;
    use vauban_web::templates::sessions::recording_detail::{
        ApprovalNarrative, RecordingDetailTemplate, RecordingDetailViewModel,
    };
    use vauban_web::templates::sessions::recording_list::{
        RecordingListItem, RecordingListTemplate,
    };

    fn make_recording_vm(session_type: &str, show_inspect: bool) -> RecordingDetailViewModel {
        RecordingDetailViewModel {
            session_uuid: "00000000-0000-0000-0000-000000000001".into(),
            session_id: 1,
            session_type: session_type.into(),
            session_type_label: session_type.into(),
            status: "terminated".into(),
            status_label: "Terminated".into(),
            status_pill_class: "bg-gray-200".into(),
            asset_name: "asset".into(),
            asset_hostname: "host".into(),
            source_ip: "10.0.0.1".into(),
            credential_username: "u".into(),
            requester_username: "alice".into(),
            connected_at_utc: None,
            disconnected_at_utc: None,
            duration_human: None,
            justification: None,
            approval: ApprovalNarrative::Awaiting,
            approver_line: None,
            rejecter_line: None,
            rejection_reason: None,
            integrity: None,
            corrupt_integrity: false,
            play_url: "/p".into(),
            download_url: "/d".into(),
            back_url: "/b".into(),
            list_url: "/l".into(),
            show_play_recording: session_type != "iacs_tunnel",
            show_inspect_capture: show_inspect,
            inspect_url: if show_inspect {
                "/sessions/recordings/00000000-0000-0000-0000-000000000001/inspect".into()
            } else {
                String::new()
            },
        }
    }

    fn render_detail(vm: RecordingDetailViewModel) -> String {
        RecordingDetailTemplate {
            title: "Recording".into(),
            user: None,
            vauban: super::make_vauban(),
            messages: Vec::new(),
            language_code: "en".into(),
            sidebar_content: None,
            header_user: None,
            perms: PermissionContext::default(),
            recording: vm,
        }
        .render()
        .expect("render")
    }

    #[test]
    fn inspect_capture_button_visible_for_iacs_session() {
        let html = render_detail(make_recording_vm("iacs_tunnel", true));
        assert!(html.contains("Inspect Capture"));
        assert!(html.contains("/inspect"));
    }

    #[test]
    fn inspect_capture_button_hidden_for_rdp() {
        let html = render_detail(make_recording_vm("rdp", false));
        assert!(!html.contains("Inspect Capture"));
    }

    #[test]
    fn inspect_capture_button_hidden_for_ssh() {
        let html = render_detail(make_recording_vm("ssh", false));
        assert!(!html.contains("Inspect Capture"));
    }

    fn make_list_item(session_type: &str, show_inspect: bool) -> RecordingListItem {
        RecordingListItem {
            id: 1,
            session_id: 100,
            session_uuid: "00000000-0000-0000-0000-000000000100".into(),
            asset_name: "asset".into(),
            session_type: session_type.into(),
            credential_username: "u".into(),
            requester_username: "alice".into(),
            connected_at: None,
            duration_seconds: None,
            size_human: None,
            recording_path: "/r".into(),
            status: "ready".into(),
            show_play_recording: session_type != "iacs_tunnel",
            show_inspect_capture: show_inspect,
        }
    }

    fn render_list(items: Vec<RecordingListItem>) -> String {
        RecordingListTemplate {
            title: "Recordings".into(),
            user: super::make_user(),
            vauban: super::make_vauban(),
            messages: Vec::new(),
            language_code: "en".into(),
            sidebar_content: None,
            header_user: None,
            recordings: items,
            format_filter: None,
            asset_filter: None,
            pagination: None,
        }
        .render()
        .expect("render")
    }

    #[test]
    fn inspect_link_visible_in_list_for_iacs_row() {
        let html = render_list(vec![make_list_item("iacs_tunnel", true)]);
        // The inspect link target is the canonical inspect URL; the
        // visible label is "Inspect". Width is pinned by `w-20
        // justify-center` on both the Play and Inspect buttons so the
        // right-hand action column stays aligned across IACS / SSH /
        // RDP rows regardless of label length.
        assert!(html.contains("/sessions/recordings/00000000-0000-0000-0000-000000000100/inspect"));
        assert!(html.contains("Inspect"));
        assert!(
            html.contains("w-20 justify-center"),
            "Inspect button must use the fixed-width centred layout to align with Play",
        );
    }

    #[test]
    fn inspect_link_hidden_in_list_for_non_iacs_rows() {
        let html = render_list(vec![
            make_list_item("ssh", false),
            make_list_item("rdp", false),
        ]);
        assert!(
            !html.contains("/sessions/recordings/00000000-0000-0000-0000-000000000100/inspect")
        );
    }
}
