//! IACS tunnel status page UX pins (no in-process sshd spawn).
//!
//! Real-time SessionLive fan-out from proxy-iacs is covered by
//! `iacs_ws_vocab_test.rs`. This file keeps the template / Alpine
//! scaffolding pins that do not need a live russh listener.

use uuid::Uuid;

#[tokio::test]
async fn template_renders_ws_subscription_scaffolding() {
    use vauban_web::templates::sessions::IacsTunnelStatusTemplate;
    let template = IacsTunnelStatusTemplate {
        title: "IACS tunnel status".to_string(),
        user: None,
        vauban: vauban_web::templates::base::VaubanConfig::default(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        session_uuid: Uuid::new_v4().to_string(),
        asset_name: "fake-iacs".to_string(),
        industrial_protocol: "Modbus".to_string(),
        bastion_hostname: "127.0.0.1".to_string(),
        bastion_port: 22322,
        local_forward_port: 50_502,
        target_host: "127.0.0.1".to_string(),
        target_port: 502,
        tunnel_target_addr: "127.0.0.1:502".to_string(),
        session_status: "waiting_client".to_string(),
        waiting_countdown_seconds: Some(300),
        waiting_ttl_seconds: 300,
        csrf_token: "test".to_string(),
    };
    use askama::Template;
    let html = template.render().expect("render");
    assert!(
        html.contains("x-data=\"iacsTunnelStatus("),
        "template must mount the Alpine status component"
    );
    // CSP pin: `script-src 'self' 'unsafe-eval'` has NO
    // 'unsafe-inline', so the component MUST live in the compiled
    // static asset, never in an inline <script> block.
    assert!(
        !html.contains("<script>"),
        "status page must not carry inline <script> blocks (CSP has no unsafe-inline)"
    );
    let components = vauban_web::static_assets::lookup("js/vauban-components.js")
        .expect("vauban-components.js must be a compiled static asset");
    let js = std::str::from_utf8(components.content).expect("utf8");
    assert!(
        js.contains("Alpine.data('iacsTunnelStatus'"),
        "iacsTunnelStatus must be registered in vauban-components.js"
    );
    for needle in [
        "startCountdown",
        "stopCountdown",
        "expireNow",
        "formatCountdown",
        "remainingSeconds",
    ] {
        assert!(
            js.contains(needle),
            "vauban-components.js must carry the countdown seam '{needle}'"
        );
    }
    assert!(
        js.contains("/ws/session/"),
        "the external component must subscribe to /ws/session/ for real-time updates"
    );
    assert!(
        html.contains("data-testid=\"iacs-tunnel-bytes-in\""),
        "template must expose live bytes_in slot"
    );
    assert!(
        html.contains("data-testid=\"iacs-tunnel-bytes-out\""),
        "template must expose live bytes_out slot"
    );
    assert!(
        html.contains("data-testid=\"iacs-tunnel-peer-ip\""),
        "template must expose live peer-ip slot"
    );
    assert!(
        html.contains("data-testid=\"iacs-tunnel-disconnect\""),
        "template must expose the disconnect button"
    );
}
