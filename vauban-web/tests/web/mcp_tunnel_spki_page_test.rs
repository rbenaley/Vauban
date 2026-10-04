//! Hop-2 tunnel SPKI on `/assets/manage/{uuid}` (0.9.46).
//!
//! The shim pins the leaf's inner-TLS identity on first use. The
//! operator closes the TOFU gap by comparing the pin the shim prints
//! with the one this page shows, so the page must render it for MCP
//! assets, escaped and whole, and only behind `assets:manage`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use askama::Template;
use axum::http::header::COOKIE;
use axum_test::TestServer;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use proptest::prelude::*;
use serial_test::serial;
use shared::ipc::IpcChannel;
use shared::messages::Message;
use uuid::Uuid;

use vauban_web::handlers::web::mcp_tunnel_spki_for;
use vauban_web::ipc::SupervisorClient;
use vauban_web::models::asset::AssetType;
use vauban_web::templates::assets::manage::{ManageAssetDetail, ManageAssetDetailTemplate};
use vauban_web::templates::base::VaubanConfig;

use crate::common::{TestApp, build_test_router};
use crate::fixtures::{
    create_admin_user, create_test_asset_group, create_test_asset_in_group_with_type,
    create_test_user, unique_name,
};

const PIN: &str = "SHA256:q3x8m1Jd0eQkZ4m3c2Vx7l1F9yQK0sXb5r2t8wA6hDc=";

fn detail(asset_type: &str, pin: Option<&str>) -> ManageAssetDetail {
    ManageAssetDetail {
        uuid: Uuid::new_v4().to_string(),
        name: "Ticket MCP".to_string(),
        hostname: "mcp.example.com".to_string(),
        port: 443,
        asset_type: asset_type.to_string(),
        badge_label: asset_type.to_uppercase(),
        type_label: asset_type.to_uppercase(),
        is_iacs: false,
        iacs_protocol_label: String::new(),
        status: "online".to_string(),
        group_name: None,
        group_uuid: None,
        description: None,
        created_at: "2026-10-04T10:00:00Z".to_string(),
        updated_at: "2026-10-04T10:00:00Z".to_string(),
        created_by: None,
        updated_by: None,
        ssh_host_key_fingerprint: None,
        ssh_host_key_mismatch: false,
        rdp_server_cert_fingerprint: None,
        rdp_server_cert_mismatch: false,
        mcp_tunnel_spki: pin.map(str::to_string),
    }
}

fn render(asset: ManageAssetDetail) -> String {
    ManageAssetDetailTemplate {
        title: "Asset".to_string(),
        user: None,
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
        asset,
    }
    .render()
    .expect("detail renders")
}

#[derive(Template)]
#[template(source = "{{ s }}", ext = "html")]
struct Escaped<'a> {
    s: &'a str,
}

// ---------------------------------------------------------------- unit

#[test]
fn mcp_asset_renders_the_tunnel_fingerprint() {
    let html = render(detail("mcp", Some(PIN)));
    assert!(html.contains("Tunnel fingerprint (SPKI)"));
    assert!(html.contains(PIN));
    assert!(html.contains("font-mono break-all"));
}

#[test]
fn mcp_asset_without_identity_says_not_provisioned() {
    let html = render(detail("mcp", None));
    assert!(html.contains("Tunnel fingerprint (SPKI)"));
    assert!(html.contains("not provisioned"));
    assert!(!html.contains("SHA256:"));
}

#[test]
fn other_asset_types_never_render_the_tunnel_block() {
    for kind in ["ssh", "rdp", "iacs_modbus"] {
        let html = render(detail(kind, Some(PIN)));
        assert!(
            !html.contains("Tunnel fingerprint (SPKI)") && !html.contains(PIN),
            "{kind} must not render the MCP tunnel pin"
        );
    }
}

#[test]
fn handler_selects_the_pin_for_mcp_only() {
    let pin = || Some(PIN.to_string());
    assert_eq!(
        mcp_tunnel_spki_for(&AssetType::Mcp, pin()).as_deref(),
        Some(PIN)
    );
    assert_eq!(mcp_tunnel_spki_for(&AssetType::Mcp, None), None);
    for t in [AssetType::Ssh, AssetType::Rdp] {
        assert_eq!(mcp_tunnel_spki_for(&t, pin()), None);
    }
}

// ---------------------------------------------------------- invariants

#[test]
fn docs_point_at_the_page_that_renders_the_pin() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let template = include_str!("../../templates/assets/manage/detail.html");
    let handler = include_str!("../../src/handlers/web/manage_assets.rs");
    let arch =
        std::fs::read_to_string(root.join("docs/technical/Vauban_MCP_Architecture_EN(1.0).md"))
            .expect("arch doc");
    let guide = std::fs::read_to_string(root.join("docs/user/Vauban_MCP_User_Guide_EN.md"))
        .expect("user guide");
    let runbook = std::fs::read_to_string(root.join("docs/runbooks/mcp_hop2_relay_smoke_test.md"))
        .expect("runbook");

    assert!(template.contains("Tunnel fingerprint (SPKI)"));
    assert!(template.contains("asset.mcp_tunnel_spki"));
    assert!(handler.contains("s.tunnel_spki()"));
    for (name, text) in [("arch", &arch), ("guide", &guide), ("runbook", &runbook)] {
        assert!(
            text.contains("Tunnel fingerprint (SPKI)") && text.contains("/assets/manage/"),
            "{name} must name the asset-page label the template renders"
        );
    }
    assert!(
        arch.contains("Only the asset can require the tunnel"),
        "arch §4.4 must say the asset, not an access rule, requires the tunnel"
    );
    assert!(
        arch.contains("unauthenticated TLS handshakes"),
        "arch §4.6 must admit the leaf sees unauthenticated handshakes in tunnel mode"
    );
}

// ------------------------------------------------------------ proptest

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn random_pins_render_escaped_and_whole(pin in "[ -~]{1,120}") {
        let html = render(detail("mcp", Some(&pin)));
        let escaped = Escaped { s: &pin }.render().expect("escape");
        prop_assert!(html.contains(&escaped), "pin truncated or not escaped");
        if pin.contains('<') {
            prop_assert!(!html.contains(&pin), "raw pin with '<' reached the page");
        }
    }
}

// -------------------------------------------------------------- battle

#[test]
fn battle_eight_parallel_renders_keep_their_own_pin() {
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let pin = format!("SHA256:thread{i}pin{}", "A".repeat(32));
                barrier.wait();
                (pin.clone(), render(detail("mcp", Some(&pin))))
            })
        })
        .collect();
    let out: Vec<(String, String)> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for (i, (pin, html)) in out.iter().enumerate() {
        assert!(html.contains(pin.as_str()));
        for (j, (other, _)) in out.iter().enumerate() {
            if i != j {
                assert!(!html.contains(other.as_str()), "render {i} leaked pin {j}");
            }
        }
    }
}

// ----------------------------------------------------------------- E2E

/// A web `SupervisorClient` fed the fingerprint the way the real
/// supervisor pushes it. The returned channel keeps the pipe open.
async fn supervisor_with_pin(pin: &str) -> (Arc<SupervisorClient>, IpcChannel) {
    let (supervisor_end, web_end) = IpcChannel::pair().unwrap();
    let (read_fd, write_fd) = (web_end.read_fd(), web_end.write_fd());
    std::mem::forget(web_end);
    let (client, _boot) = SupervisorClient::new(read_fd, write_fd, None, None);
    supervisor_end
        .send(&Message::McpTunnelIdentityFingerprint {
            spki_sha256: pin.to_string(),
        })
        .unwrap();
    let client = Arc::new(client);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while client.tunnel_spki().is_none() {
        assert!(tokio::time::Instant::now() < deadline, "pin never arrived");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (client, supervisor_end)
}

async fn asset_of_type(app: &TestApp, admin_id: i32, kind: AssetType) -> Uuid {
    use vauban_web::schema::assets::dsl as a;
    let mut conn = app.get_conn().await;
    let group = create_test_asset_group(&mut conn, &unique_name("spki-ag")).await;
    let id = create_test_asset_in_group_with_type(
        &mut conn,
        &unique_name("spki"),
        admin_id,
        &group,
        kind,
    )
    .await;
    a::assets
        .filter(a::id.eq(id))
        .select(a::uuid)
        .first(&mut conn)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn e2e_mcp_asset_page_shows_the_provisioned_pin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("spki_admin")).await;
    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("spki_user")).await;
    let mcp = asset_of_type(app, admin.user.id, AssetType::Mcp).await;
    let ssh = asset_of_type(app, admin.user.id, AssetType::Ssh).await;

    let (client, _keep) = supervisor_with_pin(PIN).await;
    let mut state = app.app_state.clone();
    state.supervisor = Some(client);
    let server = TestServer::new(build_test_router(state)).unwrap();

    let page = server
        .get(&format!("/assets/manage/{mcp}"))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_eq!(page.status_code().as_u16(), 200);
    let body = page.text();
    assert!(body.contains("Tunnel fingerprint (SPKI)"));
    assert!(
        body.contains(PIN),
        "admin must see the provisioned SHA256: pin"
    );

    let ssh_page = server
        .get(&format!("/assets/manage/{ssh}"))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_eq!(ssh_page.status_code().as_u16(), 200);
    assert!(
        !ssh_page.text().contains(PIN),
        "SSH asset must not show the MCP pin"
    );

    let denied = server
        .get(&format!("/assets/manage/{mcp}"))
        .add_header(COOKIE, format!("access_token={}", user.token))
        .await;
    assert_eq!(denied.status_code().as_u16(), 403, "role:user must get 403");
    assert!(!denied.text().contains(PIN));
}
