//! The production pump is what delivers `McpSessionOpened`.
//! Without it, hop 1 never completes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use shared::ipc::IpcChannel;
use shared::messages::Message;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use vauban_web::ipc::{McpSessionOpenRequest, ProxyMcpClient, PumpCtx, spawn_ipc_pump};

fn sample_open() -> McpSessionOpenRequest {
    McpSessionOpenRequest {
        session_id: "e2e-1".into(),
        asset_id: "asset".into(),
        user_id: "user".into(),
        api_key_id: String::new(),
        expires_at: "2099-01-01T00:00:00Z".into(),
        vbw_hash: [9u8; 32],
        allowed_tools: Some(vec!["echo".into()]),
        tool_constraints_json: "{}".into(),
        envelope_max_calls: 10,
        envelope_window_seconds: 60,
        envelope_on_exceed: "throttle".into(),
        upstream_host: "10.0.0.8".into(),
        upstream_port: 443,
        upstream_tls_spki_pin: None,
        forward_identity_headers: false,
        credential_blob: Vec::new(),
        justification: "e2e open justification text".into(),
        max_body_bytes: 1_048_576,
        session_token: vec![9, 9],
        transport: "direct".into(),
        require_seal: false,
    }
}

fn client_and_peer() -> (Arc<ProxyMcpClient>, IpcChannel) {
    let (web_side, peer) = IpcChannel::pair().expect("pair");
    let read_fd = web_side.read_fd();
    let write_fd = web_side.write_fd();
    std::mem::forget(web_side);
    let client = ProxyMcpClient::new(read_fd, write_fd).expect("client");
    (client, peer)
}

#[tokio::test]
async fn pump_absent_open_session_times_out() {
    let (client, _peer) = client_and_peer();
    let pending = tokio::time::timeout(
        Duration::from_millis(200),
        client.open_session(sample_open()),
    )
    .await;
    assert!(
        pending.is_err(),
        "without the control pump McpSessionOpened is never delivered"
    );
}

#[tokio::test]
async fn pump_delivers_mcp_session_opened() {
    let (client, peer) = client_and_peer();
    let pumping = Arc::clone(&client);
    let ctx = PumpCtx {
        server_handle: axum_server::Handle::<SocketAddr>::new(),
        shutdown: Arc::new(AtomicBool::new(false)),
        respawn_requested: Arc::new(AtomicBool::new(false)),
    };
    spawn_ipc_pump(
        "mcp_proxy",
        async move { pumping.process_incoming().await },
        ctx,
    );

    std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            match peer.try_recv() {
                Ok(Message::McpSessionOpen {
                    request_id,
                    session_id,
                    ..
                }) => {
                    peer.send(&Message::McpSessionOpened {
                        request_id,
                        session_id,
                        success: true,
                        error: None,
                    })
                    .expect("reply");
                    return;
                }
                Ok(_) => {}
                Err(shared::ipc::IpcError::Io(e)) if e.kind() == ErrorKind::WouldBlock => {
                    if std::time::Instant::now() > deadline {
                        panic!("fake leaf timed out");
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("recv: {e}"),
            }
        }
    });

    let opened = tokio::time::timeout(Duration::from_secs(3), client.open_session(sample_open()))
        .await
        .expect("pump must answer before the hop-1 timeout")
        .expect("open");
    assert!(opened.success);
    assert_eq!(opened.session_id, "e2e-1");
}
