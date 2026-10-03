//! Sixteen concurrent `open_session` calls share one MCP control pipe.
//! The pump must deliver every `McpSessionOpened` to its waiter.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use shared::ipc::IpcChannel;
use shared::messages::Message;
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Barrier;
use vauban_web::ipc::{McpSessionOpenRequest, ProxyMcpClient};

fn sample_open(session_id: &str) -> McpSessionOpenRequest {
    McpSessionOpenRequest {
        session_id: session_id.to_string(),
        asset_id: "asset".into(),
        user_id: "user".into(),
        api_key_id: String::new(),
        expires_at: "2099-01-01T00:00:00Z".into(),
        vbw_hash: [7u8; 32],
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
        justification: "battle open justification text".into(),
        max_body_bytes: 1_048_576,
        session_token: vec![1, 2, 3, 4],
        transport: "direct".into(),
        require_seal: false,
    }
}

fn would_block(err: &shared::ipc::IpcError) -> bool {
    matches!(err, shared::ipc::IpcError::Io(e) if e.kind() == ErrorKind::WouldBlock)
}

/// Answer every `McpSessionOpen` on a socketpair peer.
fn spawn_fake_leaf(peer: IpcChannel) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut answered = 0u32;
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        while answered < 16 && std::time::Instant::now() < deadline {
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
                    answered += 1;
                }
                Ok(_) => {}
                Err(e) if would_block(&e) => std::thread::sleep(Duration::from_millis(1)),
                Err(e) => panic!("fake leaf recv: {e}"),
            }
        }
        assert_eq!(answered, 16, "fake leaf must answer every open");
    })
}

#[tokio::test]
async fn battle_sixteen_open_sessions_share_the_control_pump() {
    let (web_side, peer) = IpcChannel::pair().expect("pair");
    let read_fd = web_side.read_fd();
    let write_fd = web_side.write_fd();
    std::mem::forget(web_side);
    let client = ProxyMcpClient::new(read_fd, write_fd).expect("client");
    let client_pump = Arc::clone(&client);
    tokio::spawn(async move {
        let _ = client_pump.process_incoming().await;
    });
    let leaf = spawn_fake_leaf(peer);

    let barrier = Arc::new(Barrier::new(16));
    let mut joins = Vec::new();
    for i in 0..16 {
        let client = Arc::clone(&client);
        let barrier = Arc::clone(&barrier);
        joins.push(tokio::spawn(async move {
            barrier.wait().await;
            let sid = format!("sess-{i}");
            client.open_session(sample_open(&sid)).await.expect("open")
        }));
    }
    let mut seen = Vec::new();
    for join in joins {
        let opened = join.await.expect("join");
        assert!(opened.success, "{opened:?}");
        seen.push(opened.session_id);
    }
    seen.sort();
    let mut expected: Vec<String> = (0..16).map(|i| format!("sess-{i}")).collect();
    expected.sort();
    assert_eq!(seen, expected);
    leaf.join().expect("leaf");
}
