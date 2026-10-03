//! Thirty-two tunnels on one data pipe echo without mixing bytes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;

use shared::ipc::IpcChannel;
use shared::messages::Message;
use tokio::sync::Barrier;
use vauban_web::ipc::proxy_mcp_data::ProxyMcpDataClient;

fn would_block(err: &shared::ipc::IpcError) -> bool {
    matches!(err, shared::ipc::IpcError::Io(e) if e.kind() == ErrorKind::WouldBlock)
}

#[tokio::test]
async fn battle_thirty_two_tunnels_echo() {
    let (web_side, peer) = IpcChannel::pair().unwrap();
    let read_fd = web_side.read_fd();
    let write_fd = web_side.write_fd();
    std::mem::forget(web_side);
    let data = ProxyMcpDataClient::new(read_fd, write_fd).unwrap();
    let pumping = Arc::clone(&data);
    tokio::spawn(async move {
        let _ = pumping.process_incoming().await;
    });
    std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        while std::time::Instant::now() < deadline {
            match peer.try_recv() {
                Ok(Message::McpTunnelData { tunnel_id, data }) => {
                    let _ = peer.send(&Message::McpTunnelData { tunnel_id, data });
                }
                Ok(_) => {}
                Err(e) if would_block(&e) => std::thread::sleep(Duration::from_millis(1)),
                Err(_) => break,
            }
        }
    });

    let barrier = Arc::new(Barrier::new(32));
    let mut joins = Vec::new();
    for i in 0..32u8 {
        let data = Arc::clone(&data);
        let barrier = Arc::clone(&barrier);
        joins.push(tokio::spawn(async move {
            barrier.wait().await;
            let (id, mut rx) = data.open_tunnel(format!("203.0.113.{i}")).unwrap();
            let payload = vec![i, i, i, i];
            data.send_tunnel(id, payload.clone()).unwrap();
            let echoed = tokio::time::timeout(Duration::from_secs(3), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(echoed, payload);
        }));
    }
    for join in joins {
        join.await.unwrap();
    }
}
