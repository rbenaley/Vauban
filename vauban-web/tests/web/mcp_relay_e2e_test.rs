//! Hop-2 bare router: the leaf sees only the allow-listed ticket, and
//! the edges refuse before that.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::ErrorKind;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use shared::ipc::IpcChannel;
use shared::messages::Message;
use tower::ServiceExt;
use vauban_web::handlers::mcp_relay::mcp_bare_router;
use vauban_web::ipc::ProxyMcpClient;
use vauban_web::ipc::proxy_mcp_data::ProxyMcpDataClient;
use vauban_web::services::rate_limit::RateLimiter;

use crate::common::TestApp;

fn would_block(err: &shared::ipc::IpcError) -> bool {
    matches!(err, shared::ipc::IpcError::Io(e) if e.kind() == ErrorKind::WouldBlock)
}

struct Leaf {
    peer: IpcChannel,
    seen_auth: Arc<Mutex<Vec<String>>>,
    relays: Arc<Mutex<u32>>,
    tunnel_opens: Arc<Mutex<u32>>,
}

fn attach_leaf(state: &mut vauban_web::AppState) -> Leaf {
    let (web_side, peer) = IpcChannel::pair().unwrap();
    let read_fd = web_side.read_fd();
    let write_fd = web_side.write_fd();
    std::mem::forget(web_side);
    let data = ProxyMcpDataClient::new(read_fd, write_fd).unwrap();
    let data_pump = Arc::clone(&data);
    tokio::spawn(async move {
        let _ = data_pump.process_incoming().await;
    });
    let (ctrl_web, ctrl_peer) = IpcChannel::pair().unwrap();
    let r = ctrl_web.read_fd();
    let w = ctrl_web.write_fd();
    std::mem::forget(ctrl_web);
    std::mem::forget(ctrl_peer);
    let proxy = ProxyMcpClient::new(r, w).unwrap();
    proxy.set_data(data);
    state.proxy_mcp = Some(proxy);
    state.rate_limiter = RateLimiter::in_memory();
    Leaf {
        peer,
        seen_auth: Arc::new(Mutex::new(Vec::new())),
        relays: Arc::new(Mutex::new(0)),
        tunnel_opens: Arc::new(Mutex::new(0)),
    }
}

fn spawn_leaf(leaf: Leaf) {
    let Leaf {
        peer,
        seen_auth,
        relays,
        tunnel_opens,
    } = leaf;
    std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        while std::time::Instant::now() < deadline {
            match peer.try_recv() {
                Ok(Message::McpRelayRequest {
                    relay_id,
                    authorization,
                    body_len,
                    ..
                }) => {
                    seen_auth
                        .lock()
                        .unwrap()
                        .push(authorization.as_str().to_string());
                    *relays.lock().unwrap() += 1;
                    if body_len == 0 {
                        let _ = peer.send(&Message::McpRelayResponse {
                            relay_id,
                            status: 200,
                            content_type: "application/json".into(),
                            mcp_session_id: None,
                            body_len: 2,
                        });
                        let _ = peer.send(&Message::McpRelayBody {
                            relay_id,
                            seq: 0,
                            last: true,
                            data: b"{}".to_vec(),
                        });
                    }
                }
                Ok(Message::McpRelayBody {
                    relay_id,
                    last: true,
                    ..
                }) => {
                    let _ = peer.send(&Message::McpRelayResponse {
                        relay_id,
                        status: 200,
                        content_type: "application/json".into(),
                        mcp_session_id: None,
                        body_len: 2,
                    });
                    let _ = peer.send(&Message::McpRelayBody {
                        relay_id,
                        seq: 0,
                        last: true,
                        data: b"{}".to_vec(),
                    });
                }
                Ok(Message::McpTunnelOpen { .. }) => {
                    *tunnel_opens.lock().unwrap() += 1;
                }
                Ok(_) => {}
                Err(e) if would_block(&e) => std::thread::sleep(Duration::from_millis(2)),
                Err(_) => break,
            }
        }
    });
}

fn post(
    body: &'static [u8],
    bearer: &str,
    cookie: Option<&str>,
    xff: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", bearer);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    if let Some(xff) = xff {
        builder = builder.header("x-forwarded-for", xff);
    }
    builder.body(Body::from(body)).unwrap()
}

#[tokio::test]
async fn attack_cookie_is_stripped_on_relay() {
    let app = TestApp::spawn().await;
    let mut state = app.app_state.clone();
    let seen = {
        let leaf = attach_leaf(&mut state);
        let seen = Arc::clone(&leaf.seen_auth);
        spawn_leaf(leaf);
        seen
    };
    let router = mcp_bare_router(&state).with_state(state);
    let response = router
        .oneshot(post(
            b"{}",
            "Bearer vbw_ticket",
            Some("access_token=stolen-cookie"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let auths = seen.lock().unwrap().clone();
    assert_eq!(auths, vec!["Bearer vbw_ticket".to_string()]);
    assert!(!auths[0].contains("stolen-cookie"));
}

#[tokio::test]
async fn attack_ip_outside_acl_never_reaches_leaf() {
    let app = TestApp::spawn_ip_acl().await;
    let mut state = app.app_state.clone();
    let relays = {
        let leaf = attach_leaf(&mut state);
        let relays = Arc::clone(&leaf.relays);
        spawn_leaf(leaf);
        relays
    };
    let router = mcp_bare_router(&state).with_state(state);
    let response = router
        .oneshot(post(b"{}", "Bearer vbw_ticket", None, Some("203.0.113.9")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(*relays.lock().unwrap(), 0);
}

#[tokio::test]
async fn post_oversize_is_413_before_the_pipe() {
    let app = TestApp::spawn().await;
    let mut state = app.app_state.clone();
    let relays = {
        let leaf = attach_leaf(&mut state);
        let relays = Arc::clone(&leaf.relays);
        spawn_leaf(leaf);
        relays
    };
    let router = mcp_bare_router(&state).with_state(state);
    let big = vec![b'a'; 1_048_577];
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", "Bearer vbw_ticket")
        .body(Body::from(big))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(*relays.lock().unwrap(), 0);
}

#[tokio::test]
async fn get_mcp_is_405() {
    let app = TestApp::spawn().await;
    let state = app.app_state.clone();
    let router = mcp_bare_router(&state).with_state(state);
    let request = Request::builder()
        .method("GET")
        .uri("/mcp")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn flood_is_429() {
    let app = TestApp::spawn().await;
    let mut state = app.app_state.clone();
    state.config.mcp.relay_rate_limit_per_minute = 2;
    let leaf = attach_leaf(&mut state);
    spawn_leaf(leaf);
    let router = mcp_bare_router(&state).with_state(state);
    let mut last = StatusCode::OK;
    for _ in 0..3 {
        let response = router
            .clone()
            .oneshot(post(b"{}", "Bearer vbw_ticket", None, None))
            .await
            .unwrap();
        last = response.status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

fn tunnel_get(xff: Option<&str>, upgrade: bool) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri("/mcp/tunnel");
    if upgrade {
        builder = builder
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");
    }
    if let Some(xff) = xff {
        builder = builder.header("x-forwarded-for", xff);
    }
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn attack_ip_outside_acl_never_opens_tunnel() {
    let app = TestApp::spawn_ip_acl().await;
    let mut state = app.app_state.clone();
    let opens = {
        let leaf = attach_leaf(&mut state);
        let opens = Arc::clone(&leaf.tunnel_opens);
        spawn_leaf(leaf);
        opens
    };
    let router = mcp_bare_router(&state).with_state(state);
    let response = router
        .oneshot(tunnel_get(Some("203.0.113.9"), true))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(*opens.lock().unwrap(), 0);
}

#[tokio::test]
async fn tunnel_flood_is_429_before_open() {
    let app = TestApp::spawn().await;
    let mut state = app.app_state.clone();
    state.config.mcp.relay_rate_limit_per_minute = 2;
    let opens = {
        let leaf = attach_leaf(&mut state);
        let opens = Arc::clone(&leaf.tunnel_opens);
        spawn_leaf(leaf);
        opens
    };
    let router = mcp_bare_router(&state).with_state(state);
    let mut last = StatusCode::OK;
    for _ in 0..3 {
        let response = router
            .clone()
            .oneshot(tunnel_get(None, false))
            .await
            .unwrap();
        last = response.status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(*opens.lock().unwrap(), 0);
}

#[tokio::test]
async fn tunnel_at_cap_is_503_before_open() {
    let app = TestApp::spawn().await;
    let mut state = app.app_state.clone();
    state.config.mcp.max_tunnels = 0;
    let opens = {
        let leaf = attach_leaf(&mut state);
        let opens = Arc::clone(&leaf.tunnel_opens);
        spawn_leaf(leaf);
        opens
    };
    let router = mcp_bare_router(&state).with_state(state);
    let response = router.oneshot(tunnel_get(None, false)).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(*opens.lock().unwrap(), 0);
}
