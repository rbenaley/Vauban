//! Hop-2 bare router: the leaf sees only the allow-listed ticket, and
//! the edges refuse before that.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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
use vauban_web::ipc::proxy_mcp_data::{ProxyMcpDataClient, TunnelLimits};
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

fn data_of(state: &vauban_web::AppState) -> Arc<ProxyMcpDataClient> {
    state
        .proxy_mcp
        .as_ref()
        .and_then(|proxy| proxy.data())
        .expect("data pipe attached")
}

#[tokio::test]
async fn attack_oversize_tunnel_frame_does_not_kill_relay() {
    let app = TestApp::spawn().await;
    let mut state = app.app_state.clone();
    let leaf = attach_leaf(&mut state);
    spawn_leaf(leaf);
    let data = data_of(&state);
    let id = data.reserve_tunnel_id();
    let _rx = data
        .open_tunnel(id, "198.51.100.20".into(), TunnelLimits::default())
        .unwrap();
    data.send_tunnel(id, vec![0x5A; 1_048_576]).unwrap();
    let router = mcp_bare_router(&state).with_state(state);
    let response = router
        .oneshot(post(b"{}", "Bearer vbw_ticket", None, None))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the data pipe must survive a 1 MiB tunnel frame"
    );
}

#[tokio::test]
async fn attack_huge_authorization_is_rejected() {
    let app = TestApp::spawn().await;
    let mut state = app.app_state.clone();
    let relays = {
        let leaf = attach_leaf(&mut state);
        let relays = Arc::clone(&leaf.relays);
        spawn_leaf(leaf);
        relays
    };
    let router = mcp_bare_router(&state).with_state(state);
    let bearer = format!("Bearer vbw_{}", "a".repeat(9000));
    let response = router
        .clone()
        .oneshot(post(b"{}", &bearer, None, None))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );
    let mut request = post(b"{}", "Bearer vbw_ticket", None, None);
    request
        .headers_mut()
        .insert("accept", "x".repeat(2000).parse().unwrap());
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        *relays.lock().unwrap(),
        0,
        "no relay for an oversize header"
    );
}

#[tokio::test]
async fn attack_per_ip_tunnel_cap_is_enforced() {
    let app = TestApp::spawn_ip_acl().await;
    let mut state = app.app_state.clone();
    state.config.mcp.max_tunnels_per_ip = 16;
    let leaf = attach_leaf(&mut state);
    spawn_leaf(leaf);
    let data = data_of(&state);
    let limits = vauban_web::handlers::mcp_relay::tunnel_limits(&state);
    let mut held = Vec::new();
    for _ in 0..16 {
        let id = data.reserve_tunnel_id();
        held.push((id, data.open_tunnel(id, "10.0.0.5".into(), limits).unwrap()));
    }
    let router = mcp_bare_router(&state).with_state(state);
    let refused = router
        .clone()
        .oneshot(tunnel_get(Some("10.0.0.5"), true))
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
    let other = router
        .clone()
        .oneshot(tunnel_get(Some("10.0.0.6"), true))
        .await
        .unwrap();
    assert_ne!(other.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_ne!(other.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(data.tunnels_for_ip("10.0.0.5"), 16);

    for (id, _) in &held {
        data.close_tunnel(*id, "close");
    }
    drop(held);
    assert_eq!(data.tunnels_for_ip("10.0.0.5"), 0);
    let seventeenth = router
        .oneshot(tunnel_get(Some("10.0.0.5"), true))
        .await
        .unwrap();
    assert_ne!(
        seventeenth.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "closing the 16 tunnels must give the IP its slots back"
    );
    assert_ne!(seventeenth.status(), StatusCode::TOO_MANY_REQUESTS);
}

async fn wait_for_ip_count(data: &ProxyMcpDataClient, ip: &str, want: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while data.tunnels_for_ip(ip) != want {
        assert!(
            std::time::Instant::now() < deadline,
            "{ip}: {} tunnels, want {want}",
            data.tunnels_for_ip(ip)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Sixteen real WebSockets fill the per-IP cap on a served router. The
/// 17th upgrade is refused; once the sixteen close, the IP gets its
/// slots back and the next upgrade reaches the leaf.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_per_ip_cap_frees_after_sixteen_real_websockets_close() {
    use futures_util::SinkExt;
    use std::net::SocketAddr;
    use tokio_tungstenite::tungstenite::Error as WsError;

    let app = TestApp::spawn().await;
    let mut state = app.app_state.clone();
    state.config.mcp.max_tunnels_per_ip = 16;
    state.config.mcp.relay_rate_limit_per_minute = 1000;
    let leaf = attach_leaf(&mut state);
    let opens = Arc::clone(&leaf.tunnel_opens);
    spawn_leaf(leaf);
    let data = data_of(&state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service = mcp_bare_router(&state)
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, service).await;
    });
    let url = format!("ws://{addr}/mcp/tunnel");
    let ip = "127.0.0.1";

    let mut sockets = Vec::new();
    for _ in 0..16 {
        let (ws, resp) = tokio_tungstenite::connect_async(&url).await.unwrap();
        assert_eq!(resp.status().as_u16(), 101);
        sockets.push(ws);
    }
    wait_for_ip_count(&data, ip, 16).await;

    match tokio_tungstenite::connect_async(&url).await {
        Err(WsError::Http(resp)) => assert_eq!(resp.status().as_u16(), 503),
        Err(other) => panic!("17th upgrade: unexpected error {other}"),
        Ok(_) => panic!("17th upgrade must be refused while 16 tunnels are open"),
    }
    assert_eq!(data.tunnels_for_ip(ip), 16);

    for mut ws in sockets {
        ws.close(None).await.unwrap();
        let _ = ws.flush().await;
    }
    wait_for_ip_count(&data, ip, 0).await;

    let before = *opens.lock().unwrap();
    let (_ws, resp) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("the IP has its slots back");
    assert_eq!(resp.status().as_u16(), 101);
    wait_for_ip_count(&data, ip, 1).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while *opens.lock().unwrap() <= before {
        assert!(
            std::time::Instant::now() < deadline,
            "leaf never saw the new tunnel"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The leaf ends every tunnel (idle or handshake timeout). Web must
/// free the slots so the cap does not stay exhausted.
#[tokio::test]
async fn attack_idle_tunnels_do_not_exhaust_slots() {
    let app = TestApp::spawn().await;
    let mut state = app.app_state.clone();
    state.config.mcp.max_tunnels = 4;
    state.config.mcp.max_tunnels_per_ip = 4;
    let leaf = attach_leaf(&mut state);
    let peer = leaf.peer;
    std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            match peer.try_recv() {
                Ok(Message::McpTunnelOpen { tunnel_id, .. }) => {
                    let _ = peer.send(&Message::McpTunnelClose {
                        tunnel_id,
                        reason: "idle".into(),
                    });
                }
                Ok(_) => {}
                Err(e) if would_block(&e) => std::thread::sleep(Duration::from_millis(2)),
                Err(_) => break,
            }
        }
    });
    let data = data_of(&state);
    let limits = vauban_web::handlers::mcp_relay::tunnel_limits(&state);
    let mut streams = Vec::new();
    for _ in 0..4 {
        let id = data.reserve_tunnel_id();
        streams.push(
            data.open_tunnel(id, "198.51.100.30".into(), limits)
                .unwrap(),
        );
    }
    for mut rx in streams {
        let end = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("leaf close reaches web");
        assert!(end.is_none());
    }
    assert_eq!(data.tunnel_count(), 0);
    let router = mcp_bare_router(&state).with_state(state);
    let again = router.oneshot(tunnel_get(None, true)).await.unwrap();
    assert_ne!(again.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn two_xff_clients_get_two_rate_buckets() {
    let app = TestApp::spawn_ip_acl().await;
    let mut state = app.app_state.clone();
    state.config.mcp.relay_rate_limit_per_minute = 2;
    let leaf = attach_leaf(&mut state);
    spawn_leaf(leaf);
    let router = mcp_bare_router(&state).with_state(state);
    let mut last = StatusCode::OK;
    for _ in 0..3 {
        last = router
            .clone()
            .oneshot(post(b"{}", "Bearer vbw_ticket", None, Some("10.0.0.7")))
            .await
            .unwrap()
            .status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    let other = router
        .oneshot(post(b"{}", "Bearer vbw_ticket", None, Some("10.0.0.8")))
        .await
        .unwrap();
    assert_eq!(other.status(), StatusCode::OK);
}

#[tokio::test]
async fn attack_untrusted_xff_does_not_pick_the_rate_bucket() {
    let app = TestApp::spawn().await;
    let mut state = app.app_state.clone();
    state.config.security.trusted_proxies = vec![];
    state.config.mcp.relay_rate_limit_per_minute = 2;
    let leaf = attach_leaf(&mut state);
    spawn_leaf(leaf);
    let router = mcp_bare_router(&state).with_state(state);
    for xff in ["192.0.2.1", "192.0.2.2"] {
        let ok = router
            .clone()
            .oneshot(post(b"{}", "Bearer vbw_ticket", None, Some(xff)))
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
    }
    let third = router
        .oneshot(post(b"{}", "Bearer vbw_ticket", None, Some("192.0.2.3")))
        .await
        .unwrap();
    assert_eq!(
        third.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a spoofed X-Forwarded-For must not open a fresh bucket"
    );
}

#[tokio::test]
async fn hop2_client_ip_honours_only_trusted_proxies() {
    use std::net::{IpAddr, SocketAddr};
    use vauban_web::handlers::mcp_relay::hop2_client_ip;
    let trusted = TestApp::spawn_ip_acl().await.app_state.clone();
    let mut untrusted = trusted.clone();
    untrusted.config.security.trusted_proxies = vec![];
    let loopback: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-forwarded-for", "10.1.2.3".parse().unwrap());
    let via_proxy: IpAddr = "10.1.2.3".parse().unwrap();
    assert_eq!(hop2_client_ip(&trusted, &headers, loopback), via_proxy);
    assert_eq!(
        hop2_client_ip(&untrusted, &headers, loopback),
        loopback.ip()
    );
    let outsider: SocketAddr = "198.51.100.40:5000".parse().unwrap();
    assert_eq!(hop2_client_ip(&trusted, &headers, outsider), outsider.ip());

    let mut runner = proptest::test_runner::TestRunner::default();
    runner
        .run(&proptest::prelude::any::<[u8; 4]>(), |octets| {
            let mut headers = axum::http::HeaderMap::new();
            let spoof = std::net::Ipv4Addr::from(octets).to_string();
            headers.insert("x-forwarded-for", spoof.parse().unwrap());
            proptest::prop_assert_eq!(
                hop2_client_ip(&untrusted, &headers, outsider),
                outsider.ip()
            );
            proptest::prop_assert_eq!(hop2_client_ip(&trusted, &headers, outsider), outsider.ip());
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn battle_two_xff_clients_in_parallel_keep_separate_buckets() {
    let app = TestApp::spawn_ip_acl().await;
    let mut state = app.app_state.clone();
    state.config.mcp.relay_rate_limit_per_minute = 4;
    let leaf = attach_leaf(&mut state);
    spawn_leaf(leaf);
    let router = mcp_bare_router(&state).with_state(state);
    let barrier = Arc::new(tokio::sync::Barrier::new(16));
    let mut joins = Vec::new();
    for i in 0..16 {
        let router = router.clone();
        let barrier = Arc::clone(&barrier);
        let xff = if i % 2 == 0 { "10.0.0.11" } else { "10.0.0.12" };
        joins.push(tokio::spawn(async move {
            barrier.wait().await;
            let status = router
                .oneshot(post(b"{}", "Bearer vbw_ticket", None, Some(xff)))
                .await
                .unwrap()
                .status();
            (xff, status)
        }));
    }
    let mut ok = std::collections::HashMap::new();
    for join in joins {
        let (xff, status) = join.await.unwrap();
        if status == StatusCode::OK {
            *ok.entry(xff).or_insert(0) += 1;
        } else {
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        }
    }
    assert_eq!(ok.get("10.0.0.11"), Some(&4));
    assert_eq!(ok.get("10.0.0.12"), Some(&4));
}

/// The leaf gives up first (`McpRelayAbort { reason: "timeout" }`), so
/// web answers 502 long before its own relay timeout.
#[tokio::test]
async fn leaf_timeout_abort_arrives_before_the_web_timeout() {
    let app = TestApp::spawn().await;
    let mut state = app.app_state.clone();
    let leaf = attach_leaf(&mut state);
    let peer = leaf.peer;
    std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            match peer.try_recv() {
                Ok(Message::McpRelayBody {
                    relay_id,
                    last: true,
                    ..
                }) => {
                    std::thread::sleep(Duration::from_millis(200));
                    let _ = peer.send(&Message::McpRelayAbort {
                        relay_id,
                        reason: "timeout".into(),
                    });
                }
                Ok(_) => {}
                Err(e) if would_block(&e) => std::thread::sleep(Duration::from_millis(2)),
                Err(_) => break,
            }
        }
    });
    let web_timeout = state.config.mcp.relay_timeout_seconds;
    let router = mcp_bare_router(&state).with_state(state);
    let started = std::time::Instant::now();
    let response = router
        .oneshot(post(b"{}", "Bearer vbw_ticket", None, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(started.elapsed() < Duration::from_secs(web_timeout));
    assert!(started.elapsed() < Duration::from_secs(3));
}

/// 64 parallel POSTs against a slow leaf: `relay_max_inflight` relays
/// run, the rest get 503 at once, and every answer is the caller's own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn battle_sixty_four_posts_respect_the_inflight_cap() {
    let app = TestApp::spawn().await;
    let mut state = app.app_state.clone();
    state.config.mcp.relay_max_inflight = 8;
    state.config.mcp.relay_rate_limit_per_minute = 10_000;
    let leaf = attach_leaf(&mut state);
    let peer = Arc::new(leaf.peer);
    let send_lock = Arc::new(Mutex::new(()));
    std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            match peer.try_recv() {
                Ok(Message::McpRelayBody { relay_id, data, .. }) => {
                    let peer = Arc::clone(&peer);
                    let send_lock = Arc::clone(&send_lock);
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(1500));
                        let _guard = send_lock.lock().unwrap();
                        let _ = peer.send(&Message::McpRelayResponse {
                            relay_id,
                            status: 200,
                            content_type: "application/json".into(),
                            mcp_session_id: None,
                            body_len: data.len() as u32,
                        });
                        let _ = peer.send(&Message::McpRelayBody {
                            relay_id,
                            seq: 0,
                            last: true,
                            data,
                        });
                    });
                }
                Ok(_) => {}
                Err(e) if would_block(&e) => std::thread::sleep(Duration::from_millis(1)),
                Err(_) => break,
            }
        }
    });
    let router = mcp_bare_router(&state).with_state(state);
    let barrier = Arc::new(tokio::sync::Barrier::new(64));
    let mut joins = Vec::new();
    for i in 0..64u32 {
        let router = router.clone();
        let barrier = Arc::clone(&barrier);
        joins.push(tokio::spawn(async move {
            barrier.wait().await;
            let body = format!("{{\"caller\":{i}}}");
            let request = Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .header("authorization", "Bearer vbw_ticket")
                .body(Body::from(body.clone()))
                .unwrap();
            let response = router.oneshot(request).await.unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            (status, body, bytes)
        }));
    }
    let mut ok = 0;
    for join in joins {
        let (status, sent, got) = join.await.unwrap();
        match status {
            StatusCode::OK => {
                ok += 1;
                assert_eq!(got, sent.as_bytes(), "no relay_id cross-talk");
            }
            StatusCode::SERVICE_UNAVAILABLE => {}
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(ok, 8, "exactly relay_max_inflight relays ran");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn battle_oversize_frames_and_relays_share_the_pipe() {
    let app = TestApp::spawn().await;
    let mut state = app.app_state.clone();
    state.config.mcp.relay_rate_limit_per_minute = 10_000;
    let leaf = attach_leaf(&mut state);
    spawn_leaf(leaf);
    let data = data_of(&state);
    let router = mcp_bare_router(&state).with_state(state);
    let barrier = Arc::new(tokio::sync::Barrier::new(32));
    let mut pushers = Vec::new();
    for i in 0..16u8 {
        let data = Arc::clone(&data);
        let barrier = Arc::clone(&barrier);
        pushers.push(tokio::spawn(async move {
            let id = data.reserve_tunnel_id();
            let rx = data
                .open_tunnel(id, format!("198.51.100.{i}"), TunnelLimits::default())
                .unwrap();
            barrier.wait().await;
            data.send_tunnel(id, vec![i; 1_048_576]).unwrap();
            rx
        }));
    }
    let mut relays = Vec::new();
    for _ in 0..16 {
        let router = router.clone();
        let barrier = Arc::clone(&barrier);
        relays.push(tokio::spawn(async move {
            barrier.wait().await;
            router
                .oneshot(post(b"{}", "Bearer vbw_ticket", None, None))
                .await
                .unwrap()
                .status()
        }));
    }
    for relay in relays {
        assert_eq!(relay.await.unwrap(), StatusCode::OK);
    }
    for pusher in pushers {
        drop(pusher.await.unwrap());
    }
}
