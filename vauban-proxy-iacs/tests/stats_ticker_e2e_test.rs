//! E2E suite for the per-EWS-login `tunnel_stats` ticker (July 2026:
//! status-page byte counters stuck at zero on the privsep path).
//!
//! Drives the REAL production sshd (`server::IacsTunnelServer` via
//! `russh::server::run_stream`, identical to the accept loop in
//! `src/main.rs`) with a real `russh::client`, a real TCP echo
//! upstream, and a `Some(web_tx)` [`WebReporter`] -- then asserts on
//! the exact IPC messages vauban-web would receive:
//!
//! 1. `tunnel_active` first, then periodic `tunnel_stats` whose byte
//!    counters reflect the relayed traffic (the incident regression:
//!    they used to stay at zero forever);
//! 2. the reported sequence is monotonic non-decreasing (flush/close
//!    race absorbed by `stats::MonotonicReport`);
//! 3. `IacsTunnelClosed` carries final totals >= the last stats
//!    report, and the ticker STOPS after the handler drop (no leaked
//!    5 s tasks spamming the IPC bus);
//! 4. a login that never opens a `direct-tcpip` channel emits the
//!    lifecycle pair `ews_connected` (at auth) then
//!    `IacsTunnelClosed` (at drop) but NEVER spawns a ticker nor a
//!    `tunnel_active`;
//! 5. the terminate seam works pre-channel: the russh handle
//!    registered at auth force-disconnects an authenticated login
//!    that never opened a channel.
//!
//! The pure accounting invariants (skip-closed, saturation,
//! monotonic clamp) are proptest-covered in `src/stats.rs`; the
//! vauban-web side of the wire (IPC -> canonical WS frame -> Alpine
//! component) is covered by `vauban-web/tests/web/iacs_ws_vocab_test.rs`.

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use std::sync::Arc;
use std::time::Instant;

use russh::client::{self, Handler as ClientHandler};
use russh::keys::ssh_key::Algorithm;
use russh::keys::ssh_key::rand_core::UnwrapErr;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use shared::messages::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, UnboundedReceiver};
use tokio::time::{Duration, timeout};
use uuid::Uuid;

use vauban_proxy_iacs::auth::{PendingSessions, PendingTunnel, fingerprint_sha256_hex};
use vauban_proxy_iacs::iacs_recording::{AckRouter, IacsRecordingHub, RecordingMetrics};
use vauban_proxy_iacs::registry::{SessionHandles, TunnelRegistry};
use vauban_proxy_iacs::server::{IacsTunnelServer, UpstreamOpener, build_server_config};

/// Short tick so the suite completes in seconds instead of
/// multiples of the 5 s production interval. The production value
/// is pinned separately (`stats::STATS_INTERVAL`).
const TEST_TICK: Duration = Duration::from_millis(60);

// ===================================================================
// Harness (mirrors iacs_server_handshake_test.rs, plus a WebReporter)
// ===================================================================

struct TestClient;

impl ClientHandler for TestClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct EchoUpstreamOpener {
    target: std::net::SocketAddr,
}

#[async_trait::async_trait]
impl UpstreamOpener for EchoUpstreamOpener {
    async fn open(&self, _pending: &PendingTunnel) -> std::io::Result<TcpStream> {
        TcpStream::connect(self.target).await
    }
}

fn fresh_ed25519_key() -> PrivateKey {
    PrivateKey::random(&mut UnwrapErr(getrandom::SysRng), Algorithm::Ed25519)
        .expect("ed25519 keygen")
}

async fn spawn_echo_target() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo target");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Spawn the production sshd with a live `WebReporter` and the test
/// tick interval; returns the bound address, the IPC message
/// receiver (what vauban-web's pump would drain) and the shared
/// `SessionHandles` map (what the `IacsTunnelTerminate` IPC arm
/// consults to force-disconnect).
async fn spawn_reporting_sshd(
    pending: PendingSessions,
    target: std::net::SocketAddr,
) -> (
    std::net::SocketAddr,
    UnboundedReceiver<Message>,
    SessionHandles,
) {
    let cfg = build_server_config(fresh_ed25519_key());
    let registry = TunnelRegistry::new();
    let session_handles = SessionHandles::new();
    let handles_out = session_handles.clone();
    let upstream: Arc<dyn UpstreamOpener> = Arc::new(EchoUpstreamOpener { target });
    let (web_tx, web_rx) = mpsc::unbounded_channel::<Message>();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind sshd");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let mut server = IacsTunnelServer::new(
                registry.clone(),
                pending.clone(),
                session_handles.clone(),
                Arc::clone(&upstream),
                16,
                Some(web_tx.clone()),
                None,
            )
            .with_stats_interval(TEST_TICK);
            let handler = russh::server::Server::new_client(&mut server, Some(peer));
            let cfg = Arc::clone(&cfg);
            tokio::spawn(async move {
                let _ = russh::server::run_stream(cfg, stream, handler).await;
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    (addr, web_rx, handles_out)
}

/// Like [`spawn_reporting_sshd`] but ALSO wires a live
/// `IacsRecordingHub`; returns the audit-side IPC receiver so the
/// suite can assert on `IacsRecordingSessionStart` /
/// `IacsRecordingSessionEnd` (the zero-channel `session.json` /
/// `meta.json` contract).
async fn spawn_recording_sshd(
    pending: PendingSessions,
    target: std::net::SocketAddr,
) -> (
    std::net::SocketAddr,
    UnboundedReceiver<Message>,
    UnboundedReceiver<Message>,
    SessionHandles,
) {
    let cfg = build_server_config(fresh_ed25519_key());
    let registry = TunnelRegistry::new();
    let session_handles = SessionHandles::new();
    let handles_out = session_handles.clone();
    let upstream: Arc<dyn UpstreamOpener> = Arc::new(EchoUpstreamOpener { target });
    let (web_tx, web_rx) = mpsc::unbounded_channel::<Message>();
    let (audit_tx, audit_rx) = mpsc::unbounded_channel::<Message>();
    let hub = IacsRecordingHub {
        audit_tx,
        ack_router: Arc::new(AckRouter::new()),
        metrics: Arc::new(RecordingMetrics::default()),
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind sshd");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let mut server = IacsTunnelServer::new(
                registry.clone(),
                pending.clone(),
                session_handles.clone(),
                Arc::clone(&upstream),
                16,
                Some(web_tx.clone()),
                Some(hub.clone()),
            )
            .with_stats_interval(TEST_TICK);
            let handler = russh::server::Server::new_client(&mut server, Some(peer));
            let cfg = Arc::clone(&cfg);
            tokio::spawn(async move {
                let _ = russh::server::run_stream(cfg, stream, handler).await;
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    (addr, web_rx, audit_rx, handles_out)
}

fn make_pending(
    session_uuid: Uuid,
    key: &PrivateKey,
    target: std::net::SocketAddr,
) -> PendingTunnel {
    PendingTunnel {
        session_uuid,
        user_uuid: Uuid::new_v4(),
        asset_uuid: Uuid::new_v4(),
        ews_uuid: Uuid::new_v4(),
        ews_pubkey_fp: fingerprint_sha256_hex(key.public_key()).expect("fingerprint"),
        asset_host: target.ip().to_string(),
        asset_port: target.port(),
        industrial_protocol: "tcp".to_string(),
        session_token: vec![],
        deadline: Instant::now() + Duration::from_secs(300),
    }
}

async fn connect_authenticated(
    addr: std::net::SocketAddr,
    user: &str,
    key: PrivateKey,
) -> client::Handle<TestClient> {
    let cfg = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    });
    let mut handle = client::connect(cfg, addr, TestClient)
        .await
        .expect("connect");
    let signer = PrivateKeyWithHashAlg::new(Arc::new(key), None);
    assert!(
        handle
            .authenticate_publickey(user, signer)
            .await
            .expect("auth")
            .success(),
        "auth must succeed against the production sshd"
    );
    handle
}

/// Drain `rx` until a message matching `pred` arrives (or the
/// deadline trips), returning every drained message in order.
async fn drain_until(
    rx: &mut UnboundedReceiver<Message>,
    deadline: Duration,
    mut pred: impl FnMut(&Message) -> bool,
) -> Vec<Message> {
    let mut out = Vec::new();
    let end = tokio::time::Instant::now() + deadline;
    while tokio::time::Instant::now() < end {
        match timeout(Duration::from_millis(200), rx.recv()).await {
            Ok(Some(msg)) => {
                let done = pred(&msg);
                out.push(msg);
                if done {
                    return out;
                }
            }
            Ok(None) => break,
            Err(_) => {}
        }
    }
    out
}

fn stats_bytes(msg: &Message) -> Option<(u64, u64)> {
    match msg {
        Message::IacsTunnelStatusUpdate {
            status,
            bytes_in,
            bytes_out,
            ..
        } if status == "tunnel_stats" => Some((*bytes_in, *bytes_out)),
        _ => None,
    }
}

// ===================================================================
// Tests
// ===================================================================

/// THE incident regression: after traffic flows through the relay,
/// the periodic `tunnel_stats` reports MUST surface non-zero byte
/// counters (they used to stay at zero for the whole session), the
/// very first lifecycle message MUST still be `tunnel_active`, and
/// the reported sequence MUST be monotonic non-decreasing.
#[tokio::test]
async fn ticker_reports_nonzero_monotonic_bytes_while_relaying() {
    let key = fresh_ed25519_key();
    let session_uuid = Uuid::new_v4();
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, mut web_rx, _session_handles) =
        spawn_reporting_sshd(pending.clone(), target).await;
    pending
        .insert(make_pending(session_uuid, &key, target))
        .await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key).await;
    let chan = handle
        .channel_open_direct_tcpip(
            target.ip().to_string(),
            target.port() as u32,
            "127.0.0.1",
            0,
        )
        .await
        .expect("direct-tcpip");

    // Drive real bytes through the relay (echo round-trip).
    let stream = chan.into_stream();
    let (mut r, mut w) = tokio::io::split(stream);
    w.write_all(b"PING-STATS").await.expect("write");
    let mut buf = [0u8; 10];
    timeout(Duration::from_secs(2), r.read_exact(&mut buf))
        .await
        .expect("echo timeout")
        .expect("echo read");
    assert_eq!(&buf, b"PING-STATS");

    // Wait for a stats report with non-zero counters in BOTH
    // directions (>= 2 ticks of margin against scheduler jitter).
    let msgs = drain_until(&mut web_rx, Duration::from_secs(3), |m| {
        stats_bytes(m).is_some_and(|(b_in, b_out)| b_in > 0 && b_out > 0)
    })
    .await;

    // Lifecycle ordering: the SSH auth emits `ews_connected` first,
    // then the first direct-tcpip emits `tunnel_active`; both carry
    // the EWS peer IP.
    match msgs.first() {
        Some(Message::IacsTunnelStatusUpdate {
            session_id,
            status,
            peer_ip,
            ..
        }) => {
            assert_eq!(session_id, &session_uuid.to_string());
            assert_eq!(status, "ews_connected");
            assert!(
                peer_ip.is_some(),
                "the auth event must carry the EWS peer IP"
            );
        }
        other => panic!("first IPC message must be ews_connected, got {other:?}"),
    }
    match msgs.get(1) {
        Some(Message::IacsTunnelStatusUpdate {
            session_id,
            status,
            peer_ip,
            ..
        }) => {
            assert_eq!(session_id, &session_uuid.to_string());
            assert_eq!(status, "tunnel_active");
            assert!(peer_ip.is_some(), "activation must carry the EWS peer IP");
        }
        other => panic!("second IPC message must be tunnel_active, got {other:?}"),
    }

    let stats: Vec<(u64, u64)> = msgs.iter().filter_map(stats_bytes).collect();
    let last = stats
        .last()
        .copied()
        .expect("at least one tunnel_stats report must arrive while relaying");
    assert!(
        last.0 >= 10 && last.1 >= 10,
        "stats must reflect the 10-byte echo round-trip, got {last:?}"
    );
    for pair in stats.windows(2) {
        assert!(
            pair[1].0 >= pair[0].0 && pair[1].1 >= pair[0].1,
            "reported byte sequence must be monotonic: {stats:?}"
        );
    }

    drop(r);
    drop(w);
    drop(handle);
}

/// Teardown contract: after the EWS disconnects, `IacsTunnelClosed`
/// carries final totals >= the last stats report, and the ticker
/// STOPS -- no `tunnel_stats` may arrive once the close settles
/// (a leaked ticker would spam the IPC bus forever at 5 s cadence).
#[tokio::test]
async fn ticker_stops_after_disconnect_and_close_totals_dominate() {
    let key = fresh_ed25519_key();
    let session_uuid = Uuid::new_v4();
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, mut web_rx, _session_handles) =
        spawn_reporting_sshd(pending.clone(), target).await;
    pending
        .insert(make_pending(session_uuid, &key, target))
        .await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key).await;
    let chan = handle
        .channel_open_direct_tcpip(
            target.ip().to_string(),
            target.port() as u32,
            "127.0.0.1",
            0,
        )
        .await
        .expect("direct-tcpip");
    let stream = chan.into_stream();
    let (mut r, mut w) = tokio::io::split(stream);
    w.write_all(b"BYE").await.expect("write");
    let mut buf = [0u8; 3];
    timeout(Duration::from_secs(2), r.read_exact(&mut buf))
        .await
        .expect("echo timeout")
        .expect("echo read");

    // Let at least one stats tick fire while live.
    let live_msgs = drain_until(&mut web_rx, Duration::from_secs(3), |m| {
        stats_bytes(m).is_some_and(|(b_in, b_out)| b_in > 0 && b_out > 0)
    })
    .await;
    let last_stats = live_msgs.iter().filter_map(stats_bytes).next_back();

    // EWS disconnects.
    drop(r);
    drop(w);
    handle
        .disconnect(russh::Disconnect::ByApplication, "test done", "")
        .await
        .ok();
    drop(handle);

    // The authoritative close must arrive with dominating totals.
    let msgs = drain_until(&mut web_rx, Duration::from_secs(3), |m| {
        matches!(m, Message::IacsTunnelClosed { .. })
    })
    .await;
    let (final_in, final_out) = match msgs.last() {
        Some(Message::IacsTunnelClosed {
            session_id,
            reason,
            bytes_in,
            bytes_out,
            ..
        }) => {
            assert_eq!(session_id, &session_uuid.to_string());
            assert_eq!(reason, "ews_disconnect");
            (*bytes_in, *bytes_out)
        }
        other => panic!("expected IacsTunnelClosed, got {other:?}"),
    };
    if let Some((s_in, s_out)) = last_stats {
        assert!(
            final_in >= s_in && final_out >= s_out,
            "final totals ({final_in},{final_out}) must dominate the \
             last stats report ({s_in},{s_out})"
        );
    }

    // Grace: absorb any stats tick racing the drop (the ticker checks
    // SessionHandles BEFORE sending; a check/drop interleave can let
    // at most the in-flight tick through).
    tokio::time::sleep(TEST_TICK * 4).await;
    while web_rx.try_recv().is_ok() {}

    // Silence: the ticker must have observed the SessionHandles
    // removal by now; NOTHING may arrive any more.
    tokio::time::sleep(TEST_TICK * 4).await;
    let mut leaked = Vec::new();
    while let Ok(msg) = web_rx.try_recv() {
        leaked.push(msg);
    }
    assert!(
        leaked.is_empty(),
        "ticker leaked past the handler drop: {leaked:?}"
    );
}

/// Multi-channel accounting: the normal `ssh -L` workflow opens ONE
/// `direct-tcpip` channel per local TCP `accept()`, and several can
/// be live at once. The ticker MUST report the SUM across every
/// live channel of the login -- the session-keyed `TunnelRegistry`
/// (whose `insert` REPLACES the previous handle) would only surface
/// the newest channel and under-count everything else.
#[tokio::test]
async fn ticker_sums_bytes_across_concurrent_channels() {
    let key = fresh_ed25519_key();
    let session_uuid = Uuid::new_v4();
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, mut web_rx, _session_handles) =
        spawn_reporting_sshd(pending.clone(), target).await;
    pending
        .insert(make_pending(session_uuid, &key, target))
        .await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key).await;

    // Two channels live SIMULTANEOUSLY, 8 bytes echoed on each
    // (16 bytes per direction for the login). Both stay open while
    // the ticker samples.
    let mut halves = Vec::new();
    for payload in [b"CHAN-A-8", b"CHAN-B-8"] {
        let chan = handle
            .channel_open_direct_tcpip(
                target.ip().to_string(),
                target.port() as u32,
                "127.0.0.1",
                0,
            )
            .await
            .expect("direct-tcpip");
        let stream = chan.into_stream();
        let (mut r, mut w) = tokio::io::split(stream);
        w.write_all(payload).await.expect("write");
        let mut buf = [0u8; 8];
        timeout(Duration::from_secs(2), r.read_exact(&mut buf))
            .await
            .expect("echo timeout")
            .expect("echo read");
        assert_eq!(&buf, payload);
        halves.push((r, w));
    }

    // Wait for a stats report that covers BOTH channels' traffic.
    let msgs = drain_until(&mut web_rx, Duration::from_secs(3), |m| {
        stats_bytes(m).is_some_and(|(b_in, b_out)| b_in >= 16 && b_out >= 16)
    })
    .await;
    let last = msgs
        .iter()
        .filter_map(stats_bytes)
        .next_back()
        .expect("at least one tunnel_stats report");
    assert!(
        last.0 >= 16 && last.1 >= 16,
        "stats must sum BOTH live channels (2 x 8 bytes per \
         direction), got {last:?} -- sampling only the newest \
         registry handle would cap at 8"
    );

    drop(halves);
    drop(handle);
}

/// Zero-channel lifecycle: an authenticated login that never opens
/// a `direct-tcpip` channel emits EXACTLY the pair `ews_connected`
/// (at auth) then `IacsTunnelClosed { 0, 0 }` (at drop) -- never a
/// `tunnel_active`, never a `tunnel_stats` ticker. This is the
/// audit-trail contract for silent authenticated EWS logins.
#[tokio::test]
async fn no_ticker_without_a_direct_tcpip_channel() {
    let key = fresh_ed25519_key();
    let session_uuid = Uuid::new_v4();
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, mut web_rx, _session_handles) =
        spawn_reporting_sshd(pending.clone(), target).await;
    pending
        .insert(make_pending(session_uuid, &key, target))
        .await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key).await;

    // Hold the authenticated-but-channel-less session across
    // several would-be ticks, then disconnect.
    tokio::time::sleep(TEST_TICK * 5).await;
    handle
        .disconnect(russh::Disconnect::ByApplication, "test done", "")
        .await
        .ok();
    drop(handle);
    tokio::time::sleep(TEST_TICK * 4).await;

    let mut received = Vec::new();
    while let Ok(msg) = web_rx.try_recv() {
        received.push(msg);
    }
    assert_eq!(
        received.len(),
        2,
        "an auth-only login must emit exactly ews_connected then \
         IacsTunnelClosed, got {received:?}"
    );
    match &received[0] {
        Message::IacsTunnelStatusUpdate {
            session_id,
            status,
            peer_ip,
            ..
        } => {
            assert_eq!(session_id, &session_uuid.to_string());
            assert_eq!(status, "ews_connected");
            assert!(peer_ip.is_some(), "auth event must carry the peer IP");
        }
        other => panic!("first message must be ews_connected, got {other:?}"),
    }
    match &received[1] {
        Message::IacsTunnelClosed {
            session_id,
            reason,
            bytes_in,
            bytes_out,
            ..
        } => {
            assert_eq!(session_id, &session_uuid.to_string());
            assert_eq!(reason, "ews_disconnect");
            assert_eq!(
                (*bytes_in, *bytes_out),
                (0, 0),
                "zero-channel login must close with zero totals"
            );
        }
        other => panic!("second message must be IacsTunnelClosed, got {other:?}"),
    }
}

/// Pre-channel terminate: the russh handle registered by
/// `auth_succeeded` in `SessionHandles` must be able to
/// force-disconnect an authenticated login that never opened a
/// channel (the sequence the `Message::IacsTunnelTerminate` IPC arm
/// in main.rs drives, pinned by terminate_disconnects_ssh_test.rs).
/// The EWS-side connection MUST actually break, the pending token
/// MUST be purged, and the handler drop MUST still emit the
/// `IacsTunnelClosed` audit event.
#[tokio::test]
async fn terminate_after_auth_without_channel_disconnects_ssh() {
    let key = fresh_ed25519_key();
    let session_uuid = Uuid::new_v4();
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, mut web_rx, session_handles) =
        spawn_reporting_sshd(pending.clone(), target).await;
    pending
        .insert(make_pending(session_uuid, &key, target))
        .await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key).await;

    // The auth event must arrive before the terminate is issued
    // (vauban-web only surfaces the Terminate button once the row
    // is ews_connected).
    let msgs = drain_until(&mut web_rx, Duration::from_secs(3), |m| {
        matches!(
            m,
            Message::IacsTunnelStatusUpdate { status, .. } if status == "ews_connected"
        )
    })
    .await;
    assert!(
        msgs.iter().any(|m| matches!(
            m,
            Message::IacsTunnelStatusUpdate { status, .. } if status == "ews_connected"
        )),
        "ews_connected must be emitted at auth, got {msgs:?}"
    );

    // Drive the SAME sequence as the IacsTunnelTerminate arm in
    // main.rs: purge the pending token, then force-disconnect via
    // the auth-time russh handle.
    pending.take(&session_uuid).await;
    let server_handle = session_handles
        .get(&session_uuid)
        .expect("auth_succeeded must have registered the russh handle pre-channel");
    server_handle
        .disconnect(
            russh::Disconnect::ByApplication,
            "session terminated".to_string(),
            "".to_string(),
        )
        .await
        .expect("server-side disconnect must dispatch");

    // The EWS-side connection must actually break.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while !handle.is_closed() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        handle.is_closed(),
        "the EWS SSH connection must be closed by the server-side terminate"
    );

    // Handler drop emits the audit close for the zero-channel login.
    let msgs = drain_until(&mut web_rx, Duration::from_secs(3), |m| {
        matches!(m, Message::IacsTunnelClosed { .. })
    })
    .await;
    match msgs.last() {
        Some(Message::IacsTunnelClosed {
            session_id,
            bytes_in,
            bytes_out,
            ..
        }) => {
            assert_eq!(session_id, &session_uuid.to_string());
            assert_eq!((*bytes_in, *bytes_out), (0, 0));
        }
        other => panic!("terminate must still produce IacsTunnelClosed, got {other:?}"),
    }

    // The pending token is gone: a reconnect with the same key must
    // be refused.
    assert!(
        pending.take(&session_uuid).await.is_none(),
        "the pending token must stay purged after terminate"
    );
}

/// Zero-channel audit manifest: an authenticated login that never
/// opens a channel MUST still produce `IacsRecordingSessionStart`
/// at auth (vauban-audit writes `session.json` immediately) and
/// `IacsRecordingSessionEnd { reason: "ews_disconnect" }` at drop
/// (vauban-audit writes `meta.json` with `channels: []` and
/// finalizes `session.json`). The `authenticated_at_us` /
/// `connected_at_us` anchors MUST be equal (directory-layout
/// identity with the channel PCAPs).
#[tokio::test]
async fn zero_channel_login_emits_recording_session_start_and_end() {
    let key = fresh_ed25519_key();
    let session_uuid = Uuid::new_v4();
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, _web_rx, mut audit_rx, _handles) =
        spawn_recording_sshd(pending.clone(), target).await;
    let pending_row = make_pending(session_uuid, &key, target);
    let expected_user = pending_row.user_uuid;
    let expected_asset = pending_row.asset_uuid;
    let expected_fp = pending_row.ews_pubkey_fp.clone();
    pending.insert(pending_row).await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key).await;

    let msgs = drain_until(&mut audit_rx, Duration::from_secs(3), |m| {
        matches!(m, Message::IacsRecordingSessionStart { .. })
    })
    .await;
    match msgs.last() {
        Some(Message::IacsRecordingSessionStart {
            session_id,
            user_uuid,
            asset_uuid,
            ews_fingerprint,
            peer_ip,
            authenticated_at_us,
            connected_at_us,
        }) => {
            assert_eq!(session_id, &session_uuid.to_string());
            assert_eq!(user_uuid, &expected_user.to_string());
            assert_eq!(asset_uuid, &expected_asset.to_string());
            assert_eq!(ews_fingerprint, &expected_fp);
            assert!(!peer_ip.is_empty(), "auth event must carry the peer IP");
            assert!(*authenticated_at_us > 0);
            assert_eq!(
                authenticated_at_us, connected_at_us,
                "the auth instant IS the directory-layout anchor"
            );
        }
        other => panic!("expected IacsRecordingSessionStart, got {other:?}"),
    }

    handle
        .disconnect(russh::Disconnect::ByApplication, "test done", "")
        .await
        .ok();
    drop(handle);

    let msgs = drain_until(&mut audit_rx, Duration::from_secs(3), |m| {
        matches!(m, Message::IacsRecordingSessionEnd { .. })
    })
    .await;
    match msgs.last() {
        Some(Message::IacsRecordingSessionEnd { session_id, reason }) => {
            assert_eq!(session_id, &session_uuid.to_string());
            assert_eq!(
                reason, "ews_disconnect",
                "a voluntary close must be attributed to the EWS"
            );
        }
        other => panic!("expected IacsRecordingSessionEnd, got {other:?}"),
    }
}

/// Forced-close attribution: when the terminate seam records a
/// close reason before the disconnect (the `IacsTunnelTerminate`
/// arm), the drop-time `IacsRecordingSessionEnd` MUST carry THAT
/// reason instead of the `ews_disconnect` fallback.
#[tokio::test]
async fn terminate_reason_propagates_to_recording_session_end() {
    let key = fresh_ed25519_key();
    let session_uuid = Uuid::new_v4();
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, _web_rx, mut audit_rx, session_handles) =
        spawn_recording_sshd(pending.clone(), target).await;
    pending
        .insert(make_pending(session_uuid, &key, target))
        .await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key).await;

    // Wait for the auth-time SessionStart so the russh handle is
    // guaranteed registered.
    let msgs = drain_until(&mut audit_rx, Duration::from_secs(3), |m| {
        matches!(m, Message::IacsRecordingSessionStart { .. })
    })
    .await;
    assert!(
        msgs.iter()
            .any(|m| matches!(m, Message::IacsRecordingSessionStart { .. })),
        "SessionStart must be emitted at auth"
    );

    // Same sequence as the IacsTunnelTerminate IPC arm: record the
    // cause, then force-disconnect.
    session_handles.set_close_reason(session_uuid, "user_terminated");
    let server_handle = session_handles
        .get(&session_uuid)
        .expect("russh handle registered at auth");
    server_handle
        .disconnect(
            russh::Disconnect::ByApplication,
            "session terminated".to_string(),
            "".to_string(),
        )
        .await
        .expect("server-side disconnect must dispatch");

    let msgs = drain_until(&mut audit_rx, Duration::from_secs(3), |m| {
        matches!(m, Message::IacsRecordingSessionEnd { .. })
    })
    .await;
    match msgs.last() {
        Some(Message::IacsRecordingSessionEnd { session_id, reason }) => {
            assert_eq!(session_id, &session_uuid.to_string());
            assert_eq!(
                reason, "user_terminated",
                "the recorded close reason must dominate the fallback"
            );
        }
        other => panic!("expected IacsRecordingSessionEnd, got {other:?}"),
    }
    drop(handle);
}
