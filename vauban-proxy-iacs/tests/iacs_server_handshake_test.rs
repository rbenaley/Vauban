//! REAL russh handshake suite against the production
//! `vauban-proxy-iacs` sshd (`src/server.rs::IacsTunnelServer`).
//!
//! Before this suite existed, the proxy binary's russh `Handler` was
//! only covered by source-grep pin tests (`per_asset_target_test`,
//! `terminate_disconnects_ssh_test`, ...). The handshake itself --
//! KEX, publickey auth, the `direct-tcpip` relay and every refusal
//! path -- was never exercised against THIS binary's code; the only
//! live russh handshake in the tree ran against the (now-removed)
//! in-process copy that used to live in `vauban-web`.
//!
//! These tests drive the exact production code path: they build the
//! server via [`build_server_config`] + [`IacsTunnelServer::new`] +
//! `Server::new_client` + `russh::server::run_stream`, identical to
//! the accept loop in `src/main.rs`, and connect with a real
//! `russh::client`. The upstream broker (normally the supervisor
//! SCM_RIGHTS fd) is stubbed with a direct `TcpStream::connect` to a
//! local echo target via the production [`UpstreamOpener`] seam, and
//! the DB-less pre-authorization is seeded directly into
//! [`PendingSessions`] (exactly what `Message::IacsTunnelOpen` does in
//! production).
//!
//! This is the regression net the russh 0.57 -> 0.61 bump needed: an
//! API break in the server-side handler is now caught at CI time
//! instead of only at runtime in the field.

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use std::sync::Arc;
use std::time::Instant;

use russh::client::{self, Handler as ClientHandler};
use russh::keys::ssh_key::Algorithm;
use russh::keys::ssh_key::rand_core::UnwrapErr;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, timeout};
use uuid::Uuid;

use vauban_proxy_iacs::auth::{PendingSessions, PendingTunnel, fingerprint_sha256_hex};
use vauban_proxy_iacs::registry::{SessionHandles, TunnelRegistry};
use vauban_proxy_iacs::server::{IacsTunnelServer, UpstreamOpener, build_server_config};

const SSH_AUTH_FAILED: &str = "auth must fail";
const SSH_OPEN_REJECTED: &str = "channel open must be rejected";

// ===================================================================
// Test client + upstream stub
// ===================================================================

/// Trivial russh client `Handler` that accepts any server host key.
/// We are testing the SERVER side; host-key pinning on the client is
/// out of scope (the production EWS pins out-of-band via known_hosts).
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

/// Production [`UpstreamOpener`] seam stubbed with a direct TCP
/// connect to a local echo target. In production this is the IPC
/// client that asks `vauban-supervisor` to broker the asset fd over
/// SCM_RIGHTS; the russh handler code under test is identical either
/// way (it only sees a `tokio::net::TcpStream`).
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

/// Spawn an upstream TCP echo server on `127.0.0.1:0`; returns its
/// bound address. Used as the brokered `direct-tcpip` target so the
/// happy-path test can verify the relay actually moves bytes.
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

/// Build + run the production sshd on `127.0.0.1:0` against `target`,
/// returning the bound address and a clone of the live-tunnel
/// registry. Mirrors the accept loop in `src/main.rs` byte-for-byte
/// (only `web_reporter`/`recording` are `None`, which is the
/// test-harness contract documented on [`IacsTunnelServer`]).
async fn spawn_test_sshd(
    pending: PendingSessions,
    target: std::net::SocketAddr,
    max_channels_per_session: usize,
) -> (std::net::SocketAddr, TunnelRegistry) {
    let cfg = build_server_config(fresh_ed25519_key());
    let registry = TunnelRegistry::new();
    let session_handles = SessionHandles::new();
    let upstream: Arc<dyn UpstreamOpener> = Arc::new(EchoUpstreamOpener { target });

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind sshd");
    let addr = listener.local_addr().expect("local_addr");

    let accept_registry = registry.clone();
    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let mut server = IacsTunnelServer::new(
                accept_registry.clone(),
                pending.clone(),
                session_handles.clone(),
                Arc::clone(&upstream),
                max_channels_per_session,
                None,
                None,
            );
            let handler = russh::server::Server::new_client(&mut server, Some(peer));
            let cfg = Arc::clone(&cfg);
            tokio::spawn(async move {
                let _ = russh::server::run_stream(cfg, stream, handler).await;
            });
        }
    });
    // Give the listener a beat so a client connect cannot race the
    // bind on slow CI runners.
    tokio::time::sleep(Duration::from_millis(20)).await;
    (addr, registry)
}

/// Build a `PendingTunnel` pinning `key`'s fingerprint and `target`
/// as the per-session `(asset_host, asset_port)`, with a generous
/// deadline. `industrial_protocol = "tcp"` selects the Passthrough
/// gate so the echo bytes relay unaltered.
fn make_pending(session_uuid: Uuid, key: &PrivateKey, target: std::net::SocketAddr) -> PendingTunnel {
    PendingTunnel {
        session_uuid,
        user_uuid: Uuid::new_v4(),
        asset_uuid: Uuid::new_v4(),
        ews_uuid: Uuid::new_v4(),
        ews_pubkey_fp: fingerprint_sha256_hex(&key.public_key()).expect("fingerprint"),
        asset_host: target.ip().to_string(),
        asset_port: target.port(),
        industrial_protocol: "tcp".to_string(),
        session_token: vec![],
        deadline: Instant::now() + Duration::from_secs(300),
    }
}

fn client_config() -> Arc<client::Config> {
    Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    })
}

/// Connect, present `key` for `user`, expect auth success; returns
/// the client `Handle`.
async fn connect_authenticated(
    addr: std::net::SocketAddr,
    user: &str,
    key: PrivateKey,
) -> Result<client::Handle<TestClient>, russh::Error> {
    let mut handle = client::connect(client_config(), addr, TestClient).await?;
    let signer = PrivateKeyWithHashAlg::new(Arc::new(key), None);
    let ok = handle.authenticate_publickey(user, signer).await?;
    if !ok.success() {
        return Err(russh::Error::NoAuthMethod);
    }
    Ok(handle)
}

// ===================================================================
// Happy path
// ===================================================================

#[tokio::test]
async fn happy_path_real_handshake_relays_bytes() {
    let key = fresh_ed25519_key();
    let session_uuid = Uuid::new_v4();
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, registry) = spawn_test_sshd(pending.clone(), target, 16).await;
    pending.insert(make_pending(session_uuid, &key, target)).await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key)
        .await
        .expect("auth must succeed against the production sshd");

    let chan = handle
        .channel_open_direct_tcpip(target.ip().to_string(), target.port() as u32, "127.0.0.1", 0)
        .await
        .expect("direct-tcpip to the pinned target must succeed");

    let stream = chan.into_stream();
    let (mut r, mut w) = tokio::io::split(stream);
    w.write_all(b"PING").await.expect("write");
    let mut buf = [0u8; 4];
    timeout(Duration::from_secs(5), r.read_exact(&mut buf))
        .await
        .expect("read timeout")
        .expect("read");
    assert_eq!(&buf, b"PING", "the Passthrough relay must echo bytes back");

    // The live-tunnel registry must now hold this session.
    assert_eq!(registry.len(), 1, "registry must hold the live tunnel");
    let h = registry.get(&session_uuid).expect("handle present");
    let (bytes_in, bytes_out) = h.counters();
    assert!(bytes_in >= 4, "bytes_in must reflect the echo");
    assert!(bytes_out >= 4, "bytes_out must reflect the write");

    drop(w);
    drop(r);
    drop(handle);
}

// ===================================================================
// Auth-method refusals
// ===================================================================

#[tokio::test]
async fn refuses_password_auth() {
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, _registry) = spawn_test_sshd(pending, target, 16).await;

    let mut handle = client::connect(client_config(), sshd_addr, TestClient)
        .await
        .expect("connect");
    let auth = handle
        .authenticate_password("anyone", "anything")
        .await
        .expect("auth call");
    assert!(!auth.success(), "{}", SSH_AUTH_FAILED);
}

#[tokio::test]
async fn refuses_publickey_for_unknown_session_uuid() {
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, _registry) = spawn_test_sshd(pending, target, 16).await;

    let key = fresh_ed25519_key();
    let signer = PrivateKeyWithHashAlg::new(Arc::new(key), None);
    let mut handle = client::connect(client_config(), sshd_addr, TestClient)
        .await
        .expect("connect");
    // Random UUID never inserted into PendingSessions.
    let auth = handle
        .authenticate_publickey(Uuid::new_v4().to_string(), signer)
        .await
        .expect("auth call");
    assert!(!auth.success(), "{}", SSH_AUTH_FAILED);
}

#[tokio::test]
async fn refuses_publickey_with_non_uuid_username() {
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, _registry) = spawn_test_sshd(pending, target, 16).await;

    let key = fresh_ed25519_key();
    let signer = PrivateKeyWithHashAlg::new(Arc::new(key), None);
    let mut handle = client::connect(client_config(), sshd_addr, TestClient)
        .await
        .expect("connect");
    // Non-UUID username -> InvalidSessionUuidFormat.
    let auth = handle
        .authenticate_publickey("not-a-uuid", signer)
        .await
        .expect("auth call");
    assert!(!auth.success(), "{}", SSH_AUTH_FAILED);
}

#[tokio::test]
async fn refuses_publickey_with_unrelated_key_for_valid_session() {
    let real_key = fresh_ed25519_key();
    let session_uuid = Uuid::new_v4();
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, _registry) = spawn_test_sshd(pending.clone(), target, 16).await;
    pending
        .insert(make_pending(session_uuid, &real_key, target))
        .await;

    // Present a DIFFERENT key for the same (valid) session UUID.
    let other_key = fresh_ed25519_key();
    let signer = PrivateKeyWithHashAlg::new(Arc::new(other_key), None);
    let mut handle = client::connect(client_config(), sshd_addr, TestClient)
        .await
        .expect("connect");
    let auth = handle
        .authenticate_publickey(session_uuid.to_string(), signer)
        .await
        .expect("auth call");
    assert!(!auth.success(), "{}", SSH_AUTH_FAILED);
}

#[tokio::test]
async fn refuses_publickey_when_pending_expired() {
    let key = fresh_ed25519_key();
    let session_uuid = Uuid::new_v4();
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, _registry) = spawn_test_sshd(pending.clone(), target, 16).await;
    // Insert an entry whose deadline is already in the past.
    let mut entry = make_pending(session_uuid, &key, target);
    entry.deadline = Instant::now() - Duration::from_secs(1);
    pending.insert(entry).await;

    let signer = PrivateKeyWithHashAlg::new(Arc::new(key), None);
    let mut handle = client::connect(client_config(), sshd_addr, TestClient)
        .await
        .expect("connect");
    let auth = handle
        .authenticate_publickey(session_uuid.to_string(), signer)
        .await
        .expect("auth call");
    assert!(!auth.success(), "{}", SSH_AUTH_FAILED);
}

// ===================================================================
// Channel-open refusals (post-auth)
// ===================================================================

#[tokio::test]
async fn refuses_session_channel() {
    let key = fresh_ed25519_key();
    let session_uuid = Uuid::new_v4();
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, _registry) = spawn_test_sshd(pending.clone(), target, 16).await;
    pending.insert(make_pending(session_uuid, &key, target)).await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key)
        .await
        .expect("auth");
    let res = handle.channel_open_session().await;
    assert!(res.is_err(), "{}", SSH_OPEN_REJECTED);
}

#[tokio::test]
async fn refuses_direct_tcpip_to_wrong_target() {
    let key = fresh_ed25519_key();
    let session_uuid = Uuid::new_v4();
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, _registry) = spawn_test_sshd(pending.clone(), target, 16).await;
    pending.insert(make_pending(session_uuid, &key, target)).await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key)
        .await
        .expect("auth");
    // Same host, wrong port.
    let res = handle
        .channel_open_direct_tcpip(
            target.ip().to_string(),
            target.port().wrapping_add(1) as u32,
            "127.0.0.1",
            0,
        )
        .await;
    assert!(res.is_err(), "{}", SSH_OPEN_REJECTED);
    // Different host, right port.
    let res2 = handle
        .channel_open_direct_tcpip("8.8.8.8", target.port() as u32, "127.0.0.1", 0)
        .await;
    assert!(res2.is_err(), "{}", SSH_OPEN_REJECTED);
}

#[tokio::test]
async fn refuses_tcpip_forward() {
    let key = fresh_ed25519_key();
    let session_uuid = Uuid::new_v4();
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, _registry) = spawn_test_sshd(pending.clone(), target, 16).await;
    pending.insert(make_pending(session_uuid, &key, target)).await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key)
        .await
        .expect("auth");
    let res = handle.tcpip_forward("127.0.0.1", 0).await;
    assert!(res.is_err(), "tcpip_forward (-R) must be denied");
}

#[tokio::test]
async fn refuses_streamlocal_channel() {
    let key = fresh_ed25519_key();
    let session_uuid = Uuid::new_v4();
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, _registry) = spawn_test_sshd(pending.clone(), target, 16).await;
    pending.insert(make_pending(session_uuid, &key, target)).await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key)
        .await
        .expect("auth");
    let res = handle
        .channel_open_direct_streamlocal("/tmp/iacs.sock")
        .await;
    assert!(res.is_err(), "{}", SSH_OPEN_REJECTED);
}

// ===================================================================
// Per-login concurrent channel cap
// ===================================================================

/// With the per-login cap set to 2, the third CONCURRENT
/// `direct-tcpip` MUST be rejected (anti-fan-out), and closing one of
/// the in-flight channels MUST return its slot to the pool.
#[tokio::test]
async fn enforces_per_login_concurrent_channel_cap() {
    let key = fresh_ed25519_key();
    let session_uuid = Uuid::new_v4();
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, _registry) = spawn_test_sshd(pending.clone(), target, 2).await;
    pending.insert(make_pending(session_uuid, &key, target)).await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key)
        .await
        .expect("auth");

    let chan_a = handle
        .channel_open_direct_tcpip(target.ip().to_string(), target.port() as u32, "127.0.0.1", 0)
        .await
        .expect("first concurrent channel within cap");
    let chan_b = handle
        .channel_open_direct_tcpip(target.ip().to_string(), target.port() as u32, "127.0.0.1", 0)
        .await
        .expect("second concurrent channel within cap");

    let third = handle
        .channel_open_direct_tcpip(target.ip().to_string(), target.port() as u32, "127.0.0.1", 0)
        .await;
    assert!(
        third.is_err(),
        "the THIRD concurrent direct-tcpip MUST be rejected when the \
         per-login cap is 2 (anti-fan-out exfil defence)"
    );

    // Closing one in-flight channel returns its slot to the pool.
    chan_a.close().await.expect("close first");
    tokio::time::sleep(Duration::from_millis(80)).await;
    let chan_c = handle
        .channel_open_direct_tcpip(target.ip().to_string(), target.port() as u32, "127.0.0.1", 0)
        .await
        .expect("a freed slot must allow a new direct-tcpip");
    let _ = chan_b.close().await;
    let _ = chan_c.close().await;
}
