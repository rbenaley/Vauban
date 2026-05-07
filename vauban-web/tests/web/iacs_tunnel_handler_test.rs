//! L3 -- IACS sshd adversarial test suite.
//!
//! Pins the runtime contract of the in-process russh server
//! (`vauban_web::services::iacs_tunnel`):
//!
//!   * publickey-only authentication; a valid `(session_uuid,
//!     EWS pubkey)` pair handshakes successfully and the relay
//!     round-trips bytes;
//!   * every other surface is refused (password auth,
//!     keyboard-interactive, session/x11/forwarded-tcpip channel
//!     opens, second `direct-tcpip`, wrong target, shell/exec/
//!     subsystem/pty/agent on a session channel, tcpip-forward,
//!     streamlocal-forward).
//!
//! Each test spins up a fresh sshd on `127.0.0.1:0` (ephemeral
//! port -- stress-test friendly), seeds the DB with the rows the
//! `auth.rs` module needs, and connects with a real russh client.
//!
//! The companion lint `vauban-web/scripts/check_iacs_proxy_no_shell.sh`
//! enforces the source-level absence of any allow path; this
//! suite is the runtime counterpart.

use crate::common::TestApp;
use crate::fixtures::{create_simple_user, unique_name};
use chrono::Utc;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use russh::client::{self, Handler as ClientHandler};
use russh::keys::ssh_key::Algorithm;
use russh::keys::ssh_key::rand_core::OsRng;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{Duration, timeout};
use uuid::Uuid;
use vauban_web::config::IacsTunnelConfig;
use vauban_web::services::iacs_tunnel::{TunnelRegistry, spawn_iacs_tunnel_server};

// ===================================================================
// Shared setup
// ===================================================================

const SSH_AUTH_FAILED: &str = "auth must fail";
const SSH_OPEN_REJECTED: &str = "channel open must be rejected";

/// A trivial russh client `Handler` that accepts any server host
/// key. The adversarial suite is testing the SERVER side; we do
/// not care about HostKey pinning on the client (the production
/// EWS will pin the host key out-of-band via the operator's
/// `~/.ssh/known_hosts`).
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

fn fresh_ed25519_key() -> PrivateKey {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("ed25519 keygen")
}

/// SHA-256 hex over the OpenSSH wire blob (algorithm-name +
/// payload). This is the format `services::iacs::compute_fp` and
/// `services::iacs_tunnel::auth::fingerprint_sha256_hex` agree on.
fn fingerprint_sha256_hex(key: &PrivateKey) -> String {
    use base64::Engine;
    use russh::keys::PublicKeyBase64;
    let blob = key.public_key().public_key_base64();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(blob.as_bytes())
        .expect("base64");
    hex::encode(Sha256::digest(&bytes))
}

/// Spawn an upstream TCP echo server on `127.0.0.1:0`; returns
/// the bound address. Used as the `target_addr` for a sshd
/// instance under test. Echoing back lets the happy-path test
/// verify the bidirectional relay actually moves bytes.
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

/// Spawn an IACS sshd bound on `127.0.0.1:0` with the given
/// `target_addr`. Returns the bound address (so the test client
/// can connect without race) and a clone of the registry.
async fn spawn_test_sshd(
    app: &TestApp,
    target_addr: std::net::SocketAddr,
) -> (std::net::SocketAddr, TunnelRegistry) {
    let host_key_path = std::env::temp_dir().join(format!(
        "vauban_iacs_test_host_{}.key",
        Uuid::new_v4()
    ));
    let cfg = IacsTunnelConfig {
        enabled: true,
        bind_addr: "127.0.0.1:0".to_string(),
        advertise_hostname: "127.0.0.1".to_string(),
        target_addr: target_addr.to_string(),
        host_key_path: host_key_path.to_string_lossy().to_string(),
        max_concurrent_per_user: 0,
        max_concurrent_per_ews: 0,
        waiting_client_ttl_seconds: 300,
        revocation_poll_interval_seconds: 2,
    };
    let registry = TunnelRegistry::new();
    let (addr, _join) =
        spawn_iacs_tunnel_server(registry.clone(), app.db_pool.clone(), cfg)
            .await
            .expect("spawn sshd");
    // Give the listener a beat so a client connect cannot race
    // the bind on slow CI runners.
    tokio::time::sleep(Duration::from_millis(20)).await;
    (addr, registry)
}

/// Insert a minimal IACS asset row directly. The full
/// onboarding pipeline is exercised by the L2/L4 e2e tests; this
/// adversarial suite just needs a valid `asset_id` to satisfy
/// `proxy_sessions.asset_id NOT NULL`.
async fn seed_iacs_asset(conn: &mut AsyncPgConnection, admin_id: i32) -> i32 {
    use vauban_web::schema::assets;
    let asset_uuid = Uuid::new_v4();
    let label = unique_name("iacs_asset");
    let id: i32 = diesel::insert_into(assets::table)
        .values((
            assets::uuid.eq(asset_uuid),
            assets::name.eq(label.clone()),
            assets::hostname.eq(format!("{}.test.local", label)),
            assets::port.eq(4321),
            assets::asset_type.eq("iacs_modbus"),
            assets::status.eq("active"),
            assets::connection_username.eq(""),
            assets::connection_config.eq(serde_json::json!({})),
            assets::created_by_id.eq(admin_id),
        ))
        .returning(assets::id)
        .get_result(conn)
        .await
        .expect("seed asset");
    id
}

/// Seed the DB with a `proxy_sessions` row in `waiting_client`
/// state plus a matching active EWS row whose pubkey fingerprint
/// matches `key`. Returns the session UUID (= the SSH user name
/// the client must present).
async fn seed_session_and_ews(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    key: &PrivateKey,
) -> (Uuid, Uuid) {
    let asset_id = seed_iacs_asset(conn, user_id).await;
    let request_uuid = Uuid::new_v4();
    let ews_uuid = Uuid::new_v4();
    let session_uuid = Uuid::new_v4();
    let now = Utc::now();
    let fp = fingerprint_sha256_hex(key);
    let label = unique_name("ews");

    diesel::sql_query(
        "INSERT INTO ews_onboarding_requests \
         (uuid, user_id, name, public_key, public_key_fingerprint, key_algo, \
          status, justification, decided_by_id, decided_at, created_at, updated_at) \
         VALUES ($1, $2, $3, 'ssh-ed25519 placeholder', $4, 'ed25519', \
                 'approved', 'seed-justification', $2, $5, $5, $5)",
    )
    .bind::<diesel::sql_types::Uuid, _>(request_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Text, _>(label.clone())
    .bind::<diesel::sql_types::Text, _>(&fp)
    .bind::<diesel::sql_types::Timestamptz, _>(now)
    .execute(conn)
    .await
    .expect("seed onboarding request");

    diesel::sql_query(
        "INSERT INTO ews \
         (uuid, request_uuid, user_id, name, public_key, public_key_fingerprint, \
          key_algo, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, 'ssh-ed25519 placeholder', $5, 'ed25519', $6, $6)",
    )
    .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
    .bind::<diesel::sql_types::Uuid, _>(request_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Text, _>(label)
    .bind::<diesel::sql_types::Text, _>(&fp)
    .bind::<diesel::sql_types::Timestamptz, _>(now)
    .execute(conn)
    .await
    .expect("seed ews");

    diesel::sql_query(
        "INSERT INTO proxy_sessions \
         (uuid, user_id, asset_id, credential_id, credential_username, \
          session_type, status, client_ip, ews_uuid, industrial_protocol, \
          tunnel_target_addr) \
         VALUES ($1, $2, $3, '', '', 'iacs_tunnel', 'waiting_client', \
                 '127.0.0.1'::inet, $4, 'iacs_modbus', '127.0.0.1:4321')",
    )
    .bind::<diesel::sql_types::Uuid, _>(session_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Integer, _>(asset_id)
    .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
    .execute(conn)
    .await
    .expect("seed proxy_sessions");

    (session_uuid, ews_uuid)
}

fn client_config() -> Arc<client::Config> {
    Arc::new(client::Config {
        // Fast inactivity timeout so a deny path that hangs the
        // connection cannot stall the test runner.
        inactivity_timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    })
}

/// Connect a russh client to `addr`, present `key` for `user`,
/// expect auth success. Returns the client `Handle`.
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
async fn happy_path_relay_round_trips_bytes() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id =
        create_simple_user(&mut conn, &unique_name("iacs_tunnel_user")).await;
    let key = fresh_ed25519_key();
    let (session_uuid, _ews_uuid) =
        seed_session_and_ews(&mut conn, user_id, &key).await;
    drop(conn);

    let target = spawn_echo_target().await;
    let (sshd_addr, registry) = spawn_test_sshd(app, target).await;
    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key)
        .await
        .expect("auth must succeed");

    // Open a direct-tcpip to the configured target (target.host:port).
    let chan = handle
        .channel_open_direct_tcpip(
            target.ip().to_string(),
            target.port() as u32,
            "127.0.0.1",
            0,
        )
        .await
        .expect("direct-tcpip must succeed for matching target");

    let stream = chan.into_stream();
    let (mut r, mut w) = tokio::io::split(stream);
    w.write_all(b"PING").await.expect("write");
    let mut buf = [0u8; 4];
    timeout(Duration::from_secs(5), r.read_exact(&mut buf))
        .await
        .expect("read timeout")
        .expect("read");
    assert_eq!(&buf, b"PING");

    // Registry should know about this tunnel.
    assert_eq!(registry.len(), 1, "registry must hold the live tunnel");
    let h = registry.get(&session_uuid).expect("handle");
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
    let app = TestApp::spawn().await;
    let target = spawn_echo_target().await;
    let (sshd_addr, _registry) = spawn_test_sshd(app, target).await;

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
    let app = TestApp::spawn().await;
    let target = spawn_echo_target().await;
    let (sshd_addr, _registry) = spawn_test_sshd(app, target).await;

    let key = fresh_ed25519_key();
    let signer = PrivateKeyWithHashAlg::new(Arc::new(key), None);
    let mut handle = client::connect(client_config(), sshd_addr, TestClient)
        .await
        .expect("connect");
    // Random UUID never inserted in proxy_sessions.
    let auth = handle
        .authenticate_publickey(Uuid::new_v4().to_string(), signer)
        .await
        .expect("auth call");
    assert!(!auth.success(), "{}", SSH_AUTH_FAILED);
}

#[tokio::test]
async fn refuses_publickey_with_unrelated_key_for_valid_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("iacs_other_key")).await;
    let real_key = fresh_ed25519_key();
    let (session_uuid, _) = seed_session_and_ews(&mut conn, user_id, &real_key).await;
    drop(conn);

    let target = spawn_echo_target().await;
    let (sshd_addr, _registry) = spawn_test_sshd(app, target).await;

    // Present a different key for the same session UUID.
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
async fn refuses_publickey_when_session_in_wrong_state() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("iacs_wrong_state")).await;
    let key = fresh_ed25519_key();
    let (session_uuid, _) = seed_session_and_ews(&mut conn, user_id, &key).await;
    // Flip the session row to an unrelated status -- must reject.
    use vauban_web::schema::proxy_sessions;
    diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq(session_uuid)))
        .set(proxy_sessions::status.eq("terminated"))
        .execute(&mut conn)
        .await
        .expect("flip status");
    drop(conn);

    let target = spawn_echo_target().await;
    let (sshd_addr, _registry) = spawn_test_sshd(app, target).await;

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
// Channel-open refusals
// ===================================================================

#[tokio::test]
async fn refuses_session_channel() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("iacs_no_session")).await;
    let key = fresh_ed25519_key();
    let (session_uuid, _) = seed_session_and_ews(&mut conn, user_id, &key).await;
    drop(conn);

    let target = spawn_echo_target().await;
    let (sshd_addr, _registry) = spawn_test_sshd(app, target).await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key)
        .await
        .expect("auth");
    let res = handle.channel_open_session().await;
    assert!(res.is_err(), "{}", SSH_OPEN_REJECTED);
}

#[tokio::test]
async fn refuses_direct_tcpip_to_wrong_target() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("iacs_wrong_target")).await;
    let key = fresh_ed25519_key();
    let (session_uuid, _) = seed_session_and_ews(&mut conn, user_id, &key).await;
    drop(conn);

    let target = spawn_echo_target().await;
    let (sshd_addr, _registry) = spawn_test_sshd(app, target).await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key)
        .await
        .expect("auth");
    // Same host, different port.
    let res = handle
        .channel_open_direct_tcpip("127.0.0.1", target.port().wrapping_add(1) as u32, "127.0.0.1", 0)
        .await;
    assert!(res.is_err(), "{}", SSH_OPEN_REJECTED);
    // Different host, same port.
    let res2 = handle
        .channel_open_direct_tcpip("8.8.8.8", target.port() as u32, "127.0.0.1", 0)
        .await;
    assert!(res2.is_err(), "{}", SSH_OPEN_REJECTED);
}

#[tokio::test]
async fn refuses_second_direct_tcpip_on_same_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("iacs_one_chan")).await;
    let key = fresh_ed25519_key();
    let (session_uuid, _) = seed_session_and_ews(&mut conn, user_id, &key).await;
    drop(conn);

    let target = spawn_echo_target().await;
    let (sshd_addr, _registry) = spawn_test_sshd(app, target).await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key)
        .await
        .expect("auth");
    let _first = handle
        .channel_open_direct_tcpip(
            target.ip().to_string(),
            target.port() as u32,
            "127.0.0.1",
            0,
        )
        .await
        .expect("first direct-tcpip must succeed");
    let second = handle
        .channel_open_direct_tcpip(
            target.ip().to_string(),
            target.port() as u32,
            "127.0.0.1",
            0,
        )
        .await;
    assert!(
        second.is_err(),
        "second direct-tcpip on same session must be rejected"
    );
}

#[tokio::test]
async fn refuses_tcpip_forward() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name("iacs_no_forward")).await;
    let key = fresh_ed25519_key();
    let (session_uuid, _) = seed_session_and_ews(&mut conn, user_id, &key).await;
    drop(conn);

    let target = spawn_echo_target().await;
    let (sshd_addr, _registry) = spawn_test_sshd(app, target).await;

    let mut handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key)
        .await
        .expect("auth");
    let res = handle.tcpip_forward("127.0.0.1", 0).await;
    assert!(res.is_err(), "tcpip_forward must be denied");
}

#[tokio::test]
async fn refuses_streamlocal_channel() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id =
        create_simple_user(&mut conn, &unique_name("iacs_no_streamlocal")).await;
    let key = fresh_ed25519_key();
    let (session_uuid, _) = seed_session_and_ews(&mut conn, user_id, &key).await;
    drop(conn);

    let target = spawn_echo_target().await;
    let (sshd_addr, _registry) = spawn_test_sshd(app, target).await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key)
        .await
        .expect("auth");
    let res = handle
        .channel_open_direct_streamlocal("/tmp/iacs.sock")
        .await;
    assert!(res.is_err(), "{}", SSH_OPEN_REJECTED);
}

// ===================================================================
// Boot-time refusals
// ===================================================================

#[tokio::test]
async fn refuses_to_spawn_when_disabled() {
    let app = TestApp::spawn().await;
    let cfg = IacsTunnelConfig {
        enabled: false,
        ..Default::default()
    };
    let res = spawn_iacs_tunnel_server(
        TunnelRegistry::new(),
        app.db_pool.clone(),
        cfg,
    )
    .await;
    assert!(
        res.is_err(),
        "spawn_iacs_tunnel_server must refuse when enabled=false"
    );
}

#[tokio::test]
async fn refuses_to_spawn_when_bind_equals_target() {
    let app = TestApp::spawn().await;
    let cfg = IacsTunnelConfig {
        enabled: true,
        bind_addr: "127.0.0.1:42424".to_string(),
        target_addr: "127.0.0.1:42424".to_string(),
        host_key_path: std::env::temp_dir()
            .join(format!("vauban_iacs_loop_{}.key", Uuid::new_v4()))
            .to_string_lossy()
            .to_string(),
        ..Default::default()
    };
    let res = spawn_iacs_tunnel_server(
        TunnelRegistry::new(),
        app.db_pool.clone(),
        cfg,
    )
    .await;
    assert!(
        res.is_err(),
        "spawn_iacs_tunnel_server must refuse self-loop config"
    );
}
