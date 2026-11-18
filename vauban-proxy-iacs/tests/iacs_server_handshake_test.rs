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
//! This is the regression net every russh bump needs (0.57 -> 0.61,
//! 0.61 -> 0.65): an API break in the server-side handler is caught
//! at CI time instead of only at runtime in the field. Since russh
//! 0.62 a channel open is answered through a `ChannelOpenHandle`
//! (accept / reject) instead of a returned `bool`; the refusal tests
//! below pin the reason the EWS receives.

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use std::sync::Arc;
use std::time::Instant;

use russh::client::{self, Handler as ClientHandler};
use russh::keys::ssh_key::Algorithm;
use russh::keys::ssh_key::rand_core::UnwrapErr;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
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
        _server_public_key: &PublicKeyOrCertificate,
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
    pending
        .insert(make_pending(session_uuid, &key, target))
        .await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key)
        .await
        .expect("auth must succeed against the production sshd");

    let chan = handle
        .channel_open_direct_tcpip(
            target.ip().to_string(),
            target.port() as u32,
            "127.0.0.1",
            0,
        )
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

/// The first line the sshd sends, to anyone who connects and before any
/// authentication, names neither the SSH library nor a version. It used
/// to be `SSH-2.0-russh_<version>`.
#[tokio::test]
async fn attack_banner_discloses_no_library_or_version() {
    use tokio::io::AsyncReadExt;

    let target = spawn_echo_target().await;
    let (addr, _registry) = spawn_test_sshd(PendingSessions::new(), target, 4).await;

    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while !line.ends_with(b"\r\n") && line.len() < 255 {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte))
            .await
            .expect("the sshd speaks first")
            .expect("read");
        assert_eq!(n, 1, "connection closed before the identification");
        line.push(byte[0]);
    }
    let banner = String::from_utf8(line).expect("ASCII");
    assert_eq!(banner, "SSH-2.0-Vauban\r\n");
    assert_eq!(banner.trim_end(), vauban_proxy_iacs::server::SSH_SERVER_ID);
    assert!(!banner.to_ascii_lowercase().contains("russh"));
    assert!(
        !banner["SSH-2.0-".len()..]
            .bytes()
            .any(|b| b.is_ascii_digit()),
        "no version after the protocol version: {banner:?}"
    );
}

/// Read the `SSH_MSG_KEXINIT` the sshd sends in clear right after the
/// identification strings, and return its ten name-lists (RFC 4253,
/// section 7.1). This is what a scanner sees, not what the code says.
async fn server_kexinit(addr: std::net::SocketAddr) -> Vec<Vec<String>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    stream.write_all(b"SSH-2.0-probe\r\n").await.expect("id");
    let read = async {
        let mut byte = [0u8; 1];
        let mut line = Vec::new();
        while !line.ends_with(b"\r\n") {
            stream.read_exact(&mut byte).await.expect("banner");
            line.push(byte[0]);
        }
        let mut header = [0u8; 5];
        stream.read_exact(&mut header).await.expect("packet header");
        let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        assert!(length < 35_000, "packet length {length}");
        let mut body = vec![0u8; length - 1];
        stream.read_exact(&mut body).await.expect("packet body");
        body
    };
    let body = tokio::time::timeout(Duration::from_secs(5), read)
        .await
        .expect("the sshd sends its KEXINIT");
    assert_eq!(body[0], 20, "SSH_MSG_KEXINIT");
    let mut at = 1 + 16; // message number, cookie
    let mut lists = Vec::new();
    for _ in 0..10 {
        let len = u32::from_be_bytes([body[at], body[at + 1], body[at + 2], body[at + 3]]) as usize;
        at += 4;
        let names = std::str::from_utf8(&body[at..at + len]).expect("ASCII");
        at += len;
        lists.push(
            names
                .split(',')
                .filter(|n| !n.is_empty())
                .map(str::to_string)
                .collect(),
        );
    }
    lists
}

/// What the sshd offers on the wire is the short list chosen for the
/// OpenSSH of Windows 11 and recent OpenSSH elsewhere, not the library's
/// default: no finite-field Diffie-Hellman, no ChaCha20 or CTR (Terrapin
/// without strict key exchange), no plain MAC, no compression before
/// authentication.
#[tokio::test]
async fn attack_only_the_chosen_algorithms_are_offered() {
    let target = spawn_echo_target().await;
    let (addr, _registry) = spawn_test_sshd(PendingSessions::new(), target, 4).await;
    let lists = server_kexinit(addr).await;

    assert_eq!(
        lists[0],
        [
            "mlkem768x25519-sha256",
            "curve25519-sha256",
            "ext-info-s",
            "kex-strict-s-v00@openssh.com"
        ],
        "key exchange, with strict key exchange still announced"
    );
    assert_eq!(lists[1], ["ssh-ed25519"], "host key");
    for (what, i) in [("client to server", 2), ("server to client", 3)] {
        assert_eq!(lists[i], ["aes256-gcm@openssh.com"], "cipher {what}");
    }
    for i in [4, 5] {
        assert_eq!(
            lists[i],
            [
                "hmac-sha2-512-etm@openssh.com",
                "hmac-sha2-256-etm@openssh.com"
            ],
            "MAC"
        );
    }
    for i in [6, 7] {
        assert_eq!(lists[i], ["none"], "compression");
    }
    let all = lists.concat().join(",");
    for gone in [
        "diffie-hellman",
        "chacha20",
        "-ctr",
        "-cbc",
        "zlib",
        "sha1",
        "rsa",
    ] {
        assert!(!all.contains(gone), "{gone} is offered: {all}");
    }
}

/// A client that only speaks what was removed does not get a session.
#[tokio::test]
async fn attack_client_with_removed_algorithms_only_is_refused() {
    let target = spawn_echo_target().await;
    let (addr, _registry) = spawn_test_sshd(PendingSessions::new(), target, 4).await;

    for (what, preferred) in [
        (
            "ChaCha20 only",
            russh::Preferred {
                cipher: std::borrow::Cow::Borrowed(&[russh::cipher::CHACHA20_POLY1305]),
                ..Default::default()
            },
        ),
        (
            "finite-field Diffie-Hellman only",
            russh::Preferred {
                kex: std::borrow::Cow::Borrowed(&[
                    russh::kex::DH_G14_SHA256,
                    russh::kex::DH_G16_SHA512,
                ]),
                ..Default::default()
            },
        ),
    ] {
        let config = Arc::new(client::Config {
            inactivity_timeout: Some(Duration::from_secs(5)),
            preferred,
            ..Default::default()
        });
        let result = client::connect(config, addr, TestClient).await;
        assert!(result.is_err(), "{what}: the key exchange must fail");
    }
}

/// The OpenSSH client of this machine completes the key exchange with
/// the short list and ends on AES-256-GCM. Needs `ssh` on the PATH, so
/// it is run by hand: `cargo test -p vauban-proxy-iacs --test
/// iacs_server_handshake_test -- --ignored openssh`.
#[tokio::test]
#[ignore = "needs the OpenSSH client; run by hand"]
async fn openssh_client_negotiates_the_short_list() {
    let target = spawn_echo_target().await;
    let (addr, _registry) = spawn_test_sshd(PendingSessions::new(), target, 4).await;

    // The second run is what an OpenSSH 8.x has: no post-quantum hybrid.
    for (kex_option, expected_kex) in [
        (None, "mlkem768x25519-sha256"),
        (Some("KexAlgorithms=curve25519-sha256"), "curve25519-sha256"),
    ] {
        let port = addr.port().to_string();
        // A blocking child on a blocking thread: the sshd keeps running
        // on the runtime while `ssh` talks to it.
        let output = tokio::task::spawn_blocking(move || {
            let mut ssh = std::process::Command::new("ssh");
            ssh.args(["-vv", "-F", "/dev/null", "-p", &port]);
            for option in [
                "BatchMode=yes",
                "StrictHostKeyChecking=no",
                "UserKnownHostsFile=/dev/null",
                "PreferredAuthentications=none",
                "ConnectTimeout=5",
            ]
            .into_iter()
            .chain(kex_option)
            {
                ssh.args(["-o", option]);
            }
            ssh.arg("probe@127.0.0.1").output()
        })
        .await
        .expect("join")
        .expect("run ssh");
        let log = String::from_utf8_lossy(&output.stderr);
        assert!(log.contains("remote software version Vauban"), "{log}");
        assert!(
            log.contains("kex: server->client cipher: aes256-gcm@openssh.com")
                && log.contains("kex: client->server cipher: aes256-gcm@openssh.com"),
            "{log}"
        );
        assert!(log.contains("compression: none"), "{log}");
        // The newest OpenSSH takes the hybrid; an older one would take
        // Curve25519 in the first run too.
        assert!(
            log.contains(&format!("kex: algorithm: {expected_kex}"))
                || (kex_option.is_none() && log.contains("kex: algorithm: curve25519-sha256")),
            "{log}"
        );
        assert!(
            log.contains("kex: host key algorithm: ssh-ed25519"),
            "{log}"
        );
    }
}

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

/// Signs the authentication request with a key that is NOT the one
/// named in the request: the wire format is valid, the signature is
/// not.
struct ForgingSigner {
    attacker_key: PrivateKey,
}

impl russh::Signer for ForgingSigner {
    type Error = russh::AgentAuthError;

    async fn auth_sign(
        &mut self,
        _key: &russh::keys::agent::AgentIdentity,
        _hash_alg: Option<russh::keys::HashAlg>,
        mut to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        use russh::keys::signature::Signer as _;
        use russh::keys::ssh_encoding::Encode as _;

        let sig: russh::keys::ssh_key::Signature = self
            .attacker_key
            .try_sign(&to_sign)
            .expect("attacker signature");
        // Same framing as the russh agent client: the request, then
        // string(string(algorithm) || string(signature)).
        let algo = sig.algorithm().as_str().to_string();
        let raw = sig.as_bytes().to_vec();
        (algo.len() + raw.len() + 8)
            .encode(&mut to_sign)
            .expect("length");
        algo.encode(&mut to_sign).expect("algorithm");
        raw.encode(&mut to_sign).expect("signature");
        Ok(to_sign)
    }
}

/// An attacker who knows the session UUID and the EWS PUBLIC key (both
/// are not secrets) claims that key but cannot sign with it. russh
/// verifies the signature before it calls `auth_publickey`, so the
/// handler never sees the key as verified: the login is refused and
/// the pre-authorization is NOT consumed -- the legitimate EWS can
/// still log in afterwards.
#[tokio::test]
async fn attack_publickey_with_forged_signature_is_rejected() {
    let real_key = fresh_ed25519_key();
    let session_uuid = Uuid::new_v4();
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, _registry) = spawn_test_sshd(pending.clone(), target, 16).await;
    pending
        .insert(make_pending(session_uuid, &real_key, target))
        .await;

    let mut handle = client::connect(client_config(), sshd_addr, TestClient)
        .await
        .expect("connect");
    let mut forger = ForgingSigner {
        attacker_key: fresh_ed25519_key(),
    };
    let auth = handle
        .authenticate_publickey_with(
            session_uuid.to_string(),
            real_key.public_key().clone(),
            None,
            &mut forger,
        )
        .await;
    assert!(
        !matches!(auth, Ok(ref r) if r.success()),
        "a claimed key with a forged signature must not authenticate"
    );
    // No channel for the attacker.
    let res = handle
        .channel_open_direct_tcpip(
            target.ip().to_string(),
            target.port() as u32,
            "127.0.0.1",
            0,
        )
        .await;
    assert!(res.is_err(), "{}", SSH_OPEN_REJECTED);

    // The pending entry survived the forged attempt.
    connect_authenticated(sshd_addr, &session_uuid.to_string(), real_key)
        .await
        .expect("the legitimate EWS must still authenticate");
}

// ===================================================================
// Channel-open refusals (post-auth)
// ===================================================================

/// The EWS must be told `administratively prohibited`, the reason
/// russh 0.61 sent for a handler returning `Ok(false)`.
fn assert_administratively_prohibited<T>(res: Result<T, russh::Error>, what: &str) {
    match res {
        Err(russh::Error::ChannelOpenFailure(
            russh::ChannelOpenFailure::AdministrativelyProhibited,
        )) => {}
        Err(other) => panic!("{what}: refused with an unexpected error: {other:?}"),
        Ok(_) => panic!("{what}: {SSH_OPEN_REJECTED}"),
    }
}

#[tokio::test]
async fn attack_x11_channel_is_rejected() {
    let key = fresh_ed25519_key();
    let session_uuid = Uuid::new_v4();
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, registry) = spawn_test_sshd(pending.clone(), target, 16).await;
    pending
        .insert(make_pending(session_uuid, &key, target))
        .await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key)
        .await
        .expect("auth");
    assert_administratively_prohibited(handle.channel_open_x11("127.0.0.1", 6000).await, "x11");
    assert!(
        registry.is_empty(),
        "a refused channel must not register a tunnel"
    );
}

/// Every refused channel type answers `administratively prohibited`,
/// and a refusal leaves the login usable for the one permitted
/// channel (the refusal is a channel-level failure, not a session
/// teardown, and it does not leak a slot of the per-login cap).
#[tokio::test]
async fn attack_refused_channel_types_are_rejected_with_prohibited_reason() {
    let key = fresh_ed25519_key();
    let session_uuid = Uuid::new_v4();
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    // Cap of 1: a leaked slot would make the final open fail.
    let (sshd_addr, _registry) = spawn_test_sshd(pending.clone(), target, 1).await;
    pending
        .insert(make_pending(session_uuid, &key, target))
        .await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key)
        .await
        .expect("auth");
    assert_administratively_prohibited(handle.channel_open_session().await, "session");
    assert_administratively_prohibited(handle.channel_open_x11("127.0.0.1", 6000).await, "x11");
    assert_administratively_prohibited(
        handle
            .channel_open_direct_streamlocal("/tmp/iacs.sock")
            .await,
        "direct-streamlocal",
    );
    assert_administratively_prohibited(
        handle
            .channel_open_direct_tcpip("8.8.8.8", target.port() as u32, "127.0.0.1", 0)
            .await,
        "direct-tcpip to a foreign host",
    );

    let mut chan = handle
        .channel_open_direct_tcpip(
            target.ip().to_string(),
            target.port() as u32,
            "127.0.0.1",
            0,
        )
        .await
        .expect("the pinned target stays reachable after refusals")
        .into_stream();
    chan.write_all(b"ping").await.expect("write");
    let mut buf = [0u8; 4];
    timeout(Duration::from_secs(5), chan.read_exact(&mut buf))
        .await
        .expect("echo within 5 s")
        .expect("read");
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn refuses_session_channel() {
    let key = fresh_ed25519_key();
    let session_uuid = Uuid::new_v4();
    let target = spawn_echo_target().await;
    let pending = PendingSessions::new();
    let (sshd_addr, _registry) = spawn_test_sshd(pending.clone(), target, 16).await;
    pending
        .insert(make_pending(session_uuid, &key, target))
        .await;

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
    pending
        .insert(make_pending(session_uuid, &key, target))
        .await;

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
    pending
        .insert(make_pending(session_uuid, &key, target))
        .await;

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
    pending
        .insert(make_pending(session_uuid, &key, target))
        .await;

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
    pending
        .insert(make_pending(session_uuid, &key, target))
        .await;

    let handle = connect_authenticated(sshd_addr, &session_uuid.to_string(), key)
        .await
        .expect("auth");

    let chan_a = handle
        .channel_open_direct_tcpip(
            target.ip().to_string(),
            target.port() as u32,
            "127.0.0.1",
            0,
        )
        .await
        .expect("first concurrent channel within cap");
    let chan_b = handle
        .channel_open_direct_tcpip(
            target.ip().to_string(),
            target.port() as u32,
            "127.0.0.1",
            0,
        )
        .await
        .expect("second concurrent channel within cap");

    let third = handle
        .channel_open_direct_tcpip(
            target.ip().to_string(),
            target.port() as u32,
            "127.0.0.1",
            0,
        )
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
        .channel_open_direct_tcpip(
            target.ip().to_string(),
            target.port() as u32,
            "127.0.0.1",
            0,
        )
        .await
        .expect("a freed slot must allow a new direct-tcpip");
    let _ = chan_b.close().await;
    let _ = chan_c.close().await;
}
