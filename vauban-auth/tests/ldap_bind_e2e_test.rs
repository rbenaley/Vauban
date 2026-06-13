//! End-to-end tests for the LDAPS bind, exercised at the highest
//! fidelity possible without Docker:
//!
//! * a real, in-process LDAPS server (rcgen-generated CA + server cert, real
//!   rustls TLS termination, the production BER simple-bind codec),
//! * a test "supervisor" broker that performs the `connect()` and hands the
//!   connected socket back to `vauban-auth` over a real `SCM_RIGHTS` socketpair,
//! * the production [`vauban_auth::bind::brokered_bind`] orchestration.
//!
//! So every test below drives a genuine TLS handshake + LDAP simple bind over a
//! genuinely FD-passed TCP socket -- the exact wire path used in production,
//! minus the supervisor process boundary.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rustls::{ServerConfig, ServerConnection};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use shared::ipc::{IpcChannel, poll_readable, send_fd, socketpair_for_fd_passing};
use shared::messages::{LdapBindOutcome, Message, Service};

use vauban_auth::bind::{LdapRuntime, brokered_bind};
use vauban_auth::ldap::{
    LDAP_INVALID_CREDENTIALS, LDAP_SUCCESS, encode_bind_response, parse_bind_request,
    read_ldap_message,
};
use vauban_auth::tls::build_client_config;

const DN_TEMPLATE: &str = "uid={username},ou=people,dc=example,dc=com";

// ============================================================================
// Test PKI: a throwaway CA + a server leaf signed by it (SAN = `server_dns`).
// ============================================================================

struct TestPki {
    /// PEM the client (vauban-auth) trusts as its sole anchor.
    ca_pem: String,
    server_cert_der: CertificateDer<'static>,
    server_key_der: PrivateKeyDer<'static>,
}

fn generate_pki(server_dns: &str) -> TestPki {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    };

    // Certificate authority (self-signed, can sign leaves).
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Vauban Test LDAP CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    // Server leaf, signed by the CA, with the directory hostname in its SAN.
    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(vec![server_dns.to_string()]).unwrap();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, server_dns);
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

    TestPki {
        ca_pem,
        server_cert_der: leaf_cert.der().clone(),
        server_key_der: PrivateKeyDer::try_from(leaf_key.serialize_der()).unwrap(),
    }
}

fn server_config(pki: &TestPki) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![pki.server_cert_der.clone()],
            pki.server_key_der.clone_key(),
        )
        .unwrap();
    Arc::new(cfg)
}

// ============================================================================
// In-process LDAPS server. Accepts connections, terminates TLS, parses the
// simple-bind request with the production codec, and answers success only for
// known (DN, password) couples.
// ============================================================================

struct TestLdapServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl TestLdapServer {
    fn start(pki: &TestPki, creds: Vec<(String, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = server_config(pki);
        let creds = Arc::new(creds);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_t = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            while !stop_t.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if let Err(e) = handle_conn(stream, Arc::clone(&cfg), &creds) {
                            eprintln!("test ldap server: connection error: {e}");
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            addr,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for TestLdapServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn handle_conn(
    mut stream: TcpStream,
    cfg: Arc<ServerConfig>,
    creds: &[(String, String)],
) -> std::io::Result<()> {
    // The accepted socket inherits the listener's non-blocking flag on macOS;
    // restore blocking semantics so the TLS handshake reads don't EAGAIN.
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true).ok();
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut conn = ServerConnection::new(cfg).map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut tls = rustls::Stream::new(&mut conn, &mut stream);

    let raw = read_ldap_message(&mut tls)?;
    let (message_id, dn, password) = parse_bind_request(&raw)?;
    let password = String::from_utf8_lossy(&password);

    let granted = creds
        .iter()
        .any(|(known_dn, known_pw)| known_dn == &dn && known_pw == &password);
    let code = if granted {
        LDAP_SUCCESS
    } else {
        LDAP_INVALID_CREDENTIALS
    };

    tls.write_all(&encode_bind_response(message_id, code))?;
    tls.flush()?;
    Ok(())
}

// ============================================================================
// Test broker: emulates the supervisor's `handle_tcp_connect_request` arm for
// `Service::Auth`. On a `TcpConnectRequest` it (depending on the configured
// behavior) connects to the directory and hands the FD to auth via SCM_RIGHTS,
// then answers `TcpConnectResponse`.
// ============================================================================

enum BrokerBehavior {
    /// Connect to `addr`, pass the FD, answer success (nominal supervisor arm).
    ConnectAndPass(SocketAddr),
    /// Answer success but never pass an FD (exercises the non-blocking recv_fd
    /// safety: auth must not wedge waiting for a socket that never arrives).
    SuccessWithoutFd(SocketAddr),
    /// Refuse outright (whitelist deny / disabled `[auth.ldaps]` / connect fail).
    Refuse,
}

struct TestBroker {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl TestBroker {
    fn start(channel: IpcChannel, fd_sock: OwnedFd, behavior: BrokerBehavior) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_t = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            // Hold the SCM_RIGHTS socket end open for the broker's lifetime.
            let fd_raw: RawFd = fd_sock.as_raw_fd();

            while !stop_t.load(Ordering::Relaxed) {
                match poll_readable(&[channel.read_fd()], 50) {
                    Ok(ready) if !ready.is_empty() => {}
                    Ok(_) => continue,
                    Err(_) => break,
                }

                let req = match channel.recv() {
                    Ok(m) => m,
                    Err(_) => break,
                };

                let Message::TcpConnectRequest {
                    request_id,
                    session_id,
                    target_service,
                    ..
                } = req
                else {
                    continue;
                };
                // Sanity: auth must request the FD against its own service slot.
                assert_eq!(target_service, Service::Auth);

                match &behavior {
                    BrokerBehavior::ConnectAndPass(addr) => match TcpStream::connect(addr) {
                        Ok(stream) => {
                            // FD first (queued in the socket), THEN the response:
                            // mirrors the supervisor's ordering that auth relies on.
                            let _ = send_fd(fd_raw, stream.as_raw_fd());
                            let _ = channel.send(&Message::TcpConnectResponse {
                                request_id,
                                session_id,
                                success: true,
                                error: None,
                            });
                            // The receiver now owns a dup; our copy can close.
                            drop(stream);
                        }
                        Err(e) => {
                            let _ = channel.send(&Message::TcpConnectResponse {
                                request_id,
                                session_id,
                                success: false,
                                error: Some(e.to_string()),
                            });
                        }
                    },
                    BrokerBehavior::SuccessWithoutFd(addr) => {
                        let _ = TcpStream::connect(addr);
                        let _ = channel.send(&Message::TcpConnectResponse {
                            request_id,
                            session_id,
                            success: true,
                            error: None,
                        });
                    }
                    BrokerBehavior::Refuse => {
                        let _ = channel.send(&Message::TcpConnectResponse {
                            request_id,
                            session_id,
                            success: false,
                            error: Some("not whitelisted".to_string()),
                        });
                    }
                }
            }

            drop(fd_sock);
        });

        Self {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for TestBroker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// ============================================================================
// Harness helpers
// ============================================================================

fn runtime(ca_pem: &str, host: &str, port: u16, fd_sock: RawFd) -> LdapRuntime {
    LdapRuntime {
        client_config: build_client_config(ca_pem).unwrap(),
        host: host.to_string(),
        port,
        dn_template: DN_TEMPLATE.to_string(),
        timeout: Duration::from_secs(5),
        fd_passing_socket: fd_sock,
    }
}

fn closed_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    addr
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn ldap_bind_happy_path_returns_success() {
    let pki = generate_pki("localhost");
    let dn = DN_TEMPLATE.replace("{username}", "alice");
    let server = TestLdapServer::start(&pki, vec![(dn, "s3cret".to_string())]);

    let (auth_chan, broker_chan) = IpcChannel::pair().unwrap();
    let (auth_fd, broker_fd) = socketpair_for_fd_passing().unwrap();
    let _broker = TestBroker::start(
        broker_chan,
        broker_fd,
        BrokerBehavior::ConnectAndPass(server.addr),
    );

    let rt = runtime(
        &pki.ca_pem,
        "localhost",
        server.addr.port(),
        auth_fd.as_raw_fd(),
    );
    let outcome = brokered_bind(&auth_chan, &rt, "alice", "s3cret", |_| {});

    assert_eq!(outcome, LdapBindOutcome::Success);
}

#[test]
fn ldap_bind_wrong_password_returns_invalid_credentials() {
    let pki = generate_pki("localhost");
    let dn = DN_TEMPLATE.replace("{username}", "alice");
    let server = TestLdapServer::start(&pki, vec![(dn, "s3cret".to_string())]);

    let (auth_chan, broker_chan) = IpcChannel::pair().unwrap();
    let (auth_fd, broker_fd) = socketpair_for_fd_passing().unwrap();
    let _broker = TestBroker::start(
        broker_chan,
        broker_fd,
        BrokerBehavior::ConnectAndPass(server.addr),
    );

    let rt = runtime(
        &pki.ca_pem,
        "localhost",
        server.addr.port(),
        auth_fd.as_raw_fd(),
    );
    let outcome = brokered_bind(&auth_chan, &rt, "alice", "wrong-password", |_| {});

    assert_eq!(outcome, LdapBindOutcome::InvalidCredentials);
}

#[test]
fn ldap_bind_unknown_user_returns_invalid_credentials() {
    let pki = generate_pki("localhost");
    let dn = DN_TEMPLATE.replace("{username}", "alice");
    let server = TestLdapServer::start(&pki, vec![(dn, "s3cret".to_string())]);

    let (auth_chan, broker_chan) = IpcChannel::pair().unwrap();
    let (auth_fd, broker_fd) = socketpair_for_fd_passing().unwrap();
    let _broker = TestBroker::start(
        broker_chan,
        broker_fd,
        BrokerBehavior::ConnectAndPass(server.addr),
    );

    let rt = runtime(
        &pki.ca_pem,
        "localhost",
        server.addr.port(),
        auth_fd.as_raw_fd(),
    );
    let outcome = brokered_bind(&auth_chan, &rt, "mallory", "whatever", |_| {});

    assert_eq!(outcome, LdapBindOutcome::InvalidCredentials);
}

#[test]
fn ldap_bind_directory_unreachable_returns_unreachable() {
    let pki = generate_pki("localhost");
    let (auth_chan, broker_chan) = IpcChannel::pair().unwrap();
    let (auth_fd, broker_fd) = socketpair_for_fd_passing().unwrap();
    // Broker tries to connect to a closed port -> connect() fails -> refusal.
    let _broker = TestBroker::start(
        broker_chan,
        broker_fd,
        BrokerBehavior::ConnectAndPass(closed_addr()),
    );

    let rt = runtime(&pki.ca_pem, "localhost", 636, auth_fd.as_raw_fd());
    let outcome = brokered_bind(&auth_chan, &rt, "alice", "s3cret", |_| {});

    assert_eq!(outcome, LdapBindOutcome::Unreachable);
}

#[test]
fn ldap_bind_supervisor_refusal_returns_unreachable() {
    let pki = generate_pki("localhost");
    let (auth_chan, broker_chan) = IpcChannel::pair().unwrap();
    let (auth_fd, broker_fd) = socketpair_for_fd_passing().unwrap();
    let _broker = TestBroker::start(broker_chan, broker_fd, BrokerBehavior::Refuse);

    let rt = runtime(&pki.ca_pem, "localhost", 636, auth_fd.as_raw_fd());
    let outcome = brokered_bind(&auth_chan, &rt, "alice", "s3cret", |_| {});

    assert_eq!(outcome, LdapBindOutcome::Unreachable);
}

#[test]
fn ldap_bind_untrusted_ca_returns_tls_error() {
    let pki = generate_pki("localhost");
    let dn = DN_TEMPLATE.replace("{username}", "alice");
    let server = TestLdapServer::start(&pki, vec![(dn, "s3cret".to_string())]);

    // Client trusts a DIFFERENT CA than the one that signed the server cert.
    let other = generate_pki("localhost");

    let (auth_chan, broker_chan) = IpcChannel::pair().unwrap();
    let (auth_fd, broker_fd) = socketpair_for_fd_passing().unwrap();
    let _broker = TestBroker::start(
        broker_chan,
        broker_fd,
        BrokerBehavior::ConnectAndPass(server.addr),
    );

    let rt = runtime(
        &other.ca_pem,
        "localhost",
        server.addr.port(),
        auth_fd.as_raw_fd(),
    );
    let outcome = brokered_bind(&auth_chan, &rt, "alice", "s3cret", |_| {});

    assert_eq!(outcome, LdapBindOutcome::TlsError);
}

#[test]
fn ldap_bind_hostname_mismatch_returns_tls_error() {
    let pki = generate_pki("localhost");
    let dn = DN_TEMPLATE.replace("{username}", "alice");
    let server = TestLdapServer::start(&pki, vec![(dn, "s3cret".to_string())]);

    let (auth_chan, broker_chan) = IpcChannel::pair().unwrap();
    let (auth_fd, broker_fd) = socketpair_for_fd_passing().unwrap();
    let _broker = TestBroker::start(
        broker_chan,
        broker_fd,
        BrokerBehavior::ConnectAndPass(server.addr),
    );

    // SNI/verification name does not match the cert SAN (localhost).
    let rt = runtime(
        &pki.ca_pem,
        "directory.elsewhere.invalid",
        server.addr.port(),
        auth_fd.as_raw_fd(),
    );
    let outcome = brokered_bind(&auth_chan, &rt, "alice", "s3cret", |_| {});

    assert_eq!(outcome, LdapBindOutcome::TlsError);
}

#[test]
fn ldap_bind_missing_fd_does_not_block_and_fails_closed() {
    let pki = generate_pki("localhost");
    let dn = DN_TEMPLATE.replace("{username}", "alice");
    let server = TestLdapServer::start(&pki, vec![(dn, "s3cret".to_string())]);

    let (auth_chan, broker_chan) = IpcChannel::pair().unwrap();
    let (auth_fd, broker_fd) = socketpair_for_fd_passing().unwrap();
    // Broker answers success but never sends the FD: auth must give up quickly.
    let _broker = TestBroker::start(
        broker_chan,
        broker_fd,
        BrokerBehavior::SuccessWithoutFd(server.addr),
    );

    let rt = runtime(
        &pki.ca_pem,
        "localhost",
        server.addr.port(),
        auth_fd.as_raw_fd(),
    );
    let started = Instant::now();
    let outcome = brokered_bind(&auth_chan, &rt, "alice", "s3cret", |_| {});
    let elapsed = started.elapsed();

    assert_eq!(outcome, LdapBindOutcome::Unreachable);
    assert!(
        elapsed < Duration::from_secs(2),
        "recv_fd must be non-blocking; took {elapsed:?}"
    );
}

#[test]
fn bind_request_response_codec_round_trips_over_public_api() {
    let dn = "uid=bob,ou=people,dc=example,dc=com";
    let encoded = vauban_auth::ldap::encode_bind_request(7, dn, b"hunter2");
    let (message_id, parsed_dn, password) = parse_bind_request(&encoded).unwrap();
    assert_eq!(message_id, 7);
    assert_eq!(parsed_dn, dn);
    assert_eq!(password, b"hunter2");

    let response = encode_bind_response(message_id, LDAP_SUCCESS);
    assert_eq!(
        vauban_auth::ldap::parse_bind_response(&response).unwrap(),
        LDAP_SUCCESS
    );
}

#[test]
fn malformed_bind_request_fails_closed_without_panic() {
    for bad in [
        &b""[..],
        &b"\x30"[..],
        &b"\x30\x84\xff\xff\xff\xff"[..],
        &b"\x30\x05\x02\x01\x07\x60"[..],
    ] {
        assert!(parse_bind_request(bad).is_err());
    }
}
