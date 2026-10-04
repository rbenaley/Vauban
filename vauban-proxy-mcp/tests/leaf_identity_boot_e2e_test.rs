//! Boot of the real `vauban-proxy-mcp` binary under a fake supervisor.
//!
//! The leaf must hold its tunnel identity before it enters the sandbox
//! and before its control loop runs. The pre-sandbox wait answers a Ping
//! with all-zero stats; the main control loop counts every Ping it
//! answers (`requests_processed >= 1`). That difference tells the two
//! loops apart from outside the process.
//!
//! Known limit: on macOS the sandbox is a no-op, so this suite proves the
//! ordering, not that Capsicum lets the installed identity through. Real
//! Capsicum is exercised only by step C.3 of
//! `docs/runbooks/mcp_hop2_relay_smoke_test.md` on FreeBSD staging.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use shared::ipc::{IpcChannel, IpcError, clear_cloexec, socketpair_for_fd_passing};
use shared::messages::{ControlMessage, Message, SensitiveString, ServiceStats};
use shared::session_token::TokenKey;

const BOOT: Duration = Duration::from_secs(20);

struct LeafHarness {
    child: Child,
    sup: IpcChannel,
    data: IpcChannel,
    _access: IpcChannel,
    _fd_socket: OwnedFd,
    dir: tempfile::TempDir,
}

impl LeafHarness {
    fn spawn() -> Self {
        let (sup, sup_leaf) = IpcChannel::pair().unwrap();
        let (data, data_leaf) = IpcChannel::pair().unwrap();
        let (access, access_leaf) = IpcChannel::pair().unwrap();
        let (fd_socket, fd_socket_leaf) = socketpair_for_fd_passing().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let recordings = dir.path().join("recordings");
        std::fs::create_dir_all(&recordings).unwrap();
        let log = File::create(dir.path().join("leaf.log")).unwrap();

        let inherited: Vec<RawFd> = vec![
            sup_leaf.read_fd(),
            sup_leaf.write_fd(),
            data_leaf.read_fd(),
            data_leaf.write_fd(),
            access_leaf.read_fd(),
            access_leaf.write_fd(),
            fd_socket_leaf.as_raw_fd(),
        ];
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_vauban-proxy-mcp"));
        cmd.env_clear()
            .env("NO_COLOR", "1")
            .env("VAUBAN_IPC_READ", sup_leaf.read_fd().to_string())
            .env("VAUBAN_IPC_WRITE", sup_leaf.write_fd().to_string())
            .env("VAUBAN_WEB_DATA_IPC_READ", data_leaf.read_fd().to_string())
            .env(
                "VAUBAN_WEB_DATA_IPC_WRITE",
                data_leaf.write_fd().to_string(),
            )
            .env("VAUBAN_ACCESS_IPC_READ", access_leaf.read_fd().to_string())
            .env(
                "VAUBAN_ACCESS_IPC_WRITE",
                access_leaf.write_fd().to_string(),
            )
            .env(
                "VAUBAN_FD_PASSING_SOCKET",
                fd_socket_leaf.as_raw_fd().to_string(),
            )
            .env("VAUBAN_SESSION_TOKEN_KEY", TokenKey::generate().to_base64())
            .env("VAUBAN_RECORDING_STORAGE_PATH", &recordings)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log));
        // SAFETY: the closure only calls fcntl(2) on fds owned by this
        // process; it does not allocate on the success path.
        unsafe {
            cmd.pre_exec(move || {
                for &fd in &inherited {
                    clear_cloexec(fd)
                        .map_err(|_| std::io::Error::from(std::io::ErrorKind::Other))?;
                }
                Ok(())
            });
        }
        let child = cmd.spawn().unwrap();
        drop((sup_leaf, data_leaf, access_leaf, fd_socket_leaf));
        Self {
            child,
            sup,
            data,
            _access: access,
            _fd_socket: fd_socket,
            dir,
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.log_path()).unwrap_or_default()
    }

    fn log_path(&self) -> PathBuf {
        self.dir.path().join("leaf.log")
    }

    fn ping(&self, seq: u64) {
        self.sup
            .send(&Message::Control(ControlMessage::Ping { seq }))
            .unwrap();
    }

    fn provision(&self, cert_der: Vec<u8>, key_pem: String) {
        self.sup
            .send(&Message::McpTunnelIdentityProvision {
                cert_der,
                key_pem: SensitiveString::new(key_pem),
            })
            .unwrap();
    }

    /// Next Pong for `seq`; other supervisor traffic is skipped.
    fn pong(&mut self, seq: u64, wait: Duration) -> Option<ServiceStats> {
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            match self.sup.try_recv() {
                Ok(Message::Control(ControlMessage::Pong { seq: s, stats })) if s == seq => {
                    return Some(stats);
                }
                Ok(_) => {}
                Err(IpcError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if self.child.try_wait().ok().flatten().is_some() {
                        return None;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return None,
            }
        }
        None
    }

    fn tunnel_close(&self, tunnel_id: u64, wait: Duration) -> Option<String> {
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            match self.data.try_recv() {
                Ok(Message::McpTunnelClose {
                    tunnel_id: t,
                    reason,
                }) if t == tunnel_id => {
                    return Some(reason);
                }
                Ok(_) => {}
                Err(IpcError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return None,
            }
        }
        None
    }

    fn wait_exit(&mut self, wait: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().unwrap() {
                return Some(status);
            }
            thread::sleep(Duration::from_millis(20));
        }
        None
    }
}

impl Drop for LeafHarness {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn identity(matching: bool) -> (Vec<u8>, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["vauban-proxy-mcp.internal".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let pem = if matching {
        key.serialize_pem()
    } else {
        rcgen::KeyPair::generate().unwrap().serialize_pem()
    };
    (cert.der().to_vec(), pem)
}

/// Full happy boot: wait loop, identity, main loop, a tunnel that reaches
/// the TLS stage, then a clean shutdown.
fn boot_and_serve(leaf: &mut LeafHarness) {
    leaf.ping(1);
    let early = leaf
        .pong(1, BOOT)
        .unwrap_or_else(|| panic!("no pre-identity Pong\n{}", leaf.log()));
    assert_eq!(early.requests_processed, 0, "answered by the wait loop");

    let (cert, key) = identity(true);
    leaf.provision(cert, key);
    leaf.ping(2);
    let main_loop = leaf
        .pong(2, BOOT)
        .unwrap_or_else(|| panic!("no main-loop Pong\n{}", leaf.log()));
    assert!(
        main_loop.requests_processed >= 1,
        "Ping 2 must reach the main control loop: {main_loop:?}"
    );

    leaf.data
        .send(&Message::McpTunnelOpen {
            tunnel_id: 41,
            client_ip: "203.0.113.9".into(),
        })
        .unwrap();
    leaf.data
        .send(&Message::McpTunnelData {
            tunnel_id: 41,
            data: b"this is not a TLS ClientHello\r\n\r\n".to_vec(),
        })
        .unwrap();
    let reason = leaf
        .tunnel_close(41, BOOT)
        .unwrap_or_else(|| panic!("tunnel 41 never closed\n{}", leaf.log()));
    assert_ne!(
        reason, "no_identity",
        "identity must be live before serving"
    );
    assert!(!reason.starts_with("max_tunnels"), "{reason}");

    let log = leaf.log();
    let installed = log
        .find("MCP tunnel identity installed before the sandbox")
        .unwrap_or_else(|| panic!("missing install line\n{log}"));
    let ready = log
        .find("MCP gateway ready")
        .unwrap_or_else(|| panic!("missing ready line\n{log}"));
    assert!(
        installed < ready,
        "identity must land before the gateway is ready\n{log}"
    );

    leaf.sup
        .send(&Message::Control(ControlMessage::Shutdown))
        .unwrap();
    let status = leaf
        .wait_exit(BOOT)
        .unwrap_or_else(|| panic!("leaf did not exit on Shutdown\n{}", leaf.log()));
    assert!(status.success(), "{status:?}\n{}", leaf.log());
}

#[test]
fn e2e_identity_lands_before_the_first_main_loop_pong() {
    let mut leaf = LeafHarness::spawn();
    boot_and_serve(&mut leaf);
}

#[test]
fn attack_forged_identity_is_refused_before_serving() {
    let mut leaf = LeafHarness::spawn();
    let (cert, wrong_key) = identity(false);
    leaf.provision(cert, wrong_key);
    leaf.ping(9);
    let status = leaf
        .wait_exit(BOOT)
        .unwrap_or_else(|| panic!("forged identity must stop the leaf\n{}", leaf.log()));
    assert!(!status.success(), "{status:?}");
    if let Some(stats) = leaf.pong(9, Duration::from_millis(200)) {
        assert_eq!(stats.requests_processed, 0, "the main loop must never run");
    }
    let log = leaf.log();
    assert!(
        log.contains("MCP tunnel identity required before the sandbox"),
        "{log}"
    );
    assert!(
        !log.contains("MCP tunnel identity installed before the sandbox"),
        "{log}"
    );
    assert!(!log.contains("MCP gateway ready"), "{log}");
}

#[test]
fn missing_identity_never_reaches_the_main_loop() {
    let mut leaf = LeafHarness::spawn();
    for seq in 1..=3 {
        leaf.ping(seq);
        let stats = leaf
            .pong(seq, BOOT)
            .unwrap_or_else(|| panic!("no Pong {seq}\n{}", leaf.log()));
        assert_eq!(stats.requests_processed, 0, "still in the wait loop");
    }
    assert!(!leaf.log().contains("MCP gateway ready"));
}

#[test]
fn battle_four_leaves_boot_in_parallel() {
    let barrier = Arc::new(Barrier::new(4));
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let mut leaf = LeafHarness::spawn();
                barrier.wait();
                boot_and_serve(&mut leaf);
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
}
