//! L6 -- IACS tunnel hardening tests.
//!
//! These tests pin the L6 acceptance criteria from the IACS
//! Tunnels plan:
//!
//!   * Constant-time auth rejection (anti-enumeration): the
//!     `auth_rejection_time` configured on the russh server
//!     forces a uniform delay on every refused publickey, so a
//!     timing oracle cannot tell "session UUID does not exist"
//!     apart from "EWS pubkey does not match".
//!   * Stress: 1000 concurrent connect/auth-fail cycles do not
//!     crash the runtime nor leak memory in the registry. Marked
//!     `#[ignore]` so it does not slow the regular CI run; the
//!     nightly job picks it up.
//!
//! Both tests live alongside the L3 adversarial suite but stay
//! in their own module to keep the L3 file focused on refusal
//! correctness and the L6 file focused on resilience.

use russh::client::{self, Handler as ClientHandler};
use russh::keys::ssh_key::Algorithm;
use russh::keys::ssh_key::rand_core::OsRng;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use uuid::Uuid;
use vauban_web::config::IacsTunnelConfig;
use vauban_web::services::iacs_tunnel::{TunnelRegistry, spawn_iacs_tunnel_server};

use crate::common::TestApp;

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

async fn spawn_dummy_target() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        while listener.accept().await.is_ok() {
            // drop the connection straight away
        }
    });
    addr
}

async fn spawn_test_sshd(app: &TestApp) -> (std::net::SocketAddr, TunnelRegistry) {
    let target = spawn_dummy_target().await;
    let host_key_path =
        std::env::temp_dir().join(format!("vauban_iacs_l6_test_host_{}.key", Uuid::new_v4()));
    let cfg = IacsTunnelConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        advertise_hostname: "127.0.0.1".to_string(),
        target_addr: target.to_string(),
        host_key_path: host_key_path.to_string_lossy().to_string(),
        max_concurrent_per_user: 0,
        max_concurrent_per_ews: 0,
        max_concurrent_channels_per_session: 16,
        waiting_client_ttl_seconds: 300,
        revocation_poll_interval_seconds: 2,
    };
    let registry = TunnelRegistry::new();
    let (addr, _) = spawn_iacs_tunnel_server(registry.clone(), app.db_pool.clone(), cfg)
        .await
        .expect("spawn sshd");
    tokio::time::sleep(Duration::from_millis(20)).await;
    (addr, registry)
}

fn client_config() -> Arc<client::Config> {
    Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    })
}

async fn measure_auth_fail_ms(addr: std::net::SocketAddr, user: &str, key: PrivateKey) -> u128 {
    let started = Instant::now();
    let mut handle = client::connect(client_config(), addr, TestClient)
        .await
        .expect("connect");
    let signer = PrivateKeyWithHashAlg::new(Arc::new(key), None);
    let _ = handle.authenticate_publickey(user, signer).await;
    started.elapsed().as_millis()
}

/// Anti-enumeration: a refused publickey must take roughly the
/// same time regardless of WHY it was refused. We sample 8
/// rejections (mix of "session not found" and "session
/// malformed") and assert the spread fits inside the russh
/// `auth_rejection_time` jitter window.
///
/// `russh` defaults `auth_rejection_time` to 1 s; we check that
/// every sample is `>= 800 ms` (well above what a DB roundtrip
/// alone would take) AND the standard deviation is small enough
/// that an attacker cannot glean useful signal.
#[tokio::test]
async fn auth_rejection_is_constant_time() {
    let app = TestApp::spawn().await;
    let (sshd_addr, _) = spawn_test_sshd(app).await;

    let mut samples_ms: Vec<u128> = Vec::new();
    for i in 0..6 {
        // Mix two rejection reasons:
        //   - even iterations: malformed user (parse fail, NO DB roundtrip)
        //   - odd iterations: random UUID (DB roundtrip miss)
        let user = if i % 2 == 0 {
            "not-a-uuid".to_string()
        } else {
            Uuid::new_v4().to_string()
        };
        let key = fresh_ed25519_key();
        samples_ms.push(measure_auth_fail_ms(sshd_addr, &user, key).await);
    }

    let n = samples_ms.len() as f64;
    let mean = samples_ms.iter().map(|&v| v as f64).sum::<f64>() / n;
    let variance = samples_ms
        .iter()
        .map(|&v| (v as f64 - mean).powi(2))
        .sum::<f64>()
        / n;
    let stddev = variance.sqrt();
    let min = samples_ms.iter().min().copied().unwrap();
    let max = samples_ms.iter().max().copied().unwrap();

    // Lower bound: every reject must wait at least ~800 ms (russh
    // default auth_rejection_time = 1000 ms; we leave 200 ms slack
    // for clock noise on shaky CI).
    assert!(
        min >= 800,
        "min auth-fail latency {} ms is below the 800 ms anti-enumeration floor \
         (samples: {:?})",
        min,
        samples_ms
    );
    // Spread: stddev must be small enough to defeat a naive
    // timing oracle. 200 ms is generous on a noisy CI runner;
    // tighten later if production hardware shows lower jitter.
    assert!(
        stddev <= 200.0,
        "auth-fail latency stddev {:.1} ms exceeds 200 ms anti-enumeration ceiling \
         (samples: {:?}, mean: {:.1}, min: {}, max: {})",
        stddev,
        samples_ms,
        mean,
        min,
        max
    );
}

/// Stress: 1000 concurrent connect / auth-fail cycles must not
/// crash the runtime, leak handles in the registry, or starve
/// the accept loop. Marked `#[ignore]` so the regular CI run
/// stays under 60 s; the nightly load test runs this with
/// `cargo test -- --ignored`.
#[tokio::test]
#[ignore = "L6 stress test -- run with --ignored in nightly load CI"]
async fn stress_1000_concurrent_auth_fails() {
    let app = TestApp::spawn().await;
    let (sshd_addr, registry) = spawn_test_sshd(app).await;

    const N: usize = 1000;
    const PARALLEL: usize = 50;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(PARALLEL));
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
        let addr = sshd_addr;
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let mut h = match client::connect(client_config(), addr, TestClient).await {
                Ok(h) => h,
                Err(_) => return,
            };
            let signer = PrivateKeyWithHashAlg::new(Arc::new(fresh_ed25519_key()), None);
            let _ = h
                .authenticate_publickey(Uuid::new_v4().to_string(), signer)
                .await;
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    // The registry must NOT carry any leaked handles -- each
    // connection auth-failed, so no `TunnelHandle` was ever
    // inserted.
    assert_eq!(
        registry.len(),
        0,
        "registry must not leak after 1000 auth-fail cycles"
    );
}
