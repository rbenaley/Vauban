//! Contention: parallel CLF formatting / file writes and parallel header reads.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use http::{Method, Version};
use tokio::sync::Barrier;
use topcoat::router::StatusCode;
use vcp::tls::{AccessLog, HandshakeFailureLog, format_common_log};

use crate::common::{db_lock, get, post_form, status, test_router};

#[test]
fn battle_parallel_clf_format() {
    let n = 16usize;
    let barrier = Arc::new(std::sync::Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 10_000 + i as u16);
            for j in 0..64 {
                let path = format!("/battle/{i}/{j}");
                let line = format_common_log(peer, &Method::GET, &path, Version::HTTP_11, 200, "-");
                assert!(line.contains(&path), "{line}");
                assert!(line.contains(" 200 -"), "{line}");
            }
        }));
    }
    for h in handles {
        h.join().expect("join");
    }
}

#[test]
fn battle_parallel_access_log_file_writes() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("vcp-access-log-battle-{nanos}.log"));
    let log = AccessLog::open(&path).expect("open");
    let n = 12usize;
    let barrier = Arc::new(std::sync::Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let log = log.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            for j in 0..32 {
                log.write_line(&format!(
                    "127.0.0.1 - - [01/Jan/2026:00:00:00 +0000] \"GET /b/{i}/{j} HTTP/1.1\" 200 -"
                ));
            }
        }));
    }
    for h in handles {
        h.join().expect("join");
    }
    let body = std::fs::read_to_string(&path).expect("read");
    let _ = std::fs::remove_file(&path);
    assert_eq!(body.lines().count(), n * 32);
}

#[test]
fn battle_parallel_handshake_coalescer() {
    let (log, captured) = HandshakeFailureLog::capturing(std::time::Duration::from_secs(60));
    let n = 16usize;
    let per_thread = 64u32;
    let barrier = Arc::new(std::sync::Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let log = log.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            for _ in 0..per_thread {
                log.note("NoKxGroupsInCommon".to_owned());
            }
        }));
    }
    for h in handles {
        h.join().expect("join");
    }
    log.flush();
    let events = captured.lock().expect("capture").clone();
    let total: u32 = events.iter().map(|(_, c)| *c).sum();
    assert_eq!(total, n as u32 * per_thread);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, "NoKxGroupsInCommon");
}

#[tokio::test]
async fn battle_parallel_security_header_reads() {
    let _guard = db_lock().lock().await;
    let router = Arc::new(test_router().await);
    let n = 12usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);

    for _ in 0..n {
        let router = router.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let resp = get(router.as_ref(), "/login", None).await;
            assert_eq!(status(&resp), StatusCode::OK);
            let cc = resp
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok());
            assert_eq!(cc, Some("no-store"));
            let nosniff = resp
                .headers()
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok());
            assert_eq!(nosniff, Some("nosniff"));
        }));
    }

    for h in handles {
        h.await.expect("join");
    }
}

#[tokio::test]
async fn battle_parallel_trailing_slash_308() {
    let _guard = db_lock().lock().await;
    let n = 12usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);

    for i in 0..n {
        let barrier = barrier.clone();
        let router = test_router().await;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let path = if i % 2 == 0 { "/login/" } else { "/login/?x=1" };
            let resp = get(&router, path, None).await;
            assert_eq!(status(&resp), StatusCode::PERMANENT_REDIRECT);
            let loc = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .expect("location");
            if i % 2 == 0 {
                assert_eq!(loc, "/login");
            } else {
                assert_eq!(loc, "/login?x=1");
            }
        }));
    }

    for h in handles {
        h.await.expect("join");
    }
}

#[tokio::test]
async fn battle_parallel_trailing_slash_post_is_not_308() {
    let _guard = db_lock().lock().await;
    let n = 12usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);

    for i in 0..n {
        let barrier = barrier.clone();
        let router = test_router().await;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let path = if i % 2 == 0 {
                "/login/"
            } else {
                "/_topcoat/runtime/shards/battle-slash/"
            };
            let resp = post_form(&router, path, None, "email=x@example.com").await;
            let code = status(&resp);
            assert_ne!(
                code,
                StatusCode::PERMANENT_REDIRECT,
                "{path} POST must not 308"
            );
            assert!(
                !code.is_server_error(),
                "{path} POST must not 5xx (missing runtime / twin), got {code}"
            );
        }));
    }

    for h in handles {
        h.await.expect("join");
    }
}
