//! E2E: security headers on `app::router` and HTTPS edge → Apache CLF file.
//!
//! Handshake coalescing uses the same `HandshakeFailureLog` production type
//! (capturing emit) so CI exercises the real coalescer without a TLS flood.

use std::time::{SystemTime, UNIX_EPOCH};

use topcoat::router::{Method, StatusCode};
use vcp::tls::{AccessLog, HandshakeFailureLog, build_server_config, serve_https};

use crate::common::{
    db_lock, get, install_crypto_once, post_form, request, status, test_config, test_router,
};

fn header<'a>(resp: &'a topcoat::router::response::Response, name: &str) -> Option<&'a str> {
    resp.headers().get(name).and_then(|v| v.to_str().ok())
}

#[tokio::test]
async fn e2e_login_page_sets_dynamic_security_headers() {
    let _guard = db_lock().lock().await;
    let router = test_router().await;
    let resp = get(&router, "/login", None).await;
    assert_eq!(status(&resp), StatusCode::OK);

    assert_eq!(header(&resp, "cache-control"), Some("no-store"));
    assert_eq!(header(&resp, "x-content-type-options"), Some("nosniff"));
    assert_eq!(
        header(&resp, "content-security-policy"),
        Some("frame-ancestors 'none'")
    );
    assert_eq!(
        header(&resp, "permissions-policy"),
        Some("geolocation=(), camera=(), microphone=()")
    );
}

#[tokio::test]
async fn e2e_root_redirect_also_sets_security_headers() {
    let _guard = db_lock().lock().await;
    let router = test_router().await;
    let resp = get(&router, "/", None).await;
    assert_eq!(
        status(&resp),
        StatusCode::TEMPORARY_REDIRECT,
        "GET / must redirect (307); got {}",
        status(&resp)
    );
    assert_eq!(header(&resp, "cache-control"), Some("no-store"));
    assert_eq!(header(&resp, "x-content-type-options"), Some("nosniff"));
    assert_eq!(
        header(&resp, "content-security-policy"),
        Some("frame-ancestors 'none'")
    );
}

#[tokio::test]
async fn e2e_trailing_slash_get_is_308_canonical() {
    let _guard = db_lock().lock().await;
    let router = test_router().await;

    let resp = get(&router, "/login/", None).await;
    assert_eq!(status(&resp), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(header(&resp, "location"), Some("/login"));
    assert_eq!(header(&resp, "cache-control"), Some("no-store"));
    assert_eq!(header(&resp, "x-content-type-options"), Some("nosniff"));

    let with_q = get(&router, "/login/?next=1", None).await;
    assert_eq!(status(&with_q), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(header(&with_q, "location"), Some("/login?next=1"));

    let multi = get(&router, "/login///", None).await;
    assert_eq!(status(&multi), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(header(&multi, "location"), Some("/login"));
}

#[tokio::test]
async fn e2e_trailing_slash_head_is_308() {
    let _guard = db_lock().lock().await;
    let router = test_router().await;
    let resp = request(&router, Method::HEAD, "/login/", None, None).await;
    assert_eq!(status(&resp), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(header(&resp, "location"), Some("/login"));
}

#[tokio::test]
async fn e2e_trailing_slash_post_is_not_308() {
    let _guard = db_lock().lock().await;
    let router = test_router().await;
    let resp = post_form(&router, "/login/", None, "email=x@example.com").await;
    assert_ne!(
        status(&resp),
        StatusCode::PERMANENT_REDIRECT,
        "POST must not receive trailing-slash redirect_permanent"
    );
}

#[tokio::test]
async fn e2e_serve_https_writes_clf_access_log() {
    let _guard = db_lock().lock().await;
    install_crypto_once();

    let cfg = test_config().await;
    let (tls_config, _) = build_server_config(&cfg).expect("tls config");
    let router = test_router().await;

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let log_path = std::env::temp_dir().join(format!("vcp-e2e-access-{nanos}.log"));
    let access_log = AccessLog::open(&log_path).expect("access log");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        serve_https(listener, tls_config, router, access_log, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });

    // Give the accept loop a moment to start.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("reqwest client");
    let url = format!("https://127.0.0.1:{}/login", addr.port());
    let resp = client.get(&url).send().await.expect("GET /login");
    assert_eq!(resp.status(), 200, "login over HTTPS");

    let _ = shutdown_tx.send(());
    server.await.expect("join").expect("serve_https");

    let body = std::fs::read_to_string(&log_path).expect("read clf");
    let _ = std::fs::remove_file(&log_path);
    assert!(
        body.contains("\"GET /login HTTP/"),
        "expected CLF GET /login, got:\n{body}"
    );
    assert!(
        body.contains(" 200 "),
        "expected status 200 in CLF:\n{body}"
    );
}

#[tokio::test]
async fn e2e_access_log_reopen_after_rotate_keeps_live_path() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let log_path = std::env::temp_dir().join(format!("vcp-e2e-reopen-{nanos}.log"));
    let rotated = log_path.with_extension("log.0");
    let access_log = AccessLog::open(&log_path).expect("open");
    access_log
        .write_line("127.0.0.1 - - [01/Jan/2026:00:00:00 +0000] \"GET /before HTTP/1.1\" 200 -");
    std::fs::rename(&log_path, &rotated).expect("rename");
    std::fs::File::create(&log_path).expect("create live");
    access_log.reopen().expect("reopen");
    access_log
        .write_line("127.0.0.1 - - [01/Jan/2026:00:00:01 +0000] \"GET /after HTTP/1.1\" 200 -");
    let live = std::fs::read_to_string(&log_path).expect("live");
    let old = std::fs::read_to_string(&rotated).expect("old");
    let _ = std::fs::remove_file(&log_path);
    let _ = std::fs::remove_file(&rotated);
    assert!(live.contains("/after"), "live={live}");
    assert!(old.contains("/before") && !old.contains("/after"));
}

#[tokio::test]
async fn e2e_handshake_coalescer_counts_identical_errors() {
    let (log, captured) = HandshakeFailureLog::capturing(std::time::Duration::from_secs(60));
    for _ in 0..7 {
        log.note("peer is incompatible: NoKxGroupsInCommon".to_owned());
    }
    log.note("Tls12NotOffered".to_owned());
    log.flush();
    let events = captured.lock().expect("capture").clone();
    assert_eq!(
        events,
        vec![
            ("peer is incompatible: NoKxGroupsInCommon".to_owned(), 7),
            ("Tls12NotOffered".to_owned(), 1),
        ]
    );
    let total: u32 = events.iter().map(|(_, c)| c).sum();
    assert_eq!(total, 8);
}
