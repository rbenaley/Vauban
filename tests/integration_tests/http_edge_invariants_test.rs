//! Source-shape invariants for HTTPS access log + security headers.

use std::process::Command;

#[test]
fn inv_check_http_edge_script() {
    let output = Command::new("bash")
        .arg("scripts/check_http_edge.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_http_edge.sh");
    assert!(
        output.status.success(),
        "scripts/check_http_edge.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_access_log_wired_in_serve() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/tls/serve.rs"));
    assert!(
        src.contains("AccessLogService::new"),
        "HTTPS accept loop must wrap RouterService with AccessLogService"
    );
    assert!(
        src.contains("access_log.clone()"),
        "serve_https must pass the shared AccessLog into each connection"
    );
}

#[test]
fn inv_access_log_writes_to_configured_file() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tls/access_log.rs"
    ));
    assert!(src.contains("OpenOptions::new"));
    assert!(src.contains(".append(true)"));
    assert!(src.contains("write_line"));
    assert!(
        src.contains("info!(access_log"),
        "AccessLog::open must announce the path under vcp::tls::access_log"
    );
    assert!(
        !src.contains("info!(\"{line}\")") && !src.contains("info!({line})"),
        "request CLF lines must go to the file via write_line, not tracing"
    );
    assert!(src.contains("access_log.write_line(&line)"));

    let main = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
    assert!(
        main.contains("AccessLog::open"),
        "main must open server.access_log_path"
    );

    let prod = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/config/vcp.conf"));
    assert!(prod.contains("access_log_path = \"/var/log/vcp-access.log\""));

    let dev = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/config/development.toml"
    ));
    assert!(dev.contains("access_log_path = \"logs/vcp-access.log\""));
}

#[test]
fn inv_security_headers_layer_pins() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app.rs"));
    assert!(src.contains("no-store"));
    assert!(src.contains("nosniff"));
    assert!(src.contains("frame-ancestors 'none'"));
    assert!(src.contains("geolocation=(), camera=(), microphone=()"));
    assert!(
        src.contains("contains_key(header::CACHE_CONTROL)"),
        "must not clobber Topcoat asset Cache-Control"
    );
}

#[test]
fn inv_trailing_slash_canonical_redirect_permanent() {
    let app = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app.rs"));
    assert!(app.contains("redirect_permanent"));
    assert!(app.contains("trailing_slash_redirect_location"));
    assert!(app.contains("should_redirect_trailing_slash"));
    assert!(
        !app.contains("MOVED_PERMANENTLY") && !app.contains("moved_permanently"),
        "use idiomatic redirect_permanent (308), not hand-rolled 301"
    );

    let helpers = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/http_canonical.rs"
    ));
    assert!(helpers.contains("pub fn trailing_slash_redirect_location"));
    assert!(helpers.contains("pub fn should_redirect_trailing_slash"));
    assert!(
        helpers.contains("Method::GET") && helpers.contains("Method::HEAD"),
        "permanent redirect only for safe methods"
    );

    let lib = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
    assert!(lib.contains("pub mod http_canonical"));
}

#[test]
fn inv_clf_format_contract() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tls/access_log.rs"
    ));
    assert!(
        src.contains(r#"{host} - - [{when}] \"{request_line}\" {status} {bytes}"#),
        "CLF template must stay Apache Common Log Format"
    );
}

#[test]
fn inv_handshake_coalescer_pins() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/tls/serve.rs"));
    assert!(
        src.contains("note_handshake_failure("),
        "accept Err path must call note_handshake_failure"
    );
    assert!(
        src.contains("flush_handshake_failures()"),
        "shutdown must flush pending handshake failures"
    );
    assert!(src.contains("HANDSHAKE_LOG_IDLE"));
    assert!(src.contains("TLS handshake failed error="));
    assert!(src.contains("count={count}"));
    assert!(
        src.contains("trace!"),
        "coalesced handshake failures must stay at trace"
    );
    assert!(
        !src.contains("debug!(\"TLS handshake failed"),
        "handshake failures must not log at debug"
    );
    assert!(src.contains("struct HandshakeFailureLog"));
}
