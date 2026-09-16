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
    assert!(
        main.contains("spawn_reopen_on_hangup"),
        "main must spawn SIGHUP access-log reopen for newsyslog"
    );
    assert!(
        src.contains("fn reopen"),
        "AccessLog must implement reopen()"
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
    assert!(
        src.contains("error.into_response(cx)")
            || src.contains("Err(error) => error.into_response"),
        "security layer must convert handler Err(redirect/…) before applying headers"
    );
    assert!(
        !src.contains("next.run(cx, body).await?"),
        "security layer must not ?-propagate next.run Err (skips headers on redirects)"
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

    assert!(
        app.contains("TrailingSlash::Strict"),
        "0.8.1 must opt out of Redirect so POST slash is not 308-resubmitted"
    );
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

#[test]
fn inv_bootstrap_domains_not_gated_on_acme_enabled() {
    let config = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/config.rs"));
    let start = config
        .find("pub fn bootstrap_domains")
        .expect("bootstrap_domains");
    // Only the impl body — tests below set `acme.enabled` and must not false-positive.
    let after = &config[start..];
    let open = after.find('{').expect("bootstrap_domains opening brace");
    let mut depth = 0usize;
    let mut end = open;
    for (i, c) in after[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = open + i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    let body = &after[..end];
    assert!(
        body.contains("!acme.domains.is_empty()"),
        "bootstrap must use non-empty acme.domains"
    );
    assert!(
        !body.contains("acme.enabled") && !body.contains(".enabled"),
        "bootstrap_domains must not require acme.enabled"
    );
    assert!(
        body.contains("public_origins") || body.contains("host_from_https_origin"),
        "bootstrap must fall back to public_origins hosts"
    );
    let vcp_conf = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/config/vcp.conf"));
    assert!(
        vcp_conf.contains("domains = [\"access.vauban.sh\"]"),
        "packaged ACME domains must list the portal FQDN for bootstrap SANs"
    );
}
