//! Lot 5/6 -- per-asset target pin tests for `vauban-web`.
//!
//! These tests grep the production source (`vauban-web/src/`) for
//! the EXACT call-graph contracts the IACS handler must follow.
//! They are the cheap sentinel that catches a refactor silently
//! reintroducing a process-wide loopback target or skipping the
//! out-of-process proxy-iacs path.
//!
//! Runtime semantics are pinned by the existing DB-backed integration
//! tests (`iacs_revocation_watchdog_test.rs`,
//! `vauban-proxy-iacs/tests/iacs_server_handshake_test.rs`); this
//! file is the structural lockstep companion.

use std::path::Path;

const SRC_ROOT: &str = "src";

fn read_src(rel: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(SRC_ROOT)
        .join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {}", p.display(), e))
}

#[test]
fn iacs_handler_persists_per_asset_target_addr() {
    let src = read_src("handlers/web/iacs_tunnel.rs");
    assert!(
        src.contains("Some(format!(\"{}:{}\", asset.hostname, asset.port))"),
        "Lot 3 contract: NewProxySession.tunnel_target_addr MUST be \
         derived from asset.hostname:asset.port (the per-asset \
         resolution). Reverting to a config-wide constant would \
         silently disable per-asset targeting."
    );
    assert!(
        !src.contains("config.industrial.iacs_tunnel.target_addr.clone()"),
        "Lot 5 cleanup: the legacy process-wide \
         `config.industrial.iacs_tunnel.target_addr` MUST NOT be \
         used as the persisted tunnel target. The per-asset \
         (asset.hostname, asset.port) is the single source of truth."
    );
}

#[test]
fn iacs_handler_mints_session_token_with_per_asset_binding() {
    let src = read_src("handlers/web/iacs_tunnel.rs");
    assert!(
        src.contains("host: asset.hostname.clone()"),
        "SessionTokenParams MUST bind the per-asset hostname so a \
         token minted for asset A cannot be replayed against asset \
         B (verified at the supervisor by `verify_supervisor` against \
         the TcpConnectRequest target_host)."
    );
    assert!(
        src.contains("port: asset.port as u16"),
        "SessionTokenParams MUST bind the per-asset port for the \
         same reason (cross-asset port swap rejected)."
    );
    assert!(
        src.contains("target_service: shared::messages::Service::ProxyIacs"),
        "SessionTokenParams MUST tag target_service = ProxyIacs so a \
         token minted for the IACS tunnel surface cannot be replayed \
         on the SSH or RDP proxy."
    );
    assert!(
        src.contains("shared::access_guard::PROTOCOL_IACS_TUNNEL"),
        "SessionTokenParams MUST bind the IACS tunnel protocol; the \
         proxy-iacs `verify_proxy` re-checks this exact label. The \
         transport-meta is bridged to applicative `iacs_*` protocols \
         in `vauban-access::handlers::protocol_match_filter` -- a \
         regression that switches to `asset.asset_type.as_str()` here \
         would trade the symmetric crypto binding for an asymmetric \
         one and break `verify_proxy`."
    );
}

/// Bridging-seam pin: the production fix for "IACS access denied
/// despite an explicit access rule" lives in `vauban-access` (the
/// `protocol_match_filter` helper that expands `iacs_tunnel` to the
/// applicative IACS set when filtering `access_rules.allowed_protocols`).
/// This pin protects the seam from a regression on the consumer side
/// (this handler) re-introducing the wrong proto string by accident.
#[test]
fn iacs_handler_does_not_smuggle_an_applicative_protocol_into_session_token() {
    let src = read_src("handlers/web/iacs_tunnel.rs");
    // The handler must NOT mint a SessionToken with an applicative
    // protocol in its protocol field (which would compile-pass but
    // collapse the meta-protocol bridging contract).
    for forbidden in [
        "protocol: \"iacs_modbus\"",
        "protocol: \"iacs_opcua\"",
        "protocol: \"iacs_profinet\"",
        "protocol: \"iacs_iec104\"",
        "protocol: \"iacs_tcp\"",
        "protocol: asset.asset_type.as_str()",
        "protocol: asset_type.as_str()",
    ] {
        assert!(
            !src.contains(forbidden),
            "iacs_tunnel handler MUST mint SessionToken.protocol = \
             PROTOCOL_IACS_TUNNEL (the transport-meta), NOT an \
             applicative protocol. The bridging from transport-meta \
             to applicative happens server-side in \
             vauban-access::protocol_match_filter. Found forbidden \
             literal: {forbidden}"
        );
    }
}

#[test]
fn iacs_handler_routes_through_proxy_iacs_ipc() {
    let src = read_src("handlers/web/iacs_tunnel.rs");
    assert!(
        src.contains("IacsTunnelOpenRequest"),
        "Lot 3: the handler MUST send an IacsTunnelOpenRequest IPC \
         message instead of calling an in-process registry directly."
    );
    assert!(
        src.contains("proxy_iacs_client.open_tunnel(open_req)"),
        "Lot 3: the handler MUST go through the IPC client. \
         A direct in-process register would bypass Capsicum, the \
         supervisor SCM_RIGHTS broker, and the per-asset target \
         contract."
    );
    assert!(
        src.contains("asset_host: asset.hostname.clone()"),
        "IacsTunnelOpenRequest MUST forward the per-asset hostname \
         so proxy-iacs pins it on the per-session pending entry."
    );
    assert!(
        src.contains("asset_port: asset.port as u16"),
        "IacsTunnelOpenRequest MUST forward the per-asset port."
    );
}

#[test]
fn iacs_handler_rolls_back_on_proxy_iacs_failure() {
    let src = read_src("handlers/web/iacs_tunnel.rs");
    // Two failure paths: token mint fail, and proxy-iacs refused.
    // Both must roll back the proxy_session row to avoid orphan
    // `waiting_client` entries that the watchdog would later expire
    // anyway, but it's cleaner to fail fast here.
    // Lot A fail-closed: mint failure, proxy refusal, IPC failure, and
    // missing proxy client all DELETE the waiting_client row. Match on
    // the delete call site (formatting-independent).
    let rollback_count = src.matches("diesel::delete(").count();
    assert!(
        rollback_count >= 2,
        "the IACS handler must roll back the proxy_session row on \
         BOTH session-token mint failure AND proxy-iacs open \
         refusal. Found {} diesel::delete( site(s).",
        rollback_count
    );
}

#[test]
fn iacs_tunnel_config_has_no_target_addr_field() {
    let src = read_src("config.rs");
    // Narrow to the IacsTunnelConfig struct body.
    let start = src
        .find("pub struct IacsTunnelConfig")
        .expect("IacsTunnelConfig must exist");
    let body = &src[start..];
    let end = body
        .find("impl IacsTunnelConfig")
        .expect("IacsTunnelConfig impl must follow the struct");
    let struct_body = &body[..end];
    assert!(
        !struct_body.contains("target_addr"),
        "Lot A: IacsTunnelConfig MUST NOT carry a process-wide \
         `target_addr` (per-asset targets live on proxy_sessions)"
    );
}

#[test]
fn vauban_web_cargo_toml_has_no_russh() {
    let cargo = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("read Cargo.toml");
    assert!(
        !cargo.lines().any(|l| l.trim_start().starts_with("russh")),
        "Lot A: vauban-web/Cargo.toml MUST NOT depend on russh \
         (sshd lives in vauban-proxy-iacs)"
    );
}

#[test]
fn in_process_iacs_sshd_module_is_absent() {
    let server_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(SRC_ROOT)
        .join("services/iacs_tunnel/server.rs");
    assert!(
        !server_path.exists(),
        "Lot A: vauban-web MUST NOT ship an in-process IACS sshd \
         (`services/iacs_tunnel/server.rs` must be deleted; sshd \
         lives exclusively in vauban-proxy-iacs)"
    );
    let mod_src = read_src("services/iacs_tunnel/mod.rs");
    assert!(
        !mod_src.contains("mod server") && !mod_src.contains("pub mod server"),
        "Lot A: iacs_tunnel/mod.rs MUST NOT declare `mod server`"
    );
    assert!(
        !mod_src.contains("mod relay")
            && !mod_src.contains("mod auth")
            && !mod_src.contains("mod registry"),
        "Lot A: iacs_tunnel/mod.rs MUST NOT re-export server/relay/auth/registry"
    );
    let main_src = read_src("main.rs");
    assert!(
        !main_src.contains("spawn_iacs_tunnel_server"),
        "Lot A: main.rs MUST NOT spawn an in-process IACS sshd"
    );
}

#[test]
fn watchdog_uses_proxy_iacs_aware_spawn() {
    let src = read_src("main.rs");
    assert!(
        src.contains("spawn_watchdog_with_proxy_iacs"),
        "Lot 5: the revocation watchdog MUST be spawned via \
         `spawn_watchdog_with_proxy_iacs` so revoke decisions are \
         dispatched as IPC `IacsTunnelTerminate` messages to the \
         out-of-process proxy. The legacy in-process registry path \
         is no longer authoritative."
    );
}

#[test]
fn watchdog_dispatches_terminate_via_ipc_when_client_present() {
    let src = read_src("services/iacs_tunnel/revocation.rs");
    assert!(
        src.contains("IacsTunnelTerminate"),
        "Lot 5: the watchdog MUST emit `IacsTunnelTerminate` IPC \
         messages when a `ProxyIacsClient` is wired. Without it, \
         a tunnel running in proxy-iacs would never be killed."
    );
    assert!(
        src.contains("spawn_watchdog_with_proxy_iacs"),
        "Lot 5: revocation.rs MUST expose \
         `spawn_watchdog_with_proxy_iacs(... Option<Arc<ProxyIacsClient>>)`"
    );
}

#[test]
fn proxy_iacs_client_broadcasts_real_time_status_updates() {
    let src = read_src("ipc/proxy_iacs.rs");
    assert!(
        src.contains("process_incoming_with_broadcast"),
        "Lot 5: the IPC client MUST expose a \
         `process_incoming_with_broadcast` task so the supervisor \
         dashboard receives `IacsTunnelStatusUpdate` and \
         `IacsTunnelClosed` events in real time."
    );
    assert!(
        src.contains("IacsTunnelStatusUpdate") && src.contains("IacsTunnelClosed"),
        "Lot 5: the broadcast pump MUST forward both \
         `IacsTunnelStatusUpdate` and `IacsTunnelClosed` to the \
         WebSocket layer."
    );
}

#[test]
fn no_legacy_127_0_0_1_4321_literal_in_client_source() {
    // We don't hardcode the legacy MVP loopback target string in
    // the IPC client. We construct it at test time so this very
    // file does not match its own grep (the test would otherwise
    // be self-falsifying).
    let needle = format!("{}.{}.{}.{}:{}", 127, 0, 0, 1, 4321);
    let src = read_src("ipc/proxy_iacs.rs");
    assert!(
        !src.contains(&needle),
        "ipc/proxy_iacs.rs must not embed the legacy loopback IACS \
         target literal -- per-asset target resolution is the only \
         path."
    );
}

#[test]
fn access_check_by_uuid_binds_iacs_tunnel_to_asset_type() {
    let access_handlers = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../vauban-access/src/handlers.rs"),
    )
    .unwrap_or_else(|e| panic!("read vauban-access handlers: {e}"));
    assert!(
        access_handlers.contains("iacs_tunnel_rule_includes_asset_type"),
        "handle_check_access_by_uuid MUST call iacs_tunnel_rule_includes_asset_type \
         so a modbus-only rule cannot grant a profinet asset"
    );
    assert!(
        access_handlers.contains("IACS_APPLICATIVE_PROTOCOLS.contains"),
        "handle_check_access_by_uuid MUST reject iacs_tunnel on non-IACS assets"
    );
}
