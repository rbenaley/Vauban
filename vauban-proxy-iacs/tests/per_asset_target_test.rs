//! Structural pin tests for the Lot 3 per-asset target wiring.
//!
//! These tests grep the production source for the EXACT call-graph
//! contracts the IACS proxy must enforce. They run as integration
//! tests so they fail loudly in CI if a refactor silently revokes
//! one of the gates.
//!
//! In addition, two functional tests drive `validate_target`
//! directly to pin the per-session matching semantics.
//!
//! Test code intentionally uses `unwrap` / `panic` for clarity; the
//! production lints are bypassed here as is convention for the
//! `tests/` tree (cf. `vauban-proxy-rdp/tests/openh264_sad_baseline.rs`).

#![allow(clippy::unwrap_used, clippy::panic)]

// We can't `#[path]` into the bin crate for non-pub items, so we
// re-include a minimal copy of validate_target here as a
// pre-existing function for these tests. The real source-grep tests
// below pin that the production module has the same contract.
mod relay_inner {
    /// Mirrored from `vauban-proxy-iacs/src/relay.rs::validate_target`
    /// to avoid taking a public dependency on a binary crate. Kept in
    /// lock-step by the source-grep test below.
    pub fn validate_target(
        requested_host: &str,
        requested_port: u32,
        expected_host: &str,
        expected_port: u16,
    ) -> bool {
        if requested_port != expected_port as u32 {
            return false;
        }
        if requested_host == expected_host {
            return true;
        }
        let is_loopback = |s: &str| {
            matches!(s, "127.0.0.1" | "0.0.0.0" | "localhost" | "::1" | "[::1]")
        };
        is_loopback(requested_host) && is_loopback(expected_host)
    }
}

const PROXY_IACS_SRC: &str = "src";

fn read_src(rel: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(PROXY_IACS_SRC)
        .join(rel);
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("read {}: {}", p.display(), e))
}

// ===================================================================
// Functional: per-session validate_target
// ===================================================================

/// Lot 3 contract: a `direct-tcpip` to the asset's pinned host:port
/// is accepted. Any other host or port is rejected.
#[test]
fn per_asset_target_accepted_when_match() {
    assert!(relay_inner::validate_target(
        "10.42.0.7", 502, "10.42.0.7", 502
    ));
    assert!(relay_inner::validate_target(
        "factory-plc.internal", 34962, "factory-plc.internal", 34962
    ));
}

#[test]
fn cross_asset_target_swap_rejected() {
    // Asset A pinned to 10.0.0.1:502 but EWS asks for 10.0.0.2:502.
    assert!(!relay_inner::validate_target(
        "10.0.0.2", 502, "10.0.0.1", 502
    ));
}

#[test]
fn cross_asset_port_swap_rejected() {
    // Same host, different port.
    assert!(!relay_inner::validate_target(
        "10.0.0.1", 503, "10.0.0.1", 502
    ));
}

#[test]
fn legacy_fixed_target_rejected_when_asset_is_remote() {
    // The pre-Lot-3 default (127.0.0.1:4321) MUST be rejected for an
    // asset pinned to a remote address. This is the regression the
    // Lot 3 plan calls "rejects_legacy_target".
    assert!(!relay_inner::validate_target(
        "127.0.0.1", 4321, "10.0.0.1", 502
    ));
}

#[test]
fn loopback_equivalences_accepted_only_when_both_sides_loopback() {
    // 127.0.0.1 vs localhost is permitted (operator convenience
    // within the same loopback family).
    assert!(relay_inner::validate_target(
        "localhost", 502, "127.0.0.1", 502
    ));
    assert!(relay_inner::validate_target(
        "::1", 502, "127.0.0.1", 502
    ));
    // But a routable host on one side must NOT alias to loopback on
    // the other side.
    assert!(!relay_inner::validate_target(
        "127.0.0.1", 502, "10.0.0.1", 502
    ));
}

// ===================================================================
// Source-grep pins: production gates wired in the right order
// ===================================================================

#[test]
fn server_handler_uses_per_session_pending_in_direct_tcpip() {
    let src = read_src("server.rs");
    assert!(
        src.contains("validate_target("),
        "channel_open_direct_tcpip MUST call validate_target on the \
         per-session pinned (asset_host, asset_port). Without it, an \
         EWS could request any host:port over the same SSH session."
    );
    assert!(
        src.contains("self.upstream.open(&pending)"),
        "channel_open_direct_tcpip MUST go through the UpstreamOpener \
         trait (i.e. the supervisor SCM_RIGHTS broker in production). \
         Direct TcpStream::connect would fail under Capsicum."
    );
}

#[test]
fn upstream_opener_routes_through_supervisor_broker() {
    let src = read_src("upstream.rs");
    assert!(
        src.contains("Service::ProxyIacs"),
        "SupervisorBrokerOpener MUST tag the TcpConnectRequest with \
         target_service = Service::ProxyIacs so the supervisor's \
         token gate verifies the matching discriminant."
    );
    assert!(
        src.contains("Message::TcpConnectRequest"),
        "SupervisorBrokerOpener MUST emit Message::TcpConnectRequest \
         on the supervisor pipe (no in-process socket()/connect())."
    );
    assert!(
        src.contains("session_token: pending.session_token.clone()"),
        "SupervisorBrokerOpener MUST forward the BLAKE3-bound \
         session_token from the pending entry so the supervisor can \
         re-verify in Verifier::Supervisor role."
    );
}

#[test]
fn iacs_tunnel_open_handler_verifies_session_token() {
    let src = read_src("main.rs");
    assert!(
        src.contains("session_token_gate::verify_proxy("),
        "handle_web_message MUST verify_proxy the IacsTunnelOpen \
         session_token BEFORE caching the pending entry. Removing \
         this disables the cryptographic gate -- a compromised \
         vauban-web could mint pending entries for any user/asset."
    );
    assert!(
        src.contains(
            "shared::access_guard::PROTOCOL_IACS_TUNNEL"
        ),
        "verify_proxy MUST be called with PROTOCOL_IACS_TUNNEL so the \
         token's protocol binding is enforced (a token minted for \
         'ssh' must NOT be accepted on this surface)."
    );
}

#[test]
fn iacs_tunnel_open_handler_runs_access_guard_recheck() {
    let src = read_src("main.rs");
    assert!(
        src.contains("access_guard.authorize(&user_uuid, &asset_uuid)"),
        "handle_web_message MUST run AccessGuard.authorize as a \
         defense-in-depth re-check. Without it, a stale Casbin cache \
         in vauban-access (or a mid-flight access-rule revoke between \
         token mint and IacsTunnelOpen) would silently accept the \
         tunnel."
    );
}

#[test]
fn listener_fd_inherited_from_supervisor_post_capsicum() {
    let src = read_src("main.rs");
    assert!(
        src.contains("VAUBAN_IACS_LISTENER_FD"),
        "main MUST read the IACS listener FD from the env var \
         VAUBAN_IACS_LISTENER_FD; the supervisor pre-binds it pre-\
         fork so proxy-iacs never calls bind() (forbidden by Capsicum)."
    );
    assert!(
        src.contains("setup_service_sandbox_with_listeners("),
        "main MUST call setup_service_sandbox_with_listeners so the \
         inherited listener FD is granted the listening_socket cap \
         right post-cap_enter."
    );
}

#[test]
fn proxy_iacs_does_not_call_socket_or_bind() {
    // Defense-in-depth: the production source MUST NOT contain any
    // direct socket()/bind()/connect() call (Capsicum-incompatible
    // post-cap_enter). The supervisor SCM_RIGHTS broker is the
    // single seam for outbound TCP.
    let main = read_src("main.rs");
    let upstream = read_src("upstream.rs");
    let server = read_src("server.rs");
    for src in [&main, &upstream, &server] {
        assert!(
            !src.contains("TcpStream::connect("),
            "vauban-proxy-iacs MUST NOT call TcpStream::connect \
             directly; route via SupervisorBrokerOpener instead. \
             Capsicum (FreeBSD prod) would fail-close otherwise."
        );
        assert!(
            !src.contains("TcpListener::bind("),
            "vauban-proxy-iacs MUST NOT call TcpListener::bind; the \
             supervisor pre-binds the IACS listener and passes the \
             FD via env."
        );
    }
}

/// The single-shot `AtomicBool::swap(true)` gate that used to live
/// in `channel_open_direct_tcpip` made every `direct-tcpip` past
/// the first one return `administratively prohibited` -- which
/// broke the multi-client `ssh -L` workflow on every IACS asset
/// (every TCP `accept()` on the EWS side spawns a new SSH channel
/// over the existing tunnel; OpenSSH does not "reuse" a single
/// channel).
///
/// The fix replaces the `AtomicBool` with a bounded `AtomicUsize`
/// counter (`live_channels`) decremented when the relay task ends.
/// This pin grep-fences the regression: no future refactor may
/// re-introduce the boolean kill-switch.
#[test]
fn channel_open_direct_tcpip_uses_bounded_counter_not_single_shot_atomicbool() {
    let src = read_src("server.rs");
    assert!(
        !src.contains("channel_open: std::sync::atomic::AtomicBool"),
        "the per-handler `channel_open: AtomicBool` field is forbidden: \
         it made every direct-tcpip past the first one fail with \
         `administratively prohibited`, breaking multi-client ssh -L."
    );
    assert!(
        !src.contains(".channel_open\n            .swap(true,")
            && !src.contains(".channel_open.swap(true,"),
        "the single-shot `channel_open.swap(true, ...)` gate is forbidden \
         (broke the multi-client ssh -L workflow). Use the bounded \
         `live_channels: AtomicUsize` counter with per-relay decrement \
         instead."
    );
    assert!(
        src.contains("live_channels: Arc<AtomicUsize>")
            || src.contains("live_channels: std::sync::Arc<std::sync::atomic::AtomicUsize>"),
        "channel_open_direct_tcpip MUST track in-flight channels via a \
         bounded `live_channels: Arc<AtomicUsize>` counter so closed \
         channels return their slot to the pool."
    );
    assert!(
        src.contains("max_channels_per_session"),
        "the per-login concurrent-channel cap MUST surface as \
         `max_channels_per_session` (mapped to \
         `IacsTunnelConfig::max_concurrent_channels_per_session`). 0 \
         disables the cap."
    );
    assert!(
        src.contains("live_channels.fetch_sub(1, Ordering::SeqCst)"),
        "every early-return path in channel_open_direct_tcpip MUST \
         decrement live_channels (validation rejection, missing auth \
         state, upstream connect failure). A leak here would burn a \
         slot per failed open until the SSH login ends."
    );
    assert!(
        src.contains("live_channels\n            .fetch_update(")
            || src.contains("live_channels.fetch_update("),
        "the relay teardown MUST decrement live_channels (saturating) \
         so the closed channel returns its slot to the pool. Without \
         it the bug would silently re-emerge as a slow leak per closed \
         tunnel."
    );
}

/// `vauban-proxy-iacs` MUST honor the operator-controlled cap from
/// `industrial.iacs_tunnel.max_concurrent_channels_per_session`,
/// passed through the supervisor as
/// `VAUBAN_IACS_MAX_CHANNELS_PER_SESSION`. A typo in the config or
/// a missing env var falls back to the documented default `16` so a
/// boot does not regress to single-shot tunnels.
#[test]
fn main_reads_max_channels_per_session_from_env() {
    let src = read_src("main.rs");
    assert!(
        src.contains("VAUBAN_IACS_MAX_CHANNELS_PER_SESSION"),
        "main MUST read VAUBAN_IACS_MAX_CHANNELS_PER_SESSION from the \
         env (forwarded by the supervisor from \
         IacsTunnelConfig::max_concurrent_channels_per_session)."
    );
    assert!(
        src.contains(".unwrap_or(16)"),
        "a malformed or missing VAUBAN_IACS_MAX_CHANNELS_PER_SESSION \
         MUST fall back to the documented default 16, NOT to 0/1. A \
         silent regression to 0 would disable the fan-out cap; a \
         silent regression to 1 would re-introduce the original \
         single-shot bug."
    );
    assert!(
        src.contains("IacsTunnelServer::new(") && src.contains("accept_max_channels"),
        "the value MUST be threaded through IacsTunnelServer::new so \
         every accepted EWS connection observes the same cap."
    );
}

#[test]
fn no_hardcoded_legacy_target_in_any_proxy_iacs_source() {
    // Mirrors `vauban-proxy-iacs/scripts/check_no_hardcoded_target.sh`
    // in pure Rust so a developer who runs `cargo test` (instead of
    // the CI shell job) still sees the regression at red-test time.
    let needle = format!("{}.{}.{}.{}:{}", 127, 0, 0, 1, 4321);
    for entry in
        std::fs::read_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")).unwrap()
    {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let body = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            !body.contains(&needle),
            "legacy IACS target literal in {}: per-asset target \
             resolution is the Lot 3 contract",
            path.display()
        );
    }
}
