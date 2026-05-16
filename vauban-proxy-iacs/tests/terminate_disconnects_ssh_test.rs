//! Pin tests for the operator-driven session termination flow:
//! when the operator clicks "Terminate" on `/sessions/active`,
//! `vauban-web` dispatches an `IacsTunnelTerminate` IPC to
//! `vauban-proxy-iacs`, which MUST force-disconnect the EWS SSH
//! session (not just mark the local registry as closed).
//!
//! Background regression (caught by an operator report):
//! ----------------------------------------------------
//! Before this fix, `Message::IacsTunnelTerminate` only called
//! `registry.close_and_remove(&parsed)` on the per-channel
//! `TunnelRegistry`. That method flips an `AtomicBool` inside the
//! `TunnelHandle` and notifies waiters -- but `spawn_relay` does not
//! listen on `wait_close()`, and crucially the russh `Session`
//! itself is NOT torn down. So:
//!   - The vauban-web row flipped to `terminated` (handler updated
//!     the DB row before the IPC dispatch).
//!   - The Active Sessions UI dropped the row.
//!   - The EWS-side `ssh -L 7022:...:7022 ... -p 22322 -N` link
//!     stayed alive.
//!   - A follow-up `nc -v localhost 7022` re-opened a fresh
//!     `direct-tcpip` channel on the still-live SSH session and
//!     succeeded.
//!
//! Operators interpret a green "Terminate" button as "the tunnel
//! is gone"; the gap between UI state and on-the-wire state is a
//! security-relevant correctness bug.
//!
//! The fix wires a per-session `SessionHandles` map keyed by
//! `session_uuid` that holds a clone of `russh::server::Handle`
//! captured in `Handler::auth_succeeded`. The terminate IPC handler
//! looks up the handle and dispatches `Disconnect::ByApplication`,
//! which closes the SSH transport at the russh level and drops every
//! `direct-tcpip` channel atomically. The `Drop` impl on
//! `IacsTunnelHandler` removes the entry so subsequent terminate
//! IPCs become no-ops instead of hitting a dead handle.
//!
//! These tests grep the production source so a refactor that
//! silently restores the "close-and-remove only" path fails CI BEFORE
//! the proxy is restarted in production.

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

const SRC: &str = "src";

fn read_src(rel: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(SRC)
        .join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {}", p.display(), e))
}

// ===================================================================
// 1. SessionHandles registry exists and exposes the expected surface
// ===================================================================

#[test]
fn registry_module_exposes_session_handles_type() {
    let src = read_src("registry.rs");
    assert!(
        src.contains("pub struct SessionHandles {"),
        "registry.rs MUST export a `SessionHandles` type that wraps a \
         per-session `russh::server::Handle` map -- it is the seam the \
         IacsTunnelTerminate IPC uses to force the SSH disconnect."
    );
    assert!(
        src.contains("DashMap<Uuid, russh::server::Handle>"),
        "SessionHandles MUST use a `DashMap<Uuid, russh::server::Handle>` \
         so lookups never block writers (the russh accept loop runs in \
         the same tokio runtime)."
    );
    for sym in [
        "pub fn new(",
        "pub fn insert(",
        "pub fn get(",
        "pub fn remove(",
    ] {
        assert!(
            src.contains(sym),
            "SessionHandles MUST expose `{}` -- needed by the handler \
             (`auth_succeeded` insert + `Drop` remove) and the \
             terminate IPC (`get`).",
            sym
        );
    }
}

// ===================================================================
// 2. IacsTunnelServer / Handler carry the SessionHandles
// ===================================================================

#[test]
fn iacs_tunnel_server_carries_session_handles() {
    let src = read_src("server.rs");
    assert!(
        src.contains("pub session_handles: SessionHandles"),
        "IacsTunnelServer MUST carry a `session_handles: SessionHandles` \
         field; it is propagated to every accepted handler so the \
         terminate IPC running on the IPC dispatcher task can \
         look up the russh handle by `session_uuid`."
    );

    // Constructor must accept it as the THIRD parameter (after
    // registry, pending) so a refactor that drops it shows up as a
    // compile error AND a test failure.
    let new_idx = src
        .find("impl IacsTunnelServer {")
        .expect("IacsTunnelServer impl must exist");
    let new_block = &src[new_idx..];
    let pub_new = new_block.find("pub fn new(").expect("`new` must exist");
    let new_window = &new_block[pub_new..pub_new + 600];
    assert!(
        new_window.contains("session_handles: SessionHandles"),
        "IacsTunnelServer::new MUST take `session_handles: SessionHandles` \
         as a parameter (the per-session russh handle map)."
    );
}

#[test]
fn iacs_tunnel_handler_carries_session_handles() {
    let src = read_src("server.rs");
    let handler_idx = src
        .find("pub struct IacsTunnelHandler {")
        .expect("IacsTunnelHandler must exist");
    let after_struct = &src[handler_idx..];
    let close = after_struct.find("\n}\n").expect("struct must terminate");
    let struct_body = &after_struct[..close];

    assert!(
        struct_body.contains("pub session_handles: SessionHandles"),
        "IacsTunnelHandler MUST carry the shared `session_handles: \
         SessionHandles` so it can register its russh handle in \
         `auth_succeeded` and remove it in `Drop`."
    );
}

// ===================================================================
// 3. auth_succeeded inserts the russh handle
// ===================================================================

#[test]
fn handler_auth_succeeded_inserts_russh_handle() {
    let src = read_src("server.rs");
    let auth_idx = src.find("async fn auth_succeeded(").expect(
        "Handler::auth_succeeded MUST be implemented (it is the \
                 EARLIEST callback where both the resolved \
                 `PendingTunnel.session_uuid` and the live `Session` ref \
                 are available -- see the doc comment on the impl).",
    );

    let after = &src[auth_idx..];
    let close = after
        .find("\n    }\n")
        .expect("auth_succeeded must terminate");
    let body = &after[..close];

    let collapsed: String = body.split_whitespace().collect::<Vec<_>>().join(" ");

    assert!(
        collapsed.contains("session.handle()"),
        "auth_succeeded MUST capture `session.handle()` -- the \
         `russh::server::Handle` is the only seam that can dispatch a \
         `Disconnect::ByApplication` from outside a Handler callback."
    );
    assert!(
        collapsed.contains("self.session_handles .insert(")
            || collapsed.contains("self.session_handles.insert("),
        "auth_succeeded MUST call `self.session_handles.insert(...)` \
         to register the russh handle. Whitespace-collapsed body:\n{}",
        collapsed
    );
    assert!(
        collapsed.contains("session.handle())"),
        "auth_succeeded MUST pass `session.handle()` as the second \
         argument of `insert`. Whitespace-collapsed body:\n{}",
        collapsed
    );
    assert!(
        collapsed.contains("self.authorized.lock().await"),
        "auth_succeeded MUST read `self.authorized` to recover the \
         `session_uuid` set by `auth_publickey` (the russh `Session` \
         alone does not expose the EWS user/session id we negotiated)."
    );
}

// ===================================================================
// 4. Drop removes the russh handle
// ===================================================================

#[test]
fn handler_drop_removes_russh_handle() {
    let src = read_src("server.rs");
    let drop_idx = src
        .find("impl Drop for IacsTunnelHandler {")
        .expect("Drop impl must exist");
    let after = &src[drop_idx..];
    let close = after.find("\n}\n").expect("Drop impl must terminate");
    let body = &after[..close];

    assert!(
        body.contains("self.session_handles.remove(&p.session_uuid);"),
        "Drop MUST remove the russh handle slot so a subsequent \
         terminate IPC for the same session_uuid is a no-op instead of \
         dispatching `Disconnect::ByApplication` to a dead session."
    );
}

// ===================================================================
// 5. main_loop / handle_web_message thread the SessionHandles through
// ===================================================================

#[test]
fn main_loop_threads_session_handles_to_terminate_handler() {
    let src = read_src("main.rs");

    assert!(
        src.contains("use crate::registry::{SessionHandles, TunnelRegistry};"),
        "main.rs MUST import `SessionHandles` from the registry module."
    );
    assert!(
        src.contains("let session_handles = SessionHandles::new();"),
        "main.rs MUST construct a single shared `SessionHandles` \
         instance before the russh accept loop spawns."
    );

    // The accept loop must clone the SessionHandles and pass it
    // into IacsTunnelServer::new so every handler shares the same
    // underlying DashMap.
    let accept_idx = src
        .find("IacsTunnelServer::new(")
        .expect("accept loop must construct IacsTunnelServer");
    let new_window = &src[accept_idx..accept_idx + 400];
    assert!(
        new_window.contains("accept_session_handles.clone()")
            || new_window.contains("session_handles.clone()"),
        "IacsTunnelServer::new MUST receive a clone of the shared \
         SessionHandles so all handlers share the same DashMap."
    );

    // main_loop must take the SessionHandles parameter.
    let main_loop_idx = src
        .find("async fn main_loop(")
        .expect("main_loop must exist");
    let sig_window = &src[main_loop_idx..main_loop_idx + 400];
    assert!(
        sig_window.contains("session_handles: SessionHandles"),
        "main_loop MUST accept `session_handles: SessionHandles` so it \
         can forward it to handle_web_message."
    );

    // handle_web_message must take the SessionHandles parameter.
    let hwm_idx = src
        .find("async fn handle_web_message(")
        .expect("handle_web_message must exist");
    let hwm_window = &src[hwm_idx..hwm_idx + 400];
    assert!(
        hwm_window.contains("session_handles: SessionHandles"),
        "handle_web_message MUST accept `session_handles: \
         SessionHandles` so the IacsTunnelTerminate arm can look up \
         the russh handle by session_uuid."
    );
}

// ===================================================================
// 6. The terminate IPC dispatches Disconnect::ByApplication
// ===================================================================

#[test]
fn terminate_ipc_dispatches_russh_disconnect() {
    let src = read_src("main.rs");
    let term_idx = src
        .find("Message::IacsTunnelTerminate {")
        .expect("Message::IacsTunnelTerminate arm must exist in handle_web_message");
    let after = &src[term_idx..];
    // Look at the arm body. It runs until the next `Message::` arm
    // or the closing `}` of the outer match.
    let next_arm = after
        .find("\n        other => {")
        .expect("the IacsTunnelTerminate arm must be followed by the catch-all `other =>` arm");
    let body = &after[..next_arm];

    // Pre-existing safety: stop the per-channel relay flag and drop
    // the pending entry. These were the buggy "almost did the job"
    // calls; we keep them but the disconnect MUST come on top.
    assert!(
        body.contains("pending.take(&parsed)"),
        "terminate arm MUST drop the pending entry (waiting_client \
         window) so a re-auth for the same session_uuid fails."
    );
    assert!(
        body.contains("registry.close_and_remove(&parsed)"),
        "terminate arm MUST close the per-channel TunnelHandle to wake \
         any task awaiting `wait_close`."
    );

    // The actual fix: look up the russh handle and disconnect.
    assert!(
        body.contains("session_handles.get(&parsed)"),
        "terminate arm MUST consult `session_handles` to look up the \
         russh handle for this session_uuid -- without this, \
         close_and_remove only flips an AtomicBool and the SSH \
         transport stays alive (the regression this test pins)."
    );
    // The `handle.disconnect(...)` call may be split across lines
    // by rustfmt (`let r = handle\n    .disconnect(...)`). Collapse
    // whitespace before the assertion so the contract pin is robust
    // against formatting drift but still rejects the absence of the
    // call.
    let collapsed: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        collapsed.contains("handle .disconnect (")
            || collapsed.contains("handle.disconnect(")
            || collapsed.contains("handle .disconnect("),
        "terminate arm MUST call `handle.disconnect(...)` to dispatch \
         a `Disconnect::ByApplication` to the EWS -- this is the only \
         seam that tears down the russh `Session` and drops every \
         `direct-tcpip` channel atomically. Whitespace-collapsed body:\n{}",
        collapsed
    );
    assert!(
        body.contains("russh::Disconnect::ByApplication"),
        "terminate arm MUST tag the disconnect as `ByApplication` (RFC \
         4253 reason 11). A bare `ProtocolError` would be misleading."
    );
    assert!(
        body.contains("tokio::spawn(async move"),
        "terminate arm MUST spawn the disconnect call (it is async and \
         must not block the IPC dispatcher main_loop)."
    );
}

// ===================================================================
// 7. The doc comment captures the why
// ===================================================================

#[test]
fn terminate_arm_doc_captures_the_why() {
    let src = read_src("main.rs");
    let term_idx = src
        .find("Message::IacsTunnelTerminate {")
        .expect("Message::IacsTunnelTerminate arm must exist");
    // Walk back to find the section right above the
    // `if let Some(handle) = ...` block.
    let after = &src[term_idx..];
    let disconnect_block = after
        .find("if let Some(handle) = session_handles.get(&parsed)")
        .expect("the if-let block must exist");
    let prelude = &after[..disconnect_block];

    assert!(
        prelude.contains("Force-disconnect the EWS SSH session"),
        "the terminate arm MUST carry a doc comment that explains the \
         WHY (close_and_remove alone keeps the SSH transport alive). \
         Without that comment, a future contributor will likely \
         re-introduce the bug."
    );
    assert!(
        prelude.contains("waiting_client") && prelude.contains("tunnel_active"),
        "the doc comment MUST explicitly call out that the disconnect \
         covers BOTH the `waiting_client` (auth done, no direct-tcpip) \
         AND the `tunnel_active` states. The split is the reason we \
         capture the russh handle in `auth_succeeded` instead of \
         `channel_open_direct_tcpip`."
    );
}
