//! Source-grep pin tests for the IACS active sessions integration.
//!
//! The active-sessions surface depends on three independent SQL
//! sites and a small terminate dispatch invariant. This file is a
//! purely structural (file-content) safety net that catches accidental
//! drift in CI before the integration suite even runs.
//!
//! Pinned invariants:
//! 1. The three active-list SQL filters all use
//!    `status.eq_any([... , "tunnel_active"])` -- not just
//!    `status.eq("active")`. Otherwise IACS rows go missing.
//! 2. The terminate handler dispatches IACS termination via
//!    `state.proxy_iacs` first, with the legacy in-process registry
//!    only as a fallback. Otherwise production IACS terminate would
//!    silently no-op (proxy-iacs would never receive the signal).

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {}", p.display(), e))
}

/// Like `read` but truncates the file at the first `#[cfg(test)]`
/// fence so unit tests embedded in the same source file (which often
/// contain string literals like `"connected_at.is_not_null()"` for
/// their own pin assertions) don't poison this file's window scans.
fn read_production_only(rel: &str) -> String {
    let src = read(rel);
    if let Some(cut) = src.find("#[cfg(test)]") {
        src[..cut].to_string()
    } else {
        src
    }
}

// ===================================================================
// 1. Three SQL sites must include `tunnel_active` in the filter.
// ===================================================================

const ACTIVE_LIST_SITES: &[(&str, &str)] = &[
    (
        "src/handlers/web/sessions.rs",
        "active_sessions handler (SSR page)",
    ),
    (
        "src/tasks/dashboard.rs",
        "fetch_active_sessions_full (10 s WS pump)",
    ),
    (
        "src/handlers/websocket.rs",
        "fetch_active_sessions_list (initial WS data)",
    ),
];

#[test]
fn every_active_list_query_site_includes_tunnel_active_status() {
    for (rel, what) in ACTIVE_LIST_SITES {
        let src = read_production_only(rel);
        assert!(
            src.contains(r#"status.eq_any(["active", "tunnel_active"])"#),
            "{} ({}) MUST filter the active list with \
             `status.eq_any([\"active\", \"tunnel_active\"])` so IACS \
             tunnels surface alongside SSH/RDP. Pinned at \
             tests/web/iacs_active_sessions_pin_test.rs",
            rel,
            what
        );
        // Each active-list query is identified by its
        // `connected_at.is_not_null()` neighbour. We require that the
        // 200 chars BEFORE it contain the IACS-aware filter -- a
        // regression that reverts the filter to `status.eq("active")`
        // would surface here, while leaving unrelated UPDATEs that
        // legitimately write `status = "active"` untouched.
        let mut at = 0usize;
        let mut found = 0usize;
        while let Some(idx) = src[at..].find("connected_at.is_not_null()") {
            let abs = at + idx;
            let win_start = abs.saturating_sub(200);
            let window = &src[win_start..abs];
            assert!(
                window.contains(r#"eq_any(["active", "tunnel_active"])"#),
                "{} ({}): a `connected_at.is_not_null()` filter is not \
                 paired with the IACS-aware `status.eq_any([\"active\", \
                 \"tunnel_active\"])` within the preceding 200 chars. \
                 Window:\n---\n{}\n---",
                rel,
                what,
                window
            );
            at = abs + "connected_at.is_not_null()".len();
            found += 1;
        }
        assert!(
            found >= 1,
            "{} ({}) MUST contain at least one active-list query, \
             identified by `connected_at.is_not_null()`",
            rel,
            what
        );
    }
}

#[test]
fn every_active_list_query_site_keeps_connected_at_not_null_guard() {
    for (rel, what) in ACTIVE_LIST_SITES {
        let src = read_production_only(rel);
        assert!(
            src.contains("connected_at.is_not_null()"),
            "{} ({}) MUST keep the `connected_at IS NOT NULL` guard so \
             rows still in `waiting_client` (IACS) or pre-handshake \
             (SSH/RDP) do not bleed into the active list.",
            rel,
            what
        );
    }
}

// ===================================================================
// 1bis. Every active-list site must ALSO carry the industrial
//       kill-switch branch (issue: IACS sessions leaking onto the
//       operational `/sessions/active` surface when
//       `industrial.enabled = false`). The base
//       `status.eq_any(["active", "tunnel_active"])` clause stays
//       (pinned above); under the kill-switch each site adds an
//       `session_type.ne(... ::IacsTunnel)` exclusion gated on the
//       flag. Scoped to the function body so an unrelated occurrence
//       elsewhere in the file cannot mask a regression.
// ===================================================================

const ACTIVE_LIST_KILL_SWITCH_SITES: &[(&str, &str, &str)] = &[
    (
        "src/handlers/web/sessions.rs",
        "pub async fn active_sessions",
        "active_sessions handler (SSR page)",
    ),
    (
        "src/tasks/dashboard.rs",
        "async fn fetch_active_sessions_full",
        "fetch_active_sessions_full (10 s WS pump)",
    ),
    (
        "src/handlers/websocket.rs",
        "async fn fetch_active_sessions_list",
        "fetch_active_sessions_list (initial WS data)",
    ),
];

/// Slice `src` from the given function signature to the next
/// top-level `fn` boundary, so assertions stay scoped to one body.
fn function_body<'a>(src: &'a str, sig: &str, rel: &str) -> &'a str {
    let start = src
        .find(sig)
        .unwrap_or_else(|| panic!("{}: function signature `{}` not found", rel, sig));
    let after = &src[start + sig.len()..];
    let end_rel = after
        .find("\nasync fn ")
        .or_else(|| after.find("\nfn "))
        .or_else(|| after.find("\npub async fn "))
        .or_else(|| after.find("\npub(crate) async fn "))
        .or_else(|| after.find("\npub fn "))
        .map(|e| start + sig.len() + e)
        .unwrap_or(src.len());
    &src[start..end_rel]
}

#[test]
fn every_active_list_query_site_has_kill_switch_branch() {
    for (rel, sig, what) in ACTIVE_LIST_KILL_SWITCH_SITES {
        let src = read_production_only(rel);
        let body = function_body(&src, sig, rel);
        assert!(
            body.contains("IacsTunnel"),
            "{} ({}) MUST exclude IACS tunnels under the kill-switch \
             (`session_type.ne(... ::IacsTunnel)`). The operational \
             active-list surface hides IACS when `industrial.enabled = \
             false`. Pinned at tests/web/iacs_active_sessions_pin_test.rs",
            rel,
            what
        );
        assert!(
            body.contains("industrial_enabled") || body.contains("industrial.enabled"),
            "{} ({}) MUST gate the IACS exclusion on the industrial \
             kill-switch flag (`industrial.enabled` / `industrial_enabled`)",
            rel,
            what
        );
    }
}

// ===================================================================
// 2. Terminate dispatch MUST prefer proxy-iacs IPC over legacy registry.
// ===================================================================

#[test]
fn terminate_session_handler_dispatches_iacs_via_proxy_iacs_ipc_first() {
    // The dispatch moved from the terminate_session handler into the
    // shared terminate core (services/session_termination.rs); every
    // terminate caller routes through it (pinned by
    // jit_revocation_pins_test::all_terminate_callers_use_the_shared_core).
    let src = read("src/services/session_termination.rs");

    // Match the block-bodied arm specifically (the `is_recording`
    // match earlier in the file uses one-liner arms). The terminate
    // dispatch is the multi-line block: `=> {`.
    let needle_block = "SessionType::IacsTunnel => {";
    let block_start = src.find(needle_block).expect(
        "the terminate core must keep a block-bodied IACS arm \
         (the dispatch arm, not the recording flag arm)",
    );
    let block = &src[block_start..(block_start + 2_500).min(src.len())];

    let proxy_iacs_pos = block.find("state.proxy_iacs").expect(
        "IACS terminate arm MUST reference `state.proxy_iacs` so the \
         supervised topology is the canonical dispatch path",
    );
    let terminate_call_pos = block.find("terminate_tunnel(").expect(
        "IACS terminate arm MUST call `terminate_tunnel(...)` on \
         `state.proxy_iacs` so the IPC reaches proxy-iacs",
    );
    // rustfmt may split the chained call across lines, so anchor on the
    // registry field and require the close call after it.
    let legacy_registry_pos = block.find("iacs_tunnel_registry").expect(
        "Legacy in-process registry MUST stay as the fallback (used \
         by tests / pre-supervisor dev mode)",
    );
    assert!(
        block[legacy_registry_pos..].contains("close_and_remove"),
        "The legacy registry fallback must call `close_and_remove(...)`"
    );

    assert!(
        proxy_iacs_pos < legacy_registry_pos,
        "`state.proxy_iacs.terminate_tunnel(...)` MUST appear BEFORE \
         `iacs_tunnel_registry.close_and_remove(...)` in the IACS \
         terminate arm so the IPC path is preferred."
    );
    assert!(
        terminate_call_pos < legacy_registry_pos,
        "The IPC terminate call must precede the legacy fallback."
    );
}

// ===================================================================
// 3. proxy_iacs IPC pump MUST persist DB state on lifecycle messages.
// ===================================================================

#[test]
fn proxy_iacs_ipc_pump_persists_tunnel_active_and_tunnel_closed_in_db() {
    let src = read("src/ipc/proxy_iacs.rs");

    assert!(
        src.contains("persist_tunnel_active"),
        "{}",
        "ipc::proxy_iacs MUST call `persist_tunnel_active(...)` when \
         it receives `IacsTunnelStatusUpdate {{ status = tunnel_active }}`"
    );
    assert!(
        src.contains("persist_tunnel_closed"),
        "ipc::proxy_iacs MUST call `persist_tunnel_closed(...)` when \
         it receives `IacsTunnelClosed`"
    );
    assert!(
        src.contains("push_active_sessions_update"),
        "ipc::proxy_iacs MUST trigger `push_active_sessions_update` \
         after a successful DB persistence so admin tabs see the row \
         appear / disappear in real time"
    );
}

// ===================================================================
// 4. ActiveSessionItem MUST have an iacs_tunnel branch in the badge.
// ===================================================================

#[test]
fn active_session_item_session_type_class_handles_iacs_tunnel() {
    let src = read("src/templates/sessions/active_list.rs");
    assert!(
        src.contains("\"iacs_tunnel\" =>"),
        "ActiveSessionItem::session_type_class MUST have an explicit \
         `\"iacs_tunnel\" =>` arm with a non-default colour class \
         (otherwise IACS rows would silently fall back to gray)"
    );
    assert!(
        src.contains("session_type_label"),
        "ActiveSessionItem::session_type_label MUST exist to render \
         a short 'IACS' badge instead of the verbose 'IACS_TUNNEL'"
    );
}
