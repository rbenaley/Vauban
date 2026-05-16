//! Pin tests for the `/sessions` (history list) row rendering of
//! IACS tunnel sessions.
//!
//! Background -- before 0.7.12, the row collapsed to "iacs_tunnel
//! &bull; " on a brand-new IACS session because:
//!   1. `SessionListItem::session_type_display()` had no `iacs_tunnel`
//!      arm, so the badge fell to the raw enum value.
//!   2. `credential_username` is intentionally empty for IACS (the
//!      EWS authenticates with its pubkey, no per-session credential),
//!      and the template displayed `{{ session.credential_username }}`
//!      directly.
//!   3. The three SQL select sites that hydrate the list never pulled
//!      `proxy_sessions.tunnel_target_addr`, so even after fixing the
//!      template there was no fallback string to render.
//!
//! These pin tests grep the production source so a future refactor
//! cannot silently revoke the fix.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::Path;

fn read(rel: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("vauban-web")
        .join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {}", p.display(), e))
}

/// `SessionListItem` MUST carry `tunnel_target_addr` so the row can
/// fall back to the industrial endpoint snapshot when the IACS row's
/// `credential_username` is empty.
#[test]
fn session_list_item_carries_tunnel_target_addr_field() {
    let src = read("src/templates/sessions/session_list.rs");
    assert!(
        src.contains("pub tunnel_target_addr: Option<String>"),
        "SessionListItem MUST expose tunnel_target_addr so \
         display_identity() can fall back on it for IACS rows"
    );
    assert!(
        src.contains("pub fn display_identity(&self)"),
        "SessionListItem MUST expose display_identity() (the seam \
         used by the template to pick credential_username vs \
         tunnel_target_addr)"
    );
    assert!(
        src.contains("\"iacs_tunnel\" => \"IACS\""),
        "session_type_display() MUST collapse iacs_tunnel to the \
         short `IACS` label (badge stays compact on the row)"
    );
}

/// `session_list_content.html` MUST call `display_identity()` rather
/// than reading `credential_username` directly, otherwise the IACS
/// row renders an empty string after `&bull;` (the regression we
/// are fixing).
#[test]
fn session_list_template_uses_display_identity() {
    let src = read("templates/sessions/session_list_content.html");
    assert!(
        src.contains("session.display_identity()"),
        "session_list_content.html MUST use `session.display_identity()` \
         so IACS rows render `tunnel_target_addr` when \
         credential_username is empty"
    );
    assert!(
        !src.contains("{{ session.credential_username }}"),
        "session_list_content.html MUST NOT call credential_username \
         directly; the IACS fallback path lives behind display_identity()"
    );
}

/// Each of the three SQL select sites that hydrate the list MUST
/// include `proxy_sessions::tunnel_target_addr` so the column makes
/// it through to the `SessionListItem`. Drift would silently
/// re-create the empty-row regression on one or more surfaces.
#[test]
fn three_sql_select_sites_pull_tunnel_target_addr() {
    for (label, rel) in [
        ("handlers/web/sessions.rs", "src/handlers/web/sessions.rs"),
        ("tasks/dashboard.rs", "src/tasks/dashboard.rs"),
        ("handlers/websocket.rs", "src/handlers/websocket.rs"),
    ] {
        let src = read(rel);
        assert!(
            src.contains("proxy_sessions::tunnel_target_addr,"),
            "{label} MUST select `proxy_sessions::tunnel_target_addr` so \
             the SessionListItem display falls back to the asset endpoint \
             for IACS rows"
        );
    }
}

/// Each of the three SQL hydration sites also MUST compute
/// `duration_seconds` for `tunnel_active`, otherwise IACS rows
/// freeze at "no duration" while the tunnel is alive.
#[test]
fn three_hydration_sites_compute_duration_for_tunnel_active() {
    for (label, rel) in [
        ("handlers/web/sessions.rs", "src/handlers/web/sessions.rs"),
        ("tasks/dashboard.rs", "src/tasks/dashboard.rs"),
        ("handlers/websocket.rs", "src/handlers/websocket.rs"),
    ] {
        let src = read(rel);
        assert!(
            src.contains("status == \"active\" || status == \"tunnel_active\""),
            "{label} MUST compute duration_seconds for both \
             `active` and `tunnel_active` so IACS rows show a \
             live duration"
        );
    }
}

/// `session_status_class` MUST classify `tunnel_active` and
/// `waiting_client` so the IACS rows do not fall through to the
/// gray fallback (which makes the row look stale).
#[test]
fn status_class_handles_iacs_states() {
    let src = read("src/templates/sessions/mod.rs");
    assert!(
        src.contains("\"tunnel_active\""),
        "session_status_class MUST classify `tunnel_active` (currently \
         shares the blue badge with `active`)"
    );
    assert!(
        src.contains("\"waiting_client\""),
        "session_status_class MUST classify `waiting_client` (yellow \
         badge -- distinct from blue `tunnel_active` so the operator \
         can spot a session that has not yet been claimed by an EWS)"
    );
}
