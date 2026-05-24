//! Structural pin tests for the IACS Inspect Capture handlers.
//!
//! A real `TestApp` end-to-end is intentionally out of scope here:
//! `SupervisorClient` is a concrete type, not a trait, so the
//! FD-broker that the inspect handlers depend on cannot be mocked
//! without test-only infrastructure that does not exist yet (the
//! same constraint applies to `recording_iacs_download_e2e_test`).
//!
//! These pins cover:
//!
//! 1. The 3 handler functions exist and are exported.
//! 2. Each handler gates on `perms.admin_view` and returns the
//!    same generic 404 on denial (anti-enumeration).
//! 3. Each handler funnels through `resolve_inspect_target`, which
//!    centralises the IACS+finalized check + storage_path strip.
//! 4. The handler list endpoint applies all four filters
//!    (direction, kind, search, page).
//! 5. The detail handler refuses `frame_idx == 0` (anti-enum 404).
//! 6. The 3 routes are mounted in `main.rs` with the exact path
//!    pattern documented in the plan (`/sessions/recordings/{uuid}/inspect`).

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

const SESSIONS_RS: &str = include_str!("../../src/handlers/web/sessions.rs");
const MAIN_RS: &str = include_str!("../../src/main.rs");

#[test]
fn inspect_capture_handler_exists() {
    assert!(
        SESSIONS_RS.contains("pub async fn inspect_capture("),
        "the shell handler must exist"
    );
}

#[test]
fn inspect_capture_packet_list_handler_exists() {
    assert!(
        SESSIONS_RS.contains("pub async fn inspect_capture_packet_list("),
        "the list fragment handler must exist"
    );
}

#[test]
fn inspect_capture_packet_detail_handler_exists() {
    assert!(
        SESSIONS_RS.contains("pub async fn inspect_capture_packet_detail("),
        "the detail fragment handler must exist"
    );
}

#[test]
fn every_inspect_handler_gates_on_admin_view_with_404() {
    // All three handlers must early-out when `perms.admin_view` is
    // false, returning the SAME generic 404 wording so a non-admin
    // cannot distinguish "forbidden" from "no such recording".
    let handler_starts: Vec<usize> = [
        "pub async fn inspect_capture(",
        "pub async fn inspect_capture_packet_list(",
        "pub async fn inspect_capture_packet_detail(",
    ]
    .iter()
    .map(|n| SESSIONS_RS.find(n).expect("handler exists"))
    .collect();
    for start in handler_starts {
        let end = SESSIONS_RS[start..]
            .find("\n}\n")
            .expect("handler must close")
            + start;
        let body = &SESSIONS_RS[start..end];
        assert!(
            body.contains("if !perms.admin_view {"),
            "every inspect_capture* handler must gate on admin_view"
        );
        assert!(
            body.contains("AppError::NotFound(\"Not found\".to_string())"),
            "denial must collapse to generic 404 (anti-enumeration)"
        );
    }
}

#[test]
fn handlers_funnel_through_resolve_inspect_target() {
    // Single source of truth for the IACS+finalized+storage_path
    // resolution. Each handler MUST call it.
    let count = SESSIONS_RS.matches("resolve_inspect_target(&state").count();
    assert!(
        count >= 3,
        "every inspect_capture* handler must call resolve_inspect_target (got {} calls)",
        count
    );
}

#[test]
fn resolve_inspect_target_rejects_non_iacs_or_unfinalized_with_404() {
    let resolve_idx = SESSIONS_RS
        .find("async fn resolve_inspect_target(")
        .expect("helper exists");
    let body = &SESSIONS_RS[resolve_idx..];
    let next_fn = body[1..].find("\nasync fn ").unwrap_or(body.len());
    let body = &body[..next_fn];
    assert!(
        body.contains("s_type != SessionType::IacsTunnel || s_finalized_at.is_none()"),
        "non-IACS and pending-hydration must both 404"
    );
    assert!(
        body.contains("AppError::NotFound(\"Not found\".to_string())"),
        "the rejection must be the generic 404"
    );
}

#[test]
fn packet_list_handler_applies_direction_kind_search_filters() {
    let start = SESSIONS_RS
        .find("pub async fn inspect_capture_packet_list(")
        .unwrap();
    let body = &SESSIONS_RS[start..];
    let end = body[1..].find("\npub async fn ").unwrap_or(body.len() - 1);
    let body = &body[..end];
    assert!(body.contains("direction:"), "direction filter wired");
    assert!(body.contains("kind:"), "kind filter wired");
    assert!(body.contains("search:"), "search filter wired");
    assert!(body.contains("page:"), "pagination wired");
}

#[test]
fn packet_detail_handler_rejects_zero_frame_idx() {
    let start = SESSIONS_RS
        .find("pub async fn inspect_capture_packet_detail(")
        .unwrap();
    let body = &SESSIONS_RS[start..];
    let end = body[1..].find("\nfn ").unwrap_or(body.len() - 1);
    let body = &body[..end];
    assert!(
        body.contains("if frame_idx == 0"),
        "detail handler must refuse frame_idx 0 (anti-enum)"
    );
}

#[test]
fn three_inspect_routes_are_mounted_in_main_rs() {
    assert!(
        MAIN_RS.contains("/sessions/recordings/{uuid}/inspect\""),
        "shell route must be mounted"
    );
    assert!(
        MAIN_RS.contains(
            "/sessions/recordings/{uuid}/inspect/channels/{n}/packets\""
        ),
        "list route must be mounted"
    );
    assert!(
        MAIN_RS.contains(
            "/sessions/recordings/{uuid}/inspect/channels/{n}/packets/{idx}\""
        ),
        "detail route must be mounted"
    );
    assert!(
        MAIN_RS.contains("get(handlers::web::inspect_capture)"),
        "shell route -> inspect_capture handler"
    );
    assert!(
        MAIN_RS.contains("get(handlers::web::inspect_capture_packet_list)"),
        "list route -> inspect_capture_packet_list handler"
    );
    assert!(
        MAIN_RS.contains("get(handlers::web::inspect_capture_packet_detail)"),
        "detail route -> inspect_capture_packet_detail handler"
    );
}

#[test]
fn fetch_inspect_meta_collapses_invalid_json_to_404() {
    let start = SESSIONS_RS
        .find("async fn fetch_inspect_meta(")
        .unwrap();
    let body = &SESSIONS_RS[start..];
    let end = body[1..].find("\nasync fn ").unwrap_or(body.len() - 1);
    let body = &body[..end];
    assert!(
        body.contains("AppError::NotFound(\"Not found\".to_string())"),
        "meta.json parse failure must 404, never leak parse errors"
    );
}

#[test]
fn fetch_inspect_channel_pcap_decompresses_via_flate2() {
    let start = SESSIONS_RS
        .find("async fn fetch_inspect_channel_pcap(")
        .unwrap();
    let body = &SESSIONS_RS[start..];
    let end = body[1..].find("\nfn ").unwrap_or(body.len() - 1);
    let body = &body[..end];
    assert!(
        body.contains("flate2::read::GzDecoder"),
        "channel PCAP must be gunzipped server-side"
    );
}

#[test]
fn industrial_to_profile_uses_shared_classifier() {
    assert!(
        SESSIONS_RS.contains(
            "shared::iacs_protocol::ExpectedProfile::from_industrial_label"
        ),
        "profile resolution must go through the shared classifier so a new \
         protocol gate (e.g. opcua) is automatically dispatched correctly"
    );
}

#[test]
fn build_packet_list_view_caps_pagination_and_propagates_filter() {
    let start = SESSIONS_RS
        .find("fn build_packet_list_view(")
        .unwrap();
    let body = &SESSIONS_RS[start..];
    let end = body[1..].find("\nfn ").unwrap_or(body.len() - 1);
    let body = &body[..end];
    assert!(body.contains("has_prev"), "previous-page flag computed");
    assert!(body.contains("has_next"), "next-page flag computed");
    assert!(
        body.contains("filter,"),
        "filter must round-trip back to the partial so re-fetch keeps state"
    );
}
