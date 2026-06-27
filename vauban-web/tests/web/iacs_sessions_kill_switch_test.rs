//! Source-grep pin tests for the IACS kill-switch on the **session**
//! surface (issue: IACS sessions / IACS filter remained available on
//! `/sessions` and `/sessions/active` while `industrial.enabled =
//! false`).
//!
//! Mirror of `iacs_kill_switch_test.rs`'s asset-surface pins, scoped
//! to the operational session lists. The contract:
//!
//! * Operational lists (`session_list`, `active_sessions`) drop IACS
//!   at the DB level under the kill-switch (layer 2) and strip the
//!   IACS affordance from their templates (layer 5).
//! * Forensic surfaces (`recording_list` + `recording_list.html`)
//!   stay gate-free: recordings survive switching IACS off.
//!
//! These are purely structural (file-content) assertions so CI
//! catches drift before the runtime suite runs. Runtime behaviour is
//! covered by `iacs_sessions_surface_e2e_test.rs`.

#![allow(clippy::unwrap_used, clippy::panic)]

const SESSIONS_RS: &str = include_str!("../../src/handlers/web/sessions.rs");
const SESSION_LIST_HTML: &str = include_str!("../../templates/sessions/session_list.html");
const ACTIVE_LIST_STATS_HTML: &str =
    include_str!("../../templates/sessions/active_list_stats.html");
const RECORDING_LIST_HTML: &str = include_str!("../../templates/sessions/recording_list.html");

/// Slice `src` from `sig` to the next top-level `fn` boundary.
fn scoped_fn_body<'a>(src: &'a str, sig: &str) -> &'a str {
    let start = src
        .find(sig)
        .unwrap_or_else(|| panic!("function signature `{}` not found", sig));
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

// ===================================================================
// Layer 2 -- DB filter on the operational lists
// ===================================================================

/// `session_list` MUST drop IACS rows under the kill-switch, on BOTH
/// the data query AND the count query (or pagination would report N
/// rows the caller cannot see).
#[test]
fn session_list_db_filter_is_gated_on_industrial_enabled() {
    let body = scoped_fn_body(SESSIONS_RS, "pub async fn session_list");
    assert!(
        body.contains("!state.config.industrial.enabled"),
        "session_list MUST branch on `!state.config.industrial.enabled`"
    );
    assert!(
        body.contains("query = query.filter(proxy_sessions::session_type.ne(SessionType::IacsTunnel))"),
        "session_list data query MUST exclude IACS under the kill-switch"
    );
    assert!(
        body.contains(
            "count_query = count_query.filter(proxy_sessions::session_type.ne(SessionType::IacsTunnel))"
        ),
        "session_list count query MUST exclude IACS under the kill-switch \
         (lock-step with the data query for correct pagination)"
    );
}

/// `active_sessions` MUST drop IACS rows under the kill-switch, on
/// both the count and the data query, while preserving the
/// `status.eq_any(["active", "tunnel_active"])` base clause (pinned
/// separately by `iacs_active_sessions_pin_test`).
#[test]
fn active_sessions_db_filter_is_gated_on_industrial_enabled() {
    let body = scoped_fn_body(SESSIONS_RS, "pub async fn active_sessions");
    assert!(
        body.contains("!state.config.industrial.enabled"),
        "active_sessions MUST branch on `!state.config.industrial.enabled`"
    );
    let exclusions = body
        .matches("session_type.ne(SessionType::IacsTunnel)")
        .count();
    assert!(
        exclusions >= 2,
        "active_sessions MUST exclude IACS on BOTH the count and data \
         queries under the kill-switch (found {} exclusion clause(s))",
        exclusions
    );
    assert!(
        body.contains(r#"status.eq_any(["active", "tunnel_active"])"#),
        "active_sessions MUST keep the base `status.eq_any([\"active\", \
         \"tunnel_active\"])` clause (the kill-switch ADDS an exclusion, \
         it does not replace the status filter)"
    );
}

// ===================================================================
// Layer 5 -- template affordance gates
// ===================================================================

/// The `/sessions` type filter MUST wrap the IACS option in
/// `{% if industrial_enabled %}`.
#[test]
fn session_list_template_gates_iacs_option() {
    assert!(
        SESSION_LIST_HTML.contains("{% if industrial_enabled %}"),
        "session_list.html MUST gate the IACS option on industrial_enabled"
    );
    // The IACS option must sit inside the gate: the `{% if %}` opens
    // before `value=\"iacs_tunnel\"`, and a matching `{% endif %}`
    // closes after it.
    let gate = SESSION_LIST_HTML
        .find("{% if industrial_enabled %}")
        .expect("industrial_enabled gate present");
    let opt = SESSION_LIST_HTML
        .find(r#"value="iacs_tunnel""#)
        .expect("iacs_tunnel option present");
    assert!(
        gate < opt,
        "the IACS `<option>` must be rendered INSIDE the \
         `{{% if industrial_enabled %}}` gate"
    );
}

/// The `/sessions/active` IACS stat tile MUST be wrapped in
/// `{% if industrial_enabled %}`.
#[test]
fn active_list_stats_template_gates_iacs_tile() {
    assert!(
        ACTIVE_LIST_STATS_HTML.contains("{% if industrial_enabled %}"),
        "active_list_stats.html MUST gate the IACS tile on industrial_enabled"
    );
    let gate = ACTIVE_LIST_STATS_HTML
        .find("{% if industrial_enabled %}")
        .expect("industrial_enabled gate present");
    let tile = ACTIVE_LIST_STATS_HTML
        .find("self.iacs_count()")
        .expect("iacs_count tile present");
    assert!(
        gate < tile,
        "the IACS stat tile must be rendered INSIDE the \
         `{{% if industrial_enabled %}}` gate"
    );
}

// ===================================================================
// Forensic surfaces stay gate-free
// ===================================================================

/// `recording_list` is forensic: it MUST NOT carry an
/// `industrial.enabled` guard, and `recording_list.html` MUST keep
/// the IACS (`PCAP bundle`) format option so historical IACS
/// recordings remain filterable after the kill-switch is thrown.
#[test]
fn recording_surface_stays_gate_free() {
    let body = scoped_fn_body(SESSIONS_RS, "pub async fn recording_list");
    assert!(
        !body.contains("industrial.enabled"),
        "recording_list MUST NOT gate on industrial.enabled -- recordings \
         are forensic and stay visible under the kill-switch"
    );
    assert!(
        RECORDING_LIST_HTML.contains(r#"value="iacs_tunnel""#),
        "recording_list.html MUST keep the IACS format option (forensic \
         recordings stay filterable regardless of the kill-switch)"
    );
    assert!(
        !RECORDING_LIST_HTML.contains("{% if industrial_enabled %}"),
        "recording_list.html MUST NOT gate any affordance on \
         industrial_enabled (the recordings catalogue is forensic)"
    );
}
