//! VAU-012 source-pin invariants.
//!
//! These structural tests guard the placement and ordering of the
//! session-creation controls so a future refactor cannot silently move them
//! after the resource allocation (which would re-open the DoS vector) or
//! reorder the four controls.
//!
//! INV-12-1: every `connect_*` handler calls `enforce_session_creation`
//! BEFORE the `proxy_sessions` INSERT (the first backend resource
//! allocation). INV order: global rate -> per-user rate -> per-user
//! concurrency -> per-asset concurrency.

const SSH_SRC: &str = include_str!("../../src/handlers/web/ssh.rs");
const RDP_SRC: &str = include_str!("../../src/handlers/web/rdp.rs");
const IACS_SRC: &str = include_str!("../../src/handlers/web/iacs_tunnel.rs");
const LIMITS_SRC: &str = include_str!("../../src/services/session_limits.rs");

fn assert_enforce_before_insert(name: &str, src: &str) {
    let enforce = src.find("enforce_session_creation").unwrap_or_else(|| {
        panic!("{name}: must call enforce_session_creation (VAU-012, INV-12-1)")
    });
    let insert = src
        .find("diesel::insert_into(proxy_sessions::table)")
        .unwrap_or_else(|| panic!("{name}: expected a proxy_sessions INSERT to anchor the pin"));
    assert!(
        enforce < insert,
        "{name}: enforce_session_creation (byte {enforce}) must run BEFORE the \
         proxy_sessions INSERT (byte {insert}) so a denial allocates no resource"
    );
}

#[test]
fn ssh_enforces_limits_before_insert() {
    assert_enforce_before_insert("connect_ssh", SSH_SRC);
}

#[test]
fn rdp_enforces_limits_before_insert() {
    assert_enforce_before_insert("connect_rdp", RDP_SRC);
}

#[test]
fn iacs_enforces_limits_before_insert() {
    assert_enforce_before_insert("connect_iacs", IACS_SRC);
}

#[test]
fn all_three_handlers_use_the_shared_denied_response() {
    for (name, src) in [
        ("connect_ssh", SSH_SRC),
        ("connect_rdp", RDP_SRC),
        ("connect_iacs", IACS_SRC),
    ] {
        assert!(
            src.contains("connect_limit_response"),
            "{name}: must surface a denial via the shared connect_limit_response \
             helper (429 / toast, INV-12-2)"
        );
    }
}

#[test]
fn enforce_runs_the_four_controls_in_order() {
    // Restrict the search to the enforce_session_creation body: the count
    // helpers are DEFINED earlier in the file, so a whole-file search would
    // match the definitions, not the call order.
    let fn_start = LIMITS_SRC
        .find("pub async fn enforce_session_creation")
        .expect("enforce_session_creation must exist");
    let body = &LIMITS_SRC[fn_start..];

    // The four controls must appear in this exact order in the service body.
    let order = [
        "session:global",       // 1. global rate limit
        "session:user:",        // 2. per-user rate limit
        "count_live_for_user",  // 3. per-user concurrency
        "count_live_for_asset", // 4. per-asset concurrency
    ];
    let mut last = 0usize;
    for marker in order {
        let idx = body
            .find(marker)
            .unwrap_or_else(|| panic!("enforce_session_creation must contain marker `{marker}`"));
        assert!(
            idx >= last,
            "VAU-012 controls out of order: `{marker}` appears before the previous control"
        );
        last = idx;
    }
}

#[test]
fn each_control_is_skipped_when_threshold_is_zero() {
    // INV-12-3: a `0` threshold disables the corresponding control.
    for guard in [
        "session_create_rate_global_per_minute > 0",
        "session_create_rate_per_minute > 0",
        "max_concurrent_sessions_per_user > 0",
        "max_concurrent_sessions_per_asset > 0",
    ] {
        assert!(
            LIMITS_SRC.contains(guard),
            "session_limits.rs must guard each control with `{guard}` (INV-12-3)"
        );
    }
}
