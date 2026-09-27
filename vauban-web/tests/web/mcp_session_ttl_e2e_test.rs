//! Hop-1 MCP visit TTL: appliance default from `[mcp]`, client 600, rule shorten.
//!
//! TestApp has no proxy-mcp, so we cannot persist a live `proxy_sessions`
//! row. The contract is the same `clamp_ttl_capped` the API / Connect
//! handlers call with `state.config.mcp`.

use serial_test::serial;
use vauban_web::services::mcp_session::clamp_ttl_capped;

use crate::common::TestApp;

#[tokio::test]
#[serial]
async fn e2e_mcp_visit_ttl_default_is_appliance_3600() {
    let app = TestApp::spawn().await;
    assert_eq!(
        app.config.mcp.session_ttl_seconds, 3600,
        "testing/default.toml [mcp].session_ttl_seconds"
    );
    assert_eq!(app.config.mcp.hitl_pending_ttl_seconds, 900);
    let appliance = app.config.mcp.session_ttl_clamped();
    assert_eq!(clamp_ttl_capped(None, None, Some(appliance)), 3600);
}

#[tokio::test]
#[serial]
async fn e2e_mcp_visit_ttl_client_600_still_honoured() {
    let app = TestApp::spawn().await;
    let appliance = app.config.mcp.session_ttl_clamped();
    assert_eq!(
        clamp_ttl_capped(Some(600), None, Some(appliance)),
        600,
        "existing clients that send requested_duration_seconds=600 keep 600s"
    );
}

#[tokio::test]
#[serial]
async fn e2e_mcp_visit_ttl_rule_shorter_than_appliance() {
    let app = TestApp::spawn().await;
    let appliance = app.config.mcp.session_ttl_clamped();
    assert_eq!(
        clamp_ttl_capped(None, Some(120), Some(appliance)),
        120,
        "access-rule max_session_duration shortens like SSH"
    );
}
