mod auth;
mod mcp;
mod stack;

use crate::scenario;
use crate::support::ScenarioFn;

/// Every scenario, in run order.
pub fn all() -> Vec<(&'static str, ScenarioFn)> {
    vec![
        scenario!(stack::boot_is_clean),
        scenario!(auth::login_page_renders),
        scenario!(auth::wrong_password_stays_on_login),
        scenario!(auth::every_seeded_account_enrols_mfa_and_logs_in),
        scenario!(auth::second_login_asks_for_the_totp_code),
        scenario!(auth::wrong_totp_code_is_rejected),
        scenario!(auth::logout_returns_to_login),
        scenario!(mcp::plain_user_is_denied_the_mcp_zone),
        scenario!(mcp::admin_onboards_an_mcp_server_behind_a_pinned_certificate),
        scenario!(mcp::admin_writes_mcp_tool_modes),
        scenario!(mcp::agent_visit_sees_and_reaches_only_its_tools),
        scenario!(mcp::staff_decides_hitl_calls_from_the_browser),
        scenario!(mcp::mission_seal_runs_the_contract_and_drift_suspends_the_group),
        scenario!(mcp::upheld_contestation_keeps_the_subject_out),
        scenario!(mcp::changed_tool_definition_is_quarantined_until_approved),
        scenario!(mcp::user_connects_from_assets_through_the_justification_modal),
        scenario!(mcp::shim_reaches_the_asset_through_the_pinned_tunnel),
        scenario!(mcp::iam_levers_cut_live_visits),
        scenario!(mcp::every_cutting_event_cuts_live_visits),
        scenario!(mcp::deleted_asset_leaves_no_tool_modes_behind),
        scenario!(mcp::recordings_keep_every_call_and_never_a_secret),
    ]
}
