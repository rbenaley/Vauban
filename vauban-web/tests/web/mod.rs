/// VAUBAN Web - Web Page Tests.
///
/// Tests for HTML page endpoints (non-API).
/// Organized by functional area:
/// - access_control_web_test: Access rule enforcement on SSH/RDP/detail/list
/// - access_rules_crud_web_test: CRUD operations for access rules
/// - account_pages_test: Profile, user sessions, API keys pages
/// - asset_pages_test: Asset detail, edit pages
/// - dashboard_pages_test: Dashboard, home page
/// - mfa_test: MFA setup and verification pages
/// - pages_test: Asset groups, vauban groups, users, forms, permissions
/// - session_pages_test: Proxy session pages (detail, recordings, active, filters)
/// - sidebar_menu_test: Navigation menu
pub mod access_control_web_test;
pub mod access_rules_crud_web_test;
pub mod account_pages_test;
pub mod asset_irreversible_delete_test;
pub mod asset_pages_test;
pub mod asset_protocol_test;
pub mod asset_user_admin_lifecycle_e2e_test;
pub mod asset_user_zone_render_snapshot_test;
pub mod assets_db_invariants_test;
pub mod audit_authors_render_test;
pub mod boot_smoke_test;
pub mod casbin_handler_eradication_web_test;
pub mod dashboard_pages_test;
pub mod delete_confirm_flow_test;
pub mod group_member_search_test;
pub mod htmx_input_name_test;
pub mod htmx_live_filter_test;
pub mod jit_access_test;
pub mod manage_assets_anti_enumeration_test;
pub mod manage_assets_gate_matrix_test;
pub mod manage_assets_invariants_test;
pub mod manage_assets_render_snapshot_test;
pub mod mfa_test;
pub mod pages_test;
pub mod profile_password_test;
pub mod recording_detail_test;
pub mod recording_integrity_migration_test;
pub mod responsive_templates_test;
pub mod role_invariants_test;
pub mod routing_test;
pub mod session_pages_test;
pub mod sidebar_assets_split_test;
pub mod sidebar_menu_test;
pub mod sidebar_user_zone_test;
pub mod ssh_host_key_mismatch_invariant_test;
pub mod terminate_session_test;
pub mod user_edit_test;
pub mod websocket_logging_test;
pub mod virtual_asset_group_adversarial_test;
pub mod virtual_asset_group_boot_docs_test;
pub mod virtual_asset_group_db_test;
pub mod virtual_asset_group_perf_pins_test;
pub mod virtual_asset_group_policy_test;
pub mod virtual_asset_group_ui_test;
