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
pub mod apikey_create_form_pins_test;
pub mod asset_irreversible_delete_test;
pub mod asset_modal_dataflow_test;
pub mod asset_pages_test;
pub mod asset_protocol_test;
pub mod asset_user_admin_lifecycle_e2e_test;
pub mod asset_user_zone_no_leak_test;
pub mod asset_user_zone_render_snapshot_test;
pub mod assets_db_invariants_test;
pub mod assets_name_uniqueness_e2e_test;
pub mod audit_authors_render_test;
pub mod audit_instrumentation_test;
pub mod auth_expiry_redirect_test;
pub mod bac_gate_matrix_test;
pub mod bac_source_invariants_test;
pub mod bastion_watch_iacs_count_test;
pub mod bastion_watch_test;
pub mod boot_smoke_test;
pub mod casbin_handler_eradication_web_test;
pub mod cdn_assets_lints_test;
pub mod dashboard_access_posture_test;
pub mod dashboard_isolation_test;
pub mod dashboard_pages_test;
pub mod delete_confirm_flow_test;
pub mod group_member_search_test;
pub mod heartbeat_frontend_test;
pub mod heartbeat_session_keepalive_test;
pub mod htmx_input_name_test;
pub mod htmx_live_filter_test;
pub mod iacs_active_sessions_integration_test;
pub mod iacs_active_sessions_pin_test;
pub mod iacs_admin_ux_test;
pub mod iacs_asset_create_test;
pub mod iacs_assets_surface_e2e_test;
pub mod iacs_connect_button_test;
pub mod iacs_drift_test;
pub mod iacs_kill_switch_test;
pub mod iacs_local_forward_port_test;
pub mod iacs_my_requests_render_test;
pub mod iacs_per_asset_target_pin_test;
pub mod iacs_revocation_watchdog_test;
pub mod iacs_session_list_row_test;
pub mod iacs_sessions_kill_switch_test;
pub mod iacs_sessions_surface_e2e_test;
pub mod iacs_test;
pub mod iacs_tunnel_handler_test;
pub mod iacs_tunnel_hardening_test;
pub mod iacs_tunnel_status_ux_test;
pub mod input_format_e2e_test;
pub mod input_format_pin_test;
pub mod input_format_proptest;
pub mod inspect_capture_pipeline_e2e_test;
pub mod inspect_capture_template_test;
pub mod inspect_capture_test;
pub mod ip_acl_e2e_test;
pub mod ip_acl_pins_test;
pub mod jit_access_test;
pub mod jit_grant_revocation_e2e_test;
pub mod jit_revocation_pins_test;
pub mod jwt_cookie_renewal_test;
pub mod login_post_expiry_test;
pub mod manage_assets_anti_enumeration_test;
pub mod manage_assets_gate_matrix_test;
pub mod manage_assets_invariants_test;
pub mod manage_assets_render_snapshot_test;
pub mod mfa_setup_vau008_test;
pub mod mfa_test;
pub mod pages_test;
pub mod profile_password_test;
pub mod rdp_cert_lints_test;
pub mod rdp_cert_no_silent_green_test;
pub mod rdp_cert_pin_e2e_test;
pub mod rdp_input_release_e2e_test;
pub mod rdp_kerberos_mode_test;
pub mod recording_daily_cron_e2e_test;
pub mod recording_detail_test;
pub mod recording_durability_pin_test;
pub mod recording_iacs_download_e2e_test;
pub mod recording_integrity_migration_test;
pub mod recording_retention_e2e_test;
pub mod redis_removal_lints_test;
pub mod responsive_templates_test;
pub mod role_invariants_test;
pub mod routing_test;
pub mod self_hosted_assets_e2e_test;
pub mod session_creation_limits_invariants_test;
pub mod session_creation_limits_test;
pub mod session_expired_presentation_test;
pub mod session_history_presentation_proptest;
pub mod session_identity_pair_e2e_test;
pub mod session_pages_test;
pub mod sidebar_assets_split_test;
pub mod sidebar_menu_test;
pub mod sidebar_user_zone_test;
pub mod ssh_host_key_e2e_test;
pub mod ssh_host_key_mismatch_invariant_test;
pub mod ssh_host_key_no_silent_green_test;
pub mod ssh_key_auth_adversarial_test;
pub mod ssh_key_auth_test;
pub mod terminate_session_test;
pub mod timezone_e2e_test;
pub mod timezone_lints_test;
pub mod timezone_snippet_test;
pub mod user_edit_test;
pub mod users_email_shared_e2e_test;
pub mod vault_secrets_crud_web_test;
pub mod vault_secrets_pins_test;
pub mod virtual_asset_group_adversarial_test;
pub mod virtual_asset_group_boot_docs_test;
pub mod virtual_asset_group_db_test;
pub mod virtual_asset_group_perf_pins_test;
pub mod virtual_asset_group_policy_test;
pub mod virtual_asset_group_ui_test;
pub mod websocket_logging_test;
pub mod ws_activity_keepalive_test;
pub mod ws_auth_revalidation_test;
