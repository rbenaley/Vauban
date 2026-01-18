/// VAUBAN Web - Web Page Tests.
///
/// Tests for HTML page endpoints (non-API).
/// Organized by functional area:
/// - account_pages_test: Profile, user sessions, API keys pages
/// - asset_pages_test: Asset detail, edit pages
/// - dashboard_pages_test: Dashboard, home page
/// - mfa_test: MFA setup and verification pages
/// - pages_test: Asset groups, vauban groups, users, forms, permissions
/// - session_pages_test: Proxy session pages (detail, recordings, active, filters)
/// - sidebar_menu_test: Navigation menu
pub mod account_pages_test;
pub mod asset_pages_test;
pub mod dashboard_pages_test;
pub mod mfa_test;
pub mod pages_test;
pub mod session_pages_test;
pub mod sidebar_menu_test;
