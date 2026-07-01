/// VAUBAN Web - Security Tests.
///
/// Security-related tests organized by functionality:
/// - auth_test: Authentication, JWT, MFA tests
/// - security_test: SQL injection, XSS, CSRF, rate limiting tests
pub mod access_rule_recheck_test;
pub mod api_key_invariants_test;
pub mod auth_test;
pub mod ldap_login_test;
pub mod mfa_setup_invariants_test;
pub mod privilege_revocation_test;
pub mod security_test;
pub mod session_idor_test;
pub mod username_case_insensitive_test;
