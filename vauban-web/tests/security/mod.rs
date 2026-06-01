/// VAUBAN Web - Security Tests.
///
/// Security-related tests organized by functionality:
/// - auth_test: Authentication, JWT, MFA tests
/// - security_test: SQL injection, XSS, CSRF, rate limiting tests
pub mod access_rule_recheck_test;
pub mod auth_test;
pub mod ldap_login_test;
pub mod security_test;
pub mod session_idor_test;
