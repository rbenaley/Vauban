/// VAUBAN Web - Authentication service.
///
/// Handles password hashing, JWT tokens, and MFA (TOTP).
use anyhow::anyhow;
use argon2::{
    Algorithm as Argon2Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use shared::totp::{TOTP_DIGITS, TOTP_SKEW, TOTP_STEP};
use totp_rs::{Algorithm as TotpAlgorithm, Secret as TotpSecret, TOTP};
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, AppResult};

/// Detect whether an `mfa_secret` value is a vauban-vault ciphertext.
///
/// vauban-vault wraps secrets in a versioned envelope of the form
/// `"v{digit(s)}:{base64}"` (e.g. `"v1:Abc..."`). Plaintext secrets, on the
/// other hand, are raw base32 strings produced by [`AuthService::generate_totp_secret`].
///
/// Returning `true` here means the caller MUST decrypt the value via
/// [`crate::ipc::vault::VaultCryptoClient::mfa_verify`] before passing it to
/// any local TOTP routine -- pushing the ciphertext through
/// [`AuthService::verify_totp`] will silently always return `false` because
/// `"v1:..."` is not valid base32, and the operator will see
/// "Authenticator code is incorrect" no matter what they enter (issue #11
/// bugfix).
///
/// This helper deliberately lives in the service layer (not the handlers)
/// so the step-up flow and the login flow can share the exact same
/// classification.
pub fn is_encrypted_mfa_secret(value: &str) -> bool {
    if value.len() < 4 || !value.starts_with('v') {
        return false;
    }
    let Some(colon_pos) = value.find(':') else {
        return false;
    };
    if colon_pos < 2 {
        return false;
    }
    value[1..colon_pos].chars().all(|c| c.is_ascii_digit())
}

/// Equalize the wall-clock cost of a login failure that would otherwise
/// return WITHOUT running an Argon2 verification (unknown username with no
/// LDAP JIT path, client IP denied by the global ACL).
///
/// Runs a dummy verification of a wrong password against the sacrifice
/// hash minted at boot (`AppState::login_timing_sacrifice_hash`), through
/// the SAME path as a real login (auth IPC when supervised, local Argon2
/// otherwise). Without this, an attacker could time `POST /login` to
/// enumerate valid usernames or detect the presence of the IP ACL
/// (SEC-04/05 anti-enumeration).
pub async fn equalize_login_timing(state: &crate::AppState) {
    // Any constant is fine: the verification must FAIL, we only pay for
    // its duration. The sacrifice hash was minted from a random UUID at
    // boot so this can never accidentally match.
    const WRONG_PASSWORD: &str = "vauban-login-timing-equalizer";
    let sacrifice_hash = state.login_timing_sacrifice_hash.as_str();

    let outcome = if let Some(ref client) = state.auth_ipc_client {
        client.verify_password(WRONG_PASSWORD, sacrifice_hash).await
    } else {
        state
            .auth_service
            .verify_password(WRONG_PASSWORD, sacrifice_hash)
    };

    match outcome {
        Ok(false) => {}
        Ok(true) => {
            // Cannot happen (random boot-time password); log loudly if it does.
            tracing::error!("login timing equalizer unexpectedly verified the dummy password");
        }
        Err(e) => {
            tracing::warn!(error = %e, "login timing equalizer verification errored");
        }
    }
}

/// Outcome of a step-up TOTP verification with replay classification.
///
/// Returned by [`AuthService::verify_and_consume_totp`]. The
/// `Accepted { window }` variant carries the time-step that was just
/// consumed; the caller MUST persist it (typically on
/// `users.last_totp_used_window`) before performing the side-effecting
/// operation the step-up gates, so the same code cannot be replayed within
/// its 30-second window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpVerification {
    /// Code matches the current TOTP window AND has not been consumed yet.
    Accepted { window: i64 },
    /// Code matches the current TOTP window but a code from this window (or
    /// later) has already been consumed by the same user. Refused per
    /// RFC 6238 §5.2.
    Replayed,
    /// Code does not match the current window, the secret is malformed, or
    /// the format is invalid.
    Invalid,
}

/// JWT claims.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // User UUID
    pub username: String,
    pub exp: i64,
    pub iat: i64,
    pub mfa_verified: bool,
    #[serde(default)]
    pub is_superuser: bool,
    #[serde(default)]
    pub is_staff: bool,
    /// RFC 7519 `jti` -- Vauban stores `auth_sessions.uuid` here so the
    /// web session can rotate JWTs (cookie sliding) without losing the DB
    /// row: verification keys off `(jti, sub)` instead of only
    /// `token_hash`, which would break under concurrent requests after a
    /// rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

/// Authentication service.
#[derive(Clone)]
pub struct AuthService {
    config: Config,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl AuthService {
    /// Create a new authentication service.
    pub fn new(config: Config) -> AppResult<Self> {
        let secret = config.secret_key.expose_secret().as_bytes();
        let encoding_key = EncodingKey::from_secret(secret);
        let decoding_key = DecodingKey::from_secret(secret);

        Ok(Self {
            config,
            encoding_key,
            decoding_key,
        })
    }

    /// Get access token lifetime in minutes.
    pub fn access_token_lifetime_minutes(&self) -> u64 {
        self.config.jwt.access_token_lifetime_minutes
    }

    /// Hash password using Argon2id.
    pub fn hash_password(&self, password: &str) -> AppResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        let params = Params::new(
            self.config.security.argon2.memory_size_kb,
            self.config.security.argon2.iterations,
            self.config.security.argon2.parallelism,
            Some(32),
        )
        .map_err(|e| AppError::Internal(anyhow!("Argon2 params error: {}", e)))?;

        let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params);
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AppError::Internal(anyhow!("Password hashing failed: {}", e)))?;

        Ok(password_hash.to_string())
    }

    /// Verify password against hash.
    pub fn verify_password(&self, password: &str, hash: &str) -> AppResult<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| AppError::Internal(anyhow!("Invalid hash format: {}", e)))?;

        let params = Params::new(
            self.config.security.argon2.memory_size_kb,
            self.config.security.argon2.iterations,
            self.config.security.argon2.parallelism,
            Some(32),
        )
        .map_err(|e| AppError::Internal(anyhow!("Argon2 params error: {}", e)))?;

        let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params);
        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Generate JWT access token.
    ///
    /// `session_uuid` is the `auth_sessions.uuid` row backing this login.
    /// When `Some`, it is embedded as the standard JWT `jti` claim so
    /// [`crate::middleware::auth::auth_middleware`] can rotate the cookie
    /// without orphaning the DB session row. Pass `None` only for legacy /
    /// test call sites that still key verification solely off `token_hash`
    /// (back-compat until every flow embeds `jti`).
    pub fn generate_access_token(
        &self,
        user_uuid: &str,
        username: &str,
        mfa_verified: bool,
        is_superuser: bool,
        is_staff: bool,
        session_uuid: Option<Uuid>,
    ) -> AppResult<String> {
        let now = Utc::now();
        let exp = now + Duration::minutes(self.config.jwt.access_token_lifetime_minutes as i64);

        let claims = Claims {
            sub: user_uuid.to_string(),
            username: username.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            mfa_verified,
            is_superuser,
            is_staff,
            jti: session_uuid.map(|u| u.to_string()),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AppError::Auth(format!("Token generation failed: {}", e)))
    }

    /// Remaining lifetime of the access token (from `exp` claim) below which
    /// [`crate::middleware::auth`] will mint a fresh JWT for cookie-based
    /// web sessions. Uses max(60s, 25% of configured lifetime) so operators
    /// get a full new [`access_token_lifetime_minutes`] window without
    /// rewriting the cookie on literally every HTTP request.
    pub fn access_token_renew_if_expires_within_seconds(&self) -> i64 {
        let lifetime_secs = self.config.jwt.access_token_lifetime_minutes as i64 * 60;
        (lifetime_secs / 4).max(60)
    }

    /// Verify and decode JWT token.
    pub fn verify_token(&self, token: &str) -> AppResult<Claims> {
        let mut validation = Validation::default();
        validation.validate_exp = true;

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|e| AppError::Auth(format!("Token verification failed: {}", e)))?;

        Ok(token_data.claims)
    }

    /// Generate TOTP secret with provisioning URI for QR code.
    ///
    /// Returns (base32_secret, provisioning_uri).
    /// The provisioning_uri can be used to generate a QR code for authenticator apps.
    pub fn generate_totp_secret(username: &str, issuer: &str) -> AppResult<(String, String)> {
        let secret = TotpSecret::generate_secret();
        let secret_bytes = secret.to_bytes().map_err(|e| {
            AppError::Internal(anyhow::anyhow!("Failed to generate TOTP secret: {:?}", e))
        })?;

        let totp = TOTP::new(
            TotpAlgorithm::SHA1,
            TOTP_DIGITS,
            TOTP_SKEW,
            TOTP_STEP,
            secret_bytes,
            Some(issuer.to_string()),
            username.to_string(),
        )
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to create TOTP: {:?}", e)))?;

        let base32_secret = secret.to_encoded().to_string();
        let provisioning_uri = totp.get_url();

        Ok((base32_secret, provisioning_uri))
    }

    /// Generate QR code PNG for TOTP setup.
    ///
    /// Returns base64-encoded PNG image data. The TOTP provisioning URL
    /// is generated internally by `totp-rs` and not directly accessible
    /// for zeroization, but the returned base64 string should be zeroized
    /// by the caller after use (e.g., after template rendering).
    pub fn generate_totp_qr_code(secret: &str, username: &str, issuer: &str) -> AppResult<String> {
        let secret_obj = TotpSecret::Encoded(secret.to_string());
        let secret_bytes = secret_obj
            .to_bytes()
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Invalid TOTP secret: {:?}", e)))?;

        let totp = TOTP::new(
            TotpAlgorithm::SHA1,
            TOTP_DIGITS,
            TOTP_SKEW,
            TOTP_STEP,
            secret_bytes,
            Some(issuer.to_string()),
            username.to_string(),
        )
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to create TOTP: {:?}", e)))?;

        // Generate QR code as base64 PNG
        let qr_code = totp.get_qr_base64().map_err(|e| {
            AppError::Internal(anyhow::anyhow!("Failed to generate QR code: {:?}", e))
        })?;

        Ok(qr_code)
    }

    /// Verify TOTP code.
    ///
    /// Checks the code against the current 30-second window only (no tolerance).
    pub fn verify_totp(secret: &str, code: &str) -> bool {
        let secret_obj = TotpSecret::Encoded(secret.to_string());
        let secret_bytes = match secret_obj.to_bytes() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        let totp = match TOTP::new(
            TotpAlgorithm::SHA1,
            TOTP_DIGITS,
            TOTP_SKEW,
            TOTP_STEP,
            secret_bytes,
            None,          // issuer not needed for verification
            String::new(), // account_name not needed for verification
        ) {
            Ok(t) => t,
            Err(_) => return false,
        };

        totp.check_current(code).unwrap_or(false)
    }

    /// Verify a TOTP code AND classify it for replay protection.
    ///
    /// Used by the step-up authentication flow on sensitive operations
    /// (e.g. password rotation in [`crate::handlers::web::users`]).
    ///
    /// Because `TOTP_SKEW = 0` a code is valid for exactly one 30-second
    /// window; that window is `unix_seconds / TOTP_STEP`. We refuse any code
    /// whose window is `<=` the last window already consumed by this user
    /// (RFC 6238 §5.2: a single OTP MUST NOT be accepted twice).
    ///
    /// The caller is responsible for persisting the returned `window` on the
    /// operator's row before performing the side-effecting operation, so two
    /// concurrent step-up requests by the same operator within the same
    /// 30-second window cannot both succeed.
    pub fn verify_and_consume_totp(
        secret: &str,
        code: &str,
        last_used_window: Option<i64>,
    ) -> TotpVerification {
        if !Self::verify_totp(secret, code) {
            return TotpVerification::Invalid;
        }
        let now = chrono::Utc::now().timestamp();
        let window = now / (TOTP_STEP as i64);
        if let Some(last) = last_used_window
            && window <= last
        {
            return TotpVerification::Replayed;
        }
        TotpVerification::Accepted { window }
    }

    /// Get current TOTP code (for testing/debugging).
    #[allow(dead_code)]
    pub fn get_current_totp(secret: &str) -> Option<String> {
        let secret_obj = TotpSecret::Encoded(secret.to_string());
        let secret_bytes = secret_obj.to_bytes().ok()?;

        let totp = TOTP::new(
            TotpAlgorithm::SHA1,
            TOTP_DIGITS,
            TOTP_SKEW,
            TOTP_STEP,
            secret_bytes,
            None,
            String::new(),
        )
        .ok()?;

        totp.generate_current().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Get the path to the workspace root config/ directory.
    fn config_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("Failed to get workspace root")
            .join("config")
    }

    /// Helper to load test config from TOML files.
    fn load_test_config() -> Config {
        // SAFETY: Test config must exist for tests to run
        #[allow(clippy::expect_used)]
        Config::load_with_environment(config_dir(), crate::config::Environment::Testing)
            .expect("Failed to load test config from workspace config/testing.toml")
    }

    // ==================== Password Hashing Tests ====================

    #[test]
    fn test_hash_password_generates_hash() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        let password = "TestPassword123!";
        let hash = unwrap_ok!(auth_service.hash_password(password));

        // Hash should not be empty
        assert!(!hash.is_empty());
        // Hash should start with argon2 identifier
        assert!(hash.starts_with("$argon2"));
        // Hash should not equal the password
        assert_ne!(hash, password);
    }

    #[test]
    fn test_hash_password_generates_different_hashes() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        let password = "TestPassword123!";
        let hash1 = unwrap_ok!(auth_service.hash_password(password));
        let hash2 = unwrap_ok!(auth_service.hash_password(password));

        // Different salts should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_verify_password_valid() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        let password = "TestPassword123!";
        let hash = unwrap_ok!(auth_service.hash_password(password));

        let is_valid = unwrap_ok!(auth_service.verify_password(password, &hash));
        assert!(is_valid);
    }

    #[test]
    fn test_verify_password_invalid() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        let password = "TestPassword123!";
        let wrong_password = "WrongPassword456!";
        let hash = unwrap_ok!(auth_service.hash_password(password));

        let is_valid = unwrap_ok!(auth_service.verify_password(wrong_password, &hash));
        assert!(!is_valid);
    }

    #[test]
    fn test_verify_password_malformed_hash() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        let result = auth_service.verify_password("password", "not-a-valid-hash");
        assert!(result.is_err());
    }

    // ==================== JWT Token Tests ====================

    #[test]
    fn test_generate_access_token_success() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        let token = unwrap_ok!(auth_service.generate_access_token(
            "550e8400-e29b-41d4-a716-446655440000",
            "testuser",
            true,
            false,
            false,
            None,
        ));

        // Token should not be empty
        assert!(!token.is_empty());
        // Token should have 3 parts (header.payload.signature)
        assert_eq!(token.split('.').count(), 3);
    }

    #[test]
    fn test_verify_token_valid() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        let user_uuid = "550e8400-e29b-41d4-a716-446655440000";
        let username = "testuser";

        let token = unwrap_ok!(
            auth_service.generate_access_token(user_uuid, username, true, true, true, None)
        );

        let claims = unwrap_ok!(auth_service.verify_token(&token));

        assert_eq!(claims.sub, user_uuid);
        assert_eq!(claims.username, username);
        assert!(claims.mfa_verified);
        assert!(claims.is_superuser);
        assert!(claims.is_staff);
    }

    #[test]
    fn test_verify_token_invalid() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        let result = auth_service.verify_token("invalid.token.here");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_token_wrong_secret() {
        let config1 = load_test_config();
        let auth_service1 = unwrap_ok!(AuthService::new(config1));

        let token = unwrap_ok!(auth_service1.generate_access_token(
            "550e8400-e29b-41d4-a716-446655440000",
            "testuser",
            true,
            false,
            false,
            None,
        ));

        // Create another service with a different secret
        let mut config2 = load_test_config();
        config2.secret_key = "different-secret-key-for-testing!".to_string().into();
        let auth_service2 = unwrap_ok!(AuthService::new(config2));

        let result = auth_service2.verify_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_claims_correctness() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        let token = unwrap_ok!(auth_service.generate_access_token(
            "test-uuid",
            "testuser",
            false, // mfa_verified
            true,  // is_superuser
            false, // is_staff
            None,
        ));

        let claims = unwrap_ok!(auth_service.verify_token(&token));

        assert_eq!(claims.sub, "test-uuid");
        assert_eq!(claims.username, "testuser");
        assert!(!claims.mfa_verified);
        assert!(claims.is_superuser);
        assert!(!claims.is_staff);
        assert!(claims.exp > claims.iat);
    }

    // ==================== TOTP Tests ====================

    #[test]
    fn test_generate_totp_secret_success() {
        let (secret, uri) = unwrap_ok!(AuthService::generate_totp_secret("testuser", "VAUBAN"));

        // Secret should not be empty
        assert!(!secret.is_empty());
        // URI should contain expected parts
        assert!(uri.contains("otpauth://totp/"));
        assert!(uri.contains("testuser"));
        assert!(uri.contains("VAUBAN"));
    }

    #[test]
    fn test_generate_totp_secret_different_users() {
        let (secret1, _) = unwrap_ok!(AuthService::generate_totp_secret("user1", "VAUBAN"));
        let (secret2, _) = unwrap_ok!(AuthService::generate_totp_secret("user2", "VAUBAN"));

        // Different users should get different secrets
        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_verify_totp_valid_code() {
        let (secret, _) = unwrap_ok!(AuthService::generate_totp_secret("testuser", "VAUBAN"));

        // Get the current valid code
        let current_code = unwrap_some!(AuthService::get_current_totp(&secret));

        // Verify the current code
        let is_valid = AuthService::verify_totp(&secret, &current_code);
        assert!(is_valid);
    }

    #[test]
    fn test_verify_totp_invalid_code() {
        let (secret, _) = unwrap_ok!(AuthService::generate_totp_secret("testuser", "VAUBAN"));

        // Try an obviously wrong code (might occasionally pass if 000000 is the actual code)
        let _is_valid = AuthService::verify_totp(&secret, "000000");

        // Try a malformed code - should always fail
        let is_valid_malformed = AuthService::verify_totp(&secret, "abcdef");
        assert!(!is_valid_malformed);
    }

    #[test]
    fn test_verify_totp_invalid_secret() {
        let is_valid = AuthService::verify_totp("not-a-valid-base32-secret!", "123456");
        assert!(!is_valid);
    }

    #[test]
    fn test_get_current_totp_returns_6_digits() {
        let (secret, _) = unwrap_ok!(AuthService::generate_totp_secret("testuser", "VAUBAN"));
        let code = unwrap_some!(AuthService::get_current_totp(&secret));

        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_totp_qr_code_success() {
        let (secret, _) = unwrap_ok!(AuthService::generate_totp_secret("testuser", "VAUBAN"));
        let qr_code = unwrap_ok!(AuthService::generate_totp_qr_code(
            &secret, "testuser", "VAUBAN"
        ));

        // QR code should be base64 encoded PNG
        assert!(!qr_code.is_empty());
    }

    // ==================== AuthService Creation Tests ====================

    #[test]
    fn test_auth_service_new_success() {
        let config = load_test_config();
        let result = AuthService::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_auth_service_clone() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));
        let cloned = auth_service.clone();

        // Both should work identically
        let token = unwrap_ok!(
            auth_service.generate_access_token("user-1", "test", false, false, false, None)
        );
        let claims = unwrap_ok!(cloned.verify_token(&token));
        assert_eq!(claims.sub, "user-1");
    }

    #[test]
    fn test_auth_service_access_token_lifetime() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config.clone()));

        let lifetime = auth_service.access_token_lifetime_minutes();
        assert_eq!(lifetime, config.jwt.access_token_lifetime_minutes);
    }

    // ==================== Claims Tests ====================

    #[test]
    fn test_claims_serialize_deserialize() {
        let claims = Claims {
            sub: "user-uuid".to_string(),
            username: "testuser".to_string(),
            exp: 1700000000,
            iat: 1699999000,
            mfa_verified: true,
            is_superuser: false,
            is_staff: true,
            jti: None,
        };

        let json = unwrap_ok!(serde_json::to_string(&claims));
        let parsed: Claims = unwrap_ok!(serde_json::from_str(&json));

        assert_eq!(parsed.sub, claims.sub);
        assert_eq!(parsed.username, claims.username);
        assert_eq!(parsed.exp, claims.exp);
        assert_eq!(parsed.iat, claims.iat);
        assert_eq!(parsed.mfa_verified, claims.mfa_verified);
        assert_eq!(parsed.is_superuser, claims.is_superuser);
        assert_eq!(parsed.is_staff, claims.is_staff);
        assert_eq!(parsed.jti, claims.jti);
    }

    #[test]
    fn test_claims_debug() {
        let claims = Claims {
            sub: "test-sub".to_string(),
            username: "debug-user".to_string(),
            exp: 0,
            iat: 0,
            mfa_verified: false,
            is_superuser: false,
            is_staff: false,
            jti: None,
        };

        let debug_str = format!("{:?}", claims);
        assert!(debug_str.contains("Claims"));
        assert!(debug_str.contains("test-sub"));
        assert!(debug_str.contains("debug-user"));
    }

    #[test]
    fn test_claims_default_fields() {
        // Test that is_superuser and is_staff default to false when missing
        let json = r#"{"sub":"user","username":"test","exp":0,"iat":0,"mfa_verified":false}"#;
        let claims: Claims = unwrap_ok!(serde_json::from_str(json));

        assert!(!claims.is_superuser);
        assert!(!claims.is_staff);
    }

    #[test]
    fn test_claims_all_fields_present() {
        let json = r#"{"sub":"u","username":"n","exp":1,"iat":2,"mfa_verified":true,"is_superuser":true,"is_staff":true}"#;
        let claims: Claims = unwrap_ok!(serde_json::from_str(json));

        assert!(claims.is_superuser);
        assert!(claims.is_staff);
        assert!(claims.mfa_verified);
    }

    // ==================== Password Edge Cases ====================

    #[test]
    fn test_hash_password_empty() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        // Empty password should still hash
        let hash = unwrap_ok!(auth_service.hash_password(""));
        assert!(hash.starts_with("$argon2"));
    }

    #[test]
    fn test_hash_password_unicode() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        let password = "密码测试🔐";
        let hash = unwrap_ok!(auth_service.hash_password(password));

        assert!(unwrap_ok!(auth_service.verify_password(password, &hash)));
    }

    #[test]
    fn test_hash_password_very_long() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        let password = "a".repeat(1000);
        let hash = unwrap_ok!(auth_service.hash_password(&password));

        assert!(unwrap_ok!(auth_service.verify_password(&password, &hash)));
    }

    #[test]
    fn test_verify_password_empty_password() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        let hash = unwrap_ok!(auth_service.hash_password("actual_password"));
        let result = unwrap_ok!(auth_service.verify_password("", &hash));

        assert!(!result);
    }

    #[test]
    fn test_verify_password_empty_hash() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        let result = auth_service.verify_password("password", "");
        assert!(result.is_err());
    }

    // ==================== Token Edge Cases ====================

    #[test]
    fn test_generate_token_empty_username() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        let token =
            unwrap_ok!(auth_service.generate_access_token("uuid", "", false, false, false, None));
        let claims = unwrap_ok!(auth_service.verify_token(&token));

        assert_eq!(claims.username, "");
    }

    #[test]
    fn test_generate_token_unicode_username() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        let username = "用户名";
        let token = unwrap_ok!(
            auth_service.generate_access_token("uuid", username, false, false, false, None)
        );
        let claims = unwrap_ok!(auth_service.verify_token(&token));

        assert_eq!(claims.username, username);
    }

    #[test]
    fn test_verify_token_empty() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        let result = auth_service.verify_token("");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_token_malformed() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        // Various malformed tokens
        let malformed_tokens = [
            "not.a.token",
            "onlyonepart",
            "two.parts",
            "four.parts.are.invalid",
            "eyJ.eyJ.sig", // Base64 but invalid JSON
        ];

        for token in malformed_tokens {
            let result = auth_service.verify_token(token);
            assert!(result.is_err(), "Expected error for token: {}", token);
        }
    }

    #[test]
    fn test_token_expiration_is_in_future() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        let token = unwrap_ok!(
            auth_service.generate_access_token("uuid", "user", false, false, false, None)
        );
        let claims = unwrap_ok!(auth_service.verify_token(&token));

        let now = Utc::now().timestamp();
        assert!(claims.exp > now);
        assert!(claims.iat <= now);
    }

    #[test]
    fn test_token_all_permission_combinations() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        let combinations = [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (true, true, false),
            (true, false, true),
            (false, true, true),
            (true, true, true),
        ];

        for (mfa, superuser, staff) in combinations {
            let token = unwrap_ok!(
                auth_service.generate_access_token("uuid", "user", mfa, superuser, staff, None)
            );
            let claims = unwrap_ok!(auth_service.verify_token(&token));

            assert_eq!(claims.mfa_verified, mfa);
            assert_eq!(claims.is_superuser, superuser);
            assert_eq!(claims.is_staff, staff);
        }
    }

    // ==================== TOTP Edge Cases ====================

    #[test]
    fn test_generate_totp_secret_special_chars_username() {
        let (secret, uri) = unwrap_ok!(AuthService::generate_totp_secret(
            "user@example.com",
            "VAUBAN Test"
        ));

        assert!(!secret.is_empty());
        assert!(uri.contains("otpauth://"));
    }

    #[test]
    fn test_generate_totp_secret_unicode_issuer() {
        let (secret, uri) = unwrap_ok!(AuthService::generate_totp_secret("user", "测试发行者"));

        assert!(!secret.is_empty());
        assert!(!uri.is_empty());
    }

    #[test]
    fn test_verify_totp_empty_code() {
        let (secret, _) = unwrap_ok!(AuthService::generate_totp_secret("user", "issuer"));

        let result = AuthService::verify_totp(&secret, "");
        assert!(!result);
    }

    #[test]
    fn test_verify_totp_empty_secret() {
        let result = AuthService::verify_totp("", "123456");
        assert!(!result);
    }

    #[test]
    fn test_verify_totp_wrong_length_code() {
        let (secret, _) = unwrap_ok!(AuthService::generate_totp_secret("user", "issuer"));

        // Too short
        assert!(!AuthService::verify_totp(&secret, "12345"));
        // Too long
        assert!(!AuthService::verify_totp(&secret, "1234567"));
    }

    #[test]
    fn test_get_current_totp_invalid_secret() {
        let result = AuthService::get_current_totp("invalid-base32!");
        assert!(result.is_none());
    }

    #[test]
    fn test_get_current_totp_empty_secret() {
        let result = AuthService::get_current_totp("");
        assert!(result.is_none());
    }

    #[test]
    fn test_generate_totp_qr_code_invalid_secret() {
        let result = AuthService::generate_totp_qr_code("invalid!", "user", "issuer");
        assert!(result.is_err());
    }

    #[test]
    fn test_totp_provisioning_uri_format() {
        let (_, uri) = unwrap_ok!(AuthService::generate_totp_secret("alice", "MyApp"));

        // Should follow otpauth format
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("secret="));
        assert!(uri.contains("issuer="));
    }

    // ==================== is_encrypted_mfa_secret ====================
    //
    // This classification is what tells the step-up flow whether a secret
    // must go through the vault or can be verified locally. A regression
    // here would silently break password rotations in production (issue
    // #11 bugfix), so we pin the behavior on every interesting shape.

    #[test]
    fn test_is_encrypted_mfa_secret_recognises_v1_envelope() {
        assert!(is_encrypted_mfa_secret(
            "v1:bWZhLWNpcGhlcnRleHQtZ29lcy1oZXJl"
        ));
    }

    #[test]
    fn test_is_encrypted_mfa_secret_recognises_multidigit_versions() {
        assert!(is_encrypted_mfa_secret("v2:abc"));
        assert!(is_encrypted_mfa_secret("v42:abc"));
        assert!(is_encrypted_mfa_secret("v999:abc"));
    }

    #[test]
    fn test_is_encrypted_mfa_secret_rejects_plaintext_base32() {
        let (secret, _) = unwrap_ok!(AuthService::generate_totp_secret("plaintext", "VAUBAN"));
        assert!(
            !is_encrypted_mfa_secret(&secret),
            "freshly generated base32 secret must NOT look like a vault envelope (regression: \
             would route plaintext secrets through the vault and fail closed)"
        );
    }

    #[test]
    fn test_is_encrypted_mfa_secret_rejects_lookalikes() {
        // Cases that vaguely look like the envelope but are NOT.
        assert!(!is_encrypted_mfa_secret(""), "empty");
        assert!(!is_encrypted_mfa_secret("v"), "too short");
        assert!(!is_encrypted_mfa_secret("v1"), "no colon");
        assert!(!is_encrypted_mfa_secret("v:abc"), "missing version digits");
        assert!(
            !is_encrypted_mfa_secret("vN1:abc"),
            "non-digit version number"
        );
        assert!(
            !is_encrypted_mfa_secret("V1:abc"),
            "uppercase V is not the contract"
        );
        assert!(
            !is_encrypted_mfa_secret("v1abc"),
            "no colon means not an envelope"
        );
    }

    // ==================== SEC-06 Regression Tests ====================

    /// SEC-06 regression: verify_totp must reject a code generated for a
    /// past time window. Uses the TOTP library directly to generate an
    /// expired code and verifies the service rejects it.
    #[test]
    fn test_sec06_verify_totp_rejects_expired_code() {
        let (secret, _) = unwrap_ok!(AuthService::generate_totp_secret("sec06", "VAUBAN"));

        let secret_obj = TotpSecret::Encoded(secret.clone());
        let totp = TOTP::new(
            TotpAlgorithm::SHA1,
            TOTP_DIGITS,
            TOTP_SKEW,
            TOTP_STEP,
            secret_obj.to_bytes().unwrap(),
            None,
            String::new(),
        )
        .unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expired_code = totp.generate(now - 2 * TOTP_STEP);
        let current_code = totp.generate(now);

        // Guard: skip only if codes collide by chance (1 in 1,000,000)
        if expired_code != current_code {
            assert!(
                !AuthService::verify_totp(&secret, &expired_code),
                "SEC-06: verify_totp must reject a code from a past window"
            );
        }
    }

    /// SEC-06 regression: deterministic proof that our TOTP configuration
    /// rejects codes from adjacent windows. No system clock dependency.
    #[test]
    fn test_sec06_totp_config_rejects_adjacent_windows() {
        let secret = TotpSecret::generate_secret();
        let totp = TOTP::new(
            TotpAlgorithm::SHA1,
            TOTP_DIGITS,
            TOTP_SKEW,
            TOTP_STEP,
            secret.to_bytes().unwrap(),
            None,
            String::new(),
        )
        .unwrap();

        let reference_time = 1_700_000_015u64;
        let code = totp.generate(reference_time);

        assert!(
            totp.check(&code, reference_time),
            "Code must be valid at generation time"
        );
        assert!(
            !totp.check(&code, reference_time - TOTP_STEP),
            "SEC-06: code must be rejected in the previous window"
        );
        assert!(
            !totp.check(&code, reference_time + TOTP_STEP),
            "SEC-06: code must be rejected in the next window"
        );
    }

    // ==================== Config Variations ====================

    #[test]
    fn test_auth_service_with_different_token_lifetime() {
        let mut config = load_test_config();
        config.jwt.access_token_lifetime_minutes = 60;

        let auth_service = unwrap_ok!(AuthService::new(config));
        assert_eq!(auth_service.access_token_lifetime_minutes(), 60);
    }
}
