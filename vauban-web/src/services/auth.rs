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
use totp_rs::{Algorithm as TotpAlgorithm, Secret as TotpSecret, TOTP};

use crate::config::Config;
use crate::error::{AppError, AppResult};

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
    pub fn generate_access_token(
        &self,
        user_uuid: &str,
        username: &str,
        mfa_verified: bool,
        is_superuser: bool,
        is_staff: bool,
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
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AppError::Auth(format!("Token generation failed: {}", e)))
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
            6,  // 6 digits
            1,  // 1 step tolerance (±30 seconds)
            30, // 30 second step
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
    /// Returns base64-encoded PNG image data.
    #[allow(dead_code)]
    pub fn generate_totp_qr_code(secret: &str, username: &str, issuer: &str) -> AppResult<String> {
        let secret_obj = TotpSecret::Encoded(secret.to_string());
        let secret_bytes = secret_obj
            .to_bytes()
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Invalid TOTP secret: {:?}", e)))?;

        let totp = TOTP::new(
            TotpAlgorithm::SHA1,
            6,
            1,
            30,
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
    /// Checks the code against current time with ±1 step tolerance (±30 seconds).
    pub fn verify_totp(secret: &str, code: &str) -> bool {
        let secret_obj = TotpSecret::Encoded(secret.to_string());
        let secret_bytes = match secret_obj.to_bytes() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        let totp = match TOTP::new(
            TotpAlgorithm::SHA1,
            6,
            1, // 1 step tolerance
            30,
            secret_bytes,
            None,          // issuer not needed for verification
            String::new(), // account_name not needed for verification
        ) {
            Ok(t) => t,
            Err(_) => return false,
        };

        totp.check_current(code).unwrap_or(false)
    }

    /// Get current TOTP code (for testing/debugging).
    #[allow(dead_code)]
    pub fn get_current_totp(secret: &str) -> Option<String> {
        let secret_obj = TotpSecret::Encoded(secret.to_string());
        let secret_bytes = secret_obj.to_bytes().ok()?;

        let totp = TOTP::new(
            TotpAlgorithm::SHA1,
            6,
            1,
            30,
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

        let token =
            unwrap_ok!(auth_service.generate_access_token(user_uuid, username, true, true, true));

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
        let token =
            unwrap_ok!(auth_service.generate_access_token("user-1", "test", false, false, false));
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

        let token = unwrap_ok!(auth_service.generate_access_token("uuid", "", false, false, false));
        let claims = unwrap_ok!(auth_service.verify_token(&token));

        assert_eq!(claims.username, "");
    }

    #[test]
    fn test_generate_token_unicode_username() {
        let config = load_test_config();
        let auth_service = unwrap_ok!(AuthService::new(config));

        let username = "用户名";
        let token =
            unwrap_ok!(auth_service.generate_access_token("uuid", username, false, false, false));
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

        let token =
            unwrap_ok!(auth_service.generate_access_token("uuid", "user", false, false, false));
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
                auth_service.generate_access_token("uuid", "user", mfa, superuser, staff)
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

    // ==================== Config Variations ====================

    #[test]
    fn test_auth_service_with_different_token_lifetime() {
        let mut config = load_test_config();
        config.jwt.access_token_lifetime_minutes = 60;

        let auth_service = unwrap_ok!(AuthService::new(config));
        assert_eq!(auth_service.access_token_lifetime_minutes(), 60);
    }
}
