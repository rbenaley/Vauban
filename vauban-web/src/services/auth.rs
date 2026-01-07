/// VAUBAN Web - Authentication service.
///
/// Handles password hashing, JWT tokens, and MFA (TOTP).
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

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
        let secret = config.secret_key.as_bytes();
        let encoding_key = EncodingKey::from_secret(secret);
        let decoding_key = DecodingKey::from_secret(secret);

        Ok(Self {
            config,
            encoding_key,
            decoding_key,
        })
    }

    /// Hash password using Argon2id.
    pub fn hash_password(&self, password: &str) -> AppResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Password hashing failed: {}", e)))?;

        Ok(password_hash.to_string())
    }

    /// Verify password against hash.
    pub fn verify_password(&self, password: &str, hash: &str) -> AppResult<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Invalid hash format: {}", e)))?;

        let argon2 = Argon2::default();
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
        let secret = Secret::generate_secret();
        let secret_bytes = secret.to_bytes().map_err(|e| {
            AppError::Internal(anyhow::anyhow!("Failed to generate TOTP secret: {:?}", e))
        })?;

        let totp = TOTP::new(
            Algorithm::SHA1,
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
        let secret_obj = Secret::Encoded(secret.to_string());
        let secret_bytes = secret_obj
            .to_bytes()
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Invalid TOTP secret: {:?}", e)))?;

        let totp = TOTP::new(
            Algorithm::SHA1,
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
        let secret_obj = Secret::Encoded(secret.to_string());
        let secret_bytes = match secret_obj.to_bytes() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        let totp = match TOTP::new(
            Algorithm::SHA1,
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
        let secret_obj = Secret::Encoded(secret.to_string());
        let secret_bytes = secret_obj.to_bytes().ok()?;

        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes, None, String::new()).ok()?;

        Some(totp.generate_current().ok()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to load test config from TOML files.
    fn load_test_config() -> Config {
        Config::load_with_environment("config", crate::config::Environment::Testing)
            .expect("Failed to load test config from config/testing.toml")
    }

    // ==================== Password Hashing Tests ====================

    #[test]
    fn test_hash_password_generates_hash() {
        let config = load_test_config();
        let auth_service = AuthService::new(config).unwrap();

        let password = "TestPassword123!";
        let hash = auth_service.hash_password(password).unwrap();

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
        let auth_service = AuthService::new(config).unwrap();

        let password = "TestPassword123!";
        let hash1 = auth_service.hash_password(password).unwrap();
        let hash2 = auth_service.hash_password(password).unwrap();

        // Different salts should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_verify_password_valid() {
        let config = load_test_config();
        let auth_service = AuthService::new(config).unwrap();

        let password = "TestPassword123!";
        let hash = auth_service.hash_password(password).unwrap();

        let is_valid = auth_service.verify_password(password, &hash).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_verify_password_invalid() {
        let config = load_test_config();
        let auth_service = AuthService::new(config).unwrap();

        let password = "TestPassword123!";
        let wrong_password = "WrongPassword456!";
        let hash = auth_service.hash_password(password).unwrap();

        let is_valid = auth_service.verify_password(wrong_password, &hash).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_verify_password_malformed_hash() {
        let config = load_test_config();
        let auth_service = AuthService::new(config).unwrap();

        let result = auth_service.verify_password("password", "not-a-valid-hash");
        assert!(result.is_err());
    }

    // ==================== JWT Token Tests ====================

    #[test]
    fn test_generate_access_token_success() {
        let config = load_test_config();
        let auth_service = AuthService::new(config).unwrap();

        let token = auth_service
            .generate_access_token(
                "550e8400-e29b-41d4-a716-446655440000",
                "testuser",
                true,
                false,
                false,
            )
            .unwrap();

        // Token should not be empty
        assert!(!token.is_empty());
        // Token should have 3 parts (header.payload.signature)
        assert_eq!(token.split('.').count(), 3);
    }

    #[test]
    fn test_verify_token_valid() {
        let config = load_test_config();
        let auth_service = AuthService::new(config).unwrap();

        let user_uuid = "550e8400-e29b-41d4-a716-446655440000";
        let username = "testuser";

        let token = auth_service
            .generate_access_token(user_uuid, username, true, true, true)
            .unwrap();

        let claims = auth_service.verify_token(&token).unwrap();

        assert_eq!(claims.sub, user_uuid);
        assert_eq!(claims.username, username);
        assert!(claims.mfa_verified);
        assert!(claims.is_superuser);
        assert!(claims.is_staff);
    }

    #[test]
    fn test_verify_token_invalid() {
        let config = load_test_config();
        let auth_service = AuthService::new(config).unwrap();

        let result = auth_service.verify_token("invalid.token.here");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_token_wrong_secret() {
        let config1 = load_test_config();
        let auth_service1 = AuthService::new(config1).unwrap();

        let token = auth_service1
            .generate_access_token(
                "550e8400-e29b-41d4-a716-446655440000",
                "testuser",
                true,
                false,
                false,
            )
            .unwrap();

        // Create another service with a different secret
        let mut config2 = load_test_config();
        config2.secret_key = "different-secret-key-for-testing!".to_string();
        let auth_service2 = AuthService::new(config2).unwrap();

        let result = auth_service2.verify_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_claims_correctness() {
        let config = load_test_config();
        let auth_service = AuthService::new(config).unwrap();

        let token = auth_service
            .generate_access_token(
                "test-uuid",
                "testuser",
                false, // mfa_verified
                true,  // is_superuser
                false, // is_staff
            )
            .unwrap();

        let claims = auth_service.verify_token(&token).unwrap();

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
        let (secret, uri) = AuthService::generate_totp_secret("testuser", "VAUBAN").unwrap();

        // Secret should not be empty
        assert!(!secret.is_empty());
        // URI should contain expected parts
        assert!(uri.contains("otpauth://totp/"));
        assert!(uri.contains("testuser"));
        assert!(uri.contains("VAUBAN"));
    }

    #[test]
    fn test_generate_totp_secret_different_users() {
        let (secret1, _) = AuthService::generate_totp_secret("user1", "VAUBAN").unwrap();
        let (secret2, _) = AuthService::generate_totp_secret("user2", "VAUBAN").unwrap();

        // Different users should get different secrets
        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_verify_totp_valid_code() {
        let (secret, _) = AuthService::generate_totp_secret("testuser", "VAUBAN").unwrap();

        // Get the current valid code
        let current_code = AuthService::get_current_totp(&secret).unwrap();

        // Verify the current code
        let is_valid = AuthService::verify_totp(&secret, &current_code);
        assert!(is_valid);
    }

    #[test]
    fn test_verify_totp_invalid_code() {
        let (secret, _) = AuthService::generate_totp_secret("testuser", "VAUBAN").unwrap();

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
        let (secret, _) = AuthService::generate_totp_secret("testuser", "VAUBAN").unwrap();
        let code = AuthService::get_current_totp(&secret).unwrap();

        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_totp_qr_code_success() {
        let (secret, _) = AuthService::generate_totp_secret("testuser", "VAUBAN").unwrap();
        let qr_code = AuthService::generate_totp_qr_code(&secret, "testuser", "VAUBAN").unwrap();

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
}
