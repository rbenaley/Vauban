/// VAUBAN Web - Authentication service.
///
/// Handles password hashing, JWT tokens, and MFA (TOTP).

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
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
        let secret_bytes = secret.to_bytes()
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to generate TOTP secret: {:?}", e)))?;

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,      // 6 digits
            1,      // 1 step tolerance (±30 seconds)
            30,     // 30 second step
            secret_bytes,
            Some(issuer.to_string()),
            username.to_string(),
        ).map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to create TOTP: {:?}", e)))?;

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
        let secret_bytes = secret_obj.to_bytes()
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Invalid TOTP secret: {:?}", e)))?;

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some(issuer.to_string()),
            username.to_string(),
        ).map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to create TOTP: {:?}", e)))?;

        // Generate QR code as base64 PNG
        let qr_code = totp.get_qr_base64()
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to generate QR code: {:?}", e)))?;

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
            1,  // 1 step tolerance
            30,
            secret_bytes,
            None,               // issuer not needed for verification
            String::new(),      // account_name not needed for verification
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

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            None,
            String::new(),
        ).ok()?;

        Some(totp.generate_current().ok()?)
    }
}

