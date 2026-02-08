//! IPC message handlers for vault cryptographic operations.
//!
//! Each handler receives a request, performs the crypto operation using the
//! appropriate keyring, and returns a response message. Plaintext is zeroized
//! as soon as possible.

use std::collections::HashMap;

use shared::messages::{Message, SensitiveString};
use totp_rs::{Algorithm as TotpAlgorithm, Secret as TotpSecret, TOTP};
use zeroize::Zeroize;

use vauban_vault::keyring::Keyring;

/// Handle a VaultEncrypt request.
pub fn handle_encrypt(
    keyrings: &HashMap<String, Keyring>,
    request_id: u64,
    domain: &str,
    plaintext: &SensitiveString,
) -> Message {
    let Some(keyring) = keyrings.get(domain) else {
        return Message::VaultEncryptResponse {
            request_id,
            ciphertext: None,
            error: Some(format!("unknown domain: '{}'", domain)),
        };
    };

    match keyring.encrypt(plaintext.as_str().as_bytes()) {
        Ok(ciphertext) => Message::VaultEncryptResponse {
            request_id,
            ciphertext: Some(ciphertext),
            error: None,
        },
        Err(e) => Message::VaultEncryptResponse {
            request_id,
            ciphertext: None,
            error: Some(e.to_string()),
        },
    }
}

/// Handle a VaultDecrypt request.
pub fn handle_decrypt(
    keyrings: &HashMap<String, Keyring>,
    request_id: u64,
    domain: &str,
    ciphertext: &str,
) -> Message {
    let Some(keyring) = keyrings.get(domain) else {
        return Message::VaultDecryptResponse {
            request_id,
            plaintext: None,
            error: Some(format!("unknown domain: '{}'", domain)),
        };
    };

    match keyring.decrypt(ciphertext) {
        Ok(mut bytes) => {
            let s = String::from_utf8_lossy(&bytes).to_string();
            bytes.zeroize();
            Message::VaultDecryptResponse {
                request_id,
                plaintext: Some(SensitiveString::new(s)),
                error: None,
            }
        }
        Err(e) => Message::VaultDecryptResponse {
            request_id,
            plaintext: None,
            error: Some(e.to_string()),
        },
    }
}

/// Handle a VaultMfaGenerate request.
///
/// Generates a new TOTP secret, encrypts it with the "mfa" keyring, and returns
/// both the encrypted form (for DB storage) and the plaintext as a `SensitiveString`
/// (for QR code generation by the web layer). The plaintext is moved into
/// `SensitiveString` which zeroizes on drop.
pub fn handle_mfa_generate(
    keyrings: &HashMap<String, Keyring>,
    request_id: u64,
    _username: &str,
    _issuer: &str,
) -> Message {
    let Some(keyring) = keyrings.get("mfa") else {
        return Message::VaultMfaGenerateResponse {
            request_id,
            encrypted_secret: None,
            plaintext_secret: None,
            error: Some("mfa keyring not configured".to_string()),
        };
    };

    // Generate a random TOTP secret
    let secret = TotpSecret::generate_secret();

    // Get the base32-encoded secret
    let base32_secret = secret.to_encoded().to_string();

    // Encrypt the secret for DB storage
    let encrypted = match keyring.encrypt(base32_secret.as_bytes()) {
        Ok(c) => c,
        Err(e) => {
            // base32_secret will be dropped (not zeroized since it's not mut),
            // but SensitiveString below handles zeroization for the response.
            return Message::VaultMfaGenerateResponse {
                request_id,
                encrypted_secret: None,
                plaintext_secret: None,
                error: Some(format!("failed to encrypt TOTP secret: {}", e)),
            };
        }
    };

    // Move plaintext into SensitiveString (zeroize-on-drop)
    Message::VaultMfaGenerateResponse {
        request_id,
        encrypted_secret: Some(encrypted),
        plaintext_secret: Some(SensitiveString::new(base32_secret)),
        error: None,
    }
}

/// Handle a VaultMfaVerify request.
///
/// Decrypts the TOTP secret, verifies the code, and zeroizes the plaintext.
pub fn handle_mfa_verify(
    keyrings: &HashMap<String, Keyring>,
    request_id: u64,
    encrypted_secret: &str,
    code: &str,
) -> Message {
    let Some(keyring) = keyrings.get("mfa") else {
        return Message::VaultMfaVerifyResponse {
            request_id,
            valid: false,
            error: Some("mfa keyring not configured".to_string()),
        };
    };

    // Decrypt the TOTP secret
    let mut secret_bytes = match keyring.decrypt(encrypted_secret) {
        Ok(b) => b,
        Err(e) => {
            return Message::VaultMfaVerifyResponse {
                request_id,
                valid: false,
                error: Some(format!("failed to decrypt TOTP secret: {}", e)),
            };
        }
    };

    let mut base32_str = String::from_utf8_lossy(&secret_bytes).to_string();
    secret_bytes.zeroize();

    // Build the TOTP verifier
    let secret_obj = TotpSecret::Encoded(base32_str.clone());
    let totp_secret_bytes = match secret_obj.to_bytes() {
        Ok(b) => b,
        Err(_) => {
            base32_str.zeroize();
            return Message::VaultMfaVerifyResponse {
                request_id,
                valid: false,
                error: Some("invalid TOTP secret format".to_string()),
            };
        }
    };

    let totp = match TOTP::new(
        TotpAlgorithm::SHA1,
        6,
        1, // 1 step tolerance
        30,
        totp_secret_bytes,
        None,
        String::new(),
    ) {
        Ok(t) => t,
        Err(_) => {
            base32_str.zeroize();
            return Message::VaultMfaVerifyResponse {
                request_id,
                valid: false,
                error: Some("failed to create TOTP verifier".to_string()),
            };
        }
    };

    let valid = totp.check_current(code).unwrap_or(false);
    base32_str.zeroize();

    Message::VaultMfaVerifyResponse {
        request_id,
        valid,
        error: None,
    }
}

/// Handle a VaultMfaGetSecret request.
///
/// Decrypts an encrypted TOTP secret and returns it as a `SensitiveString`.
/// Used by vauban-web to re-generate QR codes from existing encrypted secrets.
/// The plaintext is moved into `SensitiveString` which zeroizes on drop.
pub fn handle_mfa_get_secret(
    keyrings: &HashMap<String, Keyring>,
    request_id: u64,
    encrypted_secret: &str,
) -> Message {
    let Some(keyring) = keyrings.get("mfa") else {
        return Message::VaultMfaGetSecretResponse {
            request_id,
            plaintext_secret: None,
            error: Some("mfa keyring not configured".to_string()),
        };
    };

    // Decrypt the TOTP secret
    let mut secret_bytes = match keyring.decrypt(encrypted_secret) {
        Ok(b) => b,
        Err(e) => {
            return Message::VaultMfaGetSecretResponse {
                request_id,
                plaintext_secret: None,
                error: Some(format!("failed to decrypt TOTP secret: {}", e)),
            };
        }
    };

    let base32_str = String::from_utf8_lossy(&secret_bytes).to_string();
    secret_bytes.zeroize();

    // Move into SensitiveString (zeroize-on-drop)
    Message::VaultMfaGetSecretResponse {
        request_id,
        plaintext_secret: Some(SensitiveString::new(base32_str)),
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vauban_vault::keyring::MasterKey;

    fn test_keyrings() -> HashMap<String, Keyring> {
        let mk = MasterKey::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ]);
        let mut keyrings = HashMap::new();
        keyrings.insert("mfa".to_string(), Keyring::new(mk.as_bytes(), "mfa", 1));
        keyrings.insert(
            "credentials".to_string(),
            Keyring::new(mk.as_bytes(), "credentials", 1),
        );
        keyrings
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let keyrings = test_keyrings();
        let plaintext = SensitiveString::new("my-password".to_string());

        let enc_resp = handle_encrypt(&keyrings, 1, "credentials", &plaintext);
        let ciphertext = match &enc_resp {
            Message::VaultEncryptResponse {
                ciphertext: Some(c),
                error: None,
                ..
            } => c.clone(),
            other => panic!("Expected encrypt success, got: {:?}", other),
        };

        let dec_resp = handle_decrypt(&keyrings, 2, "credentials", &ciphertext);
        match dec_resp {
            Message::VaultDecryptResponse {
                plaintext: Some(pt),
                error: None,
                ..
            } => assert_eq!(pt.as_str(), "my-password"),
            other => panic!("Expected decrypt success, got: {:?}", other),
        }
    }

    #[test]
    fn test_encrypt_unknown_domain_returns_error() {
        let keyrings = test_keyrings();
        let plaintext = SensitiveString::new("data".to_string());

        let resp = handle_encrypt(&keyrings, 1, "nonexistent", &plaintext);
        match resp {
            Message::VaultEncryptResponse {
                ciphertext: None,
                error: Some(e),
                ..
            } => assert!(e.contains("unknown domain")),
            other => panic!("Expected error, got: {:?}", other),
        }
    }

    #[test]
    fn test_decrypt_unknown_domain_returns_error() {
        let keyrings = test_keyrings();
        let resp = handle_decrypt(&keyrings, 1, "nonexistent", "v1:AAAA");
        match resp {
            Message::VaultDecryptResponse {
                plaintext: None,
                error: Some(e),
                ..
            } => assert!(e.contains("unknown domain")),
            other => panic!("Expected error, got: {:?}", other),
        }
    }

    #[test]
    fn test_mfa_generate_returns_encrypted_and_plaintext_secret() {
        let keyrings = test_keyrings();
        let resp = handle_mfa_generate(&keyrings, 1, "alice", "VAUBAN");

        match resp {
            Message::VaultMfaGenerateResponse {
                encrypted_secret: Some(enc),
                plaintext_secret: Some(pt),
                error: None,
                ..
            } => {
                // Encrypted secret must have version prefix
                assert!(enc.starts_with("v1:"), "encrypted_secret = {}", enc);
                // Plaintext secret must be a non-empty base32 string
                assert!(!pt.as_str().is_empty());
            }
            other => panic!("Expected MFA generate success, got: {:?}", other),
        }
    }

    #[test]
    fn test_mfa_generate_plaintext_is_valid_base32() {
        let keyrings = test_keyrings();
        let resp = handle_mfa_generate(&keyrings, 1, "alice", "VAUBAN");

        if let Message::VaultMfaGenerateResponse {
            plaintext_secret: Some(pt),
            ..
        } = &resp
        {
            // The plaintext must be a valid base32 TOTP secret
            let secret_obj = TotpSecret::Encoded(pt.as_str().to_string());
            assert!(
                secret_obj.to_bytes().is_ok(),
                "plaintext_secret is not valid base32: {}",
                pt.as_str()
            );
        } else {
            panic!("Expected MFA generate success, got: {:?}", resp);
        }
    }

    #[test]
    fn test_mfa_generate_secret_not_in_debug_output() {
        let keyrings = test_keyrings();
        let resp = handle_mfa_generate(&keyrings, 1, "alice", "VAUBAN");

        let debug = format!("{:?}", resp);
        // SensitiveString should redact the plaintext in Debug output
        assert!(
            debug.contains("REDACTED"),
            "Debug should contain REDACTED: {}",
            debug
        );
        // Verify encrypted_secret is properly formatted
        if let Message::VaultMfaGenerateResponse {
            encrypted_secret: Some(enc),
            ..
        } = &resp
        {
            assert!(enc.starts_with("v1:"));
        }
    }

    #[test]
    fn test_mfa_verify_valid_code() {
        let keyrings = test_keyrings();

        // Generate a secret
        let gen_resp = handle_mfa_generate(&keyrings, 1, "bob", "VAUBAN");
        let encrypted_secret = match gen_resp {
            Message::VaultMfaGenerateResponse {
                encrypted_secret: Some(s),
                ..
            } => s,
            other => panic!("Expected MFA generate success, got: {:?}", other),
        };

        // Decrypt the secret to get the base32 string for code generation
        let dec_resp = handle_decrypt(&keyrings, 2, "mfa", &encrypted_secret);
        let base32_secret = match dec_resp {
            Message::VaultDecryptResponse {
                plaintext: Some(pt),
                ..
            } => pt.as_str().to_string(),
            other => panic!("Expected decrypt success, got: {:?}", other),
        };

        // Generate the current TOTP code
        let secret_obj = TotpSecret::Encoded(base32_secret);
        let totp = TOTP::new(
            TotpAlgorithm::SHA1,
            6,
            1,
            30,
            secret_obj.to_bytes().unwrap(),
            None,
            String::new(),
        )
        .unwrap();
        let current_code = totp.generate_current().unwrap();

        // Verify via vault handler
        let verify_resp =
            handle_mfa_verify(&keyrings, 3, &encrypted_secret, &current_code);
        match verify_resp {
            Message::VaultMfaVerifyResponse {
                valid: true,
                error: None,
                ..
            } => {}
            other => panic!("Expected valid=true, got: {:?}", other),
        }
    }

    #[test]
    fn test_mfa_verify_invalid_code() {
        let keyrings = test_keyrings();

        // Generate a secret
        let gen_resp = handle_mfa_generate(&keyrings, 1, "charlie", "VAUBAN");
        let encrypted_secret = match gen_resp {
            Message::VaultMfaGenerateResponse {
                encrypted_secret: Some(s),
                ..
            } => s,
            other => panic!("Expected MFA generate success, got: {:?}", other),
        };

        // Verify with a wrong code
        let verify_resp = handle_mfa_verify(&keyrings, 2, &encrypted_secret, "000000");
        match verify_resp {
            Message::VaultMfaVerifyResponse {
                valid: false,
                error: None,
                ..
            } => {}
            other => panic!("Expected valid=false, got: {:?}", other),
        }
    }

    #[test]
    fn test_mfa_get_secret_from_encrypted() {
        let keyrings = test_keyrings();

        // Generate a secret
        let gen_resp = handle_mfa_generate(&keyrings, 1, "dave", "VAUBAN");
        let (encrypted_secret, original_plaintext) = match gen_resp {
            Message::VaultMfaGenerateResponse {
                encrypted_secret: Some(enc),
                plaintext_secret: Some(pt),
                ..
            } => (enc, pt.as_str().to_string()),
            other => panic!("Expected MFA generate success, got: {:?}", other),
        };

        // Get plaintext back from encrypted secret
        let get_resp = handle_mfa_get_secret(&keyrings, 2, &encrypted_secret);
        match get_resp {
            Message::VaultMfaGetSecretResponse {
                plaintext_secret: Some(pt),
                error: None,
                ..
            } => {
                assert_eq!(pt.as_str(), original_plaintext);
            }
            other => panic!("Expected get secret success, got: {:?}", other),
        }
    }

    #[test]
    fn test_mfa_verify_missing_keyring_returns_error() {
        let keyrings = HashMap::new(); // No keyrings
        let resp = handle_mfa_verify(&keyrings, 1, "v1:data", "123456");
        match resp {
            Message::VaultMfaVerifyResponse {
                valid: false,
                error: Some(e),
                ..
            } => assert!(e.contains("not configured")),
            other => panic!("Expected error, got: {:?}", other),
        }
    }

    /// Verify that the vault correctly rejects plaintext (non-encrypted) secrets
    /// when passed to mfa_verify. This confirms that backward compat must be
    /// handled at the web layer (is_encrypted check).
    #[test]
    fn test_mfa_verify_rejects_plaintext_secret() {
        let keyrings = test_keyrings();

        // Pass a plaintext base32 TOTP secret (not encrypted)
        // The vault should return an error because it cannot decrypt plaintext
        let resp = handle_mfa_verify(&keyrings, 1, "JBSWY3DPEHPK3PXP", "123456");
        match resp {
            Message::VaultMfaVerifyResponse {
                valid: false,
                error: Some(e),
                ..
            } => {
                assert!(
                    e.contains("decrypt") || e.contains("invalid") || e.contains("format"),
                    "Error should indicate decryption failure: {}",
                    e
                );
            }
            other => panic!(
                "Expected error for plaintext secret, got: {:?}",
                other
            ),
        }
    }

    /// Verify that mfa_get_secret also rejects plaintext secrets.
    #[test]
    fn test_mfa_get_secret_rejects_plaintext_secret() {
        let keyrings = test_keyrings();

        let resp = handle_mfa_get_secret(&keyrings, 1, "JBSWY3DPEHPK3PXP");
        match resp {
            Message::VaultMfaGetSecretResponse {
                plaintext_secret: None,
                error: Some(e),
                ..
            } => {
                assert!(
                    e.contains("decrypt") || e.contains("invalid") || e.contains("format"),
                    "Error should indicate decryption failure: {}",
                    e
                );
            }
            other => panic!(
                "Expected error for plaintext secret, got: {:?}",
                other
            ),
        }
    }

    /// Verify the full encrypt-on-read flow:
    /// 1. Start with a plaintext base32 TOTP secret
    /// 2. Encrypt it via the credentials keyring (simulating encrypt-on-read)
    /// 3. Use the encrypted version for MFA verify via vault
    #[test]
    fn test_encrypt_on_read_flow() {
        let keyrings = test_keyrings();

        // Step 1: Generate a TOTP secret via vault
        let gen_resp = handle_mfa_generate(&keyrings, 1, "migrate-user", "VAUBAN");
        let encrypted_secret = match gen_resp {
            Message::VaultMfaGenerateResponse {
                encrypted_secret: Some(s),
                ..
            } => s,
            other => panic!("Expected generate success: {:?}", other),
        };

        // Step 2: Decrypt to get the plaintext (simulating a pre-migration DB value)
        let dec_resp = handle_decrypt(&keyrings, 2, "mfa", &encrypted_secret);
        let plaintext_base32 = match dec_resp {
            Message::VaultDecryptResponse {
                plaintext: Some(pt),
                ..
            } => pt.as_str().to_string(),
            other => panic!("Expected decrypt success: {:?}", other),
        };

        // Step 3: Simulate encrypt-on-read by re-encrypting the plaintext
        let enc_plaintext = SensitiveString::new(plaintext_base32.clone());
        let reenc_resp = handle_encrypt(&keyrings, 3, "mfa", &enc_plaintext);
        let re_encrypted = match reenc_resp {
            Message::VaultEncryptResponse {
                ciphertext: Some(ct),
                ..
            } => ct,
            other => panic!("Expected encrypt success: {:?}", other),
        };

        // Step 4: Generate TOTP code from plaintext for verification
        let secret_obj = TotpSecret::Encoded(plaintext_base32);
        let totp = TOTP::new(
            TotpAlgorithm::SHA1,
            6,
            1,
            30,
            secret_obj.to_bytes().unwrap(),
            None,
            String::new(),
        )
        .unwrap();
        let code = totp.generate_current().unwrap();

        // Step 5: Verify using the re-encrypted secret (as vault would after encrypt-on-read)
        let verify_resp = handle_mfa_verify(&keyrings, 4, &re_encrypted, &code);
        match verify_resp {
            Message::VaultMfaVerifyResponse {
                valid: true,
                error: None,
                ..
            } => {}
            other => panic!(
                "Expected valid=true after encrypt-on-read, got: {:?}",
                other
            ),
        }
    }
}
