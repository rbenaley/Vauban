/// VAUBAN Web - MFA setup template.
use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Template for the MFA setup page.
///
/// Displayed when a user logs in for the first time or when MFA is not yet enabled.
/// Shows QR code and secret key for authenticator app setup.
#[derive(Template)]
#[template(path = "accounts/mfa_setup.html")]
pub struct MfaSetupTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    /// VAU-008: a candidate secret is currently pending confirmation for THIS
    /// session. When `true`, the template renders the QR code and the
    /// confirmation form. The candidate lives only in the in-memory store, it
    /// is never persisted before confirmation.
    pub show_qr: bool,
    /// VAU-008: the user already has an active second factor (rotation flow,
    /// reached via `/accounts/mfa`). When `true` (and `show_qr` is `false`),
    /// the template renders a step-up form asking for the CURRENT TOTP code
    /// before a new candidate can be generated. Mutually exclusive with the
    /// first-enrolment button (rendered when both flags are `false`).
    pub needs_totp_stepup: bool,
    /// The TOTP secret key in Base32 format. Empty unless `show_qr`.
    pub secret: String,
    /// The QR code as a Base64-encoded PNG image (without data URI prefix).
    /// Empty unless `show_qr`.
    pub qr_code_base64: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_vauban_config() -> VaubanConfig {
        VaubanConfig {
            brand_name: "VAUBAN".to_string(),
            brand_logo: None,
            theme: "dark".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_mfa_setup_template_creation() {
        let template = MfaSetupTemplate {
            title: "MFA Setup".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            show_qr: true,
            needs_totp_stepup: false,
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            qr_code_base64: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==".to_string(),
        };
        assert_eq!(template.title, "MFA Setup");
        assert_eq!(template.secret, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn test_mfa_setup_template_renders() {
        let template = MfaSetupTemplate {
            title: "MFA Setup".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            show_qr: true,
            needs_totp_stepup: false,
            secret: "ABCDEF".to_string(),
            qr_code_base64: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==".to_string(),
        };
        let result = template.render();
        assert!(result.is_ok());
        let html = unwrap_ok!(result);
        assert!(html.contains("ABCDEF"));
        assert!(html.contains("data:image/png;base64,"));
    }

    #[test]
    fn test_mfa_setup_template_contains_qr_code() {
        let template = MfaSetupTemplate {
            title: "MFA Setup".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            show_qr: true,
            needs_totp_stepup: false,
            secret: "TESTSECRET".to_string(),
            qr_code_base64: "base64data".to_string(),
        };
        let result = template.render();
        assert!(result.is_ok());
        let html = unwrap_ok!(result);
        assert!(html.contains("TESTSECRET"));
        assert!(html.contains("base64data"));
    }

    /// VAU-008 (ephemeral): first enrolment with no candidate renders the
    /// "Configure 2FA" button posting to `/mfa/setup/init`, and asks for NO
    /// password (the step-up at first enrolment was removed) and shows NO QR.
    #[test]
    fn test_mfa_setup_template_first_enrolment_shows_button_no_password() {
        let template = MfaSetupTemplate {
            title: "MFA Setup".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            show_qr: false,
            needs_totp_stepup: false,
            secret: String::new(),
            qr_code_base64: String::new(),
        };
        let result = template.render();
        assert!(result.is_ok());
        let html = unwrap_ok!(result);
        // The init form targets the init endpoint...
        assert!(html.contains("/mfa/setup/init"));
        // ...but NEVER asks for a password (no double password entry).
        assert!(!html.contains("type=\"password\""));
        // No TOTP step-up field (that is the rotation path).
        assert!(!html.contains("name=\"totp_code\""));
        // No QR image when nothing is pending.
        assert!(!html.contains("data:image/png;base64,"));
    }

    /// VAU-008 (ephemeral): rotation (already enrolled) with no candidate
    /// renders a current-TOTP step-up form posting to `/mfa/setup/init`, with
    /// NO password and NO QR.
    #[test]
    fn test_mfa_setup_template_rotation_shows_totp_stepup() {
        let template = MfaSetupTemplate {
            title: "MFA Setup".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            show_qr: false,
            needs_totp_stepup: true,
            secret: String::new(),
            qr_code_base64: String::new(),
        };
        let result = template.render();
        assert!(result.is_ok());
        let html = unwrap_ok!(result);
        assert!(html.contains("/mfa/setup/init"));
        // Rotation asks for the CURRENT TOTP code, never a password.
        assert!(html.contains("name=\"totp_code\""));
        assert!(!html.contains("type=\"password\""));
        assert!(!html.contains("data:image/png;base64,"));
    }
}
