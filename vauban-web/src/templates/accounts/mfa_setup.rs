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
    /// The TOTP secret key in Base32 format.
    pub secret: String,
    /// The QR code as a Base64-encoded PNG image (without data URI prefix).
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
            secret: "TESTSECRET".to_string(),
            qr_code_base64: "base64data".to_string(),
        };
        let result = template.render();
        assert!(result.is_ok());
        let html = unwrap_ok!(result);
        assert!(html.contains("TESTSECRET"));
        assert!(html.contains("base64data"));
    }
}
