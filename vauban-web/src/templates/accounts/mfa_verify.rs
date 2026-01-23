/// VAUBAN Web - MFA verification template.
use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Template for the MFA verification page.
///
/// Displayed when a user with MFA enabled logs in and needs to enter their TOTP code.
#[derive(Template)]
#[template(path = "accounts/mfa_verify.html")]
pub struct MfaVerifyTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
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
    fn test_mfa_verify_template_creation() {
        let template = MfaVerifyTemplate {
            title: "Verify MFA".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
        };
        assert_eq!(template.title, "Verify MFA");
    }

    #[test]
    fn test_mfa_verify_template_renders() {
        let template = MfaVerifyTemplate {
            title: "Verify MFA".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
        };
        let result = template.render();
        assert!(result.is_ok());
        let html = unwrap_ok!(result);
        assert!(html.contains("Two-Factor Authentication"));
        assert!(html.contains("totp_code"));
    }

    #[test]
    fn test_mfa_verify_template_has_form() {
        let template = MfaVerifyTemplate {
            title: "Verify MFA".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
        };
        let result = template.render();
        assert!(result.is_ok());
        let html = unwrap_ok!(result);
        assert!(html.contains("action=\"/mfa/verify\""));
        assert!(html.contains("method=\"POST\""));
        assert!(html.contains("csrf_token"));
    }
}
