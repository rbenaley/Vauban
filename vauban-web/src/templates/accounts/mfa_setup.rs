use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};
/// VAUBAN Web - MFA setup template.
use askama::Template;

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
    pub secret: String,
    pub qr_code_url: String,
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
            qr_code_url: "data:image/png;base64,test".to_string(),
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
            qr_code_url: "https://example.com/qr.png".to_string(),
        };
        let result = template.render();
        assert!(result.is_ok());
    }
}
