/// VAUBAN Web - Recording detail template.

use askama::Template;
use crate::templates::base::{UserContext, VaubanConfig, FlashMessage};


#[derive(Template)]
#[template(path = "sessions/recording_detail.html")]
pub struct RecordingDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content: Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
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
    fn test_recording_detail_template_creation() {
        let template = RecordingDetailTemplate {
            title: "Recording Detail".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
        };
        assert_eq!(template.title, "Recording Detail");
    }

    #[test]
    fn test_recording_detail_template_renders() {
        let template = RecordingDetailTemplate {
            title: "Recording Detail".to_string(),
            user: None,
            vauban: create_test_vauban_config(),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
        };
        let result = template.render();
        assert!(result.is_ok());
    }
}
