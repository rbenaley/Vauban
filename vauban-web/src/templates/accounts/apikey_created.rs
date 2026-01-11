/// VAUBAN Web - API key created success template.
use askama::Template;

#[derive(Template)]
#[template(path = "accounts/apikey_created.html")]
pub struct ApikeyCreatedTemplate {
    pub name: String,
    pub key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apikey_created_renders() {
        let template = ApikeyCreatedTemplate {
            name: "Test Key".to_string(),
            key: "vbn_secret123".to_string(),
        };
        let result = template.render();
        assert!(result.is_ok());
    }

    #[test]
    fn test_apikey_created_contains_key_name() {
        let template = ApikeyCreatedTemplate {
            name: "My Production Key".to_string(),
            key: "vbn_abc123xyz".to_string(),
        };
        let html = template.render().unwrap();
        assert!(html.contains("My Production Key"));
    }

    #[test]
    fn test_apikey_created_contains_key_value() {
        let template = ApikeyCreatedTemplate {
            name: "Test".to_string(),
            key: "vbn_secret_key_value".to_string(),
        };
        let html = template.render().unwrap();
        assert!(html.contains("vbn_secret_key_value"));
    }

    #[test]
    fn test_apikey_created_with_special_characters() {
        let template = ApikeyCreatedTemplate {
            name: "Clé d'API <test>".to_string(),
            key: "vbn_test123".to_string(),
        };
        let result = template.render();
        assert!(result.is_ok());
    }
}
