/// VAUBAN Web - API key creation form template.
use askama::Template;

#[derive(Template)]
#[template(path = "accounts/apikey_create_form.html")]
pub struct ApikeyCreateFormTemplate {}

#[cfg(test)]
mod tests {
    use super::*;
    

    #[test]
    fn test_apikey_create_form_renders() {
        let template = ApikeyCreateFormTemplate {};
        let result = template.render();
        assert!(result.is_ok());
    }

    #[test]
    fn test_apikey_create_form_contains_form_elements() {
        let template = ApikeyCreateFormTemplate {};
        let html = unwrap_ok!(template.render());
        // Form should contain input fields
        assert!(html.contains("form") || html.contains("input") || html.contains("button"));
    }
}
