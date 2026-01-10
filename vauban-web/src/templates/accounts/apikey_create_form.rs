/// VAUBAN Web - API key creation form template.
use askama::Template;

#[derive(Template)]
#[template(path = "accounts/apikey_create_form.html")]
pub struct ApikeyCreateFormTemplate {}
