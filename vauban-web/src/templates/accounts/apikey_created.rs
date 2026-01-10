/// VAUBAN Web - API key created success template.
use askama::Template;

#[derive(Template)]
#[template(path = "accounts/apikey_created.html")]
pub struct ApikeyCreatedTemplate {
    pub name: String,
    pub key: String,
}
