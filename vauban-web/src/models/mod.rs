/// VAUBAN Web - Data models.
///
/// All models use Diesel for compile-time verified queries.
pub mod access_rule;
pub mod api_key;
pub mod asset;
pub mod auth_session;
pub mod email_outbox;
pub mod ews;
pub mod ews_audit;
pub mod ews_request;
pub mod session;
pub mod user;
pub mod vault_secret;

pub use access_rule::*;
pub use api_key::*;
pub use asset::*;
pub use auth_session::*;
pub use email_outbox::*;
pub use ews::*;
pub use ews_audit::*;
pub use ews_request::*;
pub use session::*;
pub use user::*;
pub use vault_secret::*;
