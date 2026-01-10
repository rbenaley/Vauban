/// VAUBAN Web - Accounts templates.
pub mod apikey_create_form;
pub mod apikey_created;
pub mod apikey_list;
pub mod group_detail;
pub mod group_list;
pub mod login;
pub mod mfa_setup;
pub mod profile;
pub mod session_list;
pub mod user_detail;
pub mod user_list;

pub use apikey_create_form::ApikeyCreateFormTemplate;
pub use apikey_created::ApikeyCreatedTemplate;
pub use apikey_list::{ApiKeyItem, ApikeyListTemplate};
pub use group_detail::GroupDetailTemplate;
pub use group_list::GroupListTemplate;
pub use login::LoginTemplate;
pub use mfa_setup::MfaSetupTemplate;
pub use profile::ProfileTemplate;
pub use session_list::{AuthSessionItem, SessionListTemplate};
pub use user_detail::{UserDetail, UserDetailTemplate};
pub use user_list::{Pagination, UserListTemplate};
