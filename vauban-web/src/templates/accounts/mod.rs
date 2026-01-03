/// VAUBAN Web - Accounts templates.

pub mod login;
pub mod user_list;
pub mod user_detail;
pub mod profile;
pub mod mfa_setup;
pub mod session_list;
pub mod apikey_list;
pub mod group_list;
pub mod group_detail;

pub use login::LoginTemplate;
pub use user_list::{UserListTemplate, Pagination};
pub use user_detail::{UserDetailTemplate, UserDetail};
pub use profile::ProfileTemplate;
pub use mfa_setup::MfaSetupTemplate;
pub use session_list::SessionListTemplate;
pub use apikey_list::ApikeyListTemplate;
pub use group_list::GroupListTemplate;
pub use group_detail::GroupDetailTemplate;

