pub mod apikey_list;
pub mod group_detail;
pub mod group_list;
/// VAUBAN Web - Accounts templates.
pub mod login;
pub mod mfa_setup;
pub mod profile;
pub mod session_list;
pub mod user_detail;
pub mod user_list;

pub use apikey_list::ApikeyListTemplate;
pub use group_detail::GroupDetailTemplate;
pub use group_list::GroupListTemplate;
pub use login::LoginTemplate;
pub use mfa_setup::MfaSetupTemplate;
pub use profile::ProfileTemplate;
pub use session_list::SessionListTemplate;
pub use user_detail::{UserDetail, UserDetailTemplate};
pub use user_list::{Pagination, UserListTemplate};
