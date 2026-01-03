/// VAUBAN Web - User detail template.

use askama::Template;
use crate::templates::base::{UserContext, VaubanConfig, FlashMessage};


/// User detail information.
#[derive(Debug, Clone)]
pub struct UserDetail {
    pub uuid: String,
    pub username: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone: Option<String>,
    pub full_name: Option<String>,
    pub is_active: bool,
    pub is_staff: bool,
    pub is_superuser: bool,
    pub mfa_enabled: bool,
    pub auth_source: String,
    pub last_login: Option<String>,
    pub created_at: String,
}

#[derive(Template)]
#[template(path = "accounts/user_detail.html")]
pub struct UserDetailTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content: Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub user_detail: UserDetail,
}

