//! Shared UI fragments (group module — no URL segment).

mod badges;
mod chips;
mod icons;
mod modal;
mod rail;
mod topbar;

pub use badges::{severity_badge, status_badge};
pub use chips::chip_row;
pub use icons::{
    ico_arrow_down, ico_builds, ico_check, ico_chevron_down, ico_chevron_right, ico_docs, ico_edit,
    ico_hourglass, ico_issues, ico_orgs, ico_paperclip, ico_plus, ico_release,
};
pub use modal::article_modal_shell;
pub use rail::vb_rail;
pub use topbar::vb_topbar;
