//! Shared UI fragments (group module — no URL segment).

mod badges;
mod chips;
mod docs_formatted;
mod icons;
mod modal;
mod note_inline;
mod pager;
mod rail;
mod topbar;

pub use badges::{severity_badge, status_badge};
pub use chips::filter_row;
pub use docs_formatted::docs_formatted_body;
pub use icons::{
    ico_arrow_down, ico_builds, ico_check, ico_chevron_down, ico_chevron_right, ico_copy, ico_docs,
    ico_hourglass, ico_issues, ico_key, ico_paperclip, ico_plus, ico_trash,
};
pub use modal::article_modal_shell;
pub use note_inline::note_inline_text;
pub use pager::list_toolbar;
pub use rail::vb_rail;
pub use topbar::vb_topbar;
