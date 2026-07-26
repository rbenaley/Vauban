//! Shared Concept UI fragments (group module — no URL segment).

mod badges;
mod chips;
mod modal;
mod rail;
mod topbar;

pub use badges::{severity_badge, status_badge};
pub use chips::chip_row;
pub use modal::article_modal_shell;
pub use rail::vb_rail;
pub use topbar::vb_topbar;
