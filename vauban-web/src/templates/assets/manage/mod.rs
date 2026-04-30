//! Admin "Manage Assets" templates — issue #27 asset zone split.
//!
//! These templates back the gated `/assets/manage/*` admin sub-tree
//! served by [`crate::handlers::web::manage_assets`]. They never expose
//! Connect / Request access affordances (the admin zone is structurally
//! session-free, enforced by source-level CI tests).
pub mod detail;
pub mod list;

pub use detail::{ManageAssetDetail, ManageAssetDetailTemplate};
pub use list::{ManageAssetItem, ManageAssetListTemplate};
