pub mod access_list;
pub mod asset_connect;
pub mod asset_create;
pub mod asset_detail;
pub mod asset_edit;
/// VAUBAN Web - Assets templates.
pub mod asset_list;
pub mod group_create;
pub mod group_detail;
pub mod group_edit;
pub mod group_list;

pub use access_list::AccessListTemplate;
pub use asset_connect::AssetConnectTemplate;
pub use asset_create::{AssetCreateForm, AssetCreateTemplate};
pub use asset_detail::AssetDetailTemplate;
pub use asset_edit::AssetEditTemplate;
pub use asset_list::AssetListTemplate;
pub use group_create::{AssetGroupCreateForm, AssetGroupCreateTemplate};
pub use group_detail::AssetGroupDetailTemplate;
pub use group_edit::AssetGroupEditTemplate;
pub use group_list::AssetGroupListTemplate;
