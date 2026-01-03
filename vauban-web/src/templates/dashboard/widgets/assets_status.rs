/// VAUBAN Web - Assets status widget template.

use askama::Template;

#[derive(Template)]
#[template(path = "dashboard/widgets/assets_status.html")]
pub struct AssetsStatusWidget {
    pub online: i32,
    pub offline: i32,
    pub maintenance: i32,
}

