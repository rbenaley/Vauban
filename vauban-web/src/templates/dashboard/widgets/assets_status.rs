/// VAUBAN Web - Assets status widget template.
use askama::Template;

#[derive(Template)]
#[template(path = "dashboard/widgets/assets_status.html")]
pub struct AssetsStatusWidget {
    pub online: i32,
    pub offline: i32,
    pub maintenance: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assets_status_widget_creation() {
        let widget = AssetsStatusWidget {
            online: 10,
            offline: 2,
            maintenance: 1,
        };
        assert_eq!(widget.online, 10);
        assert_eq!(widget.offline, 2);
        assert_eq!(widget.maintenance, 1);
    }

    #[test]
    fn test_assets_status_widget_all_online() {
        let widget = AssetsStatusWidget {
            online: 15,
            offline: 0,
            maintenance: 0,
        };
        assert_eq!(widget.online, 15);
        assert_eq!(widget.offline, 0);
    }

    #[test]
    fn test_assets_status_widget_all_offline() {
        let widget = AssetsStatusWidget {
            online: 0,
            offline: 10,
            maintenance: 0,
        };
        assert_eq!(widget.offline, 10);
    }

    #[test]
    fn test_assets_status_widget_renders() {
        let widget = AssetsStatusWidget {
            online: 5,
            offline: 2,
            maintenance: 1,
        };
        let result = widget.render();
        assert!(result.is_ok());
    }
}
