/// VAUBAN Web - Sidebar data structure.

use crate::templates::partials::sidebar_content::SidebarContentTemplate;

/// Sidebar data (not a template itself, used as data in includes).
#[derive(Debug, Clone)]
pub struct SidebarTemplate {
    pub sidebar_content: SidebarContentTemplate,
}
