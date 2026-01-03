/// VAUBAN Web - Header data structure.

use crate::templates::base::UserContext;

/// Header data (not a template itself, used as data in includes).
#[derive(Debug, Clone)]
pub struct HeaderTemplate {
    pub user: UserContext,
}
