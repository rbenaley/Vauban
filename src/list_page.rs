//! Shared SSR list pagination helpers (`LIST_PAGE_SIZE`, slice, hrefs).

/// Max rows rendered per list page (SSR GET `?page=`).
pub const LIST_PAGE_SIZE: usize = 10;

/// Builds list page size (alias — keep `builds_entitlement` pins stable).
pub const BUILDS_PAGE_SIZE: usize = LIST_PAGE_SIZE;

/// Admin companies card list — denser cards than table rows.
pub const COMPANIES_PAGE_SIZE: usize = 3;

/// Admin KEY pending/active tables (`/admin/key`) — helper SQLite pages.
pub const KEY_PAGE_SIZE: usize = 4;

/// Parse 1-based page query (default 1, minimum 1).
pub fn parse_page(raw: Option<u32>) -> usize {
    raw.map(|p| p.max(1) as usize).unwrap_or(1)
}

/// Number of pages for `total` items (`0` items still yields 1 empty page).
pub fn page_count(total: usize, page_size: usize) -> usize {
    if page_size == 0 {
        return 1;
    }
    total.div_ceil(page_size).max(1)
}

pub fn clamp_page(page: usize, pages: usize) -> usize {
    page.clamp(1, pages.max(1))
}

/// 0-based row offset for Toasty `.limit(page_size).offset(...)`.
///
/// `page` is 1-based (clamped to at least 1). Requires a prior `.limit` on the
/// same query (Toasty panics otherwise).
pub fn page_offset(page: usize, page_size: usize) -> usize {
    let page = page.max(1);
    if page_size == 0 {
        return 0;
    }
    (page - 1) * page_size
}

/// Slice of `items` for a 1-based `page` (clamped).
///
/// Prefer SQL `.limit` / `.offset` for Postgres-backed lists; use this for
/// already-bounded in-memory vecs (tests, tiny fixed slices).
pub fn page_slice<T>(items: &[T], page: usize, page_size: usize) -> &[T] {
    if items.is_empty() || page_size == 0 {
        return items;
    }
    let pages = page_count(items.len(), page_size);
    let page = clamp_page(page, pages);
    let start = (page - 1) * page_size;
    if start >= items.len() {
        return &[];
    }
    let end = (start + page_size).min(items.len());
    &items[start..end]
}

/// Append `page=N` when `page > 1`. `parts` are already-encoded `key=value` pairs.
pub fn with_page_param(parts: &mut Vec<String>, page: usize) {
    with_named_page_param(parts, "page", page);
}

/// Append `{name}=N` when `page > 1` (e.g. `pending_page`, `active_page`).
pub fn with_named_page_param(parts: &mut Vec<String>, name: &str, page: usize) {
    if page > 1 {
        parts.push(format!("{name}={page}"));
    }
}

/// Build `path` or `path?a=1&page=2` from encoded query parts.
pub fn href_with_query(path: &str, parts: &[String]) -> String {
    if parts.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{}", parts.join("&"))
    }
}

/// Model for [`crate::app::_components::vb_pager`].
#[derive(Clone, Debug)]
pub struct PagerLinks {
    pub page: usize,
    pub page_count: usize,
    pub prev_href: Option<String>,
    pub next_href: Option<String>,
    /// `(page_number, href)` for each page in `1..=page_count`.
    pub pages: Vec<(usize, String)>,
}

impl PagerLinks {
    /// Build pager links from a closure `page -> href` (must omit `page=1` itself).
    pub fn from_hrefs(
        page: usize,
        page_count: usize,
        mut href_for: impl FnMut(usize) -> String,
    ) -> Self {
        let page = clamp_page(page, page_count);
        let pages: Vec<(usize, String)> = (1..=page_count).map(|n| (n, href_for(n))).collect();
        let prev_href = pages
            .iter()
            .find(|(n, _)| *n + 1 == page)
            .map(|(_, h)| h.clone());
        let next_href = pages
            .iter()
            .find(|(n, _)| *n == page + 1)
            .map(|(_, h)| h.clone());
        Self {
            page,
            page_count,
            prev_href,
            next_href,
            pages,
        }
    }

    pub fn show(&self) -> bool {
        self.page_count > 1
    }
}

#[cfg(test)]
mod list_page_tests {
    use super::*;

    #[test]
    fn list_page_parse_page_defaults_and_clamps_min() {
        assert_eq!(parse_page(None), 1);
        assert_eq!(parse_page(Some(0)), 1);
        assert_eq!(parse_page(Some(1)), 1);
        assert_eq!(parse_page(Some(3)), 3);
    }

    #[test]
    fn list_page_page_count_empty_exact_and_overflow() {
        assert_eq!(page_count(0, LIST_PAGE_SIZE), 1);
        assert_eq!(page_count(10, LIST_PAGE_SIZE), 1);
        assert_eq!(page_count(11, LIST_PAGE_SIZE), 2);
        assert_eq!(page_count(20, LIST_PAGE_SIZE), 2);
        assert_eq!(page_count(21, LIST_PAGE_SIZE), 3);
    }

    #[test]
    fn list_page_page_offset_is_zero_based() {
        assert_eq!(page_offset(1, LIST_PAGE_SIZE), 0);
        assert_eq!(page_offset(2, LIST_PAGE_SIZE), 10);
        assert_eq!(page_offset(0, LIST_PAGE_SIZE), 0);
        assert_eq!(page_offset(3, 3), 6);
    }

    #[test]
    fn list_page_page_slice_lengths_and_clamp() {
        let items: Vec<usize> = (0..11).collect();
        assert!(page_slice::<usize>(&[], 1, LIST_PAGE_SIZE).is_empty());
        assert_eq!(page_slice(&items, 1, LIST_PAGE_SIZE).len(), 10);
        assert_eq!(page_slice(&items, 2, LIST_PAGE_SIZE), &[10]);
        assert_eq!(page_slice(&items, 99, LIST_PAGE_SIZE), &[10]);
        assert_eq!(clamp_page(99, 2), 2);
    }

    #[test]
    fn list_page_with_page_param_omits_page_one() {
        let mut parts = vec!["channel=LTS".to_owned()];
        with_page_param(&mut parts, 1);
        assert_eq!(parts, vec!["channel=LTS".to_owned()]);
        with_page_param(&mut parts, 2);
        assert_eq!(parts, vec!["channel=LTS".to_owned(), "page=2".to_owned()]);
        assert_eq!(
            href_with_query("/acme/builds", &parts),
            "/acme/builds?channel=LTS&page=2"
        );
    }
}
