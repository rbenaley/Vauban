//! Pure, shared filtering / pagination seam for every list page.
//!
//! Before this module, the query-param idiom
//! (`params.get(..).filter(|s| !s.is_empty()).cloned()`) was duplicated
//! ~19 times and the pagination arithmetic
//! (`ceil().max(1.0)` + `page.min(total_pages)` + start/end indices)
//! 13 times across `handlers/web/*.rs`, with two forks that had drifted
//! (`/sessions/approvals` lost the page clamp, `/audit/approvals` built
//! ILIKE patterns without escaping `%`/`_`). Every list handler now
//! goes through these helpers; the invariants are pinned by
//! `tests/web/list_filters_proptest.rs`.
//!
//! Everything here is synchronous and side-effect free (no DB, no
//! state) so it can be property-tested exhaustively.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Query-param parsing
// ---------------------------------------------------------------------------

/// Read an optional filter value: absent or empty string both mean
/// "no filter" (HTML selects submit `""` for the "All ..." option).
#[must_use]
pub fn opt_filter(params: &HashMap<String, String>, key: &str) -> Option<String> {
    params.get(key).filter(|s| !s.is_empty()).cloned()
}

/// Parse the `page` query param; anything unparsable or < 1 yields 1.
#[must_use]
pub fn parse_page(params: &HashMap<String, String>) -> i32 {
    parse_page_param(params, "page")
}

/// Same as [`parse_page`] for pages carried under a custom key
/// (`/iacs/admin` paginates two independent lists on one page).
#[must_use]
pub fn parse_page_param(params: &HashMap<String, String>, key: &str) -> i32 {
    params
        .get(key)
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(1)
        .max(1)
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

/// One resolved pagination window. All fields are already clamped and
/// consistent: `page` is in `1..=total_pages`, `total_pages >= 1`,
/// `start_index == 0` iff the list is empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageWindow {
    pub page: i32,
    pub total_pages: i32,
    pub total_items: usize,
    pub per_page: usize,
    /// Number of items to skip (SQL OFFSET / iterator `skip`).
    pub offset: usize,
    /// 1-based index of the first displayed item (0 when empty).
    pub start_index: usize,
    /// 1-based index of the last displayed item (0 when empty).
    pub end_index: usize,
    pub has_previous: bool,
    pub has_next: bool,
}

/// Compute the pagination window. Total replacement for the historical
/// per-handler arithmetic (`((total as f64)/(per as f64)).ceil().max(1.0)`
/// then `page.min(total_pages)`): integer `div_ceil` is equivalent for
/// the sizes at play and cannot lose precision. Never panics.
#[must_use]
pub fn paginate(total_items: usize, requested_page: i32, per_page: usize) -> PageWindow {
    let per_page = per_page.max(1);
    let total_pages_usize = total_items.div_ceil(per_page).max(1);
    let total_pages = i32::try_from(total_pages_usize).unwrap_or(i32::MAX);
    let page = requested_page.clamp(1, total_pages);
    // page >= 1 by construction, so the subtraction cannot underflow.
    let offset = usize::try_from(page - 1)
        .unwrap_or(0)
        .saturating_mul(per_page);
    let start_index = if total_items > 0 { offset + 1 } else { 0 };
    let end_index = offset.saturating_add(per_page).min(total_items);

    PageWindow {
        page,
        total_pages,
        total_items,
        per_page,
        offset,
        start_index,
        end_index,
        has_previous: page > 1,
        has_next: page < total_pages,
    }
}

fn to_i32(value: usize) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

impl PageWindow {
    /// Canonical template pagination (assets, users, sessions, ...).
    #[must_use]
    pub fn to_pagination(&self) -> crate::templates::accounts::user_list::Pagination {
        crate::templates::accounts::user_list::Pagination {
            current_page: self.page,
            total_pages: self.total_pages,
            total_items: to_i32(self.total_items),
            items_per_page: to_i32(self.per_page),
            has_previous: self.has_previous,
            has_next: self.has_next,
            start_index: to_i32(self.start_index),
            end_index: to_i32(self.end_index),
        }
    }

    /// Reduced pagination used by `/sessions/approvals`.
    #[must_use]
    pub fn to_approval_pagination(&self) -> crate::templates::sessions::approval_list::Pagination {
        crate::templates::sessions::approval_list::Pagination {
            current_page: self.page,
            total_pages: self.total_pages,
            total_items: to_i32(self.total_items),
            has_previous: self.has_previous,
            has_next: self.has_next,
        }
    }

    /// Reduced pagination used by `/audit/approvals`.
    #[must_use]
    pub fn to_audit_pagination(
        &self,
    ) -> crate::templates::audit::approval_audit_list::AuditPagination {
        crate::templates::audit::approval_audit_list::AuditPagination {
            current_page: self.page,
            total_pages: self.total_pages,
            total_items: i64::try_from(self.total_items).unwrap_or(i64::MAX),
            has_previous: self.has_previous,
            has_next: self.has_next,
        }
    }

    /// SQL OFFSET, as Diesel expects it.
    #[must_use]
    pub fn offset_i64(&self) -> i64 {
        i64::try_from(self.offset).unwrap_or(i64::MAX)
    }

    /// SQL LIMIT, as Diesel expects it.
    #[must_use]
    pub fn limit_i64(&self) -> i64 {
        i64::try_from(self.per_page).unwrap_or(i64::MAX)
    }
}

/// Keep only the current page of an in-memory (already filtered) list.
#[must_use]
pub fn slice_page<T>(items: Vec<T>, window: &PageWindow) -> Vec<T> {
    items
        .into_iter()
        .skip(window.offset)
        .take(window.per_page)
        .collect()
}

// ---------------------------------------------------------------------------
// In-memory predicates (IPC-backed lists)
// ---------------------------------------------------------------------------

/// Case-insensitive substring search across several haystack fields.
/// `None` and blank needles match everything (no filter).
#[must_use]
pub fn matches_search(haystacks: &[&str], needle: Option<&str>) -> bool {
    let Some(needle) = needle else {
        return true;
    };
    let needle = needle.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    haystacks.iter().any(|h| h.to_lowercase().contains(&needle))
}

/// Exact-match select filter; `None` matches everything.
#[must_use]
pub fn matches_select(value: &str, filter: Option<&str>) -> bool {
    filter.is_none_or(|f| value == f)
}

/// Boolean select filter (Active/Inactive, Approval yes/no, ...);
/// `None` matches everything.
#[must_use]
pub fn matches_bool(value: bool, filter: Option<bool>) -> bool {
    filter.is_none_or(|f| value == f)
}

/// Protocol select filter for access rules: `ssh` / `rdp` match
/// exactly, `iacs` matches any `iacs_*` protocol (rules store the
/// concrete IACS protocol names, e.g. `iacs_modbus`). Unknown filter
/// values match nothing (fail-closed). `None` matches everything.
#[must_use]
pub fn protocol_matches(protocols: &[String], filter: Option<&str>) -> bool {
    match filter {
        None => true,
        Some("ssh") => protocols.iter().any(|p| p == "ssh"),
        Some("rdp") => protocols.iter().any(|p| p == "rdp"),
        Some("iacs") => protocols.iter().any(|p| p.starts_with("iacs_")),
        Some(_) => false,
    }
}

/// Distinct, case-insensitively sorted option values for a filter
/// select, derived from the full (unfiltered) row set so the options
/// never shrink while filtering.
#[must_use]
pub fn distinct_sorted<'a>(values: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = values.into_iter().map(str::to_owned).collect();
    out.sort_by_key(|v| v.to_lowercase());
    out.dedup();
    out
}

/// Parse a yes/no select into an optional boolean filter. Unknown
/// values behave as "no filter" so a tampered query string degrades
/// to the unfiltered view instead of a confusing empty list.
#[must_use]
pub fn parse_yes_no(filter: Option<&str>) -> Option<bool> {
    match filter {
        Some("yes") => Some(true),
        Some("no") => Some(false),
        _ => None,
    }
}

/// Parse an active/inactive select into an optional boolean filter.
#[must_use]
pub fn parse_active_inactive(filter: Option<&str>) -> Option<bool> {
    match filter {
        Some("active") => Some(true),
        Some("inactive") => Some(false),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Pagination-link query suffix
// ---------------------------------------------------------------------------

/// Percent-encode a query-string value (RFC 3986 unreserved set kept
/// verbatim, everything else `%XX`-encoded).
#[must_use]
pub fn urlencode(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Build the `&key=value` suffix carrying every ACTIVE filter, ready
/// to be appended to `?page=N` pagination links so switching page
/// never drops the filters. Values are percent-encoded; Askama then
/// HTML-escapes the `&` to `&amp;`, which is the correct form inside
/// an href attribute.
#[must_use]
pub fn query_suffix(pairs: &[(&str, &Option<String>)]) -> String {
    let mut out = String::new();
    for (key, value) in pairs {
        if let Some(v) = value {
            out.push('&');
            out.push_str(key);
            out.push('=');
            out.push_str(&urlencode(v));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn test_opt_filter_absent_and_empty_are_none() {
        let p = params(&[("status", "")]);
        assert_eq!(opt_filter(&p, "status"), None);
        assert_eq!(opt_filter(&p, "missing"), None);
    }

    #[test]
    fn test_opt_filter_returns_value() {
        let p = params(&[("status", "online")]);
        assert_eq!(opt_filter(&p, "status"), Some("online".to_string()));
    }

    #[test]
    fn test_parse_page_defaults_and_clamps() {
        assert_eq!(parse_page(&params(&[])), 1);
        assert_eq!(parse_page(&params(&[("page", "abc")])), 1);
        assert_eq!(parse_page(&params(&[("page", "-3")])), 1);
        assert_eq!(parse_page(&params(&[("page", "7")])), 7);
    }

    #[test]
    fn test_paginate_empty_list() {
        let w = paginate(0, 1, 30);
        assert_eq!(w.total_pages, 1);
        assert_eq!(w.page, 1);
        assert_eq!(w.start_index, 0);
        assert_eq!(w.end_index, 0);
        assert!(!w.has_previous);
        assert!(!w.has_next);
    }

    #[test]
    fn test_paginate_clamps_out_of_range_page() {
        let w = paginate(45, 9999, 30);
        assert_eq!(w.total_pages, 2);
        assert_eq!(w.page, 2);
        assert_eq!(w.offset, 30);
        assert_eq!(w.start_index, 31);
        assert_eq!(w.end_index, 45);
        assert!(w.has_previous);
        assert!(!w.has_next);
    }

    #[test]
    fn test_paginate_first_page() {
        let w = paginate(45, 1, 30);
        assert_eq!(w.offset, 0);
        assert_eq!(w.start_index, 1);
        assert_eq!(w.end_index, 30);
        assert!(!w.has_previous);
        assert!(w.has_next);
    }

    #[test]
    fn test_paginate_zero_per_page_is_safe() {
        let w = paginate(10, 1, 0);
        assert_eq!(w.per_page, 1);
        assert_eq!(w.total_pages, 10);
    }

    #[test]
    fn test_slice_page_extracts_window() {
        let items: Vec<i32> = (1..=45).collect();
        let w = paginate(items.len(), 2, 30);
        let page = slice_page(items, &w);
        assert_eq!(page.first(), Some(&31));
        assert_eq!(page.last(), Some(&45));
        assert_eq!(page.len(), 15);
    }

    #[test]
    fn test_matches_search_case_insensitive_and_blank() {
        assert!(matches_search(&["Prod Servers"], Some("prod")));
        assert!(matches_search(&["abc"], Some("  ")));
        assert!(matches_search(&["abc"], None));
        assert!(!matches_search(&["abc"], Some("xyz")));
        assert!(matches_search(&["abc", "XYZ"], Some("xy")));
    }

    #[test]
    fn test_matches_select_and_bool() {
        assert!(matches_select("ops", None));
        assert!(matches_select("ops", Some("ops")));
        assert!(!matches_select("ops", Some("dev")));
        assert!(matches_bool(true, None));
        assert!(matches_bool(false, Some(false)));
        assert!(!matches_bool(true, Some(false)));
    }

    #[test]
    fn test_protocol_matches_semantics() {
        let protos = vec!["ssh".to_string(), "iacs_modbus".to_string()];
        assert!(protocol_matches(&protos, None));
        assert!(protocol_matches(&protos, Some("ssh")));
        assert!(!protocol_matches(&protos, Some("rdp")));
        assert!(protocol_matches(&protos, Some("iacs")));
        assert!(!protocol_matches(&[], Some("iacs")));
        assert!(!protocol_matches(&protos, Some("bogus")));
    }

    #[test]
    fn test_distinct_sorted_dedups_and_sorts() {
        let out = distinct_sorted(["Ops", "admin", "Ops", "Zulu"]);
        assert_eq!(out, vec!["admin", "Ops", "Zulu"]);
    }

    #[test]
    fn test_parse_yes_no_and_active_inactive() {
        assert_eq!(parse_yes_no(Some("yes")), Some(true));
        assert_eq!(parse_yes_no(Some("no")), Some(false));
        assert_eq!(parse_yes_no(Some("bogus")), None);
        assert_eq!(parse_yes_no(None), None);
        assert_eq!(parse_active_inactive(Some("active")), Some(true));
        assert_eq!(parse_active_inactive(Some("inactive")), Some(false));
        assert_eq!(parse_active_inactive(Some("x")), None);
    }

    #[test]
    fn test_to_pagination_maps_all_fields() {
        let w = paginate(45, 2, 30);
        let p = w.to_pagination();
        assert_eq!(p.current_page, 2);
        assert_eq!(p.total_pages, 2);
        assert_eq!(p.total_items, 45);
        assert_eq!(p.items_per_page, 30);
        assert_eq!(p.start_index, 31);
        assert_eq!(p.end_index, 45);
        let a = w.to_approval_pagination();
        assert_eq!(a.total_items, 45);
        let d = w.to_audit_pagination();
        assert_eq!(d.total_items, 45_i64);
    }
}
