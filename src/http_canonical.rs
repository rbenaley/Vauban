//! Canonical URL helpers for the HTTP edge (trailing-slash normalization).

use http::Method;

/// Whether this method should receive a permanent trailing-slash redirect
/// (`redirect_permanent` / HTTP 308).
///
/// Limited to safe methods so malformed POST shard/form paths stay 404
/// instead of being rewritten.
pub fn should_redirect_trailing_slash(method: &Method) -> bool {
    *method == Method::GET || *method == Method::HEAD
}

/// If `path` has a trailing slash (and is not `/`), return an origin-relative
/// Location that strips trailing slashes and preserves the query string.
///
/// Returns `None` when the path is already canonical (`/` or no trailing `/`).
pub fn trailing_slash_redirect_location(path: &str, query: Option<&str>) -> Option<String> {
    if path == "/" || !path.ends_with('/') {
        return None;
    }
    let trimmed = path.trim_end_matches('/');
    let canonical = if trimmed.is_empty() { "/" } else { trimmed };
    Some(match query {
        Some(q) if !q.is_empty() => format!("{canonical}?{q}"),
        _ => canonical.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn http_edge_root_never_redirects() {
        assert_eq!(trailing_slash_redirect_location("/", None), None);
        assert_eq!(trailing_slash_redirect_location("/", Some("x=1")), None);
    }

    #[test]
    fn http_edge_no_trailing_slash_is_canonical() {
        assert_eq!(trailing_slash_redirect_location("/login", None), None);
        assert_eq!(
            trailing_slash_redirect_location("/acme/docs", Some("q=ssh")),
            None
        );
    }

    #[test]
    fn http_edge_strips_trailing_slashes_and_keeps_query() {
        assert_eq!(
            trailing_slash_redirect_location("/login/", None).as_deref(),
            Some("/login")
        );
        assert_eq!(
            trailing_slash_redirect_location("/login///", None).as_deref(),
            Some("/login")
        );
        assert_eq!(
            trailing_slash_redirect_location("/acme/docs/", Some("q=ssh")).as_deref(),
            Some("/acme/docs?q=ssh")
        );
        assert_eq!(
            trailing_slash_redirect_location("/login/", Some("")).as_deref(),
            Some("/login")
        );
    }

    #[test]
    fn http_edge_only_get_head_redirect() {
        assert!(should_redirect_trailing_slash(&Method::GET));
        assert!(should_redirect_trailing_slash(&Method::HEAD));
        assert!(!should_redirect_trailing_slash(&Method::POST));
        assert!(!should_redirect_trailing_slash(&Method::PUT));
    }

    proptest! {
        #![proptest_config(crate::proptest_util::cases(48))]

        #[test]
        fn http_edge_prop_trailing_slash_strips_to_nonempty_path(
            segs in prop::collection::vec("[a-z0-9-]{1,8}", 1..5),
            extra_slashes in 1usize..4,
            q in prop::option::of("[a-z0-9=&.]{1,24}")
        ) {
            // e.g. `/a/b///`
            let path = format!("/{}{}", segs.join("/"), "/".repeat(extra_slashes));
            let loc = trailing_slash_redirect_location(&path, q.as_deref()).expect("redirect");
            let expected_path = format!("/{}", segs.join("/"));
            prop_assert!(!loc.ends_with('/'));
            match &q {
                Some(query) => prop_assert_eq!(loc, format!("{expected_path}?{query}")),
                None => prop_assert_eq!(loc, expected_path),
            }
        }

        #[test]
        fn http_edge_prop_idempotent_without_trailing_slash(
            segs in prop::collection::vec("[a-z0-9-]{1,8}", 1..5),
        ) {
            let path = format!("/{}", segs.join("/"));
            prop_assert_eq!(trailing_slash_redirect_location(&path, None), None);
        }
    }
}
