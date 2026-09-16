//! Canonical URL helpers for the HTTP edge (trailing-slash normalization) and
//! the POST-error rewrite used instead of `?err=` redirects.

use http::Method;
use topcoat::router::{Body, error::RewriteError, error::rewrite};

/// Re-run the page hosting a form as `GET` after a failed POST.
///
/// Topcoat `rewrite` dispatches internally: no client redirect, the address
/// bar keeps the page URL and no error flag ever appears in it. Success paths
/// keep 303 PRG (`see_other`), so a refresh after success never re-POSTs.
///
/// Topcoat refuses a rewrite to a `path?query` the request was already
/// dispatched under (cycle guard, 500). A same-URL form must therefore target
/// the page href **with** its error query, which is also how the GET page
/// reads the code. Debug builds assert the query is present.
pub fn rewrite_get_with_flash(target: &str) -> RewriteError {
    debug_assert!(
        target.contains('?'),
        "rewrite target must carry a query so it differs from the POST dispatch: {target}"
    );
    rewrite(target, Body::empty()).method(Method::GET)
}

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

    #[test]
    fn http_edge_rewrite_flash_builds_get_rewrite_with_query() {
        let err = rewrite_get_with_flash("/admin/releases/new?err=date");
        let text = format!("{err:?}");
        assert!(text.contains("/admin/releases/new?err=date"), "{text}");
        assert!(text.contains("GET"), "rewrite must force GET: {text}");
    }

    #[test]
    #[should_panic(expected = "rewrite target must carry a query")]
    fn http_edge_rewrite_flash_refuses_bare_page_path() {
        let _ = rewrite_get_with_flash("/admin/releases/new");
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
