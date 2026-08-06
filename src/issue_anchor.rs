//! Bottom-of-thread anchor for issue detail redirects (org + admin).
//!
//! The portal body scrolls inside `.vb-scroll`, not the window, so a `303`
//! back to the detail page can only land on the newest message through
//! fragment navigation. No first-party JS is involved.

/// `id` carried by the reply box, and by the closed-issue panel that replaces
/// it, so the fragment resolves whether or not replies are still accepted.
pub const ISSUE_REPLY_ANCHOR: &str = "issue-reply";

/// Append [`ISSUE_REPLY_ANCHOR`] to a detail URL, after any query string.
///
/// Idempotent: an existing fragment is replaced, never stacked.
pub fn with_reply_anchor(href: &str) -> String {
    let base = href.split('#').next().unwrap_or(href);
    format!("{base}#{ISSUE_REPLY_ANCHOR}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_matches_the_reply_box_id() {
        assert_eq!(ISSUE_REPLY_ANCHOR, "issue-reply");
    }

    #[test]
    fn appends_after_a_bare_path() {
        assert_eq!(
            with_reply_anchor("/acme/issues/VBN-200"),
            "/acme/issues/VBN-200#issue-reply"
        );
    }

    #[test]
    fn appends_after_a_query_string() {
        assert_eq!(
            with_reply_anchor("/admin/issues/VBN-200?org=acme&err=attach"),
            "/admin/issues/VBN-200?org=acme&err=attach#issue-reply"
        );
    }

    #[test]
    fn is_idempotent() {
        let once = with_reply_anchor("/acme/issues/VBN-200");
        assert_eq!(with_reply_anchor(&once), once);
    }

    #[test]
    fn replaces_a_foreign_fragment() {
        assert_eq!(
            with_reply_anchor("/acme/issues/VBN-200#issue-discussion"),
            "/acme/issues/VBN-200#issue-reply"
        );
    }
}
