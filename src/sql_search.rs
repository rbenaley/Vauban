//! SQL search helpers for Toasty PostgreSQL `ilike` patterns.

/// Escape `\`, `%`, and `_` for use with `.ilike_with_escape(..., '\\')`.
pub fn escape_ilike_literal(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Case-insensitive substring pattern for PostgreSQL `ILIKE` with escape `'\\'`.
///
/// Empty / whitespace-only needles yield `None` (caller should skip the filter).
pub fn ilike_contains(needle: &str) -> Option<String> {
    let trimmed = needle.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(format!("%{}%", escape_ilike_literal(trimmed)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn escape_ilike_literal_escapes_wildcards() {
        assert_eq!(escape_ilike_literal(r"a%b_c\d"), r"a\%b\_c\\d");
        assert_eq!(escape_ilike_literal("plain"), "plain");
    }

    #[test]
    fn ilike_contains_empty_is_none() {
        assert_eq!(ilike_contains(""), None);
        assert_eq!(ilike_contains("   "), None);
    }

    #[test]
    fn ilike_contains_wraps_escaped_needle() {
        assert_eq!(ilike_contains("  Api  ").as_deref(), Some("%Api%"));
        assert_eq!(ilike_contains("a%b").as_deref(), Some(r"%a\%b%"));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn prop_ilike_contains_none_iff_blank(s in ".*") {
            let pat = ilike_contains(&s);
            if s.trim().is_empty() {
                prop_assert!(pat.is_none());
            } else {
                let p = pat.expect("non-blank");
                prop_assert!(p.starts_with('%') && p.ends_with('%'));
                prop_assert!(!p.contains("%%") || s.trim().contains('%'));
            }
        }

        #[test]
        fn prop_escape_doubles_backslashes(s in "[\\\\%_]{0,12}") {
            let esc = escape_ilike_literal(&s);
            // Each special char gets a leading `\`; raw `\` becomes `\\`.
            let expected = s.chars().count() + s.matches('\\').count();
            prop_assert_eq!(esc.matches('\\').count(), expected);
            prop_assert_eq!(esc.len(), s.chars().count() * 2);
        }
    }
}
