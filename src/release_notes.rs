//! Release-notes text helpers for client Builds / org dashboard changelogs.
//!
//! Notes stay a light `TAG: text` dialect (not full Markdown). Inline
//! `` `code` `` spans are the only rich markup rendered in the changelog
//! body.

/// One fragment of a note line after inline-code parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InlineSegment {
    /// Literal text (may contain unpaired `` ` ``).
    Text(String),
    /// Contents between a matched pair of backticks (backticks stripped).
    Code(String),
}

/// Split `text` on paired backticks into text / code segments.
///
/// Unpaired trailing backticks stay in [`InlineSegment::Text`]. Empty
/// input yields an empty vec. Empty `` ` ` `` pairs yield
/// [`InlineSegment::Code`] with an empty string.
pub fn parse_inline_code(text: &str) -> Vec<InlineSegment> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '`' {
            buf.push(ch);
            continue;
        }
        // Collect until the next backtick (if any).
        let mut code = String::new();
        let mut closed = false;
        for c in chars.by_ref() {
            if c == '`' {
                closed = true;
                break;
            }
            code.push(c);
        }
        if closed {
            if !buf.is_empty() {
                out.push(InlineSegment::Text(std::mem::take(&mut buf)));
            }
            out.push(InlineSegment::Code(code));
        } else {
            // Unpaired opener: keep the backtick + collected remainder as text.
            buf.push('`');
            buf.push_str(&code);
        }
    }
    if !buf.is_empty() {
        out.push(InlineSegment::Text(buf));
    }
    out
}

/// Flatten segments back to a plain string (code without surrounding ticks).
/// Useful for length / coverage properties in tests.
pub fn flatten_inline_segments(segs: &[InlineSegment]) -> String {
    let mut out = String::new();
    for seg in segs {
        match seg {
            InlineSegment::Text(t) | InlineSegment::Code(t) => out.push_str(t),
        }
    }
    out
}

/// True when every `` ` `` in `text` is part of a matched pair (no leftovers).
pub fn backticks_are_balanced(text: &str) -> bool {
    text.chars().filter(|c| *c == '`').count() % 2 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proptest_util;
    use proptest::prelude::*;

    #[test]
    fn parse_plain_text_is_single_segment() {
        assert_eq!(
            parse_inline_code("Prefer the system config path"),
            vec![InlineSegment::Text("Prefer the system config path".into())]
        );
    }

    #[test]
    fn parse_single_inline_code() {
        assert_eq!(
            parse_inline_code("Prefer `config/` over workspace"),
            vec![
                InlineSegment::Text("Prefer ".into()),
                InlineSegment::Code("config/".into()),
                InlineSegment::Text(" over workspace".into()),
            ]
        );
    }

    #[test]
    fn parse_multiple_inline_codes() {
        assert_eq!(
            parse_inline_code("Use `foo` and `bar`."),
            vec![
                InlineSegment::Text("Use ".into()),
                InlineSegment::Code("foo".into()),
                InlineSegment::Text(" and ".into()),
                InlineSegment::Code("bar".into()),
                InlineSegment::Text(".".into()),
            ]
        );
    }

    #[test]
    fn parse_unpaired_backtick_stays_text() {
        assert_eq!(
            parse_inline_code("see `alone"),
            vec![InlineSegment::Text("see `alone".into())]
        );
    }

    #[test]
    fn parse_empty_and_empty_code() {
        assert!(parse_inline_code("").is_empty());
        assert_eq!(
            parse_inline_code("x``y"),
            vec![
                InlineSegment::Text("x".into()),
                InlineSegment::Code(String::new()),
                InlineSegment::Text("y".into()),
            ]
        );
    }

    #[test]
    fn parse_code_only() {
        assert_eq!(
            parse_inline_code("`only`"),
            vec![InlineSegment::Code("only".into())]
        );
    }

    #[test]
    fn flatten_drops_tick_markers() {
        let segs = parse_inline_code("a `b` c");
        assert_eq!(flatten_inline_segments(&segs), "a b c");
    }

    proptest! {
        #![proptest_config(proptest_util::cases(128))]

        #[test]
        fn prop_no_backticks_is_identity_text(
            s in "[^`]{0,80}"
        ) {
            let segs = parse_inline_code(&s);
            if s.is_empty() {
                prop_assert!(segs.is_empty());
            } else {
                prop_assert_eq!(segs, vec![InlineSegment::Text(s.clone())]);
            }
        }

        #[test]
        fn prop_balanced_code_round_trips_via_markers(
            parts in prop::collection::vec("[^`]{0,12}", 1..6)
        ) {
            // Build: t0 `c0` t1 `c1` …
            let mut raw = String::new();
            for (i, part) in parts.iter().enumerate() {
                if i % 2 == 1 {
                    raw.push('`');
                    raw.push_str(part);
                    raw.push('`');
                } else {
                    raw.push_str(part);
                }
            }
            prop_assume!(backticks_are_balanced(&raw));
            let segs = parse_inline_code(&raw);
            let mut rebuilt = String::new();
            for seg in &segs {
                match seg {
                    InlineSegment::Text(t) => rebuilt.push_str(t),
                    InlineSegment::Code(c) => {
                        rebuilt.push('`');
                        rebuilt.push_str(c);
                        rebuilt.push('`');
                    }
                }
            }
            prop_assert_eq!(rebuilt, raw);
        }

        #[test]
        fn prop_flatten_never_longer_than_input(s in ".*{0,60}") {
            let segs = parse_inline_code(&s);
            prop_assert!(flatten_inline_segments(&segs).len() <= s.len());
        }
    }
}
