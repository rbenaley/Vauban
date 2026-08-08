//! Property tests for admin docs slug / status helpers + dialect escaping.

use proptest::prelude::*;
use vcp::{
    docs_body::{self, Block},
    list_page::LIST_PAGE_SIZE,
    models::{DOC_STATUS_DRAFT, DOC_STATUS_PUBLISHED},
    release_notes::{InlineSegment, flatten_inline_segments, parse_inline_code},
    slug::slugify,
};

#[test]
fn prop_list_page_size_is_ten() {
    assert_eq!(LIST_PAGE_SIZE, 10);
}

proptest! {
    #![proptest_config(crate::common::prop_config(32))]

    #[test]
    fn prop_slugify_is_url_safe(title in "[A-Za-z0-9 _-]{1,48}") {
        let s = slugify(&title);
        prop_assert!(!s.is_empty());
        prop_assert!(s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
        prop_assert!(!s.starts_with('-'));
        prop_assert!(!s.ends_with('-'));
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(16))]

    #[test]
    fn prop_publish_flag_maps_status(publish in proptest::bool::ANY) {
        let status = if publish {
            DOC_STATUS_PUBLISHED
        } else {
            DOC_STATUS_DRAFT
        };
        prop_assert!(status == "PUBLISHED" || status == "DRAFT");
        prop_assert_ne!(DOC_STATUS_DRAFT, DOC_STATUS_PUBLISHED);
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(24))]

    #[test]
    fn prop_bump_version_increments(n in 1u32..200) {
        let cur = format!("v{n}");
        let next = vcp::docs_version::bump_version(&cur);
        prop_assert_eq!(next, format!("v{}", n + 1));
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(48))]

    #[test]
    fn prop_delete_confirm_only_exact_delete(
        s in "[A-Za-z0-9 _]{0,24}"
    ) {
        let ok = vcp::docs_version::is_delete_confirm(&s);
        prop_assert_eq!(ok, s.trim() == "delete");
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(40))]

    #[test]
    fn prop_docs_body_escape_neutralizes_angle_brackets(
        raw in "[A-Za-z0-9 <>\"'&]{0,80}"
    ) {
        let escaped = docs_body::escape_html(&raw);
        prop_assert!(!escaped.contains('<'));
        prop_assert!(!escaped.contains('>'));
        if raw.contains('<') {
            prop_assert!(escaped.contains("&lt;"));
        }
        let blocks = docs_body::parse(&raw);
        for block in blocks {
            match block {
                Block::Paragraph(t) | Block::Heading(t) | Block::Pre(t) | Block::Callout(t) => {
                    let again = docs_body::escape_html(&t);
                    prop_assert!(!again.contains('<'));
                }
                Block::List(items) => {
                    for item in items {
                        prop_assert!(!docs_body::escape_html(&item).contains('<'));
                    }
                }
            }
        }
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(48))]

    /// Block parse keeps paired backticks so the page can chip them; flatten
    /// of inline segments equals the prose without the delimiter ticks.
    #[test]
    fn prop_docs_prose_inline_code_round_trip(
        before in "[A-Za-z0-9.,]{0,24}",
        code in "[A-Za-z0-9_=/.-]{1,32}",
        after in "[A-Za-z0-9.,]{0,24}",
    ) {
        prop_assume!(!code.contains('`'));
        // No leading/trailing whitespace: docs_body::parse trims paragraphs.
        let para = format!("{before}`{code}`{after}");
        let src = format!("{para}\n");
        let blocks = docs_body::parse(&src);
        prop_assert!(matches!(
            &blocks[..],
            [Block::Paragraph(p)] if p == &para
        ));
        let segs = parse_inline_code(&para);
        prop_assert!(segs.iter().any(|s| matches!(s, InlineSegment::Code(c) if c == &code)));
        prop_assert_eq!(flatten_inline_segments(&segs), format!("{before}{code}{after}"));
    }
}
