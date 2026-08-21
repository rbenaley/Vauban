//! Properties: comment dialect parse vs raw mail excerpt.

use proptest::prelude::*;
use vcp::docs_body::{self, Block};
use vcp::issue_notify::excerpt_text;

proptest! {
    #![proptest_config(crate::common::prop_config(32))]

    #[test]
    fn prop_excerpt_keeps_fence_markers_when_present(inner in "[a-zA-Z0-9 _]{1,40}") {
        let src = format!("Note:\n\n```\n{inner}\n```\n");
        let excerpt = excerpt_text(&src);
        prop_assert!(
            excerpt.contains("```"),
            "mail excerpt must stay raw: {excerpt}"
        );
        prop_assert!(excerpt.contains(&inner));
    }

    #[test]
    fn prop_parse_turns_fences_into_pre(inner in "[a-zA-Z0-9 _]{1,40}") {
        let src = format!("Note:\n\n```\n{inner}\n```\n");
        let blocks = docs_body::parse(&src);
        prop_assert!(
            blocks.iter().any(|b| matches!(b, Block::Pre(t) if t == &inner)),
            "page parse must emit Pre({inner}): {blocks:?}"
        );
    }
}
