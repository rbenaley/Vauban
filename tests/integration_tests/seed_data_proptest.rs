//! Property tests for demo / minimal doc slug inventories.

use proptest::prelude::*;
use vcp::db::{DEMO_DOC_COUNT, MINIMAL_DOC_SLUG, demo_doc_catalog, extra_demo_doc_catalog};

proptest! {
    #![proptest_config(crate::common::prop_config(64))]

    #[test]
    fn prop_demo_catalog_contains_quick_start_and_size_seven(
        // Drive cases; inventory is fixed — assert invariants each time.
        _n in 0u8..32,
    ) {
        let catalog = demo_doc_catalog();
        prop_assert_eq!(catalog.len(), DEMO_DOC_COUNT);
        prop_assert_eq!(DEMO_DOC_COUNT, 7);

        let slugs: Vec<&str> = catalog.iter().map(|(_, _, _, s)| *s).collect();
        prop_assert!(
            slugs.contains(&MINIMAL_DOC_SLUG),
            "demo catalog must include quick-start"
        );

        let unique: std::collections::HashSet<&str> = slugs.iter().copied().collect();
        prop_assert_eq!(unique.len(), slugs.len(), "demo slugs must be unique");

        let extras = extra_demo_doc_catalog();
        prop_assert_eq!(extras.len(), DEMO_DOC_COUNT - 1);
        prop_assert!(
            extras.iter().all(|(_, _, _, s)| *s != MINIMAL_DOC_SLUG),
            "extra catalog must exclude quick-start"
        );

        let minimal_only: Vec<&str> = slugs
            .iter()
            .copied()
            .filter(|s| *s == MINIMAL_DOC_SLUG)
            .collect();
        prop_assert_eq!(minimal_only.as_slice(), &[MINIMAL_DOC_SLUG]);
    }
}
