//! Property tests for org chrome path → nav mapping.

use proptest::prelude::*;
use vcp::nav::{NavSection, nav_from_path};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn prop_nav_from_path_never_panics_and_crumb_non_empty(
        org in "[a-z0-9-]{1,24}",
        tail in prop::option::of("[a-z0-9/_-]{0,48}"),
    ) {
        let path = match &tail {
            Some(t) if !t.is_empty() => format!("/{org}/{t}"),
            _ => format!("/{org}"),
        };
        let (section, crumb) = nav_from_path(&path);
        prop_assert!(!crumb.is_empty());
        let _ = section;
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_unknown_member_section_maps_home(seg in "[a-z]{3,12}") {
        prop_assume!(!matches!(
            seg.as_str(),
            "docs" | "builds" | "issues" | "account" | "admin"
        ));
        let path = format!("/acme/{seg}");
        let (section, crumb) = nav_from_path(&path);
        prop_assert_eq!(section, NavSection::Home);
        prop_assert_eq!(crumb, "dashboard");
    }
}
