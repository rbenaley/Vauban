//! Property tests for org chrome path → nav mapping + UI polish CSS pins.

use proptest::prelude::*;
use vcp::nav::{NavSection, nav_from_path};

/// CSS polish substrings that must remain in `styles.css`.
const UI_POLISH_CSS_PINS: &[&str] = &[
    "font-variant-numeric: tabular-nums",
    "scale(0.96)",
    "-webkit-font-smoothing: antialiased",
    "text-wrap: balance",
    "text-wrap: pretty",
    "border-radius: 6px",
    "min-width: 40px",
    "min-height: 40px",
];

proptest! {
    #![proptest_config(crate::common::prop_config(48))]

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
    #![proptest_config(crate::common::prop_config(32))]

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

proptest! {
    #![proptest_config(crate::common::prop_config(64))]

    #[test]
    fn prop_ui_polish_css_pins_present(pin in prop::sample::select(UI_POLISH_CSS_PINS)) {
        let css = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/styles.css"));
        prop_assert!(
            css.contains(pin),
            "styles.css missing polish pin: {pin}"
        );
    }
}
