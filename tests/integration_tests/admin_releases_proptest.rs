//! Property tests for release metadata shaping and status badges.

use proptest::prelude::*;
use vcp::{
    app::admin_releases_list_href,
    docs_version::is_delete_confirm,
    freebsd_pkg::{FreeBsdPkgInfo, craft_minimal_pkg, inspect},
    models::{RELEASE_STATUS_HIDDEN, RELEASE_STATUS_PUBLISHED},
    ui::release_status_badge_class,
};

proptest! {
    #![proptest_config(crate::common::prop_config(48))]

    #[test]
    fn prop_admin_releases_list_href_shape(
        channel in prop_oneof![Just(""), Just("LTS"), Just("Stable"), Just("EOL")],
        page in 1usize..20,
    ) {
        let href = admin_releases_list_href(channel, page);
        prop_assert!(href.starts_with("/admin/releases"));
        if channel.is_empty() {
            prop_assert!(!href.contains("channel="));
        } else {
            let needle = format!("channel={channel}");
            prop_assert!(href.contains(&needle));
        }
        if page <= 1 {
            prop_assert!(!href.contains("page="));
        } else {
            let needle = format!("page={page}");
            prop_assert!(href.contains(&needle));
        }
        // Chip transitions reset to page 1 — the helper must never sticky-carry
        // delete/err overlays into shareable list URLs.
        prop_assert!(!href.contains("delete="));
        prop_assert!(!href.contains("err="));
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(32))]

    #[test]
    fn prop_release_version_trim(raw in " *test-[a-z0-9.]{1,24} *") {
        let version = raw.trim().to_owned();
        prop_assume!(!version.is_empty());
        prop_assert!(version.starts_with("test-"));
        prop_assert_eq!(version.as_str(), version.trim());
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(16))]

    #[test]
    fn prop_channel_is_known(channel in prop_oneof!["LTS", "Stable", "EOL"]) {
        prop_assert!(matches!(channel.as_str(), "LTS" | "Stable" | "EOL"));
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(24))]

    #[test]
    fn prop_status_badge_mapping(
        status in prop_oneof![
            Just(RELEASE_STATUS_PUBLISHED.to_owned()),
            Just(RELEASE_STATUS_HIDDEN.to_owned()),
            Just("published".to_owned()),
            Just("hidden".to_owned()),
            Just("DRAFT".to_owned()),
            Just("unknown".to_owned()),
        ]
    ) {
        let class = release_status_badge_class(&status);
        let upper = status.trim().to_ascii_uppercase();
        match upper.as_str() {
            "PUBLISHED" => prop_assert_eq!(class, "vb-badge status-published"),
            "HIDDEN" => prop_assert_eq!(class, "vb-badge status-hidden"),
            _ => prop_assert_eq!(class, "vb-badge soft"),
        }
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(32))]

    #[test]
    fn prop_delete_confirm_only_exact_delete(
        s in prop::collection::vec(prop::char::range('a', 'z'), 0..12)
            .prop_map(|v| v.into_iter().collect::<String>())
    ) {
        let ok = is_delete_confirm(&s);
        prop_assert_eq!(ok, s.trim() == "delete");
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(48))]

    /// Random garbage is never a FreeBSD package (fail closed).
    #[test]
    fn prop_inspect_rejects_random_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..512)
    ) {
        // Tiny crafted pkgs are well under 512 bytes of entropy odds; still,
        // a random corpus must not parse as a valid package.
        prop_assert!(inspect(&bytes).is_err());
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(24))]

    /// Crafted packages with arbitrary safe field strings round-trip.
    #[test]
    fn prop_craft_inspect_round_trip(
        name in "[a-z][a-z0-9_]{0,12}",
        version in "[0-9]\\.[0-9]\\.[0-9]{1,3}",
        origin_cat in "[a-z]{3,10}",
        origin_port in "[a-z][a-z0-9_]{0,12}",
        comment in "[A-Za-z0-9 .,_-]{4,48}",
    ) {
        let info = FreeBsdPkgInfo {
            name: name.clone(),
            version: version.clone(),
            origin: format!("{origin_cat}/{origin_port}"),
            architecture: "FreeBSD:15:amd64".into(),
            prefix: "/usr/local".into(),
            categories: vec![origin_cat.clone()],
            licenses: vec!["BSD2CLAUSE".into()],
            maintainer: "none@example.org".into(),
            www: "https://example.org".into(),
            comment: comment.clone(),
            shlibs_required: vec!["libc.so.7".into()],
            freebsd_version: Some("1501000".into()),
            flatsize_bytes: Some(1_048_576),
        };
        let bytes = craft_minimal_pkg(&info);
        let parsed = inspect(&bytes).expect("crafted pkg must parse");
        prop_assert_eq!(parsed.name, name);
        prop_assert_eq!(parsed.version, version);
        prop_assert_eq!(parsed.comment, comment);
        prop_assert_eq!(parsed.prefix, "/usr/local");
        prop_assert_eq!(parsed.architecture, "FreeBSD:15:amd64");
    }
}
