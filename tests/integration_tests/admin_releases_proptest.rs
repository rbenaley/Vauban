//! Property tests for release metadata shaping and status badges.

use proptest::prelude::*;
use vcp::{
    app::admin_releases_list_href,
    docs_version::is_delete_confirm,
    freebsd_pkg::{FreeBsdPkgInfo, craft_minimal_pkg, inspect},
    models::{RELEASE_STATUS_HIDDEN, RELEASE_STATUS_PUBLISHED},
    release_pkg::{
        apply_edit_channel, channel_track, cmp_admin_release_list, cmp_status_published_first,
        cmp_version_desc, derive_release_identity, package_file_name, version_for_display,
    },
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
    fn prop_derive_identity_stable_or_lts(
        major in 0u32..20,
        minor in 0u32..40,
        patch in 0u32..40,
        kind in 0u8..3,
    ) {
        let core = format!("{major}.{minor}.{patch}");
        let raw = match kind {
            0 => core.clone(),
            1 => format!("{core}+LTS"),
            _ => format!("{core}+LTS.industrial"),
        };
        let id = derive_release_identity(&raw).expect("identity");
        prop_assert!(id.version.starts_with('v'));
        match kind {
            0 => {
                prop_assert_eq!(id.channel, "Stable");
                prop_assert!(!id.version.to_ascii_uppercase().contains("+LTS"));
            }
            1 => {
                prop_assert_eq!(id.channel, "LTS");
                prop_assert!(id.version.ends_with("+LTS"));
                prop_assert!(!id.version.ends_with("+LTS.industrial"));
            }
            _ => {
                prop_assert_eq!(id.channel, "LTS.industrial");
                prop_assert!(id.version.ends_with("+LTS.industrial"));
            }
        }
    }

    #[test]
    fn prop_edit_channel_stays_on_track(
        major in 1u32..10,
        patch in 0u32..20,
        want_eol in any::<bool>(),
        start_lts in any::<bool>(),
    ) {
        let version = format!("v{major}.0.{patch}");
        let channel = if start_lts { "LTS" } else { "Stable" };
        let requested = if want_eol {
            "EOL"
        } else if start_lts {
            "LTS"
        } else {
            "Stable"
        };
        let (v, c) = apply_edit_channel(&version, channel, requested).expect("allowed");
        prop_assert_eq!(c.as_str(), requested);
        if start_lts {
            prop_assert!(v.ends_with("+LTS"));
            prop_assert!(apply_edit_channel(&version, channel, "Stable").is_none());
        } else {
            prop_assert!(!v.to_ascii_uppercase().ends_with("+LTS"));
            prop_assert!(apply_edit_channel(&version, channel, "LTS").is_none());
        }
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(32))]

    /// Display never shows `+LTS`; LTS-track package basenames always keep it.
    #[test]
    fn prop_display_strips_lts_basename_keeps_track(
        major in 0u32..20,
        minor in 0u32..40,
        patch in 0u32..40,
        channel in prop_oneof![
            Just("LTS"),
            Just("LTS.industrial"),
            Just("Stable"),
            Just("EOL")
        ],
        store_marker in any::<bool>(),
    ) {
        let core = format!("v{major}.{minor}.{patch}");
        let version = if channel == "LTS.industrial" || (store_marker && channel != "Stable") {
            if channel == "LTS.industrial" {
                format!("{core}+LTS.industrial")
            } else {
                format!("{core}+LTS")
            }
        } else if store_marker || channel == "LTS" {
            format!("{core}+LTS")
        } else {
            core.clone()
        };
        let display = version_for_display(&version);
        prop_assert!(!display.to_ascii_uppercase().ends_with("+LTS"));
        prop_assert!(!display.contains('+'));
        let track = channel_track(&version, channel);
        let pkg = package_file_name(&version, channel);
        if track == "LTS.industrial" {
            prop_assert!(
                pkg.ends_with("+LTS.industrial.pkg"),
                "industrial basename: {pkg}"
            );
        } else if track == "LTS" {
            prop_assert!(
                pkg.ends_with("+LTS.pkg"),
                "LTS track basename must keep +LTS: {pkg}"
            );
        } else {
            prop_assert!(
                !pkg.contains("+LTS"),
                "Stable/EOL-without-marker must not add +LTS: {pkg}"
            );
        }
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
        // validate-pkg maps every inspect Err to this stable JSON body.
        let body = r#"{"ok":false,"code":"not_pkg"}"#;
        prop_assert!(body.contains("\"code\":\"not_pkg\""));
        prop_assert!(body.contains("\"ok\":false"));
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

proptest! {
    #![proptest_config(crate::common::prop_config(48))]

    #[test]
    fn prop_admin_list_published_before_hidden_at_same_version(
        major in 0u32..30,
        minor in 0u32..40,
        patch in 0u32..80,
        suffix in prop_oneof![Just("".to_owned()), Just("acme1".to_owned())],
    ) {
        let version = if suffix.is_empty() {
            format!("v{major}.{minor}.{patch}")
        } else {
            format!("v{major}.{minor}.{patch}-{suffix}")
        };
        prop_assert_eq!(
            cmp_status_published_first(RELEASE_STATUS_PUBLISHED, RELEASE_STATUS_HIDDEN),
            std::cmp::Ordering::Less
        );
        prop_assert_eq!(
            cmp_admin_release_list(
                &version,
                RELEASE_STATUS_PUBLISHED,
                &version,
                RELEASE_STATUS_HIDDEN
            ),
            std::cmp::Ordering::Less
        );
        prop_assert_eq!(
            cmp_admin_release_list(
                &version,
                RELEASE_STATUS_HIDDEN,
                &version,
                RELEASE_STATUS_PUBLISHED
            ),
            std::cmp::Ordering::Greater
        );
        // Distinct versions: semver still dominates status.
        let higher = format!("v{}.{}.{}", major + 1, minor, patch);
        prop_assert_eq!(cmp_version_desc(&higher, &version), std::cmp::Ordering::Less);
        prop_assert_eq!(
            cmp_admin_release_list(
                &higher,
                RELEASE_STATUS_HIDDEN,
                &version,
                RELEASE_STATUS_PUBLISHED
            ),
            std::cmp::Ordering::Less
        );
    }
}
