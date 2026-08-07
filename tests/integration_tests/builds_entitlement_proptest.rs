//! Property tests for download entitlement + package / ephemeral URL shape.

use proptest::prelude::*;
use vcp::app::{
    BUILDS_PAGE_SIZE, DL_ERROR_PARAM, DownloadError, clamp_page, download_error_href, page_count,
    page_slice, parse_page,
};
use vcp::config::{Config, Environment};
use vcp::release_pkg::{
    cmp_sort_fields_desc, cmp_version_desc, package_file_name, sha256_cmd, version_sort_fields,
};

const MSG: &str = "download unavailable";

/// Every download failure code carried back to the Builds modal.
const DL_ERRORS: &[DownloadError] = &[
    DownloadError::Missing,
    DownloadError::Unavailable,
    DownloadError::Integrity,
];

/// (version, channel, expected package basename)
const PACKAGE_CASES: &[(&str, &str, &str)] = &[
    ("v1.0.0", "LTS", "vauban-1.0.0+LTS.pkg"),
    ("v1.0.2", "LTS", "vauban-1.0.2+LTS.pkg"),
    ("v0.9.35", "Stable", "vauban-0.9.35.pkg"),
    ("v0.8.6", "EOL", "vauban-0.8.6.pkg"),
    ("1.2.3", "LTS", "vauban-1.2.3+LTS.pkg"),
];

/// Full SHA-256 digests from the GA catalog + Acme private hotfix (64 hex).
const GA_SHA256: &[&str] = &[
    "ccff72c653fc1ad3ea4bc41fe4e56df03daa990b914017c7ab3419315bca6657",
    "9fef561cfde2aa3634de40ff3530d55072bd75ad9ae531faaff01c3d786c8336",
    "c2b1f7dfa88ec9b77eb19dfaefe70ff25a75bb6877191f84609c637a75d2fc26",
    "f4845978eb3adeab48cf20111c32cca46d5bbdad3e81b182e20168d55c33f9b8",
    "d896decde9ad8b2c280690e17339698f5a6d05dd63a175e050d17b76e8f6d04e",
    "9c404b9a11a18dc7afed63acb87aff355cd53a6d3e1425ffc87d3f448aabe93e",
    // Acme private hotfix (src/db.rs ACME_PRIVATE_SHA256)
    "b7e4d01c9e2a4f8b1d6c0e5a3f7b9d2e4c8a1f0b6d5e3c9a7f2b8d4e0c1a6953",
];

proptest! {
    #![proptest_config(crate::common::prop_config(32))]

    #[test]
    fn prop_download_message_is_stable(_n in 0u8..32) {
        prop_assert_eq!(MSG, "download unavailable");
        prop_assert!(!MSG.is_empty());
        prop_assert!(MSG.chars().all(|c| c.is_ascii_lowercase() || c == ' '));
        // Pin source constant stays aligned with the proptest corpus.
        let src = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/app/org/builds/download.rs"
        ));
        prop_assert!(src.contains("DOWNLOAD_UNAVAILABLE"));
        prop_assert!(src.contains(MSG));
    }

    #[test]
    fn prop_download_error_href_returns_to_open_build(
        ix in 0usize..DL_ERRORS.len(),
        slug in "[a-z][a-z0-9-]{2,20}",
        ver in "v[0-9]\\.[0-9]{1,2}\\.[0-9]{1,2}",
        channel in prop::option::of(prop::sample::select(vec!["LTS", "Stable", "EOL"])),
    ) {
        let err = DL_ERRORS[ix];
        let channel = channel.unwrap_or("");
        let href = download_error_href(&slug, &ver, channel, err);
        let open_prefix = format!("/{slug}/builds/{ver}?");
        let code_suffix = format!("{DL_ERROR_PARAM}={}", err.as_code());
        let channel_part = format!("channel={channel}");

        prop_assert!(href.starts_with(&open_prefix));
        prop_assert_eq!(href.matches('?').count(), 1);
        prop_assert_eq!(href.matches(DL_ERROR_PARAM).count(), 1);
        prop_assert!(href.ends_with(&code_suffix));
        prop_assert_eq!(href.contains("channel="), !channel.is_empty());
        if !channel.is_empty() {
            prop_assert!(href.contains(&channel_part));
        }
        prop_assert!(!href.contains(' '));
        // Round-trip: the page can only resolve codes the handler emits.
        prop_assert_eq!(DownloadError::from_code(err.as_code()), Some(err));
    }

    #[test]
    fn prop_unknown_dl_error_codes_never_open_the_modal(code in "[a-zA-Z<>/ ]{0,12}") {
        let known = DL_ERRORS.iter().any(|e| e.as_code() == code);
        prop_assert_eq!(DownloadError::from_code(&code).is_some(), known);
    }

    #[test]
    fn prop_package_file_name_table(ix in 0usize..PACKAGE_CASES.len()) {
        let (ver, channel, expected) = PACKAGE_CASES[ix];
        prop_assert_eq!(package_file_name(ver, channel), expected);
        prop_assert_eq!(
            sha256_cmd(expected),
            format!("sha256 {expected}")
        );
    }

    #[test]
    fn prop_ga_sha256_digests_are_64_hex(ix in 0usize..GA_SHA256.len()) {
        let digest = GA_SHA256[ix];
        prop_assert_eq!(digest.len(), 64);
        prop_assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn prop_version_desc_orders_by_number_not_lexicographic(
        minor in 1u64..40,
        patch in 0u64..40,
    ) {
        let lower = format!("v0.{minor}.{patch}");
        let higher = format!("v1.0.{patch}");
        prop_assert_eq!(cmp_version_desc(&higher, &lower), std::cmp::Ordering::Less);
        // Lexicographic string order can disagree (e.g. v0.9 vs v0.10); numeric must win.
        let a = format!("v0.9.{patch}");
        let b = format!("v0.10.{patch}");
        prop_assert_eq!(cmp_version_desc(&b, &a), std::cmp::Ordering::Less);
    }

    #[test]
    fn prop_client_suffix_sorts_above_plain_and_alpha_by_name(
        patch in 0u64..20,
        name_a in "[a-z]{3,8}",
        name_b in "[a-z]{3,8}",
    ) {
        prop_assume!(name_a != name_b);
        let plain = format!("v0.8.{patch}");
        let client_a = format!("v0.8.{patch}-{name_a}");
        let client_b = format!("v0.8.{patch}-{name_b}");
        prop_assert_eq!(cmp_version_desc(&client_a, &plain), std::cmp::Ordering::Less);
        let (first, second) = if name_a < name_b {
            (&client_a, &client_b)
        } else {
            (&client_b, &client_a)
        };
        prop_assert_eq!(cmp_version_desc(first, second), std::cmp::Ordering::Less);
    }

    #[test]
    fn prop_sort_fields_agree_with_cmp_version_desc(
        maj_a in 0u64..5,
        min_a in 0u64..20,
        pat_a in 0u64..20,
        maj_b in 0u64..5,
        min_b in 0u64..20,
        pat_b in 0u64..20,
        suffix_a in prop::option::of("[a-z]{2,6}"),
        suffix_b in prop::option::of("[a-z]{2,6}"),
    ) {
        let a = match &suffix_a {
            Some(s) => format!("v{maj_a}.{min_a}.{pat_a}-{s}"),
            None => format!("v{maj_a}.{min_a}.{pat_a}"),
        };
        let b = match &suffix_b {
            Some(s) => format!("v{maj_b}.{min_b}.{pat_b}-{s}"),
            None => format!("v{maj_b}.{min_b}.{pat_b}"),
        };
        prop_assert_eq!(
            cmp_version_desc(&a, &b),
            cmp_sort_fields_desc(&version_sort_fields(&a), &version_sort_fields(&b))
        );
    }

    #[test]
    fn prop_eph_url_uses_configured_public_origin_and_token(
        token in "[a-f0-9-]{8,36}",
        ver in "v?[0-9]\\.[0-9]\\.[0-9]",
    ) {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config");
        let cfg = Config::load_with_environment(&dir, Environment::Testing).unwrap();
        let origin = cfg.primary_public_origin();
        prop_assert!(origin.starts_with("https://"));
        let pkg = package_file_name(&ver, "Stable");
        let url = format!("{origin}/releases/{token}/{pkg}");
        let prefix = format!("{origin}/releases/");
        prop_assert!(url.starts_with(&prefix));
        prop_assert!(url.contains(&token));
        prop_assert!(url.ends_with(".pkg"));
        prop_assert!(!url.contains("vauban-v"), "package must strip leading v: {url}");
        prop_assert!(!url.contains(' '));
    }

    #[test]
    fn prop_production_primary_origin_is_access_host(_n in 0u8..4) {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config");
        let cfg = Config::load_with_environment(&dir, Environment::Production).unwrap();
        prop_assert_eq!(cfg.primary_public_origin(), "https://access.vauban.sh");
    }

    #[test]
    fn prop_list_page_count_and_slice_for_totals(total in 0usize..=40, raw_page in 0u32..20) {
        prop_assert_eq!(BUILDS_PAGE_SIZE, 10);
        prop_assert_eq!(vcp::list_page::LIST_PAGE_SIZE, BUILDS_PAGE_SIZE);
        let pages = page_count(total, BUILDS_PAGE_SIZE);
        let expected_pages = if total == 0 {
            1
        } else {
            total.div_ceil(BUILDS_PAGE_SIZE)
        };
        prop_assert_eq!(pages, expected_pages.max(1));

        let items: Vec<usize> = (0..total).collect();
        let page = clamp_page(parse_page(Some(raw_page)), pages);
        let slice = page_slice(&items, page, BUILDS_PAGE_SIZE);
        if total == 0 {
            prop_assert!(slice.is_empty());
        } else {
            let start = (page - 1) * BUILDS_PAGE_SIZE;
            let end = (start + BUILDS_PAGE_SIZE).min(total);
            prop_assert_eq!(slice.len(), end.saturating_sub(start));
            prop_assert!(slice.len() <= BUILDS_PAGE_SIZE);
        }
        // Out-of-range page clamps to last page.
        let past = page_slice(&items, pages + 5, BUILDS_PAGE_SIZE);
        let last = page_slice(&items, pages, BUILDS_PAGE_SIZE);
        prop_assert_eq!(past, last);
    }
}
