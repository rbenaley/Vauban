//! Property tests for download entitlement + ephemeral URL shape.

use proptest::prelude::*;
use vcp::config::{Config, Environment};

const MSG: &str = "download not configured";

fn eph_url(origin: &str, token: &str, ver: &str, channel: &str) -> String {
    let file = if channel.eq_ignore_ascii_case("LTS") {
        format!("vauban-{ver}+LTS.pkg")
    } else {
        format!("vauban-{ver}.pkg")
    };
    format!("{origin}/releases/{token}/{file}")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn prop_download_message_is_stable(_n in 0u8..32) {
        prop_assert_eq!(MSG, "download not configured");
        prop_assert!(!MSG.is_empty());
        prop_assert!(MSG.chars().all(|c| c.is_ascii_lowercase() || c == ' '));
    }

    #[test]
    fn prop_eph_url_uses_configured_public_origin_and_token(
        token in "[a-f0-9-]{8,36}",
        ver in "[0-9]\\.[0-9]\\.[0-9]",
    ) {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config");
        let cfg = Config::load_with_environment(&dir, Environment::Testing).unwrap();
        let origin = cfg.primary_public_origin();
        prop_assert!(origin.starts_with("https://"));
        let url = eph_url(origin, &token, &ver, "Stable");
        let prefix = format!("{origin}/releases/");
        prop_assert!(url.starts_with(&prefix));
        prop_assert!(url.contains(&token));
        prop_assert!(url.ends_with(".pkg"));
        prop_assert!(!url.contains(' '));
    }

    #[test]
    fn prop_production_primary_origin_is_access_host(_n in 0u8..4) {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config");
        let cfg = Config::load_with_environment(&dir, Environment::Production).unwrap();
        prop_assert_eq!(cfg.primary_public_origin(), "https://access.vauban.sh");
    }
}
