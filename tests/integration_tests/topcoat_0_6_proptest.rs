//! Property: HTTP body MiB must cover storage object quotas.

use proptest::prelude::*;
use topcoat::{context::Cx, router::href};
use vcp::app::Org;
use vcp::app::hrefs::{ChannelPageQ, ErrQ, PageQ};
use vcp::config::{Config, Environment, MIB};

use crate::common::config_dir;

fn unmatched_path_is_safe(path: &str) -> bool {
    let p = path.trim_start_matches('/');
    !p.is_empty()
        && !p.starts_with("login")
        && !p.starts_with("admin")
        && !p.starts_with("releases")
        && !p.starts_with("_topcoat")
        && !p.starts_with("favicon")
        && !p.contains("..")
}

proptest! {
    #![proptest_config(crate::common::prop_config(24))]

    #[test]
    fn prop_unmatched_paths_avoid_known_prefixes(
        tail in "[a-z]{4,12}(-[a-z0-9]{2,8}){0,2}"
    ) {
        let path = format!("/{tail}");
        prop_assert!(unmatched_path_is_safe(&path));
        prop_assert!(!path.contains("//"));
        prop_assert!(!path.ends_with('/'));
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(24))]

    #[test]
    fn prop_request_body_mib_covers_quotas(
        artifact_mib in 1u64..=32,
        image_mib in 1u64..=8,
        body_mib in 0u64..=64,
    ) {
        let mut cfg = Config::load_with_environment(config_dir(), Environment::Testing)
            .expect("testing config");
        cfg.storage.max_artifact_bytes = artifact_mib.saturating_mul(MIB);
        cfg.storage.max_image_bytes = image_mib.saturating_mul(MIB);
        cfg.server.max_request_body_mib = body_mib;
        let need = artifact_mib.max(image_mib);
        if body_mib == 0 || body_mib < need {
            prop_assert!(cfg.validate().is_err());
        } else {
            prop_assert!(cfg.validate().is_ok());
            prop_assert_eq!(
                cfg.server.max_request_body_bytes() as u64,
                body_mib.saturating_mul(MIB)
            );
        }
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(24))]

    #[test]
    fn prop_href_resolve_org_admin_pages(
        slug in "[a-z][a-z0-9-]{1,12}",
        page in 1usize..8,
    ) {
        let cx = Cx::default();
        let home = href!("/{org}", Org(slug.as_str())).resolve(&cx);
        prop_assert_eq!(&home, &format!("/{slug}"));
        prop_assert!(!home.contains("//"));

        let issues = href!("/{org}/issues", Org(slug.as_str()))
            .query(PageQ { page })
            .resolve(&cx);
        if page <= 1 {
            prop_assert_eq!(issues, format!("/{slug}/issues"));
        } else {
            prop_assert_eq!(issues, format!("/{slug}/issues?page={page}"));
        }

        let list = href!("/admin/releases")
            .query(ChannelPageQ {
                channel: "LTS",
                page,
            })
            .resolve(&cx);
        if page <= 1 {
            prop_assert_eq!(list.as_str(), "/admin/releases?channel=LTS");
        } else {
            prop_assert_eq!(list, format!("/admin/releases?channel=LTS&page={page}"));
        }
        let err = href!("/admin/releases")
            .query(ErrQ { err: Some("upload") })
            .resolve(&cx);
        prop_assert_eq!(err.as_str(), "/admin/releases?err=upload");
    }
}
