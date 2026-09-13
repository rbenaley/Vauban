//! Properties for the Topcoat 0.8.0 pin: empty Option query + no statement signals.

use proptest::prelude::*;
use topcoat::router::StatusCode;

use crate::common::{
    cleanup, create_org_with_membership, db_lock, get, login_cookie, status, test_db, test_router,
    unique_email, unique_slug,
};

fn collect_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.expect("dirent");
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(16))]

    #[test]
    fn prop_src_has_no_statement_form_signals(_seed in 0u8..8) {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let re = regex::Regex::new(r"signal\s+[A-Za-z_][A-Za-z0-9_]*\s*=").expect("regex");
        let mut files = Vec::new();
        collect_rs(&root, &mut files);
        for path in files {
            let src = std::fs::read_to_string(&path).expect("read");
            prop_assert!(
                !re.is_match(&src),
                "statement-form signal in {}",
                path.display()
            );
        }
        let _ = _seed;
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(12))]

    #[test]
    fn prop_empty_list_query_does_not_400(
        tail in prop::sample::select(vec!["", "q=", "page=", "q=&page="])
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async {
            let _guard = db_lock().lock().await;
            let db = test_db().await;
            cleanup(&db).await;
            let email = unique_email("empty-q");
            let slug = unique_slug("empty-q");
            let (_user, _org) =
                create_org_with_membership(&db, &email, "password", &slug, "admin").await;
            let router = test_router().await;
            let cookie = login_cookie(&router, &email).await;
            let qs = if tail.is_empty() { String::new() } else { format!("?{tail}") };
            for path in [
                format!("/{slug}/docs{qs}"),
                format!("/{slug}/issues{qs}"),
                format!("/admin/companies{qs}"),
                format!("/admin/issues{qs}"),
            ] {
                let resp = get(&router, &path, cookie.as_deref()).await;
                let code = status(&resp);
                assert_ne!(
                    code,
                    StatusCode::BAD_REQUEST,
                    "{path} must not 400 on empty Option query, got {code}"
                );
                assert!(
                    code.is_success() || code.is_redirection(),
                    "{path} must stay on the list surface, got {code}"
                );
            }
            cleanup(&db).await;
        });
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(8))]

    #[test]
    fn prop_short_search_query_stays_200(
        q in "[a-z0-9]{0,12}"
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async {
            let _guard = db_lock().lock().await;
            let db = test_db().await;
            cleanup(&db).await;
            let email = unique_email("short-q");
            let slug = unique_slug("short-q");
            let (_user, _org) =
                create_org_with_membership(&db, &email, "password", &slug, "member").await;
            let router = test_router().await;
            let cookie = login_cookie(&router, &email).await;
            let path = format!("/{slug}/docs?q={q}");
            let resp = get(&router, &path, cookie.as_deref()).await;
            let code = status(&resp);
            assert_eq!(code, StatusCode::OK, "{path} got {code}");
            cleanup(&db).await;
        });
    }
}
