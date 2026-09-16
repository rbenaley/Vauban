//! Source-shape invariants for org issues search shard.

use std::process::Command;

#[test]
fn inv_check_org_issues_search_shard_script() {
    let output = Command::new("bash")
        .arg("scripts/check_org_issues_search_shard.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_org_issues_search_shard.sh");
    assert!(
        output.status.success(),
        "scripts/check_org_issues_search_shard.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_shard_never_reads_org_from_path_params() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues/search_shard.rs"
    ));
    assert!(src.contains("#[shard]"));
    assert!(src.contains("issues_search_results"));
    assert!(
        !src.contains("path_param"),
        "shard POSTs lack {{org}}; path_param panics (use org_slug arg)"
    );
}

#[test]
fn inv_shard_reauthorizes_before_loading_issues() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues/search_shard.rs"
    ));
    let normalize = src
        .find("normalize_org_slug(&org_slug)")
        .expect("normalize_org_slug(&org_slug)");
    let require = src.find("require_org(cx").expect("require_org(cx");
    let issues_read = src.find("perms.issues_read").expect("perms.issues_read");
    let load = src
        .find("load_filtered_issues_page(cx")
        .expect("load_filtered_issues_page(cx");
    assert!(
        normalize < require && require < issues_read && issues_read < load,
        "gate order: normalize_org_slug -> require_org -> issues_read -> load"
    );
    assert!(
        src.contains("load_filtered_issues_page"),
        "shard must page via load_filtered_issues_page"
    );
    let page = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues.rs"
    ));
    assert!(
        page.contains("LIST_PAGE_SIZE") && page.contains(".limit(") && page.contains(".offset("),
        "issues loader must SQL page with limit/offset"
    );
}

#[test]
fn inv_shard_links_use_authorized_context_slug() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues/search_shard.rs"
    ));
    assert!(src.contains("ctx.org.slug"));
    assert!(src.contains("data-issues-search-shard"));
    // Lot F: stable row id for the 0.8 morph (reorders follow the row).
    assert!(
        src.contains("id=(row_dom_id(\"issue\", "),
        "shard rows must carry id=(row_dom_id(..))"
    );
}

#[test]
fn inv_page_passes_org_slug_shard_arg() {
    let page = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues.rs"
    ));
    assert!(page.contains("issues_search_results"));
    assert!(page.contains("org_slug:"));
    assert!(
        page.contains("page: Option<u32>"),
        "IssuesQuery must include page"
    );
    assert!(
        page.contains("filter_row"),
        "chips + pager must use filter_row"
    );
}

#[test]
fn inv_pure_helpers_module_exported() {
    let lib = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
    assert!(lib.contains("pub mod issues_search"));
}
