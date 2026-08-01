//! Source-shape invariants for admin issues search shard.

use std::process::Command;

#[test]
fn inv_check_admin_issues_search_shard_script() {
    let output = Command::new("bash")
        .arg("scripts/check_admin_issues_search_shard.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_admin_issues_search_shard.sh");
    assert!(
        output.status.success(),
        "scripts/check_admin_issues_search_shard.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_shard_rechecks_staff_before_loading() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/issues/search_shard.rs"
    ));
    assert!(src.contains("#[shard]"));
    assert!(src.contains("admin_issues_search_results"));
    assert!(src.contains("require_staff"));
    assert!(src.contains("issues_read"));
    assert!(src.contains("data-admin-issues-search-shard"));
    assert!(!src.contains("path_param"));

    let staff = src.find("require_staff(cx)").expect("require_staff(cx)");
    let read = src.find("perms.issues_read").expect("perms.issues_read");
    let load = src.find("Issue::all").expect("Issue::all");
    assert!(
        staff < read && read < load,
        "gate order: require_staff -> issues_read -> load"
    );
}

#[test]
fn inv_page_wires_query_and_org_signals() {
    let page = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/issues.rs"
    ));
    assert!(page.contains("admin_issues_search_results"));
    assert!(page.contains("org_query"));
    assert!(page.contains("normalize_org_filter") || page.contains("normalize_query"));
    assert!(
        page.contains("page: Option<u32>"),
        "AdminIssuesQuery must include page"
    );
    assert!(
        page.contains("filter_row"),
        "chips + pager must use filter_row"
    );
}

#[test]
fn inv_shard_paginates_with_page_slice() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/issues/search_shard.rs"
    ));
    assert!(
        src.contains("page_slice") && src.contains("LIST_PAGE_SIZE"),
        "shard must paginate with page_slice / LIST_PAGE_SIZE"
    );
}

#[test]
fn inv_helpers_resolve_org_filter() {
    let helpers = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/issues_search.rs"));
    assert!(helpers.contains("pub fn resolve_org_filter"));
    assert!(helpers.contains("pub fn issue_matches_org"));
}
