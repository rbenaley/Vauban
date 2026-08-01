//! Source-shape invariants for admin release manager.

use std::process::Command;

#[test]
fn inv_check_admin_releases_script() {
    let output = Command::new("bash")
        .arg("scripts/check_admin_releases.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_admin_releases.sh");
    assert!(
        output.status.success(),
        "scripts/check_admin_releases.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_admin_releases_create_is_post_and_gated() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/releases/new.rs"
    ));
    assert!(src.contains("method=\"POST\""));
    assert!(!src.contains("method=\"GET\""));
    assert!(src.contains("releases_manage"));
    assert!(src.contains("toasty::create!(Release"));
    assert!(src.contains("RELEASE_STATUS_PUBLISHED"));
}

#[test]
fn inv_admin_releases_mutation_routes() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/releases/release_id.rs"
    ));
    assert!(src.contains("/publish"));
    assert!(src.contains("/unpublish"));
    assert!(src.contains("/delete"));
    assert!(src.contains("is_delete_confirm"));
    assert!(src.contains("releases_manage"));
    assert!(src.contains("RELEASE_STATUS_PUBLISHED"));
    assert!(src.contains("RELEASE_STATUS_HIDDEN"));
}

#[test]
fn inv_admin_releases_list_actions_and_badges() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/releases.rs"
    ));
    assert!(src.contains("release_status_badge_class"));
    assert!(src.contains("cmp_version_desc"));
    assert!(src.contains("vb-row-actions"));
    assert!(src.contains("vb-col-actions"));
    assert!(src.contains("delete="));
    assert!(src.contains("ico_trash"));
    assert!(src.contains("Delete permanently"));
    assert!(src.contains("+ New release"));
    assert!(src.contains("Unpublish"));
    assert!(src.contains("Publish"));
    assert!(
        src.contains("format!(\"/admin/releases/{}\", rel.id)"),
        "Edit must link by release id"
    );
    let css = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/styles.css"));
    assert!(
        css.contains(".vb-row-actions .vb-btn.outline.compact"),
        "Publish/Unpublish must share a fixed min-width"
    );
    assert!(
        css.contains(".vb-table td.vb-col-actions"),
        "ACTIONS column must hug controls (no STATUS gap)"
    );
    assert!(
        css.contains("flex-wrap: nowrap"),
        "row actions must stay on one horizontal line"
    );
}

#[test]
fn inv_admin_releases_list_paginates() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/releases.rs"
    ));
    assert!(
        src.contains("LIST_PAGE_SIZE"),
        "admin releases must use LIST_PAGE_SIZE"
    );
    assert!(
        src.contains("list_toolbar"),
        "admin releases must use list_toolbar pager"
    );
    assert!(
        src.contains("page: Option<u32>"),
        "AdminReleasesQuery must include page"
    );
    assert!(
        src.contains("page_slice"),
        "admin releases must page_slice rows"
    );
}

#[test]
fn inv_builds_filter_published_status() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/builds.rs"
    ));
    assert!(
        src.contains("RELEASE_STATUS_PUBLISHED"),
        "customer builds must require PUBLISHED"
    );
    assert!(
        src.contains("release_visible_to_org"),
        "visibility helper must exist"
    );
}
