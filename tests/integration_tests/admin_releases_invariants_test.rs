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
