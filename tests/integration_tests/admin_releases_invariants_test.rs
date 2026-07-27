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
        "/src/app/org/admin/releases/new.rs"
    ));
    assert!(src.contains("method=\"POST\""));
    assert!(!src.contains("method=\"GET\""));
    assert!(src.contains("releases_manage"));
    assert!(src.contains("toasty::create!(Release"));
}
