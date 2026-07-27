//! Source-shape invariants for browser timezone display.

use std::process::Command;

#[test]
fn inv_check_display_tz_script() {
    let output = Command::new("bash")
        .arg("scripts/check_display_tz.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_display_tz.sh");
    assert!(
        output.status.success(),
        "scripts/check_display_tz.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_admin_docs_uses_format_unix_local() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/admin/docs.rs"
    ));
    assert!(src.contains("browser_tz"));
    assert!(src.contains("format_unix_local") || src.contains("format_local"));
    assert!(
        !src.contains(".format(\"%Y-%m-%d %H:%M"),
        "no naked UTC format in admin docs list"
    );
}

#[test]
fn inv_tz_helpers_exist() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/tz.rs"));
    assert!(src.contains("VCP_TZ_COOKIE"));
    assert!(src.contains("fn format_local"));
    assert!(src.contains("fn browser_tz"));
}
