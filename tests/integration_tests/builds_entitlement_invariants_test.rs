//! Source-shape invariants for builds download entitlement.

use std::process::Command;

#[test]
fn inv_check_builds_entitlement_script() {
    let output = Command::new("bash")
        .arg("scripts/check_builds_entitlement.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_builds_entitlement.sh");
    assert!(
        output.status.success(),
        "scripts/check_builds_entitlement.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_download_route_gates_and_returns_501_message() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/builds/download.rs"
    ));
    assert!(src.contains("builds_download"));
    assert!(src.contains("download not configured"));
    assert!(src.contains("NOT_IMPLEMENTED"));
    assert!(src.contains("forbidden"));
    assert!(src.contains("require_org"));
}
