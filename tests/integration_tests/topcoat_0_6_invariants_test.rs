//! Source-shape invariants for the Topcoat 0.6.2 pin.

use std::process::Command;

#[test]
fn inv_check_topcoat_0_6_script() {
    let output = Command::new("bash")
        .arg("scripts/check_topcoat_0_6.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_topcoat_0_6.sh");
    assert!(
        output.status.success(),
        "scripts/check_topcoat_0_6.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_config_files_declare_request_body_mib() {
    for rel in [
        "config/vcp.conf",
        "config/default.toml",
        "config/development.toml",
        "config/testing.toml",
    ] {
        let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel);
        let body = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel}: {e}"));
        assert!(
            body.contains("max_request_body_mib"),
            "{rel} must declare max_request_body_mib"
        );
    }
}
