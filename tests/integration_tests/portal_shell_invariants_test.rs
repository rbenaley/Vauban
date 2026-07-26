//! Source-shape invariants for portal shell chrome (layouts + nav).

use std::path::Path;
use std::process::Command;

#[test]
fn inv_check_portal_shell_script() {
    let output = Command::new("bash")
        .arg("scripts/check_portal_shell.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_portal_shell.sh");
    assert!(
        output.status.success(),
        "scripts/check_portal_shell.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_no_legacy_layout_module() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(
        !root.join("src/layout.rs").exists(),
        "legacy src/layout.rs must stay removed"
    );
}

#[test]
fn inv_org_layout_chrome_pins() {
    let org = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/org.rs"));
    assert!(org.contains("#[layout]"));
    assert!(org.contains("vb_rail"));
    assert!(org.contains("vb_topbar"));
    assert!(org.contains("show_admin: perms.admin_view"));
    assert!(org.contains("nav_from_cx"));
    assert!(org.contains("vb-shell"));
}

#[test]
fn inv_login_and_root_layout_pins() {
    let login = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/login.rs"));
    assert!(login.contains("#[layout]"));
    assert!(login.contains("vb-login-body"));

    let app = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app.rs"));
    assert!(app.contains("#[layout]"));
    assert!(app.contains("runtime::script"));
    assert!(app.contains("stylesheet!"));
}

#[test]
fn inv_nav_from_path_exists() {
    let nav = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/nav.rs"));
    assert!(nav.contains("pub fn nav_from_path"));
    assert!(nav.contains("pub fn nav_from_cx"));
}
