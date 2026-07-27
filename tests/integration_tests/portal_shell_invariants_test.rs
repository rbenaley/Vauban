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
fn inv_rail_active_uses_accent_color_mix() {
    let css = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/styles.css"));
    assert!(
        css.contains("color-mix(in srgb, var(--accent) 26%, #14171c)"),
        "active rail background must use accent mix on rail bg"
    );
    assert!(
        css.contains("color-mix(in srgb, var(--accent) 58%, #fff)"),
        "active rail foreground must use accent mix on white"
    );
    assert!(
        css.contains("--rail-idle: #6b7280"),
        "rail idle token must be #6b7280"
    );
    assert!(
        !css.contains("a.vb-rail-item.active {\n  background: var(--accent);"),
        "active rail must not use solid accent fill"
    );
}

#[test]
fn inv_org_layout_chrome_pins() {
    let org = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/org.rs"));
    assert!(org.contains("#[layout]"));
    assert!(org.contains("vb_rail"));
    assert!(org.contains("vb_topbar"));
    let rail = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/_components/rail.rs"
    ));
    assert!(
        rail.contains("admin_view"),
        "vb_rail must gate ADMIN via admin_view"
    );
    assert!(
        rail.contains("require_org"),
        "vb_rail must resolve org via require_org"
    );
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
    assert!(app.contains("rel=\"icon\""));
    assert!(app.contains("apple-touch-icon"));
    assert!(app.contains("assets/favicon.svg"));
    assert!(app.contains("assets/favicon.ico"));
    assert!(app.contains("assets/apple-touch-icon.png"));
    assert!(app.contains("GET \"/favicon.ico\""));
    assert!(app.contains("GET \"/apple-touch-icon.png\""));
    assert!(app.contains("GET \"/apple-touch-icon-precomposed.png\""));

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for rel in [
        "assets/favicon.svg",
        "assets/favicon.ico",
        "assets/favicon-16x16.png",
        "assets/favicon-32x32.png",
        "assets/apple-touch-icon.png",
        "assets/apple-touch-icon-precomposed.png",
    ] {
        assert!(root.join(rel).exists(), "missing {rel}");
    }
}

#[test]
fn inv_nav_from_path_exists() {
    let nav = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/nav.rs"));
    assert!(nav.contains("pub fn nav_from_path"));
    assert!(nav.contains("pub fn nav_from_cx"));
}
