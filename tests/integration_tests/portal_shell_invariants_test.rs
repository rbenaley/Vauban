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
fn inv_layouts_use_topcoat_05_slot_result() {
    for (name, src) in [
        (
            "app.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app.rs")),
        ),
        (
            "login.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/login.rs")),
        ),
        (
            "org.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/org.rs")),
        ),
        (
            "admin.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/admin.rs")),
        ),
    ] {
        assert!(
            src.contains("slot: Result"),
            "{name} layout must take slot: Result (Topcoat 0.5+)"
        );
        assert!(
            !src.contains("Slot<") && !src.contains("slot.await"),
            "{name} must not use Slot<'_> / slot.await"
        );
    }
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
    assert!(
        app.contains("require_catalog_assets") && app.contains("just bundle"),
        "load_assets must fail closed on stale/missing Topcoat 0.5 asset catalog"
    );
    assert!(app.contains("rel=\"icon\""));
    assert!(app.contains("apple-touch-icon"));
    assert!(app.contains("assets/favicon.svg"));
    assert!(app.contains("assets/favicon.ico"));
    assert!(app.contains("assets/apple-touch-icon.png"));
    assert!(app.contains("GET \"/favicon.ico\""));
    assert!(app.contains("GET \"/apple-touch-icon.png\""));
    assert!(app.contains("GET \"/apple-touch-icon-precomposed.png\""));
    assert!(
        app.contains("include_bytes!") && app.contains("static_icon_response"),
        "well-known icon probes must stay on include_bytes! + static_icon_response"
    );
    assert!(
        app.contains("asset!(\"assets/favicon.svg\")"),
        "layout favicon links must stay on asset!"
    );

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

#[test]
fn inv_ui_polish_css_and_rail_icon_outlines() {
    let css = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/styles.css"));
    assert!(
        css.contains("font-variant-numeric: tabular-nums"),
        "dynamic figures need tabular-nums"
    );
    let countdown = css
        .split(".vb-ephemeral-countdown")
        .nth(1)
        .expect("countdown rule");
    assert!(
        countdown.contains("tabular-nums"),
        "countdown must use tabular-nums"
    );
    let stat = css.split(".vb-stat-value {").nth(1).expect("stat-value");
    assert!(
        stat.contains("tabular-nums"),
        "stat-value must use tabular-nums"
    );
    let screen = css
        .lines()
        .find(|l| l.contains(".vb-screen"))
        .expect(".vb-screen");
    assert!(
        !screen.contains("vbIn"),
        ".vb-screen must not animate with vbIn"
    );
    assert!(
        css.contains(".vb-modal") && css.contains("vbIn"),
        ".vb-modal must keep vbIn"
    );
    let modal_body = css
        .split(".vb-modal-body {")
        .nth(1)
        .and_then(|s| s.split('}').next())
        .expect(".vb-modal-body rule");
    assert!(
        !modal_body.contains("max-width"),
        "article modal body must use the full modal width"
    );
    assert!(
        modal_body.contains("28px"),
        "modal body padding must match .vb-modal-head horizontal padding"
    );
    assert!(
        css.contains("scale(0.96)"),
        "buttons need active scale(0.96)"
    );
    assert!(
        css.contains("antialiased"),
        "body must enable font-smoothing antialiased"
    );
    assert!(css.contains("text-wrap: balance"));
    assert!(css.contains("text-wrap: pretty"));
    let seg = css.split(".vb-eph-seg {").nth(1).expect("eph-seg");
    assert!(
        seg.contains("border-radius: 6px"),
        "eph-seg outer radius must be 6px"
    );

    let icons = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/_components/icons.rs"
    ));
    assert!(icons.contains("pub const RAIL_STROKE: &str = \"1.6\""));
    assert!(icons.contains("pub const CONTROL_STROKE: &str = \"1.8\""));
    let home = icons
        .split("pub async fn ico_home")
        .nth(1)
        .and_then(|s| s.split("pub async fn ").next())
        .expect("ico_home");
    assert!(home.contains("fill=\"none\""));
    assert!(!home.contains("fill=\"currentColor\""));
    let issues = icons
        .split("pub async fn ico_issues")
        .nth(1)
        .and_then(|s| s.split("pub async fn ").next())
        .expect("ico_issues");
    assert!(issues.contains("fill=\"none\""));
    assert!(!issues.contains("fill=\"currentColor\""));
}
