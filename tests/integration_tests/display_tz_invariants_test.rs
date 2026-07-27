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
        "/src/app/admin/docs/doc.rs"
    ));
    assert!(src.contains("browser_tz"));
    assert!(src.contains("format_unix_local") || src.contains("format_local"));
    assert!(
        !src.contains(".format(\"%Y-%m-%d %H:%M"),
        "no naked UTC format in admin docs edit"
    );
}

#[test]
fn inv_tz_helpers_exist() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/tz.rs"));
    assert!(src.contains("VCP_TZ_COOKIE"));
    assert!(src.contains("fn format_local"));
    assert!(src.contains("fn browser_tz"));
}

#[test]
fn inv_vcp_tz_js_sets_cookie_matching_rust_name() {
    let js = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/vcp_tz.js"));
    let rust = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/tz.rs"));
    assert!(js.contains("vcp_tz="), "script must write vcp_tz cookie");
    assert!(js.contains("timeZone"), "script must read Intl timeZone");
    assert!(js.contains("location.reload"), "script must reload for SSR");
    assert!(
        rust.contains("\"vcp_tz\""),
        "Rust VCP_TZ_COOKIE must remain vcp_tz"
    );
    let app = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app.rs"));
    assert!(
        app.contains("vcp_tz.js") || app.contains("VCP_TZ_JS"),
        "root layout must include timezone script asset"
    );
}
