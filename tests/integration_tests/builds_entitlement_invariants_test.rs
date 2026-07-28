//! Source-shape invariants for builds download entitlement.

use std::process::Command;

use crate::common::{assert_topcoat_click_handlers_are_functions, is_topcoat_function_handler};

#[test]
fn inv_topcoat_click_bind_requires_function_expression() {
    // Mirrors Topcoat runtime: `return ${attr}` then invoke as handler.
    assert!(is_topcoat_function_handler(
        "(e) => { const el = e.current_target.inner; navigator.clipboard.writeText('x'); }"
    ));
    assert!(!is_topcoat_function_handler(
        "navigator.clipboard.writeText(this.getAttribute('data-copy')); this.textContent='Copied';"
    ));
    let good = r#"<div class="vb-ephemeral">
        <button data-topcoat-on:click="(e) => { const el = e.current_target.inner; }"></button>
        <button data-topcoat-on:click="(() => { return (__local0) => __external0.set(cx.hydrate(true)); })()"></button>
    </div>"#;
    assert_topcoat_click_handlers_are_functions(good);
}

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

#[test]
fn inv_builds_concept_ephemeral_server_side() {
    let builds = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/builds.rs"
    ));
    assert!(builds.contains("5-minute download link"));
    assert!(builds.contains("open=none"));
    assert!(builds.contains("vb-ephemeral"));
    assert!(builds.contains("EPHEMERAL DOWNLOAD LINK"));
    assert!(builds.contains("Generate new link"));
    assert!(builds.contains("signal remaining"));
    assert!(builds.contains("signal use_curl"));
    assert!(builds.contains("use_curl.set(true)"));
    assert!(builds.contains("use_curl.set(false)"));
    assert!(builds.contains("@animationiteration"));
    assert!(builds.contains("navigator.clipboard.writeText"));
    assert!(
        builds.contains("current_target.inner"),
        "clipboard @click must be a function using event.current_target (Topcoat calls return <js> at bind time)"
    );
    assert!(
        !builds.contains("@click=\"navigator.clipboard"),
        "bind-time clipboard statements abort Topcoat scan and break fetch/cURL tabs"
    );
    assert!(builds.contains("data-copy"));
    assert!(builds.contains("ico_copy"));
    assert!(
        builds.contains("primary_public_origin"),
        "builds UI must take download host from Config::primary_public_origin"
    );
    assert!(!builds.contains("?tool="));
    assert!(!builds.contains("Collapse"));
    assert!(!builds.contains("t=demo"));
    assert!(!builds.contains("04:58"));
    assert!(!builds.contains("ACCESS_PUBLIC_ORIGIN"));

    let eph = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/builds/ephemeral.rs"
    ));
    assert!(eph.contains("EphemeralDownload"));
    assert!(eph.contains("Uuid::new_v4"));
    assert!(eph.contains("eph_public_url"));
    assert!(eph.contains("public_origin"));
    assert!(eph.contains("ephemeral/revoke"));
    assert!(!eph.contains("ACCESS_PUBLIC_ORIGIN"));

    let conf = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/config/vcp.conf"));
    assert!(
        conf.contains("public_origins = [\"https://access.vauban.sh\"]"),
        "production public_origins must be https://access.vauban.sh"
    );

    let app = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app.rs"));
    assert!(!app.contains("vcp_builds_eph"));
    assert!(!app.contains("VCP_BUILDS_EPH"));

    assert!(
        !std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/assets/vcp_builds_eph.js"
        ))
        .exists(),
        "client ephemeral JS must not exist"
    );
}
