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
fn inv_check_storage_script() {
    let output = Command::new("bash")
        .arg("scripts/check_storage.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_storage.sh");
    assert!(
        output.status.success(),
        "scripts/check_storage.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_download_route_gates_and_streams_via_storage() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/builds/download.rs"
    ));
    assert!(src.contains("builds_download"));
    assert!(src.contains("DOWNLOAD_UNAVAILABLE"));
    assert!(src.contains("download unavailable"));
    assert!(src.contains("find_release_object"));
    assert!(src.contains("get_release"));
    assert!(!src.contains("NOT_IMPLEMENTED"));
    assert!(!src.contains("download not configured"));
    assert!(src.contains("forbidden"));
    assert!(src.contains("require_org"));
    assert!(
        src.contains("org_builds_entitled"),
        "download must deny when org has zero LTS/Industrial subscriptions"
    );
    assert!(
        src.contains("package_file_name") && src.contains("CONTENT_DISPOSITION"),
        "download must set Content-Disposition from package_file_name"
    );
}

#[test]
fn inv_builds_surface_gates_zero_subscription_orgs() {
    let builds = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/builds.rs"
    ));
    let rail = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/_components/rail.rs"
    ));
    let detail = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/builds/release_ver.rs"
    ));
    assert!(
        builds.contains("org_builds_entitled") && builds.contains("capability_denied"),
        "builds list must 404 when org has no Builds entitlement"
    );
    assert!(
        builds.contains("builds_channel_filter_chips"),
        "builds chips must be subscription-filtered"
    );
    assert!(
        detail.contains("org_builds_entitled"),
        "build detail must 404 when org has no Builds entitlement"
    );
    assert!(
        rail.contains("org_builds_entitled") && rail.contains("show_builds"),
        "rail must hide Builds without subscription entitlement"
    );
}

#[test]
fn inv_builds_and_dashboard_use_version_for_display() {
    let builds = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/builds.rs"
    ));
    assert!(
        builds.contains("version_for_display"),
        "builds list must strip +LTS via version_for_display"
    );
    let org = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/org.rs"));
    assert!(
        org.contains("version_for_display"),
        "org dashboard must strip +LTS via version_for_display"
    );
}

#[test]
fn inv_failed_download_redirects_to_builds_modal() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/builds/download.rs"
    ));
    assert!(
        src.contains("SEE_OTHER") && src.contains("download_error_href"),
        "failed download must PRG back to Builds"
    );
    assert!(
        src.contains("dl_error"),
        "redirect must carry a dl_error code"
    );
    assert!(
        !src.contains("text/plain"),
        "session download must not render a plain-text error page"
    );
    for code in ["missing", "unavailable", "integrity"] {
        assert!(src.contains(code), "DlError must expose the {code} code");
    }

    // Public cURL surface keeps machine-readable text + status.
    let eph = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/builds/ephemeral.rs"
    ));
    assert!(
        eph.contains("text/plain") && eph.contains("SERVICE_UNAVAILABLE"),
        "public ephemeral GET must stay a 503 text surface"
    );

    let builds = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/builds.rs"
    ));
    assert!(
        builds.contains("pub dl_error:") && builds.contains("DlError::from_code"),
        "BuildsQuery must map dl_error through the enum (never echo raw query text)"
    );
    assert!(
        builds.contains("download_error_modal")
            && builds.contains("vb-confirm-root")
            && builds.contains("aria-modal=\"true\""),
        "builds must raise the Concept confirm modal on download failure"
    );

    let styles = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/styles.css"));
    assert!(
        styles.contains(".vb-confirm-root") && styles.contains(".vb-confirm-actions"),
        "modal must reuse existing Concept confirm CSS (no new stylesheet)"
    );
}

#[test]
fn inv_builds_concept_ephemeral_server_side() {
    let builds = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/builds.rs"
    ));
    assert!(builds.contains("5-minute download link"));
    assert!(
        builds.contains("channel_badge_class"),
        "builds list must color LTS/Stable/EOL via channel_badge_class"
    );
    assert!(
        !builds.contains("vb-badge soft\">(rel.channel")
            && !builds.contains("vb-badge soft\">(rel.channel.clone())"),
        "builds must not hardcode soft badge on channel column"
    );
    assert!(builds.contains("open=none"));
    assert!(builds.contains("vb-ephemeral"));
    assert!(builds.contains("EPHEMERAL DOWNLOAD LINK"));
    assert!(builds.contains("Generate new link"));
    assert!(builds.contains("signal use_curl"));
    assert!(builds.contains("use_curl.set(true)"));
    assert!(builds.contains("use_curl.set(false)"));
    assert!(
        builds.contains("data-expires-at")
            && builds.contains("Date.now()")
            && builds.contains("@animationiteration"),
        "ephemeral countdown must sync from data-expires-at + Date.now (CSS ticks pause off-focus)"
    );
    assert!(
        !builds.contains("signal remaining")
            && !builds.contains("remaining.set(next)")
            && !builds.contains("let next = r - 1.0"),
        "must not decrement a remaining signal on each animation tick"
    );
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
    assert!(builds.contains("signal verify_open"));
    assert!(builds.contains("vb-verify") || builds.contains("data-verify-signature-panel"));
    assert!(builds.contains("PACKAGE SIGNATURE"));
    assert!(
        builds.contains("vb-build-sig-hash"),
        "list must show full sha256 (not truncated prefix)"
    );
    assert!(
        !builds.contains("take(7)"),
        "list must not truncate sha256 with take(7)"
    );
    assert!(
        !builds.contains("vb-btn muted vb-btn-build\">\n                                            \"Verify signature\""),
        "Verify signature must not be a muted span"
    );
    let verify_slice = builds
        .split("vb-ephemeral vb-verify")
        .nth(1)
        .and_then(|s| s.split("if let Some(panel) = eph_panel").next())
        .expect("verify panel block");
    assert!(
        !verify_slice.contains("use_curl"),
        "verify panel must not include fetch/cURL"
    );
    assert!(
        !verify_slice.contains("vb-ephemeral-revoke"),
        "verify panel must not include Revoke"
    );
    assert!(
        !verify_slice.contains("vb-ephemeral-countdown"),
        "verify panel must not include countdown"
    );

    // Verify open must hide the live ephemeral panel (one slot).
    let eph_host = builds
        .split("if let Some(panel) = eph_panel")
        .nth(1)
        .and_then(|s| s.split("async fn ephemeral_link_panel").next())
        .expect("ephemeral host after verify");
    assert!(
        eph_host.contains("data-ephemeral-panel-host"),
        "ephemeral panel must wrap in data-ephemeral-panel-host for exclusivity"
    );
    assert!(
        eph_host.contains("verify_open.get()")
            && eph_host.contains("display:none")
            && eph_host.contains(r#"{ "display:none" } else { "" })"#),
        "ephemeral host must hide with display:none while verify_open: {eph_host}"
    );
    assert!(
        !eph_host.contains(r#"{ "" } else { "display:none" }"#),
        "ephemeral host visibility must be inverted vs the verify panel"
    );
    assert!(!builds.contains("?tool="));
    assert!(!builds.contains("Collapse"));
    assert!(!builds.contains("t=demo"));
    assert!(!builds.contains("04:58"));
    assert!(!builds.contains("ACCESS_PUBLIC_ORIGIN"));

    let models = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/models/mod.rs"));
    assert!(
        models.contains("struct StorageObject"),
        "digests live on StorageObject"
    );
    assert!(models.contains("pub sha256: String"));
    let release_block = models
        .split("pub struct Release {")
        .nth(1)
        .and_then(|s| s.split('}').next())
        .expect("Release struct");
    assert!(
        !release_block.contains("sha256") && !release_block.contains("size_mb"),
        "Release must not declare sha256/size_mb: {release_block}"
    );
    assert!(!models.contains("signature_prefix"));
    assert!(
        builds.contains("release_blob_display"),
        "builds UI must read digests via release_blob_display"
    );

    let mig = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/toasty/migrations/0005_release_sha256.sql"
    ));
    assert!(mig.contains("RENAME COLUMN \"signature_prefix\" TO \"sha256\""));
    let mig13 = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/toasty/migrations/0013_storage_objects.sql"
    ));
    assert!(
        mig13.contains("storage_objects"),
        "migration 0013 must introduce storage_objects"
    );

    let seed = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/db.rs"));
    assert!(
        seed.contains("upsert_acme_private_release"),
        "demo catalog must refresh Acme private sha256"
    );
    assert!(
        seed.contains("b7e4d01c9e2a4f8b1d6c0e5a3f7b9d2e4c8a1f0b6d5e3c9a7f2b8d4e0c1a6953"),
        "Acme private digest must be full 64-hex SHA-256"
    );

    let pkg = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/release_pkg.rs"));
    assert!(pkg.contains("version_for_package"));
    assert!(pkg.contains("strip_prefix('v')"));
    assert!(pkg.contains("cmp_version_desc"));
    assert!(pkg.contains("version_sort_key"));
    assert!(pkg.contains("fn version_sort_fields"));

    assert!(
        builds.contains("v_major().desc()"),
        "builds must SQL ORDER BY semver columns"
    );
    assert!(
        builds.contains("load_releases_page_for_org"),
        "builds list must use load_releases_page_for_org"
    );
    assert!(
        builds.contains("page_offset"),
        "builds must use SQL page_offset"
    );
    assert!(
        !builds.contains("fn sort_releases"),
        "builds must not Rust-sort on the hot path"
    );

    let org = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/org.rs"));
    assert!(
        org.contains("load_releases_for_org"),
        "dashboard latest build must use load_releases_for_org (SQL-ordered)"
    );
    assert!(
        builds.contains("RESERVED_ORG_SLUG"),
        "builds visibility must let reserved vauban see all client releases"
    );
    assert!(
        pkg.contains("has_client_suffix"),
        "version sort must place X.Y.Z-client above plain X.Y.Z"
    );

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

    let list_page = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/list_page.rs"));
    assert!(
        list_page.contains("LIST_PAGE_SIZE: usize = 10"),
        "LIST_PAGE_SIZE must be 10"
    );
    assert!(
        builds.contains("BUILDS_PAGE_SIZE"),
        "builds must re-export BUILDS_PAGE_SIZE"
    );
    assert!(
        builds.contains("pub page:"),
        "BuildsQuery must include page"
    );
    assert!(
        builds.contains("filter_row") && builds.contains("PagerLinks"),
        "builds must use filter_row / PagerLinks"
    );
    let chips_comp = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/_components/chips.rs"
    ));
    let pager_comp = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/_components/pager.rs"
    ));
    assert!(chips_comp.contains("vb-chip-group"), "chip group markup");
    assert!(pager_comp.contains("vb-pager"), "SSR pager markup");
    let styles = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/styles.css"));
    assert!(styles.contains(".vb-pager"), "styles must define .vb-pager");
    let filter_at = builds.find("filter_row").expect("filter_row");
    let table_at = builds.find("vb-table-wrap").expect("table");
    assert!(
        filter_at < table_at,
        "filter_row must sit before builds table"
    );
    assert!(
        !builds.contains("channel={ch}&page="),
        "channel chips must not sticky-bind page="
    );
    let pager_css = styles
        .split(".vb-pager {")
        .nth(1)
        .and_then(|s| s.split('}').next())
        .expect(".vb-pager block");
    assert!(
        pager_css.contains("margin: 0 0 0 auto") || pager_css.contains("margin-left: auto"),
        "pager must right-align in chip row: {pager_css}"
    );
    let pager_link_css = styles
        .split("a.vb-pager-link {")
        .nth(1)
        .and_then(|s| s.split('}').next())
        .expect("a.vb-pager-link block");
    assert!(
        pager_link_css.contains("padding: 6px 12px"),
        "pager links must match chip padding: {pager_link_css}"
    );
    assert!(
        !pager_link_css.contains("height: 40px") && !pager_link_css.contains("min-height: 40px"),
        "pager links must not use fixed 40px height: {pager_link_css}"
    );
    let chip_css = styles
        .split("a.vb-chip, span.vb-chip, button.vb-chip {")
        .nth(1)
        .and_then(|s| s.split('}').next())
        .expect("vb-chip block");
    assert!(
        chip_css.contains("padding: 6px 12px"),
        "chips must keep padding 6px 12px for pager parity: {chip_css}"
    );
    signature_column_fits_a_full_digest(styles);
}

/// The SIGNATURE column floor is what keeps a SHA-256 on one line.
///
/// `prop_ga_sha256_digests_are_64_hex` guarantees the digest length, and
/// JetBrains Mono advances 0.6em, so the glyphs need
/// `64 * 0.6 * 11.5px = 442px` plus the check mark and its gap. A smaller
/// floor silently wraps the digest onto a second row.
fn signature_column_fits_a_full_digest(styles: &str) {
    let floor = styles
        .split("--vb-col-signature: minmax(")
        .nth(1)
        .and_then(|rest| rest.split("rem").next())
        .and_then(|rem| rem.trim().parse::<f32>().ok())
        .expect("--vb-col-signature: minmax(<rem floor>, 1fr)");
    let glyphs_px = 64.0 * 0.6 * 11.5;
    assert!(
        floor * 16.0 >= glyphs_px,
        "SIGNATURE floor {floor}rem is under the {glyphs_px}px a 64-hex \
         digest needs: it would wrap"
    );
}
