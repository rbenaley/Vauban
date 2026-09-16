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
        "/src/app/admin/releases/new.rs"
    ));
    assert!(src.contains("method=\"POST\""));
    assert!(!src.contains("method=\"GET\""));
    assert!(src.contains("enctype=\"multipart/form-data\""));
    assert!(src.contains("name=\"package\""));
    assert!(src.contains("Multipart"));
    assert!(src.contains("releases_manage"));
    assert!(src.contains("toasty::create!(Release"));
    assert!(src.contains("RELEASE_STATUS_PUBLISHED"));
    assert!(src.contains("upsert_release_object"));
    // Publishing is all-or-nothing: staged until the ceremony commits, and
    // never left behind as a half-created HIDDEN row.
    assert!(src.contains("RELEASE_STATUS_STAGING"));
    assert!(!src.contains("RELEASE_STATUS_HIDDEN"));
    assert!(src.contains("rollback_staged_release"));
    assert!(src.contains("sweep_staged_releases"));
    assert!(src.contains("name=\"package\" type=\"file\" required=\"\""));
    assert!(
        src.contains("name=\"date\"")
            && src.contains("type=\"date\"")
            && src.contains("required=\"\""),
        "compose Date must be a required HTML date input"
    );
    assert!(
        !src.contains("\"1970-01-01\".to_owned()") && !src.contains("\"1970-01-01\".into()"),
        "create must not invent a Unix-epoch default for released_on"
    );
    // Lot D: refused creates re-run the compose page through `create_error`
    // (Topcoat rewrite) instead of a 303 to `?err=`.
    assert!(src.contains("create_error(cx, \"date\")"));
    assert!(src.contains("parse_released_on"));
    assert!(src.contains("create_error(cx, \"package\")"));
    assert!(src.contains("freebsd_pkg::inspect"));
    assert!(src.contains("create_error(cx, \"not_pkg\")"));
    assert!(
        src.contains("derive_release_identity"),
        "create must derive version/channel from the package manifeste"
    );
    assert!(src.contains("create_error(cx, \"identity\")"));
    assert!(
        src.contains("rewrite_get_with_flash") && src.contains("fn create_error"),
        "create errors must funnel through the rewrite helper"
    );
    assert!(
        src.contains("Ok(see_other(href!(admin_releases_page).resolve(cx)))"),
        "successful create stays 303 PRG to the list"
    );
    assert!(
        !src.contains("name=\"version\"") && !src.contains("name=\"channel\""),
        "compose form must not collect version or channel"
    );
    assert!(
        src.contains("vb-confirm-root")
            && src.contains("aria-modal=\"true\"")
            && src.contains("let not_pkg_open = signal(cx")
            && src.contains("id=\"vcp-not-pkg-open\"")
            && src.contains("id=\"vcp-release-create\"")
            && src.contains("@submit=$(")
            && src.contains("@animationend")
            && src.contains("vb-pkg-kick")
            && !src
                .split_once("#[cfg(test)]")
                .expect("new.rs tests")
                .0
                .contains("@animationiteration"),
        "not_pkg must use signal modal + submit preflight (Builds confirm chrome)"
    );
    assert!(
        src.contains("let no_key_open = signal(cx")
            && src.contains("fn require_active_key")
            && src.contains("#[procedure]")
            && !src.contains("GET \"/admin/releases/new/require-active-key\"")
            && !src.contains("GET \"./require-active-key\"")
            && (src.contains("err=no_active_key")
                || src.contains("err: Some(\"no_active_key\")")
                || src.contains("create_error(cx, \"no_active_key\")"))
            && src.contains("has_active_key")
            && src.contains("No active security key"),
        "publish must modal-gate on zero ACTIVE keys before WebAuthn"
    );
    assert!(
        src.contains("\"not_pkg\" | \"no_active_key\" => None")
            || (src.contains("\"not_pkg\" => None") && src.contains("\"no_active_key\" => None")),
        "not_pkg / no_active_key must not use the inline red banner"
    );
    assert!(
        src.contains("fn admin_releases_validate_pkg")
            && src.contains("#[route(POST \"./validate-pkg\")]")
            && src.contains("StatusCode::NO_CONTENT")
            && src.contains("UNPROCESSABLE_ENTITY"),
        "validate-pkg preflight must exist (204/422)"
    );
    let validate_at = src
        .find("fn admin_releases_validate_pkg")
        .expect("validate fn");
    // Module-relative (0.8.1): create is `#[route(POST)]` at the module path.
    let validate_end = src[validate_at..]
        .find("\n#[route(POST)]")
        .map(|i| validate_at + i)
        .expect("create route after validate");
    let validate_body = &src[validate_at..validate_end];
    assert!(
        validate_body.contains("freebsd_pkg::inspect"),
        "validate-pkg must inspect"
    );
    assert!(
        !validate_body.contains("RELEASE_STATUS_STAGING")
            && !validate_body.contains("put_begin")
            && !validate_body.contains("stash_pending_release")
            && !validate_body.contains("toasty::create!"),
        "validate-pkg must never stage or put_begin"
    );
    let create_at = src
        .find("async fn admin_releases_create")
        .expect("create fn");
    let create_body = &src[create_at..];
    let inspect_at = create_body.find("freebsd_pkg::inspect").expect("inspect");
    let staging_at = create_body
        .find("status: RELEASE_STATUS_STAGING")
        .expect("staging create");
    let put_begin_at = create_body.find("put_begin_release").expect("put_begin");
    assert!(
        inspect_at < staging_at && inspect_at < put_begin_at,
        "FreeBSD inspect must run before STAGING / put_begin on create"
    );
}

#[test]
fn inv_admin_releases_freebsd_pkg_gate_and_confirm() {
    let pkg = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/freebsd_pkg.rs"));
    assert!(pkg.contains("pub fn inspect"));
    assert!(pkg.contains("pub fn format_pkg_info"));
    assert!(pkg.contains("MAX_MANIFEST_BYTES"));
    assert!(pkg.contains("MAX_METADATA_PREFIX_BYTES"));
    assert!(
        !pkg.contains("Command::new(\"pkg\")") && !pkg.contains("pkg-static"),
        "must not shell out to pkg(8)"
    );

    let confirm = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/releases/confirm.rs"
    ));
    assert!(confirm.contains("format_pkg_info"));
    assert!(confirm.contains("vcp-pkg-info"));
    assert!(confirm.contains("pkg_info"));

    let client = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/storage/client.rs"
    ));
    assert!(
        client.contains("pkg_info: FreeBsdPkgInfo"),
        "PendingReleaseCeremony must carry FreeBsdPkgInfo"
    );

    let cargo = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
    for dep in ["tar", "zstd", "xz2", "flate2", "bzip2"] {
        assert!(
            cargo.contains(dep),
            "Cargo.toml must depend on {dep} for FreeBSD pkg parsing"
        );
    }
}

#[test]
fn inv_admin_releases_staged_rows_are_transactional() {
    let staging = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/releases/staging.rs"
    ));
    assert!(staging.contains("fn rollback_staged_release"));
    assert!(staging.contains("fn sweep_staged_releases"));
    assert!(staging.contains("fn orphan_staged_ids"));
    assert!(staging.contains("RELEASE_STATUS_STAGING"));

    let confirm = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/releases/confirm.rs"
    ));
    assert!(confirm.contains("#[route(POST \"./cancel\")]"));
    assert!(confirm.contains("rollback_staged_release"));
    assert!(confirm.contains("Cancel publish"));

    let list = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/releases.rs"
    ));
    assert!(list.contains("RELEASE_STATUS_STAGING"));
    assert!(list.contains("sweep_staged_releases"));

    let edit = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/releases/release_id.rs"
    ));
    assert!(edit.contains("RELEASE_STATUS_STAGING"));
}

#[test]
fn inv_admin_releases_mutation_routes() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/releases/release_id.rs"
    ));
    assert!(src.contains("/publish"));
    assert!(src.contains("/unpublish"));
    assert!(src.contains("/delete"));
    assert!(src.contains("is_delete_confirm"));
    assert!(src.contains("releases_manage"));
    assert!(src.contains("RELEASE_STATUS_PUBLISHED"));
    assert!(src.contains("RELEASE_STATUS_HIDDEN"));
    assert!(src.contains("channel_track"));
    assert!(src.contains("apply_edit_channel"));
    assert!(
        !src.contains("name=\"version\"")
            && !src.contains("name=\"date\"")
            && !src.contains("id=\"version\"")
            && !src.contains("id=\"date\""),
        "edit must only expose channel, organization, and notes"
    );
    assert!(src.contains("selected=(track_selected)"));
    assert!(src.contains("selected=(channel_eol)"));
}

#[test]
fn inv_admin_releases_list_actions_and_badges() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/releases.rs"
    ));
    assert!(src.contains("release_status_badge_class"));
    assert!(src.contains("v_major().desc()"));
    assert!(
        src.contains("status().desc()"),
        "admin list must tie-break same semver with status DESC (PUBLISHED before HIDDEN)"
    );
    assert!(!src.contains("cmp_version_desc"));
    assert!(!src.contains("cmp_admin_release_list"));
    assert!(src.contains("vb-row-actions"));
    assert!(src.contains("vb-rel-actions"));
    let pkg = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/release_pkg.rs"));
    assert!(
        pkg.contains("fn cmp_admin_release_list") && pkg.contains("fn cmp_status_published_first"),
        "release_pkg must keep admin list order contract helpers"
    );
    assert!(src.contains("vb-rel-head"));
    assert!(src.contains("vb-rel-row"));
    assert!(src.contains("delete="));
    assert!(src.contains("ico_trash"));
    assert!(src.contains("Delete permanently"));
    assert!(src.contains("+ New release"));
    assert!(src.contains("Unpublish"));
    assert!(src.contains("Publish"));
    assert!(
        src.contains("admin_releases_edit_page") && src.contains("ReleaseId(rel.id)"),
        "Edit must link by typed release id"
    );
    assert!(
        src.contains("version_for_display"),
        "list VERSION / delete overlay must use version_for_display"
    );
    assert!(
        src.contains("delete_err_webauthn"),
        "list must surface err=webauthn on delete overlay"
    );
    assert!(
        !src.contains("later slice"),
        "list must not claim upload/signing is a later slice"
    );
    let css = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/styles.css"));
    assert!(
        css.contains(".vb-row-actions .vb-btn.outline.compact"),
        "Publish/Unpublish must share a fixed min-width"
    );
    assert!(
        css.contains("flex-wrap: nowrap"),
        "row actions must stay on one horizontal line"
    );
    assert!(
        css.contains("--vb-catalog-gap")
            && css.contains("column-gap: var(--vb-catalog-gap)")
            && css.contains("--vb-rel-cols"),
        "releases catalog must share the Builds gutter token"
    );
    // Shared columns resolve to the same rem token on both surfaces, so the
    // gutters line up between /{org}/builds and /admin/releases.
    for token in [
        "--vb-col-version",
        "--vb-col-channel",
        "--vb-col-date",
        "--vb-col-size",
    ] {
        let uses = css.matches(&format!("var({token})")).count();
        assert!(
            uses >= 2,
            "{token} must be used by both Builds and Releases grids"
        );
    }
    assert!(
        css.contains(".vb-catalog-wrap { overflow-x: auto"),
        "fixed catalog tracks must scroll, not clip the last column"
    );
    let rel_tracks = css
        .split("--vb-rel-cols:")
        .nth(1)
        .and_then(|rest| rest.split(';').next())
        .expect("--vb-rel-cols declaration");
    // Six shared tokens plus the ACTIONS track: the grid fills the card
    // width and still never sizes on the rows it happens to show.
    assert_eq!(
        rel_tracks.matches("var(--vb-col-").count(),
        6,
        "releases must reuse the six shared column tokens: {rel_tracks}"
    );
    assert!(
        rel_tracks.contains("1fr)"),
        "the ACTIONS track must be minmax(<rem floor>, 1fr): {rel_tracks}"
    );
    for keyword in ["auto", "min-content", "max-content", "fit-content"] {
        assert!(
            !rel_tracks.contains(keyword),
            "content-sized track {keyword} drifts page to page: {rel_tracks}"
        );
    }
    for token in [
        "--vb-col-version",
        "--vb-col-channel",
        "--vb-col-target",
        "--vb-col-date",
        "--vb-col-size",
        "--vb-col-status",
    ] {
        let def = css
            .split(&format!("{token}:"))
            .nth(1)
            .and_then(|rest| rest.split(';').next())
            .unwrap_or_else(|| panic!("{token} declaration"));
        assert!(
            def.contains("minmax(") && def.trim().ends_with("1fr)"),
            "{token} must be minmax(<rem floor>, 1fr): {def}"
        );
    }
    // A fraction above 1 hoards the leftover width: the widest column opens
    // a hole (before SIZE on Builds, before ACTIONS here) while the others
    // stay cramped. Equal growth keeps the column pitch regular.
    for decl in ["--vb-col-", "--vb-rel-cols:", "--vb-build-cols:"] {
        for chunk in css.split(decl).skip(1) {
            let head = chunk.split(';').next().unwrap_or_default();
            for (idx, _) in head.match_indices("fr") {
                let fraction = head[..idx]
                    .rsplit(|c: char| !c.is_ascii_digit() && c != '.')
                    .next()
                    .unwrap_or_default();
                assert!(
                    fraction.is_empty() || fraction == "1",
                    "catalog columns must all grow by 1fr, found {fraction}fr \
                     in {decl}{head}"
                );
            }
        }
    }
}

#[test]
fn inv_admin_releases_list_paginates() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/releases.rs"
    ));
    assert!(
        src.contains("LIST_PAGE_SIZE"),
        "admin releases must use LIST_PAGE_SIZE"
    );
    assert!(
        src.contains("filter_row"),
        "admin releases must use filter_row (channel chips + pager)"
    );
    assert!(
        !src.contains("list_toolbar"),
        "admin releases must not use list_toolbar once channel chips exist"
    );
    assert!(
        src.contains("channel: Option<String>"),
        "AdminReleasesQuery must include channel"
    );
    assert!(
        src.contains("page: Option<u32>"),
        "AdminReleasesQuery must include page"
    );
    assert!(
        src.contains("CHANNEL_CHIPS") && src.contains("admin_releases_list_href"),
        "admin releases must share chip/pager href helper"
    );
    assert!(
        src.contains("vb-rel-head") && src.contains("vb-rel-row"),
        "admin releases must use the catalog grid (same gutters as Builds)"
    );
    assert!(
        src.contains("page_offset"),
        "admin releases must use SQL page_offset"
    );
    assert!(
        !src.contains("page_slice"),
        "admin releases must not page_slice"
    );
}

#[test]
fn inv_builds_filter_published_status() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/builds.rs"
    ));
    assert!(
        src.contains("RELEASE_STATUS_PUBLISHED"),
        "customer builds must require PUBLISHED"
    );
    assert!(
        src.contains("release_visible_to_org"),
        "visibility helper must exist"
    );
}
