//! Source-shape invariants for the Topcoat 0.8 pin (0.8.1 + Strict).

use std::process::Command;

#[test]
fn inv_check_topcoat_0_8_script() {
    let output = Command::new("bash")
        .arg("scripts/check_topcoat_0_8.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_topcoat_0_8.sh");
    assert!(
        output.status.success(),
        "scripts/check_topcoat_0_8.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_runtime_and_error_boundary_pins() {
    let app = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app.rs"));
    assert!(
        app.contains(".runtime()"),
        "router must register .runtime()"
    );
    assert!(
        app.contains("error_boundary"),
        "root_layout must wrap the slot in error_boundary"
    );
    assert!(
        app.contains("runtime::script"),
        "root_layout must emit the 0.8 runtime script"
    );
    assert!(
        app.contains(".trailing_slash") && app.contains("TrailingSlash::Strict"),
        "router must set TrailingSlash::Strict so POST slash stays 404"
    );

    let admin = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/admin.rs"));
    assert!(admin.contains("error_boundary"));
    assert!(admin.contains("slot: Slot<'_>"));

    let org = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/org.rs"));
    assert!(org.contains("error_boundary"));
    assert!(org.contains("slot: Slot<'_>"));
}

fn collect_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.expect("dirent");
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn inv_trailing_slash_enum_only_in_app() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs(&root, &mut files);
    let mut hits = Vec::new();
    for path in files {
        let src = std::fs::read_to_string(&path).expect("read");
        if src.contains("TrailingSlash") {
            hits.push(path.display().to_string());
        }
    }
    assert_eq!(
        hits.len(),
        1,
        "TrailingSlash must appear only in app.rs, found: {}",
        hits.join(", ")
    );
    assert!(
        hits[0].ends_with("src/app.rs"),
        "TrailingSlash must be imported only in app.rs, found: {}",
        hits.join(", ")
    );
}

/// 0.8.1 module-relative routes: an absolute route string that merely repeats
/// the module path is drift waiting to happen. Only paths that cannot be
/// derived from the module tree stay absolute.
#[test]
fn inv_route_paths_are_module_relative_outside_whitelist() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/app");
    let re = regex::Regex::new(r#"#\[route\((?:GET|POST|\[[A-Z, ]+\]|\*) "(/[^"]*)"\)\]"#)
        .expect("regex");
    let mut files = Vec::new();
    collect_rs(&root, &mut files);
    files.push(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/app.rs"));
    let mut offenders = Vec::new();
    for path in files {
        let src = std::fs::read_to_string(&path).expect("read");
        for caps in re.captures_iter(&src) {
            let route = &caps[1];
            let allowed = route.starts_with("/vauban/")
                || route.starts_with("/{org}/builds/{release_ver}/")
                || route.starts_with("/{org}/images")
                || route == "/"
                || route == "/favicon.ico"
                || route.starts_with("/apple-touch-icon")
                || route == "/logout"
                || route == "/choose-org";
            if !allowed {
                offenders.push(format!("{}: {route}", path.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "absolute route paths outside the whitelist (use #[route(POST)] / \"./x\"): {}",
        offenders.join(", ")
    );

    let release = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/releases/release_id.rs"
    ));
    assert!(release.contains("path_param!(pub(crate) release_id: u64, error = not_found);"));
    assert!(!release.contains("fn parse_release_id"));
    let company = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/company_id.rs"
    ));
    assert!(company.contains("path_param!(pub(crate) company_id: u64, error = not_found);"));
    assert!(!company.contains("fn parse_company_id"));
}

#[test]
fn inv_no_statement_form_signals_in_src() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let re = regex::Regex::new(r"signal\s+[A-Za-z_][A-Za-z0-9_]*\s*=").expect("regex");
    let mut files = Vec::new();
    collect_rs(&root, &mut files);
    let mut hits = Vec::new();
    for path in files {
        let src = std::fs::read_to_string(&path).expect("read");
        if re.is_match(&src) {
            hits.push(path.display().to_string());
        }
    }
    assert!(
        hits.is_empty(),
        "statement-form signals remain in: {}",
        hits.join(", ")
    );
}
