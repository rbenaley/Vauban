//! BAC hardening — source-level invariants.
//!
//! Complements the E2E matrix (`bac_gate_matrix_test.rs`): the tests
//! below `include_str!` the production sources and pin the structural
//! contracts so a regression is caught at `cargo test` time even
//! without a database.
//!
//! 1. `check_bac_handler_gates.sh` (every `pub async fn` in
//!    `handlers/web/*.rs` reads `perms.<flag>` or carries an explicit
//!    `// allow-ungated: <reason>` annotation) passes and stays wired
//!    into the suite.
//! 2. `main.rs` mounts the admin sub-trees behind their `require_*`
//!    route_layers and never re-mounts the flat (pre-hardening) admin
//!    routes.
//! 3. The generic middleware wrappers exist and read the exact flag
//!    they advertise.

use std::path::PathBuf;
use std::process::Command;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Strip line comments and `#[cfg(test)]` tails (same helper family
/// as `manage_assets_invariants_test.rs`).
fn strip_comments_and_tests(body: &str) -> String {
    let body = body
        .split("#[cfg(test)]")
        .next()
        .expect("source always has a non-test prefix");
    body.lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                ""
            } else if let Some(idx) = line.find("//") {
                &line[..idx]
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ===================================================================
// 1. The bash lint passes and stays wired
// ===================================================================

#[test]
fn check_bac_handler_gates_passes() {
    let script = manifest_dir()
        .join("scripts")
        .join("check_bac_handler_gates.sh");
    assert!(script.exists(), "missing lint script: {}", script.display());

    let out = Command::new("bash")
        .arg(&script)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {}", script.display(), e));

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "check_bac_handler_gates.sh failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn check_bac_handler_gates_script_exists_and_executable() {
    use std::os::unix::fs::PermissionsExt;
    let path = manifest_dir()
        .join("scripts")
        .join("check_bac_handler_gates.sh");
    assert!(path.exists(), "missing lint script: {}", path.display());
    let mode = std::fs::metadata(&path)
        .expect("metadata")
        .permissions()
        .mode();
    assert!(
        mode & 0o111 != 0,
        "lint script not executable: {} (mode={:o})",
        path.display(),
        mode
    );
}

#[test]
fn check_users_usable_filters_passes() {
    let script = manifest_dir()
        .join("scripts")
        .join("check_users_usable_filters.sh");
    assert!(script.exists(), "missing lint script: {}", script.display());
    let out = Command::new("bash")
        .arg(&script)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {}", script.display(), e));
    assert!(
        out.status.success(),
        "check_users_usable_filters.sh failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// ===================================================================
// 2. Router shape: gated nests, no flat admin routes
// ===================================================================

/// `main.rs` MUST mount the three hardened nests, each with its
/// `require_*` route_layer, plus the pre-existing
/// `require_assets_manage` nest that now also fences the asset
/// groups.
#[test]
fn main_rs_mounts_every_admin_nest_with_its_gate() {
    let raw = include_str!("../../src/main.rs");
    let body = strip_comments_and_tests(raw);
    let collapsed: String = body.split_whitespace().collect::<Vec<_>>().join(" ");

    for (nest_path, gate) in [
        ("/accounts/users", "require_permission::require_users_read"),
        (
            "/accounts/groups",
            "require_permission::require_groups_read",
        ),
        (
            "/assets/access",
            "require_permission::require_access_rules_read",
        ),
        (
            "/assets/manage",
            "require_assets_manage::require_assets_manage",
        ),
    ] {
        let spaced = format!(".nest( \"{}\"", nest_path);
        let compact = format!(".nest(\"{}\"", nest_path);
        assert!(
            collapsed.contains(spaced.as_str()) || collapsed.contains(compact.as_str()),
            "main.rs must mount `{}` via Router::nest",
            nest_path
        );
        assert!(
            body.contains(gate),
            "main.rs must wire `{}` (route_layer of the `{}` nest)",
            gate,
            nest_path
        );
    }
}

/// No flat admin route may be re-mounted outside the nests. A
/// contributor re-adding e.g. `.route("/accounts/users", ...)` to the
/// main router would bypass the route_layer — the nest strips the
/// prefix, so inside the nest every path literal starts at `/`.
#[test]
fn main_rs_carries_no_flat_admin_route() {
    let raw = include_str!("../../src/main.rs");
    let body = strip_comments_and_tests(raw);
    let collapsed: String = body.split_whitespace().collect::<Vec<_>>().join(" ");

    // A `.route("<full-prefix>...")` literal is a flat (non-nested)
    // mount: inside a nest the literals start at `/` because axum
    // strips the prefix. `.nest("<prefix>", ...)` remains allowed —
    // it is the hardened form.
    for prefix in [
        "/accounts/users",
        "/accounts/groups",
        "/assets/access",
        "/assets/groups",
    ] {
        for pattern in [
            format!(".route( \"{}", prefix),
            format!(".route(\"{}", prefix),
        ] {
            assert!(
                !collapsed.contains(pattern.as_str()),
                "main.rs must not carry a flat `.route(\"{}...\")` mount — \
                 the sub-tree lives in a `Router::nest` behind its \
                 `require_*` route_layer (BAC hardening).",
                prefix
            );
        }
    }
}

/// The test router (`tests/common/mod.rs`) must mirror the production
/// nests so the E2E matrix exercises the same middleware stack.
#[test]
fn test_router_mirrors_the_admin_nests() {
    let body = include_str!("../common/mod.rs");
    for gate in [
        "require_permission::require_users_read",
        "require_permission::require_groups_read",
        "require_permission::require_access_rules_read",
        "require_assets_manage::require_assets_manage",
    ] {
        assert!(
            body.contains(gate),
            "tests/common/mod.rs must wire `{}` exactly like main.rs \
             (otherwise the E2E matrix exercises a weaker stack than \
             production).",
            gate
        );
    }
}

// ===================================================================
// 3. Middleware wrappers read the exact flag they advertise
// ===================================================================

#[test]
fn require_permission_wrappers_read_their_own_flag() {
    let body = include_str!("../../src/middleware/require_permission.rs");
    let production = strip_comments_and_tests(body);

    for (wrapper, flag, label) in [
        ("require_users_read", "p.users_read", "\"users:read\""),
        ("require_groups_read", "p.groups_read", "\"groups:read\""),
        (
            "require_access_rules_read",
            "p.access_rules_read",
            "\"access_rules:read\"",
        ),
    ] {
        let decl = format!("pub async fn {}", wrapper);
        let idx = production
            .find(&decl)
            .unwrap_or_else(|| panic!("{} must exist in require_permission.rs", wrapper));
        let rest = &production[idx..];
        let end = rest[decl.len()..]
            .find("pub async fn ")
            .map(|p| p + decl.len())
            .unwrap_or(rest.len());
        let fn_body = &rest[..end];
        assert!(
            fn_body.contains(flag),
            "{} must gate on `{}` (and nothing else)",
            wrapper,
            flag
        );
        assert!(
            fn_body.contains(label),
            "{} must surface the canonical `{}` label in its 403 body \
             (anti-enumeration: one stable shape per sub-tree)",
            wrapper,
            label
        );
    }

    // Fail-closed plumbing: the shared body must fall back to the
    // deny-all default context when the extension is missing.
    assert!(
        production.contains("unwrap_or_default()"),
        "require_flag must fall back to PermissionContext::default() \
         (deny-all) when the extension is missing"
    );
}
