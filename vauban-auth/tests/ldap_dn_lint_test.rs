//! Rust pin for `check_ldap_dn_escaping.sh`.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

fn script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("check_ldap_dn_escaping.sh")
}

#[test]
fn check_ldap_dn_escaping_passes() {
    let script = script_path();
    assert!(script.exists(), "missing {}", script.display());
    let out = Command::new("bash")
        .arg(&script)
        .output()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", script.display()));
    assert!(
        out.status.success(),
        "check_ldap_dn_escaping.sh failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn ldap_dn_lint_script_exists_and_executable() {
    use std::os::unix::fs::PermissionsExt;
    let path = script_path();
    let mode = std::fs::metadata(&path)
        .expect("metadata")
        .permissions()
        .mode();
    assert!(
        mode & 0o111 != 0,
        "not executable: {} (mode={:o})",
        path.display(),
        mode
    );
}

#[test]
fn ldap_dn_lint_script_covers_core_invariants() {
    let body = std::fs::read_to_string(script_path()).expect("read");
    for needle in [
        "fn substitute_bind_dn",
        "fn username_allowed_in_bind_dn",
        r#".replace("{username}""#,
        "vauban-auth/src",
    ] {
        assert!(
            body.contains(needle),
            "check_ldap_dn_escaping.sh must still reference `{needle}`"
        );
    }
}
