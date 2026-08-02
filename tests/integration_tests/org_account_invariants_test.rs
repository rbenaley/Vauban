//! Source-shape invariants for /{org}/account.

use std::process::Command;

#[test]
fn inv_check_org_account_script() {
    let output = Command::new("bash")
        .arg("scripts/check_org_account.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_org_account.sh");
    assert!(
        output.status.success(),
        "scripts/check_org_account.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_account_page_reads_org_and_members() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/account.rs"
    ));
    assert!(src.contains("account_read"));
    assert!(src.contains("require_org"));
    assert!(src.contains("org.address"));
    assert!(src.contains("org.vat"));
    assert!(src.contains("lts_subscriptions"));
    assert!(src.contains("industrial_lts_subscriptions"));
    assert!(src.contains("USER ACCOUNTS"));
    assert!(src.contains("Membership::all"));
    assert!(!src.contains("SIGNED-IN USER"));
    assert!(!src.contains("Acme Infrastructure"));
    assert!(!src.contains("l.martin@acme"));
    let login = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/login.rs"));
    assert!(
        !login.contains("\"acme-infrastructure\""),
        "login must not hardcode Acme as client landing fallback"
    );
}

#[test]
fn inv_account_nav_segment_known() {
    let nav = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/nav.rs"));
    assert!(nav.contains("\"account\"") || nav.contains("Account"));
}
