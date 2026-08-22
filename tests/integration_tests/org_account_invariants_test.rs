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
    assert!(
        src.contains("account_address_display"),
        "account must format addresses (reserved tenant = live build label)"
    );
    assert!(
        src.contains("data-vcp-build"),
        "reserved /vauban/account must expose data-vcp-build"
    );
    assert!(src.contains("org.vat"));
    assert!(src.contains("lts_subscriptions"));
    assert!(src.contains("industrial_lts_subscriptions"));
    assert!(src.contains("USER ACCOUNTS"));
    assert!(src.contains("Membership::all"));
    assert!(
        src.contains("ctx.user.email") && src.contains("account_member_pill_class"),
        "account must bind session email and highlight the matching pill"
    );
    assert!(
        !src.contains("SESSION")
            && !src.contains("Signed in as")
            && !src.contains("data-account-signed-in"),
        "session identity is the USER ACCOUNTS pill only"
    );
    assert!(
        !src.contains("SIGNED-IN USER"),
        "must not use the Concept SIGNED-IN USER mockup label"
    );
    assert!(!src.contains("Acme Infrastructure"));
    assert!(!src.contains("l.martin@acme"));
    let helpers = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/companies_accounts.rs"
    ));
    assert!(helpers.contains("fn is_signed_in_member"));
    assert!(helpers.contains("fn account_member_pill_class"));
    assert!(
        helpers.contains("fn account_address_display"),
        "reserved vauban address must resolve through account_address_display"
    );
    let build = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/build_info.rs"));
    assert!(build.contains("fn product_label"));
    assert!(build.contains("VCP_GIT_HASH"));
    let build_rs = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/build.rs"));
    assert!(
        build_rs.contains("VCP_GIT_HASH") && build_rs.contains("rev-parse"),
        "build.rs must bake a short git SHA"
    );
    let css = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/styles.css"));
    assert!(
        css.contains(".vb-account-pill.is-you"),
        "styles must highlight the session account pill"
    );
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
