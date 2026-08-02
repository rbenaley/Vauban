//! Source-shape invariants for admin client companies.

use std::process::Command;

use vcp::models::MAX_USERS_PER_COMPANY;

#[test]
fn inv_check_admin_companies_script() {
    let output = Command::new("bash")
        .arg("scripts/check_admin_companies.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_admin_companies.sh");
    assert!(
        output.status.success(),
        "scripts/check_admin_companies.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_seat_cap_default_is_five() {
    assert_eq!(MAX_USERS_PER_COMPANY, 5);
    let seats = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/seats.rs"));
    assert!(seats.contains("can_add_member"));
    assert!(seats.contains("membership_count"));
    let cfg = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/config.rs"));
    assert!(cfg.contains("max_accounts_per_org"));
    assert!(cfg.contains("struct OrgConfig"));
}

#[test]
fn inv_admin_companies_create_is_post_and_gated() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/new.rs"
    ));
    assert!(src.contains("method=\"POST\"") || src.contains("Form(form)"));
    assert!(src.contains("companies_manage"));
    assert!(src.contains("toasty::create!(Organization"));
    assert!(src.contains("sync_org_accounts"));
    assert!(src.contains("see_other"));
    assert!(!src.contains("Err(redirect("));
    assert!(!src.contains("type=\"password\""));
}

#[test]
fn inv_admin_companies_list_concept_and_edit_delete() {
    let list = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies.rs"
    ));
    let edit = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/company_id.rs"
    ));
    let form = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/form.rs"
    ));
    assert!(list.contains("+ New company"));
    assert!(list.contains("USER ACCOUNTS"));
    assert!(list.contains("vb-account-pill"));
    assert!(list.contains("ico_trash"));
    assert!(list.contains("delete="));
    assert!(edit.contains("/delete"));
    assert!(edit.contains("sync_org_accounts"));
    assert!(edit.contains("see_other"));
    assert!(!edit.contains("Err(redirect("));
    assert!(form.contains("USER ACCOUNTS"));
    assert!(form.contains("account_rows"));
    assert!(form.contains("compose_action"));
    assert!(form.contains("email_"));
    assert!(!form.contains("type=\"password\""));
}
