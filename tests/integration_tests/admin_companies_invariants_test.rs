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
fn inv_seat_cap_is_five() {
    assert_eq!(MAX_USERS_PER_COMPANY, 5);
    let seats = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/seats.rs"));
    assert!(seats.contains("can_add_member"));
    assert!(seats.contains("membership_count"));
}

#[test]
fn inv_admin_companies_create_is_post_and_gated() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/admin/companies/new.rs"
    ));
    assert!(src.contains("method=\"POST\""));
    assert!(src.contains("companies_manage"));
    assert!(src.contains("toasty::create!(Organization"));
}
