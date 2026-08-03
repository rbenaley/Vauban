//! Invariants: Topcoat boolean HTML attrs must not use string ""/"selected".

use std::process::Command;

#[test]
fn inv_check_topcoat_boolean_attrs_script() {
    let status = Command::new("bash")
        .arg("scripts/check_topcoat_boolean_attrs.sh")
        .status()
        .expect("run check_topcoat_boolean_attrs.sh");
    assert!(
        status.success(),
        "scripts/check_topcoat_boolean_attrs.sh failed (exit {status})"
    );
}

#[test]
fn inv_no_stringly_selected_in_src() {
    let edit = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/releases/release_id.rs"
    ));
    assert!(
        !edit.contains(r#"{ "selected" } else { "" }"#),
        "release edit must not use string selected=\"\"/\"selected\""
    );
    assert!(
        edit.contains("selected=(org.id == org_id)"),
        "release edit must pin boolean org selected"
    );
    assert!(
        edit.contains("selected=(channel_stable)"),
        "release edit must pin boolean channel selected"
    );
}
