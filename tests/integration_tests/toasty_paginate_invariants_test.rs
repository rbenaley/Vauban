//! Source-shape invariants for cursor pagination on full scans.

use std::process::Command;

#[test]
fn inv_check_toasty_paginate_script() {
    let output = Command::new("bash")
        .arg("scripts/check_toasty_paginate.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_toasty_paginate.sh");
    assert!(
        output.status.success(),
        "scripts/check_toasty_paginate.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_helper_and_callers_pin_paginate() {
    let helper = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/toasty_page.rs"));
    assert!(helper.contains("SCAN_PAGE_SIZE"));
    assert!(helper.contains("advance_scan_page"));
    assert!(helper.contains("page.next"));

    let db = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/db.rs"));
    assert!(db.contains(".paginate("));
    assert!(db.contains("advance_scan_page"));
    assert!(!db.contains(".paginate(") || !db.contains(".paginate(SCAN_PAGE_SIZE).offset"));

    let bundle = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/docs_bundle.rs"));
    assert!(bundle.contains(".paginate("));
}

#[test]
fn inv_smoke_runbook_exists() {
    let runbook = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/runbooks/toasty_paginate_smoke_test.md"
    ));
    assert!(runbook.contains("paginate"));
    assert!(runbook.contains("Pass"));
    assert!(runbook.contains("vcp docs export"));
}
