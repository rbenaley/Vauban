//! Pins: the filter encoder is the only site that may build `(attr=…)`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

use shared::ldap_filter::equality_filter;

#[test]
fn encoder_is_exported_and_fail_closed() {
    assert!(equality_filter("member)", "x").is_err());
    assert!(equality_filter("member", "x)(uid=y").is_ok());
}

#[test]
fn interpolation_lint_still_passes() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("check_untrusted_interpolation.sh");
    let out = Command::new("bash")
        .arg(&path)
        .output()
        .expect("spawn lint");
    assert!(
        out.status.success(),
        "interpolation lint failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
