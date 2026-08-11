//! Source-shape invariants for docs Markdown bundle CLI.

use std::process::Command;

#[test]
fn inv_check_docs_bundle_script() {
    let output = Command::new("bash")
        .arg("scripts/check_docs_bundle.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_docs_bundle.sh");
    assert!(
        output.status.success(),
        "scripts/check_docs_bundle.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_docs_bundle_module_pins() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/docs_bundle.rs"));
    assert!(src.contains("unpublish_other_published"));
    assert!(src.contains("export_articles_to_dir"));
    assert!(src.contains("import_articles_from_dir"));
    assert!(src.contains("bundle_filename"));
    assert!(src.contains("__"));
}

#[test]
fn inv_main_and_cli_wire_docs_commands() {
    let main = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
    let cli = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/cli.rs"));
    assert!(main.contains("\"docs\""));
    assert!(main.contains("run_docs"));
    assert!(cli.contains("docs export"));
    assert!(cli.contains("docs import"));
}

#[test]
fn inv_smoke_runbook_exists() {
    let runbook = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/runbooks/docs_bundle_smoke_test.md"
    ));
    assert!(runbook.contains("vcp docs export"));
    assert!(runbook.contains("vcp docs import"));
    assert!(runbook.contains("Pass"));
}
