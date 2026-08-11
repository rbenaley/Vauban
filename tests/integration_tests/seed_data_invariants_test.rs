//! Source-shape invariants for minimal boot seed vs `vcp seed-data`.

use std::process::Command;

#[test]
fn inv_check_seed_data_script() {
    let output = Command::new("bash")
        .arg("scripts/check_seed_data.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_seed_data.sh");
    assert!(
        output.status.success(),
        "scripts/check_seed_data.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_main_boot_calls_minimal_not_demo_or_ga_upsert() {
    let main = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
    assert!(
        main.contains("seed_minimal_if_empty"),
        "server boot must call seed_minimal_if_empty"
    );
    assert!(
        main.contains("seed_demo_catalog"),
        "seed-data path must call seed_demo_catalog"
    );
    assert!(main.contains("seed-data"), "CLI must expose seed-data");
    assert!(
        !main.contains("ensure_demo_catalog"),
        "boot must not call ensure_demo_catalog"
    );
    assert!(
        !main.contains("upsert_ga_releases"),
        "boot must not call upsert_ga_releases"
    );
}

#[test]
fn inv_cli_usage_pins() {
    let cli = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/cli.rs"));
    assert!(cli.contains("fn wants_help"));
    assert!(cli.contains("fn cli_usage"));
    assert!(cli.contains("seed-data"));
    assert!(cli.contains("docs export"));
    assert!(cli.contains("docs import"));
    assert!(cli.contains("migration"));
    assert!(cli.contains("Usage:"));
    assert!(cli.contains("Commands:"));
    assert!(cli.contains("Options:"));
    assert!(cli.contains("-h, --help"));
    assert!(cli.contains("-V, --version"));
    assert!(cli.contains("wants_version"));
    assert!(cli.contains("BOLD_UNDERLINE") || cli.contains("1;4m"));
    // Old lowercase / footer forms must not remain in the usage string literal.
    assert!(!cli.contains("\"usage: vcp"));
    assert!(!cli.contains("Help: -h, --help, help"));
    assert!(!cli.contains("Usage: vcp-cli"));
}

#[test]
fn inv_smoke_runbook_exists() {
    let runbook = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/runbooks/seed_data_smoke_test.md"
    ));
    assert!(runbook.contains("vcp seed-data"));
    assert!(runbook.contains("Quick start"));
    assert!(runbook.contains("Pass"));
}
