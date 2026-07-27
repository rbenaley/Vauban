//! Source-shape invariants for docs search shard.

use std::process::Command;

#[test]
fn inv_check_docs_search_shard_script() {
    let output = Command::new("bash")
        .arg("scripts/check_docs_search_shard.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_docs_search_shard.sh");
    assert!(
        output.status.success(),
        "scripts/check_docs_search_shard.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_shard_rechecks_org_and_docs_read() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/docs/search_shard.rs"
    ));
    assert!(src.contains("#[shard]"));
    assert!(src.contains("docs_search_results"));
    assert!(src.contains("require_org"));
    assert!(src.contains("docs_read"));
}
