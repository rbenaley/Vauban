//! Docs hygiene pins (architecture quick-win QW2 / I-DOC-1..3).
//!
//! - Runbooks must not link stale Recording 1.3.
//! - Superseded banners on n-1 Vault / Privsep / Recording archaeology.
//! - Fictional root mermaid diagram must stay deleted.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn runbooks_do_not_link_recording_architecture_1_3() {
    let runbooks = workspace_root().join("docs/runbooks");
    let mut hits = Vec::new();
    for entry in std::fs::read_dir(&runbooks).expect("runbooks dir") {
        let entry = entry.expect("entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let body = std::fs::read_to_string(&path).expect("read");
        if body.contains("Vauban_Recording_Architecture_EN(1.3)") {
            hits.push(path.display().to_string());
        }
    }
    assert!(
        hits.is_empty(),
        "runbooks must not link Recording Architecture 1.3 (I-DOC-1); hits: {hits:?}"
    );
}

#[test]
fn superseded_banners_on_archaeology_docs() {
    let root = workspace_root();
    let cases = [
        (
            "docs/technical/Vauban_Recording_Architecture_EN(1.0).md",
            "1.8",
        ),
        (
            "docs/technical/Vauban_Recording_Architecture_EN(1.4).md",
            "1.8",
        ),
        (
            "docs/technical/Vauban_Privsep_Architecture_EN(1.0).md",
            "1.3",
        ),
        (
            "docs/technical/Vauban_Privsep_Architecture_EN(1.1).md",
            "1.3",
        ),
        (
            "docs/technical/Vauban_Privsep_Architecture_EN(1.2).md",
            "1.3",
        ),
        ("docs/technical/Vauban_IAM_Architecture_EN(1.0).md", "1.1"),
        ("docs/technical/Vauban_Vault_Architecture_EN(1.0).md", "1.2"),
        ("docs/technical/Vauban_Vault_Architecture_EN(1.1).md", "1.2"),
    ];
    for (rel, latest) in cases {
        let path = root.join(rel);
        let body = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        assert!(
            body.contains("**Superseded.**"),
            "{rel} must carry Superseded banner (I-DOC-2)"
        );
        assert!(
            body.contains(&format!("EN({latest}).md")),
            "{rel} banner must point at EN({latest})"
        );
    }
}

#[test]
fn root_architecture_mermaid_is_deleted() {
    let path = workspace_root().join("docs/technical/Vauban_Architecture_Diagram.mermaid");
    assert!(
        !path.exists(),
        "fictional root mermaid must stay deleted (I-DOC-3): {}",
        path.display()
    );
}

#[test]
fn readme_architecture_table_has_no_adr_links() {
    let readme = std::fs::read_to_string(workspace_root().join("README.md")).expect("README");
    assert!(
        !readme.contains("docs/adr/"),
        "README must not link ADRs from the architecture table"
    );
}
