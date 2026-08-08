//! Source-shape invariants for release-note inline ``code`` chips.

use std::process::Command;

#[test]
fn inv_check_release_notes_inline_script() {
    let output = Command::new("bash")
        .arg("scripts/check_release_notes_inline.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_release_notes_inline.sh");
    assert!(
        output.status.success(),
        "scripts/check_release_notes_inline.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_helper_is_shared_library_module() {
    let lib = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
    assert!(
        lib.contains("pub mod release_notes;"),
        "release_notes must be a public library module"
    );
    let helper = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/release_notes.rs"));
    assert!(helper.contains("parse_inline_code"));
    assert!(helper.contains("InlineSegment::Code"));
    assert!(
        !helper.contains("<script"),
        "helper must not embed raw HTML"
    );
}

#[test]
fn inv_builds_and_dashboard_wire_note_inline_text() {
    let builds = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/builds.rs"
    ));
    let org = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/org.rs"));
    let comp = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/_components/note_inline.rs"
    ));
    let css = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/styles.css"));

    assert!(
        builds.contains("note_inline_text"),
        "Builds changelog must use note_inline_text"
    );
    assert!(
        org.contains("note_inline_text"),
        "org dashboard must use note_inline_text"
    );
    assert!(
        comp.contains("vb-inline-code") && comp.contains("parse_inline_code"),
        "component must map Code segments to vb-inline-code"
    );
    assert!(
        css.contains(".vb-inline-code"),
        "styles.css must define .vb-inline-code"
    );
}

#[test]
fn inv_components_mod_exports_note_inline_text() {
    let mods = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/_components.rs"
    ));
    assert!(mods.contains("mod note_inline;"));
    assert!(mods.contains("note_inline_text"));
}
