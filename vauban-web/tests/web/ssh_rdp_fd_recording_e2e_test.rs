//! E2E / wiring pins for proxy-owned SSH/RDP FD recording (0.9.29).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[test]
fn e2e_ui_lossy_wording_is_io_not_audit_channel() {
    let detail = include_str!("../../templates/sessions/recording_detail.html");
    assert!(detail.contains("Incomplete capture"));
    assert!(
        detail.contains("local recording write") || detail.contains("FD lease"),
        "detail must describe I/O / FD lease failure, not audit channel drops"
    );
    assert!(
        !detail.contains("audit channel dropped"),
        "legacy audit-channel wording must be gone"
    );
}

#[test]
fn e2e_recording_architecture_doc_is_19() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace");
    assert!(
        root.join("docs/technical/Vauban_Recording_Architecture_EN(1.9).md")
            .exists()
    );
    let adr =
        std::fs::read_to_string(root.join("docs/adr/001-recording-durability-per-protocol.md"))
            .expect("ADR 001");
    assert!(adr.contains("proxy-owned") || adr.contains("brokered FDs"));
    assert!(
        root.join("docs/runbooks/ssh_rdp_fd_recording_smoke_test.md")
            .exists()
    );
}
