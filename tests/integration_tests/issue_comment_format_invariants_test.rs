//! Source-shape invariants for issue comment docs dialect.

use std::process::Command;

#[test]
fn inv_check_issue_comment_format_script() {
    let output = Command::new("bash")
        .arg("scripts/check_issue_comment_format.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_issue_comment_format.sh");
    assert!(
        output.status.success(),
        "scripts/check_issue_comment_format.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_shared_renderer_and_raw_mail() {
    let thumbs = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/issue_thumbs.rs"
    ));
    let notify = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/issue_notify.rs"));
    let formatted = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/_components/docs_formatted.rs"
    ));
    assert!(thumbs.contains("docs_formatted_body"));
    assert!(formatted.contains("docs_body::parse"));
    assert!(formatted.contains("vb-pre"));
    assert!(!notify.contains("docs_body::parse"));
    assert!(!notify.contains("docs_formatted_body"));
}

#[test]
fn inv_titles_stay_raw() {
    let org = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues/issue_key.rs"
    ));
    let admin = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/issues/issue_key.rs"
    ));
    assert!(org.contains("issue.title.clone()"));
    assert!(admin.contains("issue.title.clone()"));
    assert!(!org.contains("docs_formatted_body(body: &issue.title"));
    assert!(!admin.contains("docs_formatted_body(body: &issue.title"));
}
