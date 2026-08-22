//! Source-shape invariants for branded transactional email HTML.

use std::process::Command;

#[test]
fn inv_check_mail_templates_script() {
    let output = Command::new("bash")
        .arg("scripts/check_mail_templates.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_mail_templates.sh");
    assert!(
        output.status.success(),
        "scripts/check_mail_templates.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_mailer_sends_html_text_and_cid_logo() {
    let mailer = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/mailer.rs"));
    assert!(mailer.contains("deliver_branded"));
    assert!(mailer.contains("mail!"));
    assert!(mailer.contains("login_mail_html"));
    assert!(mailer.contains("join_mail_html"));
    assert!(mailer.contains("leave_mail_html"));
    assert!(mailer.contains("issue_mail_html"));
    assert!(mailer.contains("Attachment::inline"));
    assert!(mailer.contains("LOGO_CONTENT_ID"));
    assert!(
        !mailer.contains("Unescaped"),
        "mailer must not use Unescaped on the send path"
    );
    assert!(
        !mailer.contains("send_text_mail"),
        "plain-only send_text_mail path must be gone"
    );
}

#[test]
fn inv_email_tree_placeholders_and_no_base64() {
    let join = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/email/user-join.html"));
    let login = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/email/user-login.html"
    ));
    let leave = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/email/user-leave.html"
    ));
    let issue = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/email/issue-event.html"
    ));
    for (name, html) in [
        ("join", join),
        ("login", login),
        ("leave", leave),
        ("issue", issue),
    ] {
        assert!(html.contains(r#"src="cid:vauban-logo""#), "{name} cid");
        assert!(!html.contains("data:image"), "{name} no data URI");
    }
    assert!(join.contains("__ORG_NAME__") && join.contains("__MAGIC_URL__"));
    assert!(login.contains("__MAGIC_URL__") && !login.contains("__ORG_NAME__"));
    assert!(leave.contains("__ORG_NAME__") && !leave.contains("__MAGIC_URL__"));
}
