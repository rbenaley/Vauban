//! Source invariants for evidence sub-crate + sealed mailer extract (§10.13).

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("parent")
        .to_path_buf()
}

fn run_lint(name: &str) -> std::process::Output {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join(name);
    assert!(script.exists(), "missing {}", script.display());
    Command::new("bash")
        .arg(&script)
        .output()
        .unwrap_or_else(|e| panic!("run {name}: {e}"))
}

#[test]
fn check_web_evidence_crate_lint_passes() {
    let out = run_lint("check_web_evidence_crate.sh");
    assert!(
        out.status.success(),
        "check_web_evidence_crate.sh failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn check_mailer_sealed_lint_passes() {
    let out = run_lint("check_mailer_sealed.sh");
    assert!(
        out.status.success(),
        "check_mailer_sealed.sh failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn inv_service_mailer_discriminant_is_nine() {
    assert_eq!(shared::messages::Service::Mailer.as_token_discriminant(), 9);
}

#[test]
fn inv_web_reexports_evidence_analyzer() {
    let mod_rs = include_str!("../../src/services/mod.rs");
    assert!(mod_rs.contains("vauban_web_evidence::analyzer as iacs_packet_analyzer"));
}

#[test]
fn inv_web_keeps_mailer_queue_not_smtp_dispatcher() {
    let mailer = include_str!("../../src/services/mailer.rs");
    assert!(
        mailer.contains("pub async fn queue") || mailer.contains("fn queue"),
        "web must keep Mailer::queue"
    );
    let tasks_mod = include_str!("../../src/tasks/mod.rs");
    assert!(
        !tasks_mod.contains("mod mailer") && !tasks_mod.contains("start_mailer_dispatcher"),
        "web must not spawn sealed mailer dispatcher"
    );
}

#[test]
fn inv_evidence_hydrator_pipeline_exists() {
    let root = repo_root();
    assert!(
        root.join("vauban-web-evidence/src/hydrator/pipeline.rs")
            .exists()
    );
    assert!(
        root.join("vauban-web/src/services/recording_hydrator/adapters.rs")
            .exists()
    );
}

#[test]
fn inv_mailer_crate_targets_service_mailer() {
    let broker = std::fs::read_to_string(repo_root().join("vauban-mailer/src/broker.rs"))
        .expect("broker.rs");
    assert!(
        broker.contains("Service::Mailer"),
        "mailer broker must request TcpConnect with Service::Mailer"
    );
}

#[test]
fn inv_mailer_fd_passing_not_in_ipc_vec() {
    let main = include_str!("../../../vauban-mailer/src/main.rs");
    assert!(
        !main.contains("vec![ipc_read_fd, ipc_write_fd, fd_passing_socket]"),
        "fd_passing_socket must not appear in ipc_fds (ConflictingFdRights)"
    );
    assert!(
        main.contains("let ipc_fds = vec![ipc_read_fd, ipc_write_fd]"),
        "ipc_fds must be supervisor pipes only"
    );
    assert!(
        main.contains("one fd, one kind"),
        "mailer main must document one-fd-one-kind at seal site"
    );
    assert!(
        main.contains("fd_passing_socket")
            && main.contains("fd_receiver_fds")
            && main.contains("setup_service_sandbox_extended(&ipc_fds"),
        "fd_passing must be declared via fd_receiver_fds only"
    );
}

#[test]
fn inv_mailer_kinds_catalogue_exists() {
    let profiles = include_str!("../../../shared/src/sandbox/profiles.rs");
    assert!(
        profiles.contains("pub const MAILER_KINDS"),
        "shared sandbox profiles must define MAILER_KINDS"
    );
    assert!(
        profiles.contains("MAILER_KINDS")
            && profiles.contains("ResourceKind::IpcPipe")
            && profiles.contains("ResourceKind::FdReceiver"),
        "MAILER_KINDS must be IpcPipe + FdReceiver"
    );
}

#[test]
fn inv_production_mailer_uid_gid_is_909() {
    let conf =
        std::fs::read_to_string(repo_root().join("config/vauban.conf")).expect("vauban.conf");
    let start = conf
        .find("[services.mailer]")
        .expect("[services.mailer] in vauban.conf");
    let window = &conf[start..start.saturating_add(200).min(conf.len())];
    assert!(
        window.contains("uid = 909") && window.contains("gid = 909"),
        "production mailer must run as uid/gid 909"
    );
}

#[test]
fn inv_pkg_creates_vb_mailer_909() {
    let pre = std::fs::read_to_string(repo_root().join("pkg/+PRE_INSTALL")).expect("PRE_INSTALL");
    assert!(
        pre.contains("create_user_if_missing vb-mailer 909 909 vauban-mailer"),
        "pkg/+PRE_INSTALL must create vb-mailer 909/909"
    );
    let post =
        std::fs::read_to_string(repo_root().join("pkg/+POST_INSTALL")).expect("POST_INSTALL");
    assert!(
        post.contains("vb-mailer"),
        "pkg/+POST_INSTALL must ACL vb-mailer on etc/vauban"
    );
    let build = std::fs::read_to_string(repo_root().join("pkg/build-pkg.sh")).expect("build-pkg");
    assert!(
        build.contains("vauban-mailer"),
        "pkg/build-pkg.sh must stage vauban-mailer binary"
    );
}
