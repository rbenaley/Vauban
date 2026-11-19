//! Invariants on the workspace `[patch.crates-io]` section, and the mirror
//! of `scripts/check_patch_pins.sh` so that they also fail under
//! `cargo test`.
//!
//! `Cargo.lock` is not versioned: an entry without a `rev` builds whatever
//! its branch holds that day. The `sspi` entry carries the fix without
//! which both Kerberos RDP modes fail against every Windows target (the
//! acceptor signs the SPNEGO mechListMIC with sequence number 0, which
//! `sspi` 0.23.0 refuses).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

const MANIFEST: &str = include_str!("../../Cargo.toml");
const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/check_patch_pins.sh");

/// The entries of `[patch.crates-io]`: no comments, no blank lines.
fn patch_entries(manifest: &str) -> Vec<&str> {
    manifest
        .lines()
        .skip_while(|line| line.trim() != "[patch.crates-io]")
        .skip(1)
        .take_while(|line| !line.starts_with('['))
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

fn rev_of(entry: &str) -> Option<&str> {
    let rest = entry.split("rev = \"").nth(1)?;
    rest.split('"').next()
}

#[test]
fn every_patch_entry_is_pinned_by_a_full_commit_id() {
    let entries = patch_entries(MANIFEST);
    assert!(!entries.is_empty(), "no [patch.crates-io] entry found");
    for entry in entries {
        let rev = rev_of(entry).unwrap_or_else(|| panic!("entry without rev: {entry}"));
        assert_eq!(rev.len(), 40, "rev is not a full commit id: {entry}");
        assert!(
            rev.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "rev is not lowercase hexadecimal: {entry}"
        );
        assert!(
            !entry.contains("branch = "),
            "entry follows a branch: {entry}"
        );
        assert!(!entry.contains("tag = "), "entry follows a tag: {entry}");
    }
}

#[test]
fn sspi_is_taken_from_the_fork_with_the_windows_mic_fix() {
    let entries = patch_entries(MANIFEST);
    let sspi = entries
        .iter()
        .find(|entry| entry.starts_with("sspi ") || entry.starts_with("sspi="))
        .expect("the sspi entry is gone from [patch.crates-io]");
    assert!(
        sspi.contains("git = \"https://github.com/rbenaley/sspi-rs-vb\""),
        "sspi must come from the fork: {sspi}"
    );
}

/// The manifest states why the fork exists and when it goes away.
#[test]
fn the_sspi_entry_states_its_removal_condition() {
    let section = MANIFEST
        .split("[patch.crates-io]")
        .nth(1)
        .expect("[patch.crates-io] section");
    assert!(section.contains("Devolutions/sspi-rs#772"));
    assert!(section.contains("when IronRDP resolves sspi >= 0.23.1"));
}

/// Run the lint on `manifest`, written under the test's own scratch
/// directory. `name` keeps parallel tests on separate files.
fn run_script_on(name: &str, manifest: &str) -> bool {
    let path =
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("patch_pins_{name}.toml"));
    std::fs::write(&path, manifest).unwrap();
    let passed = Command::new("bash")
        .arg(SCRIPT)
        .arg(&path)
        .output()
        .expect("bash runs the lint")
        .status
        .success();
    let _ = std::fs::remove_file(&path);
    passed
}

#[test]
fn the_lint_accepts_the_workspace_manifest() {
    assert!(run_script_on("workspace", MANIFEST));
}

#[test]
fn attack_the_lint_refuses_an_entry_without_rev() {
    let floating = MANIFEST.replacen(
        ", rev = \"07926c0cd7c816cea02602288535600fe8d3a5da\"",
        "",
        1,
    );
    assert_ne!(
        floating, MANIFEST,
        "the sspi rev is not the one this test knows"
    );
    assert!(!run_script_on("floating", &floating));
}

#[test]
fn attack_the_lint_refuses_an_entry_following_a_branch() {
    let branch = MANIFEST.replacen(
        "rev = \"07926c0cd7c816cea02602288535600fe8d3a5da\"",
        "branch = \"vauban/0.23.0-mic-seq\"",
        1,
    );
    assert!(!run_script_on("branch", &branch));
}

#[test]
fn attack_the_lint_refuses_a_manifest_without_the_sspi_fork() {
    let without: String = MANIFEST
        .lines()
        .filter(|line| !line.starts_with("sspi = "))
        .map(|line| format!("{line}\n"))
        .collect();
    assert!(!run_script_on("without", &without));
}

#[test]
fn attack_the_lint_refuses_sspi_from_another_repository() {
    let elsewhere = MANIFEST.replacen("rbenaley/sspi-rs-vb", "someone/sspi-rs", 1);
    assert!(!run_script_on("elsewhere", &elsewhere));
}
