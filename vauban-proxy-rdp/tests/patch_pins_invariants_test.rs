//! Invariants on the workspace `[patch.crates-io]` section, and the mirror
//! of `scripts/check_patch_pins.sh` so that they also fail under
//! `cargo test`.
//!
//! `Cargo.lock` is not versioned: an entry without a `rev` builds whatever
//! its branch holds that day. The `ironrdp-*` entries carry Remote
//! Credential Guard, which no published crate has; they must all come
//! from upstream IronRDP, on one rev. The proxy has its own backend for
//! the redirection channel and leaves the connector's `remote-guard`
//! feature off.
//! `sspi` comes from crates.io: 0.23.1 holds the Windows mechListMIC fix
//! the `sspi-rs-vb` fork used to carry.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

const MANIFEST: &str = include_str!("../../Cargo.toml");
const PROXY_MANIFEST: &str = include_str!("../Cargo.toml");
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

const IRONRDP_REPO: &str = "git = \"https://github.com/Devolutions/IronRDP\"";
const IRONRDP_REV: &str = "a8da54ba4d849370bc92e1d5230cc18e99cf5ff1";
/// Any other full commit id, for the tests that move one entry.
const OTHER_REV: &str = "0123456789abcdef0123456789abcdef01234567";

fn ironrdp_entries(manifest: &str) -> Vec<&str> {
    patch_entries(manifest)
        .into_iter()
        .filter(|entry| entry.starts_with("ironrdp-"))
        .collect()
}

/// The crate name of an entry: what precedes ` = `.
fn name_of(entry: &str) -> &str {
    entry.split('=').next().unwrap_or(entry).trim()
}

#[test]
fn every_ironrdp_crate_comes_from_upstream_on_one_rev() {
    let entries = ironrdp_entries(MANIFEST);
    assert!(
        entries
            .iter()
            .any(|entry| name_of(entry) == "ironrdp-connector"),
        "the ironrdp-connector entry is gone from [patch.crates-io]"
    );
    for entry in &entries {
        assert!(
            entry.contains(IRONRDP_REPO),
            "an ironrdp entry must come from upstream IronRDP: {entry}"
        );
        assert_eq!(
            rev_of(entry),
            Some(IRONRDP_REV),
            "an ironrdp entry is on another rev: {entry}"
        );
    }
}

/// Every `ironrdp-*` package the proxy resolves is patched. One left on
/// crates.io would be a second copy of the types the others exchange.
/// `ironrdp-rdpear` is not on crates.io: it has no entry and reaches the
/// tree as a direct dependency of the proxy.
#[test]
fn every_resolved_ironrdp_crate_has_an_entry() {
    let patched: Vec<&str> = ironrdp_entries(MANIFEST).into_iter().map(name_of).collect();
    let output = Command::new(env!("CARGO"))
        .args(["tree", "-p", "vauban-proxy-rdp", "--prefix", "none"])
        .args(["--edges", "normal,build", "--format", "{p}"])
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
        .output()
        .expect("cargo tree runs");
    assert!(output.status.success(), "cargo tree failed");
    let tree = String::from_utf8(output.stdout).unwrap();
    let mut seen = 0;
    for line in tree.lines().filter(|line| line.starts_with("ironrdp-")) {
        seen += 1;
        let name = line.split(' ').next().unwrap();
        assert!(
            line.contains("github.com/Devolutions/IronRDP?rev="),
            "{name} does not come from upstream IronRDP: {line}"
        );
        assert!(
            name == "ironrdp-rdpear" || patched.contains(&name),
            "{name} is resolved but has no [patch.crates-io] entry"
        );
    }
    assert!(seen > 0, "cargo tree lists no ironrdp crate");
}

#[test]
fn sspi_comes_from_the_registry() {
    assert!(
        !patch_entries(MANIFEST)
            .iter()
            .any(|entry| name_of(entry) == "sspi"),
        "an sspi entry is back in [patch.crates-io]"
    );
}

/// The manifest states why the entries exist and when they go away.
#[test]
fn the_ironrdp_entries_state_their_removal_condition() {
    let section = MANIFEST
        .split("[patch.crates-io]")
        .nth(1)
        .expect("[patch.crates-io] section");
    assert!(section.contains("Devolutions/sspi-rs#772"));
    assert!(
        section.contains("when a\n# published IronRDP release contains Remote Credential Guard")
    );
    assert!(section.contains("KERB_ASN1_DATA.Pdu"));
    assert!(section.contains("without a DNS resolver"));
    assert!(section.contains("remote_guard_channel.rs"));
}

/// Run the lint on `manifest` and on the proxy's own manifest, written
/// under the test's own scratch directory. `name` keeps parallel tests
/// on separate files.
fn run_script_on_both(name: &str, manifest: &str, proxy_manifest: &str) -> bool {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    let path = dir.join(format!("patch_pins_{name}.toml"));
    let proxy_path = dir.join(format!("patch_pins_{name}_proxy.toml"));
    std::fs::write(&path, manifest).unwrap();
    std::fs::write(&proxy_path, proxy_manifest).unwrap();
    let passed = Command::new("bash")
        .arg(SCRIPT)
        .arg(&path)
        .arg(&proxy_path)
        .output()
        .expect("bash runs the lint")
        .status
        .success();
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&proxy_path);
    passed
}

/// Run the lint on `manifest`, with the proxy's real manifest.
fn run_script_on(name: &str, manifest: &str) -> bool {
    run_script_on_both(name, manifest, PROXY_MANIFEST)
}

/// The line of the proxy manifest that takes `ironrdp-rdpear` from
/// upstream.
fn rdpear_line() -> &'static str {
    PROXY_MANIFEST
        .lines()
        .find(|line| line.starts_with("ironrdp-rdpear = "))
        .expect("ironrdp-rdpear dependency")
}

/// `ironrdp-rdpear` is not on crates.io: the proxy takes it from
/// upstream directly, on the rev of the patch entries.
#[test]
fn the_direct_git_dependency_is_on_the_patch_rev() {
    let line = rdpear_line();
    assert!(line.contains(IRONRDP_REPO), "{line}");
    assert_eq!(rev_of(line), Some(IRONRDP_REV), "{line}");
    assert!(!line.contains("branch = ") && !line.contains("tag = "));
}

#[test]
fn attack_the_lint_refuses_a_direct_git_dependency_on_another_rev() {
    let line = rdpear_line();
    let other = line.replacen(IRONRDP_REV, OTHER_REV, 1);
    assert_ne!(other, line);
    let proxy = PROXY_MANIFEST.replacen(line, &other, 1);
    assert!(!run_script_on_both("direct_rev", MANIFEST, &proxy));
}

#[test]
fn attack_the_lint_refuses_a_direct_git_dependency_following_a_branch() {
    let line = rdpear_line();
    let branch = line.replacen(
        &format!("rev = \"{IRONRDP_REV}\""),
        "branch = \"master\"",
        1,
    );
    assert_ne!(branch, line);
    let proxy = PROXY_MANIFEST.replacen(line, &branch, 1);
    assert!(!run_script_on_both("direct_branch", MANIFEST, &proxy));
}

#[test]
fn the_lint_accepts_the_workspace_manifest() {
    assert!(run_script_on("workspace", MANIFEST));
}

/// The first `ironrdp-connector` entry line of the manifest.
fn connector_line() -> &'static str {
    MANIFEST
        .lines()
        .find(|line| line.starts_with("ironrdp-connector = "))
        .expect("ironrdp-connector entry")
}

#[test]
fn attack_the_lint_refuses_an_entry_without_rev() {
    let line = connector_line();
    let floating_line = line.replacen(&format!(", rev = \"{IRONRDP_REV}\""), "", 1);
    assert_ne!(
        floating_line, line,
        "the ironrdp rev is not the one this test knows"
    );
    let floating = MANIFEST.replacen(line, &floating_line, 1);
    assert!(!run_script_on("floating", &floating));
}

#[test]
fn attack_the_lint_refuses_an_entry_following_a_branch() {
    let line = connector_line();
    let branch_line = line.replacen(
        &format!("rev = \"{IRONRDP_REV}\""),
        "branch = \"master\"",
        1,
    );
    let branch = MANIFEST.replacen(line, &branch_line, 1);
    assert!(!run_script_on("branch", &branch));
}

#[test]
fn attack_the_lint_refuses_a_manifest_without_the_connector_entry() {
    let without: String = MANIFEST
        .lines()
        .filter(|line| !line.starts_with("ironrdp-connector = "))
        .map(|line| format!("{line}\n"))
        .collect();
    assert!(!run_script_on("without", &without));
}

#[test]
fn attack_the_lint_refuses_an_ironrdp_crate_from_another_repository() {
    let line = connector_line();
    let elsewhere_line = line.replacen("Devolutions/IronRDP", "someone/IronRDP", 1);
    let elsewhere = MANIFEST.replacen(line, &elsewhere_line, 1);
    assert!(!run_script_on("elsewhere", &elsewhere));
}

#[test]
fn attack_the_lint_refuses_ironrdp_crates_on_two_revs() {
    let line = connector_line();
    let other_line = line.replacen(IRONRDP_REV, OTHER_REV, 1);
    let split = MANIFEST.replacen(line, &other_line, 1);
    assert!(!run_script_on("two_revs", &split));
}

#[test]
fn attack_the_lint_refuses_an_sspi_entry_brought_back() {
    let line = connector_line();
    let with_sspi = MANIFEST.replacen(
        line,
        &format!(
            "sspi = {{ git = \"https://github.com/rbenaley/sspi-rs-vb\", rev = \"07926c0cd7c816cea02602288535600fe8d3a5da\" }}\n{line}"
        ),
        1,
    );
    assert!(!run_script_on("sspi_back", &with_sspi));
}

/// The connector's `remote-guard` feature brings `sspi`'s DNS resolver
/// and a channel backend that returns `KERB_ASN1_DATA.Pdu` as 0. The proxy
/// installs its own backend and leaves the feature off.
#[test]
fn the_proxy_leaves_the_connector_remote_guard_feature_off() {
    let line = PROXY_MANIFEST
        .lines()
        .find(|line| line.starts_with("ironrdp-connector = "))
        .expect("ironrdp-connector dependency");
    assert!(!line.contains("remote-guard"), "{line}");
}

#[test]
fn attack_the_lint_refuses_the_connector_remote_guard_feature() {
    let line = PROXY_MANIFEST
        .lines()
        .find(|line| line.starts_with("ironrdp-connector = "))
        .expect("ironrdp-connector dependency");
    let with_feature = "ironrdp-connector = { version = \"0.12\", features = [\"remote-guard\"] }";
    let proxy = PROXY_MANIFEST.replacen(line, with_feature, 1);
    assert_ne!(proxy, PROXY_MANIFEST);
    assert!(!run_script_on_both("connector_feature", MANIFEST, &proxy));
}

/// The proxy is sandboxed and reaches a KDC through the supervisor broker:
/// no DNS resolver belongs in its tree. One would come back with the
/// connector's `remote-guard` feature (and fail `cargo deny`: the resolver
/// carries open advisories).
#[test]
fn the_proxy_has_no_dns_resolver_in_its_tree() {
    let output = Command::new(env!("CARGO"))
        .args(["tree", "-p", "vauban-proxy-rdp", "--prefix", "none"])
        .args(["--edges", "normal,build", "--format", "{p}"])
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
        .output()
        .expect("cargo tree runs");
    assert!(output.status.success(), "cargo tree failed");
    let tree = String::from_utf8(output.stdout).unwrap();
    assert!(tree.contains("sspi v"), "cargo tree does not list sspi");
    for line in tree.lines() {
        assert!(
            !line.starts_with("hickory-"),
            "a DNS resolver is in the proxy's dependency tree: {line}"
        );
    }
}
