//! `shared/scripts/check_no_environment_data.sh`, run on the repository
//! and on small trees that break its rule.
//!
//! The repository is public and its history cannot be rewritten: an
//! address or a home directory of a real system must not reach a commit.
//! The script finds what a pattern can find; these tests pin what it
//! accepts and what it refuses, so that it cannot be loosened unnoticed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

const SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/scripts/check_no_environment_data.sh"
);
const BASELINE: &str = include_str!("../scripts/environment_data_baseline.txt");

/// A scratch directory holding one file with `content`.
fn tree(name: &str, content: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("env_data_{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("sample.md"), content).unwrap();
    dir
}

fn accepts(name: &str, content: &str) -> bool {
    let dir = tree(name, content);
    let passed = Command::new("bash")
        .arg(SCRIPT)
        .arg(&dir)
        .output()
        .expect("bash runs the lint")
        .status
        .success();
    let _ = std::fs::remove_dir_all(&dir);
    passed
}

#[test]
fn the_repository_passes() {
    let output = Command::new("bash")
        .arg(SCRIPT)
        .output()
        .expect("bash runs the lint");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn reserved_addresses_are_accepted() {
    assert!(accepts(
        "reserved",
        "loopback 127.0.0.1, any 0.0.0.0, docs 192.0.2.10, 198.51.100.7 and 203.0.113.9:88.\n"
    ));
}

/// 240.0.0.0/4 is reserved and unrouted: an address that is neither a
/// documentation one nor anybody's.
#[test]
fn attack_a_public_address_is_refused() {
    assert!(!accepts("public", "the client came from 240.17.33.201\n"));
}

/// A private address is still an address of someone's network.
#[test]
fn attack_a_private_address_outside_the_baseline_is_refused() {
    assert!(!accepts("private", "kdc_host = \"10.77.12.5\"\n"));
    assert!(!accepts("private_192", "target 192.168.44.17:3389\n"));
}

#[test]
fn attack_an_address_at_the_end_of_a_sentence_is_refused() {
    assert!(!accepts(
        "sentence",
        "The request came from 240.17.33.201.\n"
    ));
}

#[test]
fn attack_an_address_in_a_url_or_with_a_port_is_refused() {
    assert!(!accepts("url", "SSPI_KDC_URL=tcp://240.17.33.201:88\n"));
    assert!(!accepts("cidr", "allowed = [\"240.17.33.0/24\"]\n"));
}

#[test]
fn dotted_numbers_that_are_not_addresses_are_accepted() {
    assert!(accepts(
        "not_addresses",
        "OID 1.3.6.1.5.5.2, section 2.2.1.2, build 10.519.149.023, part 09.00.10.08, 999.1.1.1.\n"
    ));
}

#[test]
fn generic_home_directories_are_accepted() {
    assert!(accepts(
        "generic_home",
        "/home/user/.ssh, /home/builder/src and /Users/username/Vauban\n"
    ));
}

#[test]
fn attack_a_named_home_directory_is_refused() {
    assert!(!accepts("named_home", "/Users/rsmith/Code/Vauban/\n"));
    assert!(!accepts("named_home_linux", "/home/rsmith/vauban/config\n"));
}

/// The baseline is a list of addresses and nothing else, sorted, without
/// duplicates: a line cannot be slipped in unseen.
#[test]
fn the_baseline_is_a_sorted_list_of_addresses() {
    let values: Vec<&str> = BASELINE
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .collect();
    assert!(!values.is_empty());
    let key = |value: &str| -> Vec<u32> {
        value
            .split('.')
            .map(|part| {
                part.parse()
                    .unwrap_or_else(|_| panic!("not a dotted number: {value}"))
            })
            .collect()
    };
    for value in &values {
        assert_eq!(key(value).len(), 4, "not four parts: {value}");
    }
    for pair in values.windows(2) {
        assert!(
            key(pair[0]) < key(pair[1]),
            "not sorted or duplicated: {pair:?}"
        );
    }
}

/// The baseline only shrinks: its size when the lint was added is the
/// ceiling. Lower this number when a line is removed.
#[test]
fn the_baseline_does_not_grow() {
    let count = BASELINE
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .count();
    assert!(count <= 55, "the baseline grew to {count} lines");
}

/// Reserved blocks never need a baseline line.
#[test]
fn the_baseline_holds_no_reserved_address() {
    for value in BASELINE.lines().filter(|line| !line.starts_with('#')) {
        assert!(!value.starts_with("127."));
        assert!(!value.starts_with("192.0.2."));
        assert!(!value.starts_with("198.51.100."));
        assert!(!value.starts_with("203.0.113."));
    }
}
