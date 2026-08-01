//! Package filename, size display, and version ordering for release artifacts.

use std::cmp::Ordering;

/// Strip a single leading `v` / `V` from a DB version string for package names.
pub fn version_for_package(version: &str) -> &str {
    version
        .strip_prefix('v')
        .or_else(|| version.strip_prefix('V'))
        .unwrap_or(version)
}

/// Parsed release version for ordering (numeric core + optional client suffix).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionSortKey {
    nums: Vec<u64>,
    /// `true` when version is `X.Y.Z-client_name` (org-private hotfix).
    has_client_suffix: bool,
    /// Client suffix (`acme1`, …); empty for plain GA versions.
    suffix: String,
}

/// Parse a DB version (`v1.0.2`, `v0.8.6-acme1`) into a comparable key.
pub fn version_sort_key(version: &str) -> VersionSortKey {
    let ver = version_for_package(version);
    let (core, suffix) = match ver.split_once('-') {
        Some((c, s)) => (c, s.to_owned()),
        None => (ver, String::new()),
    };
    let mut nums: Vec<u64> = core
        .split('.')
        .map(|part| {
            let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse().unwrap_or(0)
        })
        .collect();
    while nums.len() < 3 {
        nums.push(0);
    }
    let has_client_suffix = !suffix.is_empty();
    VersionSortKey {
        nums,
        has_client_suffix,
        suffix,
    }
}

/// List order: higher numeric version first; for the same `X.Y.Z`,
/// `X.Y.Z-client` rows sit above plain `X.Y.Z`, sorted A→Z by client name.
/// Ignores release dates.
pub fn cmp_version_desc(a: &str, b: &str) -> Ordering {
    let ka = version_sort_key(a);
    let kb = version_sort_key(b);
    kb.nums
        .cmp(&ka.nums)
        .then_with(|| kb.has_client_suffix.cmp(&ka.has_client_suffix))
        .then_with(|| ka.suffix.cmp(&kb.suffix))
}

/// Artifact basename: LTS → `vauban-{ver}+LTS.pkg`, else `vauban-{ver}.pkg`.
/// DB versions may keep a leading `v`; package names never include it.
pub fn package_file_name(version: &str, channel: &str) -> String {
    let ver = version_for_package(version);
    if channel.eq_ignore_ascii_case("LTS") {
        format!("vauban-{ver}+LTS.pkg")
    } else {
        format!("vauban-{ver}.pkg")
    }
}

/// One-decimal MiB display string (`bytes / 1048576`).
pub fn size_mb_from_bytes(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / 1_048_576.0)
}

/// Shell verify command copied from the Verify signature panel.
pub fn sha256_cmd(package_name: &str) -> String {
    format!("sha256 {package_name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_name_strips_v_and_adds_lts() {
        assert_eq!(package_file_name("v1.0.0", "LTS"), "vauban-1.0.0+LTS.pkg");
        assert_eq!(package_file_name("v0.9.35", "Stable"), "vauban-0.9.35.pkg");
        assert_eq!(package_file_name("1.2.3", "LTS"), "vauban-1.2.3+LTS.pkg");
    }

    #[test]
    fn size_mb_one_decimal() {
        assert_eq!(size_mb_from_bytes(22_419_122), "21.4");
        assert_eq!(size_mb_from_bytes(22_565_449), "21.5");
    }

    #[test]
    fn sha256_command_shape() {
        assert_eq!(
            sha256_cmd("vauban-1.0.0+LTS.pkg"),
            "sha256 vauban-1.0.0+LTS.pkg"
        );
    }

    #[test]
    fn version_sort_ignores_dates_and_orders_by_number() {
        let mut vers = vec![
            "v0.9.35",
            "v1.0.0",
            "v0.2.0",
            "v1.0.2",
            "v0.8.6-zenith",
            "v0.8.6-acme1",
            "v0.8.6",
            "v0.9.4",
        ];
        vers.sort_by(|a, b| cmp_version_desc(a, b));
        assert_eq!(
            vers,
            vec![
                "v1.0.2",
                "v1.0.0",
                "v0.9.35",
                "v0.9.4",
                "v0.8.6-acme1",
                "v0.8.6-zenith",
                "v0.8.6",
                "v0.2.0",
            ]
        );
    }

    #[test]
    fn version_sort_key_treats_missing_patch_as_zero() {
        assert_eq!(
            version_sort_key("v1.0").nums,
            version_sort_key("v1.0.0").nums
        );
        assert!(version_sort_key("v1.0.1").nums > version_sort_key("v1.0").nums);
    }
}
