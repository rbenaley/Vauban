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
    /// Exactly three components (pad / truncate) — matches SQL columns.
    nums: [u64; 3],
    /// `true` when version is `X.Y.Z-client_name` (org-private hotfix).
    has_client_suffix: bool,
    /// Client suffix (`acme1`, …); empty for plain GA versions.
    suffix: String,
}

/// DB columns for SQL `ORDER BY` matching [`cmp_version_desc`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionSortFields {
    pub v_major: u64,
    pub v_minor: u64,
    pub v_patch: u64,
    /// `1` when a client suffix is present; else `0`.
    pub has_client_suffix: u64,
    pub client_suffix: String,
}

/// Parse a DB version (`v1.0.2`, `v0.8.6-acme1`) into a comparable key.
pub fn version_sort_key(version: &str) -> VersionSortKey {
    let ver = version_for_package(version);
    let (core, suffix) = match ver.split_once('-') {
        Some((c, s)) => (c, s.to_owned()),
        None => (ver, String::new()),
    };
    let mut parts: Vec<u64> = core
        .split('.')
        .map(|part| {
            let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse().unwrap_or(0)
        })
        .collect();
    while parts.len() < 3 {
        parts.push(0);
    }
    parts.truncate(3);
    let nums = [parts[0], parts[1], parts[2]];
    let has_client_suffix = !suffix.is_empty();
    VersionSortKey {
        nums,
        has_client_suffix,
        suffix,
    }
}

/// Materialize sort columns from a version string (write path + resync).
pub fn version_sort_fields(version: &str) -> VersionSortFields {
    let key = version_sort_key(version);
    VersionSortFields {
        v_major: key.nums[0],
        v_minor: key.nums[1],
        v_patch: key.nums[2],
        has_client_suffix: u64::from(key.has_client_suffix),
        client_suffix: key.suffix,
    }
}

/// List order: higher numeric version first; for the same `X.Y.Z`,
/// `X.Y.Z-client` rows sit above plain `X.Y.Z`, sorted A→Z by client name.
/// Ignores release dates. Must match SQL
/// `ORDER BY v_major DESC, v_minor DESC, v_patch DESC, has_client_suffix DESC, client_suffix ASC`.
pub fn cmp_version_desc(a: &str, b: &str) -> Ordering {
    let fa = version_sort_fields(a);
    let fb = version_sort_fields(b);
    cmp_sort_fields_desc(&fa, &fb)
}

/// Compare materialized sort fields (same order as SQL / [`cmp_version_desc`]).
pub fn cmp_sort_fields_desc(a: &VersionSortFields, b: &VersionSortFields) -> Ordering {
    b.v_major
        .cmp(&a.v_major)
        .then_with(|| b.v_minor.cmp(&a.v_minor))
        .then_with(|| b.v_patch.cmp(&a.v_patch))
        .then_with(|| b.has_client_suffix.cmp(&a.has_client_suffix))
        .then_with(|| a.client_suffix.cmp(&b.client_suffix))
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

    #[test]
    fn version_sort_fields_match_cmp_and_truncate_extra_components() {
        let f = version_sort_fields("v1.2.3.9-acme");
        assert_eq!(f.v_major, 1);
        assert_eq!(f.v_minor, 2);
        assert_eq!(f.v_patch, 3);
        assert_eq!(f.has_client_suffix, 1);
        assert_eq!(f.client_suffix, "acme");
        assert_eq!(
            cmp_version_desc("v1.2.3.9-acme", "v1.2.3-acme"),
            Ordering::Equal
        );
        assert_eq!(
            cmp_sort_fields_desc(
                &version_sort_fields("v0.8.6-acme1"),
                &version_sort_fields("v0.8.6")
            ),
            Ordering::Less
        );
    }
}
