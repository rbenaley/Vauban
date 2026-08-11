//! Package filename, size display, and version ordering for release artifacts.

use std::cmp::Ordering;

use crate::models::RESERVED_ORG_SLUG;

/// Product track / channel label for industrial LTS packages.
pub const PRODUCT_TRACK_INDUSTRIAL: &str = "LTS.industrial";
/// Product track for classic LTS packages.
pub const PRODUCT_TRACK_LTS: &str = "LTS";
/// Product track for Stable packages.
pub const PRODUCT_TRACK_STABLE: &str = "Stable";

const INDUSTRIAL_SUFFIX: &str = "+LTS.industrial";
const LTS_SUFFIX: &str = "+LTS";

/// Strip a single leading `v` / `V` from a DB version string for package names.
pub fn version_for_package(version: &str) -> &str {
    version
        .strip_prefix('v')
        .or_else(|| version.strip_prefix('V'))
        .unwrap_or(version)
}

/// FreeBSD / portal versions may end with `+LTS.industrial` (longest marker).
pub fn has_industrial_marker(version: &str) -> bool {
    let ver = version_for_package(version.trim());
    ver.len() >= INDUSTRIAL_SUFFIX.len()
        && ver[ver.len() - INDUSTRIAL_SUFFIX.len()..].eq_ignore_ascii_case(INDUSTRIAL_SUFFIX)
}

/// FreeBSD / portal versions may end with `+LTS` (not `+LTS.industrial`).
pub fn has_lts_marker(version: &str) -> bool {
    if has_industrial_marker(version) {
        return false;
    }
    let ver = version_for_package(version.trim());
    ver.len() >= LTS_SUFFIX.len()
        && ver[ver.len() - LTS_SUFFIX.len()..].eq_ignore_ascii_case(LTS_SUFFIX)
}

/// Remove trailing `+LTS.industrial` / `+LTS` and a leading `v`/`V`.
pub fn strip_track_markers(version: &str) -> &str {
    let ver = version_for_package(version.trim());
    if has_industrial_marker(version) {
        &ver[..ver.len() - INDUSTRIAL_SUFFIX.len()]
    } else if has_lts_marker(version) {
        &ver[..ver.len() - LTS_SUFFIX.len()]
    } else {
        ver
    }
}

/// Remove a trailing `+LTS` marker (case-insensitive). Leaves industrial alone.
pub fn strip_lts_marker(version: &str) -> &str {
    strip_track_markers(version)
}

fn strip_display_suffix<'a>(version: &'a str, suffix: &str) -> Option<&'a str> {
    let v = version.trim();
    if v.len() >= suffix.len() && v[v.len() - suffix.len()..].eq_ignore_ascii_case(suffix) {
        Some(&v[..v.len() - suffix.len()])
    } else {
        None
    }
}

/// Human-facing version label: keep a leading `v`, drop track markers.
///
/// List UIs show channel in its own column, so markers on the version are
/// redundant. Storage / URLs / package basenames keep the marker.
pub fn version_for_display(version: &str) -> &str {
    let v = version.trim();
    if let Some(stripped) = strip_display_suffix(v, INDUSTRIAL_SUFFIX) {
        return stripped;
    }
    if let Some(stripped) = strip_display_suffix(v, LTS_SUFFIX) {
        return stripped;
    }
    v
}

/// Ensure a portal version string ends with `+LTS` (preserves a leading `v`).
pub fn ensure_lts_marker(version: &str) -> String {
    if has_industrial_marker(version) {
        // Never downgrade an industrial marker to plain LTS.
        return version.to_owned();
    }
    if has_lts_marker(version) {
        return version.to_owned();
    }
    let trimmed = version.trim();
    if trimmed.is_empty() {
        return LTS_SUFFIX.to_owned();
    }
    format!("{trimmed}{LTS_SUFFIX}")
}

/// Ensure a portal version string ends with `+LTS.industrial`.
pub fn ensure_industrial_marker(version: &str) -> String {
    if has_industrial_marker(version) {
        return version.to_owned();
    }
    let core = strip_track_markers(version);
    let trimmed = version.trim();
    let with_v = if trimmed.starts_with('v') || trimmed.starts_with('V') {
        format!("{}{core}", &trimmed[..1])
    } else if core.is_empty() {
        String::new()
    } else {
        format!("v{core}")
    };
    if with_v.is_empty() {
        return INDUSTRIAL_SUFFIX.to_owned();
    }
    format!("{with_v}{INDUSTRIAL_SUFFIX}")
}

/// Identity derived from a FreeBSD package manifeste `Version` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedReleaseIdentity {
    /// Portal DB version (`v1.0.1`, `v1.0.1+LTS`, or `v1.0.1+LTS.industrial`).
    pub version: String,
    /// `LTS.industrial`, `LTS`, or `Stable` — never `EOL` at create time.
    pub channel: &'static str,
}

/// Map manifeste `Version` → portal version + channel.
///
/// Markers are matched longest-first (`+LTS.industrial` then `+LTS`).
/// Empty / whitespace-only input returns `None`.
pub fn derive_release_identity(pkg_version: &str) -> Option<DerivedReleaseIdentity> {
    let raw = pkg_version.trim();
    if raw.is_empty() {
        return None;
    }
    let is_industrial = has_industrial_marker(raw);
    let is_lts = has_lts_marker(raw);
    let core = strip_track_markers(raw).trim();
    if core.is_empty() {
        return None;
    }
    let mut version = if core.starts_with('v') || core.starts_with('V') {
        core.to_owned()
    } else {
        format!("v{core}")
    };
    let channel = if is_industrial {
        version = ensure_industrial_marker(&version);
        PRODUCT_TRACK_INDUSTRIAL
    } else if is_lts {
        version = ensure_lts_marker(&version);
        PRODUCT_TRACK_LTS
    } else {
        PRODUCT_TRACK_STABLE
    };
    Some(DerivedReleaseIdentity { version, channel })
}

/// Immutable product track for entitlement / edit UI (survives `EOL` channel).
///
/// Industrial when channel or version marker says so; else LTS; else Stable.
pub fn channel_track(version: &str, channel: &str) -> &'static str {
    if channel.eq_ignore_ascii_case(PRODUCT_TRACK_INDUSTRIAL) || has_industrial_marker(version) {
        PRODUCT_TRACK_INDUSTRIAL
    } else if channel.eq_ignore_ascii_case(PRODUCT_TRACK_LTS) || has_lts_marker(version) {
        PRODUCT_TRACK_LTS
    } else {
        PRODUCT_TRACK_STABLE
    }
}

/// Alias used when persisting `Release.product_track`.
pub fn product_track(version: &str, channel: &str) -> &'static str {
    channel_track(version, channel)
}

/// Apply an edit-form channel choice. Rejects cross-track moves and unknowns.
///
/// Returns `(version_to_store, channel_to_store)`. Track saves always keep the
/// matching package marker so EOL downloads keep the correct basename.
pub fn apply_edit_channel(
    version: &str,
    current_channel: &str,
    requested: &str,
) -> Option<(String, String)> {
    let track = channel_track(version, current_channel);
    let req = requested.trim().to_ascii_lowercase();
    let channel = match (track, req.as_str()) {
        (PRODUCT_TRACK_INDUSTRIAL, "lts.industrial") => PRODUCT_TRACK_INDUSTRIAL,
        (PRODUCT_TRACK_INDUSTRIAL, "eol") => "EOL",
        (PRODUCT_TRACK_LTS, "lts") => PRODUCT_TRACK_LTS,
        (PRODUCT_TRACK_LTS, "eol") => "EOL",
        (PRODUCT_TRACK_STABLE, "stable") => PRODUCT_TRACK_STABLE,
        (PRODUCT_TRACK_STABLE, "eol") => "EOL",
        _ => return None,
    };
    let version = match track {
        PRODUCT_TRACK_INDUSTRIAL => ensure_industrial_marker(version),
        PRODUCT_TRACK_LTS => ensure_lts_marker(version),
        _ => {
            let core = strip_track_markers(version);
            if version.starts_with('v') || version.starts_with('V') {
                format!("{}{core}", &version[..1])
            } else {
                format!("v{core}")
            }
        }
    };
    Some((version, channel.to_owned()))
}

/// Tracks an org may see/download from subscription counters.
///
/// - `None` — reserved `vauban` (unrestricted)
/// - `Some([])` — deny all tracks
/// - `Some(list)` — `product_track` must be in `list`
pub fn allowed_product_tracks(
    org_slug: &str,
    lts: i32,
    industrial: i32,
) -> Option<Vec<&'static str>> {
    if org_slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG) {
        return None;
    }
    let mut out = Vec::new();
    if lts > 0 {
        out.push(PRODUCT_TRACK_STABLE);
        out.push(PRODUCT_TRACK_LTS);
    }
    if industrial > 0 {
        out.push(PRODUCT_TRACK_INDUSTRIAL);
    }
    Some(out)
}

/// Whether `track` is permitted by [`allowed_product_tracks`].
pub fn product_track_allowed(allowed: Option<&[&str]>, track: &str) -> bool {
    match allowed {
        None => true,
        Some([]) => false,
        Some(list) => list.iter().any(|t| t.eq_ignore_ascii_case(track)),
    }
}

/// Whether the org may enter the Builds surface at all (list / rail / download).
///
/// `vauban` is always entitled. Client orgs need at least one of
/// `lts_subscriptions` / `industrial_lts_subscriptions` > 0.
pub fn org_builds_entitled(org_slug: &str, lts: i32, industrial: i32) -> bool {
    match allowed_product_tracks(org_slug, lts, industrial) {
        None => true,
        Some(tracks) => !tracks.is_empty(),
    }
}

/// Channel filter chips for `/{org}/builds` (order matches UI).
///
/// Wire values stay `LTS` / `LTS.industrial` / `Stable` / `EOL`. Chips that
/// the org cannot download are omitted. `EOL` appears whenever any track is
/// entitled (lifecycle overlay). Empty when the org has no Builds access.
pub fn builds_channel_filter_chips(org_slug: &str, lts: i32, industrial: i32) -> Vec<&'static str> {
    const CHIPS: &[&str] = &["LTS", "LTS.industrial", "Stable", "EOL"];
    match allowed_product_tracks(org_slug, lts, industrial) {
        None => CHIPS.to_vec(),
        Some(tracks) if tracks.is_empty() => Vec::new(),
        Some(tracks) => CHIPS
            .iter()
            .copied()
            .filter(|ch| {
                if *ch == "EOL" {
                    true
                } else {
                    tracks.iter().any(|t| t.eq_ignore_ascii_case(ch))
                }
            })
            .collect(),
    }
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
    /// `1` when version carries `+LTS.industrial`; else `0`.
    pub is_industrial: u64,
    /// `1` when a client suffix is present; else `0`.
    pub has_client_suffix: u64,
    pub client_suffix: String,
}

/// Parse a DB version into a key (markers stripped before suffix / numeric parse).
pub fn version_sort_key(version: &str) -> VersionSortKey {
    let ver = strip_track_markers(version);
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
        is_industrial: u64::from(has_industrial_marker(version)),
        has_client_suffix: u64::from(key.has_client_suffix),
        client_suffix: key.suffix,
    }
}

/// Sort + product_track fields for Release create/update (channel-aware industrial bit).
pub fn release_write_keys(version: &str, channel: &str) -> (VersionSortFields, &'static str) {
    let mut sort = version_sort_fields(version);
    let track = product_track(version, channel);
    sort.is_industrial = u64::from(track == PRODUCT_TRACK_INDUSTRIAL);
    (sort, track)
}

/// List order: higher numeric version first; same `X.Y.Z` → industrial above
/// plain LTS/Stable; then `X.Y.Z-client` above plain, A→Z by client name.
///
/// Must match SQL
/// `ORDER BY v_major DESC, v_minor DESC, v_patch DESC, is_industrial DESC,
/// has_client_suffix DESC, client_suffix ASC`.
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
        .then_with(|| b.is_industrial.cmp(&a.is_industrial))
        .then_with(|| b.has_client_suffix.cmp(&a.has_client_suffix))
        .then_with(|| a.client_suffix.cmp(&b.client_suffix))
}

/// Admin `/admin/releases` tie-break after semver keys: `PUBLISHED` before
/// `HIDDEN`. Matches SQL `ORDER BY status DESC`.
pub fn cmp_status_published_first(a: &str, b: &str) -> Ordering {
    b.cmp(a)
}

/// Full admin list order: [`cmp_version_desc`] then [`cmp_status_published_first`].
pub fn cmp_admin_release_list(
    a_version: &str,
    a_status: &str,
    b_version: &str,
    b_status: &str,
) -> Ordering {
    cmp_version_desc(a_version, b_version)
        .then_with(|| cmp_status_published_first(a_status, b_status))
}

/// Artifact basename from version markers / channel.
///
/// - industrial → `vauban-{ver}+LTS.industrial.pkg`
/// - LTS → `vauban-{ver}+LTS.pkg`
/// - else → `vauban-{ver}.pkg`
pub fn package_file_name(version: &str, channel: &str) -> String {
    let core = strip_track_markers(version);
    let industrial =
        has_industrial_marker(version) || channel.eq_ignore_ascii_case(PRODUCT_TRACK_INDUSTRIAL);
    let lts = has_lts_marker(version) || channel.eq_ignore_ascii_case(PRODUCT_TRACK_LTS);
    if industrial {
        format!("vauban-{core}{INDUSTRIAL_SUFFIX}.pkg")
    } else if lts {
        format!("vauban-{core}{LTS_SUFFIX}.pkg")
    } else {
        format!("vauban-{core}.pkg")
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
    fn package_name_strips_v_and_adds_markers() {
        assert_eq!(package_file_name("v1.0.0", "LTS"), "vauban-1.0.0+LTS.pkg");
        assert_eq!(package_file_name("v0.9.35", "Stable"), "vauban-0.9.35.pkg");
        assert_eq!(package_file_name("1.2.3", "LTS"), "vauban-1.2.3+LTS.pkg");
        assert_eq!(
            package_file_name("v1.0.0+LTS", "EOL"),
            "vauban-1.0.0+LTS.pkg"
        );
        assert_eq!(
            package_file_name("v1.0.0+LTS.industrial", "EOL"),
            "vauban-1.0.0+LTS.industrial.pkg"
        );
        assert_eq!(
            package_file_name("v1.0.0", "LTS.industrial"),
            "vauban-1.0.0+LTS.industrial.pkg"
        );
    }

    #[test]
    fn version_display_hides_track_markers() {
        assert_eq!(version_for_display("v1.0.1+LTS"), "v1.0.1");
        assert_eq!(version_for_display("v1.0.1+LTS.industrial"), "v1.0.1");
        assert_eq!(version_for_display("v0.9.35"), "v0.9.35");
        assert_eq!(version_for_display("v1.0.0+lts"), "v1.0.0");
    }

    #[test]
    fn derive_identity_longest_marker_first() {
        let ind = derive_release_identity("1.0.0+LTS.industrial").unwrap();
        assert_eq!(ind.version, "v1.0.0+LTS.industrial");
        assert_eq!(ind.channel, PRODUCT_TRACK_INDUSTRIAL);
        let lts = derive_release_identity("1.0.1+LTS").unwrap();
        assert_eq!(lts.version, "v1.0.1+LTS");
        assert_eq!(lts.channel, PRODUCT_TRACK_LTS);
        let stable = derive_release_identity("0.9.35").unwrap();
        assert_eq!(stable.version, "v0.9.35");
        assert_eq!(stable.channel, PRODUCT_TRACK_STABLE);
        assert!(derive_release_identity("").is_none());
        assert!(derive_release_identity("+LTS").is_none());
        assert!(derive_release_identity("+LTS.industrial").is_none());
    }

    #[test]
    fn edit_channel_respects_tracks() {
        let (v, c) = apply_edit_channel("v1.0.0", "LTS", "EOL").unwrap();
        assert_eq!(c, "EOL");
        assert_eq!(v, "v1.0.0+LTS");
        let (v2, c2) = apply_edit_channel(&v, "EOL", "LTS").unwrap();
        assert_eq!(c2, "LTS");
        assert_eq!(v2, "v1.0.0+LTS");
        assert!(apply_edit_channel("v1.0.0", "LTS", "Stable").is_none());
        assert!(apply_edit_channel("v0.9.35", "Stable", "LTS").is_none());
        assert!(apply_edit_channel("v1.0.0+LTS", "LTS", "LTS.industrial").is_none());
        let (iv, ic) =
            apply_edit_channel("v1.0.0+LTS.industrial", "LTS.industrial", "EOL").unwrap();
        assert_eq!(ic, "EOL");
        assert_eq!(iv, "v1.0.0+LTS.industrial");
        let (iv2, ic2) = apply_edit_channel(&iv, "EOL", "LTS.industrial").unwrap();
        assert_eq!(ic2, "LTS.industrial");
        assert_eq!(iv2, "v1.0.0+LTS.industrial");
    }

    #[test]
    fn allowed_tracks_matrix() {
        assert!(allowed_product_tracks("vauban", 0, 0).is_none());
        assert_eq!(allowed_product_tracks("acme", 0, 0), Some(vec![]));
        assert_eq!(
            allowed_product_tracks("acme", 1, 0),
            Some(vec![PRODUCT_TRACK_STABLE, PRODUCT_TRACK_LTS])
        );
        assert_eq!(
            allowed_product_tracks("acme", 0, 2),
            Some(vec![PRODUCT_TRACK_INDUSTRIAL])
        );
        assert_eq!(
            allowed_product_tracks("acme", 1, 1),
            Some(vec![
                PRODUCT_TRACK_STABLE,
                PRODUCT_TRACK_LTS,
                PRODUCT_TRACK_INDUSTRIAL
            ])
        );
        assert!(!org_builds_entitled("acme", 0, 0));
        assert!(org_builds_entitled("acme", 1, 0));
        assert!(org_builds_entitled("acme", 0, 1));
        assert!(org_builds_entitled("vauban", 0, 0));
        assert_eq!(
            builds_channel_filter_chips("acme", 0, 0),
            Vec::<&str>::new()
        );
        assert_eq!(
            builds_channel_filter_chips("acme", 2, 0),
            vec!["LTS", "Stable", "EOL"]
        );
        assert_eq!(
            builds_channel_filter_chips("acme", 0, 1),
            vec!["LTS.industrial", "EOL"]
        );
        assert_eq!(
            builds_channel_filter_chips("acme", 1, 1),
            vec!["LTS", "LTS.industrial", "Stable", "EOL"]
        );
        assert_eq!(
            builds_channel_filter_chips("vauban", 0, 0),
            vec!["LTS", "LTS.industrial", "Stable", "EOL"]
        );
        assert!(product_track_allowed(None, PRODUCT_TRACK_INDUSTRIAL));
        assert!(!product_track_allowed(Some(&[]), PRODUCT_TRACK_LTS));
        assert!(product_track_allowed(
            Some(&[PRODUCT_TRACK_LTS]),
            PRODUCT_TRACK_LTS
        ));
    }

    #[test]
    fn industrial_sorts_above_same_semver_lts() {
        assert_eq!(
            cmp_version_desc("v1.0.0+LTS.industrial", "v1.0.0+LTS"),
            Ordering::Less
        );
        assert_eq!(
            version_sort_fields("v1.0.0+LTS.industrial").is_industrial,
            1
        );
        assert_eq!(version_sort_fields("v1.0.0+LTS").is_industrial, 0);
    }

    #[test]
    fn version_sort_strips_markers() {
        assert_eq!(
            version_sort_fields("v1.0.1+LTS").v_major,
            version_sort_fields("v1.0.1").v_major
        );
        let f = version_sort_fields("v0.8.6-acme1+LTS");
        assert_eq!(f.v_major, 0);
        assert_eq!(f.v_minor, 8);
        assert_eq!(f.v_patch, 6);
        assert_eq!(f.has_client_suffix, 1);
        assert_eq!(f.client_suffix, "acme1");
        let ind = version_sort_fields("v0.8.6-acme1+LTS.industrial");
        assert_eq!(ind.client_suffix, "acme1");
        assert_eq!(ind.is_industrial, 1);
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

    #[test]
    fn status_tie_break_published_before_hidden() {
        use crate::models::{RELEASE_STATUS_HIDDEN, RELEASE_STATUS_PUBLISHED};

        assert_eq!(
            cmp_status_published_first(RELEASE_STATUS_PUBLISHED, RELEASE_STATUS_HIDDEN),
            Ordering::Less
        );
        assert_eq!(
            cmp_status_published_first(RELEASE_STATUS_HIDDEN, RELEASE_STATUS_PUBLISHED),
            Ordering::Greater
        );
        assert_eq!(
            cmp_admin_release_list(
                "v1.0.1",
                RELEASE_STATUS_HIDDEN,
                "v1.0.1",
                RELEASE_STATUS_PUBLISHED
            ),
            Ordering::Greater,
            "same version: HIDDEN must sort after PUBLISHED"
        );
        assert_eq!(
            cmp_admin_release_list(
                "v1.0.2",
                RELEASE_STATUS_HIDDEN,
                "v1.0.1",
                RELEASE_STATUS_PUBLISHED
            ),
            Ordering::Less,
            "semver still beats status"
        );
    }
}
