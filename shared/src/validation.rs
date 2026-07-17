//! Canonical input-format validators shared across services.
//!
//! These helpers are the single source of truth for the closed-format
//! fields that cross the vauban-web -> vauban-access IPC boundary
//! (group slugs, hex colors, icon identifiers) plus the hostname
//! charset gate used by the asset forms. Keeping them in `shared`
//! guarantees the web-layer validation (flash PRG errors) and the
//! vauban-access fail-closed re-check can never drift apart, mirroring
//! the [`crate::username::normalize_username`] pattern.
//!
//! Every function is pure and total: no panic, no allocation, no
//! regex engine (the `shared` crate stays dependency-light for the
//! Capsicum-sandboxed consumers).
//!
//! Format contracts (also enforced by DB CHECK constraints, see the
//! `20260717000000_input_format_constraints` migration):
//!
//! * **Slug** -- `^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$`, at most
//!   [`SLUG_MAX_LEN`] bytes. Interior `_` / `-` are allowed but the
//!   first and last characters must be alphanumeric, which reserves
//!   the `__`-prefixed namespace for system-seeded virtual groups
//!   (`__all-assets__`, `__all-secrets__`, ...).
//! * **Hex color** -- `^#[0-9a-fA-F]{6}$` (callers should persist the
//!   lower-cased form).
//! * **Icon** -- one of the closed [`ICON_CATALOG`] rendered by the
//!   asset-group templates.
//! * **Hostname** -- 1..=255 bytes drawn from `[A-Za-z0-9.:_-]`
//!   (covers DNS names, IPv4 and IPv6 literals; rejects whitespace
//!   and control characters).

/// Maximum accepted slug length (matches the `VARCHAR(100)` columns
/// `asset_groups.slug`, `secret_groups.slug` and `vault_secrets.name`).
pub const SLUG_MAX_LEN: usize = 100;

/// Maximum accepted hostname length (matches `assets.hostname`
/// `VARCHAR(255)` and RFC 1035's 255-octet bound).
pub const HOSTNAME_MAX_LEN: usize = 255;

/// Closed catalog of icon identifiers rendered by the asset-group
/// templates (`vauban-web/templates/assets/manage/groups/*.html`).
/// Kept in lock-step with the `<select name="icon">` options and the
/// `{% if group.icon == ... %}` SVG arms.
pub const ICON_CATALOG: &[&str] = &[
    "server", "database", "code", "desktop", "wifi", "cloud", "folder",
];

/// Whether `input` is a well-formed URL-friendly slug:
/// lowercase ASCII alphanumerics with interior hyphens/underscores,
/// starting and ending with an alphanumeric, 1..=[`SLUG_MAX_LEN`] bytes.
#[must_use]
pub fn is_valid_slug(input: &str) -> bool {
    if input.is_empty() || input.len() > SLUG_MAX_LEN {
        return false;
    }
    let interior_ok = input
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    let edge_ok = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    // `input` is non-empty ASCII at this point, so first/last bytes exist.
    interior_ok
        && input.as_bytes().first().copied().is_some_and(edge_ok)
        && input.as_bytes().last().copied().is_some_and(edge_ok)
}

/// Whether `input` is a 6-digit hex color with a leading `#`
/// (`#RRGGBB`, case-insensitive). Callers should persist the
/// lower-cased form so the DB CHECK (`^#[0-9a-f]{6}$`) holds.
#[must_use]
pub fn is_valid_hex_color(input: &str) -> bool {
    let bytes = input.as_bytes();
    bytes.len() == 7 && bytes[0] == b'#' && bytes[1..].iter().all(u8::is_ascii_hexdigit)
}

/// Whether `input` is one of the closed [`ICON_CATALOG`] identifiers.
#[must_use]
pub fn is_valid_icon(input: &str) -> bool {
    ICON_CATALOG.contains(&input)
}

/// Whether `input` is a plausible connection target: a DNS name, an
/// IPv4 literal or an IPv6 literal. This is a charset/length gate, not
/// a resolver: it rejects whitespace, control characters and anything
/// outside `[A-Za-z0-9.:_-]` so a value accepted here can be embedded
/// verbatim in `host:port` connection strings and structured logs.
#[must_use]
pub fn is_valid_hostname(input: &str) -> bool {
    !input.is_empty()
        && input.len() <= HOSTNAME_MAX_LEN
        && input
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_accepts_canonical_forms() {
        let valid = [
            "production",
            "prod-servers",
            "prod_servers",
            "a",
            "0",
            "ag_audit-42",
            "x-1_y-2",
            &"a".repeat(SLUG_MAX_LEN),
        ];
        for s in valid {
            assert!(is_valid_slug(s), "expected valid: {s:?}");
        }
    }

    #[test]
    fn slug_rejects_invalid_forms() {
        let invalid = [
            "",
            "Prod uction {BUG}",
            "Production",
            "prod uction",
            "prod/uction",
            "-prod",
            "prod-",
            "_prod",
            "prod_",
            "__all-assets__",
            "prod.servers",
            "prodé",
            "prod\n",
            " prod",
            "prod ",
            &"a".repeat(SLUG_MAX_LEN + 1),
        ];
        for s in invalid {
            assert!(!is_valid_slug(s), "expected invalid: {s:?}");
        }
    }

    #[test]
    fn hex_color_accepts_six_hex_digits_with_hash() {
        for s in ["#000000", "#ffffff", "#3B82F6", "#abcdef", "#ABCDEF"] {
            assert!(is_valid_hex_color(s), "expected valid: {s:?}");
        }
    }

    #[test]
    fn hex_color_rejects_everything_else() {
        let invalid = [
            "",
            "#fff",
            "#ffffffff",
            "ffffff",
            "#gggggg",
            "#zzz {BUG}",
            "red",
            "#ffffff ",
            " #ffffff",
            "#fffff\u{e9}",
            "transparent;background-image:url(https://evil)",
        ];
        for s in invalid {
            assert!(!is_valid_hex_color(s), "expected invalid: {s:?}");
        }
    }

    #[test]
    fn icon_catalog_is_closed() {
        for s in ICON_CATALOG {
            assert!(is_valid_icon(s), "catalog entry must validate: {s:?}");
        }
        for s in ["", "Server", "rocket", "folder ", "<svg>"] {
            assert!(!is_valid_icon(s), "expected invalid: {s:?}");
        }
    }

    #[test]
    fn hostname_accepts_dns_ipv4_ipv6() {
        let valid = [
            "example.com",
            "srv-01.internal_zone.example.com",
            "10.0.0.1",
            "2001:db8::1",
            "::1",
            "localhost",
            &"a".repeat(HOSTNAME_MAX_LEN),
        ];
        for s in valid {
            assert!(is_valid_hostname(s), "expected valid: {s:?}");
        }
    }

    #[test]
    fn hostname_rejects_whitespace_and_exotic_chars() {
        let invalid = [
            "",
            "host name",
            "host\tname",
            "host\nname",
            "host{BUG}",
            "host/path",
            "hôte.example",
            "host name.example.com",
            &"a".repeat(HOSTNAME_MAX_LEN + 1),
        ];
        for s in invalid {
            assert!(!is_valid_hostname(s), "expected invalid: {s:?}");
        }
    }
}
