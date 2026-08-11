//! Catalogue of issue `component` values (report form + validation).
//!
//! Labels are customer-facing Vauban product surfaces (not crate names).
//! See `../Vauban` Privsep / README process map.

/// Canonical labels shown in the report `<select>` (order = UI order).
pub const ISSUE_COMPONENTS: &[&str] = &[
    "SSH",
    "RDP",
    "IACS",
    "Web UI",
    "Authentication",
    "Access control",
    "Vault",
    "Recording & audit",
    "Notifications",
    "Infrastructure",
    "Portal",
    "Other",
];

/// Default selection on the report form.
pub const DEFAULT_ISSUE_COMPONENT: &str = "SSH";

/// True when `value` matches a catalogue label (case-insensitive).
pub fn is_known_issue_component(value: &str) -> bool {
    let trimmed = value.trim();
    ISSUE_COMPONENTS
        .iter()
        .any(|c| c.eq_ignore_ascii_case(trimmed))
}

/// Map a submitted (or legacy) label onto the catalogue.
///
/// Unknown / empty → [`None`]. Known catalogue values are returned in
/// canonical casing. Legacy VCP labels are remapped when unambiguous.
pub fn normalize_issue_component(value: &str) -> Option<&'static str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    for &c in ISSUE_COMPONENTS {
        if c.eq_ignore_ascii_case(trimmed) {
            return Some(c);
        }
    }
    // Legacy report-form values (pre-Vauban catalogue).
    if trimmed.eq_ignore_ascii_case("SSH Proxy") {
        return Some("SSH");
    }
    if trimmed.eq_ignore_ascii_case("RDP Gateway") {
        return Some("RDP");
    }
    // "Control plane" was overloaded; keep as Other unless a caller remaps
    // from title/details (see ops remap for local `vcp`).
    if trimmed.eq_ignore_ascii_case("Control plane") {
        return Some("Other");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_contains_default_and_other() {
        assert!(ISSUE_COMPONENTS.contains(&DEFAULT_ISSUE_COMPONENT));
        assert!(ISSUE_COMPONENTS.contains(&"Other"));
        assert!(ISSUE_COMPONENTS.contains(&"Infrastructure"));
        assert!(ISSUE_COMPONENTS.contains(&"Portal"));
        assert_eq!(ISSUE_COMPONENTS.len(), 12);
    }

    #[test]
    fn normalize_accepts_canonical_and_legacy() {
        assert_eq!(normalize_issue_component("SSH"), Some("SSH"));
        assert_eq!(normalize_issue_component(" ssh "), Some("SSH"));
        assert_eq!(normalize_issue_component("SSH Proxy"), Some("SSH"));
        assert_eq!(normalize_issue_component("RDP Gateway"), Some("RDP"));
        assert_eq!(normalize_issue_component("Control plane"), Some("Other"));
        assert_eq!(normalize_issue_component("Portal"), Some("Portal"));
        assert_eq!(normalize_issue_component(""), None);
        assert_eq!(normalize_issue_component("NotAThing"), None);
    }

    #[test]
    fn known_helper_matches_normalize() {
        for &c in ISSUE_COMPONENTS {
            assert!(is_known_issue_component(c));
            assert_eq!(normalize_issue_component(c), Some(c));
        }
    }
}
