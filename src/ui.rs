//! Shared UI helpers. Styles live in `styles.css` (Tailwind + @theme).

pub const ACCENT: &str = "#117a6b";

/// Stable DOM id for a list row re-rendered by a shard (`doc-ssh-guide`,
/// `issue-ISS-12`, `company-7`).
///
/// Topcoat 0.8 morphs shard output in place; an `id` per row lets the morph
/// follow a row to its new position instead of rewriting the rows in
/// between. Only `[A-Za-z0-9_-]` survives (other bytes become `_`) and the
/// result is never empty, so the id stays a valid HTML id / CSS selector.
pub fn row_dom_id(prefix: &str, key: &str) -> String {
    let mut id = String::with_capacity(prefix.len() + key.len() + 1);
    id.push_str(prefix);
    id.push('-');
    let mut pushed = false;
    for c in key.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            id.push(c);
        } else {
            id.push('_');
        }
        pushed = true;
    }
    if !pushed {
        id.push('_');
    }
    id
}

pub fn org_initials(name: &str) -> String {
    let mut initials = String::new();
    for part in name.split_whitespace().take(2) {
        if let Some(c) = part.chars().next() {
            initials.push(c.to_ascii_uppercase());
        }
    }
    if initials.is_empty() {
        initials.push('V');
    }
    initials
}

#[cfg(test)]
mod row_dom_id_tests {
    use super::row_dom_id;

    #[test]
    fn row_dom_id_keeps_safe_chars_and_prefix() {
        assert_eq!(row_dom_id("doc", "ssh-guide"), "doc-ssh-guide");
        assert_eq!(row_dom_id("issue", "ISS-12"), "issue-ISS-12");
        assert_eq!(row_dom_id("company", "7"), "company-7");
    }

    #[test]
    fn row_dom_id_sanitizes_and_never_ends_empty() {
        assert_eq!(row_dom_id("doc", "a b/c\"d"), "doc-a_b_c_d");
        assert_eq!(row_dom_id("doc", ""), "doc-_");
        assert_eq!(row_dom_id("doc", "é"), "doc-_");
    }
}

/// Channel badge class (Concept: LTS green, industrial teal, Stable blue, EOL muted).
pub fn channel_badge_class(channel: &str) -> &'static str {
    match channel.trim() {
        c if c.eq_ignore_ascii_case("LTS.industrial") => "vb-badge chan-lts-industrial",
        c if c.eq_ignore_ascii_case("LTS") => "vb-badge chan-lts",
        c if c.eq_ignore_ascii_case("Stable") => "vb-badge chan-stable",
        c if c.eq_ignore_ascii_case("EOL") => "vb-badge chan-eol",
        _ => "vb-badge soft",
    }
}

/// Human label for Builds / Release-manager filter chips only.
///
/// Wire / DB / badges keep `LTS.industrial`; chips show "LTS Industrial".
pub fn channel_filter_label(channel: &str) -> &str {
    if channel.trim().eq_ignore_ascii_case("LTS.industrial") {
        "LTS Industrial"
    } else {
        channel
    }
}

/// Release STATUS badge (PUBLISHED green, HIDDEN amber).
pub fn release_status_badge_class(status: &str) -> &'static str {
    match status.trim() {
        c if c.eq_ignore_ascii_case("PUBLISHED") => "vb-badge status-published",
        c if c.eq_ignore_ascii_case("HIDDEN") => "vb-badge status-hidden",
        _ => "vb-badge soft",
    }
}

/// Doc STATUS badge (PUBLISHED green, DRAFT amber — same unpublished look as HIDDEN).
pub fn doc_status_badge_class(status: &str) -> &'static str {
    match status.trim() {
        c if c.eq_ignore_ascii_case("PUBLISHED") => "vb-badge status-published",
        c if c.eq_ignore_ascii_case("DRAFT") => "vb-badge status-hidden",
        _ => "vb-badge soft",
    }
}

/// Changelog / release-note tag color.
pub fn note_tag_color(tag: &str) -> &'static str {
    match tag.to_ascii_uppercase().as_str() {
        "FIX" => "#2f7d52",
        "FEAT" | "FEATURE" => "#117a6b",
        "SECURITY" | "SEC" => "#b5403a",
        "RBAC" => "#2f5fb0",
        _ => "#5a5f66",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_badge_classes() {
        assert_eq!(channel_badge_class("LTS"), "vb-badge chan-lts");
        assert_eq!(
            channel_badge_class("LTS.industrial"),
            "vb-badge chan-lts-industrial"
        );
        assert_eq!(channel_badge_class("Stable"), "vb-badge chan-stable");
        assert_eq!(channel_badge_class("EOL"), "vb-badge chan-eol");
        assert_eq!(channel_badge_class("lts"), "vb-badge chan-lts");
        assert_eq!(channel_badge_class(" unknown "), "vb-badge soft");
    }

    #[test]
    fn channel_filter_label_humanizes_industrial_chip_only() {
        assert_eq!(channel_filter_label("LTS.industrial"), "LTS Industrial");
        assert_eq!(channel_filter_label("lts.industrial"), "LTS Industrial");
        assert_eq!(channel_filter_label("LTS"), "LTS");
        assert_eq!(channel_filter_label("Stable"), "Stable");
        assert_eq!(channel_filter_label("EOL"), "EOL");
    }

    #[test]
    fn note_tag_colors() {
        assert_eq!(note_tag_color("FIX"), "#2f7d52");
        assert_eq!(note_tag_color("feat"), "#117a6b");
        assert_eq!(note_tag_color("SECURITY"), "#b5403a");
    }

    #[test]
    fn release_status_badge_classes() {
        assert_eq!(
            release_status_badge_class("PUBLISHED"),
            "vb-badge status-published"
        );
        assert_eq!(
            release_status_badge_class("HIDDEN"),
            "vb-badge status-hidden"
        );
        assert_eq!(
            release_status_badge_class("published"),
            "vb-badge status-published"
        );
        assert_eq!(release_status_badge_class("DRAFT"), "vb-badge soft");
    }

    #[test]
    fn doc_status_badge_classes() {
        assert_eq!(
            doc_status_badge_class("PUBLISHED"),
            "vb-badge status-published"
        );
        assert_eq!(doc_status_badge_class("DRAFT"), "vb-badge status-hidden");
        assert_eq!(doc_status_badge_class("draft"), "vb-badge status-hidden");
        assert_eq!(doc_status_badge_class("HIDDEN"), "vb-badge soft");
    }
}
