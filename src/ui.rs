//! Shared UI helpers. Styles live in `styles.css` (Tailwind + @theme).

pub const ACCENT: &str = "#117a6b";

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

/// Channel chip class for builds (soft fill + border, not solid accent).
pub fn channel_badge_class(channel: &str) -> &'static str {
    match channel {
        "LTS" => "vb-badge chan-lts",
        "Stable" => "vb-badge chan-stable",
        "EOL" => "vb-badge chan-eol",
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
        assert_eq!(channel_badge_class("Stable"), "vb-badge chan-stable");
        assert_eq!(channel_badge_class("EOL"), "vb-badge chan-eol");
    }

    #[test]
    fn note_tag_colors() {
        assert_eq!(note_tag_color("FIX"), "#2f7d52");
        assert_eq!(note_tag_color("feat"), "#117a6b");
        assert_eq!(note_tag_color("SECURITY"), "#b5403a");
    }
}
