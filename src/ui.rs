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

/// Channel badge class (Concept: LTS green, Stable blue, EOL muted).
pub fn channel_badge_class(channel: &str) -> &'static str {
    match channel.trim() {
        c if c.eq_ignore_ascii_case("LTS") => "vb-badge chan-lts",
        c if c.eq_ignore_ascii_case("Stable") => "vb-badge chan-stable",
        c if c.eq_ignore_ascii_case("EOL") => "vb-badge chan-eol",
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
        assert_eq!(channel_badge_class("lts"), "vb-badge chan-lts");
        assert_eq!(channel_badge_class(" unknown "), "vb-badge soft");
    }

    #[test]
    fn note_tag_colors() {
        assert_eq!(note_tag_color("FIX"), "#2f7d52");
        assert_eq!(note_tag_color("feat"), "#117a6b");
        assert_eq!(note_tag_color("SECURITY"), "#b5403a");
    }
}
