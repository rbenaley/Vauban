//! Shared Concept mockup helpers. Styles live in `styles.css` (Tailwind + @theme).

/// Accent teal from Concept mockups.
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
