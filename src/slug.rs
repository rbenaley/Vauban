//! Slug helpers for org / article identifiers.

/// Derive a URL-safe slug from a display name (lowercase, hyphenated).
pub fn slugify(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_hyphen = false;
    for ch in input.chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            out.push(c);
            prev_hyphen = false;
        } else if (c.is_whitespace() || c == '-' || c == '_') && !prev_hyphen && !out.is_empty() {
            out.push('-');
            prev_hyphen = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "item".to_owned()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugify_basic() {
        assert_eq!(slugify("Hello World"), "hello-world");
        assert_eq!(slugify("  ACME Infra  "), "acme-infra");
        assert_eq!(slugify("A--B"), "a-b");
        assert_eq!(slugify("!!!"), "item");
    }
}
