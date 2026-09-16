//! Compile-time portal identity (crate semver + git short SHA).

/// Crate semver from `Cargo.toml`.
pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Short git SHA baked by `build.rs` (`unknown` if git is unavailable).
pub const GIT_HASH: &str = env!("VCP_GIT_HASH");

/// Account / ops line: `VCP — v0.1.3 [2745693a]`.
pub fn product_label() -> String {
    format!("VCP — v{PKG_VERSION} [{GIT_HASH}]")
}

#[cfg(test)]
mod tests {
    use super::{GIT_HASH, PKG_VERSION, product_label};

    #[test]
    fn product_label_embeds_semver_and_hash() {
        let label = product_label();
        assert_eq!(label, format!("VCP — v{PKG_VERSION} [{GIT_HASH}]"));
        assert!(label.starts_with("VCP — v"));
        assert!(
            GIT_HASH == "unknown"
                || (GIT_HASH.len() >= 7
                    && GIT_HASH.len() <= 12
                    && GIT_HASH.chars().all(|c| c.is_ascii_hexdigit())),
            "GIT_HASH must be a short SHA or unknown: {GIT_HASH}"
        );
        assert!(!label.contains("reserved preview tenant"));
    }
}
