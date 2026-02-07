//! Static assets embedded in the binary at compile time.
//!
//! Every file served by `/static/*` is listed here explicitly and included
//! via `include_bytes!()`.  This means:
//!
//! - **No filesystem access at runtime** (Capsicum-compatible).
//! - **No directory walk** that could load rogue files from a compromised server.
//! - Files are verified by the compiler: a missing file is a build error.
//!
//! ## Adding a new static file
//!
//! 1. Place the file under `vauban-web/static/` (e.g. `static/js/new.js`).
//! 2. Add an entry to [`STATIC_FILES`] below:
//!    ```ignore
//!    StaticAsset {
//!        path: "js/new.js",
//!        content: include_bytes!("../static/js/new.js"),
//!        content_type: "application/javascript; charset=utf-8",
//!    },
//!    ```
//! 3. Recompile.  The file is now part of the binary.

/// A single static asset embedded in the binary.
pub struct StaticAsset {
    /// Relative path used in the URL (e.g. `js/app.js` -> `/static/js/app.js`).
    pub path: &'static str,
    /// File content, included at compile time.
    pub content: &'static [u8],
    /// MIME content-type sent in the `Content-Type` header.
    pub content_type: &'static str,
}

/// Exhaustive list of static assets compiled into the binary.
///
/// **Security**: only files listed here can be served.  An attacker who
/// compromises the filesystem cannot inject additional assets.
pub static STATIC_FILES: &[StaticAsset] = &[
    // ── JavaScript ────────────────────────────────────────────────────────
    StaticAsset {
        path: "js/tailwind-config.js",
        content: include_bytes!("../static/js/tailwind-config.js"),
        content_type: "application/javascript; charset=utf-8",
    },
    StaticAsset {
        path: "js/vauban-components.js",
        content: include_bytes!("../static/js/vauban-components.js"),
        content_type: "application/javascript; charset=utf-8",
    },
    // ── CSS ───────────────────────────────────────────────────────────────
    StaticAsset {
        path: "css/vauban.css",
        content: include_bytes!("../static/css/vauban.css"),
        content_type: "text/css; charset=utf-8",
    },
    StaticAsset {
        path: "css/terminal.css",
        content: include_bytes!("../static/css/terminal.css"),
        content_type: "text/css; charset=utf-8",
    },
];

/// Look up an embedded static asset by its relative path.
///
/// Returns `None` if the path is not in the compiled registry.
pub fn lookup(path: &str) -> Option<&'static StaticAsset> {
    STATIC_FILES.iter().find(|a| a.path == path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_assets_have_content() {
        for asset in STATIC_FILES {
            assert!(
                !asset.content.is_empty(),
                "Static asset '{}' has empty content",
                asset.path
            );
        }
    }

    #[test]
    fn test_all_assets_have_valid_content_type() {
        for asset in STATIC_FILES {
            assert!(
                !asset.content_type.is_empty(),
                "Static asset '{}' has empty content_type",
                asset.path
            );
            assert!(
                asset.content_type.contains('/'),
                "Static asset '{}' has invalid content_type: {}",
                asset.path,
                asset.content_type
            );
        }
    }

    #[test]
    fn test_no_duplicate_paths() {
        let mut seen = std::collections::HashSet::new();
        for asset in STATIC_FILES {
            assert!(
                seen.insert(asset.path),
                "Duplicate static asset path: {}",
                asset.path
            );
        }
    }

    #[test]
    fn test_lookup_existing() {
        assert!(lookup("js/tailwind-config.js").is_some());
        assert!(lookup("css/vauban.css").is_some());
    }

    #[test]
    fn test_lookup_missing() {
        assert!(lookup("nonexistent.js").is_none());
        assert!(lookup("../../../etc/passwd").is_none());
    }

    #[test]
    fn test_js_files_contain_expected_content() {
        let tw = lookup("js/tailwind-config.js").expect("tailwind-config.js must exist");
        let content = std::str::from_utf8(tw.content).expect("JS must be valid UTF-8");
        assert!(
            content.contains("tailwind"),
            "tailwind-config.js must contain 'tailwind'"
        );

        let components = lookup("js/vauban-components.js").expect("vauban-components.js must exist");
        let content = std::str::from_utf8(components.content).expect("JS must be valid UTF-8");
        assert!(
            content.contains("Alpine"),
            "vauban-components.js must contain 'Alpine'"
        );
    }
}
