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

impl StaticAsset {
    /// Stable ETag derived from content length and a FNV-1a hash of the bytes.
    /// Changes whenever the binary is recompiled with different file contents.
    pub fn etag(&self) -> String {
        let mut hash: u64 = 0xcbf29ce484222325;
        for &b in self.content {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        format!("\"v{:016x}\"", hash)
    }
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
    // Browser timezone bootstrap - sets the `vbn_tz` cookie before
    // first paint so the server can render every DateTime<Utc> in the
    // operator's local zone. MUST be loaded synchronously from
    // base.html <head>; a 404 here silently collapses the entire UI
    // to UTC (regression observed in v0.7.7). Pinned by
    // `tests/web/timezone_snippet_test::vbn_tz_js_is_served_under_static`.
    StaticAsset {
        path: "js/vbn-tz.js",
        content: include_bytes!("../static/js/vbn-tz.js"),
        content_type: "application/javascript; charset=utf-8",
    },
    StaticAsset {
        path: "js/shaka-player.compiled.js",
        content: include_bytes!("../static/js/shaka-player.compiled.js"),
        content_type: "application/javascript; charset=utf-8",
    },
    StaticAsset {
        path: "js/shaka-init.js",
        content: include_bytes!("../static/js/shaka-init.js"),
        content_type: "application/javascript; charset=utf-8",
    },
    StaticAsset {
        path: "js/asciinema-player.min.js",
        content: include_bytes!("../static/js/asciinema-player.min.js"),
        content_type: "application/javascript; charset=utf-8",
    },
    StaticAsset {
        path: "js/asciinema-init.js",
        content: include_bytes!("../static/js/asciinema-init.js"),
        content_type: "application/javascript; charset=utf-8",
    },
    // ── Vendored front-end libraries (self-hosted, no runtime CDN) ─────────
    // These were previously loaded from cdn.tailwindcss.com / unpkg.com /
    // cdn.jsdelivr.net. They are vendored verbatim (no minification change,
    // pinned versions) so the browser never reaches a third-party origin at
    // runtime. Refresh with `scripts/vendor_assets.sh`. Versions and licenses
    // are documented in docs/THIRD_PARTY_LICENSES.md.
    //
    // tailwindcss.js is the Tailwind *JIT runtime compiler* (Play CDN bundle,
    // v3.4.17), NOT a pre-compiled stylesheet: utility classes are still
    // compiled in the browser, which is why the CSP keeps 'unsafe-eval'.
    StaticAsset {
        path: "js/vendor/tailwindcss.js",
        content: include_bytes!("../static/js/vendor/tailwindcss.js"),
        content_type: "application/javascript; charset=utf-8",
    },
    StaticAsset {
        path: "js/vendor/htmx.min.js",
        content: include_bytes!("../static/js/vendor/htmx.min.js"),
        content_type: "application/javascript; charset=utf-8",
    },
    StaticAsset {
        path: "js/vendor/htmx-ext-ws.js",
        content: include_bytes!("../static/js/vendor/htmx-ext-ws.js"),
        content_type: "application/javascript; charset=utf-8",
    },
    StaticAsset {
        path: "js/vendor/htmx-ext-json-enc.js",
        content: include_bytes!("../static/js/vendor/htmx-ext-json-enc.js"),
        content_type: "application/javascript; charset=utf-8",
    },
    // Alpine.js standard build (3.14.0). NOT the @alpinejs/csp build: keeping
    // the standard build preserves every existing inline x-data expression
    // (it relies on `new Function`, hence the CSP 'unsafe-eval').
    StaticAsset {
        path: "js/vendor/alpine.min.js",
        content: include_bytes!("../static/js/vendor/alpine.min.js"),
        content_type: "application/javascript; charset=utf-8",
    },
    // xterm 5.5.0 + addons. xterm injects <style> elements at runtime for
    // terminal sizing/theming, which is why the CSP keeps 'unsafe-inline' on
    // style-src.
    StaticAsset {
        path: "js/vendor/xterm.min.js",
        content: include_bytes!("../static/js/vendor/xterm.min.js"),
        content_type: "application/javascript; charset=utf-8",
    },
    StaticAsset {
        path: "js/vendor/xterm-addon-fit.min.js",
        content: include_bytes!("../static/js/vendor/xterm-addon-fit.min.js"),
        content_type: "application/javascript; charset=utf-8",
    },
    StaticAsset {
        path: "js/vendor/xterm-addon-web-links.min.js",
        content: include_bytes!("../static/js/vendor/xterm-addon-web-links.min.js"),
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
    StaticAsset {
        path: "css/asciinema-player.css",
        content: include_bytes!("../static/css/asciinema-player.css"),
        content_type: "text/css; charset=utf-8",
    },
    // Vendored xterm stylesheet (5.5.0), self-hosted alongside the JS above.
    StaticAsset {
        path: "css/vendor/xterm.min.css",
        content: include_bytes!("../static/css/vendor/xterm.min.css"),
        content_type: "text/css; charset=utf-8",
    },
    // ── Fonts ─────────────────────────────────────────────────────────────
    // text-security-disc.woff2: maps every glyph to "•" so a plain
    // <input type="text"> can be visually masked without setting
    // type="password" (which would re-arm Safari/Chrome credential
    // heuristics).  Source: https://github.com/noppa/text-security
    // License: SIL Open Font License 1.1 (see THIRD_PARTY_LICENSES.md).
    StaticAsset {
        path: "fonts/text-security-disc.woff2",
        content: include_bytes!("../static/fonts/text-security-disc.woff2"),
        content_type: "font/woff2",
    },
    // ── Images ────────────────────────────────────────────────────────────
    // Favicon referenced from templates/base.html. STATIC_FILES is an
    // exhaustive Capsicum whitelist: a template link without a registry
    // entry returns 404 and spams the audit middleware (regression that
    // lingered until 0.9.31). Pinned by
    // `tests/web/favicon_static_test.rs`.
    StaticAsset {
        path: "img/favicon.svg",
        content: include_bytes!("../static/img/favicon.svg"),
        content_type: "image/svg+xml",
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
    fn test_etag_is_deterministic() {
        let a = lookup("js/tailwind-config.js").unwrap();
        let e1 = a.etag();
        let e2 = a.etag();
        assert_eq!(e1, e2, "Same content must produce same ETag");
    }

    #[test]
    fn test_etag_is_quoted() {
        let a = lookup("css/vauban.css").unwrap();
        let etag = a.etag();
        assert!(
            etag.starts_with('"') && etag.ends_with('"'),
            "ETag must be quoted: {}",
            etag
        );
    }

    #[test]
    fn test_different_assets_have_different_etags() {
        let js = lookup("js/tailwind-config.js").unwrap();
        let css = lookup("css/vauban.css").unwrap();
        assert_ne!(
            js.etag(),
            css.etag(),
            "Different files must have different ETags"
        );
    }

    #[test]
    fn test_js_files_contain_expected_content() {
        let tw = lookup("js/tailwind-config.js").expect("tailwind-config.js must exist");
        let content = std::str::from_utf8(tw.content).expect("JS must be valid UTF-8");
        assert!(
            content.contains("tailwind"),
            "tailwind-config.js must contain 'tailwind'"
        );

        let components =
            lookup("js/vauban-components.js").expect("vauban-components.js must exist");
        let content = std::str::from_utf8(components.content).expect("JS must be valid UTF-8");
        assert!(
            content.contains("Alpine"),
            "vauban-components.js must contain 'Alpine'"
        );
    }

    /// The vendored front-end libraries replacing the runtime CDNs MUST all be
    /// registered so `/static/...` serves them same-origin (no CDN fetch).
    #[test]
    fn test_vendored_front_assets_are_registered() {
        for path in [
            "js/vendor/tailwindcss.js",
            "js/vendor/htmx.min.js",
            "js/vendor/htmx-ext-ws.js",
            "js/vendor/htmx-ext-json-enc.js",
            "js/vendor/alpine.min.js",
            "js/vendor/xterm.min.js",
            "js/vendor/xterm-addon-fit.min.js",
            "js/vendor/xterm-addon-web-links.min.js",
            "css/vendor/xterm.min.css",
        ] {
            let asset = lookup(path).unwrap_or_else(|| panic!("missing vendored asset: {path}"));
            assert!(!asset.content.is_empty(), "vendored asset {path} is empty");
        }
    }

    /// Pin the pinned upstream versions: a silent CDN refresh that swapped the
    /// bytes for a different major would break the inline expressions / JIT
    /// contract this self-hosting was built around.
    #[test]
    fn test_vendored_assets_pin_expected_versions() {
        let tailwind = lookup("js/vendor/tailwindcss.js").expect("tailwindcss.js must exist");
        let tailwind = std::str::from_utf8(tailwind.content).expect("JS must be valid UTF-8");
        assert!(
            tailwind.contains("3.4.17"),
            "tailwindcss.js must be the pinned 3.4.17 JIT bundle"
        );

        let alpine = lookup("js/vendor/alpine.min.js").expect("alpine.min.js must exist");
        let alpine = std::str::from_utf8(alpine.content).expect("JS must be valid UTF-8");
        assert!(
            alpine.contains("3.14.0") && alpine.contains("Alpine"),
            "alpine.min.js must be the pinned 3.14.0 standard build"
        );

        let xterm = lookup("js/vendor/xterm.min.js").expect("xterm.min.js must exist");
        let xterm = std::str::from_utf8(xterm.content).expect("JS must be valid UTF-8");
        assert!(
            xterm.contains("5.5.0"),
            "xterm.min.js must be the pinned 5.5.0 build"
        );
    }
}
