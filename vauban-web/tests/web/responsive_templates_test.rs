//! Structural responsive-design tests for Askama templates.
//!
//! These tests scan `vauban-web/templates/` at compile time (via the
//! `CARGO_MANIFEST_DIR` env var resolved at runtime) and enforce the
//! mobile-first rules captured by issue #14 (Users table overflow).
//!
//! The same rules are checked by `scripts/check_responsive_templates.sh`
//! so CI fails early; the integration test is the in-process safety net
//! when the script is bypassed.

use std::fs;
use std::path::{Path, PathBuf};

fn templates_dir() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(manifest).join("templates")
}

fn collect_html_files(root: &Path, files: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_html_files(&path, files);
        } else if path.extension().and_then(|s| s.to_str()) == Some("html") {
            files.push(path);
        }
    }
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

/// Rule 1: every `<table>` must live inside a horizontally-scrollable
/// container. We use a structural heuristic: the file containing the
/// table must mention `overflow-x-auto` or `overflow-auto`.
#[test]
fn test_tables_have_overflow_x_auto_wrapper() {
    let dir = templates_dir();
    let mut files = Vec::new();
    collect_html_files(&dir, &mut files);
    assert!(
        !files.is_empty(),
        "no template files found under {dir:?}; CARGO_MANIFEST_DIR misconfigured?"
    );

    let mut offenders = Vec::new();
    for file in &files {
        let body = read(file);
        if body.contains("<table") && !(body.contains("overflow-x-auto") || body.contains("overflow-auto")) {
            offenders.push(file.display().to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "templates with <table> but no overflow-x-auto wrapper:\n  {}",
        offenders.join("\n  ")
    );
}

/// Rule 2: page titles `<h1>`/`<h2>` must include a responsive step
/// (any `sm:`/`md:`/`lg:`/`xl:text-*`) when they reach `text-2xl`/`3xl`.
#[test]
fn test_page_titles_have_responsive_text_size() {
    let dir = templates_dir();
    let mut files = Vec::new();
    collect_html_files(&dir, &mut files);

    let mut offenders: Vec<String> = Vec::new();
    for file in &files {
        let body = read(file);
        for (lineno, line) in body.lines().enumerate() {
            let lower = line.to_lowercase();
            let is_title_tag = lower.contains("<h1 ") || lower.contains("<h2 ");
            if !is_title_tag {
                continue;
            }
            let has_fixed_big = lower.contains("text-2xl") || lower.contains("text-3xl");
            if !has_fixed_big {
                continue;
            }
            let has_responsive = lower.contains("sm:text-")
                || lower.contains("md:text-")
                || lower.contains("lg:text-")
                || lower.contains("xl:text-");
            if !has_responsive {
                offenders.push(format!("{}:{}: {}", file.display(), lineno + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "<h1>/<h2> with fixed text-2xl/3xl and no sm:/md:/lg: step:\n  {}",
        offenders.join("\n  ")
    );
}

/// Rule 3: floating containers must not pin a fixed `w-96` at the base
/// breakpoint. Acceptable: `w-full max-w-md` or `sm:w-96`.
#[test]
fn test_no_unscoped_w_96_floating_container() {
    let dir = templates_dir();
    let mut files = Vec::new();
    collect_html_files(&dir, &mut files);

    let mut offenders: Vec<String> = Vec::new();
    for file in &files {
        let body = read(file);
        for (lineno, line) in body.lines().enumerate() {
            if !line.contains("w-96") {
                continue;
            }
            // Allow only when prefixed by a breakpoint variant (e.g. sm:w-96).
            let mut iter = line.match_indices("w-96").peekable();
            let mut bare = false;
            while let Some((idx, _)) = iter.next() {
                let prev = line[..idx].chars().last();
                if !matches!(prev, Some(':')) {
                    bare = true;
                    break;
                }
            }
            if bare {
                offenders.push(format!("{}:{}: {}", file.display(), lineno + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "templates with hard-coded w-96 (overflows on 375px iPhone):\n  {}",
        offenders.join("\n  ")
    );
}
