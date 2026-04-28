//! Structural HTMX/CSRF tests for Askama templates.
//!
//! Mirrors `vauban-web/scripts/check_htmx_input_name.sh` so the rules
//! also fail at `cargo test` time, not only when CI runs the lint
//! script. Both checks must agree -- if you relax one, relax the other
//! at the same time.
//!
//! Pinned regressions:
//!
//!   - Issue #24 / BUG-13: an `<input ... hx-get=...>` with no `name`
//!     attribute makes `hx-include="this"` (and the implicit serializer
//!     for forms) produce an empty payload. The handler then sees no
//!     query param and degrades to "return everything".
//!
//!   - Sibling regression in the same handler: `<input
//!     name="csrf_token" />` shipped empty in the HTMX response, which
//!     would have silently broken Add the moment BUG-13 was fixed,
//!     because the double-submit verifier rejects empty tokens. The
//!     pattern is also explicitly forbidden by
//!     `.cursor/skills/front-end-design/SKILL.md`.

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

/// One coalesced `<input ...>` tag, with its starting line for diagnostics.
struct InputTag {
    line_no: usize,
    tag: String,
}

/// Coalesce multi-line `<input ...>` tags into single logical strings.
/// Returns one entry per `<input>` tag in the file (including the
/// trailing `>` and any attributes between).
fn coalesce_input_tags(body: &str) -> Vec<InputTag> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_tag = false;
    let mut start_line = 0usize;
    for (idx, line) in body.lines().enumerate() {
        let lineno = idx + 1;
        // Find every `<input` opener on this line; we handle one tag at
        // a time so a multi-tag line still works.
        let mut cursor = line;
        let mut col_offset = 0usize;
        loop {
            if !in_tag {
                if let Some(pos) = cursor.find("<input") {
                    in_tag = true;
                    start_line = lineno;
                    buf.clear();
                    cursor = &cursor[pos..];
                    col_offset += pos;
                } else {
                    break;
                }
            }
            // We're inside a tag. Look for its closing `>`.
            if let Some(end) = cursor.find('>') {
                buf.push_str(&cursor[..=end]);
                let normalized: String = buf.split_whitespace().collect::<Vec<_>>().join(" ");
                out.push(InputTag {
                    line_no: start_line,
                    tag: normalized,
                });
                in_tag = false;
                cursor = &cursor[end + 1..];
                col_offset += end + 1;
            } else {
                // Continues on the next line.
                buf.push_str(cursor);
                buf.push(' ');
                let _ = col_offset;
                break;
            }
        }
    }
    out
}

/// Rule 1: every `<input>` carrying any `hx-*` attribute must also
/// carry a non-empty `name="..."`.
#[test]
fn test_htmx_input_must_have_name_attribute() {
    let dir = templates_dir();
    let mut files = Vec::new();
    collect_html_files(&dir, &mut files);
    assert!(
        !files.is_empty(),
        "no template files found under {dir:?}; CARGO_MANIFEST_DIR misconfigured?"
    );

    // Whitespace + `hx-` + at least one letter, attribute-style.
    let hx_re = regex::Regex::new(r#"\shx-[a-zA-Z]+="#).unwrap();
    let name_re = regex::Regex::new(r#"\sname="[^"]+""#).unwrap();

    let mut offenders: Vec<String> = Vec::new();
    for file in &files {
        let body = read(file);
        for input in coalesce_input_tags(&body) {
            if hx_re.is_match(&input.tag) && !name_re.is_match(&input.tag) {
                offenders.push(format!(
                    "{}:{}: HTMX input missing name=\"...\":\n        {}",
                    file.display(),
                    input.line_no,
                    input.tag
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "HTMX-bearing inputs without a non-empty name (BUG-13 regression):\n  {}",
        offenders.join("\n  ")
    );
}

/// Rule 2: `<input name="csrf_token" ...>` must be populated via a
/// CANONICAL channel only. Exactly two are accepted:
///
///   - `value="..."` (server-side injection by Askama -- canonical for
///     login/MFA where the token is rendered into the page),
///   - `x-model="token"` (Alpine `csrf` component, canonical for
///     post-auth pages -- the `csrf` component encapsulates the cookie
///     read, see front-end-design SKILL).
///
/// Inline `:value="..."` / `x-bind:value="..."` is REJECTED. It is
/// functionally equivalent to vanilla-JS cookie reading and bypasses
/// the `csrf` Alpine component (the single source of truth for CSRF
/// reading). Migration path: wrap the form in `x-data="csrf"` and use
/// `x-model="token"` on the hidden input.
#[test]
fn test_csrf_input_must_be_populated_via_canonical_channel() {
    let dir = templates_dir();
    let mut files = Vec::new();
    collect_html_files(&dir, &mut files);

    let csrf_name_re = regex::Regex::new(r#"\sname="csrf_token""#).unwrap();
    let value_re = regex::Regex::new(r#"\svalue="[^"]+""#).unwrap();
    let xmodel_re = regex::Regex::new(r#"\sx-model="token""#).unwrap();
    let inline_bind_re = regex::Regex::new(r#"\s(?::value|x-bind:value)=""#).unwrap();

    let mut offenders: Vec<String> = Vec::new();
    for file in &files {
        let body = read(file);
        for input in coalesce_input_tags(&body) {
            if !csrf_name_re.is_match(&input.tag) {
                continue;
            }
            let has_value = value_re.is_match(&input.tag);
            let has_xmodel = xmodel_re.is_match(&input.tag);
            let has_inline_bind = inline_bind_re.is_match(&input.tag);

            if has_inline_bind {
                offenders.push(format!(
                    "{}:{}: csrf_token uses inline :value/x-bind:value \
                     (forbidden -- bypasses the `csrf` Alpine component). \
                     Use <form x-data=\"csrf\"> + x-model=\"token\":\n        {}",
                    file.display(),
                    input.line_no,
                    input.tag
                ));
            } else if !has_value && !has_xmodel {
                offenders.push(format!(
                    "{}:{}: csrf_token input is empty (need either server \
                     value=\"...\" or x-model=\"token\"):\n        {}",
                    file.display(),
                    input.line_no,
                    input.tag
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "csrf_token inputs violating the canonical-channel rule:\n  {}",
        offenders.join("\n  ")
    );
}

/// Rule 3: `document.cookie` must NEVER appear in a template. The
/// `csrf` Alpine component (`static/js/vauban-components.js`) is the
/// single reader of `__vauban_csrf`. Catches:
///
///   - `<input :value="document.cookie.match(...)">` on csrf_token
///     inputs (the modal pattern fixed in the issue #24 follow-up),
///   - `hx-vals="js:{csrf_token: document.cookie.match(...)}"` on
///     standalone Connect buttons (same pattern dressed up as an HTMX
///     evaluator).
///
/// If the cookie name or shape ever changes, the canonical component
/// is updated once; inline readers break silently.
#[test]
fn test_no_inline_cookie_reads_in_templates() {
    let dir = templates_dir();
    let mut files = Vec::new();
    collect_html_files(&dir, &mut files);

    let mut offenders: Vec<String> = Vec::new();
    for file in &files {
        let body = read(file);
        for (idx, line) in body.lines().enumerate() {
            if line.contains("document.cookie") {
                offenders.push(format!(
                    "{}:{}: 'document.cookie' must not appear in a template; \
                     use <form x-data=\"csrf\"> + x-model=\"token\":\n        {}",
                    file.display(),
                    idx + 1,
                    line.trim()
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "inline cookie reads in templates (front-end-design SKILL FORBIDDEN pattern):\n  {}",
        offenders.join("\n  ")
    );
}

/// Coverage / sanity test: this test file's expectations must be in
/// lock-step with the shell lint. If you change one, change both.
#[test]
fn test_lint_script_exists_and_is_executable() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let script = PathBuf::from(manifest)
        .join("scripts")
        .join("check_htmx_input_name.sh");
    assert!(
        script.exists(),
        "expected the matching shell lint at {}",
        script.display()
    );
}
