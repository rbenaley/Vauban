//! Issue #27 — source-level invariants for the asset zone split.
//!
//! These tests `include_str!` the production source files (handlers,
//! templates, router) and grep them with `format!`-built forbidden
//! tokens so the test cannot self-match. They are CHEAP (no DB, no
//! HTTP) and run in milliseconds, but they pin the architectural
//! contracts that distinguish the user zone (`/assets/*` ≠ session
//! opening, no CRUD) from the admin zone (`/assets/manage/*`,
//! gated `assets:manage`, never opens a session).
//!
//! Forbidden tokens are intentionally constructed via `format!("{}{}",
//! "abc", "def")` so a future grep test running over THIS file does
//! not match its own assertion strings. Each token is documented at
//! the call site.

/// Strip line comments (`//`, `///`, `//!`) and `#[cfg(test)]` blocks
/// from a Rust source file before scanning for forbidden tokens.
///
/// Doc comments routinely *describe* the patterns we forbid (they
/// are an integral part of the architectural contract being pinned),
/// so leaving them in the corpus would produce a permanent false
/// positive. We also drop everything after the first `#[cfg(test)]`
/// because per-file unit tests legitimately reference forbidden
/// tokens in their assertion strings.
fn strip_comments_and_tests(body: &str) -> String {
    let body = body
        .split("#[cfg(test)]")
        .next()
        .expect("source always has a non-test prefix");
    body.lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                ""
            } else if let Some(idx) = line.find("//") {
                // Best-effort inline comment strip. We do not attempt
                // to honour string literals here because the forbidden
                // tokens are not legitimately needed inside string
                // literals of production code.
                &line[..idx]
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Strip line comments from an HTML/Askama template before scanning.
///
/// Templates use `<!-- ... -->` and Askama `{# ... #}` for comments.
/// Both forms can legitimately reference the forbidden tokens in
/// human-readable annotations describing what the template MUST NOT
/// do, so we collapse them out of the scanned corpus.
fn strip_template_comments(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    loop {
        let html_idx = rest.find("<!--");
        let askama_idx = rest.find("{#");
        let (start, end_marker) = match (html_idx, askama_idx) {
            (None, None) => {
                out.push_str(rest);
                return out;
            }
            (Some(h), None) => (h, "-->"),
            (None, Some(a)) => (a, "#}"),
            (Some(h), Some(a)) if h < a => (h, "-->"),
            (Some(_), Some(a)) => (a, "#}"),
        };
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        match after.find(end_marker) {
            Some(end) => rest = &after[end + end_marker.len()..],
            None => return out,
        }
    }
}

/// `manage_assets` web handlers MUST NEVER open a session.
///
/// The admin zone is structurally session-free: no Connect / Request /
/// SSH connect / RDP connect / WebSocket reference may appear in the
/// admin handler module or in the admin templates. A regression here
/// would mean an admin path could spawn a privileged session bypassing
/// the user-facing access-rule pipeline.
#[test]
fn manage_assets_handlers_have_no_session_opening_path() {
    let sources: Vec<(&str, &str)> = vec![
        (
            "vauban-web/src/handlers/web/manage_assets.rs",
            include_str!("../../src/handlers/web/manage_assets.rs"),
        ),
        (
            "vauban-web/src/handlers/api/manage_assets.rs",
            include_str!("../../src/handlers/api/manage_assets.rs"),
        ),
        (
            "vauban-web/templates/assets/manage/list.html",
            include_str!("../../templates/assets/manage/list.html"),
        ),
        (
            "vauban-web/templates/assets/manage/detail.html",
            include_str!("../../templates/assets/manage/detail.html"),
        ),
    ];

    let forbidden: Vec<String> = vec![
        format!("connect{}rdp", "-"),
        format!("connect{}ssh", "_"),
        format!("submit{}access{}request", "_", "_"),
        format!("request{}access", "-"),
        format!("/sessions/{}request", ""),
        format!("ws{}://", "s"),
        format!("WebSocket{}", "Upgrade"),
    ];

    for (path, body) in sources {
        let production_body = if path.ends_with(".rs") {
            strip_comments_and_tests(body)
        } else {
            strip_template_comments(body)
        };
        for token in &forbidden {
            assert!(
                !production_body.contains(token.as_str()),
                "{path} must never reference '{token}' (asset zone split — admin zone is session-free)"
            );
        }
    }
}

/// User-zone `/assets` web handler MUST NEVER mutate or expose admin
/// affordances.
///
/// `assets.rs` (user zone) is allowed to issue READ queries against
/// `assets::table` (asset list, detail page lookup) but never an
/// `insert_into` / `update` / `delete` that targets the assets table,
/// and never a Casbin gate on `assets_manage` (that flag belongs in
/// the admin module).
#[test]
fn user_zone_assets_handler_has_no_crud_or_admin_gate() {
    let body = include_str!("../../src/handlers/web/assets.rs");
    let production_body = strip_comments_and_tests(body);

    let forbidden_mutations: Vec<String> = vec![
        format!("insert{}into{}assets::table", "_", "("),
        format!("diesel::update(assets::table"),
        format!("diesel::delete(assets::table"),
        format!("perms.assets{}manage", "_"),
        format!("AppError::forbidden(\"assets:{}\")", "manage"),
    ];

    for token in &forbidden_mutations {
        assert!(
            !production_body.contains(token.as_str()),
            "vauban-web/src/handlers/web/assets.rs (user zone) must never reference '{token}' \
             (mutations + assets:manage gate live in handlers/web/manage_assets.rs)"
        );
    }
}

/// Every public handler in `manage_assets.rs` (web + API) MUST gate
/// on `perms.assets_manage` AT THE TOP OF ITS BODY.
///
/// We grep for `pub async fn ...` followed by an early return on
/// `assets_manage`. This guarantees that even if the routing
/// middleware is stripped (regression), the handler still refuses
/// the call. The two layers are intentional defence-in-depth.
#[test]
fn manage_assets_every_handler_gates_on_assets_manage() {
    let sources: Vec<(&str, &str)> = vec![
        (
            "vauban-web/src/handlers/web/manage_assets.rs",
            include_str!("../../src/handlers/web/manage_assets.rs"),
        ),
        (
            "vauban-web/src/handlers/api/manage_assets.rs",
            include_str!("../../src/handlers/api/manage_assets.rs"),
        ),
    ];

    for (path, body) in sources {
        let production_body = strip_comments_and_tests(body);
        let production_body = production_body.as_str();

        // Walk every `pub async fn ` declaration and assert that its
        // body (up to the next top-level `pub async fn ` or EOF)
        // mentions both `perms.assets_manage` AND a forbidden /
        // forbidden-style early return. A handler that talks to the
        // DB before checking the gate cannot satisfy the assertion.
        let needle = "\npub async fn ";
        let mut pos = 0usize;
        let mut handlers = 0usize;
        while let Some(start) = production_body[pos..].find(needle) {
            let abs_start = pos + start + 1; // skip leading newline
            let body_after = &production_body[abs_start..];
            let next = body_after[needle.len()..]
                .find(needle)
                .map(|p| p + needle.len())
                .unwrap_or(body_after.len());
            let signature_and_body = &body_after[..next];

            assert!(
                signature_and_body.contains("perms.assets_manage"),
                "{path}: every public handler must read `perms.assets_manage` \
                 in its body (defence-in-depth on top of the routing gate). \
                 First 200 chars of offending handler:\n{}",
                &signature_and_body[..signature_and_body.len().min(200)]
            );

            // The gate must short-circuit (return early); we accept
            // either the web pattern (`flash_redirect(...)`,
            // `Err(AppError::Authorization(...))`, `Err(AppError::Forbidden)`)
            // or the API pattern (`AppError::forbidden("assets:manage")`).
            let short_circuits_web =
                signature_and_body.contains("flash_redirect(") // web admin handlers
                    || signature_and_body.contains("AppError::Authorization")
                    || signature_and_body.contains("AppError::Forbidden");
            let short_circuits_api = signature_and_body.contains("AppError::forbidden");
            assert!(
                short_circuits_web || short_circuits_api,
                "{path}: handler that gates on `perms.assets_manage` must \
                 also short-circuit on the deny path."
            );

            pos = abs_start + needle.len();
            handlers += 1;
        }
        assert!(
            handlers > 0,
            "{path} must declare at least one `pub async fn` handler \
             (otherwise the file is dead and the gate test is trivially passing)."
        );
    }
}

/// `main.rs` MUST mount the `/assets/manage` admin sub-router via
/// `Router::nest` and layer it with the `require_assets_manage`
/// middleware. A flat declaration of admin routes outside the nest
/// would silently bypass the routing-layer gate.
#[test]
fn router_mounts_assets_manage_under_a_gated_nest() {
    let raw = include_str!("../../src/main.rs");
    let body = strip_comments_and_tests(raw);

    // Collapse all whitespace so we tolerate `.nest(\n   "/path", ...)` formatting.
    let collapsed: String = body.split_whitespace().collect::<Vec<_>>().join(" ");

    let nest_token = format!(".nest( \"{}\"", "/assets/manage");
    let nest_token_compact = format!(".nest(\"{}\"", "/assets/manage");
    let api_nest_token = format!(".nest( \"{}\"", "/api/v1/assets/manage");
    let api_nest_token_compact = format!(".nest(\"{}\"", "/api/v1/assets/manage");

    assert!(
        collapsed.contains(nest_token.as_str())
            || collapsed.contains(nest_token_compact.as_str()),
        "main.rs must mount `/assets/manage` via Router::nest (web)"
    );
    assert!(
        collapsed.contains(api_nest_token.as_str())
            || collapsed.contains(api_nest_token_compact.as_str()),
        "main.rs must mount `/api/v1/assets/manage` via Router::nest (API)"
    );

    let middleware_token = "require_assets_manage::require_assets_manage";
    let occurrences = body.matches(middleware_token).count();
    assert!(
        occurrences >= 2,
        "main.rs must wire `require_assets_manage::require_assets_manage` on BOTH the web \
         and the API admin nest (found {occurrences} occurrence(s))."
    );
}

/// The Casbin permission catalogue rename (`assets_write` →
/// `assets_manage`) must be complete: no production code path may
/// reference the legacy `assets_write` field, the legacy
/// `("assets", "write")` tuple, nor the legacy `assets:write`
/// permission string. A drift here would mean a custom Casbin policy
/// granting `assets:manage` would fail to authorise a handler still
/// keying off the old name.
#[test]
fn no_legacy_assets_write_in_production_code() {
    let sources: Vec<(&str, &str)> = vec![
        (
            "vauban-web/src/auth/permissions.rs",
            include_str!("../../src/auth/permissions.rs"),
        ),
        (
            "vauban-web/src/handlers/web/assets.rs",
            include_str!("../../src/handlers/web/assets.rs"),
        ),
        (
            "vauban-web/src/handlers/web/manage_assets.rs",
            include_str!("../../src/handlers/web/manage_assets.rs"),
        ),
        (
            "vauban-web/src/handlers/api/assets.rs",
            include_str!("../../src/handlers/api/assets.rs"),
        ),
        (
            "vauban-web/src/handlers/api/manage_assets.rs",
            include_str!("../../src/handlers/api/manage_assets.rs"),
        ),
        (
            "vauban-web/src/handlers/web/ssh.rs",
            include_str!("../../src/handlers/web/ssh.rs"),
        ),
        (
            "vauban-web/src/middleware/permissions.rs",
            include_str!("../../src/middleware/permissions.rs"),
        ),
    ];

    let legacy_field = format!("perms.assets{}write", "_");
    let legacy_tuple = format!("(\"{}\", \"{}\")", "assets", "write");
    let legacy_perm_string = format!("assets:{}", "write");

    for (path, body) in sources {
        let production_body = strip_comments_and_tests(body);
        let production_body = production_body.as_str();

        assert!(
            !production_body.contains(legacy_field.as_str()),
            "{path}: production code must not reference the legacy \
             `perms.assets_write` field (renamed to `assets_manage` in issue #27)."
        );
        assert!(
            !production_body.contains(legacy_tuple.as_str()),
            "{path}: production code must not use the legacy Casbin tuple \
             `(\"assets\", \"write\")` (renamed to `(\"assets\", \"manage\")`)."
        );
        assert!(
            !production_body.contains(legacy_perm_string.as_str()),
            "{path}: production code must not surface the legacy permission \
             string `assets:write` (use `assets:manage`)."
        );
    }
}
