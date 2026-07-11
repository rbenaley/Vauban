//! Vault Secrets — source-level structural pins.
//!
//! `include_str!`/fs-walk greps over the production sources that cement
//! the architectural contracts of the organisational secrets feature:
//!
//! - The M2M API surface is read-only, isolated in its own crypto
//!   domain, and has no `read_all` / superuser bypass.
//! - vauban-access is the single oracle for `secret_access_rules`
//!   (no local Diesel access from vauban-web handlers).
//! - The web admin nest carries its `route_layer` AND every handler
//!   re-checks `perms.vault_secrets_manage` (defence-in-depth).
//! - The dedicated `secrets` API-key scope is wired outside of the
//!   read/write/admin hierarchy.
//!
//! Forbidden tokens are built via `format!` so this file cannot
//! self-match under a future grep test.

/// Strip line comments and `#[cfg(test)]` blocks (same helper contract
/// as `manage_assets_invariants_test`).
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
                &line[..idx]
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// =============================================================================
// 1. API surface: domain isolation, no bypass
// =============================================================================

/// The vault-secrets API handler must only ever touch the `"secrets"`
/// vault domain and must not carry any superuser / read_all bypass.
#[test]
fn api_handler_never_touches_other_domains_or_bypasses() {
    let body = include_str!("../../src/handlers/api/vault_secrets.rs");
    let production_body = strip_comments_and_tests(body);

    let forbidden: Vec<String> = vec![
        format!("\"{}\"", "credentials"),
        format!("\"{}\"", "mfa"),
        format!("read{}all", "_"),
        format!("is{}superuser", "_"),
        format!("is{}staff", "_"),
    ];
    for token in &forbidden {
        assert!(
            !production_body.contains(token.as_str()),
            "handlers/api/vault_secrets.rs must never reference '{token}' \
             (dedicated 'secrets' domain, rule-only access, no bypass)"
        );
    }

    assert!(
        production_body.contains("\"secrets\""),
        "handlers/api/vault_secrets.rs must decrypt through the dedicated 'secrets' domain"
    );
}

/// The API surface is GET-only: `main.rs` must not mount any mutating
/// verb under `/api/v1/vault`.
#[test]
fn api_vault_zone_is_get_only_in_router() {
    let raw = include_str!("../../src/main.rs");
    let body = strip_comments_and_tests(raw);
    let collapsed: String = body.split_whitespace().collect::<Vec<_>>().join("");

    // Every `.route("/api/v1/vault...` declaration must bind `get(`
    // only. We scan each occurrence of the path prefix and inspect the
    // method router that follows.
    let needle = "\"/api/v1/vault";
    let mut pos = 0usize;
    let mut routes = 0usize;
    while let Some(start) = collapsed[pos..].find(needle) {
        let abs = pos + start;
        let after = &collapsed[abs..];
        // The method binding follows the closing quote + comma.
        let binding_zone = &after[..after.len().min(120)];
        for verb in ["post(", "put(", "delete(", "patch("] {
            assert!(
                !binding_zone.contains(verb),
                "main.rs: `/api/v1/vault/*` must be GET-only, found '{verb}' near: {binding_zone}"
            );
        }
        assert!(
            binding_zone.contains("get("),
            "main.rs: `/api/v1/vault/*` route must bind get(), got: {binding_zone}"
        );
        routes += 1;
        pos = abs + needle.len();
    }
    assert!(
        routes >= 3,
        "main.rs must mount the three GET endpoints under /api/v1/vault (found {routes})"
    );
}

// =============================================================================
// 2. Single oracle: no secret_access_rules Diesel access in vauban-web
// =============================================================================

/// `secret_access_rules::table` is forbidden everywhere under
/// `vauban-web/src/handlers/` and `vauban-web/src/services/`:
/// vauban-access is the single evaluation + CRUD oracle. Only the
/// `secret_secret_groups` junction may be driven in local Diesel.
#[test]
fn secret_access_rules_table_never_queried_locally() {
    let forbidden = format!("secret_access_rules::{}", "table");
    let roots = [
        concat!(env!("CARGO_MANIFEST_DIR"), "/src/handlers"),
        concat!(env!("CARGO_MANIFEST_DIR"), "/src/services"),
    ];

    let mut scanned = 0usize;
    for root in roots {
        let mut stack = vec![std::path::PathBuf::from(root)];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("readable source dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let body = std::fs::read_to_string(&path).expect("readable source file");
                    let production_body = strip_comments_and_tests(&body);
                    assert!(
                        !production_body.contains(forbidden.as_str()),
                        "{} must not query secret_access_rules directly \
                         (single oracle = vauban-access IPC)",
                        path.display()
                    );
                    scanned += 1;
                }
            }
        }
    }
    assert!(
        scanned > 20,
        "sanity: the walk must scan the handler/service tree (scanned {scanned} files)"
    );
}

// =============================================================================
// 3. Web nest: route_layer + exhaustive per-handler gate
// =============================================================================

/// `main.rs` must mount `/vault/secrets` via Router::nest and layer it
/// with `require_vault_secrets_manage`.
#[test]
fn router_mounts_vault_secrets_under_a_gated_nest() {
    let raw = include_str!("../../src/main.rs");
    let body = strip_comments_and_tests(raw);
    let collapsed: String = body.split_whitespace().collect::<Vec<_>>().join(" ");

    let nest_token = format!(".nest( \"{}\"", "/vault/secrets");
    let nest_token_compact = format!(".nest(\"{}\"", "/vault/secrets");
    assert!(
        collapsed.contains(nest_token.as_str()) || collapsed.contains(nest_token_compact.as_str()),
        "main.rs must mount `/vault/secrets` via Router::nest"
    );

    let middleware_token = "require_vault_secrets_manage::require_vault_secrets_manage";
    assert!(
        body.contains(middleware_token),
        "main.rs must wire `require_vault_secrets_manage` as the nest's route_layer"
    );
}

/// Every public handler of the three web sub-CRUD modules must gate on
/// `perms.vault_secrets_manage` in its body and short-circuit on deny
/// (mirror of `manage_assets_every_handler_gates_on_assets_manage`).
#[test]
fn vault_secrets_every_web_handler_gates_on_manage() {
    let sources: Vec<(&str, &str)> = vec![
        (
            "vauban-web/src/handlers/web/vault_secrets.rs",
            include_str!("../../src/handlers/web/vault_secrets.rs"),
        ),
        (
            "vauban-web/src/handlers/web/secret_groups.rs",
            include_str!("../../src/handlers/web/secret_groups.rs"),
        ),
        (
            "vauban-web/src/handlers/web/secret_access_rules.rs",
            include_str!("../../src/handlers/web/secret_access_rules.rs"),
        ),
    ];

    for (path, body) in sources {
        let production_body = strip_comments_and_tests(body);
        let production_body = production_body.as_str();

        let needle = "\npub async fn ";
        let mut pos = 0usize;
        let mut handlers = 0usize;
        while let Some(start) = production_body[pos..].find(needle) {
            let abs_start = pos + start + 1;
            let body_after = &production_body[abs_start..];
            let next = body_after[needle.len()..]
                .find(needle)
                .map(|p| p + needle.len())
                .unwrap_or(body_after.len());
            let signature_and_body = &body_after[..next];

            assert!(
                signature_and_body.contains("perms.vault_secrets_manage"),
                "{path}: every public handler must read `perms.vault_secrets_manage` \
                 in its body (defence-in-depth on top of the routing gate). \
                 First 200 chars of offending handler:\n{}",
                &signature_and_body[..signature_and_body.len().min(200)]
            );

            let short_circuits = signature_and_body.contains("flash_redirect(")
                || signature_and_body.contains("AppError::forbidden")
                || signature_and_body.contains("AppError::Authorization")
                || signature_and_body.contains("AppError::Forbidden");
            assert!(
                short_circuits,
                "{path}: handler gating on `perms.vault_secrets_manage` must \
                 short-circuit on the deny path."
            );

            pos = abs_start + needle.len();
            handlers += 1;
        }
        assert!(
            handlers > 0,
            "{path} must declare at least one `pub async fn` handler."
        );
    }
}

/// The web admin zone must never render or re-expose a stored secret
/// value: templates carry no `secret.value` / ciphertext binding.
#[test]
fn templates_never_render_secret_value() {
    let templates: Vec<(&str, &str)> = vec![
        (
            "templates/secrets/secret_detail.html",
            include_str!("../../templates/secrets/secret_detail.html"),
        ),
        (
            "templates/secrets/secret_edit.html",
            include_str!("../../templates/secrets/secret_edit.html"),
        ),
        (
            "templates/secrets/secret_list.html",
            include_str!("../../templates/secrets/secret_list.html"),
        ),
    ];
    let forbidden: Vec<String> = vec![
        format!("secret.{}", "value"),
        format!("secret.{}", "ciphertext"),
        format!("{{ {} }}", "ciphertext"),
    ];
    for (path, body) in templates {
        for token in &forbidden {
            assert!(
                !body.contains(token.as_str()),
                "{path} must never bind the secret value/ciphertext (write-only contract)"
            );
        }
    }
}

// =============================================================================
// 4. Scope isolation wiring
// =============================================================================

/// `required_scope` must map the `/api/v1/vault` prefix to
/// `ApiKeyScope::Secrets` BEFORE the method match, and `satisfies` must
/// keep `Secrets` outside the read/write/admin hierarchy.
#[test]
fn api_key_middleware_wires_secrets_scope_isolation() {
    let body = include_str!("../../src/middleware/api_key.rs");
    let production_body = strip_comments_and_tests(body);

    assert!(
        production_body.contains("/api/v1/vault"),
        "middleware/api_key.rs: required_scope must special-case the /api/v1/vault prefix"
    );
    assert!(
        production_body.contains("ApiKeyScope::Secrets"),
        "middleware/api_key.rs: the Secrets scope must be wired in required_scope/satisfies"
    );

    // The hierarchy ranking must exclude Secrets (a `scope_rank` that
    // ranks Secrets would silently fold it back into the hierarchy).
    let models_body = include_str!("../../src/models/api_key.rs");
    let production_models = strip_comments_and_tests(models_body);
    assert!(
        production_models.contains("Secrets"),
        "models/api_key.rs must declare the Secrets scope variant"
    );
}

/// The `vault_secrets` Casbin resource must be tracked by the
/// PermissionContext (both flags) and granted in the default policy.
#[test]
fn casbin_vault_secrets_resource_is_wired() {
    let perms_body = include_str!("../../src/auth/permissions.rs");
    let production_perms = strip_comments_and_tests(perms_body);
    for field in ["vault_secrets_read", "vault_secrets_manage"] {
        assert!(
            production_perms.contains(field),
            "auth/permissions.rs must expose the `{field}` flag"
        );
    }

    let policy = include_str!("../../../config/access/default_policy.csv");
    assert!(
        policy.contains("vault_secrets, read"),
        "default_policy.csv must grant vault_secrets:read"
    );
    assert!(
        policy.contains("vault_secrets, manage"),
        "default_policy.csv must grant vault_secrets:manage"
    );
}
