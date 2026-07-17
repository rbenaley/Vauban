//! Structural pins for the input-format validation seams (July 2026).
//!
//! Pure `include_str!` source pins, no DB, no HTTP. They freeze the
//! call-graph decisions of the hardening so a refactor cannot silently
//! drop a validation layer:
//!
//! 1. Every web handler that persists a slug-shaped field calls
//!    `validate_slug_format` (asset groups, secret groups, vault
//!    secret name) BEFORE the write.
//! 2. `manage_assets.rs` never persists `form.status` without a prior
//!    `AssetStatus::parse_strict` gate (web create + update, API
//!    update).
//! 3. The web users handlers reuse the API-zone rule
//!    (`validate_username_format` -> `RE_USERNAME`) + email validation.
//! 4. vauban-access re-checks fail-closed with the SAME
//!    `shared::validation` source of truth (asset groups + secret
//!    groups).
//! 5. The slug/username `pattern` attributes stay on the form inputs
//!    (browser layer).

const WEB_MOD_RS: &str = include_str!("../../src/handlers/web/mod.rs");
const ASSET_GROUPS_RS: &str = include_str!("../../src/handlers/web/asset_groups.rs");
const SECRET_GROUPS_RS: &str = include_str!("../../src/handlers/web/secret_groups.rs");
const VAULT_SECRETS_RS: &str = include_str!("../../src/handlers/web/vault_secrets.rs");
const USERS_RS: &str = include_str!("../../src/handlers/web/users.rs");
const MANAGE_ASSETS_WEB_RS: &str = include_str!("../../src/handlers/web/manage_assets.rs");
const MANAGE_ASSETS_API_RS: &str = include_str!("../../src/handlers/api/manage_assets.rs");

const ACCESS_HANDLERS_RS: &str = include_str!("../../../vauban-access/src/handlers.rs");
const ACCESS_SECRETS_RS: &str = include_str!("../../../vauban-access/src/secrets.rs");

const AG_CREATE_HTML: &str = include_str!("../../templates/assets/manage/groups/create.html");
const AG_EDIT_HTML: &str = include_str!("../../templates/assets/manage/groups/edit.html");
const SG_CREATE_HTML: &str = include_str!("../../templates/secrets/group_create.html");
const SG_EDIT_HTML: &str = include_str!("../../templates/secrets/group_edit.html");
const VS_CREATE_HTML: &str = include_str!("../../templates/secrets/secret_create.html");
const VS_EDIT_HTML: &str = include_str!("../../templates/secrets/secret_edit.html");
const USER_CREATE_HTML: &str = include_str!("../../templates/accounts/user_create.html");
const USER_EDIT_HTML: &str = include_str!("../../templates/accounts/user_edit.html");

/// Count non-commented occurrences of `needle` in `src`.
fn count_calls(src: &str, needle: &str) -> usize {
    src.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .filter(|l| l.contains(needle))
        .count()
}

// =============================================================================
// 1. Web slug surfaces
// =============================================================================

#[test]
fn every_slug_form_handler_validates_the_slug_format() {
    // asset_groups: create + update.
    assert!(
        count_calls(ASSET_GROUPS_RS, "validate_slug_format") >= 2,
        "asset_groups.rs must gate slug format on create AND update"
    );
    // secret_groups: create + update.
    assert!(
        count_calls(SECRET_GROUPS_RS, "validate_slug_format") >= 2,
        "secret_groups.rs must gate slug format on create AND update"
    );
    // vault_secrets: the name is the M2M lookup key -> slug policy.
    assert!(
        count_calls(VAULT_SECRETS_RS, "validate_slug_format") >= 2,
        "vault_secrets.rs must gate the name format on create AND update"
    );
}

#[test]
fn asset_group_handlers_validate_color_and_icon() {
    assert!(
        count_calls(ASSET_GROUPS_RS, "validate_hex_color_format") >= 2,
        "asset_groups.rs must gate the color format on create AND update"
    );
    assert!(
        count_calls(ASSET_GROUPS_RS, "validate_icon_choice") >= 2,
        "asset_groups.rs must gate the icon catalog on create AND update"
    );
}

// =============================================================================
// 2. Asset status: strict parse before every persisted write
// =============================================================================

#[test]
fn asset_status_writes_are_gated_by_parse_strict() {
    // Web zone: create + update both persist `form.status` -> both must
    // carry the strict-parse gate.
    let web_writes = count_calls(MANAGE_ASSETS_WEB_RS, "status.eq(&form.status)");
    let web_gates = count_calls(MANAGE_ASSETS_WEB_RS, "AssetStatus::parse_strict");
    assert!(
        web_writes >= 2,
        "expected the web create+update status writes to exist (refactor? update this pin)"
    );
    assert!(
        web_gates >= web_writes,
        "manage_assets.rs (web): every `status.eq(&form.status)` write needs a prior \
         AssetStatus::parse_strict gate ({web_gates} gates for {web_writes} writes)"
    );

    // API zone: the update path persists `request.status`.
    assert!(
        count_calls(MANAGE_ASSETS_API_RS, "AssetStatus::parse_strict") >= 1,
        "manage_assets.rs (API) must gate request.status with AssetStatus::parse_strict"
    );
}

#[test]
fn lenient_asset_status_parse_never_feeds_a_write() {
    // The display-side fallback (`AssetStatus::parse` -> Unknown) must
    // not appear on the same line as a Diesel `.set(`/`.values(` write
    // in the asset write paths.
    for (name, src) in [
        ("web/manage_assets.rs", MANAGE_ASSETS_WEB_RS),
        ("api/manage_assets.rs", MANAGE_ASSETS_API_RS),
    ] {
        for line in src.lines() {
            let l = line.trim_start();
            if l.starts_with("//") {
                continue;
            }
            assert!(
                !(l.contains("AssetStatus::parse(")
                    && (l.contains(".set(") || l.contains(".values("))),
                "{name}: lenient AssetStatus::parse must never launder a status into a write: {l}"
            );
        }
    }
}

// =============================================================================
// 3. Users web zone: same rule as the API zone
// =============================================================================

#[test]
fn web_users_handlers_reuse_the_api_username_and_email_rules() {
    assert!(
        count_calls(USERS_RS, "validate_username_format") >= 2,
        "users.rs must gate the username charset on create AND update"
    );
    assert!(
        count_calls(USERS_RS, "validate_email_format") >= 2,
        "users.rs must gate the email format on create AND update"
    );
    // The shared helper itself must delegate to the API-zone regex --
    // this is the anti-divergence pin between the two zones.
    assert!(
        WEB_MOD_RS.contains("RE_USERNAME.is_match"),
        "validate_username_format must delegate to models::user::RE_USERNAME"
    );
    assert!(
        WEB_MOD_RS.contains("ValidateEmail"),
        "validate_email_format must use the same validator-crate rule as #[validate(email)]"
    );
}

// =============================================================================
// 4. Hostname charset gate
// =============================================================================

#[test]
fn asset_handlers_gate_the_hostname_charset() {
    assert!(
        count_calls(MANAGE_ASSETS_WEB_RS, "validate_hostname_format") >= 2,
        "web manage_assets.rs must gate the hostname charset on create AND update"
    );
    assert!(
        count_calls(MANAGE_ASSETS_API_RS, "is_valid_hostname") >= 2,
        "API manage_assets.rs must gate the hostname charset on create AND update"
    );
}

// =============================================================================
// 5. vauban-access fail-closed re-checks
// =============================================================================

#[test]
fn vauban_access_recheck_uses_the_shared_validators() {
    // Asset groups: one shared helper called from create AND update.
    assert!(
        ACCESS_HANDLERS_RS.contains("fn validate_asset_group_formats"),
        "vauban-access handlers.rs must define the asset-group format re-check"
    );
    assert!(
        count_calls(ACCESS_HANDLERS_RS, "validate_asset_group_formats(") >= 2,
        "vauban-access must re-check asset-group formats on create AND update"
    );
    assert!(
        ACCESS_HANDLERS_RS.contains("shared::validation::is_valid_slug")
            && ACCESS_HANDLERS_RS.contains("shared::validation::is_valid_hex_color")
            && ACCESS_HANDLERS_RS.contains("shared::validation::is_valid_icon"),
        "the vauban-access re-check must delegate to shared::validation (single source of truth)"
    );

    // Secret groups: slug re-check on create AND update.
    assert!(
        count_calls(ACCESS_SECRETS_RS, "shared::validation::is_valid_slug") >= 2,
        "vauban-access secrets.rs must re-check the slug on create AND update"
    );
}

// =============================================================================
// 6. Browser layer: pattern attributes on the form inputs
// =============================================================================

#[test]
fn slug_inputs_carry_the_canonical_pattern_attribute() {
    const SLUG_PATTERN: &str = r#"pattern="[a-z0-9]([a-z0-9_-]*[a-z0-9])?""#;
    for (name, html) in [
        ("assets/manage/groups/create.html", AG_CREATE_HTML),
        ("assets/manage/groups/edit.html", AG_EDIT_HTML),
        ("secrets/group_create.html", SG_CREATE_HTML),
        ("secrets/group_edit.html", SG_EDIT_HTML),
        ("secrets/secret_create.html", VS_CREATE_HTML),
        ("secrets/secret_edit.html", VS_EDIT_HTML),
    ] {
        assert!(
            html.contains(SLUG_PATTERN),
            "{name}: the slug/name input must carry the canonical pattern attribute"
        );
        assert!(
            html.contains(r#"maxlength="100""#),
            "{name}: the slug/name input must cap at 100 chars"
        );
    }
}

#[test]
fn username_inputs_match_the_api_regex() {
    // Browser mirror of RE_USERNAME (`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`).
    const USERNAME_PATTERN: &str = r#"pattern="[a-zA-Z0-9][a-zA-Z0-9._-]*""#;
    for (name, html) in [
        ("accounts/user_create.html", USER_CREATE_HTML),
        ("accounts/user_edit.html", USER_EDIT_HTML),
    ] {
        assert!(
            html.contains(USERNAME_PATTERN),
            "{name}: the username input pattern must mirror RE_USERNAME"
        );
    }
}

// =============================================================================
// 7. CI lint wiring (same rationale as cdn_assets_lints_test.rs: the
//    bash lint must be green from `cargo test` too, so a developer
//    that bypasses CI's bash runner still trips the regression).
// =============================================================================

#[test]
fn check_input_format_validation_lint_passes() {
    use std::path::PathBuf;
    use std::process::Command;

    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("check_input_format_validation.sh");
    assert!(script.exists(), "missing lint script: {}", script.display());

    let out = Command::new("bash")
        .arg(&script)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {}", script.display(), e));

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "check_input_format_validation.sh failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}
