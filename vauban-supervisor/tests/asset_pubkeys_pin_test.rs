//! Source-grep pin tests for the `asset-pubkeys` admin subcommand.
//!
//! The command extracts the SSH public keys of `ssh_key`-auth assets
//! for external consumption (inventory, authorized_keys provisioning).
//! These pins freeze the contract:
//!
//! - INV-APK-1: the subcommand exists in the clap enum and is
//!   dispatched by `run_admin_command` (no dead CLI surface).
//! - INV-APK-2: the query carries the three row-selection invariants
//!   of the reference SQL -- `auth_type = 'ssh_key'` via `->>`,
//!   `is_deleted = false`, deterministic hostname ordering.
//! - INV-APK-3: the query only ever reads the PUBLIC key
//!   (`ssh_public_key`); the private-key / passphrase / password
//!   fields never appear in the asset-pubkeys code path.
//! - INV-APK-4: admin.rs stays DSL-only (no raw `sql_query`), so the
//!   type-checked Diesel layer cannot be bypassed.
//! - INV-APK-5: `--format` exposes exactly the two documented
//!   variants (Table, Plain).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

const SUPERVISOR_MAIN: &str = include_str!("../src/main.rs");
const ADMIN: &str = include_str!("../src/admin.rs");

/// Slice `src` from the given function signature to the next
/// top-level `fn` boundary, so assertions stay scoped to one body.
fn function_body<'a>(src: &'a str, sig: &str) -> &'a str {
    let start = src
        .find(sig)
        .unwrap_or_else(|| panic!("function signature `{sig}` not found"));
    let after = &src[start + sig.len()..];
    let end = after
        .find("\nfn ")
        .or_else(|| after.find("\npub fn "))
        .or_else(|| after.find("\n#[cfg(test)]"))
        .map(|e| start + sig.len() + e)
        .unwrap_or(src.len());
    &src[start..end]
}

// ==================== INV-APK-1: CLI wiring ====================

#[test]
fn subcommand_exists_and_is_dispatched() {
    assert!(
        SUPERVISOR_MAIN.contains("AssetPubkeys {"),
        "AdminSubcommand must carry the AssetPubkeys variant"
    );
    assert!(
        ADMIN.contains("AdminSubcommand::AssetPubkeys { format } => cmd_asset_pubkeys(format)"),
        "run_admin_command must dispatch AssetPubkeys to cmd_asset_pubkeys"
    );
}

// ==================== INV-APK-2: row-selection invariants ====================

#[test]
fn fetch_carries_the_reference_sql_filters() {
    let body = function_body(ADMIN, "fn fetch_asset_pubkeys");
    assert!(
        body.contains(r#".retrieve_as_text("auth_type")"#),
        "fetch_asset_pubkeys must filter on connection_config->>'auth_type'"
    );
    assert!(
        body.contains(r#".eq("ssh_key")"#),
        "fetch_asset_pubkeys must only select ssh_key-auth assets"
    );
    assert!(
        body.contains("assets::is_deleted.eq(false)"),
        "fetch_asset_pubkeys must exclude tombstoned assets"
    );
    assert!(
        body.contains("assets::hostname.asc()"),
        "fetch_asset_pubkeys must order by hostname for deterministic output"
    );
}

// ==================== INV-APK-3: public key only ====================

#[test]
fn pubkeys_code_path_never_touches_secret_fields() {
    for sig in [
        "fn fetch_asset_pubkeys",
        "fn format_pubkeys_table",
        "fn format_pubkeys_plain",
        "fn cmd_asset_pubkeys",
    ] {
        let body = function_body(ADMIN, sig);
        for secret in ["private_key", "passphrase", "\"password\""] {
            assert!(
                !body.contains(secret),
                "{sig} must never read the secret `{secret}` field"
            );
        }
    }
    let body = function_body(ADMIN, "fn fetch_asset_pubkeys");
    assert!(
        body.contains(r#".retrieve_as_text("ssh_public_key")"#),
        "fetch_asset_pubkeys must read connection_config->>'ssh_public_key'"
    );
}

// ==================== INV-APK-4: DSL-only ====================

#[test]
fn admin_module_stays_dsl_only() {
    assert!(
        !ADMIN.contains("sql_query"),
        "admin.rs must not use raw sql_query; the Diesel DSL is the only query surface"
    );
}

// ==================== INV-APK-5: format variants ====================

#[test]
fn format_flag_exposes_exactly_table_and_plain() {
    // Slice the enum block precisely (up to its closing brace).
    let start = SUPERVISOR_MAIN
        .find("pub enum PubkeysOutputFormat")
        .expect("PubkeysOutputFormat enum must exist in main.rs");
    let end = SUPERVISOR_MAIN[start..]
        .find("\n}")
        .map(|e| start + e)
        .expect("enum block must close");
    let body = &SUPERVISOR_MAIN[start..end];
    assert!(body.contains("Table"), "Table variant must exist");
    assert!(body.contains("Plain"), "Plain variant must exist");
    // Exactly two variants: the dispatch match in cmd_asset_pubkeys
    // stays exhaustive without a catch-all.
    let variant_count = body
        .lines()
        .filter(|l| {
            let t = l.trim();
            (t == "Table," || t == "Plain,") || (t == "Table" || t == "Plain")
        })
        .count();
    assert_eq!(
        variant_count, 2,
        "PubkeysOutputFormat must have exactly Table and Plain"
    );
    assert!(
        ADMIN.contains("PubkeysOutputFormat::Table => format_pubkeys_table(&rows)"),
        "table format must render via format_pubkeys_table"
    );
    assert!(
        ADMIN.contains("PubkeysOutputFormat::Plain => format_pubkeys_plain(&rows)"),
        "plain format must render via format_pubkeys_plain"
    );
}
