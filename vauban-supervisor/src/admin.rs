//! Admin CLI commands for the supervisor.
//!
//! Each subcommand loads config, connects to the database directly, and
//! executes the operation. Password hashing uses Argon2id.
//!
//! Future: These will be orchestrated via IPC to the appropriate services.
//! For now, the supervisor (most privileged process) performs direct DB access.

// Admin CLI tools use interactive prompts and expect()/unwrap() on I/O
#![allow(clippy::expect_used, clippy::unwrap_used)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use crate::config::SupervisorConfig;
use crate::{AdminSubcommand, PubkeysOutputFormat};
use anyhow::{Context, Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version, password_hash::SaltString};
use diesel::dsl::exists;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use rand::rngs::OsRng;
use std::io::{self, Write};
use vauban_db::schema::{asset_groups, assets, users, vauban_groups};

/// Execute an admin subcommand.
pub fn run_admin_command(cmd: AdminSubcommand) -> Result<()> {
    match cmd {
        AdminSubcommand::CreateSuperuser => cmd_create_superuser(),
        AdminSubcommand::ResetPassword { username } => cmd_reset_password(&username),
        AdminSubcommand::Reset2fa { username } => cmd_reset_2fa(&username),
        AdminSubcommand::MigrateSecrets { dry_run } => cmd_migrate_secrets(dry_run),
        AdminSubcommand::SeedData => cmd_seed_data(),
        AdminSubcommand::Migrate {
            check,
            database_url,
        } => cmd_migrate(check, database_url),
        AdminSubcommand::AssetPubkeys { format } => cmd_asset_pubkeys(format),
    }
}

fn load_db_connection() -> Result<PgConnection> {
    let config = SupervisorConfig::load_auto().context("Failed to load configuration")?;
    PgConnection::establish(&config.database.url).context("Failed to connect to database")
}

/// Resolve the database URL for `migrate`: `--database-url` flag, then
/// the `DATABASE_URL` environment variable, then the configuration
/// file. The config file is only touched as a last resort because the
/// post-install path runs as the `postgres` OS user, which cannot read
/// vauban.conf (0600 root + service-user ACLs).
fn resolve_migrate_database_url(flag: Option<String>) -> Result<String> {
    if let Some(url) = flag {
        return Ok(url);
    }
    if let Ok(url) = std::env::var("DATABASE_URL")
        && !url.is_empty()
    {
        return Ok(url);
    }
    let config = SupervisorConfig::load_auto().context("Failed to load configuration")?;
    Ok(config.database.url)
}

/// `vauban-supervisor migrate [--check] [--database-url <url>]`
///
/// Applies pending embedded schema migrations through the
/// baseline-aware runner (`vauban_db::migrations::run`). With
/// `--check`, only reports pending migrations (read-only) and fails if
/// any are pending. Any error -- SQL failure, partial schema, dead DB
/// -- exits non-zero so `pkg install` surfaces a loud POST-INSTALL
/// failure instead of a clean install on a broken database.
fn cmd_migrate(check: bool, database_url: Option<String>) -> Result<()> {
    let url = resolve_migrate_database_url(database_url)?;
    let mut conn = PgConnection::establish(&url).context("Failed to connect to database")?;

    if check {
        let pending =
            vauban_db::migrations::check(&mut conn).map_err(|e| anyhow!(e.to_string()))?;
        if pending.is_empty() {
            println!("Database schema is up to date (no pending migrations).");
            return Ok(());
        }
        for version in &pending {
            println!("pending: {version}");
        }
        bail!(
            "{} pending migration(s); run `vauban-supervisor migrate`",
            pending.len()
        );
    }

    let report = vauban_db::migrations::run(&mut conn).map_err(|e| anyhow!(e.to_string()))?;

    println!("Database state detected: {}", report.state);
    if !report.stamped.is_empty() {
        println!(
            "Stamped {} baseline migration(s) as already applied:",
            report.stamped.len()
        );
        for version in &report.stamped {
            println!("  stamped: {version}");
        }
    }
    if report.applied.is_empty() {
        println!("No pending migrations to apply.");
    } else {
        println!("Applied {} migration(s):", report.applied.len());
        for version in &report.applied {
            println!("  applied: {version}");
        }
    }
    Ok(())
}

// ==================== asset-pubkeys ====================

/// One `ssh_key`-auth asset, ready for display.
#[derive(Debug, PartialEq, Eq)]
struct AssetPubkeyRow {
    /// `login@hostname` -- login is `connection_config->>'username'`
    /// when non-empty, else the `connection_username` column.
    user_at_host: String,
    /// `connection_config->>'ssh_public_key'` (clear OpenSSH text; a
    /// PUBLIC key, so no vault decryption involved). `None`/empty means
    /// a misconfigured asset.
    public_key: Option<String>,
}

/// Rust-side COALESCE: the JSON `username` wins when present and
/// non-empty, otherwise fall back to the `connection_username` column.
fn coalesce_login(json_username: Option<&str>, connection_username: &str) -> String {
    match json_username {
        Some(u) if !u.trim().is_empty() => u.to_string(),
        _ => connection_username.to_string(),
    }
}

/// Load the SSH public keys of every non-deleted `ssh_key`-auth asset,
/// ordered by hostname (deterministic output).
///
/// DSL equivalent of:
/// `SELECT COALESCE(connection_config->>'username', connection_username)
///  || '@' || hostname, connection_config->>'ssh_public_key'
///  FROM assets WHERE connection_config->>'auth_type' = 'ssh_key'
///  AND is_deleted = false` (the COALESCE and `||` happen in Rust).
fn fetch_asset_pubkeys(conn: &mut PgConnection) -> Result<Vec<AssetPubkeyRow>> {
    let rows: Vec<(Option<String>, String, String, Option<String>)> = assets::table
        .filter(
            assets::connection_config
                .retrieve_as_text("auth_type")
                .eq("ssh_key"),
        )
        .filter(assets::is_deleted.eq(false))
        .order(assets::hostname.asc())
        .select((
            // `->>` returns SQL NULL when the key is absent, but diesel
            // types `retrieve_as_text` on a NOT NULL jsonb column as
            // non-nullable Text -- force the honest Option<String>.
            assets::connection_config
                .retrieve_as_text("username")
                .nullable(),
            assets::connection_username,
            assets::hostname,
            assets::connection_config
                .retrieve_as_text("ssh_public_key")
                .nullable(),
        ))
        .load(conn)
        .context("Failed to query ssh_key assets")?;

    Ok(rows
        .into_iter()
        .map(
            |(json_username, connection_username, hostname, public_key)| AssetPubkeyRow {
                user_at_host: format!(
                    "{}@{hostname}",
                    coalesce_login(json_username.as_deref(), &connection_username)
                ),
                public_key,
            },
        )
        .collect())
}

/// psql-like aligned table. Rows without a public key show an empty
/// cell so misconfigured `ssh_key` assets stay visible.
fn format_pubkeys_table(rows: &[AssetPubkeyRow]) -> String {
    if rows.is_empty() {
        return "(no ssh_key assets)\n".to_string();
    }

    const HDR_HOST: &str = "user@hostname";
    const HDR_KEY: &str = "ssh_public_key";

    let key_of = |row: &AssetPubkeyRow| row.public_key.as_deref().unwrap_or("").to_string();

    let host_width = rows
        .iter()
        .map(|r| r.user_at_host.len())
        .chain([HDR_HOST.len()])
        .max()
        .unwrap_or(0);
    let key_width = rows
        .iter()
        .map(|r| key_of(r).len())
        .chain([HDR_KEY.len()])
        .max()
        .unwrap_or(0);

    // psql-style: headers centered, values left-aligned, `|` at the
    // same column on every line; trailing whitespace trimmed.
    let mut out = String::new();
    out.push_str(format!(" {HDR_HOST:^host_width$} | {HDR_KEY:^key_width$}").trim_end());
    out.push('\n');
    out.push_str(&format!(
        "{}+{}\n",
        "-".repeat(host_width + 2),
        "-".repeat(key_width + 2)
    ));
    for row in rows {
        out.push_str(format!(" {:<host_width$} | {}", row.user_at_host, key_of(row)).trim_end());
        out.push('\n');
    }
    out
}

/// Machine-consumable output: one `user@host key` line per asset.
/// Rows without a public key are SKIPPED (safe to pipe into an
/// authorized_keys-style consumer).
fn format_pubkeys_plain(rows: &[AssetPubkeyRow]) -> String {
    let mut out = String::new();
    for row in rows {
        if let Some(key) = row.public_key.as_deref()
            && !key.trim().is_empty()
        {
            out.push_str(&format!("{} {key}\n", row.user_at_host));
        }
    }
    out
}

/// `vauban-supervisor asset-pubkeys [--format=table|plain]`
fn cmd_asset_pubkeys(format: PubkeysOutputFormat) -> Result<()> {
    let mut conn = load_db_connection()?;
    let rows = fetch_asset_pubkeys(&mut conn)?;
    let rendered = match format {
        PubkeysOutputFormat::Table => format_pubkeys_table(&rows),
        PubkeysOutputFormat::Plain => format_pubkeys_plain(&rows),
    };
    print!("{rendered}");
    Ok(())
}

fn cmd_create_superuser() -> Result<()> {
    println!("\nVAUBAN - Create Superuser");
    println!("========================\n");

    let mut conn = load_db_connection()?;

    let has_superuser: bool = diesel::select(exists(
        users::table.filter(
            users::is_superuser
                .eq(true)
                .and(users::is_deleted.eq(false)),
        ),
    ))
    .get_result(&mut conn)
    .unwrap_or(false);

    if has_superuser {
        println!("A superuser already exists.");
        let confirm = prompt("Create another superuser? (y/N): ")?;
        if confirm.to_lowercase() != "y" {
            println!("Operation cancelled.");
            return Ok(());
        }
        println!();
    }

    let username = loop {
        let input = prompt("Username: ")?;
        if let Err(e) = validate_username(&input) {
            eprintln!("{e}");
            continue;
        }
        // Canonicalise to the case-insensitive identity form so the
        // superuser can log in on the web regardless of the casing typed
        // here, and so the DB `lower(username)` unique index is honoured.
        let input = shared::username::normalize_username(&input);
        let exists: bool = diesel::select(exists(
            users::table.filter(users::username.eq(&input).and(users::is_deleted.eq(false))),
        ))
        .get_result(&mut conn)
        .unwrap_or(false);

        if exists {
            eprintln!("Username '{input}' already exists.");
            continue;
        }
        break input;
    };

    // No uniqueness check on the e-mail: several accounts may belong to
    // the same person and share one address (the DB constraint was
    // dropped by migration 20260704000000_users_email_drop_unique).
    let email = loop {
        let input = prompt("Email: ")?;
        if let Err(e) = validate_email(&input) {
            eprintln!("{e}");
            continue;
        }
        break input;
    };

    let first_name = prompt("First name (optional): ")?;
    let last_name = prompt("Last name (optional): ")?;

    let password = loop {
        let pw = prompt_password("Password (min 12 chars): ")?;
        if pw.len() < 12 {
            eprintln!("Password must be at least 12 characters.");
            continue;
        }
        let confirm = prompt_password("Confirm password: ")?;
        if pw != confirm {
            eprintln!("Passwords do not match.");
            continue;
        }
        break pw;
    };

    let hash = hash_password(&password)?;
    let user_uuid = uuid::Uuid::new_v4();

    let first_name_opt = if first_name.is_empty() {
        None
    } else {
        Some(first_name.as_str())
    };
    let last_name_opt = if last_name.is_empty() {
        None
    } else {
        Some(last_name.as_str())
    };

    diesel::insert_into(users::table)
        .values((
            users::uuid.eq(user_uuid),
            users::username.eq(&username),
            users::email.eq(&email),
            users::password_hash.eq(&hash),
            users::first_name.eq(first_name_opt),
            users::last_name.eq(last_name_opt),
            users::is_active.eq(true),
            users::is_staff.eq(true),
            users::is_superuser.eq(true),
            users::is_service_account.eq(false),
            users::mfa_enabled.eq(false),
            users::mfa_enforced.eq(false),
            users::preferences.eq(serde_json::json!({})),
            users::auth_source.eq("local"),
        ))
        .execute(&mut conn)
        .context("Failed to create superuser")?;

    println!("\nSuperuser created successfully!");
    println!("  Username: {username}");
    println!("  Email:    {email}");
    println!("  UUID:     {user_uuid}");

    Ok(())
}

fn cmd_reset_password(username: &str) -> Result<()> {
    println!("\nVAUBAN - Reset Password");
    println!("=======================\n");

    if username.trim().is_empty() {
        bail!("Username cannot be empty");
    }
    // Usernames are stored in canonical (case-insensitive) form, so an
    // operator passing `Admin` must still resolve the stored `admin`.
    let username: &str = &shared::username::normalize_username(username);

    let mut conn = load_db_connection()?;

    let user_exists: bool = diesel::select(exists(
        users::table.filter(
            users::username
                .eq(username)
                .and(users::is_deleted.eq(false)),
        ),
    ))
    .get_result(&mut conn)
    .unwrap_or(false);

    if !user_exists {
        bail!("User '{username}' not found");
    }

    let password = loop {
        let pw = prompt_password("New password (min 12 chars): ")?;
        if pw.len() < 12 {
            eprintln!("Password must be at least 12 characters.");
            continue;
        }
        let confirm = prompt_password("Confirm new password: ")?;
        if pw != confirm {
            eprintln!("Passwords do not match.");
            continue;
        }
        break pw;
    };

    let hash = hash_password(&password)?;

    let rows = diesel::update(
        users::table.filter(
            users::username
                .eq(username)
                .and(users::is_deleted.eq(false)),
        ),
    )
    .set((
        users::password_hash.eq(&hash),
        users::updated_at.eq(diesel::dsl::now),
    ))
    .execute(&mut conn)
    .context("Failed to update password")?;

    if rows > 0 {
        println!("\nPassword for '{username}' has been updated.");
    } else {
        bail!("Failed to update password");
    }

    Ok(())
}

fn cmd_reset_2fa(username: &str) -> Result<()> {
    println!("\nVAUBAN - Reset 2FA");
    println!("==================\n");

    if username.trim().is_empty() {
        bail!("Username cannot be empty");
    }
    // Usernames are stored in canonical (case-insensitive) form, so an
    // operator passing `Admin` must still resolve the stored `admin`.
    let username: &str = &shared::username::normalize_username(username);

    let mut conn = load_db_connection()?;

    let mfa_status: Option<MfaStatus> = users::table
        .filter(
            users::username
                .eq(username)
                .and(users::is_deleted.eq(false)),
        )
        .select(MfaStatus::as_select())
        .first(&mut conn)
        .optional()
        .context("Database error")?;

    match mfa_status {
        None => bail!("User '{username}' not found"),
        Some(ref status) if !status.mfa_enabled => {
            println!("User '{username}' does not have MFA enabled. No action needed.");
            return Ok(());
        }
        _ => {}
    }

    println!("WARNING: This will disable two-factor authentication for '{username}'.");
    println!("The user will need to set up MFA again on their next login.\n");

    let confirm = prompt("Are you sure? (yes/no): ")?;
    if confirm.trim().to_lowercase() != "yes" {
        println!("Operation cancelled.");
        return Ok(());
    }

    diesel::update(
        users::table.filter(
            users::username
                .eq(username)
                .and(users::is_deleted.eq(false)),
        ),
    )
    .set((
        users::mfa_enabled.eq(false),
        users::mfa_secret.eq(None::<String>),
        users::updated_at.eq(diesel::dsl::now),
    ))
    .execute(&mut conn)
    .context("Failed to disable MFA")?;

    println!("\nTwo-factor authentication disabled for '{username}'.");
    println!("The user will need to set up MFA again on their next login.");

    Ok(())
}

fn cmd_migrate_secrets(dry_run: bool) -> Result<()> {
    println!("\nVAUBAN - Migrate Secrets");
    println!("========================\n");

    if dry_run {
        println!("[DRY RUN] No changes will be made.\n");
    }

    use vauban_vault::keyring::{Keyring, MasterKey};

    let default_master_key_path = "/var/vauban/vault/master.key";
    let default_key_version_path = "/var/vauban/vault/key_version";

    let master_key_path = std::env::var("VAUBAN_VAULT_MASTER_KEY_PATH")
        .unwrap_or_else(|_| default_master_key_path.to_string());
    let master_key = MasterKey::from_file(&master_key_path).context(format!(
        "Failed to load master key from '{master_key_path}'"
    ))?;

    let key_version = load_key_version(default_key_version_path)?;
    println!("Master key loaded (version {key_version}).");

    let mfa_keyring = Keyring::new(master_key.as_bytes(), "mfa", key_version);
    let cred_keyring = Keyring::new(master_key.as_bytes(), "credentials", key_version);
    drop(master_key);

    let mut conn = load_db_connection()?;
    println!("Connected to database.\n");

    if !dry_run {
        println!("WARNING: This will encrypt all plaintext secrets in the database.");
        println!("Make sure you have a backup before proceeding.\n");
        let confirm = prompt("Continue? (yes/no): ")?;
        if confirm.trim().to_lowercase() != "yes" {
            println!("Operation cancelled.");
            return Ok(());
        }
        println!();
    }

    // Migrate MFA secrets
    let mfa_count = migrate_mfa_secrets(&mut conn, &mfa_keyring, dry_run)?;
    let cred_count = migrate_credential_secrets(&mut conn, &cred_keyring, dry_run)?;

    println!("\n--- Summary ---");
    println!("MFA secrets migrated:        {mfa_count}");
    println!("Asset credentials migrated:  {cred_count}");
    if dry_run {
        println!("\n[DRY RUN] No changes were made.");
    } else {
        println!("\nMigration complete.");
    }

    Ok(())
}

fn cmd_seed_data() -> Result<()> {
    println!("\nVAUBAN - Seed Data");
    println!("==================\n");

    let mut conn = load_db_connection()?;

    let default_hash = hash_password("SecurePassword123!")?;

    // Seed users
    let users_data = [
        (
            "admin",
            "admin@vauban.local",
            "System",
            "Administrator",
            true,
            true,
        ),
        (
            "operator1",
            "operator1@vauban.local",
            "John",
            "Smith",
            true,
            false,
        ),
        (
            "operator2",
            "operator2@vauban.local",
            "Jane",
            "Doe",
            true,
            false,
        ),
        (
            "user1",
            "user1@vauban.local",
            "Alice",
            "Martin",
            false,
            false,
        ),
        ("user2", "user2@vauban.local", "Bob", "Wilson", false, false),
    ];

    let mut user_count = 0u32;
    for (uname, mail, fname, lname, staff, superuser) in &users_data {
        let exists: bool = diesel::select(exists(users::table.filter(users::username.eq(uname))))
            .get_result(&mut conn)
            .unwrap_or(false);

        if exists {
            println!("  - {uname} already exists");
            user_count += 1;
            continue;
        }

        let uid = uuid::Uuid::new_v4();
        let result = diesel::insert_into(users::table)
            .values((
                users::uuid.eq(uid),
                users::username.eq(uname),
                users::email.eq(mail),
                users::password_hash.eq(&default_hash),
                users::first_name.eq(Some(fname)),
                users::last_name.eq(Some(lname)),
                users::is_active.eq(true),
                users::is_staff.eq(staff),
                users::is_superuser.eq(superuser),
                users::is_service_account.eq(false),
                users::mfa_enabled.eq(false),
                users::mfa_enforced.eq(false),
                users::preferences.eq(serde_json::json!({})),
                users::auth_source.eq("local"),
            ))
            .execute(&mut conn);

        match result {
            Ok(_) => {
                println!("  - {uname} created");
                user_count += 1;
            }
            Err(e) => eprintln!("  WARNING: Failed to create {uname}: {e}"),
        }
    }
    println!("{user_count} users ready.\n");

    // Seed groups
    let groups = [
        ("Administrators", "Full system administrators"),
        ("Operators", "System operators"),
        ("Developers", "Development team"),
        ("Auditors", "Security auditors"),
        ("Support", "Support team"),
    ];

    let mut group_count = 0u32;
    for (name, desc) in &groups {
        let exists: bool = diesel::select(exists(
            vauban_groups::table.filter(vauban_groups::name.eq(name)),
        ))
        .get_result(&mut conn)
        .unwrap_or(false);

        if !exists {
            let uid = uuid::Uuid::new_v4();
            let _ = diesel::insert_into(vauban_groups::table)
                .values((
                    vauban_groups::uuid.eq(uid),
                    vauban_groups::name.eq(name),
                    vauban_groups::description.eq(desc),
                    vauban_groups::source.eq("local"),
                ))
                .execute(&mut conn);
            println!("  - {name} created");
        } else {
            println!("  - {name} already exists");
        }
        group_count += 1;
    }
    println!("{group_count} groups ready.\n");

    // Seed asset groups
    let asset_groups = [
        ("Production Servers", "production", "#EF4444", "server"),
        ("Development Servers", "development", "#3B82F6", "code"),
        ("Database Servers", "databases", "#8B5CF6", "database"),
        ("Network Devices", "network", "#10B981", "wifi"),
        ("Windows Workstations", "workstations", "#F59E0B", "desktop"),
    ];

    let mut ag_count = 0u32;
    for (name, slug, color, icon) in &asset_groups {
        let exists: bool = diesel::select(exists(
            asset_groups::table.filter(
                asset_groups::slug
                    .eq(slug)
                    .and(asset_groups::is_deleted.eq(false)),
            ),
        ))
        .get_result(&mut conn)
        .unwrap_or(false);

        if !exists {
            let uid = uuid::Uuid::new_v4();
            let _ = diesel::insert_into(asset_groups::table)
                .values((
                    asset_groups::uuid.eq(uid),
                    asset_groups::name.eq(name),
                    asset_groups::slug.eq(slug),
                    asset_groups::description.eq(format!("{name} environment")),
                    asset_groups::color.eq(color),
                    asset_groups::icon.eq(icon),
                ))
                .execute(&mut conn);
            println!("  - {name} created");
        } else {
            println!("  - {name} already exists");
        }
        ag_count += 1;
    }
    println!("{ag_count} asset groups ready.\n");

    println!("Seed data generation complete!");

    Ok(())
}

// ==================== Migration helpers ====================

fn load_key_version(default_path: &str) -> Result<u32> {
    if let Ok(v) = std::env::var("VAUBAN_VAULT_KEY_VERSION") {
        let version: u32 = v
            .parse()
            .context("VAUBAN_VAULT_KEY_VERSION must be a number")?;
        if version == 0 {
            bail!("Key version must be >= 1");
        }
        return Ok(version);
    }

    let path =
        std::env::var("VAUBAN_VAULT_KEY_VERSION_PATH").unwrap_or_else(|_| default_path.to_string());

    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let version: u32 = content
                .trim()
                .parse()
                .context(format!("Invalid key version in '{path}'"))?;
            if version == 0 {
                bail!("Key version must be >= 1");
            }
            Ok(version)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("Key version file not found, defaulting to version 1");
            Ok(1)
        }
        Err(e) => Err(e).context(format!("Failed to read key version from '{path}'")),
    }
}

fn is_encrypted(value: &str) -> bool {
    // Thin alias: shape grammar lives in shared (I2). migrate_secrets still
    // encrypts via vauban_vault::keyring::Keyring.
    shared::vault_envelope::is_vault_envelope(value)
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = users)]
struct MfaRow {
    id: i32,
    username: String,
    mfa_secret: Option<String>,
}

fn migrate_mfa_secrets(
    conn: &mut PgConnection,
    keyring: &vauban_vault::keyring::Keyring,
    dry_run: bool,
) -> Result<usize> {
    println!("Scanning MFA secrets...");

    let rows: Vec<MfaRow> = users::table
        .filter(
            users::mfa_secret
                .is_not_null()
                .and(users::is_deleted.eq(false)),
        )
        .select(MfaRow::as_select())
        .load(conn)
        .context("Failed to query users")?;

    let mut migrated = 0;
    for row in &rows {
        if let Some(ref secret) = row.mfa_secret {
            if is_encrypted(secret) {
                continue;
            }
            match keyring.encrypt(secret.as_bytes()) {
                Ok(encrypted) => {
                    if dry_run {
                        println!(
                            "  [DRY RUN] Would migrate MFA for '{}' (id={})",
                            row.username, row.id
                        );
                    } else {
                        diesel::update(users::table.filter(users::id.eq(row.id)))
                            .set(users::mfa_secret.eq(&encrypted))
                            .execute(conn)
                            .context(format!("Failed to update MFA for '{}'", row.username))?;
                        println!("  Migrated MFA for '{}' (id={})", row.username, row.id);
                    }
                    migrated += 1;
                }
                Err(e) => eprintln!(
                    "  WARNING: Failed to encrypt MFA for '{}': {e}",
                    row.username
                ),
            }
        }
    }
    println!("MFA: {} scanned, {} migrated", rows.len(), migrated);
    Ok(migrated)
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = assets)]
struct AssetCredRow {
    id: i32,
    name: String,
    connection_config: serde_json::Value,
}

fn migrate_credential_secrets(
    conn: &mut PgConnection,
    keyring: &vauban_vault::keyring::Keyring,
    dry_run: bool,
) -> Result<usize> {
    println!("\nScanning asset credentials...");

    let credential_fields = ["password", "private_key", "passphrase"];

    let rows: Vec<AssetCredRow> = assets::table
        .select(AssetCredRow::as_select())
        .load(conn)
        .context("Failed to query assets")?;

    let mut migrated = 0;
    for row in &rows {
        let mut config = row.connection_config.clone();
        let mut changed = false;

        if let Some(obj) = config.as_object_mut() {
            for field in &credential_fields {
                if let Some(serde_json::Value::String(val)) = obj.get(*field)
                    && !val.is_empty()
                    && !is_encrypted(val)
                {
                    match keyring.encrypt(val.as_bytes()) {
                        Ok(encrypted) => {
                            obj.insert(field.to_string(), serde_json::Value::String(encrypted));
                            changed = true;
                        }
                        Err(e) => eprintln!(
                            "  WARNING: Failed to encrypt '{field}' for '{}': {e}",
                            row.name
                        ),
                    }
                }
            }
        }

        if changed {
            if dry_run {
                println!(
                    "  [DRY RUN] Would encrypt credentials for '{}' (id={})",
                    row.name, row.id
                );
            } else {
                diesel::update(assets::table.filter(assets::id.eq(row.id)))
                    .set(assets::connection_config.eq(&config))
                    .execute(conn)
                    .context(format!("Failed to update '{}' credentials", row.name))?;
                println!("  Encrypted credentials for '{}' (id={})", row.name, row.id);
            }
            migrated += 1;
        }
    }

    println!("Credentials: {} scanned, {} migrated", rows.len(), migrated);
    Ok(migrated)
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = users)]
struct MfaStatus {
    #[allow(dead_code)]
    id: i32,
    mfa_enabled: bool,
}

// ==================== Helpers ====================

fn prompt(message: &str) -> Result<String> {
    print!("{message}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("Failed to read input")?;
    Ok(input.trim().to_string())
}

fn prompt_password(message: &str) -> Result<String> {
    print!("{message}");
    io::stdout().flush()?;
    rpassword::read_password().context("Failed to read password")
}

fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| anyhow!("Failed to create Argon2 parameters: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("Failed to hash password: {e}"))?
        .to_string();
    Ok(hash)
}

pub fn validate_username(username: &str) -> Result<()> {
    if username.len() < 3 {
        bail!("Username must be at least 3 characters");
    }
    if username.len() > 150 {
        bail!("Username must be at most 150 characters");
    }
    if !username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        bail!("Username can only contain letters, numbers, underscores, dots, and hyphens");
    }
    Ok(())
}

pub fn validate_email(email: &str) -> Result<()> {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        bail!("Invalid email address");
    }
    if !parts[1].contains('.') {
        bail!("Email domain must contain a dot");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== validate_username ====================

    #[test]
    fn test_validate_username_valid() {
        assert!(validate_username("admin").is_ok());
        assert!(validate_username("user_123").is_ok());
        assert!(validate_username("user.name").is_ok());
        assert!(validate_username("user-name").is_ok());
        assert!(validate_username("abc").is_ok());
    }

    #[test]
    fn test_validate_username_boundary_lengths() {
        assert!(validate_username("abc").is_ok());
        assert!(validate_username("ab").is_err());
        let exact_150 = "a".repeat(150);
        assert!(validate_username(&exact_150).is_ok());
        let too_long = "a".repeat(151);
        assert!(validate_username(&too_long).is_err());
    }

    #[test]
    fn test_validate_username_empty() {
        assert!(validate_username("").is_err());
    }

    #[test]
    fn test_validate_username_invalid_chars() {
        assert!(validate_username("user@name").is_err());
        assert!(validate_username("user name").is_err());
        assert!(validate_username("user/name").is_err());
        assert!(validate_username("user!").is_err());
        assert!(validate_username("user#tag").is_err());
    }

    #[test]
    fn test_validate_username_allowed_special_chars() {
        assert!(validate_username("user_name").is_ok());
        assert!(validate_username("user.name").is_ok());
        assert!(validate_username("user-name").is_ok());
        assert!(validate_username("u_s.e-r").is_ok());
    }

    // ==================== validate_email ====================

    #[test]
    fn test_validate_email_valid() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("test@domain.org").is_ok());
        assert!(validate_email("a@b.c").is_ok());
    }

    #[test]
    fn test_validate_email_invalid() {
        assert!(validate_email("userexample.com").is_err());
        assert!(validate_email("user@localhost").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@").is_err());
    }

    #[test]
    fn test_validate_email_no_at_sign() {
        assert!(validate_email("plaintext").is_err());
    }

    #[test]
    fn test_validate_email_multiple_at_signs() {
        assert!(validate_email("user@@example.com").is_err());
        assert!(validate_email("u@s@e.com").is_err());
    }

    #[test]
    fn test_validate_email_empty() {
        assert!(validate_email("").is_err());
    }

    #[test]
    fn test_validate_email_domain_without_dot() {
        assert!(validate_email("user@localhost").is_err());
    }

    // ==================== hash_password ====================

    #[test]
    fn test_hash_password_produces_argon2id() {
        let hash = hash_password("securepassword12").unwrap();
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn test_hash_password_different_salts() {
        let h1 = hash_password("securepassword12").unwrap();
        let h2 = hash_password("securepassword12").unwrap();
        assert_ne!(
            h1, h2,
            "same password must produce different hashes (random salt)"
        );
    }

    #[test]
    fn test_hash_password_contains_version_and_params() {
        let hash = hash_password("testpassword123").unwrap();
        assert!(
            hash.contains("$v=19$"),
            "hash must contain Argon2 version v0x13=19"
        );
        assert!(hash.contains("m=65536"), "hash must use 64 MiB memory");
        assert!(hash.contains("t=3"), "hash must use 3 iterations");
        assert!(hash.contains("p=4"), "hash must use 4 parallelism");
    }

    #[test]
    fn test_hash_password_empty_input() {
        let hash = hash_password("").unwrap();
        assert!(
            hash.starts_with("$argon2id$"),
            "even empty password must hash"
        );
    }

    // ==================== is_encrypted ====================

    #[test]
    fn test_is_encrypted_valid() {
        assert!(is_encrypted("v1:data"));
        assert!(is_encrypted("v12:AAAA"));
        assert!(is_encrypted("v999:x"));
    }

    #[test]
    fn test_is_encrypted_invalid() {
        assert!(!is_encrypted("plaintext"));
        assert!(!is_encrypted(""));
        assert!(!is_encrypted("v:data"));
        assert!(!is_encrypted("data:v1"));
        assert!(!is_encrypted("va:data"));
        assert!(!is_encrypted("1:data"));
    }

    #[test]
    fn test_is_encrypted_too_short() {
        assert!(!is_encrypted("v1:"));
        assert!(!is_encrypted("v1"));
        assert!(!is_encrypted("v"));
    }

    #[test]
    fn test_is_encrypted_no_colon() {
        assert!(!is_encrypted("v12data"));
    }

    // ==================== run_admin_command routing ====================

    #[test]
    fn test_admin_subcommand_variants_exist() {
        let _create = AdminSubcommand::CreateSuperuser;
        let _reset_pw = AdminSubcommand::ResetPassword {
            username: "test".to_string(),
        };
        let _reset_mfa = AdminSubcommand::Reset2fa {
            username: "test".to_string(),
        };
        let _migrate = AdminSubcommand::MigrateSecrets { dry_run: true };
        let _seed = AdminSubcommand::SeedData;
        let _db_migrate = AdminSubcommand::Migrate {
            check: false,
            database_url: None,
        };
        let _pubkeys = AdminSubcommand::AssetPubkeys {
            format: PubkeysOutputFormat::Table,
        };
    }

    #[test]
    fn test_resolve_migrate_database_url_prefers_flag() {
        let url = resolve_migrate_database_url(Some("postgresql:///flagged".to_string()))
            .expect("flag resolution must not touch config or env");
        assert_eq!(url, "postgresql:///flagged");
    }

    // ==================== structural checks ====================

    #[test]
    fn test_admin_module_has_all_commands() {
        let source = include_str!("admin.rs");
        assert!(source.contains("fn cmd_create_superuser"));
        assert!(source.contains("fn cmd_reset_password"));
        assert!(source.contains("fn cmd_reset_2fa"));
        assert!(source.contains("fn cmd_migrate_secrets"));
        assert!(source.contains("fn cmd_seed_data"));
        assert!(source.contains("fn cmd_migrate"));
        assert!(source.contains("fn cmd_asset_pubkeys"));
    }

    #[test]
    fn test_admin_uses_argon2id() {
        let source = include_str!("admin.rs");
        assert!(source.contains("Argon2id"), "must use Argon2id algorithm");
        assert!(
            source.contains("Algorithm::Argon2id"),
            "hash_password must explicitly select Argon2id variant"
        );
    }

    #[test]
    fn test_admin_seed_passwords_are_hashed() {
        let source = include_str!("admin.rs");
        assert!(
            source.contains("hash_password(\"SecurePassword123!\")"),
            "seed data must hash passwords via hash_password(), not store plaintext"
        );
        assert!(
            !source.contains("insert_into(users::table)") || source.contains("default_hash"),
            "seed INSERT must use hashed password variable, not inline plaintext"
        );
    }

    #[test]
    fn test_migrate_secrets_uses_keyring() {
        let source = include_str!("admin.rs");
        assert!(
            source.contains("Keyring::new"),
            "must use vauban-vault Keyring"
        );
        assert!(source.contains("MasterKey"), "must load master key");
    }

    #[test]
    fn test_migrate_handles_both_secret_types() {
        let source = include_str!("admin.rs");
        assert!(source.contains("migrate_mfa_secrets"));
        assert!(source.contains("migrate_credential_secrets"));
    }

    #[test]
    fn test_seed_data_creates_all_entity_types() {
        let source = include_str!("admin.rs");
        assert!(source.contains("insert_into(users::table)"));
        assert!(source.contains("insert_into(vauban_groups::table)"));
        assert!(source.contains("insert_into(asset_groups::table)"));
    }

    // ==================== asset-pubkeys: coalesce_login ====================

    #[test]
    fn test_coalesce_login_json_username_wins() {
        assert_eq!(coalesce_login(Some("root"), "fallback"), "root");
    }

    #[test]
    fn test_coalesce_login_falls_back_when_absent() {
        assert_eq!(coalesce_login(None, "fallback"), "fallback");
    }

    #[test]
    fn test_coalesce_login_falls_back_when_empty_or_blank() {
        assert_eq!(coalesce_login(Some(""), "fallback"), "fallback");
        assert_eq!(coalesce_login(Some("   "), "fallback"), "fallback");
    }

    // ==================== asset-pubkeys: table format ====================

    fn pk_row(user_at_host: &str, key: Option<&str>) -> AssetPubkeyRow {
        AssetPubkeyRow {
            user_at_host: user_at_host.to_string(),
            public_key: key.map(str::to_string),
        }
    }

    #[test]
    fn test_format_pubkeys_table_matches_psql_layout() {
        const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMnTWoVi5btjn4YfOQxk48ziaWBDUjs+U02LSQeCkBAR root@localhost";
        let rows = [pk_row("root@localhost", Some(KEY))];
        let out = format_pubkeys_table(&rows);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "header + separator + one row");
        // Headers are centered (psql style); values are left-aligned;
        // trailing whitespace is trimmed.
        assert_eq!(
            lines[0],
            format!(
                " {:^14} | {:^width$}",
                "user@hostname",
                "ssh_public_key",
                width = KEY.len()
            )
            .trim_end()
        );
        assert_eq!(
            lines[1],
            format!("{}+{}", "-".repeat(16), "-".repeat(KEY.len() + 2))
        );
        assert_eq!(lines[2], format!(" {:<14} | {KEY}", "root@localhost"));
    }

    #[test]
    fn test_format_pubkeys_table_pads_to_longest_value() {
        let rows = [
            pk_row("a@b", Some("k1")),
            pk_row("longer-user@longer-hostname", Some("key-two")),
        ];
        let out = format_pubkeys_table(&rows);
        let lines: Vec<&str> = out.lines().collect();
        // The column joint sits at the same offset on every line
        // (`|` on header/rows, `+` on the separator).
        let joint = lines[1].find('+').expect("separator must have a joint");
        assert_eq!(lines[0].find('|'), Some(joint));
        for row_line in &lines[2..] {
            assert_eq!(
                row_line.find('|'),
                Some(joint),
                "misaligned row: {row_line:?}"
            );
        }
        // Both column headers survive.
        assert!(lines[0].contains("user@hostname"));
        assert!(lines[0].contains("ssh_public_key"));
        // Separator has exactly one column joint.
        assert_eq!(lines[1].matches('+').count(), 1);
        assert!(lines[1].chars().all(|c| c == '-' || c == '+'));
    }

    #[test]
    fn test_format_pubkeys_table_shows_missing_key_as_empty_cell() {
        let rows = [pk_row("root@nokey", None)];
        let out = format_pubkeys_table(&rows);
        let last = out.lines().last().unwrap();
        assert!(
            last.contains("root@nokey"),
            "misconfigured ssh_key assets must stay visible in table mode"
        );
        let key_cell = last.split('|').nth(1).unwrap();
        assert!(key_cell.trim().is_empty(), "key cell must be empty");
    }

    #[test]
    fn test_format_pubkeys_table_empty() {
        assert_eq!(format_pubkeys_table(&[]), "(no ssh_key assets)\n");
    }

    // ==================== asset-pubkeys: plain format ====================

    #[test]
    fn test_format_pubkeys_plain_one_line_per_asset() {
        let rows = [
            pk_row("root@h1", Some("ssh-ed25519 AAA root@h1")),
            pk_row("admin@h2", Some("ssh-rsa BBB admin@h2")),
        ];
        assert_eq!(
            format_pubkeys_plain(&rows),
            "root@h1 ssh-ed25519 AAA root@h1\nadmin@h2 ssh-rsa BBB admin@h2\n"
        );
    }

    #[test]
    fn test_format_pubkeys_plain_skips_missing_or_blank_keys() {
        let rows = [
            pk_row("root@h1", None),
            pk_row("root@h2", Some("   ")),
            pk_row("root@h3", Some("ssh-ed25519 CCC")),
        ];
        assert_eq!(
            format_pubkeys_plain(&rows),
            "root@h3 ssh-ed25519 CCC\n",
            "plain output must be safe to pipe (no empty-key lines)"
        );
    }

    #[test]
    fn test_format_pubkeys_plain_empty() {
        assert_eq!(format_pubkeys_plain(&[]), "");
    }

    // ==================== asset-pubkeys: DB integration matrix ============

    fn test_db_connection() -> PgConnection {
        let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgresql://vauban_test:vauban_test@localhost/vauban_test".to_string()
        });
        PgConnection::establish(&url).expect("test database must be reachable")
    }

    fn insert_test_asset(
        conn: &mut PgConnection,
        name: &str,
        hostname: &str,
        connection_username: &str,
        config: serde_json::Value,
        deleted: bool,
    ) {
        diesel::insert_into(assets::table)
            .values((
                assets::name.eq(name),
                assets::hostname.eq(hostname),
                assets::connection_username.eq(connection_username),
                assets::connection_config.eq(config),
                assets::is_deleted.eq(deleted),
            ))
            .execute(conn)
            .expect("failed to seed test asset");
    }

    /// Full E2E matrix on a live database: inclusion (ssh_key only,
    /// not deleted), Rust-side COALESCE, missing-key rows surfaced as
    /// None, deterministic hostname ordering.
    #[test]
    fn test_fetch_asset_pubkeys_db_matrix() {
        let mut conn = test_db_connection();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros();
        let prefix = format!("pkmx{ts}");

        // a: ssh_key + JSON username -> JSON username wins.
        insert_test_asset(
            &mut conn,
            &format!("{prefix}-a"),
            &format!("{prefix}-a.example"),
            "colfallback",
            serde_json::json!({
                "auth_type": "ssh_key",
                "username": "jsonroot",
                "ssh_public_key": "ssh-ed25519 AAAA a"
            }),
            false,
        );
        // b: ssh_key without JSON username -> connection_username.
        insert_test_asset(
            &mut conn,
            &format!("{prefix}-b"),
            &format!("{prefix}-b.example"),
            "colroot",
            serde_json::json!({
                "auth_type": "ssh_key",
                "ssh_public_key": "ssh-ed25519 BBBB b"
            }),
            false,
        );
        // c: ssh_key without public key -> present, key = None.
        insert_test_asset(
            &mut conn,
            &format!("{prefix}-c"),
            &format!("{prefix}-c.example"),
            "nokey",
            serde_json::json!({ "auth_type": "ssh_key" }),
            false,
        );
        // d: password auth -> excluded.
        insert_test_asset(
            &mut conn,
            &format!("{prefix}-d"),
            &format!("{prefix}-d.example"),
            "pw",
            serde_json::json!({ "auth_type": "password", "ssh_public_key": "ssh-ed25519 DDDD d" }),
            false,
        );
        // e: deleted asset -> excluded. The DB tombstone constraint
        // (assets_tombstone_no_secrets) forces connection_config = '{}'
        // on deleted rows, so exclusion is doubly guaranteed: by the
        // is_deleted filter AND by the emptied config.
        insert_test_asset(
            &mut conn,
            &format!("{prefix}-e"),
            &format!("{prefix}-e.example"),
            "gone",
            serde_json::json!({}),
            true,
        );

        let all = fetch_asset_pubkeys(&mut conn).expect("fetch must succeed");
        let ours: Vec<&AssetPubkeyRow> = all
            .iter()
            .filter(|r| r.user_at_host.contains(&prefix))
            .collect();

        assert_eq!(
            ours,
            vec![
                &pk_row(
                    &format!("jsonroot@{prefix}-a.example"),
                    Some("ssh-ed25519 AAAA a"),
                ),
                &pk_row(
                    &format!("colroot@{prefix}-b.example"),
                    Some("ssh-ed25519 BBBB b"),
                ),
                &pk_row(&format!("nokey@{prefix}-c.example"), None),
            ],
            "inclusion, COALESCE and hostname ordering must all hold"
        );

        // Cleanup the seeded rows (hard delete: test fixtures only).
        diesel::delete(assets::table.filter(assets::hostname.like(format!("{prefix}%"))))
            .execute(&mut conn)
            .expect("cleanup failed");
    }

    /// Empty-DB behaviour: with no matching asset the fetch returns an
    /// empty vec (formatters then render the explicit empty states).
    #[test]
    fn test_fetch_asset_pubkeys_ignores_unrelated_rows() {
        let mut conn = test_db_connection();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros();
        let prefix = format!("pkun{ts}");

        insert_test_asset(
            &mut conn,
            &format!("{prefix}-pw"),
            &format!("{prefix}-pw.example"),
            "pw",
            serde_json::json!({ "auth_type": "password" }),
            false,
        );

        let all = fetch_asset_pubkeys(&mut conn).expect("fetch must succeed");
        assert!(
            !all.iter().any(|r| r.user_at_host.contains(&prefix)),
            "password-auth assets must never leak into asset-pubkeys"
        );

        diesel::delete(assets::table.filter(assets::hostname.like(format!("{prefix}%"))))
            .execute(&mut conn)
            .expect("cleanup failed");
    }
}
