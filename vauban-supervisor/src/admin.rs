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

use crate::AdminSubcommand;
use crate::config::SupervisorConfig;
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
    }
}

fn load_db_connection() -> Result<PgConnection> {
    let config = SupervisorConfig::load_auto().context("Failed to load configuration")?;
    PgConnection::establish(&config.database.url).context("Failed to connect to database")
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

    let email = loop {
        let input = prompt("Email: ")?;
        if let Err(e) = validate_email(&input) {
            eprintln!("{e}");
            continue;
        }
        let exists: bool = diesel::select(exists(
            users::table.filter(users::email.eq(&input).and(users::is_deleted.eq(false))),
        ))
        .get_result(&mut conn)
        .unwrap_or(false);

        if exists {
            eprintln!("Email '{input}' already exists.");
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
    if value.len() < 4 || !value.starts_with('v') {
        return false;
    }
    let Some(colon_pos) = value.find(':') else {
        return false;
    };
    colon_pos >= 2 && value[1..colon_pos].chars().all(|c| c.is_ascii_digit())
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
}
