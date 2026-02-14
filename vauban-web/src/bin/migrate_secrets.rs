// SAFETY: This is a CLI migration tool where expect()/unwrap() on database operations
// is acceptable - failures should terminate the tool. println!/eprintln! are the
// correct output mechanism for CLI tools (not tracing).
#![allow(clippy::expect_used, clippy::unwrap_used)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

/// VAUBAN - Batch secret migration utility.
///
/// Encrypts plaintext secrets in the database using vauban-vault's keyring.
/// Addresses M-1 (TOTP secrets) and C-2 (SSH credentials).
///
/// Usage: cargo run --bin migrate_secrets [-- --dry-run]
///
/// The tool reads the master key, builds keyrings, connects to PostgreSQL,
/// and migrates all plaintext secrets to encrypted form in a single pass.
/// Already-encrypted values (matching `v{N}:...` format) are skipped.
///
/// Options:
///   --dry-run   Show what would be migrated without making changes
///   --help      Show usage information
use anyhow::{Context, Result, anyhow};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::sql_types::{Integer, Jsonb, Text};
use secrecy::ExposeSecret;
use std::io::{self, Write};

use vauban_vault::keyring::{Keyring, MasterKey};
use vauban_web::config::Config;

// ── Schema definitions (only the columns we need) ──

mod schema {
    diesel::table! {
        users (id) {
            id -> Int4,
            username -> Varchar,
            mfa_secret -> Nullable<Varchar>,
            is_deleted -> Bool,
        }
    }

    diesel::table! {
        assets (id) {
            id -> Int4,
            name -> Varchar,
            connection_config -> Jsonb,
        }
    }
}

use schema::users;

/// Default path for the master key file (production).
const DEFAULT_MASTER_KEY_PATH: &str = "/var/vauban/vault/master.key";

/// Default path for the key version file (production).
const DEFAULT_KEY_VERSION_PATH: &str = "/var/vauban/vault/key_version";

/// Fields in connection_config that contain credentials.
const CREDENTIAL_FIELDS: &[&str] = &["password", "private_key", "passphrase"];

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return Ok(());
    }

    let dry_run = args.iter().any(|a| a == "--dry-run");

    println!("VAUBAN Secret Migration Utility");
    println!("===============================\n");

    if dry_run {
        println!("[DRY RUN] No changes will be made to the database.\n");
    }

    // Load configuration
    let config = Config::load().context("Failed to load configuration from config/*.toml")?;

    // Load master key
    let master_key_path = std::env::var("VAUBAN_VAULT_MASTER_KEY_PATH")
        .unwrap_or_else(|_| DEFAULT_MASTER_KEY_PATH.to_string());
    let master_key = MasterKey::from_file(&master_key_path)
        .context(format!("Failed to load master key from '{}'", master_key_path))?;

    // Load key version
    let key_version = load_key_version()?;

    println!(
        "Master key loaded, building keyrings (version {})...",
        key_version
    );

    // Build keyrings
    let mfa_keyring = Keyring::new(master_key.as_bytes(), "mfa", key_version);
    let cred_keyring = Keyring::new(master_key.as_bytes(), "credentials", key_version);
    drop(master_key); // Zeroize master key ASAP

    // Connect to database
    let mut conn = PgConnection::establish(config.database.url.expose_secret())
        .context("Failed to connect to database")?;

    println!("Connected to database.\n");

    // Confirm unless dry-run
    if !dry_run {
        println!("WARNING: This will encrypt all plaintext secrets in the database.");
        println!("         Make sure you have a backup before proceeding.\n");
        let confirm = prompt("Continue? (yes/no): ").context("Failed to read confirmation")?;
        if confirm.trim().to_lowercase() != "yes" {
            println!("Operation cancelled.");
            return Ok(());
        }
        println!();
    }

    // Migrate MFA secrets
    let mfa_count = migrate_mfa_secrets(&mut conn, &mfa_keyring, dry_run)?;

    // Migrate credential secrets
    let cred_count = migrate_credential_secrets(&mut conn, &cred_keyring, dry_run)?;

    println!("\n--- Summary ---");
    println!("MFA secrets migrated:        {}", mfa_count);
    println!("Asset credentials migrated:  {}", cred_count);
    if dry_run {
        println!("\n[DRY RUN] No changes were made. Run without --dry-run to apply.");
    } else {
        println!("\nMigration complete.");
    }

    Ok(())
}

fn print_usage() {
    eprintln!(
        "Usage: cargo run --bin migrate_secrets [-- OPTIONS]

Encrypts all plaintext secrets in the database using vauban-vault's keyring.

Environment variables:
  VAUBAN_VAULT_MASTER_KEY_PATH   Path to master key (default: /var/vauban/vault/master.key)
  VAUBAN_VAULT_KEY_VERSION       Key version override (default: read from key_version file)
  VAUBAN_VAULT_KEY_VERSION_PATH  Path to key version file (default: /var/vauban/vault/key_version)

Options:
  --dry-run   Show what would be migrated without making changes
  -h, --help  Show this help message

Examples:
  cargo run --bin migrate_secrets -- --dry-run
  cargo run --bin migrate_secrets"
    );
}

/// Load the key version from file or environment variable.
fn load_key_version() -> Result<u32> {
    if let Ok(v) = std::env::var("VAUBAN_VAULT_KEY_VERSION") {
        let version: u32 = v
            .parse()
            .context("VAUBAN_VAULT_KEY_VERSION must be a number")?;
        if version == 0 {
            return Err(anyhow!("Key version must be >= 1"));
        }
        return Ok(version);
    }

    let path = std::env::var("VAUBAN_VAULT_KEY_VERSION_PATH")
        .unwrap_or_else(|_| DEFAULT_KEY_VERSION_PATH.to_string());

    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let version: u32 = content
                .trim()
                .parse()
                .context(format!("Invalid key version in '{}'", path))?;
            if version == 0 {
                return Err(anyhow!("Key version must be >= 1"));
            }
            Ok(version)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!(
                "Key version file '{}' not found, defaulting to version 1",
                path
            );
            Ok(1)
        }
        Err(e) => Err(e).context(format!("Failed to read key version from '{}'", path)),
    }
}

/// Check whether a value looks like an encrypted ciphertext from vauban-vault.
///
/// Encrypted values have the format `"v{digit(s)}:{base64}"`.
pub fn is_encrypted(value: &str) -> bool {
    if value.len() < 4 {
        return false;
    }
    if !value.starts_with('v') {
        return false;
    }
    let Some(colon_pos) = value.find(':') else {
        return false;
    };
    if colon_pos < 2 {
        return false;
    }
    value[1..colon_pos].chars().all(|c| c.is_ascii_digit())
}

/// Row from the users table.
#[derive(Queryable, Selectable)]
#[diesel(table_name = users)]
struct UserMfaRow {
    id: i32,
    username: String,
    mfa_secret: Option<String>,
}

/// Row from the assets table.
#[derive(QueryableByName)]
struct AssetRow {
    #[diesel(sql_type = Integer)]
    id: i32,
    #[diesel(sql_type = Text)]
    name: String,
    #[diesel(sql_type = Jsonb)]
    connection_config: serde_json::Value,
}

/// Migrate plaintext MFA secrets to encrypted form.
fn migrate_mfa_secrets(
    conn: &mut PgConnection,
    keyring: &Keyring,
    dry_run: bool,
) -> Result<usize> {
    println!("Scanning users for plaintext MFA secrets...");

    let rows: Vec<UserMfaRow> = users::table
        .filter(users::mfa_secret.is_not_null())
        .filter(users::is_deleted.eq(false))
        .select(UserMfaRow::as_select())
        .load(conn)
        .context("Failed to query users")?;

    let mut migrated = 0;

    for row in &rows {
        if let Some(ref secret) = row.mfa_secret {
            if is_encrypted(secret) {
                continue; // Already encrypted
            }

            match keyring.encrypt(secret.as_bytes()) {
                Ok(encrypted) => {
                    if dry_run {
                        println!(
                            "  [DRY RUN] Would migrate MFA secret for user '{}' (id={})",
                            row.username, row.id
                        );
                    } else {
                        diesel::update(users::table.filter(users::id.eq(row.id)))
                            .set(users::mfa_secret.eq(Some(&encrypted)))
                            .execute(conn)
                            .context(format!(
                                "Failed to update MFA secret for user '{}'",
                                row.username
                            ))?;
                        println!(
                            "  Migrated MFA secret for user '{}' (id={})",
                            row.username, row.id
                        );
                    }
                    migrated += 1;
                }
                Err(e) => {
                    eprintln!(
                        "  WARNING: Failed to encrypt MFA secret for user '{}': {}",
                        row.username, e
                    );
                }
            }
        }
    }

    println!(
        "MFA: {} users scanned, {} migrated",
        rows.len(),
        migrated
    );

    Ok(migrated)
}

/// Migrate plaintext credentials in asset connection_config to encrypted form.
fn migrate_credential_secrets(
    conn: &mut PgConnection,
    keyring: &Keyring,
    dry_run: bool,
) -> Result<usize> {
    println!("\nScanning assets for plaintext credentials...");

    let rows: Vec<AssetRow> = diesel::sql_query(
        "SELECT id, name, connection_config FROM assets WHERE connection_config IS NOT NULL",
    )
    .load(conn)
    .context("Failed to query assets")?;

    let mut migrated = 0;

    for row in &rows {
        let mut config = row.connection_config.clone();
        let mut changed = false;
        let mut fields_encrypted = Vec::new();

        if let Some(obj) = config.as_object_mut() {
            for field in CREDENTIAL_FIELDS {
                if let Some(serde_json::Value::String(val)) = obj.get(*field)
                    && !val.is_empty()
                    && !is_encrypted(val)
                {
                    match keyring.encrypt(val.as_bytes()) {
                        Ok(encrypted) => {
                            obj.insert(
                                field.to_string(),
                                serde_json::Value::String(encrypted),
                            );
                            changed = true;
                            fields_encrypted.push(*field);
                        }
                        Err(e) => {
                            eprintln!(
                                "  WARNING: Failed to encrypt '{}' for asset '{}' (id={}): {}",
                                field, row.name, row.id, e
                            );
                        }
                    }
                }
            }
        }

        if changed {
            if dry_run {
                println!(
                    "  [DRY RUN] Would encrypt [{}] for asset '{}' (id={})",
                    fields_encrypted.join(", "),
                    row.name,
                    row.id
                );
            } else {
                let config_str = serde_json::to_string(&config)
                    .context("Failed to serialize connection_config")?;
                diesel::sql_query(
                    "UPDATE assets SET connection_config = $1::jsonb WHERE id = $2",
                )
                .bind::<Text, _>(&config_str)
                .bind::<Integer, _>(row.id)
                .execute(conn)
                .context(format!(
                    "Failed to update connection_config for asset '{}'",
                    row.name
                ))?;
                println!(
                    "  Encrypted [{}] for asset '{}' (id={})",
                    fields_encrypted.join(", "),
                    row.name,
                    row.id
                );
            }
            migrated += 1;
        }
    }

    println!(
        "Credentials: {} assets scanned, {} migrated",
        rows.len(),
        migrated
    );

    Ok(migrated)
}

/// Prompt user for input (visible).
fn prompt(message: &str) -> io::Result<String> {
    print!("{}", message);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

// =============================================================================
// Validation Functions (for testing)
// =============================================================================

/// Validate key version.
pub fn validate_key_version(version: u32) -> Result<(), String> {
    if version == 0 {
        return Err("Key version must be >= 1".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== is_encrypted Tests ====================

    #[test]
    fn test_is_encrypted_valid_formats() {
        assert!(is_encrypted("v1:SGVsbG8="));
        assert!(is_encrypted("v12:AAAA"));
        assert!(is_encrypted("v999:data"));
    }

    #[test]
    fn test_is_encrypted_invalid_formats() {
        assert!(!is_encrypted("plaintext"));
        assert!(!is_encrypted("JBSWY3DPEHPK3PXP")); // Base32 TOTP secret
        assert!(!is_encrypted(""));
        assert!(!is_encrypted("v:data")); // no version number
        assert!(!is_encrypted("v1data")); // no colon
        assert!(!is_encrypted("va:data")); // non-digit version
        assert!(!is_encrypted("abc")); // too short
    }

    #[test]
    fn test_is_encrypted_distinguishes_real_ciphertext() {
        let mk = [0x42u8; 32];
        let kr = Keyring::new(&mk, "mfa", 1);

        let plaintext = "JBSWY3DPEHPK3PXP";
        assert!(!is_encrypted(plaintext));

        let encrypted = kr.encrypt(plaintext.as_bytes()).unwrap();
        assert!(is_encrypted(&encrypted));
        assert!(encrypted.starts_with("v1:"));
    }

    // ==================== Migration Logic Tests ====================

    #[test]
    fn test_credential_fields_are_correct() {
        assert_eq!(
            CREDENTIAL_FIELDS,
            &["password", "private_key", "passphrase"]
        );
    }

    #[test]
    fn test_encrypt_connection_config_fields() {
        let mk = [0x42u8; 32];
        let kr = Keyring::new(&mk, "credentials", 1);

        let mut config = serde_json::json!({
            "host": "192.168.1.1",
            "port": 22,
            "username": "admin",
            "auth_type": "password",
            "password": "my-secret-password"
        });

        // Simulate what migration does
        let mut changed = false;
        if let Some(obj) = config.as_object_mut() {
            for field in CREDENTIAL_FIELDS {
                if let Some(serde_json::Value::String(val)) = obj.get(*field)
                    && !val.is_empty()
                    && !is_encrypted(val)
                {
                    let encrypted = kr.encrypt(val.as_bytes()).unwrap();
                    obj.insert(field.to_string(), serde_json::Value::String(encrypted));
                    changed = true;
                }
            }
        }

        assert!(changed);

        // Verify password is encrypted
        let pw = config["password"].as_str().unwrap();
        assert!(is_encrypted(pw), "password should be encrypted: {}", pw);

        // Verify non-credential fields are untouched
        assert_eq!(config["host"], "192.168.1.1");
        assert_eq!(config["port"], 22);
        assert_eq!(config["username"], "admin");

        // Verify roundtrip
        let decrypted = kr.decrypt(pw).unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), "my-secret-password");
    }

    #[test]
    fn test_encrypt_connection_config_skips_encrypted() {
        let mk = [0x42u8; 32];
        let kr = Keyring::new(&mk, "credentials", 1);

        let encrypted_pw = kr.encrypt(b"already-encrypted").unwrap();
        let mut config = serde_json::json!({
            "password": encrypted_pw,
            "username": "admin"
        });

        let mut changed = false;
        if let Some(obj) = config.as_object_mut() {
            for field in CREDENTIAL_FIELDS {
                if let Some(serde_json::Value::String(val)) = obj.get(*field)
                    && !val.is_empty()
                    && !is_encrypted(val)
                {
                    let encrypted = kr.encrypt(val.as_bytes()).unwrap();
                    obj.insert(field.to_string(), serde_json::Value::String(encrypted));
                    changed = true;
                }
            }
        }

        assert!(!changed, "Should not re-encrypt already encrypted values");
    }

    #[test]
    fn test_encrypt_connection_config_multiple_fields() {
        let mk = [0x42u8; 32];
        let kr = Keyring::new(&mk, "credentials", 1);

        let mut config = serde_json::json!({
            "auth_type": "key",
            "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nkey-data\n-----END OPENSSH PRIVATE KEY-----",
            "passphrase": "my-passphrase"
        });

        let mut changed = false;
        if let Some(obj) = config.as_object_mut() {
            for field in CREDENTIAL_FIELDS {
                if let Some(serde_json::Value::String(val)) = obj.get(*field)
                    && !val.is_empty()
                    && !is_encrypted(val)
                {
                    let encrypted = kr.encrypt(val.as_bytes()).unwrap();
                    obj.insert(field.to_string(), serde_json::Value::String(encrypted));
                    changed = true;
                }
            }
        }

        assert!(changed);
        assert!(is_encrypted(config["private_key"].as_str().unwrap()));
        assert!(is_encrypted(config["passphrase"].as_str().unwrap()));

        // Decrypt and verify
        let pk = kr
            .decrypt(config["private_key"].as_str().unwrap())
            .unwrap();
        assert!(String::from_utf8(pk)
            .unwrap()
            .contains("OPENSSH PRIVATE KEY"));
    }

    #[test]
    fn test_encrypt_connection_config_empty_fields_skipped() {
        let mk = [0x42u8; 32];
        let kr = Keyring::new(&mk, "credentials", 1);

        let mut config = serde_json::json!({
            "password": "",
            "private_key": null,
            "username": "admin"
        });

        let mut changed = false;
        if let Some(obj) = config.as_object_mut() {
            for field in CREDENTIAL_FIELDS {
                if let Some(serde_json::Value::String(val)) = obj.get(*field)
                    && !val.is_empty()
                    && !is_encrypted(val)
                {
                    let encrypted = kr.encrypt(val.as_bytes()).unwrap();
                    obj.insert(field.to_string(), serde_json::Value::String(encrypted));
                    changed = true;
                }
            }
        }

        assert!(!changed, "Empty and null fields should not be encrypted");
    }

    #[test]
    fn test_mfa_secret_roundtrip() {
        let mk = [0x42u8; 32];
        let kr = Keyring::new(&mk, "mfa", 1);

        let secret = "JBSWY3DPEHPK3PXP";
        assert!(!is_encrypted(secret));

        let encrypted = kr.encrypt(secret.as_bytes()).unwrap();
        assert!(is_encrypted(&encrypted));

        let decrypted = kr.decrypt(&encrypted).unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), secret);
    }

    // ==================== Validation Tests ====================

    #[test]
    fn test_validate_key_version_valid() {
        assert!(validate_key_version(1).is_ok());
        assert!(validate_key_version(100).is_ok());
    }

    #[test]
    fn test_validate_key_version_zero() {
        assert!(validate_key_version(0).is_err());
    }
}
