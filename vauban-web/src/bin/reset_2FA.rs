/// VAUBAN - Reset user 2FA (MFA) utility.
///
/// Interactive CLI tool to disable two-factor authentication for a user.
/// This is the only way to disable MFA - users cannot disable it themselves.
///
/// Usage: cargo run --bin reset_2FA
///
/// The tool will prompt for the username and confirm before disabling MFA.
use anyhow::{anyhow, Context, Result};
use diesel::prelude::*;
use diesel::pg::PgConnection;
use secrecy::ExposeSecret;
use std::io::{self, Write};

use vauban_web::config::Config;

// Define the users table schema for this binary
mod schema {
    diesel::table! {
        users (id) {
            id -> Int4,
            username -> Varchar,
            mfa_enabled -> Bool,
            mfa_secret -> Nullable<Varchar>,
            is_deleted -> Bool,
            updated_at -> Timestamptz,
        }
    }
}

use schema::users;

fn main() -> Result<()> {
    println!("🔐 VAUBAN 2FA Reset Utility");
    println!("===========================\n");
    println!("⚠️  WARNING: This tool will disable two-factor authentication for a user.");
    println!("⚠️  The user will need to set up MFA again on their next login.\n");

    // Load configuration from TOML files
    let config = Config::load().context("Failed to load configuration from config/*.toml")?;

    let mut conn = PgConnection::establish(config.database.url.expose_secret())
        .context("Failed to connect to database")?;

    // Prompt for username
    let username_input = prompt("Enter username: ").context("Failed to read username")?;
    let username_input = username_input.trim();

    if username_input.is_empty() {
        return Err(anyhow!("Username cannot be empty"));
    }

    // Check if user exists and get MFA status
    let user_result: Result<(i32, bool), _> = users::table
        .filter(users::username.eq(username_input))
        .filter(users::is_deleted.eq(false))
        .select((users::id, users::mfa_enabled))
        .first(&mut conn);

    let (user_id, mfa_enabled) = match user_result {
        Ok(data) => data,
        Err(diesel::result::Error::NotFound) => {
            return Err(anyhow!("User '{}' not found", username_input));
        }
        Err(e) => {
            return Err(anyhow!("Database error: {}", e));
        }
    };

    if !mfa_enabled {
        println!("ℹ️  User '{}' does not have MFA enabled.", username_input);
        println!("   No action needed.");
        return Ok(());
    }

    // Confirm action
    println!("\n⚠️  User '{}' has MFA enabled.", username_input);
    let confirm = prompt("Are you sure you want to disable MFA? (yes/no): ")
        .context("Failed to read confirmation")?;

    if confirm.trim().to_lowercase() != "yes" {
        println!("❌ Operation cancelled.");
        return Ok(());
    }

    // Disable MFA using Diesel DSL
    let rows_affected = diesel::update(users::table.filter(users::id.eq(user_id)))
        .set((
            users::mfa_enabled.eq(false),
            users::mfa_secret.eq(None::<String>),
            users::updated_at.eq(chrono::Utc::now()),
        ))
        .execute(&mut conn)
        .context("Failed to update user")?;

    if rows_affected > 0 {
        println!(
            "\n✅ Two-factor authentication has been disabled for '{}'",
            username_input
        );
        println!("   The user will need to set up MFA again on their next login.");
    } else {
        return Err(anyhow!("Failed to disable MFA"));
    }

    Ok(())
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

/// Validate that username is not empty.
pub fn validate_username_not_empty(username: &str) -> Result<(), String> {
    if username.trim().is_empty() {
        return Err("Username cannot be empty".to_string());
    }
    Ok(())
}

/// Validate confirmation input.
pub fn validate_confirmation(input: &str) -> bool {
    input.trim().to_lowercase() == "yes"
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Username Validation Tests ====================

    #[test]
    fn test_validate_username_not_empty_valid() {
        assert!(validate_username_not_empty("admin").is_ok());
        assert!(validate_username_not_empty("user123").is_ok());
    }

    #[test]
    fn test_validate_username_not_empty_empty() {
        assert!(validate_username_not_empty("").is_err());
        assert!(validate_username_not_empty("   ").is_err());
    }

    #[test]
    fn test_validate_username_not_empty_whitespace() {
        assert!(validate_username_not_empty("\t").is_err());
        assert!(validate_username_not_empty("\n").is_err());
    }

    #[test]
    fn test_validate_username_not_empty_valid_with_spaces() {
        // Username with leading/trailing spaces should be trimmed
        assert!(validate_username_not_empty("  admin  ").is_ok());
    }

    // ==================== Confirmation Validation Tests ====================

    #[test]
    fn test_validate_confirmation_yes() {
        assert!(validate_confirmation("yes"));
        assert!(validate_confirmation("YES"));
        assert!(validate_confirmation("Yes"));
        assert!(validate_confirmation("  yes  "));
    }

    #[test]
    fn test_validate_confirmation_no() {
        assert!(!validate_confirmation("no"));
        assert!(!validate_confirmation("NO"));
        assert!(!validate_confirmation(""));
        assert!(!validate_confirmation("y"));
        assert!(!validate_confirmation("oui"));
    }

    #[test]
    fn test_validate_confirmation_mixed_case() {
        assert!(validate_confirmation("yEs"));
        assert!(validate_confirmation("YeS"));
    }
}
