// SAFETY: This is an interactive CLI tool where expect()/unwrap() on I/O is acceptable
// for user prompts - failures should terminate the tool. println!/eprintln! are the
// correct output mechanism for CLI tools (not tracing).
#![allow(clippy::expect_used, clippy::unwrap_used)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

/// VAUBAN - Reset user password utility.
///
/// Interactive CLI tool to reset a user's password.
/// No secrets are stored in code - all input is provided interactively.
use anyhow::{Context, Result, anyhow};
use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version, password_hash::SaltString};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::sql_types::Text;
use rand::rngs::OsRng;
use secrecy::ExposeSecret;
use std::io::{self, Write};
use vauban_web::config::Config;

fn main() -> Result<()> {
    println!("🔐 VAUBAN Password Reset Utility");
    println!("================================\n");

    // Load configuration from TOML files
    let config = Config::load().context("Failed to load configuration from config/*.toml")?;

    let mut conn = PgConnection::establish(config.database.url.expose_secret())
        .context("Failed to connect to database")?;

    // Prompt for username
    let username = prompt("Enter username: ").context("Failed to read username")?;

    if username.trim().is_empty() {
        return Err(anyhow!("Username cannot be empty"));
    }

    // Check if user exists
    let user_exists: bool = diesel::sql_query(
        "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1 AND is_deleted = false) as exists",
    )
    .bind::<Text, _>(username.trim())
    .get_result::<ExistsResult>(&mut conn)
    .map(|r| r.exists)
    .unwrap_or(false);

    if !user_exists {
        return Err(anyhow!("User '{}' not found", username.trim()));
    }

    // Prompt for new password
    let password = prompt_password("Enter new password (min 12 chars): ")
        .context("Failed to read password")?;

    if password.len() < 12 {
        return Err(anyhow!("Password must be at least 12 characters"));
    }

    // Confirm password
    let password_confirm = prompt_password("Confirm new password: ")
        .context("Failed to read password confirmation")?;

    if password != password_confirm {
        return Err(anyhow!("Passwords do not match"));
    }

    // Hash the password
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(
        config.security.argon2.memory_size_kb,
        config.security.argon2.iterations,
        config.security.argon2.parallelism,
        Some(32),
    )
    .map_err(|e| anyhow!("Failed to create Argon2 parameters: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("Failed to hash password: {}", e))?
        .to_string();

    // Update user password
    let rows_affected = diesel::sql_query(
        "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE username = $2 AND is_deleted = false"
    )
    .bind::<Text, _>(&hash)
    .bind::<Text, _>(username.trim())
    .execute(&mut conn)
    .context("Failed to update password")?;

    if rows_affected > 0 {
        println!(
            "\n✅ Password for '{}' has been updated successfully",
            username.trim()
        );
    } else {
        return Err(anyhow!("Failed to update password"));
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

/// Prompt user for password (hidden input on Unix).
fn prompt_password(message: &str) -> io::Result<String> {
    print!("{}", message);
    io::stdout().flush()?;

    // Try to use rpassword-like behavior by disabling echo
    #[cfg(unix)]
    {
        use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};

        let stdin = io::stdin();

        // Get current terminal attributes
        if let Ok(original) = tcgetattr(&stdin) {
            let mut new_termios = original.clone();
            new_termios.local_flags.remove(LocalFlags::ECHO);

            // Disable echo
            if tcsetattr(&stdin, SetArg::TCSANOW, &new_termios).is_ok() {
                let mut input = String::new();
                let result = stdin.read_line(&mut input);

                // Restore terminal (always, even on error)
                let _ = tcsetattr(&stdin, SetArg::TCSANOW, &original);
                println!(); // New line after hidden input

                result?;
                return Ok(input.trim().to_string());
            }
        }
    }

    // Fallback: visible input
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

#[derive(QueryableByName)]
struct ExistsResult {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    exists: bool,
}

// ==================== Validation Functions ====================

/// Validate that username is not empty.
pub fn validate_username_not_empty(username: &str) -> Result<(), String> {
    if username.trim().is_empty() {
        return Err("Username cannot be empty".to_string());
    }
    Ok(())
}

/// Validate password strength.
pub fn validate_password_strength(password: &str) -> Result<(), String> {
    if password.len() < 12 {
        return Err("Password must be at least 12 characters".to_string());
    }
    Ok(())
}

/// Validate password confirmation matches.
pub fn validate_password_confirmation(password: &str, confirmation: &str) -> Result<(), String> {
    if password != confirmation {
        return Err("Passwords do not match".to_string());
    }
    Ok(())
}

/// Escape SQL string to prevent injection.
pub fn escape_sql_string(input: &str) -> String {
    input.replace('\'', "''")
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

    // ==================== Password Strength Tests ====================

    #[test]
    fn test_validate_password_strength_valid() {
        assert!(validate_password_strength("securepassword123").is_ok());
        assert!(validate_password_strength("123456789012").is_ok());
    }

    #[test]
    fn test_validate_password_strength_too_short() {
        assert!(validate_password_strength("short").is_err());
        assert!(validate_password_strength("12345678901").is_err());
    }

    #[test]
    fn test_validate_password_strength_minimum() {
        assert!(validate_password_strength("123456789012").is_ok()); // 12 chars
    }

    // ==================== Password Confirmation Tests ====================

    #[test]
    fn test_validate_password_confirmation_match() {
        assert!(validate_password_confirmation("password123!", "password123!").is_ok());
    }

    #[test]
    fn test_validate_password_confirmation_mismatch() {
        assert!(validate_password_confirmation("password123!", "different").is_err());
    }

    #[test]
    fn test_validate_password_confirmation_case_sensitive() {
        assert!(validate_password_confirmation("Password", "password").is_err());
    }

    // ==================== SQL Escape Tests ====================

    #[test]
    fn test_escape_sql_string_no_quotes() {
        assert_eq!(escape_sql_string("hello"), "hello");
    }

    #[test]
    fn test_escape_sql_string_single_quote() {
        assert_eq!(escape_sql_string("O'Brien"), "O''Brien");
    }

    #[test]
    fn test_escape_sql_string_multiple_quotes() {
        assert_eq!(escape_sql_string("It's John's"), "It''s John''s");
    }

    #[test]
    fn test_escape_sql_string_empty() {
        assert_eq!(escape_sql_string(""), "");
    }

    // ==================== Username Validation Edge Cases ====================

    #[test]
    fn test_validate_username_not_empty_spaces_only() {
        assert!(validate_username_not_empty("     ").is_err());
    }

    #[test]
    fn test_validate_username_not_empty_mixed_whitespace() {
        assert!(validate_username_not_empty(" \t \n ").is_err());
    }

    #[test]
    fn test_validate_username_not_empty_valid_with_spaces() {
        // Username with leading/trailing spaces should be trimmed
        assert!(validate_username_not_empty("  admin  ").is_ok());
    }

    // ==================== Password Strength Edge Cases ====================

    #[test]
    fn test_validate_password_strength_unicode() {
        // Unicode counts as characters
        assert!(validate_password_strength("密码password").is_ok());
    }

    #[test]
    fn test_validate_password_strength_exactly_12() {
        assert!(validate_password_strength("abcdefghijkl").is_ok());
    }

    #[test]
    fn test_validate_password_strength_empty() {
        assert!(validate_password_strength("").is_err());
    }

    // ==================== Password Confirmation Edge Cases ====================

    #[test]
    fn test_validate_password_confirmation_empty_both() {
        assert!(validate_password_confirmation("", "").is_ok());
    }

    #[test]
    fn test_validate_password_confirmation_whitespace_difference() {
        assert!(validate_password_confirmation("password", "password ").is_err());
    }

    #[test]
    fn test_validate_password_confirmation_unicode() {
        assert!(validate_password_confirmation("пароль123", "пароль123").is_ok());
    }

    // ==================== SQL Escape Edge Cases ====================

    #[test]
    fn test_escape_sql_string_only_quotes() {
        assert_eq!(escape_sql_string("'''"), "''''''");
    }

    #[test]
    fn test_escape_sql_string_unicode() {
        assert_eq!(escape_sql_string("用户'名"), "用户''名");
    }

    #[test]
    fn test_escape_sql_string_special_chars() {
        // Only single quotes need escaping for SQL strings
        let input = "test@#$%^&*()";
        assert_eq!(escape_sql_string(input), input);
    }

    #[test]
    fn test_escape_sql_string_double_quotes() {
        // Double quotes don't need escaping in single-quoted strings
        let input = r#"test"value"#;
        assert_eq!(escape_sql_string(input), input);
    }

    #[test]
    fn test_escape_sql_string_backslash() {
        // Backslashes don't need escaping in standard SQL
        let input = r"test\path";
        assert_eq!(escape_sql_string(input), input);
    }

    #[test]
    fn test_escape_sql_string_long_input() {
        let long_input = "a'b".repeat(1000);
        let escaped = escape_sql_string(&long_input);
        assert!(escaped.len() > long_input.len());
    }
}
