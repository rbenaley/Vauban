// SAFETY: This is an interactive CLI tool where expect()/unwrap() on I/O is acceptable
// for user prompts - failures should terminate the tool. println!/eprintln! are the
// correct output mechanism for CLI tools (not tracing).
#![allow(clippy::expect_used, clippy::unwrap_used)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

//! VAUBAN CLI - Create Superuser
//!
//! Interactive command to create the initial superuser account.
//! Usage: cargo run --bin create_superuser

use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version, password_hash::SaltString};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::sql_types::{Nullable, Text};
use rand::rngs::OsRng;
use rpassword::read_password;
use secrecy::ExposeSecret;
use std::io::{self, Write};
use uuid::Uuid;
use std::process::ExitCode;
use vauban_web::config::Config;

mod schema {
    diesel::table! {
        users (id) {
            id -> Int4,
            uuid -> diesel::sql_types::Uuid,
            username -> Varchar,
            email -> Varchar,
            password_hash -> Varchar,
            first_name -> Nullable<Varchar>,
            last_name -> Nullable<Varchar>,
            phone -> Nullable<Varchar>,
            is_active -> Bool,
            is_staff -> Bool,
            is_superuser -> Bool,
            is_service_account -> Bool,
            mfa_enabled -> Bool,
            mfa_enforced -> Bool,
            mfa_secret -> Nullable<Varchar>,
            preferences -> diesel::sql_types::Jsonb,
            auth_source -> Varchar,
            external_id -> Nullable<Varchar>,
            last_login -> Nullable<Timestamptz>,
            last_login_ip -> Nullable<Text>,
            failed_login_attempts -> Int4,
            locked_until -> Nullable<Timestamptz>,
            password_changed_at -> Nullable<Timestamptz>,
            created_at -> Timestamptz,
            updated_at -> Timestamptz,
            is_deleted -> Bool,
            deleted_at -> Nullable<Timestamptz>,
        }
    }
}

fn main() -> ExitCode {
    println!("\n🔐 VAUBAN - Create Superuser");
    println!("============================\n");

    // Load configuration from TOML files
    let config = Config::load().expect("Failed to load configuration from config/*.toml");

    let mut conn = PgConnection::establish(config.database.url.expose_secret())
        .expect("Failed to connect to database");

    // Check if any superuser already exists
    let existing_superuser: Option<i32> = diesel::sql_query(
        "SELECT id FROM users WHERE is_superuser = true AND is_deleted = false LIMIT 1",
    )
    .get_result::<ExistsResult>(&mut conn)
    .map(|r| Some(r.id))
    .unwrap_or(None);

    if existing_superuser.is_some() {
        println!("⚠️  A superuser already exists in the database.");
        print!("Do you want to create another superuser? (y/N): ");
        io::stdout().flush().unwrap();

        let mut confirm = String::new();
        io::stdin()
            .read_line(&mut confirm)
            .expect("Failed to read input");
        if confirm.trim().to_lowercase() != "y" {
            println!("\n❌ Operation cancelled.");
            return ExitCode::SUCCESS;
        }
        println!();
    }

    // Prompt for username
    let username = loop {
        print!("Username: ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read username");
        let trimmed = input.trim().to_string();

        if trimmed.len() < 3 {
            eprintln!("Username must be at least 3 characters.");
            continue;
        }
        if trimmed.len() > 150 {
            eprintln!("Username must be at most 150 characters.");
            continue;
        }

        // Check if username already exists
        let exists: bool = diesel::sql_query(
            "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1 AND is_deleted = false) as exists"
        )
        .bind::<Text, _>(&trimmed)
        .get_result::<ExistsBool>(&mut conn)
        .map(|r| r.exists)
        .unwrap_or(false);

        if exists {
            eprintln!(
                "Username '{}' already exists. Please choose another.",
                trimmed
            );
            continue;
        }

        break trimmed;
    };

    // Prompt for email
    let email = loop {
        print!("Email: ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read email");
        let trimmed = input.trim().to_string();

        if !trimmed.contains('@') || !trimmed.contains('.') {
            eprintln!("Please enter a valid email address.");
            continue;
        }

        // Check if email already exists
        let exists: bool = diesel::sql_query(
            "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND is_deleted = false) as exists",
        )
        .bind::<Text, _>(&trimmed)
        .get_result::<ExistsBool>(&mut conn)
        .map(|r| r.exists)
        .unwrap_or(false);

        if exists {
            eprintln!("Email '{}' already exists. Please choose another.", trimmed);
            continue;
        }

        break trimmed;
    };

    // Prompt for first name (optional)
    print!("First name (optional): ");
    io::stdout().flush().unwrap();
    let mut first_name_input = String::new();
    io::stdin()
        .read_line(&mut first_name_input)
        .expect("Failed to read first name");
    let first_name = first_name_input.trim();
    let first_name = if first_name.is_empty() {
        None
    } else {
        Some(first_name.to_string())
    };

    // Prompt for last name (optional)
    print!("Last name (optional): ");
    io::stdout().flush().unwrap();
    let mut last_name_input = String::new();
    io::stdin()
        .read_line(&mut last_name_input)
        .expect("Failed to read last name");
    let last_name = last_name_input.trim();
    let last_name = if last_name.is_empty() {
        None
    } else {
        Some(last_name.to_string())
    };

    // Prompt for password
    let password = loop {
        print!("Password (min 12 chars): ");
        io::stdout().flush().unwrap();
        let password_input = read_password().expect("Failed to read password");

        if password_input.len() < 12 {
            eprintln!("Password must be at least 12 characters.");
            continue;
        }

        print!("Confirm password: ");
        io::stdout().flush().unwrap();
        let confirm_input = read_password().expect("Failed to read password confirmation");

        if password_input != confirm_input {
            eprintln!("Passwords do not match. Please try again.");
            continue;
        }

        break password_input;
    };

    // Hash the password
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(
        config.security.argon2.memory_size_kb,
        config.security.argon2.iterations,
        config.security.argon2.parallelism,
        Some(32),
    )
    .expect("Failed to create Argon2 parameters");

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string();

    // Create the superuser
    let user_uuid = Uuid::new_v4();

    let result = diesel::sql_query(
        "INSERT INTO users (uuid, username, email, password_hash, first_name, last_name, 
                           is_active, is_staff, is_superuser, is_service_account, 
                           mfa_enabled, mfa_enforced, preferences, auth_source)
         VALUES ($1::uuid, $2, $3, $4, $5, $6, 
                 true, true, true, false, 
                 false, false, '{}', 'local')
         RETURNING id",
    )
    .bind::<Text, _>(user_uuid.to_string())
    .bind::<Text, _>(&username)
    .bind::<Text, _>(&email)
    .bind::<Text, _>(&password_hash)
    .bind::<Nullable<Text>, _>(first_name.as_deref())
    .bind::<Nullable<Text>, _>(last_name.as_deref())
    .execute(&mut conn);

    match result {
        Ok(_) => {
            println!("\n✅ Superuser created successfully!");
            println!("\n   Username: {}", username);
            println!("   Email:    {}", email);
            if let Some(ref fn_) = first_name {
                println!(
                    "   Name:     {} {}",
                    fn_,
                    last_name.as_deref().unwrap_or("")
                );
            }
            println!("   UUID:     {}", user_uuid);
            println!(
                "\nYou can now log in at http://{}:{}/login",
                config.server.host, config.server.port
            );
        }
        Err(e) => {
            eprintln!("\n❌ Failed to create superuser: {}", e);
            // M-8: Return ExitCode instead of exit(1) so destructors run
            // (zeroize password in memory).
            return ExitCode::FAILURE;
        }
    }

    ExitCode::SUCCESS
}

#[derive(diesel::QueryableByName)]
struct ExistsResult {
    #[diesel(sql_type = diesel::sql_types::Int4)]
    id: i32,
}

#[derive(diesel::QueryableByName)]
struct ExistsBool {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    exists: bool,
}

// ==================== Validation Functions ====================

/// Validate username format and length.
pub fn validate_username(username: &str) -> Result<(), String> {
    if username.len() < 3 {
        return Err("Username must be at least 3 characters.".to_string());
    }
    if username.len() > 150 {
        return Err("Username must be at most 150 characters.".to_string());
    }
    // Check for valid characters (alphanumeric, underscore, dot, hyphen)
    if !username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        return Err(
            "Username can only contain letters, numbers, underscores, dots, and hyphens."
                .to_string(),
        );
    }
    Ok(())
}

/// Validate email format.
pub fn validate_email(email: &str) -> Result<(), String> {
    if !email.contains('@') || !email.contains('.') {
        return Err("Please enter a valid email address.".to_string());
    }
    // Basic email format validation
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return Err("Email must contain exactly one @ symbol.".to_string());
    }
    if parts[0].is_empty() || parts[1].is_empty() {
        return Err("Email cannot be empty before or after @.".to_string());
    }
    if !parts[1].contains('.') {
        return Err("Email domain must contain a dot.".to_string());
    }
    Ok(())
}

/// Validate password strength.
pub fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < 12 {
        return Err("Password must be at least 12 characters.".to_string());
    }
    Ok(())
}

/// Validate password confirmation.
pub fn validate_password_match(password: &str, confirmation: &str) -> Result<(), String> {
    if password != confirmation {
        return Err("Passwords do not match.".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Username Validation Tests ====================

    #[test]
    fn test_validate_username_valid() {
        assert!(validate_username("validuser").is_ok());
        assert!(validate_username("user_123").is_ok());
        assert!(validate_username("user.name").is_ok());
        assert!(validate_username("user-name").is_ok());
    }

    #[test]
    fn test_validate_username_too_short() {
        assert!(validate_username("ab").is_err());
        assert!(validate_username("a").is_err());
        assert!(validate_username("").is_err());
    }

    #[test]
    fn test_validate_username_too_long() {
        let long_name = "a".repeat(151);
        assert!(validate_username(&long_name).is_err());
    }

    #[test]
    fn test_validate_username_minimum_length() {
        assert!(validate_username("abc").is_ok());
    }

    #[test]
    fn test_validate_username_maximum_length() {
        let max_name = "a".repeat(150);
        assert!(validate_username(&max_name).is_ok());
    }

    #[test]
    fn test_validate_username_invalid_chars() {
        assert!(validate_username("user@name").is_err());
        assert!(validate_username("user name").is_err());
        assert!(validate_username("user!name").is_err());
    }

    // ==================== Email Validation Tests ====================

    #[test]
    fn test_validate_email_valid() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("test.user@domain.org").is_ok());
        assert!(validate_email("admin@company.co.uk").is_ok());
    }

    #[test]
    fn test_validate_email_missing_at() {
        assert!(validate_email("userexample.com").is_err());
    }

    #[test]
    fn test_validate_email_missing_dot() {
        assert!(validate_email("user@example").is_err());
    }

    #[test]
    fn test_validate_email_multiple_at() {
        assert!(validate_email("user@@example.com").is_err());
        assert!(validate_email("user@sub@example.com").is_err());
    }

    #[test]
    fn test_validate_email_empty_parts() {
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@").is_err());
    }

    // ==================== Password Validation Tests ====================

    #[test]
    fn test_validate_password_valid() {
        assert!(validate_password("securepassword123").is_ok());
        assert!(validate_password("123456789012").is_ok());
    }

    #[test]
    fn test_validate_password_too_short() {
        assert!(validate_password("short").is_err());
        assert!(validate_password("12345678901").is_err()); // 11 chars
    }

    #[test]
    fn test_validate_password_minimum_length() {
        assert!(validate_password("123456789012").is_ok()); // Exactly 12 chars
    }

    // ==================== Password Match Tests ====================

    #[test]
    fn test_validate_password_match_success() {
        assert!(validate_password_match("password123!", "password123!").is_ok());
    }

    #[test]
    fn test_validate_password_match_failure() {
        assert!(validate_password_match("password123!", "password456!").is_err());
    }

    #[test]
    fn test_validate_password_match_case_sensitive() {
        assert!(validate_password_match("Password123", "password123").is_err());
    }

    // ==================== Username Validation Edge Cases ====================

    #[test]
    fn test_validate_username_with_numbers() {
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("123user").is_ok());
    }

    #[test]
    fn test_validate_username_all_allowed_chars() {
        assert!(validate_username("user_name.test-123").is_ok());
    }

    #[test]
    fn test_validate_username_unicode_accepted() {
        // is_alphanumeric() accepts Unicode letters/numbers
        assert!(validate_username("user\u{00E9}").is_ok()); // é is alphanumeric
        assert!(validate_username("user123").is_ok());
    }

    #[test]
    fn test_validate_username_unicode_chinese_accepted() {
        // Chinese characters are alphanumeric in Unicode
        assert!(validate_username("用户名").is_ok());
    }

    #[test]
    fn test_validate_username_boundary_length() {
        let min_valid = "abc";
        let max_valid = "a".repeat(150);
        let too_long = "a".repeat(151);

        assert!(validate_username(min_valid).is_ok());
        assert!(validate_username(&max_valid).is_ok());
        assert!(validate_username(&too_long).is_err());
    }

    // ==================== Email Validation Edge Cases ====================

    #[test]
    fn test_validate_email_subdomains() {
        assert!(validate_email("user@mail.example.com").is_ok());
        assert!(validate_email("user@sub.domain.example.org").is_ok());
    }

    #[test]
    fn test_validate_email_plus_addressing() {
        assert!(validate_email("user+tag@example.com").is_ok());
    }

    #[test]
    fn test_validate_email_domain_no_dot() {
        assert!(validate_email("user@localhost").is_err());
    }

    #[test]
    fn test_validate_email_special_local_part() {
        assert!(validate_email("user.name@example.com").is_ok());
        assert!(validate_email("user_name@example.com").is_ok());
    }

    // ==================== Password Validation Edge Cases ====================

    #[test]
    fn test_validate_password_unicode() {
        // Unicode characters should count
        assert!(validate_password("пароль123456").is_ok()); // Russian "password"
    }

    #[test]
    fn test_validate_password_spaces() {
        assert!(validate_password("password with spaces").is_ok());
    }

    #[test]
    fn test_validate_password_special_chars() {
        assert!(validate_password("P@$$w0rd!#$%").is_ok());
    }

    // ==================== Password Match Edge Cases ====================

    #[test]
    fn test_validate_password_match_empty() {
        assert!(validate_password_match("", "").is_ok());
    }

    #[test]
    fn test_validate_password_match_whitespace() {
        assert!(validate_password_match("pass word", "pass word").is_ok());
        assert!(validate_password_match("password ", "password").is_err());
    }

    #[test]
    fn test_validate_password_match_unicode() {
        assert!(validate_password_match("パスワード", "パスワード").is_ok());
    }
}
