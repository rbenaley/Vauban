/// VAUBAN - Reset user password utility.
///
/// Interactive CLI tool to reset a user's password.
/// No secrets are stored in code - all input is provided interactively.

use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use rand::rngs::OsRng;
use diesel::prelude::*;
use diesel::pg::PgConnection;
use std::io::{self, Write};

fn main() {
    dotenv::dotenv().ok();

    println!("🔐 VAUBAN Password Reset Utility");
    println!("================================\n");

    // Get database connection
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env file");

    let mut conn = PgConnection::establish(&database_url)
        .expect("Failed to connect to database");

    // Prompt for username
    let username = prompt("Enter username: ")
        .expect("Failed to read username");

    if username.trim().is_empty() {
        eprintln!("❌ Username cannot be empty");
        std::process::exit(1);
    }

    // Check if user exists
    let user_exists: bool = diesel::sql_query(format!(
        "SELECT EXISTS(SELECT 1 FROM users WHERE username = '{}' AND is_deleted = false) as exists",
        username.trim().replace('\'', "''")
    ))
    .get_result::<ExistsResult>(&mut conn)
    .map(|r| r.exists)
    .unwrap_or(false);

    if !user_exists {
        eprintln!("❌ User '{}' not found", username.trim());
        std::process::exit(1);
    }

    // Prompt for new password
    let password = prompt_password("Enter new password (min 12 chars): ")
        .expect("Failed to read password");

    if password.len() < 12 {
        eprintln!("❌ Password must be at least 12 characters");
        std::process::exit(1);
    }

    // Confirm password
    let password_confirm = prompt_password("Confirm new password: ")
        .expect("Failed to read password confirmation");

    if password != password_confirm {
        eprintln!("❌ Passwords do not match");
        std::process::exit(1);
    }

    // Hash the password
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string();

    // Update user password
    let rows_affected = diesel::sql_query(format!(
        "UPDATE users SET password_hash = '{}', updated_at = NOW() WHERE username = '{}' AND is_deleted = false",
        hash.replace('\'', "''"),
        username.trim().replace('\'', "''")
    ))
    .execute(&mut conn)
    .expect("Failed to update password");

    if rows_affected > 0 {
        println!("\n✅ Password for '{}' has been updated successfully", username.trim());
    } else {
        eprintln!("\n❌ Failed to update password");
        std::process::exit(1);
    }
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
        use std::os::unix::io::AsRawFd;
        
        let stdin_fd = io::stdin().as_raw_fd();
        let mut termios = unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(stdin_fd, &mut t) == 0 {
                Some(t)
            } else {
                None
            }
        };

        if let Some(ref mut t) = termios {
            let original = *t;
            t.c_lflag &= !libc::ECHO;
            unsafe { libc::tcsetattr(stdin_fd, libc::TCSANOW, t) };

            let mut input = String::new();
            let result = io::stdin().read_line(&mut input);

            // Restore terminal
            unsafe { libc::tcsetattr(stdin_fd, libc::TCSANOW, &original) };
            println!(); // New line after hidden input

            result?;
            return Ok(input.trim().to_string());
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
