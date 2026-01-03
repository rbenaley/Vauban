/// VAUBAN CLI - Create Superuser
///
/// Interactive command to create the initial superuser account.
/// Usage: cargo run --bin create_superuser

use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use rand::rngs::OsRng;
use diesel::prelude::*;
use diesel::pg::PgConnection;
use std::io::{self, Write};
use rpassword::read_password;
use uuid::Uuid;

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

fn main() {
    dotenv::dotenv().ok();

    println!("\n🔐 VAUBAN - Create Superuser");
    println!("============================\n");

    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");

    let mut conn = PgConnection::establish(&database_url)
        .expect("Failed to connect to database");

    // Check if any superuser already exists
    let existing_superuser: Option<i32> = diesel::sql_query(
        "SELECT id FROM users WHERE is_superuser = true AND is_deleted = false LIMIT 1"
    )
    .get_result::<ExistsResult>(&mut conn)
    .map(|r| Some(r.id))
    .unwrap_or(None);

    if existing_superuser.is_some() {
        println!("⚠️  A superuser already exists in the database.");
        print!("Do you want to create another superuser? (y/N): ");
        io::stdout().flush().unwrap();
        
        let mut confirm = String::new();
        io::stdin().read_line(&mut confirm).expect("Failed to read input");
        if confirm.trim().to_lowercase() != "y" {
            println!("\n❌ Operation cancelled.");
            return;
        }
        println!();
    }

    // Prompt for username
    let username = loop {
        print!("Username: ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read username");
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
        let exists: bool = diesel::sql_query(format!(
            "SELECT EXISTS(SELECT 1 FROM users WHERE username = '{}' AND is_deleted = false) as exists",
            trimmed.replace('\'', "''")
        ))
        .get_result::<ExistsBool>(&mut conn)
        .map(|r| r.exists)
        .unwrap_or(false);
        
        if exists {
            eprintln!("Username '{}' already exists. Please choose another.", trimmed);
            continue;
        }
        
        break trimmed;
    };

    // Prompt for email
    let email = loop {
        print!("Email: ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read email");
        let trimmed = input.trim().to_string();
        
        if !trimmed.contains('@') || !trimmed.contains('.') {
            eprintln!("Please enter a valid email address.");
            continue;
        }
        
        // Check if email already exists
        let exists: bool = diesel::sql_query(format!(
            "SELECT EXISTS(SELECT 1 FROM users WHERE email = '{}' AND is_deleted = false) as exists",
            trimmed.replace('\'', "''")
        ))
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
    io::stdin().read_line(&mut first_name_input).expect("Failed to read first name");
    let first_name = first_name_input.trim();
    let first_name = if first_name.is_empty() { None } else { Some(first_name.to_string()) };

    // Prompt for last name (optional)
    print!("Last name (optional): ");
    io::stdout().flush().unwrap();
    let mut last_name_input = String::new();
    io::stdin().read_line(&mut last_name_input).expect("Failed to read last name");
    let last_name = last_name_input.trim();
    let last_name = if last_name.is_empty() { None } else { Some(last_name.to_string()) };

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
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string();

    // Create the superuser
    let user_uuid = Uuid::new_v4();
    
    let first_name_sql = first_name.as_ref()
        .map(|n| format!("'{}'", n.replace('\'', "''")))
        .unwrap_or_else(|| "NULL".to_string());
    let last_name_sql = last_name.as_ref()
        .map(|n| format!("'{}'", n.replace('\'', "''")))
        .unwrap_or_else(|| "NULL".to_string());

    let result = diesel::sql_query(format!(
        "INSERT INTO users (uuid, username, email, password_hash, first_name, last_name, 
                           is_active, is_staff, is_superuser, is_service_account, 
                           mfa_enabled, mfa_enforced, preferences, auth_source)
         VALUES ('{}', '{}', '{}', '{}', {}, {}, 
                 true, true, true, false, 
                 false, false, '{{}}', 'local')
         RETURNING id",
        user_uuid,
        username.replace('\'', "''"),
        email.replace('\'', "''"),
        password_hash.replace('\'', "''"),
        first_name_sql,
        last_name_sql
    ))
    .execute(&mut conn);

    match result {
        Ok(_) => {
            println!("\n✅ Superuser created successfully!");
            println!("\n   Username: {}", username);
            println!("   Email:    {}", email);
            if let Some(ref fn_) = first_name {
                println!("   Name:     {} {}", fn_, last_name.as_deref().unwrap_or(""));
            }
            println!("   UUID:     {}", user_uuid);
            println!("\nYou can now log in at http://localhost:8000/login");
        }
        Err(e) => {
            eprintln!("\n❌ Failed to create superuser: {}", e);
            std::process::exit(1);
        }
    }
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

