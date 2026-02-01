// SAFETY: This is a development-only seed script where expect() is acceptable
// for database operations - failures should terminate the script.
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

//! VAUBAN - Seed Data Generator
//!
//! Creates test data for development (idempotent):
//! - 5 users (1 admin, 2 staff, 2 regular)
//! - 30 assets (SSH, RDP, VNC)
//! - 30 sessions (including 20 recordings)
//! - 20 approval requests
//!
//! This script can be run multiple times without creating duplicates.
//!
//! Refactored to use Diesel DSL instead of raw SQL queries for type safety.

use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version, password_hash::SaltString};
use chrono::{DateTime, Duration, Utc};
use diesel::dsl::exists;
use diesel::prelude::*;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use ipnetwork::IpNetwork;
use rand::Rng;
use rand::rngs::OsRng;
use secrecy::ExposeSecret;
use uuid::Uuid;
use vauban_web::config::Config;

// Import schema
mod schema {
    include!("../schema.rs");
}

// ==================== Local Insertable Structs ====================
// These are used only for seed data generation

/// New user for insertion (local to seed_data).
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = schema::users)]
struct NewUser {
    pub uuid: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub is_active: bool,
    pub is_staff: bool,
    pub is_superuser: bool,
    pub auth_source: String,
    pub preferences: serde_json::Value,
}

/// New asset for insertion (local to seed_data).
#[derive(Debug, Clone, Insertable, AsChangeset)]
#[diesel(table_name = schema::assets)]
struct NewAsset {
    pub uuid: Uuid,
    pub name: String,
    pub hostname: String,
    pub ip_address: Option<IpNetwork>,
    pub port: i32,
    pub asset_type: String,
    pub status: String,
    pub os_type: Option<String>,
    pub os_version: Option<String>,
    pub description: Option<String>,
    pub created_by_id: Option<i32>,
    pub require_mfa: bool,
    pub require_justification: bool,
    pub connection_config: serde_json::Value,
    pub max_session_duration: i32,
}

/// New proxy session for insertion (local to seed_data).
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = schema::proxy_sessions)]
struct NewProxySession {
    pub uuid: Uuid,
    pub user_id: i32,
    pub asset_id: i32,
    pub credential_id: String,
    pub credential_username: String,
    pub session_type: String,
    pub status: String,
    pub client_ip: IpNetwork,
    pub connected_at: Option<DateTime<Utc>>,
    pub disconnected_at: Option<DateTime<Utc>>,
    pub is_recorded: bool,
    pub recording_path: Option<String>,
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub commands_count: i32,
    pub justification: Option<String>,
    pub metadata: serde_json::Value,
}

/// New vauban group for insertion (local to seed_data).
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = schema::vauban_groups)]
struct NewVaubanGroup {
    pub uuid: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub source: String,
}

/// New asset group for insertion (local to seed_data).
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = schema::asset_groups)]
struct NewAssetGroup {
    pub uuid: Uuid,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub color: String,
    pub icon: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 VAUBAN Seed Data Generator (Idempotent)");
    println!("==========================================\n");

    // Load configuration from TOML files
    let config = Config::load().context("Failed to load configuration from config/*.toml")?;

    // Create async connection pool
    let manager =
        AsyncDieselConnectionManager::<AsyncPgConnection>::new(config.database.url.expose_secret());
    let pool = Pool::builder(manager)
        .max_size(5)
        .build()
        .context("Failed to create database pool")?;

    let mut conn = pool
        .get()
        .await
        .context("Failed to get database connection")?;

    // Create users
    println!("👥 Creating users...");
    let user_ids = create_users(&mut conn, &config).await;
    println!("   ✅ {} users ready\n", user_ids.len());

    // Get first user id for ownership
    let owner_id = user_ids.get(0).copied().unwrap_or(1);

    // Create assets
    println!("📦 Creating assets...");
    let asset_ids = create_assets(&mut conn, owner_id).await;
    println!("   ✅ {} assets ready\n", asset_ids.len());

    // Check existing sessions count
    use schema::proxy_sessions::dsl::{proxy_sessions, status};
    let existing_sessions: i64 = proxy_sessions
        .filter(status.ne("pending"))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap_or(0);

    if existing_sessions < 30 {
        println!("🔗 Creating sessions and recordings...");
        let session_count = create_sessions(
            &mut conn,
            &user_ids,
            &asset_ids,
            30 - existing_sessions as i32,
        )
        .await;
        println!(
            "   ✅ Created {} new sessions (total: {})\n",
            session_count,
            existing_sessions + session_count as i64
        );
    } else {
        println!(
            "🔗 Sessions already exist ({} found), skipping...\n",
            existing_sessions
        );
    }

    // Check existing approvals count
    let existing_approvals: i64 = proxy_sessions
        .filter(status.eq("pending"))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap_or(0);

    if existing_approvals < 20 {
        println!("📋 Creating approval requests...");
        let approval_count = create_approval_requests(
            &mut conn,
            &user_ids,
            &asset_ids,
            20 - existing_approvals as i32,
        )
        .await;
        println!(
            "   ✅ Created {} new approval requests (total: {})\n",
            approval_count,
            existing_approvals + approval_count as i64
        );
    } else {
        println!(
            "📋 Approval requests already exist ({} found), skipping...\n",
            existing_approvals
        );
    }

    // Create user groups
    println!("👥 Creating user groups...");
    let group_count = create_groups(&mut conn).await;
    println!("   ✅ {} user groups ready\n", group_count);

    // Create asset groups
    println!("📦 Creating asset groups...");
    let asset_group_count = create_asset_groups(&mut conn).await;
    println!("   ✅ {} asset groups ready\n", asset_group_count);

    println!("🎉 Seed data generation complete!");
    println!("\nSummary:");
    println!("  - {} users", user_ids.len());
    println!("  - {} assets", asset_ids.len());
    println!("  - {} user groups", group_count);
    println!("  - {} asset groups", asset_group_count);

    Ok(())
}

/// Hash a password using Argon2.
///
/// # Panics
/// Panics if Argon2 parameters are invalid (configuration error).
#[allow(clippy::expect_used)]
fn hash_password(password: &str, config: &Config) -> String {
    let salt = SaltString::generate(&mut OsRng);
    // SAFETY: Config is validated at load time, these params are always valid
    let params = Params::new(
        config.security.argon2.memory_size_kb,
        config.security.argon2.iterations,
        config.security.argon2.parallelism,
        Some(32),
    )
    .expect("Failed to create Argon2 parameters");

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string()
}

/// Create test users (idempotent) using Diesel DSL.
async fn create_users(conn: &mut AsyncPgConnection, config: &Config) -> Vec<i32> {
    use schema::users::dsl::*;

    let mut user_ids = Vec::new();

    // Define users: (username, email, first_name, last_name, is_staff, is_superuser)
    let users_data = vec![
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

    let default_password = "SecurePassword123!";
    let password_hash_value = hash_password(default_password, config);

    for (uname, mail, fname, lname, staff, superuser) in users_data {
        // Check if user already exists
        let existing: Option<i32> = users
            .filter(username.eq(uname).or(email.eq(mail)))
            .select(id)
            .first(conn)
            .await
            .optional()
            .expect("Failed to query users");

        if let Some(user_id) = existing {
            user_ids.push(user_id);
            let role = if superuser {
                "admin"
            } else if staff {
                "staff"
            } else {
                "user"
            };
            println!("   - {} ({}) already exists", uname, role);
            continue;
        }

        // Create new user using Diesel DSL
        let new_user = NewUser {
            uuid: Uuid::new_v4(),
            username: uname.to_string(),
            email: mail.to_string(),
            password_hash: password_hash_value.clone(),
            first_name: Some(fname.to_string()),
            last_name: Some(lname.to_string()),
            is_active: true,
            is_staff: staff,
            is_superuser: superuser,
            auth_source: "local".to_string(),
            preferences: serde_json::json!({}),
        };

        let result: Result<i32, _> = diesel::insert_into(users)
            .values(&new_user)
            .on_conflict(username)
            .do_nothing()
            .returning(id)
            .get_result(conn)
            .await;

        match result {
            Ok(user_id) => {
                user_ids.push(user_id);
                let role = if superuser {
                    "admin"
                } else if staff {
                    "staff"
                } else {
                    "user"
                };
                println!("   - {} ({}) created", uname, role);
            }
            Err(e) => {
                eprintln!("   ⚠ Failed to create {}: {}", uname, e);
            }
        }
    }

    // Also include existing 'mnemonic' user if present
    let mnemonic_id: Option<i32> = users
        .filter(username.eq("mnemonic"))
        .select(id)
        .first(conn)
        .await
        .optional()
        .expect("Failed to query users");

    if let Some(uid) = mnemonic_id {
        if !user_ids.contains(&uid) {
            user_ids.push(uid);
            println!("   - mnemonic (existing) included");
        }
    }

    user_ids
}

/// Create test assets (idempotent) using Diesel DSL with upsert.
async fn create_assets(conn: &mut AsyncPgConnection, admin_id: i32) -> Vec<i32> {
    let mut rng = rand::thread_rng();
    let mut asset_ids = Vec::new();
    let mut created_count = 0;
    let mut existing_count = 0;

    // Helper to create and upsert an asset
    async fn upsert_asset(
        conn: &mut AsyncPgConnection,
        new_asset: NewAsset,
        asset_ids: &mut Vec<i32>,
        created_count: &mut i32,
        existing_count: &mut i32,
        display_type: &str,
    ) {
        use schema::assets::dsl::*;

        // Check if asset already exists
        let existing_id: Option<i32> = assets
            .filter(hostname.eq(&new_asset.hostname))
            .filter(port.eq(new_asset.port))
            .select(id)
            .first(conn)
            .await
            .optional()
            .unwrap_or(None);

        if let Some(asset_id) = existing_id {
            // Update status only
            let _ = diesel::update(assets.filter(id.eq(asset_id)))
                .set(status.eq(&new_asset.status))
                .execute(conn)
                .await;
            asset_ids.push(asset_id);
            *existing_count += 1;
        } else {
            // Insert new asset
            let result: Result<i32, _> = diesel::insert_into(assets)
                .values(&new_asset)
                .returning(id)
                .get_result(conn)
                .await;

            match result {
                Ok(asset_id) => {
                    asset_ids.push(asset_id);
                    *created_count += 1;
                    println!(
                        "   - {} ({}, {})",
                        new_asset.name, display_type, new_asset.status
                    );
                }
                Err(e) => {
                    eprintln!("   ⚠ Failed to create asset {}: {}", new_asset.name, e);
                }
            }
        }
    }

    // Linux SSH servers
    let linux_servers = vec![
        ("web-prod-01", "Ubuntu 22.04", "Web Server Production"),
        ("web-prod-02", "Ubuntu 22.04", "Web Server Production"),
        ("web-staging-01", "Ubuntu 20.04", "Web Server Staging"),
        ("db-prod-master", "Rocky Linux 9", "Database Master"),
        ("db-prod-replica-01", "Rocky Linux 9", "Database Replica"),
        ("db-prod-replica-02", "Rocky Linux 9", "Database Replica"),
        ("cache-prod-01", "Debian 12", "Redis Cache"),
        ("cache-prod-02", "Debian 12", "Redis Cache"),
        ("monitoring-01", "Ubuntu 22.04", "Prometheus/Grafana"),
        ("logging-01", "Ubuntu 22.04", "ELK Stack"),
        ("ci-runner-01", "Ubuntu 22.04", "GitLab Runner"),
        ("ci-runner-02", "Ubuntu 22.04", "GitLab Runner"),
        ("backup-01", "Debian 12", "Backup Server"),
        ("vpn-gateway", "pfSense", "VPN Gateway"),
        ("bastion-internal", "Ubuntu 22.04", "Internal Bastion"),
    ];

    for (i, (name_val, os_val, desc_val)) in linux_servers.iter().enumerate() {
        let ip_str = format!("10.0.{}.{}", (i / 50) + 1, (i % 254) + 1);
        let status_val = if rng.gen_bool(0.85) {
            "online"
        } else {
            "offline"
        };

        let new_asset = NewAsset {
            uuid: Uuid::new_v4(),
            name: name_val.to_string(),
            hostname: format!("{}.vauban.local", name_val),
            ip_address: Some(ip_str.parse().expect("Invalid IP")),
            port: 22,
            asset_type: "ssh".to_string(),
            status: status_val.to_string(),
            os_type: Some("linux".to_string()),
            os_version: Some(os_val.to_string()),
            description: Some(desc_val.to_string()),
            created_by_id: Some(admin_id),
            require_mfa: rng.gen_bool(0.3),
            require_justification: rng.gen_bool(0.2),
            connection_config: serde_json::json!({}),
            max_session_duration: 28800,
        };

        upsert_asset(
            conn,
            new_asset,
            &mut asset_ids,
            &mut created_count,
            &mut existing_count,
            "SSH",
        )
        .await;
    }

    // Windows RDP servers
    let windows_servers = vec![
        ("win-dc-01", "Windows Server 2022", "Domain Controller"),
        ("win-dc-02", "Windows Server 2022", "Domain Controller"),
        ("win-file-01", "Windows Server 2019", "File Server"),
        ("win-app-01", "Windows Server 2019", "Application Server"),
        ("win-app-02", "Windows Server 2019", "Application Server"),
        ("win-sql-01", "Windows Server 2022", "SQL Server"),
        ("win-exchange", "Windows Server 2019", "Exchange Server"),
        ("win-admin-01", "Windows 11 Pro", "Admin Workstation"),
        ("win-admin-02", "Windows 11 Pro", "Admin Workstation"),
        ("win-dev-01", "Windows 11 Pro", "Developer Workstation"),
    ];

    for (i, (name_val, os_val, desc_val)) in windows_servers.iter().enumerate() {
        let ip_str = format!("10.1.{}.{}", (i / 50) + 1, (i % 254) + 1);
        let status_val = if rng.gen_bool(0.9) {
            "online"
        } else {
            "offline"
        };

        let new_asset = NewAsset {
            uuid: Uuid::new_v4(),
            name: name_val.to_string(),
            hostname: format!("{}.vauban.local", name_val),
            ip_address: Some(ip_str.parse().expect("Invalid IP")),
            port: 3389,
            asset_type: "rdp".to_string(),
            status: status_val.to_string(),
            os_type: Some("windows".to_string()),
            os_version: Some(os_val.to_string()),
            description: Some(desc_val.to_string()),
            created_by_id: Some(admin_id),
            require_mfa: rng.gen_bool(0.5),
            require_justification: rng.gen_bool(0.4),
            connection_config: serde_json::json!({}),
            max_session_duration: 28800,
        };

        upsert_asset(
            conn,
            new_asset,
            &mut asset_ids,
            &mut created_count,
            &mut existing_count,
            "RDP",
        )
        .await;
    }

    // VNC servers
    let vnc_servers = [
        ("kvm-host-01", "Proxmox VE 8", "KVM Hypervisor"),
        ("kvm-host-02", "Proxmox VE 8", "KVM Hypervisor"),
        ("esxi-01", "VMware ESXi 8", "VMware Host"),
        ("network-switch-mgmt", "Custom Linux", "Network Management"),
        ("ilo-server-01", "HP iLO", "Server Management"),
    ];

    for (i, (name_val, os_val, desc_val)) in vnc_servers.iter().enumerate() {
        let ip_str = format!("10.2.{}.{}", (i / 50) + 1, (i % 254) + 1);
        let status_val = if rng.gen_bool(0.95) {
            "online"
        } else {
            "maintenance"
        };

        let new_asset = NewAsset {
            uuid: Uuid::new_v4(),
            name: name_val.to_string(),
            hostname: format!("{}.vauban.local", name_val),
            ip_address: Some(ip_str.parse().expect("Invalid IP")),
            port: 5900,
            asset_type: "vnc".to_string(),
            status: status_val.to_string(),
            os_type: Some("linux".to_string()),
            os_version: Some(os_val.to_string()),
            description: Some(desc_val.to_string()),
            created_by_id: Some(admin_id),
            require_mfa: true,
            require_justification: true,
            connection_config: serde_json::json!({}),
            max_session_duration: 28800,
        };

        upsert_asset(
            conn,
            new_asset,
            &mut asset_ids,
            &mut created_count,
            &mut existing_count,
            "VNC",
        )
        .await;
    }

    if existing_count > 0 {
        println!(
            "   ({} already existed, {} created)",
            existing_count, created_count
        );
    }

    asset_ids
}

/// Create test sessions using Diesel DSL.
async fn create_sessions(
    conn: &mut AsyncPgConnection,
    user_ids: &[i32],
    asset_ids: &[i32],
    count: i32,
) -> i32 {
    use schema::proxy_sessions::dsl::*;

    let mut rng = rand::thread_rng();
    let mut created = 0;

    if asset_ids.is_empty() || user_ids.is_empty() {
        return 0;
    }

    let statuses = ["active", "disconnected", "completed", "terminated"];
    let session_types = ["ssh", "rdp", "vnc"];
    let client_ips_list = [
        "192.168.1.10",
        "192.168.1.25",
        "192.168.1.100",
        "10.0.0.50",
        "172.16.0.15",
        "192.168.2.200",
    ];

    for i in 0..count {
        let uid = user_ids[rng.gen_range(0..user_ids.len())];
        let aid = asset_ids[rng.gen_range(0..asset_ids.len())];
        let status_val = if i < 3 {
            "active"
        } else {
            statuses[rng.gen_range(0..statuses.len())]
        };
        let session_type_val = session_types[rng.gen_range(0..session_types.len())];
        let client_ip_str = client_ips_list[rng.gen_range(0..client_ips_list.len())];

        let is_recorded_val = i >= 10;
        let recording_path_val = if is_recorded_val {
            Some(format!(
                "/recordings/{}/{}.cast",
                Utc::now().format("%Y/%m"),
                Uuid::new_v4()
            ))
        } else {
            None
        };

        let connected_at_val = Utc::now() - Duration::hours(rng.gen_range(1..720));
        let disconnected_at_val = if status_val != "active" {
            Some(connected_at_val + Duration::minutes(rng.gen_range(5..180)))
        } else {
            None
        };

        let credential_id_val = Uuid::new_v4().to_string();
        let credential_username_val = if session_type_val == "ssh" {
            "root"
        } else {
            "Administrator"
        };
        let bytes_sent_val: i64 = rng.gen_range(1000..1000000);
        let bytes_received_val: i64 = rng.gen_range(5000..5000000);
        let commands_count_val: i32 = rng.gen_range(0..500);
        let justification_val: Option<String> = if rng.gen_bool(0.3) {
            Some("Maintenance task".to_string())
        } else {
            None
        };

        let new_session = NewProxySession {
            uuid: Uuid::new_v4(),
            user_id: uid,
            asset_id: aid,
            credential_id: credential_id_val,
            credential_username: credential_username_val.to_string(),
            session_type: session_type_val.to_string(),
            status: status_val.to_string(),
            client_ip: client_ip_str.parse().expect("Invalid client IP"),
            connected_at: Some(connected_at_val),
            disconnected_at: disconnected_at_val,
            is_recorded: is_recorded_val,
            recording_path: recording_path_val,
            bytes_sent: bytes_sent_val,
            bytes_received: bytes_received_val,
            commands_count: commands_count_val,
            justification: justification_val,
            metadata: serde_json::json!({}),
        };

        let result = diesel::insert_into(proxy_sessions)
            .values(&new_session)
            .execute(conn)
            .await;

        match result {
            Ok(_) => {
                created += 1;
                let rec_str = if is_recorded_val { " (recorded)" } else { "" };
                println!("   - Session {} [{}]{}", i + 1, status_val, rec_str);
            }
            Err(e) => {
                eprintln!("   ⚠ Failed to create session {}: {}", i + 1, e);
            }
        }
    }

    created
}

/// Create approval requests using Diesel DSL.
async fn create_approval_requests(
    conn: &mut AsyncPgConnection,
    user_ids: &[i32],
    asset_ids: &[i32],
    count: i32,
) -> i32 {
    use schema::proxy_sessions::dsl::*;

    let mut rng = rand::thread_rng();
    let mut created = 0;

    if asset_ids.is_empty() || user_ids.is_empty() {
        return 0;
    }

    let justifications_list = vec![
        "Urgent production issue - server not responding",
        "Scheduled maintenance window",
        "Security patching required",
        "Database migration task",
        "Log investigation for incident #12345",
        "Performance tuning",
        "Backup verification",
        "Configuration update",
        "User access audit",
        "Emergency fix for critical bug",
    ];

    let session_types = ["ssh", "rdp"];
    let client_ips_list = [
        "192.168.1.50",
        "192.168.1.75",
        "192.168.1.150",
        "10.0.0.100",
        "172.16.0.30",
    ];

    for i in 0..count {
        let uid = user_ids[rng.gen_range(0..user_ids.len())];
        let aid = asset_ids[rng.gen_range(0..asset_ids.len())];
        let session_type_val = session_types[rng.gen_range(0..session_types.len())];
        let client_ip_str = client_ips_list[rng.gen_range(0..client_ips_list.len())];
        let justification_val = justifications_list[rng.gen_range(0..justifications_list.len())];

        let credential_id_val = Uuid::new_v4().to_string();
        let credential_username_val = if session_type_val == "ssh" {
            "root"
        } else {
            "Administrator"
        };

        let new_session = NewProxySession {
            uuid: Uuid::new_v4(),
            user_id: uid,
            asset_id: aid,
            credential_id: credential_id_val,
            credential_username: credential_username_val.to_string(),
            session_type: session_type_val.to_string(),
            status: "pending".to_string(),
            client_ip: client_ip_str.parse().expect("Invalid client IP"),
            connected_at: None,
            disconnected_at: None,
            is_recorded: true,
            recording_path: None,
            bytes_sent: 0,
            bytes_received: 0,
            commands_count: 0,
            justification: Some(justification_val.to_string()),
            metadata: serde_json::json!({"approval_required": true}),
        };

        let result = diesel::insert_into(proxy_sessions)
            .values(&new_session)
            .execute(conn)
            .await;

        match result {
            Ok(_) => {
                created += 1;
                println!(
                    "   - Approval #{}: {}",
                    i + 1,
                    &justification_val[..50.min(justification_val.len())]
                );
            }
            Err(e) => {
                eprintln!("   ⚠ Failed to create approval {}: {}", i + 1, e);
            }
        }
    }

    created
}

/// Create user groups (idempotent) using Diesel DSL.
async fn create_groups(conn: &mut AsyncPgConnection) -> i32 {
    use schema::vauban_groups::dsl::*;

    let mut count = 0;

    // Define groups: (name, description, source)
    let groups_data = vec![
        (
            "Administrators",
            "Full system administrators with all permissions",
            "local",
        ),
        (
            "Operators",
            "System operators with limited administrative access",
            "local",
        ),
        ("Developers", "Development team members", "local"),
        (
            "Auditors",
            "Security auditors with read-only access to logs and recordings",
            "local",
        ),
        (
            "Support",
            "Support team with access to user management",
            "local",
        ),
    ];

    for (name_val, description_val, source_val) in groups_data {
        // Check if group already exists
        let existing: bool = diesel::select(exists(vauban_groups.filter(name.eq(name_val))))
            .get_result(conn)
            .await
            .unwrap_or(false);

        if existing {
            count += 1;
            println!("   - {} already exists", name_val);
            continue;
        }

        // Create new group
        let new_group = NewVaubanGroup {
            uuid: Uuid::new_v4(),
            name: name_val.to_string(),
            description: Some(description_val.to_string()),
            source: source_val.to_string(),
        };

        let result = diesel::insert_into(vauban_groups)
            .values(&new_group)
            .on_conflict(name)
            .do_nothing()
            .execute(conn)
            .await;

        match result {
            Ok(rows) if rows > 0 => {
                count += 1;
                println!("   - {} created", name_val);
            }
            Ok(_) => {
                count += 1;
                println!("   - {} already exists", name_val);
            }
            Err(e) => {
                eprintln!("   ⚠ Failed to create {}: {}", name_val, e);
            }
        }
    }

    count
}

/// Create asset groups (idempotent) using Diesel DSL.
async fn create_asset_groups(conn: &mut AsyncPgConnection) -> i32 {
    use schema::asset_groups::dsl::*;

    let mut count = 0;

    // Define asset groups: (name, slug, description, color, icon)
    let groups_data = vec![
        (
            "Production Servers",
            "production",
            "Production environment servers",
            "#EF4444",
            "server",
        ),
        (
            "Development Servers",
            "development",
            "Development and testing servers",
            "#3B82F6",
            "code",
        ),
        (
            "Database Servers",
            "databases",
            "Database servers (PostgreSQL, MySQL, etc.)",
            "#8B5CF6",
            "database",
        ),
        (
            "Network Devices",
            "network",
            "Routers, switches, and network equipment",
            "#10B981",
            "wifi",
        ),
        (
            "Windows Workstations",
            "workstations",
            "Windows workstations for remote access",
            "#F59E0B",
            "desktop",
        ),
    ];

    for (name_val, slug_val, description_val, color_val, icon_val) in groups_data {
        // Check if group already exists
        let existing: bool = diesel::select(exists(
            asset_groups
                .filter(slug.eq(slug_val))
                .filter(is_deleted.eq(false)),
        ))
        .get_result(conn)
        .await
        .unwrap_or(false);

        if existing {
            count += 1;
            println!("   - {} already exists", name_val);
            continue;
        }

        // Create new group
        let new_group = NewAssetGroup {
            uuid: Uuid::new_v4(),
            name: name_val.to_string(),
            slug: slug_val.to_string(),
            description: Some(description_val.to_string()),
            color: color_val.to_string(),
            icon: icon_val.to_string(),
        };

        let result = diesel::insert_into(asset_groups)
            .values(&new_group)
            .on_conflict(slug)
            .do_nothing()
            .execute(conn)
            .await;

        match result {
            Ok(rows) if rows > 0 => {
                count += 1;
                println!("   - {} created", name_val);
            }
            Ok(_) => {
                count += 1;
                println!("   - {} already exists", name_val);
            }
            Err(e) => {
                eprintln!("   ⚠ Failed to create {}: {}", name_val, e);
            }
        }
    }

    count
}

// ==================== Data Generation Functions ====================

/// Generate a random asset name based on type.
pub fn generate_asset_name(asset_type: &str, index: usize) -> String {
    let prefixes = match asset_type {
        "ssh" => ["web", "app", "db", "cache", "proxy", "monitor"],
        "rdp" => [
            "desktop",
            "workstation",
            "terminal",
            "citrix",
            "admin",
            "dev",
        ],
        "vnc" => ["kvm", "console", "remote", "display", "graphic", "screen"],
        _ => ["server", "host", "node", "instance", "vm", "container"],
    };

    let prefix = prefixes[index % prefixes.len()];
    format!("{}-{:03}", prefix, index + 1)
}

/// Generate a hostname from asset name.
pub fn generate_hostname(asset_name: &str, domain: &str) -> String {
    format!("{}.{}", asset_name.to_lowercase(), domain)
}

/// Generate a random IP address in a given range.
pub fn generate_ip_address(base: &str, index: usize) -> String {
    let parts: Vec<&str> = base.split('.').collect();
    if parts.len() >= 3 {
        format!(
            "{}.{}.{}.{}",
            parts[0],
            parts[1],
            parts[2],
            (index % 254) + 1
        )
    } else {
        format!("10.0.0.{}", (index % 254) + 1)
    }
}

/// Get default port for asset type.
pub fn get_default_port(asset_type: &str) -> i32 {
    match asset_type {
        "ssh" => 22,
        "rdp" => 3389,
        "vnc" => 5900,
        _ => 22,
    }
}

/// Generate session status.
pub fn generate_session_status(index: usize) -> &'static str {
    match index % 5 {
        0 => "active",
        1 => "completed",
        2 => "terminated",
        3 => "error",
        _ => "completed",
    }
}

/// Generate approval status.
pub fn generate_approval_status(index: usize) -> &'static str {
    match index % 4 {
        0 => "pending",
        1 => "approved",
        2 => "rejected",
        _ => "pending",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Asset Name Generation Tests ====================

    #[test]
    fn test_generate_asset_name_ssh() {
        let name = generate_asset_name("ssh", 0);
        assert!(name.starts_with("web-"));
        assert!(name.ends_with("001"));
    }

    #[test]
    fn test_generate_asset_name_rdp() {
        let name = generate_asset_name("rdp", 0);
        assert!(name.starts_with("desktop-"));
    }

    #[test]
    fn test_generate_asset_name_vnc() {
        let name = generate_asset_name("vnc", 0);
        assert!(name.starts_with("kvm-"));
    }

    #[test]
    fn test_generate_asset_name_cycles() {
        // SSH has 6 prefixes, so index 6 should cycle back
        let name1 = generate_asset_name("ssh", 0);
        let name2 = generate_asset_name("ssh", 6);

        // Both should start with "web-"
        assert!(name1.starts_with("web-"));
        assert!(name2.starts_with("web-"));

        // But have different numbers
        assert!(name1.ends_with("001"));
        assert!(name2.ends_with("007"));
    }

    // ==================== Hostname Generation Tests ====================

    #[test]
    fn test_generate_hostname() {
        let hostname = generate_hostname("web-001", "example.com");
        assert_eq!(hostname, "web-001.example.com");
    }

    #[test]
    fn test_generate_hostname_lowercase() {
        let hostname = generate_hostname("WEB-001", "example.com");
        assert_eq!(hostname, "web-001.example.com");
    }

    // ==================== IP Address Generation Tests ====================

    #[test]
    fn test_generate_ip_address() {
        let ip = generate_ip_address("192.168.1.0", 0);
        assert_eq!(ip, "192.168.1.1");
    }

    #[test]
    fn test_generate_ip_address_increment() {
        let ip1 = generate_ip_address("10.0.0.0", 0);
        let ip2 = generate_ip_address("10.0.0.0", 1);
        let ip3 = generate_ip_address("10.0.0.0", 2);

        assert_eq!(ip1, "10.0.0.1");
        assert_eq!(ip2, "10.0.0.2");
        assert_eq!(ip3, "10.0.0.3");
    }

    #[test]
    fn test_generate_ip_address_wraps() {
        // Index 254 should wrap to 1
        let ip = generate_ip_address("10.0.0.0", 254);
        assert_eq!(ip, "10.0.0.1");
    }

    // ==================== Default Port Tests ====================

    #[test]
    fn test_get_default_port_ssh() {
        assert_eq!(get_default_port("ssh"), 22);
    }

    #[test]
    fn test_get_default_port_rdp() {
        assert_eq!(get_default_port("rdp"), 3389);
    }

    #[test]
    fn test_get_default_port_vnc() {
        assert_eq!(get_default_port("vnc"), 5900);
    }

    #[test]
    fn test_get_default_port_unknown() {
        assert_eq!(get_default_port("unknown"), 22);
    }

    // ==================== Session Status Tests ====================

    #[test]
    fn test_generate_session_status() {
        assert_eq!(generate_session_status(0), "active");
        assert_eq!(generate_session_status(1), "completed");
        assert_eq!(generate_session_status(2), "terminated");
        assert_eq!(generate_session_status(3), "error");
        assert_eq!(generate_session_status(4), "completed");
    }

    #[test]
    fn test_generate_session_status_cycles() {
        assert_eq!(generate_session_status(5), "active");
        assert_eq!(generate_session_status(10), "active");
    }

    // ==================== Approval Status Tests ====================

    #[test]
    fn test_generate_approval_status() {
        assert_eq!(generate_approval_status(0), "pending");
        assert_eq!(generate_approval_status(1), "approved");
        assert_eq!(generate_approval_status(2), "rejected");
        assert_eq!(generate_approval_status(3), "pending");
    }

    #[test]
    fn test_generate_approval_status_cycles() {
        assert_eq!(generate_approval_status(4), "pending");
        assert_eq!(generate_approval_status(8), "pending");
    }

    // ==================== Asset Name Edge Cases ====================

    #[test]
    fn test_generate_asset_name_unknown_type() {
        let name = generate_asset_name("unknown", 0);
        assert!(name.starts_with("server-"));
    }

    #[test]
    fn test_generate_asset_name_large_index() {
        let name = generate_asset_name("ssh", 1000);
        assert!(name.ends_with("1001"));
    }

    #[test]
    fn test_generate_asset_name_zero_index() {
        let name = generate_asset_name("rdp", 0);
        assert!(name.ends_with("001"));
    }

    // ==================== Hostname Generation Edge Cases ====================

    #[test]
    fn test_generate_hostname_uppercase() {
        let hostname = generate_hostname("WEB-SERVER-01", "EXAMPLE.COM");
        // Should lowercase the asset name
        assert!(hostname.starts_with("web-server-01"));
    }

    #[test]
    fn test_generate_hostname_empty_name() {
        let hostname = generate_hostname("", "example.com");
        assert_eq!(hostname, ".example.com");
    }

    #[test]
    fn test_generate_hostname_subdomain() {
        let hostname = generate_hostname("app", "prod.internal.example.com");
        assert_eq!(hostname, "app.prod.internal.example.com");
    }

    // ==================== IP Address Edge Cases ====================

    #[test]
    fn test_generate_ip_address_different_base() {
        let ip = generate_ip_address("172.16.0.0", 0);
        assert_eq!(ip, "172.16.0.1");
    }

    #[test]
    fn test_generate_ip_address_partial_base() {
        let ip = generate_ip_address("10.0", 0);
        assert_eq!(ip, "10.0.0.1");
    }

    #[test]
    fn test_generate_ip_address_single_octet_base() {
        let ip = generate_ip_address("10", 0);
        assert_eq!(ip, "10.0.0.1");
    }

    #[test]
    fn test_generate_ip_address_max_index() {
        let ip = generate_ip_address("10.0.0.0", 253);
        assert_eq!(ip, "10.0.0.254");
    }

    // ==================== Default Port Edge Cases ====================

    #[test]
    fn test_get_default_port_empty() {
        assert_eq!(get_default_port(""), 22);
    }

    #[test]
    fn test_get_default_port_case_sensitive() {
        // Uppercase should not match
        assert_eq!(get_default_port("SSH"), 22);
        assert_eq!(get_default_port("RDP"), 22);
    }

    // ==================== Session Status Edge Cases ====================

    #[test]
    fn test_generate_session_status_all_values() {
        let statuses: Vec<&str> = (0..5).map(generate_session_status).collect();
        assert!(statuses.contains(&"active"));
        assert!(statuses.contains(&"completed"));
        assert!(statuses.contains(&"terminated"));
        assert!(statuses.contains(&"error"));
    }

    #[test]
    fn test_generate_session_status_large_index() {
        // Should still work with large indices
        assert_eq!(generate_session_status(1000), "active");
    }

    // ==================== Approval Status Edge Cases ====================

    #[test]
    fn test_generate_approval_status_all_values() {
        let statuses: Vec<&str> = (0..4).map(generate_approval_status).collect();
        assert!(statuses.contains(&"pending"));
        assert!(statuses.contains(&"approved"));
        assert!(statuses.contains(&"rejected"));
    }

    #[test]
    fn test_generate_approval_status_large_index() {
        // Should still work with large indices
        assert_eq!(generate_approval_status(1000), "pending");
    }
}
