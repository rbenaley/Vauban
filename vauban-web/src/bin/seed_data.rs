/// VAUBAN - Seed Data Generator
/// 
/// Creates test data for development (idempotent):
/// - 5 users (1 admin, 2 staff, 2 regular)
/// - 30 assets (SSH, RDP, VNC)
/// - 30 sessions (including 20 recordings)
/// - 20 approval requests
///
/// This script can be run multiple times without creating duplicates.

use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::PgConnection;
use uuid::Uuid;
use chrono::{Utc, Duration};
use rand::Rng;
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use rand::rngs::OsRng;

// Import schema
mod schema {
    include!("../schema.rs");
}

fn main() {
    dotenv::dotenv().ok();
    
    println!("🚀 VAUBAN Seed Data Generator (Idempotent)");
    println!("==========================================\n");

    // Get database URL
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env file");

    // Create connection pool
    let manager = ConnectionManager::<PgConnection>::new(&database_url);
    let pool = Pool::builder()
        .build(manager)
        .expect("Failed to create database pool");

    let mut conn = pool.get().expect("Failed to get database connection");

    // Create users
    println!("👥 Creating users...");
    let user_ids = create_users(&mut conn);
    println!("   ✅ {} users ready\n", user_ids.len());

    // Get first user id for ownership
    let owner_id = user_ids.first().copied().unwrap_or(1);

    // Create assets
    println!("📦 Creating assets...");
    let asset_ids = create_assets(&mut conn, owner_id);
    println!("   ✅ {} assets ready\n", asset_ids.len());

    // Check existing sessions count
    let existing_sessions: i64 = diesel::sql_query(
        "SELECT COUNT(*) as count FROM proxy_sessions WHERE status != 'pending'"
    )
    .get_result::<CountResult>(&mut conn)
    .map(|r| r.count)
    .unwrap_or(0);

    if existing_sessions < 30 {
        println!("🔗 Creating sessions and recordings...");
        let session_count = create_sessions(&mut conn, &user_ids, &asset_ids, 30 - existing_sessions as i32);
        println!("   ✅ Created {} new sessions (total: {})\n", session_count, existing_sessions + session_count as i64);
    } else {
        println!("🔗 Sessions already exist ({} found), skipping...\n", existing_sessions);
    }

    // Check existing approvals count
    let existing_approvals: i64 = diesel::sql_query(
        "SELECT COUNT(*) as count FROM proxy_sessions WHERE status = 'pending'"
    )
    .get_result::<CountResult>(&mut conn)
    .map(|r| r.count)
    .unwrap_or(0);

    if existing_approvals < 20 {
        println!("📋 Creating approval requests...");
        let approval_count = create_approval_requests(&mut conn, &user_ids, &asset_ids, 20 - existing_approvals as i32);
        println!("   ✅ Created {} new approval requests (total: {})\n", approval_count, existing_approvals + approval_count as i64);
    } else {
        println!("📋 Approval requests already exist ({} found), skipping...\n", existing_approvals);
    }

    // Create user groups
    println!("👥 Creating user groups...");
    let group_count = create_groups(&mut conn);
    println!("   ✅ {} user groups ready\n", group_count);

    // Create asset groups
    println!("📦 Creating asset groups...");
    let asset_group_count = create_asset_groups(&mut conn);
    println!("   ✅ {} asset groups ready\n", asset_group_count);

    println!("🎉 Seed data generation complete!");
    println!("\nSummary:");
    println!("  - {} users", user_ids.len());
    println!("  - {} assets", asset_ids.len());
    println!("  - {} user groups", group_count);
    println!("  - {} asset groups", asset_group_count);
}

/// Hash a password using Argon2.
fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2.hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string()
}

/// Create test users (idempotent).
fn create_users(conn: &mut PgConnection) -> Vec<i32> {
    let mut user_ids = Vec::new();
    
    // Define users: (username, email, first_name, last_name, is_staff, is_superuser)
    let users_data = vec![
        ("admin", "admin@vauban.local", "System", "Administrator", true, true),
        ("operator1", "operator1@vauban.local", "John", "Smith", true, false),
        ("operator2", "operator2@vauban.local", "Jane", "Doe", true, false),
        ("user1", "user1@vauban.local", "Alice", "Martin", false, false),
        ("user2", "user2@vauban.local", "Bob", "Wilson", false, false),
    ];

    let default_password = "SecurePassword123!";
    let password_hash = hash_password(default_password);

    for (username, email, first_name, last_name, is_staff, is_superuser) in users_data {
        // Check if user already exists
        let existing: Option<i32> = diesel::sql_query(format!(
            "SELECT id FROM users WHERE username = '{}' OR email = '{}'",
            username, email
        ))
        .get_result::<UserId>(conn)
        .optional()
        .expect("Failed to query users")
        .map(|u| u.id);

        if let Some(id) = existing {
            user_ids.push(id);
            let role = if is_superuser { "admin" } else if is_staff { "staff" } else { "user" };
            println!("   - {} ({}) already exists", username, role);
            continue;
        }

        // Create new user
        let result = diesel::sql_query(format!(
            "INSERT INTO users (uuid, username, email, password_hash, first_name, last_name, is_active, is_staff, is_superuser, auth_source, preferences)
             VALUES (uuid_generate_v4(), '{}', '{}', '{}', '{}', '{}', true, {}, {}, 'local', '{{}}')
             ON CONFLICT (username) DO NOTHING
             RETURNING id",
            username, email, password_hash, first_name, last_name, is_staff, is_superuser
        ))
        .get_result::<UserId>(conn);

        match result {
            Ok(u) => {
                user_ids.push(u.id);
                let role = if is_superuser { "admin" } else if is_staff { "staff" } else { "user" };
                println!("   - {} ({}) created", username, role);
            }
            Err(e) => {
                eprintln!("   ⚠ Failed to create {}: {}", username, e);
            }
        }
    }

    // Also include existing 'mnemonic' user if present
    let mnemonic_id: Option<i32> = diesel::sql_query(
        "SELECT id FROM users WHERE username = 'mnemonic'"
    )
    .get_result::<UserId>(conn)
    .optional()
    .expect("Failed to query users")
    .map(|u| u.id);

    if let Some(id) = mnemonic_id {
        if !user_ids.contains(&id) {
            user_ids.push(id);
            println!("   - mnemonic (existing) included");
        }
    }

    user_ids
}

/// Create test assets (idempotent).
fn create_assets(conn: &mut PgConnection, admin_id: i32) -> Vec<i32> {
    let mut rng = rand::thread_rng();
    let mut asset_ids = Vec::new();
    let mut created_count = 0;
    let mut existing_count = 0;

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

    for (i, (name, os, desc)) in linux_servers.iter().enumerate() {
        let ip = format!("10.0.{}.{}", (i / 50) + 1, (i % 254) + 1);
        let status = if rng.gen_bool(0.85) { "online" } else { "offline" };
        
        let result = diesel::sql_query(format!(
            "INSERT INTO assets (uuid, name, hostname, ip_address, port, asset_type, status, os_type, os_version, description, created_by_id, require_mfa, require_justification, connection_config)
             VALUES (uuid_generate_v4(), '{}', '{}.vauban.local', '{}', 22, 'ssh', '{}', 'linux', '{}', '{}', {}, {}, {}, '{{}}')
             ON CONFLICT (hostname, port) DO UPDATE SET status = EXCLUDED.status
             RETURNING id",
            name, name, ip, status, os, desc, admin_id,
            rng.gen_bool(0.3), rng.gen_bool(0.2)
        ))
        .get_result::<AssetId>(conn);
        
        if let Ok(asset) = result {
            asset_ids.push(asset.id);
            // Check if it was an insert or update
            let was_update = diesel::sql_query(format!(
                "SELECT created_at < NOW() - INTERVAL '1 second' as existed FROM assets WHERE id = {}",
                asset.id
            ))
            .get_result::<ExistedCheck>(conn)
            .map(|r| r.existed)
            .unwrap_or(false);
            
            if was_update {
                existing_count += 1;
            } else {
                created_count += 1;
                println!("   - {} (SSH, {})", name, status);
            }
        }
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

    for (i, (name, os, desc)) in windows_servers.iter().enumerate() {
        let ip = format!("10.1.{}.{}", (i / 50) + 1, (i % 254) + 1);
        let status = if rng.gen_bool(0.9) { "online" } else { "offline" };
        
        let result = diesel::sql_query(format!(
            "INSERT INTO assets (uuid, name, hostname, ip_address, port, asset_type, status, os_type, os_version, description, created_by_id, require_mfa, require_justification, connection_config)
             VALUES (uuid_generate_v4(), '{}', '{}.vauban.local', '{}', 3389, 'rdp', '{}', 'windows', '{}', '{}', {}, {}, {}, '{{}}')
             ON CONFLICT (hostname, port) DO UPDATE SET status = EXCLUDED.status
             RETURNING id",
            name, name, ip, status, os, desc, admin_id,
            rng.gen_bool(0.5), rng.gen_bool(0.4)
        ))
        .get_result::<AssetId>(conn);
        
        if let Ok(asset) = result {
            asset_ids.push(asset.id);
            let was_update = diesel::sql_query(format!(
                "SELECT created_at < NOW() - INTERVAL '1 second' as existed FROM assets WHERE id = {}",
                asset.id
            ))
            .get_result::<ExistedCheck>(conn)
            .map(|r| r.existed)
            .unwrap_or(false);
            
            if was_update {
                existing_count += 1;
            } else {
                created_count += 1;
                println!("   - {} (RDP, {})", name, status);
            }
        }
    }

    // VNC servers
    let vnc_servers = vec![
        ("kvm-host-01", "Proxmox VE 8", "KVM Hypervisor"),
        ("kvm-host-02", "Proxmox VE 8", "KVM Hypervisor"),
        ("esxi-01", "VMware ESXi 8", "VMware Host"),
        ("network-switch-mgmt", "Custom Linux", "Network Management"),
        ("ilo-server-01", "HP iLO", "Server Management"),
    ];

    for (i, (name, os, desc)) in vnc_servers.iter().enumerate() {
        let ip = format!("10.2.{}.{}", (i / 50) + 1, (i % 254) + 1);
        let status = if rng.gen_bool(0.95) { "online" } else { "maintenance" };
        
        let result = diesel::sql_query(format!(
            "INSERT INTO assets (uuid, name, hostname, ip_address, port, asset_type, status, os_type, os_version, description, created_by_id, require_mfa, require_justification, connection_config)
             VALUES (uuid_generate_v4(), '{}', '{}.vauban.local', '{}', 5900, 'vnc', '{}', 'linux', '{}', '{}', {}, true, true, '{{}}')
             ON CONFLICT (hostname, port) DO UPDATE SET status = EXCLUDED.status
             RETURNING id",
            name, name, ip, status, os, desc, admin_id
        ))
        .get_result::<AssetId>(conn);
        
        if let Ok(asset) = result {
            asset_ids.push(asset.id);
            let was_update = diesel::sql_query(format!(
                "SELECT created_at < NOW() - INTERVAL '1 second' as existed FROM assets WHERE id = {}",
                asset.id
            ))
            .get_result::<ExistedCheck>(conn)
            .map(|r| r.existed)
            .unwrap_or(false);
            
            if was_update {
                existing_count += 1;
            } else {
                created_count += 1;
                println!("   - {} (VNC, {})", name, status);
            }
        }
    }

    if existing_count > 0 {
        println!("   ({} already existed, {} created)", existing_count, created_count);
    }

    asset_ids
}

/// Create test sessions.
fn create_sessions(conn: &mut PgConnection, user_ids: &[i32], asset_ids: &[i32], count: i32) -> i32 {
    let mut rng = rand::thread_rng();
    let mut created = 0;

    if asset_ids.is_empty() || user_ids.is_empty() {
        return 0;
    }

    let statuses = vec!["active", "disconnected", "completed", "terminated"];
    let session_types = vec!["ssh", "rdp", "vnc"];
    let client_ips = vec![
        "192.168.1.10", "192.168.1.25", "192.168.1.100",
        "10.0.0.50", "172.16.0.15", "192.168.2.200"
    ];

    for i in 0..count {
        let user_id = user_ids[rng.gen_range(0..user_ids.len())];
        let asset_id = asset_ids[rng.gen_range(0..asset_ids.len())];
        let status = if i < 3 {
            "active"
        } else {
            statuses[rng.gen_range(0..statuses.len())]
        };
        let session_type = session_types[rng.gen_range(0..session_types.len())];
        let client_ip = client_ips[rng.gen_range(0..client_ips.len())];
        
        let is_recorded = i >= 10;
        let recording_path = if is_recorded {
            Some(format!("/recordings/{}/{}.cast", Utc::now().format("%Y/%m"), Uuid::new_v4()))
        } else {
            None
        };

        let connected_at = Utc::now() - Duration::hours(rng.gen_range(1..720));
        let disconnected_at = if status != "active" {
            Some(connected_at + Duration::minutes(rng.gen_range(5..180)))
        } else {
            None
        };

        let result = diesel::sql_query(format!(
            "INSERT INTO proxy_sessions (uuid, user_id, asset_id, credential_id, credential_username, session_type, status, client_ip, connected_at, disconnected_at, is_recorded, recording_path, bytes_sent, bytes_received, commands_count, justification, metadata)
             VALUES (uuid_generate_v4(), {}, {}, '{}', '{}', '{}', '{}', '{}', '{}', {}, {}, {}, {}, {}, {}, {}, '{{}}')
             RETURNING id",
            user_id, asset_id,
            Uuid::new_v4(), 
            if session_type == "ssh" { "root" } else { "Administrator" },
            session_type, status, client_ip,
            connected_at.format("%Y-%m-%d %H:%M:%S%z"),
            disconnected_at.map(|d| format!("'{}'", d.format("%Y-%m-%d %H:%M:%S%z"))).unwrap_or("NULL".to_string()),
            is_recorded,
            recording_path.map(|p| format!("'{}'", p)).unwrap_or("NULL".to_string()),
            rng.gen_range(1000..1000000),
            rng.gen_range(5000..5000000),
            rng.gen_range(0..500),
            if rng.gen_bool(0.3) { "'Maintenance task'" } else { "NULL" }
        ))
        .execute(conn);

        if result.is_ok() {
            created += 1;
            let rec_str = if is_recorded { " (recorded)" } else { "" };
            println!("   - Session {} [{}]{}", i + 1, status, rec_str);
        }
    }

    created
}

/// Create approval requests.
fn create_approval_requests(conn: &mut PgConnection, user_ids: &[i32], asset_ids: &[i32], count: i32) -> i32 {
    let mut rng = rand::thread_rng();
    let mut created = 0;

    if asset_ids.is_empty() || user_ids.is_empty() {
        return 0;
    }

    let justifications = vec![
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

    let session_types = vec!["ssh", "rdp"];
    let client_ips = vec![
        "192.168.1.50", "192.168.1.75", "192.168.1.150",
        "10.0.0.100", "172.16.0.30"
    ];

    for i in 0..count {
        let user_id = user_ids[rng.gen_range(0..user_ids.len())];
        let asset_id = asset_ids[rng.gen_range(0..asset_ids.len())];
        let session_type = session_types[rng.gen_range(0..session_types.len())];
        let client_ip = client_ips[rng.gen_range(0..client_ips.len())];
        let justification = justifications[rng.gen_range(0..justifications.len())];

        let result = diesel::sql_query(format!(
            "INSERT INTO proxy_sessions (uuid, user_id, asset_id, credential_id, credential_username, session_type, status, client_ip, is_recorded, justification, metadata)
             VALUES (uuid_generate_v4(), {}, {}, '{}', '{}', '{}', 'pending', '{}', true, '{}', '{{\"approval_required\": true}}')
             RETURNING id",
            user_id, asset_id,
            Uuid::new_v4(),
            if session_type == "ssh" { "root" } else { "Administrator" },
            session_type, client_ip, justification
        ))
        .execute(conn);

        if result.is_ok() {
            created += 1;
            println!("   - Approval #{}: {}", i + 1, &justification[..50.min(justification.len())]);
        }
    }

    created
}

/// Create user groups (idempotent).
fn create_groups(conn: &mut PgConnection) -> i32 {
    let mut count = 0;

    // Define groups: (name, description, source)
    let groups_data = vec![
        ("Administrators", "Full system administrators with all permissions", "local"),
        ("Operators", "System operators with limited administrative access", "local"),
        ("Developers", "Development team members", "local"),
        ("Auditors", "Security auditors with read-only access to logs and recordings", "local"),
        ("Support", "Support team with access to user management", "local"),
    ];

    for (name, description, source) in groups_data {
        // Check if group already exists
        let existing: bool = diesel::sql_query(format!(
            "SELECT EXISTS(SELECT 1 FROM vauban_groups WHERE name = '{}') as exists",
            name.replace('\'', "''")
        ))
        .get_result::<ExistsResult>(conn)
        .map(|r| r.exists)
        .unwrap_or(false);

        if existing {
            count += 1;
            println!("   - {} already exists", name);
            continue;
        }

        // Create new group
        let result = diesel::sql_query(format!(
            "INSERT INTO vauban_groups (uuid, name, description, source)
             VALUES (uuid_generate_v4(), '{}', '{}', '{}')
             ON CONFLICT (name) DO NOTHING",
            name.replace('\'', "''"),
            description.replace('\'', "''"),
            source
        ))
        .execute(conn);

        match result {
            Ok(rows) if rows > 0 => {
                count += 1;
                println!("   - {} created", name);
            }
            Ok(_) => {
                count += 1;
                println!("   - {} already exists", name);
            }
            Err(e) => {
                eprintln!("   ⚠ Failed to create {}: {}", name, e);
            }
        }
    }

    count
}

/// Create asset groups (idempotent).
fn create_asset_groups(conn: &mut PgConnection) -> i32 {
    let mut count = 0;

    // Define asset groups: (name, slug, description, color, icon)
    let groups_data = vec![
        ("Production Servers", "production", "Production environment servers", "#EF4444", "server"),
        ("Development Servers", "development", "Development and testing servers", "#3B82F6", "code"),
        ("Database Servers", "databases", "Database servers (PostgreSQL, MySQL, etc.)", "#8B5CF6", "database"),
        ("Network Devices", "network", "Routers, switches, and network equipment", "#10B981", "wifi"),
        ("Windows Workstations", "workstations", "Windows workstations for remote access", "#F59E0B", "desktop"),
    ];

    for (name, slug, description, color, icon) in groups_data {
        // Check if group already exists
        let existing: bool = diesel::sql_query(format!(
            "SELECT EXISTS(SELECT 1 FROM asset_groups WHERE slug = '{}' AND is_deleted = false) as exists",
            slug
        ))
        .get_result::<ExistsResult>(conn)
        .map(|r| r.exists)
        .unwrap_or(false);

        if existing {
            count += 1;
            println!("   - {} already exists", name);
            continue;
        }

        // Create new group
        let result = diesel::sql_query(format!(
            "INSERT INTO asset_groups (uuid, name, slug, description, color, icon)
             VALUES (uuid_generate_v4(), '{}', '{}', '{}', '{}', '{}')
             ON CONFLICT (slug) DO NOTHING",
            name.replace('\'', "''"),
            slug,
            description.replace('\'', "''"),
            color,
            icon
        ))
        .execute(conn);

        match result {
            Ok(rows) if rows > 0 => {
                count += 1;
                println!("   - {} created", name);
            }
            Ok(_) => {
                count += 1;
                println!("   - {} already exists", name);
            }
            Err(e) => {
                eprintln!("   ⚠ Failed to create {}: {}", name, e);
            }
        }
    }

    count
}

// Helper structs for returning data
#[derive(QueryableByName)]
struct AssetId {
    #[diesel(sql_type = diesel::sql_types::Int4)]
    id: i32,
}

#[derive(QueryableByName)]
struct UserId {
    #[diesel(sql_type = diesel::sql_types::Int4)]
    id: i32,
}

#[derive(QueryableByName)]
struct CountResult {
    #[diesel(sql_type = diesel::sql_types::Int8)]
    count: i64,
}

#[derive(QueryableByName)]
struct ExistedCheck {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    existed: bool,
}

#[derive(QueryableByName)]
struct ExistsResult {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    exists: bool,
}
