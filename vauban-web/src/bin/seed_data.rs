/// VAUBAN - Seed Data Generator
///
/// Creates test data for development (idempotent):
/// - 5 users (1 admin, 2 staff, 2 regular)
/// - 30 assets (SSH, RDP, VNC)
/// - 30 sessions (including 20 recordings)
/// - 20 approval requests
///
/// This script can be run multiple times without creating duplicates.
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use chrono::{Duration, Utc};
use diesel::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::sql_types::{BigInt, Bool, Integer, Nullable, Text};
use rand::Rng;
use rand::rngs::OsRng;
use uuid::Uuid;
use vauban_web::config::Config;

// Import schema
mod schema {
    include!("../schema.rs");
}

fn main() {
    println!("🚀 VAUBAN Seed Data Generator (Idempotent)");
    println!("==========================================\n");

    // Load configuration from TOML files
    let config = Config::load().expect("Failed to load configuration from config/*.toml");

    // Create connection pool
    let manager = ConnectionManager::<PgConnection>::new(&config.database.url);
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
    use schema::proxy_sessions::dsl::{proxy_sessions, status};
    let existing_sessions: i64 = proxy_sessions
        .filter(status.ne("pending"))
        .count()
        .get_result(&mut conn)
        .unwrap_or(0);

    if existing_sessions < 30 {
        println!("🔗 Creating sessions and recordings...");
        let session_count = create_sessions(
            &mut conn,
            &user_ids,
            &asset_ids,
            30 - existing_sessions as i32,
        );
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
        .unwrap_or(0);

    if existing_approvals < 20 {
        println!("📋 Creating approval requests...");
        let approval_count = create_approval_requests(
            &mut conn,
            &user_ids,
            &asset_ids,
            20 - existing_approvals as i32,
        );
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
    argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string()
}

/// Create test users (idempotent).
fn create_users(conn: &mut PgConnection) -> Vec<i32> {
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
    let password_hash = hash_password(default_password);

    for (username, email, first_name, last_name, is_staff, is_superuser) in users_data {
        // Check if user already exists
        use schema::users::dsl::{users, username as user_username, email as user_email, id as user_id};
        let existing: Option<i32> = users
            .filter(user_username.eq(username).or(user_email.eq(email)))
            .select(user_id)
            .first(conn)
            .optional()
            .expect("Failed to query users");

        if let Some(id) = existing {
            user_ids.push(id);
            let role = if is_superuser {
                "admin"
            } else if is_staff {
                "staff"
            } else {
                "user"
            };
            println!("   - {} ({}) already exists", username, role);
            continue;
        }

        // NOTE: Raw SQL required - uses uuid_generate_v4() and ON CONFLICT (UPSERT)
        let result = diesel::sql_query(
            "INSERT INTO users (uuid, username, email, password_hash, first_name, last_name, is_active, is_staff, is_superuser, auth_source, preferences)
             VALUES (uuid_generate_v4(), $1, $2, $3, $4, $5, true, $6, $7, 'local', '{}')
             ON CONFLICT (username) DO NOTHING
             RETURNING id"
        )
        .bind::<Text, _>(username)
        .bind::<Text, _>(email)
        .bind::<Text, _>(&password_hash)
        .bind::<Text, _>(first_name)
        .bind::<Text, _>(last_name)
        .bind::<Bool, _>(is_staff)
        .bind::<Bool, _>(is_superuser)
        .get_result::<UserId>(conn);

        match result {
            Ok(u) => {
                user_ids.push(u.id);
                let role = if is_superuser {
                    "admin"
                } else if is_staff {
                    "staff"
                } else {
                    "user"
                };
                println!("   - {} ({}) created", username, role);
            }
            Err(e) => {
                eprintln!("   ⚠ Failed to create {}: {}", username, e);
            }
        }
    }

    // Also include existing 'mnemonic' user if present
    use schema::users::dsl::{users, username as user_username, id as user_id};
    let mnemonic_id: Option<i32> = users
        .filter(user_username.eq("mnemonic"))
        .select(user_id)
        .first(conn)
        .optional()
        .expect("Failed to query users");

    if let Some(id) = mnemonic_id {
        if !user_ids.contains(&id) {
            user_ids.push(id);
            println!("   - mnemonic (existing) included");
        }
    }

    user_ids
}

/// Create test assets (idempotent).
/// NOTE: Uses raw SQL for INSERT with uuid_generate_v4(), ON CONFLICT (UPSERT),
/// and NOW() - INTERVAL which cannot be expressed in Diesel DSL.
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
        let status = if rng.gen_bool(0.85) {
            "online"
        } else {
            "offline"
        };

        let hostname = format!("{}.vauban.local", name);
        let require_mfa = rng.gen_bool(0.3);
        let require_justification = rng.gen_bool(0.2);
        let result = diesel::sql_query(
            "INSERT INTO assets (uuid, name, hostname, ip_address, port, asset_type, status, os_type, os_version, description, created_by_id, require_mfa, require_justification, connection_config)
             VALUES (uuid_generate_v4(), $1, $2, $3, 22, 'ssh', $4, 'linux', $5, $6, $7, $8, $9, '{}')
             ON CONFLICT (hostname, port) DO UPDATE SET status = EXCLUDED.status
             RETURNING id"
        )
        .bind::<Text, _>(*name)
        .bind::<Text, _>(&hostname)
        .bind::<Text, _>(&ip)
        .bind::<Text, _>(status)
        .bind::<Text, _>(*os)
        .bind::<Text, _>(*desc)
        .bind::<Integer, _>(admin_id)
        .bind::<Bool, _>(require_mfa)
        .bind::<Bool, _>(require_justification)
        .get_result::<AssetId>(conn);

        if let Ok(asset) = result {
            asset_ids.push(asset.id);
            // Check if it was an insert or update
            let was_update = diesel::sql_query(
                "SELECT created_at < NOW() - INTERVAL '1 second' as existed FROM assets WHERE id = $1"
            )
            .bind::<Integer, _>(asset.id)
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
        let status = if rng.gen_bool(0.9) {
            "online"
        } else {
            "offline"
        };

        let hostname = format!("{}.vauban.local", name);
        let require_mfa = rng.gen_bool(0.5);
        let require_justification = rng.gen_bool(0.4);
        let result = diesel::sql_query(
            "INSERT INTO assets (uuid, name, hostname, ip_address, port, asset_type, status, os_type, os_version, description, created_by_id, require_mfa, require_justification, connection_config)
             VALUES (uuid_generate_v4(), $1, $2, $3, 3389, 'rdp', $4, 'windows', $5, $6, $7, $8, $9, '{}')
             ON CONFLICT (hostname, port) DO UPDATE SET status = EXCLUDED.status
             RETURNING id"
        )
        .bind::<Text, _>(*name)
        .bind::<Text, _>(&hostname)
        .bind::<Text, _>(&ip)
        .bind::<Text, _>(status)
        .bind::<Text, _>(*os)
        .bind::<Text, _>(*desc)
        .bind::<Integer, _>(admin_id)
        .bind::<Bool, _>(require_mfa)
        .bind::<Bool, _>(require_justification)
        .get_result::<AssetId>(conn);

        if let Ok(asset) = result {
            asset_ids.push(asset.id);
            let was_update = diesel::sql_query(
                "SELECT created_at < NOW() - INTERVAL '1 second' as existed FROM assets WHERE id = $1"
            )
            .bind::<Integer, _>(asset.id)
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
        let status = if rng.gen_bool(0.95) {
            "online"
        } else {
            "maintenance"
        };

        let hostname = format!("{}.vauban.local", name);
        let result = diesel::sql_query(
            "INSERT INTO assets (uuid, name, hostname, ip_address, port, asset_type, status, os_type, os_version, description, created_by_id, require_mfa, require_justification, connection_config)
             VALUES (uuid_generate_v4(), $1, $2, $3, 5900, 'vnc', $4, 'linux', $5, $6, $7, true, true, '{}')
             ON CONFLICT (hostname, port) DO UPDATE SET status = EXCLUDED.status
             RETURNING id"
        )
        .bind::<Text, _>(*name)
        .bind::<Text, _>(&hostname)
        .bind::<Text, _>(&ip)
        .bind::<Text, _>(status)
        .bind::<Text, _>(*os)
        .bind::<Text, _>(*desc)
        .bind::<Integer, _>(admin_id)
        .get_result::<AssetId>(conn);

        if let Ok(asset) = result {
            asset_ids.push(asset.id);
            let was_update = diesel::sql_query(
                "SELECT created_at < NOW() - INTERVAL '1 second' as existed FROM assets WHERE id = $1"
            )
            .bind::<Integer, _>(asset.id)
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
        println!(
            "   ({} already existed, {} created)",
            existing_count, created_count
        );
    }

    asset_ids
}

/// Create test sessions.
/// NOTE: Uses raw SQL for INSERT with uuid_generate_v4() and complex date formatting.
fn create_sessions(
    conn: &mut PgConnection,
    user_ids: &[i32],
    asset_ids: &[i32],
    count: i32,
) -> i32 {
    let mut rng = rand::thread_rng();
    let mut created = 0;

    if asset_ids.is_empty() || user_ids.is_empty() {
        return 0;
    }

    let statuses = vec!["active", "disconnected", "completed", "terminated"];
    let session_types = vec!["ssh", "rdp", "vnc"];
    let client_ips = vec![
        "192.168.1.10",
        "192.168.1.25",
        "192.168.1.100",
        "10.0.0.50",
        "172.16.0.15",
        "192.168.2.200",
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
            Some(format!(
                "/recordings/{}/{}.cast",
                Utc::now().format("%Y/%m"),
                Uuid::new_v4()
            ))
        } else {
            None
        };

        let connected_at = Utc::now() - Duration::hours(rng.gen_range(1..720));
        let disconnected_at = if status != "active" {
            Some(connected_at + Duration::minutes(rng.gen_range(5..180)))
        } else {
            None
        };

        let credential_id = Uuid::new_v4().to_string();
        let credential_username = if session_type == "ssh" { "root" } else { "Administrator" };
        let connected_at_str = connected_at.format("%Y-%m-%d %H:%M:%S%z").to_string();
        let disconnected_at_str = disconnected_at.map(|d| d.format("%Y-%m-%d %H:%M:%S%z").to_string());
        let bytes_sent: i64 = rng.gen_range(1000..1000000);
        let bytes_received: i64 = rng.gen_range(5000..5000000);
        let commands_count: i32 = rng.gen_range(0..500);
        let justification: Option<&str> = if rng.gen_bool(0.3) { Some("Maintenance task") } else { None };
        
        let result = diesel::sql_query(
            "INSERT INTO proxy_sessions (uuid, user_id, asset_id, credential_id, credential_username, session_type, status, client_ip, connected_at, disconnected_at, is_recorded, recording_path, bytes_sent, bytes_received, commands_count, justification, metadata)
             VALUES (uuid_generate_v4(), $1, $2, $3, $4, $5, $6, $7, $8::timestamptz, $9::timestamptz, $10, $11, $12, $13, $14, $15, '{}')
             RETURNING id"
        )
        .bind::<Integer, _>(user_id)
        .bind::<Integer, _>(asset_id)
        .bind::<Text, _>(&credential_id)
        .bind::<Text, _>(credential_username)
        .bind::<Text, _>(session_type)
        .bind::<Text, _>(status)
        .bind::<Text, _>(client_ip)
        .bind::<Text, _>(&connected_at_str)
        .bind::<Nullable<Text>, _>(disconnected_at_str.as_deref())
        .bind::<Bool, _>(is_recorded)
        .bind::<Nullable<Text>, _>(recording_path.as_deref())
        .bind::<BigInt, _>(bytes_sent)
        .bind::<BigInt, _>(bytes_received)
        .bind::<Integer, _>(commands_count)
        .bind::<Nullable<Text>, _>(justification)
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
/// NOTE: Uses raw SQL for INSERT with uuid_generate_v4().
fn create_approval_requests(
    conn: &mut PgConnection,
    user_ids: &[i32],
    asset_ids: &[i32],
    count: i32,
) -> i32 {
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
        "192.168.1.50",
        "192.168.1.75",
        "192.168.1.150",
        "10.0.0.100",
        "172.16.0.30",
    ];

    for i in 0..count {
        let user_id = user_ids[rng.gen_range(0..user_ids.len())];
        let asset_id = asset_ids[rng.gen_range(0..asset_ids.len())];
        let session_type = session_types[rng.gen_range(0..session_types.len())];
        let client_ip = client_ips[rng.gen_range(0..client_ips.len())];
        let justification = justifications[rng.gen_range(0..justifications.len())];

        let credential_id = Uuid::new_v4().to_string();
        let credential_username = if session_type == "ssh" { "root" } else { "Administrator" };
        
        let result = diesel::sql_query(
            "INSERT INTO proxy_sessions (uuid, user_id, asset_id, credential_id, credential_username, session_type, status, client_ip, is_recorded, justification, metadata)
             VALUES (uuid_generate_v4(), $1, $2, $3, $4, $5, 'pending', $6, true, $7, '{\"approval_required\": true}')
             RETURNING id"
        )
        .bind::<Integer, _>(user_id)
        .bind::<Integer, _>(asset_id)
        .bind::<Text, _>(&credential_id)
        .bind::<Text, _>(credential_username)
        .bind::<Text, _>(session_type)
        .bind::<Text, _>(client_ip)
        .bind::<Text, _>(justification)
        .execute(conn);

        if result.is_ok() {
            created += 1;
            println!(
                "   - Approval #{}: {}",
                i + 1,
                &justification[..50.min(justification.len())]
            );
        }
    }

    created
}

/// Create user groups (idempotent).
/// NOTE: Uses raw SQL for INSERT with uuid_generate_v4() and ON CONFLICT.
/// EXISTS check has been migrated to Diesel DSL.
fn create_groups(conn: &mut PgConnection) -> i32 {
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

    for (name, description, source) in groups_data {
        // Check if group already exists
        use diesel::dsl::exists;
        use schema::vauban_groups::dsl::{vauban_groups, name as group_name};
        let existing: bool = diesel::select(exists(
            vauban_groups.filter(group_name.eq(name))
        ))
        .get_result(conn)
        .unwrap_or(false);

        if existing {
            count += 1;
            println!("   - {} already exists", name);
            continue;
        }

        // Create new group
        let result = diesel::sql_query(
            "INSERT INTO vauban_groups (uuid, name, description, source)
             VALUES (uuid_generate_v4(), $1, $2, $3)
             ON CONFLICT (name) DO NOTHING"
        )
        .bind::<Text, _>(name)
        .bind::<Text, _>(description)
        .bind::<Text, _>(source)
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
/// NOTE: Uses raw SQL for INSERT with uuid_generate_v4() and ON CONFLICT.
fn create_asset_groups(conn: &mut PgConnection) -> i32 {
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

    for (name, slug, description, color, icon) in groups_data {
        // Check if group already exists
        use diesel::dsl::exists;
        use schema::asset_groups::dsl::{asset_groups, slug as group_slug, is_deleted};
        let existing: bool = diesel::select(exists(
            asset_groups.filter(group_slug.eq(slug)).filter(is_deleted.eq(false))
        ))
        .get_result(conn)
        .unwrap_or(false);

        if existing {
            count += 1;
            println!("   - {} already exists", name);
            continue;
        }

        // Create new group
        let result = diesel::sql_query(
            "INSERT INTO asset_groups (uuid, name, slug, description, color, icon)
             VALUES (uuid_generate_v4(), $1, $2, $3, $4, $5)
             ON CONFLICT (slug) DO NOTHING"
        )
        .bind::<Text, _>(name)
        .bind::<Text, _>(slug)
        .bind::<Text, _>(description)
        .bind::<Text, _>(color)
        .bind::<Text, _>(icon)
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

// NOTE: CountResult and ExistsResult removed - migrated to Diesel DSL

#[derive(QueryableByName)]
struct ExistedCheck {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    existed: bool,
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
