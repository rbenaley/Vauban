//! Toasty database connection, migrations, and seed data.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{
    Argon2, PasswordHasher,
    password_hash::{SaltString, rand_core::OsRng},
};
use toasty::Db;
use toasty::db::ConnectContext;
use toasty::migration::History;
use toasty::schema::db::Migration;
use toasty_cli::Config as ToastyConfig;

use crate::models::{DocArticle, Issue, Membership, Organization, Release, User};

/// Open a Toasty handle with VCP models registered (no schema changes).
pub async fn open(database_url: &str) -> anyhow::Result<Db> {
    Ok(Db::builder()
        .models(toasty::models!(
            crate::models::User,
            crate::models::AuthSession,
            crate::models::Organization,
            crate::models::Membership,
            crate::models::DocArticle,
            crate::models::Release,
            crate::models::Issue,
        ))
        .connect(database_url)
        .await?)
}

/// Open the database and apply any pending Toasty migrations from `toasty/`.
pub async fn connect(database_url: &str) -> anyhow::Result<Db> {
    let db = open(database_url).await?;
    apply_pending_migrations(&db).await?;
    Ok(db)
}

fn package_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Apply migrations listed in `toasty/history.toml` that are not yet recorded
/// in `__toasty_migrations`. Paths are resolved from the package root so this
/// works regardless of process CWD.
pub async fn apply_pending_migrations(db: &Db) -> anyhow::Result<()> {
    let root = package_root();
    let config = ToastyConfig::load_from(&root.join("Toasty.toml"))?;
    let history_path = root.join(config.migration.get_history_file_path());
    let history = History::load_or_default(&history_path)?;

    if history.entries().is_empty() {
        anyhow::bail!(
            "no Toasty migrations in {}; run: cargo run --bin vcp-cli -- migration generate --name initial",
            history_path.display()
        );
    }

    let migrations_dir = root.join(config.migration.get_migrations_dir());
    let mut conn = db.driver().connect(&ConnectContext::default()).await?;
    let applied = conn.applied_migrations().await?;
    let applied_ids: HashSet<u64> = applied.iter().map(|m| m.id()).collect();

    for entry in history.entries() {
        if applied_ids.contains(&entry.id) {
            continue;
        }
        let path = migrations_dir.join(&entry.name);
        let sql = fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("failed to read migration {}: {e}", path.display()))?;
        let migration = Migration::new_sql(sql);
        conn.apply_migration(entry.id, &entry.name, &migration)
            .await
            .map_err(|e| anyhow::anyhow!("failed to apply {}: {e}", entry.name))?;
        tracing::info!(migration = %entry.name, "applied Toasty migration");
    }

    Ok(())
}

pub async fn seed_if_empty(db: &Db) -> anyhow::Result<()> {
    let mut db = db.clone();
    let users = User::all().exec(&mut db).await?;
    if !users.is_empty() {
        return Ok(());
    }

    let password_hash = hash_password("password")?;

    let admin = toasty::create!(User {
        email: "admin@acme.example".to_owned(),
        display_name: "M. Dubois".to_owned(),
        password_hash: password_hash.clone(),
    })
    .exec(&mut db)
    .await?;

    let member = toasty::create!(User {
        email: "l.martin@acme.example".to_owned(),
        display_name: "L. Martin".to_owned(),
        password_hash,
    })
    .exec(&mut db)
    .await?;

    let org = toasty::create!(Organization {
        slug: "acme-infrastructure".to_owned(),
        name: "ACME Infrastructure".to_owned(),
        address: "12 Rue de la Citadelle, 59000 Lille, France".to_owned(),
        vat: "FR 12 345678901".to_owned(),
        plan_label: "Sovereign plan · Long Term Support (LTS)".to_owned(),
        supported_builds: "LTS 0.8.x".to_owned(),
        lts_subscriptions: 2,
        industrial_lts_subscriptions: 1,
        technical_contact: "support@vauban.sh".to_owned(),
        status: "ACTIVE".to_owned(),
    })
    .exec(&mut db)
    .await?;

    toasty::create!(Membership {
        user_id: admin.id,
        organization_id: org.id,
        role: "admin".to_owned(),
    })
    .exec(&mut db)
    .await?;

    toasty::create!(Membership {
        user_id: member.id,
        organization_id: org.id,
        role: "member".to_owned(),
    })
    .exec(&mut db)
    .await?;

    for (title, summary, category, slug) in [
        (
            "Quick start — deploy Vauban in 15 minutes",
            "Install the bastion, enroll a host, and open a supervised SSH session.",
            "Getting started",
            "quick-start",
        ),
        (
            "Bastion architecture: SSH proxy & RDP gateway",
            "How the control plane, proxies, and audit path fit together.",
            "Getting started",
            "bastion-architecture",
        ),
        (
            "High-availability (HA) deployment",
            "Multi-node layout, failover expectations, and health checks.",
            "Deployment",
            "ha-deployment",
        ),
        (
            "Configuring RBAC: roles, groups, and policies",
            "Casbin model, role nesting, and least-privilege patterns.",
            "Security",
            "configuring-rbac",
        ),
        (
            "Enabling MFA (TOTP, WebAuthn)",
            "Require a second factor for interactive and API access.",
            "Security",
            "enabling-mfa",
        ),
        (
            "Session recording & replay",
            "Retention, storage, and forensic replay of supervised sessions.",
            "Operations",
            "session-recording",
        ),
        (
            "API reference — REST & audit events",
            "Machine endpoints, authentication, and event schemas.",
            "API",
            "api-reference",
        ),
    ] {
        toasty::create!(DocArticle {
            title: title.to_owned(),
            summary: summary.to_owned(),
            category: category.to_owned(),
            slug: slug.to_owned(),
            version: "v1".to_owned(),
            status: "PUBLISHED".to_owned(),
            body: seed_doc_body(slug, summary),
            updated_at: now_unix(),
        })
        .exec(&mut db)
        .await?;
    }

    toasty::create!(Release {
        version: "v1.0.0".to_owned(),
        channel: "LTS".to_owned(),
        released_on: "2026-06-23".to_owned(),
        size_mb: "21.1".to_owned(),
        signature_prefix: "48f1014".to_owned(),
        status: "PUBLISHED".to_owned(),
        notes:
            "FIX: stop newsyslog rotation from killing daemon(8)\nFEAT: expand staff Casbin grants"
                .to_owned(),
    })
    .exec(&mut db)
    .await?;

    toasty::create!(Release {
        version: "v0.8.6".to_owned(),
        channel: "LTS".to_owned(),
        released_on: "2026-06-18".to_owned(),
        size_mb: "20.4".to_owned(),
        signature_prefix: "a91c002".to_owned(),
        status: "PUBLISHED".to_owned(),
        notes: "FIX: proxy reconnect under load\nFIX: audit seal clock skew".to_owned(),
    })
    .exec(&mut db)
    .await?;

    toasty::create!(Issue {
        key: "VBN-214".to_owned(),
        title: "Intermittent SSH proxy latency under heavy load".to_owned(),
        component: "SSH Proxy".to_owned(),
        severity: "Major".to_owned(),
        status: "In analysis".to_owned(),
        organization_id: org.id,
        details: "Seeing intermittent latency spikes on the SSH proxy under load. Happy to share metrics.".to_owned(),
    })
    .exec(&mut db)
    .await?;

    toasty::create!(Issue {
        key: "VBN-208".to_owned(),
        title: "RDP clipboard sync drops large payloads".to_owned(),
        component: "RDP Gateway".to_owned(),
        severity: "Minor".to_owned(),
        status: "Open".to_owned(),
        organization_id: org.id,
        details: "Large clipboard payloads fail to sync over RDP.".to_owned(),
    })
    .exec(&mut db)
    .await?;

    let _ = (admin, member);
    Ok(())
}

/// Top up missing Concept catalog rows when the DB already had a sparse seed.
pub async fn ensure_demo_catalog(db: &Db) -> anyhow::Result<()> {
    let mut db = db.clone();
    let existing = DocArticle::all().exec(&mut db).await?;
    let have: std::collections::HashSet<String> = existing.into_iter().map(|a| a.slug).collect();

    for (title, summary, category, slug) in [
        (
            "Bastion architecture: SSH proxy & RDP gateway",
            "How the control plane, proxies, and audit path fit together.",
            "Getting started",
            "bastion-architecture",
        ),
        (
            "High-availability (HA) deployment",
            "Multi-node layout, failover expectations, and health checks.",
            "Deployment",
            "ha-deployment",
        ),
        (
            "Configuring RBAC: roles, groups, and policies",
            "Casbin model, role nesting, and least-privilege patterns.",
            "Security",
            "configuring-rbac",
        ),
        (
            "Enabling MFA (TOTP, WebAuthn)",
            "Require a second factor for interactive and API access.",
            "Security",
            "enabling-mfa",
        ),
        (
            "Session recording & replay",
            "Retention, storage, and forensic replay of supervised sessions.",
            "Operations",
            "session-recording",
        ),
        (
            "API reference — REST & audit events",
            "Machine endpoints, authentication, and event schemas.",
            "API",
            "api-reference",
        ),
    ] {
        if have.contains(slug) {
            continue;
        }
        toasty::create!(DocArticle {
            title: title.to_owned(),
            summary: summary.to_owned(),
            category: category.to_owned(),
            slug: slug.to_owned(),
            version: "v1".to_owned(),
            status: "PUBLISHED".to_owned(),
            body: seed_doc_body(slug, summary),
            updated_at: now_unix(),
        })
        .exec(&mut db)
        .await?;
    }

    let releases = Release::all().exec(&mut db).await?;
    let have_ver: std::collections::HashSet<String> =
        releases.into_iter().map(|r| r.version).collect();
    for (version, channel, date, size, sig, notes) in [
        (
            "v0.8.6",
            "Stable",
            "2026-06-18",
            "22.2",
            "a3f9c1e",
            "SECURITY: Self-heal CSRF on login after session expiry.",
        ),
        (
            "v0.7.16",
            "Stable",
            "2026-05-22",
            "20.4",
            "7d2b80a",
            "FIX: Stability and security fixes for the SSH proxy.\nRBAC: Support for nested groups in policies.",
        ),
    ] {
        if have_ver.contains(version) {
            continue;
        }
        toasty::create!(Release {
            version: version.to_owned(),
            channel: channel.to_owned(),
            released_on: date.to_owned(),
            size_mb: size.to_owned(),
            signature_prefix: sig.to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: notes.to_owned(),
        })
        .exec(&mut db)
        .await?;
    }

    Ok(())
}

fn seed_doc_body(slug: &str, summary: &str) -> String {
    if slug == "quick-start" {
        return concat!(
            "Vauban ships as a single signed binary. This guide takes you from a fresh host ",
            "to your first end-to-end recorded SSH session in about fifteen minutes.\n\n",
            "1. Install the binary\n",
            "Download the latest LTS build and verify its signature before running it.\n\n",
            "2. Enroll your first target host\n",
            "Register machines by DNS name and assign them to groups.\n\n",
            "3. Define an access policy\n",
            "Map subjects to targets and actions; keep policies narrow.\n\n",
            "4. Open your first session\n",
            "Point SSH at the bastion. Vauban authenticates, enforces MFA, and records the session."
        )
        .to_owned();
    }
    format!("{summary}\n\nFull article body will expand as the knowledge base grows.")
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("argon2 hash failed: {e}"))
}

pub fn verify_password(password: &str, password_hash: &str) -> bool {
    use argon2::{PasswordHash, PasswordVerifier};
    PasswordHash::new(password_hash)
        .ok()
        .and_then(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .ok()
        })
        .is_some()
}

pub fn token_hash_hex(hash: &topcoat::session::TokenHash) -> String {
    hex::encode(**hash)
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_roundtrip() {
        let hash = hash_password("password").expect("hash");
        assert!(verify_password("password", &hash));
        assert!(!verify_password("wrong", &hash));
    }

    #[test]
    fn toasty_migration_tree_is_present() {
        let root = package_root();
        assert!(
            root.join("Toasty.toml").is_file(),
            "Toasty.toml must exist at package root"
        );
        assert!(
            root.join("toasty").join("history.toml").is_file(),
            "toasty/history.toml must exist (run: cargo run --bin vcp-cli -- migration generate)"
        );
        let migrations = root.join("toasty").join("migrations");
        assert!(migrations.is_dir(), "toasty/migrations/ must exist");
        let sql_count = std::fs::read_dir(&migrations)
            .expect("read migrations dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sql"))
            .count();
        assert!(
            sql_count > 0,
            "expected at least one .sql migration under toasty/migrations/"
        );
    }

    #[test]
    fn connect_source_does_not_use_push_schema_scaffold() {
        let src = include_str!("db.rs");
        // Split the needle so this assert body does not match itself.
        let forbidden = format!(".{}(", "push_schema");
        assert!(
            !src.contains(&forbidden),
            "db::connect must use Toasty migrations, not push_schema"
        );
        let scaffold = format!("async fn {}", "ensure_schema_columns");
        assert!(
            !src.contains(&scaffold),
            "scaffold ALTER helper must stay removed"
        );
        assert!(
            src.contains("apply_pending_migrations"),
            "db::connect must apply pending Toasty migrations"
        );
    }
}
