//! Toasty database connection and seed data.

use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{
    Argon2, PasswordHasher,
    password_hash::{SaltString, rand_core::OsRng},
};
use toasty::Db;

use crate::models::{DocArticle, Issue, Membership, Organization, Release, User};

pub async fn connect(database_url: &str) -> anyhow::Result<Db> {
    let db = Db::builder()
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
        .await?;
    // Scaffold: Toasty `push_schema` is not idempotent. Tolerate an already
    // provisioned database until a real migration story lands.
    if let Err(err) = db.push_schema().await {
        let msg = err.to_string();
        if !msg.contains("already exists") {
            return Err(err.into());
        }
    }
    Ok(db)
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
}
