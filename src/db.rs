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

    toasty::create!(DocArticle {
        title: "Quick start — deploy Vauban in 15 minutes".to_owned(),
        summary: "Install the bastion, enroll a host, and open a supervised SSH session."
            .to_owned(),
        category: "Getting started".to_owned(),
        slug: "quick-start".to_owned(),
        version: "v1".to_owned(),
        status: "PUBLISHED".to_owned(),
    })
    .exec(&mut db)
    .await?;

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

    let _ = (admin, member);
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
