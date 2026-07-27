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

use crate::docs_body;
use crate::models::{
    DocArticle, ISSUE_COMMENT_KIND_COMMENT, ISSUE_COMMENT_KIND_STATUS, ISSUE_ROLE_SUPPORT,
    ISSUE_ROLE_SYSTEM, Issue, IssueComment, Membership, Organization, Release, User,
};

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
            crate::models::IssueComment,
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

    let now = now_unix();
    let issue_214 = toasty::create!(Issue {
        key: "VBN-214".to_owned(),
        title: "Intermittent SSH proxy latency under heavy load".to_owned(),
        component: "SSH Proxy".to_owned(),
        severity: "Major".to_owned(),
        status: "In analysis".to_owned(),
        organization_id: org.id,
        details: "Seeing intermittent latency spikes on the SSH proxy under load. Happy to share metrics.".to_owned(),
        opened_by_user_id: member.id,
        created_at: now - 86_400,
        updated_at: now - 7_200,
    })
    .exec(&mut db)
    .await?;

    toasty::create!(IssueComment {
        issue_id: issue_214.id,
        author_user_id: 0,
        author_role: ISSUE_ROLE_SYSTEM.to_owned(),
        body: "Moved to analysis".to_owned(),
        kind: ISSUE_COMMENT_KIND_STATUS.to_owned(),
        created_at: now - 10_800,
    })
    .exec(&mut db)
    .await?;

    toasty::create!(IssueComment {
        issue_id: issue_214.id,
        author_user_id: admin.id,
        author_role: ISSUE_ROLE_SUPPORT.to_owned(),
        body: "Thanks — we are correlating proxy latency with concurrent session count. Initial analysis underway.".to_owned(),
        kind: ISSUE_COMMENT_KIND_COMMENT.to_owned(),
        created_at: now - 7_200,
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
        opened_by_user_id: member.id,
        created_at: now - 172_800,
        updated_at: now - 172_800,
    })
    .exec(&mut db)
    .await?;

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

    refresh_thin_doc_bodies(&mut db).await?;
    ensure_demo_issue_comments(&mut db).await?;
    Ok(())
}

/// Backfill demo discussion rows for seeded issues that have none yet.
async fn ensure_demo_issue_comments(db: &mut Db) -> anyhow::Result<()> {
    let issues = Issue::all().exec(db).await?;
    let users = User::all().exec(db).await?;
    let admin_id = users
        .iter()
        .find(|u| u.email == "admin@acme.example")
        .map(|u| u.id)
        .unwrap_or(0);
    let now = now_unix();

    for issue in issues {
        let comments = IssueComment::all()
            .filter(IssueComment::fields().issue_id().eq(issue.id))
            .exec(db)
            .await?;
        if !comments.is_empty() {
            continue;
        }
        if issue.status.eq_ignore_ascii_case("In analysis") {
            toasty::create!(IssueComment {
                issue_id: issue.id,
                author_user_id: 0,
                author_role: ISSUE_ROLE_SYSTEM.to_owned(),
                body: "Moved to analysis".to_owned(),
                kind: ISSUE_COMMENT_KIND_STATUS.to_owned(),
                created_at: issue.updated_at.saturating_sub(3_600).max(issue.created_at),
            })
            .exec(db)
            .await?;
            toasty::create!(IssueComment {
                issue_id: issue.id,
                author_user_id: admin_id,
                author_role: ISSUE_ROLE_SUPPORT.to_owned(),
                body: "Thanks — we are correlating proxy latency with concurrent session count. Initial analysis underway.".to_owned(),
                kind: ISSUE_COMMENT_KIND_COMMENT.to_owned(),
                created_at: issue.updated_at.max(now.saturating_sub(7_200)),
            })
            .exec(db)
            .await?;
        }
    }
    Ok(())
}

/// Replace pre-dialect thin bodies so existing local DBs pick up rich content.
async fn refresh_thin_doc_bodies(db: &mut Db) -> anyhow::Result<()> {
    let articles = DocArticle::all()
        .include(DocArticle::fields().body())
        .exec(db)
        .await?;
    for mut article in articles {
        let body = article.body.get().clone();
        if !docs_body::is_thin_seed_body(&body, &article.summary) {
            continue;
        }
        let rich = seed_doc_body(&article.slug, &article.summary);
        article
            .update()
            .body(rich)
            .updated_at(now_unix())
            .exec(db)
            .await?;
    }
    Ok(())
}

fn seed_doc_body(slug: &str, summary: &str) -> String {
    match slug {
        "quick-start" => QUICK_START_BODY.to_owned(),
        "bastion-architecture" => format!(
            "{summary}\n\n\
             # Control plane\n\n\
             The bastion brokers every session. Proxies terminate client connections and \
             open supervised channels to enrolled targets.\n\n\
             ::: callout\n\
             No agent is installed on protected machines — policy is enforced at the bastion.\n\
             :::\n\n\
             # Audit path\n\n\
             Session recordings and audit events are sealed for later replay from the portal."
        ),
        "ha-deployment" => format!(
            "{summary}\n\n\
             # Topology\n\n\
             Run at least two bastion nodes behind a TCP load balancer. Shared policy store \
             and session metadata keep failover within SLA.\n\n\
             ```\n\
             # health check\n\
             curl -fsS https://bastion.example/healthz\n\
             ```\n\n\
             ::: callout\n\
             Sticky sessions are not required for SSH; reconnects re-authenticate through MFA.\n\
             :::"
        ),
        "configuring-rbac" => format!(
            "{summary}\n\n\
             # Subjects and targets\n\n\
             Bind roles to groups, then map groups to target sets. Prefer nested groups over \
             one-off user grants.\n\n\
             ```\n\
             policy \"oncall-prod\" {{\n\
               subjects = [\"group:on-call\"]\n\
               targets  = [\"group:production\"]\n\
               actions  = [\"ssh:shell\"]\n\
             }}\n\
             ```"
        ),
        "enabling-mfa" => format!(
            "{summary}\n\n\
             # Factors\n\n\
             Require TOTP or WebAuthn for interactive shells. API tokens remain scoped and short-lived.\n\n\
             ::: callout\n\
             Privileged sessions should prefer hardware-backed WebAuthn keys.\n\
             :::"
        ),
        "session-recording" => format!(
            "{summary}\n\n\
             # Retention\n\n\
             Recordings follow your subscription retention window. Export to SIEM via webhook when needed.\n\n\
             - Full TTY stream is sealed and searchable\n\
             - Replay is available from the customer portal\n\
             - Retention defaults are plan-specific"
        ),
        "api-reference" => format!(
            "{summary}\n\n\
             # Authentication\n\n\
             Machine endpoints use bearer tokens issued from the portal. Audit events are JSON over HTTPS.\n\n\
             ```\n\
             curl -H \"Authorization: Bearer $TOKEN\" \\\n\
               https://portal.example/api/v1/audit/events\n\
             ```"
        ),
        _ => format!(
            "{summary}\n\n\
             # Overview\n\n\
             {summary}\n\n\
             ::: callout\n\
             Initial analysis and support follow your subscription SLA (2-5 business days).\n\
             :::"
        ),
    }
}

const QUICK_START_BODY: &str = r#"Vauban ships as a single signed binary. This guide takes you from a fresh host to your first end-to-end recorded SSH session in about fifteen minutes. No agent is installed on the protected machines — every connection is brokered by the bastion.

::: callout
You will need: a Linux or FreeBSD host with 2 vCPU / 2 GB RAM, outbound access to your target hosts, and a DNS record pointing at the bastion.
:::

# 1. Install the binary

Download the latest LTS build for your platform and verify its signature before running it. The checksum is published alongside each release in the customer portal.

```
$ curl -fsSLO https://vauban.sh/releases/freebsd/15/x86_64/vauban-0.8.6
$ vauban verify ./vauban-0.8.6
  signature: OK (key 0xA3F9C1E...)
$ install -m 0755 vauban-0.8.6 /usr/local/bin/vauban
```

Initialize the server. This generates the host keys, the local policy store, and an admin enrollment token printed once to stdout.

```
$ vauban server init --domain bastion.acme.internal
  [ok] host keys generated
  [ok] policy store created at /var/db/vauban
  admin token: vbn_enroll_8f3a...  (valid 30 min)
```

# 2. Enroll your first target host

A target is any machine your users will reach through the bastion. Register it by address and assign it to a group — groups are what RBAC policies bind to.

```
$ vauban host add db-01.acme.internal \
    --group production \
    --protocol ssh
```

- Use stable DNS names rather than IP addresses so policies survive re-addressing.
- Group by blast radius (production, staging, pci) — not by team.
- A host can belong to several groups; the most restrictive policy wins.

# 3. Define an access policy

Policies map subjects to the targets and actions they may use. Keep them narrow and compose by inheritance.

```
policy "oncall-prod" {
  subjects = ["group:on-call"]
  targets  = ["group:production"]
  actions  = ["ssh:shell"]
  record   = true
  mfa      = "required"
}
```

::: callout
With record = true, every keystroke and the full TTY stream are captured and signed for audit. Recordings are searchable from the portal.
:::

# 4. Open your first session

Point your SSH client at the bastion. Vauban authenticates you, enforces MFA, applies the policy, then transparently proxies you to the target while recording the session.

```
$ ssh db-01.acme.internal@bastion.acme.internal
  > MFA: approve push on your device... [ok]
  > policy oncall-prod matched · recording on
  Last login: Fri Jun 20 14:02 2026
  db-01 $
```

# Next steps

- Enable WebAuthn hardware keys for privileged sessions.
- Wire audit events to your SIEM via native export or webhooks.
- Deploy a second node behind a TCP load balancer for high availability.
"#;

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
