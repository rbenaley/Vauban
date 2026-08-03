//! Toasty database connection, migrations, and seed data.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use toasty::Db;
use toasty::db::ConnectContext;
use toasty::migration::History;
use toasty::schema::db::Migration;
use toasty_cli::Config as ToastyConfig;

use crate::docs_body;
use crate::models::{
    DocArticle, ISSUE_COMMENT_KIND_COMMENT, ISSUE_COMMENT_KIND_STATUS, ISSUE_ROLE_SYSTEM, Issue,
    IssueComment, MEMBERSHIP_ROLE_ORG, Membership, Organization, PORTAL_ROLE_ORG,
    RELEASE_GA_ORG_ID, RESERVED_ORG_SLUG, Release, USER_NOT_DELETED, User,
};
use crate::release_pkg::{size_mb_from_bytes, version_sort_fields};

/// GA release catalog: (version, channel, released_on, bytes, sha256, notes).
fn ga_release_catalog() -> Vec<(
    &'static str,
    &'static str,
    &'static str,
    u64,
    &'static str,
    &'static str,
)> {
    vec![
        (
            "v1.0.2",
            "LTS",
            "2026-07-11",
            22_518_584,
            "ccff72c653fc1ad3ea4bc41fe4e56df03daa990b914017c7ab3419315bca6657",
            "FIX: LTS maintenance release",
        ),
        (
            "v1.0.1",
            "LTS",
            "2026-07-10",
            22_565_449,
            "9fef561cfde2aa3634de40ff3530d55072bd75ad9ae531faaff01c3d786c8336",
            "FIX: LTS maintenance release",
        ),
        (
            "v1.0.0",
            "LTS",
            "2026-07-02",
            22_419_122,
            "c2b1f7dfa88ec9b77eb19dfaefe70ff25a75bb6877191f84609c637a75d2fc26",
            "FIX: stop newsyslog rotation from killing daemon(8)\nFEAT: expand staff Casbin grants",
        ),
        (
            "v0.9.35",
            "Stable",
            "2026-07-30",
            23_384_585,
            "f4845978eb3adeab48cf20111c32cca46d5bbdad3e81b182e20168d55c33f9b8",
            "FIX: Stable channel updates",
        ),
        (
            "v0.9.31",
            "Stable",
            "2026-07-24",
            23_711_290,
            "db1e937d4dccd708a4505367f7daaffafb83deb9c1c31b5b140b151e8517a2a3",
            "FIX: Stable channel updates",
        ),
        (
            "v0.9.29",
            "Stable",
            "2026-07-24",
            23_707_797,
            "809fdc120a32e6b906967d0c69f2dafc08ce9ac37962e30de8ff030f48b704f0",
            "FIX: Stable channel updates",
        ),
        (
            "v0.9.24",
            "Stable",
            "2026-07-22",
            22_845_321,
            "1779cf43e0b4c76d2c0e070a72685fcad6560fbfe1985da03685f183bc675fc2",
            "FIX: Stable channel updates",
        ),
        (
            "v0.9.20",
            "Stable",
            "2026-07-21",
            22_801_871,
            "41174fe54c62ebc6d68f0a3d021e7d0c70f5c0663dcb57d6e5b2749b8b37ebf7",
            "FIX: Stable channel updates",
        ),
        (
            "v0.9.12",
            "Stable",
            "2026-07-19",
            23_404_786,
            "c4d0b4567dfb54b9732c671b81c7bfff2e5fb40502484f9a962cf22d4beac951",
            "FIX: Stable channel updates",
        ),
        (
            "v0.9.4",
            "Stable",
            "2026-07-16",
            23_157_411,
            "1a6a9aaaab06775fdb7e2166bfa67b6d0e8f7b6ddd5516a04a44c82f070c46ec",
            "FIX: Stable channel updates",
        ),
        (
            "v0.8.7",
            "EOL",
            "2026-06-21",
            22_174_281,
            "0b63eb91c92807e729fb50d51f11c5e15d2b947093510c96243ec9a0b149541f",
            "FIX: EOL maintenance",
        ),
        (
            "v0.8.6",
            "EOL",
            "2026-06-18",
            22_160_844,
            "d896decde9ad8b2c280690e17339698f5a6d05dd63a175e050d17b76e8f6d04e",
            "FIX: proxy reconnect under load\nFIX: audit seal clock skew",
        ),
        (
            "v0.7.16",
            "EOL",
            "2026-05-22",
            20_366_875,
            "4af82df6b9c11bf1cbf98218b3f546b11e0fe0865cd790015f880ac010f28d1a",
            "FIX: Stability and security fixes for the SSH proxy.\nRBAC: Support for nested groups in policies.",
        ),
        (
            "v0.7.4",
            "EOL",
            "2026-05-05",
            17_824_584,
            "5ee0400cae292f52c0a5b6997aa1a1061cbeb40a195683bae5419b74a583a01b",
            "FIX: EOL maintenance",
        ),
        (
            "v0.7.2",
            "EOL",
            "2026-05-02",
            17_794_160,
            "cdcd9320d6f4580dfb014ac65737964a85c55be3fbb3412be05b1a1f1536987d",
            "FIX: EOL maintenance",
        ),
        (
            "v0.6.6",
            "EOL",
            "2026-04-16",
            16_418_804,
            "ff5c7a1ac6891b1ec21c2834195ff8dce87ce226f9fb2d55fe5b1ac27197c85f",
            "FIX: EOL maintenance",
        ),
        (
            "v0.6.3",
            "EOL",
            "2026-04-07",
            15_998_560,
            "1162337c51c098843e7d0d188070f97f342dfa3a3eb4c430af8e2a580264f3ac",
            "FIX: EOL maintenance",
        ),
        (
            "v0.6.2",
            "EOL",
            "2026-04-04",
            16_341_114,
            "89ad28ceec0e69d6d1aaaf9fdb33f6d5d83542824e11fc574700662e33aeef03",
            "FIX: EOL maintenance",
        ),
        (
            "v0.6.0",
            "EOL",
            "2026-03-31",
            16_291_798,
            "92003c333f95da1cbab7f0576a0e73f666819e76d14ca2391d52bd8691531f97",
            "FIX: EOL maintenance",
        ),
        (
            "v0.5.0",
            "EOL",
            "2026-03-24",
            16_120_496,
            "eb87260fb16ca749865ecc7ba2fdbe1be9d59a7489226d1b0a264bd7773605de",
            "FIX: EOL maintenance",
        ),
        (
            "v0.3.0",
            "EOL",
            "2026-03-15",
            16_416_713,
            "eeeca7b8b74230363a0ff4f0d72dbddf94c7ea0435bf233c8379fe42be04b531",
            "FIX: EOL maintenance",
        ),
        (
            "v0.2.1",
            "EOL",
            "2026-03-08",
            15_570_229,
            "8635616d7aeca08e7b3815a28c4bd56106b3e4897d7c2698da18dc6bc6f3b5d5",
            "FIX: EOL maintenance",
        ),
        (
            "v0.2.0",
            "EOL",
            "2026-03-06",
            15_306_594,
            "9c404b9a11a18dc7afed63acb87aff355cd53a6d3e1425ffc87d3f448aabe93e",
            "FIX: EOL maintenance",
        ),
    ]
}

/// Invented 64-hex digest for the org-private Acme hotfix package.
/// Keeps the legacy `b7e4d01` prefix from the old signature_prefix seed.
const ACME_PRIVATE_SHA256: &str =
    "b7e4d01c9e2a4f8b1d6c0e5a3f7b9d2e4c8a1f0b6d5e3c9a7f2b8d4e0c1a6953";

const ACME_PRIVATE_VERSION: &str = "v0.8.6-acme1";
const ACME_ORG_SLUG: &str = "acme-infrastructure";

async fn upsert_ga_releases(db: &mut Db) -> anyhow::Result<()> {
    let existing = Release::all().exec(db).await?;
    let mut by_ver: std::collections::HashMap<String, Release> = existing
        .into_iter()
        .filter(|r| r.organization_id == RELEASE_GA_ORG_ID)
        .map(|r| (r.version.clone(), r))
        .collect();

    for (version, channel, date, bytes, sha, notes) in ga_release_catalog() {
        let size = size_mb_from_bytes(bytes);
        let sort = version_sort_fields(version);
        if let Some(mut rel) = by_ver.remove(version) {
            rel.update()
                .channel(channel.to_owned())
                .released_on(date.to_owned())
                .size_mb(size)
                .sha256(sha.to_owned())
                .status("PUBLISHED".to_owned())
                .notes(notes.to_owned())
                .v_major(sort.v_major)
                .v_minor(sort.v_minor)
                .v_patch(sort.v_patch)
                .has_client_suffix(sort.has_client_suffix)
                .client_suffix(sort.client_suffix.clone())
                .exec(db)
                .await?;
        } else {
            toasty::create!(Release {
                version: version.to_owned(),
                channel: channel.to_owned(),
                released_on: date.to_owned(),
                size_mb: size,
                sha256: sha.to_owned(),
                status: "PUBLISHED".to_owned(),
                notes: notes.to_owned(),
                organization_id: RELEASE_GA_ORG_ID,
                v_major: sort.v_major,
                v_minor: sort.v_minor,
                v_patch: sort.v_patch,
                has_client_suffix: sort.has_client_suffix,
                client_suffix: sort.client_suffix,
            })
            .exec(db)
            .await?;
        }
    }
    Ok(())
}

/// Upsert the Acme-private hotfix so existing demo DBs replace the legacy
/// 7-char `signature_prefix` with a full SHA-256 digest.
async fn upsert_acme_private_release(db: &mut Db) -> anyhow::Result<()> {
    let orgs = Organization::all().exec(db).await?;
    let Some(org) = orgs
        .into_iter()
        .find(|o| o.slug.eq_ignore_ascii_case(ACME_ORG_SLUG))
    else {
        return Ok(());
    };

    let existing = Release::all().exec(db).await?;
    let sort = version_sort_fields(ACME_PRIVATE_VERSION);
    if let Some(mut rel) = existing
        .into_iter()
        .find(|r| r.version == ACME_PRIVATE_VERSION)
    {
        rel.update()
            .channel("EOL".to_owned())
            .released_on("2026-06-20".to_owned())
            .size_mb("20.5".to_owned())
            .sha256(ACME_PRIVATE_SHA256.to_owned())
            .status("PUBLISHED".to_owned())
            .notes("HOTFIX: Acme-only proxy backpressure patch".to_owned())
            .organization_id(org.id)
            .v_major(sort.v_major)
            .v_minor(sort.v_minor)
            .v_patch(sort.v_patch)
            .has_client_suffix(sort.has_client_suffix)
            .client_suffix(sort.client_suffix.clone())
            .exec(db)
            .await?;
    } else {
        toasty::create!(Release {
            version: ACME_PRIVATE_VERSION.to_owned(),
            channel: "EOL".to_owned(),
            released_on: "2026-06-20".to_owned(),
            size_mb: "20.5".to_owned(),
            sha256: ACME_PRIVATE_SHA256.to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "HOTFIX: Acme-only proxy backpressure patch".to_owned(),
            organization_id: org.id,
            v_major: sort.v_major,
            v_minor: sort.v_minor,
            v_patch: sort.v_patch,
            has_client_suffix: sort.has_client_suffix,
            client_suffix: sort.client_suffix,
        })
        .exec(db)
        .await?;
    }
    Ok(())
}

/// Recompute `v_*` / `client_suffix` from `version` for every release row.
pub async fn resync_release_sort_keys(db: &Db) -> anyhow::Result<()> {
    let mut conn = db.clone();
    let releases = Release::all().exec(&mut conn).await?;
    for mut rel in releases {
        let sort = version_sort_fields(&rel.version);
        if rel.v_major == sort.v_major
            && rel.v_minor == sort.v_minor
            && rel.v_patch == sort.v_patch
            && rel.has_client_suffix == sort.has_client_suffix
            && rel.client_suffix == sort.client_suffix
        {
            continue;
        }
        rel.update()
            .v_major(sort.v_major)
            .v_minor(sort.v_minor)
            .v_patch(sort.v_patch)
            .has_client_suffix(sort.has_client_suffix)
            .client_suffix(sort.client_suffix)
            .exec(&mut conn)
            .await?;
    }
    Ok(())
}

/// Open a Toasty handle with VCP models registered (no schema changes).
pub async fn open(database_url: &str) -> anyhow::Result<Db> {
    Ok(Db::builder()
        .models(toasty::models!(
            crate::models::User,
            crate::models::AuthSession,
            crate::models::MagicLinkToken,
            crate::models::Organization,
            crate::models::Membership,
            crate::models::DocArticle,
            crate::models::Release,
            crate::models::Issue,
            crate::models::IssueComment,
            crate::models::EphemeralDownload,
        ))
        .connect(database_url)
        .await?)
}

/// Open the database and apply any pending Toasty migrations from `toasty/`.
pub async fn connect(database_url: &str) -> anyhow::Result<Db> {
    let db = open(database_url).await?;
    apply_pending_migrations(&db).await?;
    resync_release_sort_keys(&db).await?;
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

    // Staff (`vcp_admin`) is JIT-created on first magic-link login — not seeded.
    let member = toasty::create!(User {
        email: "l.martin@acme.example".to_owned(),
        display_name: "L. Martin".to_owned(),
        portal_role: PORTAL_ROLE_ORG.to_owned(),
        deleted_at: USER_NOT_DELETED,
    })
    .exec(&mut db)
    .await?;

    let _vauban = toasty::create!(Organization {
        slug: RESERVED_ORG_SLUG.to_owned(),
        name: "Vauban".to_owned(),
        address: "Vauban — reserved preview tenant".to_owned(),
        vat: "BE0508613560".to_owned(),
        plan_label: "Internal · Vauban Support".to_owned(),
        supported_builds: "LTS".to_owned(),
        lts_subscriptions: 0,
        industrial_lts_subscriptions: 0,
        technical_contact_name: "Vauban Support".to_owned(),
        technical_contact_email: "support@vauban.sh".to_owned(),
        status: "INTERNAL".to_owned(),
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
        technical_contact_name: "L. Martin".to_owned(),
        technical_contact_email: "l.martin@acme.example".to_owned(),
        status: "ACTIVE".to_owned(),
    })
    .exec(&mut db)
    .await?;

    toasty::create!(Membership {
        user_id: member.id,
        organization_id: org.id,
        role: MEMBERSHIP_ROLE_ORG.to_owned(),
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

    upsert_ga_releases(&mut db).await?;
    upsert_acme_private_release(&mut db).await?;

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
        author_user_id: 0,
        author_role: ISSUE_ROLE_SYSTEM.to_owned(),
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

    upsert_ga_releases(&mut db).await?;
    upsert_acme_private_release(&mut db).await?;

    refresh_thin_doc_bodies(&mut db).await?;
    ensure_demo_issue_comments(&mut db).await?;
    Ok(())
}

#[cfg(test)]
mod seed_digest_tests {
    use super::ACME_PRIVATE_SHA256;

    #[test]
    fn acme_private_sha256_is_full_digest() {
        assert_eq!(ACME_PRIVATE_SHA256.len(), 64);
        assert!(
            ACME_PRIVATE_SHA256.chars().all(|c| c.is_ascii_hexdigit()),
            "must be hex: {ACME_PRIVATE_SHA256}"
        );
        assert!(
            ACME_PRIVATE_SHA256.starts_with("b7e4d01"),
            "keep legacy signature_prefix seed prefix"
        );
    }
}

/// Backfill demo discussion rows for seeded issues that have none yet.
async fn ensure_demo_issue_comments(db: &mut Db) -> anyhow::Result<()> {
    let issues = Issue::all().exec(db).await?;
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
                author_user_id: 0,
                author_role: ISSUE_ROLE_SYSTEM.to_owned(),
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
