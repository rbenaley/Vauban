//! Shared harness for `vcp_test` integration suites.

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use toasty::Db;
use tokio::sync::Mutex;
use topcoat::router::{Body, Method, Request, Response, Router, StatusCode};
use vcp::{
    app,
    auth::persist_session_record,
    config::{Config, Environment},
    db::{self, hash_password, now_unix},
    models::{AuthSession, DocArticle, Issue, Membership, Organization, Release, User},
    perms::PolicyStore,
};

static TRACING: OnceLock<()> = OnceLock::new();
static CRYPTO: OnceLock<()> = OnceLock::new();
static DB_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static SCHEMA_READY: OnceLock<()> = OnceLock::new();

/// Absolute HTTPS origin used so `__Host-` / `Secure` session cookies apply.
pub const TEST_ORIGIN: &str = "https://127.0.0.1:3001";

fn ensure_tracing() {
    TRACING.get_or_init(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error")),
            )
            .with_test_writer()
            .try_init();
    });
}

/// Install the rustls crypto provider once per test process.
pub fn install_crypto_once() {
    CRYPTO.get_or_init(|| {
        let _ = vcp::tls::install_crypto_provider();
    });
}

pub fn config_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config")
}

pub async fn test_config() -> Config {
    ensure_tracing();
    Config::load_with_environment(config_dir(), Environment::Testing).expect("load testing config")
}

/// Fresh Toasty `Db` per call (safe under concurrency). Migrations applied once.
pub async fn test_db() -> Db {
    let cfg = test_config().await;
    let db = db::connect(&cfg.database.url)
        .await
        .expect("connect vcp_test");
    let _ = SCHEMA_READY.set(());
    db
}

pub fn database_url() -> String {
    // Blocking helper for spawned tasks — config load is cheap/sync-enough via try.
    let dir = config_dir();
    Config::load_with_environment(dir, Environment::Testing)
        .expect("load testing config")
        .database
        .url
}

/// Serialize tests that mutate shared `vcp_test` fixtures.
pub fn db_lock() -> &'static Mutex<()> {
    DB_LOCK.get_or_init(|| Mutex::new(()))
}

pub async fn test_router() -> Router {
    let cfg = test_config().await;
    let database = test_db().await;
    let policy = std::sync::Arc::new(
        PolicyStore::load_from_csv(&cfg.access.policy_path).expect("load policy"),
    );
    app::router(database, policy, &cfg)
}

pub fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos}")
}

pub fn unique_email(prefix: &str) -> String {
    format!("test_{prefix}_{}@example.com", unique_suffix())
}

pub fn unique_slug(prefix: &str) -> String {
    format!("test-{prefix}-{}", unique_suffix())
}

pub async fn create_test_user(db: &Db, email: &str, password: &str) -> User {
    let mut db = db.clone();
    let password_hash = hash_password(password).expect("hash password");
    toasty::create!(User {
        email: email.to_owned(),
        display_name: format!("Test {email}"),
        password_hash,
    })
    .exec(&mut db)
    .await
    .expect("create user")
}

pub async fn create_test_org(db: &Db, slug: &str) -> Organization {
    let mut db = db.clone();
    toasty::create!(Organization {
        slug: slug.to_owned(),
        name: format!("Org {slug}"),
        address: "1 Test Street".to_owned(),
        vat: "FR 00 000000000".to_owned(),
        plan_label: "Test plan".to_owned(),
        supported_builds: "LTS".to_owned(),
        lts_subscriptions: 1,
        industrial_lts_subscriptions: 0,
        technical_contact: "ops@example.com".to_owned(),
        status: "ACTIVE".to_owned(),
    })
    .exec(&mut db)
    .await
    .expect("create org")
}

pub async fn create_membership(db: &Db, user_id: u64, organization_id: u64, role: &str) {
    let mut db = db.clone();
    toasty::create!(Membership {
        user_id,
        organization_id,
        role: role.to_owned(),
    })
    .exec(&mut db)
    .await
    .expect("create membership");
}

pub async fn create_org_with_membership(
    db: &Db,
    email: &str,
    password: &str,
    slug: &str,
    role: &str,
) -> (User, Organization) {
    let user = create_test_user(db, email, password).await;
    let org = create_test_org(db, slug).await;
    create_membership(db, user.id, org.id, role).await;
    (user, org)
}

pub async fn cleanup(db: &Db) {
    let mut db = db.clone();

    let users = User::all().exec(&mut db).await.unwrap_or_default();
    let test_users: Vec<_> = users
        .into_iter()
        .filter(|u| u.email.starts_with("test_"))
        .collect();
    let test_user_ids: Vec<u64> = test_users.iter().map(|u| u.id).collect();

    let orgs = Organization::all().exec(&mut db).await.unwrap_or_default();
    let test_orgs: Vec<_> = orgs
        .into_iter()
        .filter(|o| o.slug.starts_with("test-"))
        .collect();
    let test_org_ids: Vec<u64> = test_orgs.iter().map(|o| o.id).collect();

    let sessions = AuthSession::all().exec(&mut db).await.unwrap_or_default();
    for s in sessions {
        if test_user_ids.contains(&s.user_id) {
            let _ = AuthSession::delete_by_token_hash(&mut db, &s.token_hash).await;
        }
    }

    let memberships = Membership::all().exec(&mut db).await.unwrap_or_default();
    for m in memberships {
        let drop = test_user_ids.contains(&m.user_id) || test_org_ids.contains(&m.organization_id);
        if drop {
            let _ = Membership::delete_by_id(&mut db, m.id).await;
        }
    }

    let issues = Issue::all().exec(&mut db).await.unwrap_or_default();
    for issue in issues {
        if test_org_ids.contains(&issue.organization_id) || issue.key.starts_with("TEST-") {
            let _ = Issue::delete_by_id(&mut db, issue.id).await;
        }
    }

    let docs = DocArticle::all().exec(&mut db).await.unwrap_or_default();
    for doc in docs {
        if doc.slug.starts_with("test-") {
            let _ = DocArticle::delete_by_id(&mut db, doc.id).await;
        }
    }

    let releases = Release::all().exec(&mut db).await.unwrap_or_default();
    for rel in releases {
        if rel.version.starts_with("test-") {
            let _ = Release::delete_by_id(&mut db, rel.id).await;
        }
    }

    for u in test_users {
        let _ = User::delete_by_id(&mut db, u.id).await;
    }
    for o in test_orgs {
        let _ = Organization::delete_by_id(&mut db, o.id).await;
    }
}

fn absolute_uri(path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        path.to_owned()
    } else if path.starts_with('/') {
        format!("{TEST_ORIGIN}{path}")
    } else {
        format!("{TEST_ORIGIN}/{path}")
    }
}

pub async fn request(
    router: &Router,
    method: Method,
    path: &str,
    cookie: Option<&str>,
    body: Option<String>,
) -> Response {
    let uri = absolute_uri(path);
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    builder = builder.header("origin", TEST_ORIGIN);
    if body.is_some() {
        builder = builder.header("content-type", "application/x-www-form-urlencoded");
    }
    let req = builder
        .body(body.map(Body::from).unwrap_or_else(Body::empty))
        .expect("build request");
    router.handle(req).await
}

pub async fn get(router: &Router, path: &str, cookie: Option<&str>) -> Response {
    request(router, Method::GET, path, cookie, None).await
}

pub async fn post_form(router: &Router, path: &str, cookie: Option<&str>, form: &str) -> Response {
    request(router, Method::POST, path, cookie, Some(form.to_owned())).await
}

pub fn status(resp: &Response) -> StatusCode {
    resp.status()
}

pub fn cookie_header(resp: &Response) -> Option<String> {
    let mut parts = Vec::new();
    for value in resp.headers().get_all(topcoat::router::header::SET_COOKIE) {
        let Ok(s) = value.to_str() else {
            continue;
        };
        if let Some(pair) = s.split(';').next() {
            parts.push(pair.trim().to_owned());
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    }
}

pub async fn expire_all_sessions_for_user(db: &Db, user_id: u64) {
    let mut db = db.clone();
    let sessions = AuthSession::all().exec(&mut db).await.unwrap_or_default();
    for s in sessions.into_iter().filter(|s| s.user_id == user_id) {
        persist_session_record(&mut db, s.token_hash, user_id, now_unix() - 10)
            .await
            .expect("rewrite expired session");
    }
}

/// Percent-encode a form field value (application/x-www-form-urlencoded).
pub fn urlencoding_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
