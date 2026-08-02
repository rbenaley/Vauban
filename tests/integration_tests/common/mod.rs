//! Shared harness for `vcp_test` integration suites.

mod topcoat_click;

pub use topcoat_click::{
    assert_topcoat_click_handlers_are_functions, data_topcoat_on_click_values,
    is_topcoat_function_handler,
};

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
    models::{
        AuthSession, DOC_STATUS_PUBLISHED, DocArticle, EphemeralDownload, Issue,
        MEMBERSHIP_ROLE_ORG, Membership, Organization, PORTAL_ROLE_ADMIN, RESERVED_ORG_SLUG,
        Release, User,
    },
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
    test_router_with_config(cfg).await
}

pub async fn test_router_with_config(cfg: Config) -> Router {
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
    create_test_user_with_portal_role(db, email, password, "").await
}

pub async fn create_test_user_with_portal_role(
    db: &Db,
    email: &str,
    password: &str,
    portal_role: &str,
) -> User {
    let mut db = db.clone();
    let password_hash = hash_password(password).expect("hash password");
    toasty::create!(User {
        email: email.to_owned(),
        display_name: format!("Test {email}"),
        password_hash,
        portal_role: portal_role.to_owned(),
    })
    .exec(&mut db)
    .await
    .expect("create user")
}

/// Find or create the reserved `vauban` org (staff chrome preview tenant).
pub async fn ensure_reserved_org(db: &Db) -> Organization {
    let mut conn = db.clone();
    let existing = Organization::all()
        .filter(Organization::fields().slug().eq(RESERVED_ORG_SLUG))
        .exec(&mut conn)
        .await
        .unwrap_or_default()
        .into_iter()
        .next();
    if let Some(org) = existing {
        return org;
    }
    create_test_org(db, RESERVED_ORG_SLUG).await
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
        technical_contact_name: "Ops Contact".to_owned(),
        technical_contact_email: "ops@example.com".to_owned(),
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
    let is_admin = role == "admin" || role == PORTAL_ROLE_ADMIN;
    let user = if is_admin {
        create_test_user_with_portal_role(db, email, password, PORTAL_ROLE_ADMIN).await
    } else {
        create_test_user(db, email, password).await
    };
    let org = create_test_org(db, slug).await;
    // Memberships are always `org`; staff capability lives on `User.portal_role`.
    create_membership(db, user.id, org.id, MEMBERSHIP_ROLE_ORG).await;
    if is_admin && !slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG) {
        let vauban = ensure_reserved_org(db).await;
        create_membership(db, user.id, vauban.id, MEMBERSHIP_ROLE_ORG).await;
    }
    (user, org)
}

/// Versions upserted by `db::seed` / GA catalog — must survive test cleanup.
fn is_seed_release_version(version: &str) -> bool {
    matches!(
        version,
        "v1.0.2"
            | "v1.0.1"
            | "v1.0.0"
            | "v0.9.35"
            | "v0.9.31"
            | "v0.9.29"
            | "v0.9.24"
            | "v0.9.20"
            | "v0.9.12"
            | "v0.9.4"
            | "v0.8.7"
            | "v0.8.6"
            | "v0.8.6-acme1"
            | "v0.7.16"
            | "v0.7.4"
            | "v0.7.2"
            | "v0.6.6"
            | "v0.6.3"
            | "v0.6.2"
            | "v0.6.0"
            | "v0.5.0"
            | "v0.3.0"
            | "v0.2.1"
            | "v0.2.0"
            | "v1"
    )
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
        // Keep seed / catalog rows; drop every fixture release (including
        // pagination versions like `v99.0.N` that must sort numerically).
        if !is_seed_release_version(&rel.version) {
            let _ = Release::delete_by_id(&mut db, rel.id).await;
        }
    }

    let ephs = EphemeralDownload::all()
        .exec(&mut db)
        .await
        .unwrap_or_default();
    for row in ephs {
        let drop =
            test_user_ids.contains(&row.user_id) || test_org_ids.contains(&row.organization_id);
        if drop {
            let _ = row.delete().exec(&mut db).await;
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

/// POST JSON (Topcoat shard / procedure bodies).
pub async fn post_json(router: &Router, path: &str, cookie: Option<&str>, json: &str) -> Response {
    let uri = absolute_uri(path);
    let mut builder = Request::builder().method(Method::POST).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    builder = builder
        .header("origin", TEST_ORIGIN)
        .header("content-type", "application/json");
    let req = builder
        .body(Body::from(json.to_owned()))
        .expect("build json request");
    router.handle(req).await
}

/// Login helper (password fixture `password`).
pub async fn login_cookie(router: &Router, email: &str) -> Option<String> {
    let form = format!("email={}&password=password", urlencoding_encode(email));
    let login = post_form(router, "/login", None, &form).await;
    cookie_header(&login)
}

/// Extract the first `/_topcoat/shards/{id}` path from SSR HTML.
pub fn shard_path_from_html(html: &str) -> Option<String> {
    let key = "/_topcoat/shards/";
    let i = html.find(key)?;
    let rest = &html[i..];
    let end = rest
        .find(['"', '\'', ' ', ')', ',', '&'])
        .unwrap_or(rest.len());
    Some(rest[..end].replace("\\/", "/"))
}

/// JSON body for `docs_search_results(org_slug, q, cat, page)`.
pub fn docs_search_shard_body(org_slug: &str, q: &str, cat: &str) -> String {
    docs_search_shard_body_page(org_slug, q, cat, "1")
}

/// JSON body for `docs_search_results` with an explicit page.
pub fn docs_search_shard_body_page(org_slug: &str, q: &str, cat: &str, page: &str) -> String {
    format!(
        "[{},{},{},{}]",
        json_string(org_slug),
        json_string(q),
        json_string(cat),
        json_string(page)
    )
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Create a published doc article with a `test-` slug prefix for cleanup.
pub async fn create_published_doc(
    db: &Db,
    title: &str,
    summary: &str,
    category: &str,
    slug: &str,
) -> DocArticle {
    let mut conn = db.clone();
    toasty::create!(DocArticle {
        title: title.to_owned(),
        summary: summary.to_owned(),
        category: category.to_owned(),
        slug: slug.to_owned(),
        version: "v1".to_owned(),
        status: DOC_STATUS_PUBLISHED.to_owned(),
        body: "body".to_owned(),
        updated_at: now_unix(),
    })
    .exec(&mut conn)
    .await
    .expect("create published doc")
}

/// JSON body for `issues_search_results(org_slug, q, status, page)`.
pub fn org_issues_search_shard_body(org_slug: &str, q: &str, status: &str) -> String {
    org_issues_search_shard_body_page(org_slug, q, status, "1")
}

/// JSON body for `issues_search_results` with an explicit page.
pub fn org_issues_search_shard_body_page(
    org_slug: &str,
    q: &str,
    status: &str,
    page: &str,
) -> String {
    format!(
        "[{},{},{},{}]",
        json_string(org_slug),
        json_string(q),
        json_string(status),
        json_string(page)
    )
}

/// JSON body for `admin_issues_search_results(q, org, status, page)`.
pub fn admin_issues_search_shard_body(q: &str, org: &str, status: &str) -> String {
    admin_issues_search_shard_body_page(q, org, status, "1")
}

/// JSON body for `admin_issues_search_results` with an explicit page.
pub fn admin_issues_search_shard_body_page(q: &str, org: &str, status: &str, page: &str) -> String {
    format!(
        "[{},{},{},{}]",
        json_string(q),
        json_string(org),
        json_string(status),
        json_string(page)
    )
}

/// JSON body for `admin_companies_search_results(q, page)`.
pub fn admin_companies_search_shard_body(q: &str) -> String {
    admin_companies_search_shard_body_page(q, "1")
}

/// JSON body for `admin_companies_search_results` with an explicit page.
pub fn admin_companies_search_shard_body_page(q: &str, page: &str) -> String {
    format!("[{},{}]", json_string(q), json_string(page))
}

/// Create an open issue for search fixtures (cleaned via test org id).
pub async fn create_test_issue(
    db: &Db,
    organization_id: u64,
    opened_by_user_id: u64,
    key: &str,
    title: &str,
    status: &str,
) -> Issue {
    let mut conn = db.clone();
    let now = now_unix();
    toasty::create!(Issue {
        key: key.to_owned(),
        title: title.to_owned(),
        component: "SSH Proxy".to_owned(),
        severity: "Major".to_owned(),
        status: status.to_owned(),
        organization_id,
        details: "fixture".to_owned(),
        opened_by_user_id,
        created_at: now,
        updated_at: now,
    })
    .exec(&mut conn)
    .await
    .expect("create test issue")
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
