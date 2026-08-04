//! Shared harness for `vcp_test` integration suites.

mod topcoat_click;

pub use topcoat_click::{
    assert_topcoat_click_handlers_are_functions, assert_topcoat_submit_handlers_are_functions,
    data_topcoat_on_click_values, is_topcoat_function_handler,
};

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use http_body_util::BodyExt;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use toasty::Db;
use tokio::sync::Mutex;
use topcoat::mail::MemoryTransport;
use topcoat::router::{Body, Method, Request, Response, Router, StatusCode};
use vcp::{
    app,
    auth::persist_session_record,
    config::{Config, Environment},
    db::{self, now_unix},
    magic_link::{active_user_by_email, issue_token},
    models::{
        AuthSession, DOC_STATUS_PUBLISHED, DocArticle, EphemeralDownload, Issue,
        MEMBERSHIP_ROLE_ORG, MagicLinkToken, Membership, Organization, PORTAL_ROLE_ADMIN,
        PORTAL_ROLE_ORG, RESERVED_ORG_SLUG, Release, USER_NOT_DELETED, User,
    },
    perms::PolicyStore,
    storage::{StorageClient, upsert_release_object, write_and_hash},
};

static TRACING: OnceLock<()> = OnceLock::new();
static CRYPTO: OnceLock<()> = OnceLock::new();
static DB_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static SCHEMA_READY: OnceLock<()> = OnceLock::new();

/// Absolute HTTPS origin used so `__Host-` / `Secure` session cookies apply.
pub const TEST_ORIGIN: &str = "https://localhost:3001";

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

/// Router with [`MemoryTransport`] for asserting outbound mail without SMTP.
pub async fn test_router_with_memory_mail(memory: MemoryTransport) -> Router {
    let cfg = test_config().await;
    let database = test_db().await;
    let policy = std::sync::Arc::new(
        PolicyStore::load_from_csv(&cfg.access.policy_path).expect("load policy"),
    );
    app::router_with_memory_mail(database, policy, &cfg, memory)
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

pub async fn create_test_user(db: &Db, email: &str, _password: &str) -> User {
    create_test_user_with_portal_role(db, email, _password, PORTAL_ROLE_ORG).await
}

pub async fn create_test_user_with_portal_role(
    db: &Db,
    email: &str,
    _password: &str,
    portal_role: &str,
) -> User {
    let mut db = db.clone();
    toasty::create!(User {
        email: email.to_owned(),
        display_name: format!("Test {email}"),
        portal_role: portal_role.to_owned(),
        deleted_at: USER_NOT_DELETED,
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

    let tokens = MagicLinkToken::all()
        .exec(&mut db)
        .await
        .unwrap_or_default();
    for t in tokens {
        if test_user_ids.contains(&t.user_id) {
            let _ = MagicLinkToken::delete_by_token_hash(&mut db, &t.token_hash).await;
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
            let _ = vcp::storage::delete_release_object(&mut db, rel.id).await;
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

/// POST `multipart/form-data` with text fields (optional empty `package` file field).
pub async fn post_multipart(
    router: &Router,
    path: &str,
    cookie: Option<&str>,
    fields: &[(&str, &str)],
) -> Response {
    post_multipart_with_files(router, path, cookie, fields, &[]).await
}

/// One binary file part for [`post_multipart_with_files`].
pub struct MultipartFile<'a> {
    pub field: &'a str,
    pub filename: &'a str,
    pub content_type: &'a str,
    pub bytes: &'a [u8],
}

/// POST `multipart/form-data` with text fields and zero or more file parts.
pub async fn post_multipart_with_files(
    router: &Router,
    path: &str,
    cookie: Option<&str>,
    fields: &[(&str, &str)],
    files: &[MultipartFile<'_>],
) -> Response {
    let boundary = "----VcpTestBoundary7MA4YWxkTrZu0gW";
    let mut body: Vec<u8> = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(b"--");
        body.extend_from_slice(boundary.as_bytes());
        body.extend_from_slice(b"\r\nContent-Disposition: form-data; name=\"");
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(b"\"\r\n\r\n");
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    for file in files {
        body.extend_from_slice(b"--");
        body.extend_from_slice(boundary.as_bytes());
        body.extend_from_slice(b"\r\nContent-Disposition: form-data; name=\"");
        body.extend_from_slice(file.field.as_bytes());
        body.extend_from_slice(b"\"; filename=\"");
        body.extend_from_slice(file.filename.as_bytes());
        body.extend_from_slice(b"\"\r\nContent-Type: ");
        body.extend_from_slice(file.content_type.as_bytes());
        body.extend_from_slice(b"\r\n\r\n");
        body.extend_from_slice(file.bytes);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--");
    body.extend_from_slice(boundary.as_bytes());
    body.extend_from_slice(b"--\r\n");

    let uri = absolute_uri(path);
    let mut builder = Request::builder().method(Method::POST).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    builder = builder.header("origin", TEST_ORIGIN).header(
        "content-type",
        format!("multipart/form-data; boundary={boundary}"),
    );
    let req = builder
        .body(Body::from(body))
        .expect("build multipart request");
    router.handle(req).await
}

/// Minimal valid 1×1 PNG (magic + IHDR + IEND) for image upload tests.
pub const TINY_PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // signature
    0x00, 0x00, 0x00, 0x0D, // IHDR len
    0x49, 0x48, 0x44, 0x52, // IHDR
    0x00, 0x00, 0x00, 0x01, // w
    0x00, 0x00, 0x00, 0x01, // h
    0x08, 0x02, // bit depth / color
    0x00, 0x00, 0x00, // compression / filter / interlace
    0x90, 0x77, 0x53, 0xDE, // CRC
    0x00, 0x00, 0x00, 0x00, // IEND len
    0x49, 0x45, 0x4E, 0x44, // IEND
    0xAE, 0x42, 0x60, 0x82, // CRC
];

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

/// Login helper: issue a magic-link token and consume it (same production path).
pub async fn login_cookie(router: &Router, email: &str) -> Option<String> {
    let db = test_db().await;
    let mut conn = db.clone();
    let normalized = email.trim().to_ascii_lowercase();
    let user = active_user_by_email(&mut conn, &normalized).await.ok()??;
    let raw = issue_token(&mut conn, user.id, 300).await.ok()?;
    let path = format!("/login/magic?token={raw}");
    let login = get(router, &path, None).await;
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

/// Extract the first `/_topcoat/procedures/{id}` path from SSR HTML.
///
/// Procedure IDs are compile-time UUIDs embedded as hydrated
/// `{ t: "Procedure", id: "…" }` markers (or a literal path).
pub fn procedure_path_from_html(html: &str) -> Option<String> {
    let key = "/_topcoat/procedures/";
    if let Some(i) = html.find(key) {
        let rest = &html[i..];
        let end = rest
            .find(['"', '\'', ' ', ')', ',', '&'])
            .unwrap_or(rest.len());
        return Some(rest[..end].replace("\\/", "/"));
    }
    procedure_id_from_html(html).map(|id| format!("/_topcoat/procedures/{id}"))
}

/// Pull a Topcoat procedure UUID out of SSR hydrate / attribute payloads.
pub fn procedure_id_from_html(html: &str) -> Option<String> {
    // Unescaped: "t":"Procedure","id":"<uuid>"
    const MARKERS: &[&str] = &[
        "\"t\":\"Procedure\",\"id\":\"",
        "\"t\": \"Procedure\", \"id\": \"",
        "&quot;t&quot;:&quot;Procedure&quot;,&quot;id&quot;:&quot;",
        "&quot;t&quot;: &quot;Procedure&quot;, &quot;id&quot;: &quot;",
    ];
    for marker in MARKERS {
        if let Some(i) = html.find(marker) {
            let rest = &html[i + marker.len()..];
            let end = rest.find(['"', '&']).unwrap_or(rest.len());
            let id = &rest[..end];
            if looks_like_procedure_id(id) {
                return Some(id.to_owned());
            }
        }
    }
    None
}

fn looks_like_procedure_id(id: &str) -> bool {
    // UUID or any non-empty opaque id Topcoat may emit.
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// JSON body for `request_login_link(email)` (single String arg).
pub fn request_login_link_json(email: &str) -> String {
    format!("[{}]", json_string(email))
}

/// Resolve the login magic-link procedure path from a fresh GET `/login`, then POST.
pub async fn call_request_login_link(router: &Router, email: &str) -> Response {
    let page = get(router, "/login", None).await;
    assert_eq!(
        status(&page),
        StatusCode::OK,
        "GET /login must succeed before calling request_login_link"
    );
    let html = {
        let bytes = page
            .into_body()
            .collect()
            .await
            .expect("login body")
            .to_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    };
    let path = procedure_path_from_html(&html).expect("procedure path in /login SSR HTML");
    post_json(router, &path, None, &request_login_link_json(email)).await
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

/// Upsert Postgres mirror + helper SQLite SoT for a release (metadata only).
///
/// Does not write a blob; downloads still need a real artifact via
/// [`seed_release_artifact`] (or matching bytes on disk).
pub async fn seed_release_digest(db: &Db, release_id: u64, sha256: &str, size_bytes: u64) {
    let mut conn = db.clone();
    upsert_release_object(&mut conn, release_id, sha256, size_bytes)
        .await
        .expect("upsert storage_objects");
    let cfg = test_config().await;
    std::fs::create_dir_all(&cfg.storage.blob_path).expect("blob_path mkdir");
    let meta = vcp::storage::MetaDb::open(&cfg.storage.blob_path).expect("meta open");
    meta.upsert(&vcp::storage::MetaObject {
        scope: vcp::storage::StorageScope::Release,
        object_key: release_id.to_string(),
        org_id: String::new(),
        sha256: sha256.trim().to_ascii_lowercase(),
        size_bytes,
        content_type: String::new(),
        ext: String::new(),
    })
    .expect("meta upsert");
}

/// Write a release blob via inline `StorageClient` and upsert `storage_objects`.
///
/// Returns the lowercase hex SHA-256 of `bytes`.
pub async fn seed_release_artifact(db: &Db, release_id: u64, bytes: &[u8]) -> String {
    let cfg = test_config().await;
    let client = StorageClient::connect(&cfg.storage).expect("storage connect");
    let (upload_id, mut file) = client
        .put_begin_release(release_id, bytes.len() as u64)
        .expect("put_begin_release");
    let (size, sha) =
        write_and_hash(&mut file, std::io::Cursor::new(bytes)).expect("write_and_hash");
    drop(file);
    client
        .put_commit_release(&upload_id, release_id, &sha)
        .expect("put_commit_release");
    seed_release_digest(db, release_id, &sha, size).await;
    sha
}

/// Proptest config that persists failure seeds under `target/proptest-regressions/`.
///
/// The integration harness crate root is `tests/integration_tests/` (has
/// `main.rs`). Default `SourceParallel("proptest-regressions")` therefore lands
/// in `tests/proptest-regressions/`. Using `../target/…` redirects into the
/// Cargo `target/` tree (already gitignored).
pub fn prop_config(cases: u32) -> ProptestConfig {
    ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::SourceParallel(
            "../target/proptest-regressions",
        ))),
        ..ProptestConfig::with_cases(cases)
    }
}
