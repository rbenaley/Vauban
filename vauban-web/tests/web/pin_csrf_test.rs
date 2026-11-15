//! CSRF on the routes that pin a trust anchor.
//!
//! `POST /assets/manage/{uuid}/fetch-host-key` stores the SSH host key of
//! an asset and `POST /assets/manage/{uuid}/fetch-rdp-cert` its RDP server
//! certificate. Both decide what the bastion accepts as the identity of a
//! target. They used to take no CSRF token, and a changed pin was accepted
//! with `?confirm=true` in the URL.
//!
//! No SSH or RDP proxy runs in this suite: a request that passes the token
//! check reaches the "proxy not available" answer, which is how these tests
//! tell "refused for the token" from "let through".

use crate::common::{TestApp, assertions::assert_status};
use crate::fixtures::{
    create_admin_user, create_simple_rdp_asset, create_simple_ssh_asset, get_asset_uuid,
    unique_name,
};
use axum::http::header::COOKIE;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serial_test::serial;
use uuid::Uuid;

const INVALID_TOKEN: &str = "Invalid CSRF token";

/// `(route suffix, text of the answer once the token check is passed)`.
const PIN_ROUTES: [(&str, &str); 2] = [
    ("fetch-host-key", "SSH proxy not available"),
    ("fetch-rdp-cert", "RDP proxy not available"),
];

/// What the handler told the browser: the toast it triggers (the HTMX
/// error path answers with an `HX-Trigger` header and an empty body) and
/// the body.
fn answer(resp: &axum_test::TestResponse) -> String {
    let toast = resp
        .headers()
        .get("HX-Trigger")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    format!("{toast}\n{}", resp.text())
}

async fn stored_config(conn: &mut AsyncPgConnection, asset: Uuid) -> serde_json::Value {
    use vauban_web::schema::assets;
    assets::table
        .filter(assets::uuid.eq(asset))
        .select(assets::connection_config)
        .first(conn)
        .await
        .expect("asset row")
}

struct Scenario {
    app: &'static TestApp,
    conn: diesel_async::pooled_connection::deadpool::Object<AsyncPgConnection>,
    admin_token: String,
    ssh: Uuid,
    rdp: Uuid,
}

impl Scenario {
    async fn new() -> Self {
        let app = TestApp::spawn().await;
        let mut conn = app.get_conn().await;
        let admin =
            create_admin_user(&mut conn, &app.auth_service, &unique_name("pin_csrf_adm")).await;
        let ssh_id = create_simple_ssh_asset(&mut conn, "test-pin-csrf-ssh", admin.user.id).await;
        let rdp_id = create_simple_rdp_asset(&mut conn, "test-pin-csrf-rdp", admin.user.id).await;
        let ssh = get_asset_uuid(&mut conn, ssh_id).await;
        let rdp = get_asset_uuid(&mut conn, rdp_id).await;
        Self {
            app,
            conn,
            admin_token: admin.token,
            ssh,
            rdp,
        }
    }

    fn asset_for(&self, route: &str) -> Uuid {
        if route == "fetch-host-key" {
            self.ssh
        } else {
            self.rdp
        }
    }

    /// POST to a pin route as the administrator. `cookie_token` is the
    /// CSRF cookie, `form` the urlencoded body.
    async fn post(
        &self,
        route: &str,
        query: &str,
        cookie_token: Option<&str>,
        form: &[(&str, &str)],
    ) -> axum_test::TestResponse {
        let cookie = match cookie_token {
            Some(t) => format!("access_token={}; __vauban_csrf={}", self.admin_token, t),
            None => format!("access_token={}", self.admin_token),
        };
        // The flat test router mounts the RDP pin route outside
        // `/assets/manage` (see `tests/common/mod.rs`); the handler is the
        // production one.
        let prefix = if route == "fetch-host-key" {
            "/assets/manage"
        } else {
            "/assets"
        };
        self.app
            .server
            .post(&format!(
                "{prefix}/{}/{route}{query}",
                self.asset_for(route)
            ))
            .add_header(COOKIE, cookie)
            .form(form)
            .await
    }
}

#[tokio::test]
#[serial]
async fn attack_repin_without_csrf_token_is_rejected() {
    let mut s = Scenario::new().await;
    let token = s.app.generate_csrf_token();

    for (route, _) in PIN_ROUTES {
        let asset = s.asset_for(route);
        let before = stored_config(&mut s.conn, asset).await;

        // No body at all: the handler cannot even be entered.
        let no_body = s.post(route, "", Some(&token), &[]).await;
        assert!(
            no_body.status_code().is_client_error(),
            "{route}: a request with no token field must be a client error, got {}",
            no_body.status_code()
        );

        // A token field that does not match the cookie.
        for (cookie, field) in [
            (Some(token.as_str()), "not-the-token"),
            (Some(token.as_str()), ""),
            (None, token.as_str()),
            (Some("not-the-token"), "not-the-token"),
        ] {
            let resp = s.post(route, "", cookie, &[("csrf_token", field)]).await;
            assert!(
                answer(&resp).contains(INVALID_TOKEN),
                "{route}: cookie={cookie:?} field={field:?} must be refused for the token, got: {}",
                answer(&resp)
            );
        }

        assert_eq!(
            stored_config(&mut s.conn, asset).await,
            before,
            "{route}: a refused request must not change the stored pin"
        );
    }
}

#[tokio::test]
#[serial]
async fn attack_repin_confirm_in_query_does_not_bypass_the_token() {
    let s = Scenario::new().await;
    let token = s.app.generate_csrf_token();

    for (route, _) in PIN_ROUTES {
        // The old way to force a re-pin: a bare link with the flag.
        let resp = s
            .post(route, "?confirm=true", Some(&token), &[("csrf_token", "x")])
            .await;
        assert!(
            answer(&resp).contains(INVALID_TOKEN),
            "{route}: ?confirm=true must not get past the token check"
        );
    }
}

#[tokio::test]
#[serial]
async fn test_pin_request_with_a_valid_token_reaches_the_handler() {
    let s = Scenario::new().await;
    let token = s.app.generate_csrf_token();

    for (route, past_the_check) in PIN_ROUTES {
        for form in [
            &[("csrf_token", token.as_str())][..],
            &[("csrf_token", token.as_str()), ("confirm", "true")][..],
        ] {
            let resp = s.post(route, "", Some(&token), form).await;
            assert_status(&resp, 200);
            let body = answer(&resp);
            assert!(
                !body.contains(INVALID_TOKEN),
                "{route}: a valid token must be accepted"
            );
            assert!(
                body.contains(past_the_check),
                "{route}: expected the handler to go on to {past_the_check:?}, got: {body}"
            );
        }
    }
}

/// The handlers read `confirm` from the body they validated, never from
/// the URL.
#[test]
fn attack_repin_confirm_in_query_is_ignored() {
    for (name, source) in [
        (
            "fetch_ssh_host_key",
            include_str!("../../src/handlers/web/ssh.rs"),
        ),
        (
            "fetch_rdp_server_cert",
            include_str!("../../src/handlers/web/rdp.rs"),
        ),
    ] {
        let body = handler_body(source, name);
        assert!(
            !body.contains("Query("),
            "{name} must not take query parameters"
        );
        assert!(
            body.contains("Form(form): Form<PinTrustAnchorForm>"),
            "{name} must take the pin form"
        );
        let check = body
            .find("pin_request_csrf_is_valid(&state, &jar, &form)")
            .unwrap_or_else(|| panic!("{name} must validate the CSRF token"));
        let confirm = body
            .find("form.confirmed()")
            .unwrap_or_else(|| panic!("{name} must read confirm from the form"));
        assert!(check < confirm, "{name}: token check comes first");
        // Nothing reaches a proxy or the database before the token check.
        for later in ["state.db_pool", "_proxy"] {
            if let Some(pos) = body.find(later) {
                assert!(check < pos, "{name}: `{later}` before the token check");
            }
        }
    }
}

/// Text of `pub async fn <name>(...) { ... }` in `source`.
fn handler_body<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source
        .find(&format!("pub async fn {name}("))
        .unwrap_or_else(|| panic!("handler {name} not found"));
    let rest = &source[start..];
    let open = rest.find(") -> Response {").expect("signature end") + ") -> Response ".len();
    let mut depth = 0usize;
    for (i, c) in rest[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &rest[..open + i + 1];
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces in {name}");
}

/// Every fragment that offers a pin action sends the token, and none puts
/// `confirm` in the URL.
#[test]
fn test_pin_fragments_send_the_token_in_the_body() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates/assets");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).expect("templates/assets") {
        let path = entry.expect("entry").path();
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        for (i, _) in text.match_indices("hx-post=\"/assets/manage/") {
            let tag_end = text[i..].find('>').map(|e| i + e).unwrap_or(text.len());
            let tag_start = text[..i].rfind('<').unwrap_or(0);
            let tag = &text[tag_start..tag_end];
            if !(tag.contains("/fetch-host-key") || tag.contains("/fetch-rdp-cert")) {
                continue;
            }
            seen += 1;
            assert!(
                !tag.contains("?confirm"),
                "{}: confirm must not be in the URL",
                path.display()
            );
            let sends_token = tag.contains("x-bind:hx-vals=\"JSON.stringify({csrf_token: token")
                || text[tag_end..].find("</form>").is_some_and(|close| {
                    text[tag_end..tag_end + close].contains("name=\"csrf_token\"")
                });
            assert!(
                sends_token,
                "{}: the pin action must send csrf_token",
                path.display()
            );
        }
    }
    assert!(
        seen >= 10,
        "expected the pin fragments, found {seen} actions"
    );
}

/// Every route of the web zone that changes state checks the CSRF token.
///
/// Reads the router and the handlers as text. A handler passes when its
/// body mentions the CSRF check; the exceptions are listed with the reason.
#[test]
fn test_every_web_mutation_route_checks_csrf() {
    // Handlers that delegate the check to a helper they call.
    const DELEGATED: [(&str, &str); 2] = [
        ("mcp_hitl_approve_web", "decide_web("),
        ("mcp_hitl_deny_web", "decide_web("),
    ];

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let main = std::fs::read_to_string(root.join("main.rs")).expect("main.rs");
    let main = main
        .split("#[cfg(test)]\nmod tests")
        .next()
        .unwrap_or(&main);

    let mut handlers = String::new();
    for file in std::fs::read_dir(root.join("handlers/web")).expect("handlers/web") {
        let path = file.expect("entry").path();
        if path.extension().is_some_and(|e| e == "rs") {
            handlers.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
        }
    }
    handlers.push_str(&std::fs::read_to_string(root.join("handlers/auth.rs")).unwrap_or_default());

    let mut checked = 0;
    for method in ["post(", "put(", "delete(", "patch("] {
        for (i, _) in main.match_indices(method) {
            let rest = main[i + method.len()..].trim_start();
            let Some(path) = rest
                .strip_prefix("handlers::web::")
                .or_else(|| rest.strip_prefix("handlers::auth::"))
            else {
                continue;
            };
            // `handlers::web::iacs::connect` -> `connect`.
            let full: String = path
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == ':')
                .collect();
            let name = full.rsplit("::").next().unwrap_or(&full).to_string();
            // `handlers::auth::login` and `logout` under /api/v1 take an
            // API-style JSON body, not a browser form.
            if rest.starts_with("handlers::auth::") && !name.ends_with("_web") {
                continue;
            }
            let Some(start) = handlers.find(&format!("pub async fn {name}(")) else {
                panic!("handler {name} not found");
            };
            let end = handlers[start + 1..]
                .find("\npub async fn ")
                .map(|e| start + 1 + e)
                .unwrap_or(handlers.len());
            let body = &handlers[start..end];
            let delegated = DELEGATED
                .iter()
                .any(|(h, call)| *h == name && body.contains(call));
            assert!(
                delegated
                    || body.contains("validate_double_submit")
                    || body.contains("pin_request_csrf_is_valid")
                    || body.to_ascii_lowercase().contains("csrf"),
                "web mutation route `{name}` does not check the CSRF token"
            );
            checked += 1;
        }
    }
    assert!(checked >= 60, "inventory looks too small: {checked} routes");
}
