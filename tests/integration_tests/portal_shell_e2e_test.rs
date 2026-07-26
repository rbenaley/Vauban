//! E2E: login splash + org chrome markers (not auth denial paths).

use http_body_util::BodyExt;
use topcoat::router::StatusCode;

use crate::common::{
    cleanup, cookie_header, create_org_with_membership, db_lock, get, post_form, status, test_db,
    test_router, unique_email, unique_slug,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn urlencoding_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[tokio::test]
async fn e2e_login_page_renders_splash_chrome() {
    let _guard = db_lock().lock().await;
    let router = test_router().await;
    let resp = get(&router, "/login", None).await;
    assert_eq!(status(&resp), StatusCode::OK);
    let html = body_text(resp).await;
    assert!(html.contains("vb-login-body"), "{html}");
    assert!(html.contains("Sign in"), "{html}");
    assert!(html.contains("VAUBAN"), "{html}");
}

#[tokio::test]
async fn e2e_admin_dashboard_renders_shell_with_admin_rail() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("shell-admin");
    let slug = unique_slug("shell-admin");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;

    let form = format!("email={}&password=password", urlencoding_encode(&email));
    let login = post_form(&router, "/login", None, &form).await;
    let cookie = cookie_header(&login);
    assert!(cookie.is_some(), "login cookie required");

    let dash = get(&router, &format!("/{slug}"), cookie.as_deref()).await;
    assert_eq!(status(&dash), StatusCode::OK);
    let html = body_text(dash).await;
    assert!(html.contains("vb-shell"), "{html}");
    assert!(html.contains("vb-rail"), "{html}");
    assert!(html.contains("vb-topbar"), "{html}");
    assert!(html.contains("vauban://portal"), "{html}");
    assert!(html.contains("vb-rail-admin"), "admin must see ADMIN rail");

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_member_dashboard_shell_without_admin_rail() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("shell-member");
    let slug = unique_slug("shell-member");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let form = format!("email={}&password=password", urlencoding_encode(&email));
    let login = post_form(&router, "/login", None, &form).await;
    let cookie = cookie_header(&login);
    assert!(cookie.is_some(), "login cookie required");

    let dash = get(&router, &format!("/{slug}"), cookie.as_deref()).await;
    assert_eq!(status(&dash), StatusCode::OK);
    let html = body_text(dash).await;
    assert!(html.contains("vb-shell"), "{html}");
    assert!(html.contains("vb-rail"), "{html}");
    assert!(html.contains("vb-topbar"), "{html}");
    assert!(
        !html.contains("vb-rail-admin"),
        "member must not see ADMIN rail marker"
    );

    cleanup(&db).await;
}
