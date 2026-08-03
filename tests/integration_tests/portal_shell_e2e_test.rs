//! E2E: login splash + org chrome markers (not auth denial paths).

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::models::{RELEASE_GA_ORG_ID, Release};

use crate::common::{
    cleanup, create_org_with_membership, create_published_doc, db_lock, get, login_cookie,
    post_form, status, test_db, test_router, unique_email, unique_slug,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
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
    assert!(html.contains("apple-touch-icon"), "{html}");
}

#[tokio::test]
async fn e2e_well_known_icon_probes_return_brand_bitmaps() {
    let _guard = db_lock().lock().await;
    let router = test_router().await;

    let ico = get(&router, "/favicon.ico", None).await;
    assert_eq!(status(&ico), StatusCode::OK);
    assert_eq!(
        ico.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("image/x-icon")
    );
    let ico_bytes = ico.into_body().collect().await.expect("body").to_bytes();
    assert!(ico_bytes.len() > 16, "favicon.ico too small");
    assert_eq!(&ico_bytes[0..4], &[0x00, 0x00, 0x01, 0x00], "ICO magic");

    for path in ["/apple-touch-icon.png", "/apple-touch-icon-precomposed.png"] {
        let resp = get(&router, path, None).await;
        assert_eq!(status(&resp), StatusCode::OK, "{path}");
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("image/png"),
            "{path}"
        );
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"), "{path} PNG magic");
    }
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

    let cookie = login_cookie(&router, &email).await;
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

    let cookie = login_cookie(&router, &email).await;
    assert!(cookie.is_some(), "login cookie required");

    let dash = get(&router, &format!("/{slug}"), cookie.as_deref()).await;
    assert_eq!(status(&dash), StatusCode::OK);
    let html = body_text(dash).await;
    assert!(html.contains("vb-shell"), "{html}");
    assert!(html.contains("vb-rail"), "{html}");
    assert!(html.contains("vb-topbar"), "{html}");
    assert!(
        html.contains("vb-stat-value"),
        "dashboard polish hook: {html}"
    );
    assert!(
        !html.contains("vb-rail-admin"),
        "member must not see ADMIN rail marker"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_docs_modal_exposes_close_hit_target() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("shell-docs-modal");
    let slug = unique_slug("shell-docs-modal");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let article = unique_slug("shell-article");
    create_published_doc(&db, "Shell Polish Doc", "summary", "Guides", &article).await;

    let cookie = login_cookie(&router, &email).await.expect("session cookie");

    let modal = get(&router, &format!("/{slug}/docs/{article}"), Some(&cookie)).await;
    assert_eq!(status(&modal), StatusCode::OK);
    let html = body_text(modal).await;
    assert!(
        html.contains("vb-modal-close"),
        "docs modal close hook: {html}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_builds_ephemeral_exposes_countdown_class() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("shell-eph");
    let slug = unique_slug("shell-eph");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let version = unique_slug("shell-rel");
    {
        let mut conn = db.clone();
        let _ = toasty::create!(Release {
            version: version.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-15".to_owned(),
            size_mb: "2.0".to_owned(),
            sha256: "abc".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "FIX: polish".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: vcp::release_pkg::version_sort_fields(&version).v_major,
            v_minor: vcp::release_pkg::version_sort_fields(&version).v_minor,
            v_patch: vcp::release_pkg::version_sort_fields(&version).v_patch,
            has_client_suffix: vcp::release_pkg::version_sort_fields(&version).has_client_suffix,
            client_suffix: vcp::release_pkg::version_sort_fields(&version).client_suffix,
        })
        .exec(&mut conn)
        .await
        .expect("release");
    }

    let cookie = login_cookie(&router, &email).await.expect("session cookie");

    let gen_resp = post_form(
        &router,
        &format!("/{slug}/builds/{version}/ephemeral"),
        Some(&cookie),
        "",
    )
    .await;
    assert!(
        status(&gen_resp).is_redirection(),
        "generate ephemeral must PRG: {:?}",
        status(&gen_resp)
    );

    let detail = get(&router, &format!("/{slug}/builds/{version}"), Some(&cookie)).await;
    assert_eq!(status(&detail), StatusCode::OK);
    let html = body_text(detail).await;
    assert!(
        html.contains("vb-ephemeral-countdown"),
        "ephemeral countdown polish hook: {html}"
    );

    cleanup(&db).await;
}
