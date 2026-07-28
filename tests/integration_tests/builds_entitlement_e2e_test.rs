//! E2E: authorized download 501; wrong org 404; anonymous denied; GA vs private.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::{
    db::now_unix,
    models::{EphemeralDownload, RELEASE_GA_ORG_ID, Release},
};

use crate::common::{
    assert_topcoat_click_handlers_are_functions, cleanup, cookie_header,
    create_org_with_membership, create_test_org, data_topcoat_on_click_values, db_lock, get,
    post_form, status, test_config, test_db, test_router, unique_email, unique_slug,
    urlencoding_encode,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

async fn login(router: &topcoat::router::Router, email: &str) -> Option<String> {
    let form = format!("email={}&password=password", urlencoding_encode(email));
    let login = post_form(router, "/login", None, &form).await;
    assert!(status(&login).is_redirection());
    cookie_header(&login)
}

#[tokio::test]
async fn e2e_authorized_download_returns_501() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("dl-ok");
    let slug = unique_slug("dl-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let version = unique_slug("dlv");
    {
        let mut conn = db.clone();
        let _ = toasty::create!(Release {
            version: version.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            size_mb: "1.0".to_owned(),
            signature_prefix: "abc".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "FIX: x".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
        })
        .exec(&mut conn)
        .await
        .expect("release");
    }

    let cookie = login(&router, &email).await;
    let resp = post_form(
        &router,
        &format!("/{slug}/builds/{version}/download"),
        cookie.as_deref(),
        "",
    )
    .await;
    assert_eq!(status(&resp), StatusCode::NOT_IMPLEMENTED);
    let body = body_text(resp).await;
    assert!(body.contains("download not configured"), "{body}");

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_download_wrong_org_is_404() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("dl-wo");
    let slug = unique_slug("dl-home");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let _other = create_test_org(&db, &unique_slug("dl-other")).await;
    let version = unique_slug("dlv2");
    {
        let mut conn = db.clone();
        let _ = toasty::create!(Release {
            version: version.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            size_mb: "1.0".to_owned(),
            signature_prefix: "abc".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "FIX: x".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
        })
        .exec(&mut conn)
        .await
        .expect("release");
    }

    let cookie = login(&router, &email).await;
    let resp = post_form(
        &router,
        &format!("/{}/builds/{version}/download", unique_slug("no-access")),
        cookie.as_deref(),
        "",
    )
    .await;
    assert_eq!(status(&resp), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_download_anonymous_denied() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let version = unique_slug("dl-anon");
    {
        let mut conn = db.clone();
        let _ = toasty::create!(Release {
            version: version.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            size_mb: "1.0".to_owned(),
            signature_prefix: "abc".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "FIX: x".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
        })
        .exec(&mut conn)
        .await
        .expect("release");
    }

    // No session cookie: require_org maps to 404 (anti-enumeration); also accept 401 / redirect.
    let resp = post_form(
        &router,
        &format!("/{}/builds/{version}/download", unique_slug("anon-org")),
        None,
        "",
    )
    .await;
    let st = status(&resp);
    assert!(
        st == StatusCode::NOT_FOUND
            || st == StatusCode::UNAUTHORIZED
            || st.is_redirection()
            || st == StatusCode::FORBIDDEN,
        "anonymous must not get 501, got {st}"
    );
    assert_ne!(st, StatusCode::NOT_IMPLEMENTED);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_org_private_release_hidden_from_other_org() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email_a = unique_email("priv-a");
    let slug_a = unique_slug("priv-a");
    let (_user_a, org_a) =
        create_org_with_membership(&db, &email_a, "password", &slug_a, "org").await;

    let email_b = unique_email("priv-b");
    let slug_b = unique_slug("priv-b");
    let (_user_b, _org_b) =
        create_org_with_membership(&db, &email_b, "password", &slug_b, "org").await;

    let private_ver = unique_slug("priv-rel");
    let ga_ver = unique_slug("ga-rel");
    {
        let mut conn = db.clone();
        let _ = toasty::create!(Release {
            version: private_ver.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            size_mb: "1.0".to_owned(),
            signature_prefix: "abc".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "HOTFIX: private".to_owned(),
            organization_id: org_a.id,
        })
        .exec(&mut conn)
        .await
        .expect("private release");
        let _ = toasty::create!(Release {
            version: ga_ver.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-02".to_owned(),
            size_mb: "1.0".to_owned(),
            signature_prefix: "def".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "GA".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
        })
        .exec(&mut conn)
        .await
        .expect("ga release");
    }

    let cookie_a = login(&router, &email_a).await;
    let list_a = get(&router, &format!("/{slug_a}/builds"), cookie_a.as_deref()).await;
    assert!(status(&list_a).is_success());
    let body_a = body_text(list_a).await;
    assert!(
        body_a.contains(&private_ver),
        "owner must see private build"
    );
    assert!(body_a.contains(&ga_ver), "owner must see GA build");

    let cookie_b = login(&router, &email_b).await;
    let list_b = get(&router, &format!("/{slug_b}/builds"), cookie_b.as_deref()).await;
    assert!(status(&list_b).is_success());
    let body_b = body_text(list_b).await;
    assert!(
        !body_b.contains(&private_ver),
        "other org must not see private build"
    );
    assert!(body_b.contains(&ga_ver), "other org must see GA build");

    let detail_b = get(
        &router,
        &format!("/{slug_b}/builds/{private_ver}"),
        cookie_b.as_deref(),
    )
    .await;
    assert_eq!(status(&detail_b), StatusCode::NOT_FOUND);

    let dl_b = post_form(
        &router,
        &format!("/{slug_b}/builds/{private_ver}/download"),
        cookie_b.as_deref(),
        "",
    )
    .await;
    assert_eq!(status(&dl_b), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_builds_list_opens_latest_with_concept_actions() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("builds-ui");
    let slug = unique_slug("builds-ui");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "org").await;
    let older = unique_slug("old-rel");
    let newer = unique_slug("new-rel");
    {
        let mut conn = db.clone();
        for (ver, date) in [(&older, "2026-06-01"), (&newer, "2026-07-15")] {
            let _ = toasty::create!(Release {
                version: ver.clone(),
                channel: "LTS".to_owned(),
                released_on: date.to_owned(),
                size_mb: "2.0".to_owned(),
                signature_prefix: "abc".to_owned(),
                status: "PUBLISHED".to_owned(),
                notes: "FIX: concept".to_owned(),
                organization_id: RELEASE_GA_ORG_ID,
            })
            .exec(&mut conn)
            .await
            .expect("release");
        }
    }

    let cookie = login(&router, &email).await;
    let list = get(&router, &format!("/{slug}/builds"), cookie.as_deref()).await;
    assert!(status(&list).is_success());
    let body = body_text(list).await;
    assert!(
        body.contains(&format!("RELEASE NOTES · {newer}")),
        "latest build panel must be open by default: {body}"
    );
    assert!(
        !body.contains(&format!("RELEASE NOTES · {older}")),
        "older build must not be open by default"
    );
    assert!(body.contains("5-minute download link"), "{body}");
    assert!(body.contains("Verify signature"), "{body}");
    assert!(!body.contains("Collapse"), "Collapse must not appear");
    assert!(!body.contains("vcp_builds_eph"), "no client ephemeral JS");
    assert!(
        !body.contains("EPHEMERAL DOWNLOAD LINK"),
        "panel must stay hidden until server issues a token"
    );

    let gen_resp = post_form(
        &router,
        &format!("/{slug}/builds/{newer}/ephemeral"),
        cookie.as_deref(),
        "",
    )
    .await;
    assert!(
        status(&gen_resp).is_redirection(),
        "generate ephemeral must PRG: {:?}",
        status(&gen_resp)
    );

    let detail = get(
        &router,
        &format!("/{slug}/builds/{newer}"),
        cookie.as_deref(),
    )
    .await;
    assert!(status(&detail).is_success());
    let detail_body = body_text(detail).await;
    assert!(
        detail_body.contains("EPHEMERAL DOWNLOAD LINK"),
        "SSR panel after generate: {detail_body}"
    );
    let public_origin = test_config().await.primary_public_origin().to_owned();
    assert!(
        detail_body.contains(&format!("{public_origin}/releases/")),
        "public URL must use server.public_origins ({public_origin}): {detail_body}"
    );
    assert!(detail_body.contains("Regenerate link"), "{detail_body}");
    assert!(detail_body.contains("fetch"), "{detail_body}");
    assert!(detail_body.contains("cURL"), "{detail_body}");
    assert!(detail_body.contains("Revoke"), "{detail_body}");
    assert!(detail_body.contains("Copy"), "{detail_body}");
    assert!(
        detail_body.contains("Copy command") || detail_body.contains("vb-ephemeral-cmd-copy"),
        "cmd copy affordance: {detail_body}"
    );
    assert!(
        detail_body.contains("expires in "),
        "live countdown label: {detail_body}"
    );
    assert!(
        detail_body.contains("expires in ") && detail_body.contains(":"),
        "countdown must be M:SS shaped: {detail_body}"
    );

    assert!(
        detail_body.contains("vb-eph-seg") && detail_body.contains("cURL"),
        "fetch/cURL segment must be client-side (no ?tool=): {detail_body}"
    );
    assert!(
        !detail_body.contains("?tool="),
        "tool tabs must not navigate: {detail_body}"
    );
    let seg = detail_body
        .find("vb-eph-seg")
        .map(|i| &detail_body[i..detail_body.len().min(i + 1600)])
        .unwrap_or("");
    assert!(
        seg.contains("data-topcoat-on:click")
            && seg.contains("cx.hydrate(true)")
            && seg.contains("cx.hydrate(false)"),
        "fetch/cURL tabs must emit Topcoat click handlers that set the tool signal: {seg}"
    );
    // CI cannot drive a real browser click here; instead enforce the Topcoat
    // bind contract that the WKWebView repro showed was necessary for the
    // fetch/cURL tabs to hydrate at all (see common::topcoat_click).
    let eph = detail_body
        .find("vb-ephemeral")
        .map(|i| &detail_body[i..])
        .unwrap_or(detail_body.as_str());
    assert_topcoat_click_handlers_are_functions(eph);
    let clicks = data_topcoat_on_click_values(eph);
    assert!(
        clicks.iter().any(|c| c.contains("current_target")),
        "clipboard handlers must read current_target (not bind-time this): {clicks:?}"
    );
    assert!(
        clicks.iter().any(|c| c.contains("hydrate(true)")),
        "cURL tab handler must set signal true: {clicks:?}"
    );
    assert!(
        clicks.iter().any(|c| c.contains("hydrate(false)")),
        "fetch tab handler must set signal false: {clicks:?}"
    );

    let revoke = post_form(
        &router,
        &format!("/{slug}/builds/{newer}/ephemeral/revoke"),
        cookie.as_deref(),
        "",
    )
    .await;
    assert!(status(&revoke).is_redirection());
    let after_revoke = get(
        &router,
        &format!("/{slug}/builds/{newer}"),
        cookie.as_deref(),
    )
    .await;
    let after_body = body_text(after_revoke).await;
    assert!(
        !after_body.contains("EPHEMERAL DOWNLOAD LINK"),
        "revoke must clear SSR panel: {after_body}"
    );
    assert!(
        after_body.contains("5-minute download link"),
        "{after_body}"
    );

    let collapsed = get(
        &router,
        &format!("/{slug}/builds?open=none"),
        cookie.as_deref(),
    )
    .await;
    assert!(status(&collapsed).is_success());
    let collapsed_body = body_text(collapsed).await;
    assert!(
        !collapsed_body.contains("RELEASE NOTES ·"),
        "open=none must collapse all panels"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_ephemeral_expired_offers_generate_new_link() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("eph-exp");
    let slug = unique_slug("eph-exp-org");
    let (user, org) = create_org_with_membership(&db, &email, "password", &slug, "org").await;
    let version = unique_slug("eph-exp-rel");
    {
        let mut conn = db.clone();
        let _ = toasty::create!(Release {
            version: version.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-20".to_owned(),
            size_mb: "1.5".to_owned(),
            signature_prefix: "abc".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "FIX: expired".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
        })
        .exec(&mut conn)
        .await
        .expect("release");

        let now = now_unix();
        let _ = toasty::create!(EphemeralDownload {
            token: "expired-token-fixture".to_owned(),
            user_id: user.id,
            organization_id: org.id,
            release_version: version.clone(),
            expires_at: now - 30,
            created_at: now - 330,
        })
        .exec(&mut conn)
        .await
        .expect("expired ephemeral");
    }

    let cookie = login(&router, &email).await;
    let detail = get(
        &router,
        &format!("/{slug}/builds/{version}"),
        cookie.as_deref(),
    )
    .await;
    assert!(status(&detail).is_success());
    let body = body_text(detail).await;
    assert!(body.contains("EPHEMERAL DOWNLOAD LINK"), "{body}");
    assert!(body.contains("expired"), "{body}");
    assert!(
        body.contains("Generate new link"),
        "expired panel must offer regenerate: {body}"
    );

    cleanup(&db).await;
}
