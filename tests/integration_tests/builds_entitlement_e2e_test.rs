//! E2E: authorized download streams blob; wrong org 404; anonymous denied; GA vs private.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::{
    db::now_unix,
    models::{
        EphemeralDownload, RELEASE_GA_ORG_ID, RELEASE_STATUS_HIDDEN, RELEASE_STATUS_PUBLISHED,
        Release,
    },
};

use crate::common::{
    assert_topcoat_click_handlers_are_functions, cleanup, create_org_with_membership,
    create_test_org, data_topcoat_on_click_values, db_lock, get, login_cookie, post_form,
    seed_release_artifact, seed_release_digest, status, test_config, test_db, test_router,
    unique_email, unique_slug,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

async fn login(router: &topcoat::router::Router, email: &str) -> Option<String> {
    login_cookie(router, email).await
}

#[tokio::test]
async fn e2e_authorized_download_returns_200_with_blob() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("dl-ok");
    let slug = unique_slug("dl-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let version = unique_slug("dlv");
    let payload = b"vcp-entitlement-download-fixture-bytes";
    {
        let mut conn = db.clone();
        let id = toasty::create!(Release {
            version: version.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "FIX: x".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: vcp::release_pkg::version_sort_fields(&version).v_major,
            v_minor: vcp::release_pkg::version_sort_fields(&version).v_minor,
            v_patch: vcp::release_pkg::version_sort_fields(&version).v_patch,
            has_client_suffix: vcp::release_pkg::version_sort_fields(&version).has_client_suffix,
            client_suffix: vcp::release_pkg::version_sort_fields(&version).client_suffix,
        })
        .exec(&mut conn)
        .await
        .expect("release")
        .id;
        let _sha = seed_release_artifact(&db, id, payload).await;
    }

    let router = test_router().await;
    let cookie = login(&router, &email).await;
    let resp = post_form(
        &router,
        &format!("/{slug}/builds/{version}/download"),
        cookie.as_deref(),
        "",
    )
    .await;
    assert_eq!(status(&resp), StatusCode::OK);
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    assert_eq!(bytes.as_ref(), payload);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_download_without_storage_row_is_404() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("dl-nostore");
    let slug = unique_slug("dl-nostore");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let version = unique_slug("dlv-nostore");
    {
        let mut conn = db.clone();
        let _ = toasty::create!(Release {
            version: version.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "FIX: no blob meta".to_owned(),
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

    let cookie = login(&router, &email).await;
    let resp = post_form(
        &router,
        &format!("/{slug}/builds/{version}/download"),
        cookie.as_deref(),
        "",
    )
    .await;
    assert_eq!(status(&resp), StatusCode::NOT_FOUND);

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
            status: "PUBLISHED".to_owned(),
            notes: "FIX: x".to_owned(),
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
            status: "PUBLISHED".to_owned(),
            notes: "FIX: x".to_owned(),
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
        "anonymous must not get 200/501, got {st}"
    );
    assert_ne!(st, StatusCode::OK);
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

    // High versions so both rows land on page 1 above the seed catalog.
    let private_ver = "v97.0.1-acme".to_owned();
    let ga_ver = "v97.0.0".to_owned();
    {
        let mut conn = db.clone();
        let _ = toasty::create!(Release {
            version: private_ver.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "HOTFIX: private".to_owned(),
            organization_id: org_a.id,
            v_major: vcp::release_pkg::version_sort_fields(&private_ver).v_major,
            v_minor: vcp::release_pkg::version_sort_fields(&private_ver).v_minor,
            v_patch: vcp::release_pkg::version_sort_fields(&private_ver).v_patch,
            has_client_suffix: vcp::release_pkg::version_sort_fields(&private_ver)
                .has_client_suffix,
            client_suffix: vcp::release_pkg::version_sort_fields(&private_ver).client_suffix,
        })
        .exec(&mut conn)
        .await
        .expect("private release");
        let _ = toasty::create!(Release {
            version: ga_ver.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-02".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "GA".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: vcp::release_pkg::version_sort_fields(&ga_ver).v_major,
            v_minor: vcp::release_pkg::version_sort_fields(&ga_ver).v_minor,
            v_patch: vcp::release_pkg::version_sort_fields(&ga_ver).v_patch,
            has_client_suffix: vcp::release_pkg::version_sort_fields(&ga_ver).has_client_suffix,
            client_suffix: vcp::release_pkg::version_sort_fields(&ga_ver).client_suffix,
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
async fn e2e_reserved_vauban_org_sees_all_client_private_releases() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let staff_email = unique_email("staff-see-priv");
    // Admin helper also attaches membership on reserved `vauban`.
    let (_staff, _home) = create_org_with_membership(
        &db,
        &staff_email,
        "password",
        &unique_slug("staff-home"),
        "admin",
    )
    .await;

    let client_email = unique_email("client-priv");
    let client_slug = unique_slug("client-priv");
    let (_client, client_org) =
        create_org_with_membership(&db, &client_email, "password", &client_slug, "member").await;

    // High shared core so the three rows share page 1 above the seed catalog.
    let private_ver = "v96.0.0-acme1".to_owned();
    let other_client_ver = "v96.0.0-zenith".to_owned();
    let plain = "v96.0.0".to_owned();
    {
        let mut conn = db.clone();
        for (ver, org_id) in [
            (private_ver.as_str(), client_org.id),
            (other_client_ver.as_str(), client_org.id),
            (plain.as_str(), RELEASE_GA_ORG_ID),
        ] {
            let _ = toasty::create!(Release {
                version: ver.to_owned(),
                channel: "EOL".to_owned(),
                released_on: "2026-06-18".to_owned(),
                status: "PUBLISHED".to_owned(),
                notes: "FIX: visibility".to_owned(),
                organization_id: org_id,
                v_major: vcp::release_pkg::version_sort_fields(ver).v_major,
                v_minor: vcp::release_pkg::version_sort_fields(ver).v_minor,
                v_patch: vcp::release_pkg::version_sort_fields(ver).v_patch,
                has_client_suffix: vcp::release_pkg::version_sort_fields(ver).has_client_suffix,
                client_suffix: vcp::release_pkg::version_sort_fields(ver).client_suffix,
            })
            .exec(&mut conn)
            .await
            .expect("release");
        }
    }

    let cookie = login(&router, &staff_email).await;
    let list = get(&router, "/vauban/builds", cookie.as_deref()).await;
    assert!(status(&list).is_success());
    let body = body_text(list).await;
    assert!(body.contains(&private_ver), "staff must see acme1: {body}");
    assert!(
        body.contains(&other_client_ver),
        "staff must see zenith: {body}"
    );
    assert!(body.contains(&plain), "staff must see GA plain: {body}");
    // Exact version cell text — avoid substring hits inside `v96.0.0-acme1`.
    let acme_pos = body.find(">v96.0.0-acme1<").expect("acme1 cell");
    let zenith_pos = body.find(">v96.0.0-zenith<").expect("zenith cell");
    let plain_pos = body.find(">v96.0.0<").expect("plain cell");
    assert!(
        acme_pos < zenith_pos && zenith_pos < plain_pos,
        "client variants A→Z above plain: {body}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_hidden_ga_release_absent_from_client_builds() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("hidden-ga");
    let slug = unique_slug("hidden-ga");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "org").await;

    let hidden_ver = "v94.hidden.0".to_owned();
    let published_ver = "v94.pub.0".to_owned();
    {
        let mut conn = db.clone();
        let _ = toasty::create!(Release {
            version: hidden_ver.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            status: RELEASE_STATUS_HIDDEN.to_owned(),
            notes: "FIX: hidden".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: vcp::release_pkg::version_sort_fields(&hidden_ver).v_major,
            v_minor: vcp::release_pkg::version_sort_fields(&hidden_ver).v_minor,
            v_patch: vcp::release_pkg::version_sort_fields(&hidden_ver).v_patch,
            has_client_suffix: vcp::release_pkg::version_sort_fields(&hidden_ver).has_client_suffix,
            client_suffix: vcp::release_pkg::version_sort_fields(&hidden_ver).client_suffix,
        })
        .exec(&mut conn)
        .await
        .expect("hidden");
        let _ = toasty::create!(Release {
            version: published_ver.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-02".to_owned(),
            status: RELEASE_STATUS_PUBLISHED.to_owned(),
            notes: "FIX: published".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: vcp::release_pkg::version_sort_fields(&published_ver).v_major,
            v_minor: vcp::release_pkg::version_sort_fields(&published_ver).v_minor,
            v_patch: vcp::release_pkg::version_sort_fields(&published_ver).v_patch,
            has_client_suffix: vcp::release_pkg::version_sort_fields(&published_ver)
                .has_client_suffix,
            client_suffix: vcp::release_pkg::version_sort_fields(&published_ver).client_suffix,
        })
        .exec(&mut conn)
        .await
        .expect("published");
    }

    let cookie = login(&router, &email).await;
    let list = get(&router, &format!("/{slug}/builds"), cookie.as_deref()).await;
    assert!(status(&list).is_success());
    let body = body_text(list).await;
    assert!(
        !body.contains(&hidden_ver),
        "client must not see HIDDEN GA: {body}"
    );
    assert!(
        body.contains(&published_ver),
        "client must see PUBLISHED GA: {body}"
    );

    let detail = get(
        &router,
        &format!("/{slug}/builds/{hidden_ver}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&detail), StatusCode::NOT_FOUND);

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
    // Higher version must win even when its released_on is older.
    // Use v98.* so fixtures sort above the seed GA catalog and stay on page 1.
    let higher = "v98.0.1".to_owned();
    let lower = "v98.0.0".to_owned();
    let digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    {
        let mut conn = db.clone();
        for (ver, date) in [(&higher, "2026-01-01"), (&lower, "2026-12-31")] {
            let id = toasty::create!(Release {
                version: ver.clone(),
                channel: "LTS".to_owned(),
                released_on: date.to_owned(),
                status: "PUBLISHED".to_owned(),
                notes: "FIX: concept".to_owned(),
                organization_id: RELEASE_GA_ORG_ID,
                v_major: vcp::release_pkg::version_sort_fields(ver).v_major,
                v_minor: vcp::release_pkg::version_sort_fields(ver).v_minor,
                v_patch: vcp::release_pkg::version_sort_fields(ver).v_patch,
                has_client_suffix: vcp::release_pkg::version_sort_fields(ver).has_client_suffix,
                client_suffix: vcp::release_pkg::version_sort_fields(ver).client_suffix,
            })
            .exec(&mut conn)
            .await
            .expect("release")
            .id;
            // Digests live on storage_objects (UI via release_blob_display).
            seed_release_digest(&db, id, digest, 1_048_576).await;
        }
    }

    let cookie = login(&router, &email).await;
    let list = get(&router, &format!("/{slug}/builds"), cookie.as_deref()).await;
    assert!(status(&list).is_success());
    let body = body_text(list).await;
    assert!(
        body.contains(&format!("RELEASE NOTES · {higher}")),
        "highest version must open by default (not newest date): {body}"
    );
    assert!(
        !body.contains(&format!("RELEASE NOTES · {lower}")),
        "lower version must not be open by default: {body}"
    );
    let higher_pos = body.find(&higher).expect("higher version in list");
    let lower_pos = body.find(&lower).expect("lower version in list");
    assert!(
        higher_pos < lower_pos,
        "list must order by version desc (ignore dates): {body}"
    );
    assert!(body.contains("5-minute download link"), "{body}");
    assert!(
        body.contains("vb-badge chan-lts"),
        "LTS channel badge must use Concept green class: {body}"
    );
    assert!(body.contains("Verify signature"), "{body}");
    assert!(
        body.contains("<button") && body.contains("Verify signature"),
        "Verify must be a button: {body}"
    );
    assert!(
        body.contains("vb-verify") || body.contains("data-verify-signature-panel"),
        "verify panel hook: {body}"
    );
    assert!(body.contains(digest), "full sha256 in page: {body}");
    let verify_cmd = format!(
        "sha256 {}",
        vcp::release_pkg::package_file_name(&higher, "LTS")
    );
    assert!(
        body.contains(&verify_cmd),
        "verify cmd copy target: {verify_cmd} not in {body}"
    );
    assert!(body.contains("PACKAGE SIGNATURE"), "{body}");
    assert!(!body.contains("Collapse"), "Collapse must not appear");
    assert!(!body.contains("vcp_builds_eph"), "no client ephemeral JS");
    assert!(
        !body.contains("EPHEMERAL DOWNLOAD LINK"),
        "panel must stay hidden until server issues a token"
    );

    let gen_resp = post_form(
        &router,
        &format!("/{slug}/builds/{higher}/ephemeral"),
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
        &format!("/{slug}/builds/{higher}"),
        cookie.as_deref(),
    )
    .await;
    assert!(status(&detail).is_success());
    let detail_body = body_text(detail).await;
    assert!(
        detail_body.contains("EPHEMERAL DOWNLOAD LINK"),
        "SSR panel after generate: {detail_body}"
    );
    assert!(
        detail_body.contains("data-ephemeral-panel-host"),
        "ephemeral must be host-wrapped so Verify can hide it: {detail_body}"
    );
    // Mutual exclusivity is client-side (verify_open → display:none on host).
    // Pin the Topcoat :style bind on the host so CI catches a missing gate.
    let host_idx = detail_body
        .find("data-ephemeral-panel-host")
        .expect("ephemeral host attr");
    let host_window =
        &detail_body[host_idx.saturating_sub(80)..detail_body.len().min(host_idx + 500)];
    assert!(
        host_window.contains("data-topcoat-bind:style"),
        "ephemeral host must emit data-topcoat-bind:style (verify_open exclusivity): {host_window}"
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
        &format!("/{slug}/builds/{higher}/ephemeral/revoke"),
        cookie.as_deref(),
        "",
    )
    .await;
    assert!(status(&revoke).is_redirection());
    let after_revoke = get(
        &router,
        &format!("/{slug}/builds/{higher}"),
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
            status: "PUBLISHED".to_owned(),
            notes: "FIX: expired".to_owned(),
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

#[tokio::test]
async fn e2e_builds_list_pagination() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("builds-page");
    let slug = unique_slug("builds-page");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "org").await;
    {
        let mut conn = db.clone();
        for i in 0..11u32 {
            let version = format!("v99.0.{i}");
            let _ = toasty::create!(Release {
                version: version.clone(),
                channel: "LTS".to_owned(),
                released_on: "2026-07-01".to_owned(),
                status: "PUBLISHED".to_owned(),
                notes: "FIX: pagination".to_owned(),
                organization_id: RELEASE_GA_ORG_ID,
                v_major: vcp::release_pkg::version_sort_fields(&version).v_major,
                v_minor: vcp::release_pkg::version_sort_fields(&version).v_minor,
                v_patch: vcp::release_pkg::version_sort_fields(&version).v_patch,
                has_client_suffix: vcp::release_pkg::version_sort_fields(&version)
                    .has_client_suffix,
                client_suffix: vcp::release_pkg::version_sort_fields(&version).client_suffix,
            })
            .exec(&mut conn)
            .await
            .expect("release");
        }
    }

    let cookie = login(&router, &email).await;
    let page1 = get(
        &router,
        &format!("/{slug}/builds?page=1"),
        cookie.as_deref(),
    )
    .await;
    assert!(status(&page1).is_success());
    let p1 = body_text(page1).await;
    let rows_p1 = p1.matches("vb-build-row").count();
    assert_eq!(rows_p1, 10, "page 1 must show 10 rows: {p1}");
    assert!(
        p1.contains("RELEASE NOTES · v99.0.10"),
        "page 1 default-open highest: {p1}"
    );
    assert!(p1.contains("vb-pager"), "pager when >10: {p1}");
    assert!(p1.contains(&format!("/{slug}/builds?page=2")), "{p1}");
    // Layout: pager shares the chip row (chips left, pager right), before table.
    let chip_row = p1
        .find("vb-chip-row")
        .and_then(|i| {
            let rest = &p1[i..];
            rest.find("vb-table-wrap").map(|j| &rest[..j])
        })
        .expect("chip row before table");
    assert!(
        chip_row.contains("vb-chip-group"),
        "chip group in row: {chip_row}"
    );
    assert!(
        chip_row.contains("vb-pager"),
        "pager in chip row: {chip_row}"
    );
    let group_at = chip_row.find("vb-chip-group").expect("group");
    let pager_at = chip_row.find("vb-pager").expect("pager");
    assert!(group_at < pager_at, "chips before pager in row: {chip_row}");

    let page2 = get(
        &router,
        &format!("/{slug}/builds?page=2"),
        cookie.as_deref(),
    )
    .await;
    assert!(status(&page2).is_success());
    let p2 = body_text(page2).await;
    let rows_p2 = p2.matches("vb-build-row").count();
    // Seed catalog may add further pages; page 2 must include the remainder marker.
    assert!(
        (1..=10).contains(&rows_p2),
        "page 2 row count: {rows_p2} in {p2}"
    );
    assert!(p2.contains(">v99.0.0<") || p2.contains("v99.0.0"), "{p2}");
    assert!(
        !p2.contains("RELEASE NOTES ·"),
        "page 2 must not default-open: {p2}"
    );
    assert!(
        !p2.contains(">v99.0.10<"),
        "page 2 must not list page-1 highest: {p2}"
    );

    // Channel chip from page 2 must drop page= (reset to page 1).
    assert!(
        p2.contains(&format!("href=\"/{slug}/builds?channel=LTS\""))
            || p2.contains(&format!("/{slug}/builds?channel=LTS\"")),
        "LTS chip must omit page: {p2}"
    );
    assert!(
        !p2.contains("channel=LTS&page=") && !p2.contains("channel=LTS&amp;page="),
        "channel chips must not sticky page=: {p2}"
    );

    let deep = get(
        &router,
        &format!("/{slug}/builds/v99.0.0"),
        cookie.as_deref(),
    )
    .await;
    assert!(status(&deep).is_success());
    let deep_body = body_text(deep).await;
    assert!(
        deep_body.contains("RELEASE NOTES · v99.0.0"),
        "deep-link must open page-2 version: {deep_body}"
    );
    assert!(
        (deep_body.contains("vb-pager-link active") && deep_body.contains(">2<"))
            || deep_body.contains("page=2"),
        "deep-link must land on page 2: {deep_body}"
    );
    assert!(
        !deep_body.contains(">v99.0.10<"),
        "open build must stay on its page slice: {deep_body}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_builds_sql_semver_order_matches_product_rules() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("semver-ord");
    let slug = unique_slug("semver-ord");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let versions = ["v0.9.0", "v0.10.0", "v0.9.0-zenith", "v0.9.0-acme"];
    {
        let mut conn = db.clone();
        for version in versions {
            let _ = toasty::create!(Release {
                version: version.to_owned(),
                channel: "LTS".to_owned(),
                released_on: "2026-07-01".to_owned(),
                status: "PUBLISHED".to_owned(),
                notes: "FIX: semver order".to_owned(),
                organization_id: RELEASE_GA_ORG_ID,
                v_major: vcp::release_pkg::version_sort_fields(version).v_major,
                v_minor: vcp::release_pkg::version_sort_fields(version).v_minor,
                v_patch: vcp::release_pkg::version_sort_fields(version).v_patch,
                has_client_suffix: vcp::release_pkg::version_sort_fields(version).has_client_suffix,
                client_suffix: vcp::release_pkg::version_sort_fields(version).client_suffix,
            })
            .exec(&mut conn)
            .await
            .expect("release");
        }
    }

    let cookie = login(&router, &email).await;
    let page = get(
        &router,
        &format!("/{slug}/builds?channel=LTS"),
        cookie.as_deref(),
    )
    .await;
    assert!(status(&page).is_success());
    let html = body_text(page).await;
    let i10 = html.find("v0.10.0").expect("v0.10.0 in html");
    let i_acme = html.find("v0.9.0-acme").expect("acme in html");
    let i_zen = html.find("v0.9.0-zenith").expect("zenith in html");
    let i_plain = html
        .rfind(">v0.9.0<")
        .or_else(|| html.find("v0.9.0"))
        .expect("plain");
    assert!(i10 < i_acme, "0.10 before acme: {html}");
    assert!(i_acme < i_zen, "acme before zenith: {html}");
    assert!(i_zen < i_plain, "zenith before plain: {html}");

    cleanup(&db).await;
}
