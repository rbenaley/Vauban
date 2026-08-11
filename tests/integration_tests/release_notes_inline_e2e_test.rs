//! E2E: Builds changelog + org dashboard render paired backticks as mono chips.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::{
    models::{RELEASE_GA_ORG_ID, RELEASE_STATUS_PUBLISHED, Release},
    release_pkg::version_sort_fields,
};

use crate::common::{
    cleanup, create_org_with_membership, db_lock, get, login_cookie, seed_release_artifact, status,
    test_db, test_router, unique_email, unique_slug,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

async fn seed_ga_release_with_notes(db: &toasty::Db, version: &str, notes: &str) -> u64 {
    let sort = version_sort_fields(version);
    let mut conn = db.clone();
    let id = toasty::create!(Release {
        version: version.to_owned(),
        channel: "Stable".to_owned(),
        released_on: "2026-08-01".to_owned(),
        status: RELEASE_STATUS_PUBLISHED.to_owned(),
        notes: notes.to_owned(),
        organization_id: RELEASE_GA_ORG_ID,
        v_major: sort.v_major,
        v_minor: sort.v_minor,
        v_patch: sort.v_patch,
        is_industrial: 0,
        has_client_suffix: sort.has_client_suffix,
        client_suffix: sort.client_suffix,
        product_track: "Stable".to_owned(),
    })
    .exec(&mut conn)
    .await
    .expect("release")
    .id;
    let _ = seed_release_artifact(db, id, b"vcp-inline-code-fixture").await;
    id
}

#[tokio::test]
async fn e2e_builds_and_dashboard_render_inline_code_chips() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("notes-inline");
    let slug = unique_slug("notes-inline");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    // Unique high major so this row is the latest on the dashboard.
    let version = {
        let n = slug.bytes().map(|b| b as u32).sum::<u32>() % 50 + 50;
        format!("v{n}.3.1")
    };
    let notes =
        "FIX: Prefer `config/` over the workspace tree.\nFEAT: Add `webauthn_required` gate.";
    let _id = seed_ga_release_with_notes(&db, &version, notes).await;

    let router = test_router().await;
    let cookie = login_cookie(&router, &email).await;

    let builds = get(
        &router,
        &format!("/{slug}/builds/{version}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&builds), StatusCode::OK);
    let builds_body = body_text(builds).await;
    assert!(
        builds_body.contains("RELEASE NOTES"),
        "expected open changelog panel: {builds_body}"
    );
    assert!(
        builds_body.contains("vb-inline-code"),
        "Builds must emit vb-inline-code chips: {builds_body}"
    );
    assert!(
        builds_body.contains(">config/<") || builds_body.contains(">config/"),
        "chip must contain config/: {builds_body}"
    );
    assert!(
        builds_body.contains("webauthn_required"),
        "second chip body missing: {builds_body}"
    );
    // Backtick markers must not appear as visible delimiters around the chip.
    assert!(
        !builds_body.contains("`config/`"),
        "raw backtick-wrapped token must not remain in HTML: {builds_body}"
    );

    let dash = get(&router, &format!("/{slug}"), cookie.as_deref()).await;
    assert_eq!(status(&dash), StatusCode::OK);
    let dash_body = body_text(dash).await;
    assert!(dash_body.contains("LATEST CERTIFIED BUILD"), "{dash_body}");
    assert!(
        dash_body.contains("vb-inline-code"),
        "dashboard notes must emit vb-inline-code: {dash_body}"
    );
    assert!(
        dash_body.contains("config/"),
        "dashboard chip content missing: {dash_body}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_unpaired_backtick_stays_plain_text() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("notes-unpaired");
    let slug = unique_slug("notes-unpaired");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let version = {
        let n = slug.bytes().map(|b| b as u32).sum::<u32>() % 40 + 40;
        format!("v{n}.4.2")
    };
    let notes = "FIX: see `alone without close";
    let _id = seed_ga_release_with_notes(&db, &version, notes).await;

    let router = test_router().await;
    let cookie = login_cookie(&router, &email).await;
    let builds = get(
        &router,
        &format!("/{slug}/builds/{version}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&builds), StatusCode::OK);
    let body = body_text(builds).await;
    assert!(
        body.contains("alone without close"),
        "unpaired text must still render: {body}"
    );
    // No Code chip for the unpaired case — either zero chips, or chips only
    // from other content (none here).
    let chip_count = body.matches("vb-inline-code").count();
    assert_eq!(
        chip_count, 0,
        "unpaired backtick must not open a code chip: {body}"
    );

    cleanup(&db).await;
}
