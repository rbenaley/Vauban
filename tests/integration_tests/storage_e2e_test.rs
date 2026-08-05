//! E2E: image upload/serve + release upload→download sha match via storage helper.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::models::{RELEASE_GA_ORG_ID, RELEASE_STATUS_PUBLISHED, Release};
use vcp::storage::sha256_hex;

use crate::common::{
    MultipartFile, TINY_PNG, cleanup, config_dir, create_org_with_membership, db_lock, get,
    login_cookie, post_form, post_multipart_with_files, status, test_db, test_router, unique_email,
    unique_slug, urlencoding_encode,
};

async fn body_bytes(resp: topcoat::router::Response) -> bytes::Bytes {
    resp.into_body().collect().await.expect("body").to_bytes()
}

async fn body_text(resp: topcoat::router::Response) -> String {
    String::from_utf8_lossy(&body_bytes(resp).await).into_owned()
}

#[tokio::test]
async fn e2e_image_upload_get_nosniff() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("img-ok");
    let slug = unique_slug("img-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login_cookie(&router, &email).await;

    let upload = post_multipart_with_files(
        &router,
        &format!("/{slug}/images"),
        cookie.as_deref(),
        &[],
        &[MultipartFile {
            field: "image",
            filename: "shot.png",
            content_type: "image/png",
            bytes: TINY_PNG,
        }],
    )
    .await;
    assert_eq!(status(&upload), StatusCode::CREATED);
    let name = body_text(upload).await.trim().to_owned();
    assert!(
        name.ends_with(".png") && vcp::storage::is_uuid_key(name.trim_end_matches(".png")),
        "{name}"
    );

    let get_resp = get(
        &router,
        &format!("/{slug}/images/{name}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&get_resp), StatusCode::OK);
    let nosniff = get_resp
        .headers()
        .get("x-content-type-options")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(nosniff, "nosniff");
    let ct = get_resp
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(ct, "image/png");
    let bytes = body_bytes(get_resp).await;
    assert_eq!(bytes.as_ref(), TINY_PNG);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_image_missing_row_is_404_before_ipc() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("img-404");
    let slug = unique_slug("img-404-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login_cookie(&router, &email).await;

    // Valid UUID/ext shape, but no storage_objects row for this org → 404 before IPC.
    let fake = "550e8400-e29b-41d4-a716-446655440099.png";
    let resp = get(
        &router,
        &format!("/{slug}/images/{fake}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&resp), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_image_wrong_org_is_404() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email_a = unique_email("img-a");
    let slug_a = unique_slug("img-a");
    let (_ua, _oa) = create_org_with_membership(&db, &email_a, "password", &slug_a, "member").await;
    let cookie_a = login_cookie(&router, &email_a).await;

    let upload = post_multipart_with_files(
        &router,
        &format!("/{slug_a}/images"),
        cookie_a.as_deref(),
        &[],
        &[MultipartFile {
            field: "image",
            filename: "a.png",
            content_type: "image/png",
            bytes: TINY_PNG,
        }],
    )
    .await;
    assert_eq!(status(&upload), StatusCode::CREATED);
    let name = body_text(upload).await.trim().to_owned();

    let email_b = unique_email("img-b");
    let slug_b = unique_slug("img-b");
    let (_ub, _ob) = create_org_with_membership(&db, &email_b, "password", &slug_b, "member").await;
    let cookie_b = login_cookie(&router, &email_b).await;

    let resp = get(
        &router,
        &format!("/{slug_b}/images/{name}"),
        cookie_b.as_deref(),
    )
    .await;
    assert_eq!(status(&resp), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_release_upload_download_sha_match() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let admin_email = unique_email("store-admin");
    let admin_slug = unique_slug("store-admin-org");
    let (_admin, _aorg) =
        create_org_with_membership(&db, &admin_email, "password", &admin_slug, "admin").await;
    let admin_cookie = login_cookie(&router, &admin_email).await;

    let version = unique_slug("vstore");
    let pkg = b"vcp-storage-e2e-package-bytes";
    let expected_sha = sha256_hex(pkg);

    let create = post_multipart_with_files(
        &router,
        "/admin/releases/new",
        admin_cookie.as_deref(),
        &[
            ("version", &version),
            ("channel", "LTS"),
            ("date", "2026-08-01"),
            ("notes", "FIX: storage e2e"),
        ],
        &[MultipartFile {
            field: "package",
            filename: "vauban.pkg",
            content_type: "application/octet-stream",
            bytes: pkg,
        }],
    )
    .await;
    assert!(
        status(&create).is_redirection(),
        "create should PRG, got {}",
        status(&create)
    );

    // Catalog row must be PUBLISHED with a storage_objects digest.
    {
        let mut conn = db.clone();
        let rel = Release::all()
            .filter(Release::fields().version().eq(version.clone()))
            .exec(&mut conn)
            .await
            .expect("query")
            .into_iter()
            .next()
            .expect("release");
        assert_eq!(rel.status, RELEASE_STATUS_PUBLISHED);
        assert_eq!(rel.organization_id, RELEASE_GA_ORG_ID);
        let obj = vcp::storage::find_release_object(&mut conn, rel.id)
            .await
            .expect("storage_objects row");
        assert_eq!(obj.sha256, expected_sha);
        assert_eq!(obj.size_bytes, pkg.len() as u64);
    }

    let member_email = unique_email("store-member");
    let member_slug = unique_slug("store-member-org");
    let (_member, _morg) =
        create_org_with_membership(&db, &member_email, "password", &member_slug, "member").await;
    let member_cookie = login_cookie(&router, &member_email).await;

    let dl = post_form(
        &router,
        &format!("/{member_slug}/builds/{version}/download"),
        member_cookie.as_deref(),
        "",
    )
    .await;
    assert_eq!(status(&dl), StatusCode::OK);
    let nosniff = dl
        .headers()
        .get("x-content-type-options")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(nosniff, "nosniff");
    let bytes = body_bytes(dl).await;
    assert_eq!(bytes.as_ref(), pkg);
    assert_eq!(sha256_hex(&bytes), expected_sha);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_release_mirror_digest_mismatch_is_503() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let admin_email = unique_email("store-mm-admin");
    let admin_slug = unique_slug("store-mm-admin-org");
    let (_admin, _aorg) =
        create_org_with_membership(&db, &admin_email, "password", &admin_slug, "admin").await;
    let admin_cookie = login_cookie(&router, &admin_email).await;

    let version = unique_slug("vstore-mm");
    let pkg = b"vcp-storage-mirror-mismatch-bytes";

    let create = post_multipart_with_files(
        &router,
        "/admin/releases/new",
        admin_cookie.as_deref(),
        &[
            ("version", &version),
            ("channel", "LTS"),
            ("date", "2026-08-01"),
            ("notes", "FIX: mirror mismatch"),
        ],
        &[MultipartFile {
            field: "package",
            filename: "vauban.pkg",
            content_type: "application/octet-stream",
            bytes: pkg,
        }],
    )
    .await;
    assert!(
        status(&create).is_redirection(),
        "create should PRG, got {}",
        status(&create)
    );

    let release_id = {
        let mut conn = db.clone();
        let rel = Release::all()
            .filter(Release::fields().version().eq(version.clone()))
            .exec(&mut conn)
            .await
            .expect("query")
            .into_iter()
            .next()
            .expect("release");
        // Forge Postgres mirror digest while SQLite SoT + disk stay correct.
        vcp::storage::upsert_release_object(
            &mut conn,
            rel.id,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            pkg.len() as u64,
        )
        .await
        .expect("forge mirror");
        rel.id
    };
    let _ = release_id;

    let member_email = unique_email("store-mm-member");
    let member_slug = unique_slug("store-mm-member-org");
    let (_member, _morg) =
        create_org_with_membership(&db, &member_email, "password", &member_slug, "member").await;
    let member_cookie = login_cookie(&router, &member_email).await;

    let dl = post_form(
        &router,
        &format!("/{member_slug}/builds/{version}/download"),
        member_cookie.as_deref(),
        "",
    )
    .await;
    assert_eq!(status(&dl), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_text(dl).await;
    assert_eq!(body.trim(), "integrity mismatch");

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_webauthn_gated_release_prepare_commit_soft() {
    use vcp::config::{StorageConfig, StorageIpcMode};
    use vcp::storage::{StorageEngine, StorageScope, soft_assertion_json, write_abs_file};

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let cfg = StorageConfig {
        blob_path: root.to_string_lossy().into(),
        ipc: StorageIpcMode::Inline,
        webauthn_required: true,
        max_artifact_bytes: 1024 * 1024,
        ..StorageConfig::default()
    };
    let eng = StorageEngine::open(&root, cfg).unwrap();
    let cred = b"e2e-soft-key";
    eng.seed_soft_active_credential(cred, "e2e").unwrap();
    let data = b"release-pkg-bytes";
    let begin = eng
        .put_begin(
            StorageScope::Release,
            Some("9001"),
            None,
            data.len() as u64,
            None,
        )
        .unwrap();
    write_abs_file(&eng.partial_abs_path(&begin.upload_id).unwrap(), data).unwrap();
    let digest = sha256_hex(data);
    let prep = eng.put_prepare(&begin.upload_id, &digest).unwrap();
    assert!(prep.challenge.summary.contains("release_put_commit"));
    let deny = eng
        .put_commit(&begin.upload_id, &digest, None, None)
        .unwrap_err();
    assert_eq!(deny.code, vcp::storage::StorageErrorCode::WebauthnRequired);
    let assertion = soft_assertion_json(cred, &prep.challenge.challenge_id, true, 0);
    let st = eng
        .put_commit(&begin.upload_id, &digest, None, Some(&assertion))
        .unwrap();
    assert_eq!(st.sha256, digest);
}

/// §6.5 KEY dashboard: staff sees the E1/E2 surfaces; non-staff gets 404
/// (anti-enumeration); revoke without the typed confirmation never reaches
/// the helper (PRG back with `err=confirm`).
#[tokio::test]
async fn e2e_key_dashboard_staff_ok_member_404_and_revoke_guard() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let admin_email = unique_email("key-admin");
    let admin_slug = unique_slug("key-admin-org");
    let (_admin, _aorg) =
        create_org_with_membership(&db, &admin_email, "password", &admin_slug, "admin").await;
    let admin_cookie = login_cookie(&router, &admin_email).await;

    let page = get(&router, "/admin/key", admin_cookie.as_deref()).await;
    assert_eq!(status(&page), StatusCode::OK);
    let html = body_text(page).await;
    assert!(html.contains("Security keys"), "page title");
    assert!(
        html.contains("vcp-store key approve"),
        "E2 CLI instructions (ADR 003)"
    );
    assert!(
        html.contains("vcp-store key pending"),
        "helper-host cross-check hint"
    );
    assert!(
        html.contains("data-mode=\"create\""),
        "E1 WebAuthn ceremony root"
    );

    let member_email = unique_email("key-member");
    let member_slug = unique_slug("key-member-org");
    let (_member, _morg) =
        create_org_with_membership(&db, &member_email, "password", &member_slug, "member").await;
    let member_cookie = login_cookie(&router, &member_email).await;
    let denied = get(&router, "/admin/key", member_cookie.as_deref()).await;
    assert_eq!(status(&denied), StatusCode::NOT_FOUND);

    let bad_confirm = post_form(
        &router,
        "/admin/key/revoke",
        admin_cookie.as_deref(),
        "credential_id_hex=0a0b&confirm=nope",
    )
    .await;
    assert!(status(&bad_confirm).is_redirection());
    let loc = bad_confirm
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(loc.contains("err=confirm"), "got location {loc}");

    cleanup(&db).await;
}

/// Empty / whitespace `admin_label` on enrol must PRG to `err=label` before
/// attestation parsing (denial path without a real WebAuthn payload).
#[tokio::test]
async fn e2e_key_enrol_rejects_empty_admin_label() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let admin_email = unique_email("key-label");
    let admin_slug = unique_slug("key-label-org");
    let (_admin, _aorg) =
        create_org_with_membership(&db, &admin_email, "password", &admin_slug, "admin").await;
    let admin_cookie = login_cookie(&router, &admin_email).await;

    for (name, form) in [
        ("empty", "admin_label=&attestation=%7B%7D"),
        ("spaces", "admin_label=+++&attestation=%7B%7D"),
        ("tabs", "admin_label=%09%09&attestation=garbage"),
    ] {
        let resp = post_form(&router, "/admin/key/enrol", admin_cookie.as_deref(), form).await;
        assert!(
            status(&resp).is_redirection(),
            "{name}: expected redirect, got {:?}",
            status(&resp)
        );
        let loc = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            loc.contains("err=label"),
            "{name}: expected err=label, got {loc}"
        );
        assert!(
            !loc.contains("err=attestation"),
            "{name}: label must be checked before attestation"
        );
    }

    cleanup(&db).await;
}

/// Full KEY lifecycle on the portal seam: enrol (fake attestation) → CLI-equivalent
/// approve on the test blob root → dashboard ACTIVE → typed revoke clears ACTIVE.
#[tokio::test]
async fn e2e_key_enrol_approve_revoke_lifecycle() {
    use vcp::config::{Config, Environment};
    use vcp::storage::{StorageEngine, credential_fingerprint, test_attestation_object_b64};

    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let admin_email = unique_email("key-life");
    let admin_slug = unique_slug("key-life-org");
    let (_admin, _aorg) =
        create_org_with_membership(&db, &admin_email, "password", &admin_slug, "admin").await;
    let admin_cookie = login_cookie(&router, &admin_email).await;

    // Unique per run so parallel / leftover meta.sqlite rows cannot collide.
    let cred = format!("e2e-key-lifecycle-{}", unique_slug("cred")).into_bytes();
    let cose = format!("e2e-key-cose-{}", unique_slug("cose")).into_bytes();
    let fp = credential_fingerprint(&cred, &cose);
    let att_json = serde_json::json!({
        "response": { "attestationObject": test_attestation_object_b64(&cred, &cose) }
    })
    .to_string();
    let form = format!(
        "admin_label=e2e-lifecycle&attestation={}",
        urlencoding_encode(&att_json)
    );
    let enrol = post_form(&router, "/admin/key/enrol", admin_cookie.as_deref(), &form).await;
    assert!(status(&enrol).is_redirection());
    let loc = enrol
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        loc.contains(&format!("enrolled={fp}")),
        "expected enrolled fingerprint, got {loc}"
    );

    let cfg = Config::load_with_environment(config_dir(), Environment::Testing).unwrap();
    std::fs::create_dir_all(&cfg.storage.blob_path).unwrap();
    let eng = StorageEngine::open(
        std::path::Path::new(&cfg.storage.blob_path),
        cfg.storage.clone(),
    )
    .unwrap();
    let pending = eng.key_list_json("pending").unwrap();
    assert!(
        pending.contains(&fp) && pending.contains("e2e-lifecycle"),
        "pending list: {pending}"
    );
    eng.key_approve(&fp).unwrap();
    let active = eng.key_list_json("active").unwrap();
    assert!(
        active.contains(&fp) && active.contains("e2e-lifecycle"),
        "active list: {active}"
    );
    assert!(!eng.key_list_json("pending").unwrap().contains(&fp));

    let page = get(&router, "/admin/key", admin_cookie.as_deref()).await;
    assert_eq!(status(&page), StatusCode::OK);
    let html = body_text(page).await;
    assert!(html.contains("e2e-lifecycle"), "ACTIVE table label");
    assert!(html.contains(&fp[..12]), "fingerprint prefix in UI");

    let active_json: serde_json::Value = serde_json::from_str(&active).unwrap();
    let cred_hex = active_json
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r.get("fingerprint").and_then(|v| v.as_str()) == Some(fp.as_str()))
        .and_then(|r| r.get("credential_id_hex"))
        .and_then(|v| v.as_str())
        .expect("credential_id_hex for enrolled fingerprint");
    let revoke = post_form(
        &router,
        "/admin/key/revoke",
        admin_cookie.as_deref(),
        &format!("credential_id_hex={cred_hex}&confirm=revoke"),
    )
    .await;
    assert!(status(&revoke).is_redirection());
    let rloc = revoke
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(!rloc.contains("err="), "revoke must succeed, got {rloc}");
    let after = eng.key_list_json("active").unwrap();
    assert!(
        !after.contains(&fp),
        "revoked key must leave ACTIVE list: {after}"
    );

    cleanup(&db).await;
}
