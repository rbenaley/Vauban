//! Contention: concurrent put_commit under tempfile + parallel image GET.

use std::sync::Arc;

use http_body_util::BodyExt;
use std::io::Write;
use tokio::sync::Barrier;
use topcoat::router::StatusCode;
use vcp::config::{StorageConfig, StorageIpcMode};
use vcp::list_page::KEY_PAGE_SIZE;
use vcp::storage::{MetaDb, MetaObject, StorageEngine, StorageScope, sha256_hex, write_abs_file};

use crate::common::{
    MultipartFile, TINY_PNG, assert_rewritten_page, cleanup, create_org_with_membership, db_lock,
    get, login_cookie, post_form, post_multipart_with_files, status, test_db, test_router,
    unique_email, unique_slug,
};

/// Lot D: a flood of invalid enrol POSTs (empty label / garbage attestation)
/// re-runs `/admin/key` (200 + callout) for every request — no 303, no 5xx.
#[tokio::test]
async fn battle_parallel_invalid_key_enrol_rerenders() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = Arc::new(test_router().await);

    let email = unique_email("battle-key-enrol");
    let slug = unique_slug("battle-key-enrol");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login_cookie(router.as_ref(), &email).await.expect("cookie");

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let router = router.clone();
        let cookie = cookie.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let (form, marker) = if i % 2 == 0 {
                ("admin_label=&attestation=%7B%7D", "Key label is required")
            } else {
                (
                    "admin_label=battle&attestation=not-json",
                    "did not return a usable attestation",
                )
            };
            let resp = post_form(router.as_ref(), "/admin/key/enrol", Some(&cookie), form).await;
            let html = assert_rewritten_page(resp, marker).await;
            assert!(html.contains("vb-rail"), "rewritten key page keeps chrome");
        }));
    }
    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}

fn engine_cfg() -> StorageConfig {
    StorageConfig {
        blob_path: "/tmp/unused".into(),
        ipc: StorageIpcMode::Inline,
        max_artifact_bytes: 1024 * 1024,
        max_image_bytes: 64 * 1024,
        max_concurrent_uploads: 8,
        max_images_per_org: 100,
        webauthn_required: false,
        ..StorageConfig::default()
    }
}

#[test]
fn battle_concurrent_dirfd_handoff_write_commit() {
    let dir = tempfile::tempdir().unwrap();
    let root = Arc::new(dir.path().canonicalize().unwrap());
    {
        let _bootstrap = StorageEngine::open(root.as_path(), engine_cfg()).expect("bootstrap");
    }
    let n = 8usize;
    let barrier = Arc::new(std::sync::Barrier::new(n));
    let mut handles = Vec::with_capacity(n);

    for i in 0..n {
        let root = root.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let opened = StorageEngine::open(root.as_path(), engine_cfg());
            barrier.wait();
            let eng = opened.expect("open engine");
            let release_id = format!("{}", 20_000 + i);
            let data = format!("dirfd-handoff-{i}").into_bytes();
            let digest = sha256_hex(&data);
            let begin = eng
                .put_begin(
                    StorageScope::Release,
                    Some(&release_id),
                    None,
                    data.len() as u64,
                    None,
                )
                .expect("put_begin");
            let mut file = eng
                .open_partial_for_handoff(&begin.upload_id)
                .expect("dirfd handoff");
            file.write_all(&data).expect("write fd");
            file.sync_all().expect("fsync");
            drop(file);
            let st = eng
                .put_commit(&begin.upload_id, &digest, None, None)
                .expect("put_commit");
            assert_eq!(st.sha256, digest);
            let mut obj = eng
                .open_object_for_handoff(StorageScope::Release, Some(&release_id), None, None, None)
                .expect("object handoff");
            let mut got = Vec::new();
            std::io::Read::read_to_end(&mut obj, &mut got).expect("read");
            assert_eq!(got, data);
        }));
    }

    for h in handles {
        h.join().expect("join");
    }
}

#[test]
fn battle_concurrent_put_commit_under_tempfile() {
    let dir = tempfile::tempdir().unwrap();
    let root = Arc::new(dir.path().canonicalize().unwrap());
    // Serialize schema / WAL bootstrap so N concurrent opens do not race CREATE.
    {
        let _bootstrap = StorageEngine::open(root.as_path(), engine_cfg()).expect("bootstrap");
    }
    let n = 8usize;
    let barrier = Arc::new(std::sync::Barrier::new(n));
    let mut handles = Vec::with_capacity(n);

    for i in 0..n {
        let root = root.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            // Per-thread engine (cap-std Dir is not Sync); same blob root.
            // Always reach the barrier even if open fails — otherwise a panic
            // before wait() deadlocks the other threads forever.
            let opened = StorageEngine::open(root.as_path(), engine_cfg());
            barrier.wait();
            let eng = opened.expect("open engine");
            let release_id = format!("{}", 10_000 + i);
            let data = format!("pkg-body-{i}").into_bytes();
            let digest = sha256_hex(&data);
            let begin = eng
                .put_begin(
                    StorageScope::Release,
                    Some(&release_id),
                    None,
                    data.len() as u64,
                    None,
                )
                .expect("put_begin");
            write_abs_file(&eng.partial_abs_path(&begin.upload_id).unwrap(), &data).expect("write");
            let st = eng
                .put_commit(&begin.upload_id, &digest, None, None)
                .expect("put_commit");
            assert_eq!(st.sha256, digest);
            let (got, _) = eng
                .get_verified(
                    StorageScope::Release,
                    Some(&release_id),
                    None,
                    None,
                    None,
                    &digest,
                )
                .expect("get_verified");
            assert_eq!(got.sha256, digest);
        }));
    }

    for h in handles {
        h.join().expect("join");
    }
}

#[test]
fn battle_challenge_double_consume() {
    use vcp::storage::{StorageErrorCode, soft_assertion_json};

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let mut cfg = engine_cfg();
    cfg.webauthn_required = true;
    let eng = Arc::new(StorageEngine::open(&root, cfg).unwrap());
    let cred = b"battle-soft";
    eng.seed_soft_active_credential(cred, "t").unwrap();
    let ch = eng.challenge_begin_delete_org("99").unwrap();
    let assertion = soft_assertion_json(cred, &ch.challenge_id, true, 0);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let eng = eng.clone();
        let assertion = assertion.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            eng.delete_org("99", Some(&assertion))
        }));
    }
    let mut oks = 0;
    let mut fails = 0;
    for h in handles {
        match h.join().unwrap() {
            Ok(_) => oks += 1,
            Err(e) => {
                fails += 1;
                assert!(
                    matches!(
                        e.code,
                        StorageErrorCode::WebauthnInvalid
                            | StorageErrorCode::ChallengeUnknown
                            | StorageErrorCode::WebauthnExpired
                    ),
                    "unexpected {:?}",
                    e.code
                );
            }
        }
    }
    assert_eq!(oks, 1);
    assert_eq!(fails, 1);
}

/// Digest drift after `challenge_begin_delete`: concurrent deletes must all
/// fail closed (`object_modified` / challenge gone) — never unlink.
#[test]
fn battle_delete_object_modified_under_contention() {
    use vcp::storage::{StorageErrorCode, soft_assertion_json};

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let mut cfg = engine_cfg();
    cfg.webauthn_required = true;
    let eng = Arc::new(StorageEngine::open(&root, cfg).unwrap());
    let cred = b"battle-omod";
    eng.seed_soft_active_credential(cred, "t").unwrap();
    let begin = eng
        .put_begin(StorageScope::Release, Some("77"), None, 4, None)
        .unwrap();
    write_abs_file(&eng.partial_abs_path(&begin.upload_id).unwrap(), b"abcd").unwrap();
    let digest = sha256_hex(b"abcd");
    let prep = eng.put_prepare(&begin.upload_id, &digest).unwrap();
    let assertion = soft_assertion_json(cred, &prep.challenge.challenge_id, true, 0);
    eng.put_commit(&begin.upload_id, &digest, None, Some(&assertion))
        .unwrap();

    let ch = eng
        .challenge_begin_delete(StorageScope::Release, Some("77"), None, None, None)
        .unwrap();
    // Second SQLite handle (WAL): flip SoT digest while the engine stays open.
    MetaDb::open(root.as_path())
        .unwrap()
        .upsert(&MetaObject {
            scope: StorageScope::Release,
            object_key: "77".into(),
            org_id: String::new(),
            sha256: "a".repeat(64),
            size_bytes: 4,
            content_type: String::new(),
            ext: String::new(),
        })
        .unwrap();
    let del_assertion = soft_assertion_json(cred, &ch.challenge_id, true, 0);
    let n = 8usize;
    let barrier = Arc::new(std::sync::Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let eng = eng.clone();
        let assertion = del_assertion.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            eng.delete(
                StorageScope::Release,
                Some("77"),
                None,
                None,
                None,
                Some(&assertion),
            )
        }));
    }
    let mut oks = 0;
    for h in handles {
        match h.join().unwrap() {
            Ok(()) => oks += 1,
            Err(e) => {
                assert!(
                    matches!(
                        e.code,
                        StorageErrorCode::ObjectModified
                            | StorageErrorCode::ChallengeUnknown
                            | StorageErrorCode::WebauthnInvalid
                            | StorageErrorCode::WebauthnExpired
                    ),
                    "unexpected {:?}",
                    e.code
                );
            }
        }
    }
    assert_eq!(oks, 0, "digest drift must never unlink under contention");
    let st = eng
        .get_stat(StorageScope::Release, Some("77"), None, None, None)
        .expect("blob must remain on disk");
    assert_eq!(st.sha256, digest);
    let deny = eng
        .get_verified(StorageScope::Release, Some("77"), None, None, None, &digest)
        .unwrap_err();
    assert_eq!(deny.code, StorageErrorCode::IntegrityMismatch);
}

/// Concurrent empty / whitespace-only enrol labels must all fail closed
/// (InvalidId) — no PENDING row under contention.
#[test]
fn battle_key_enrol_empty_label_fail_closed() {
    use vcp::storage::StorageErrorCode;

    let dir = tempfile::tempdir().unwrap();
    let root = Arc::new(dir.path().canonicalize().unwrap());
    {
        let _bootstrap = StorageEngine::open(root.as_path(), engine_cfg()).expect("bootstrap");
    }
    let n = 8usize;
    let barrier = Arc::new(std::sync::Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let root = root.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let eng = StorageEngine::open(root.as_path(), engine_cfg()).expect("open");
            barrier.wait();
            let label = if i % 2 == 0 { "" } else { " \t\n " };
            eng.key_enrol_stage(format!("cred-{i}").as_bytes(), b"cose", "u", label, true)
        }));
    }
    for h in handles {
        let err = h.join().expect("join").expect_err("empty label");
        assert_eq!(err.code, StorageErrorCode::InvalidId);
    }
    let eng = StorageEngine::open(root.as_path(), engine_cfg()).expect("reopen");
    assert!(
        eng.list_pending_credentials_cli().unwrap().is_empty(),
        "no PENDING credential after blank-label flood"
    );
}

#[test]
fn battle_parallel_key_list_pages() {
    let dir = tempfile::tempdir().unwrap();
    let root = Arc::new(dir.path().canonicalize().unwrap());
    {
        let eng = StorageEngine::open(root.as_path(), engine_cfg()).expect("bootstrap");
        for i in 0..12 {
            eng.key_enrol_stage(
                format!("battle-cred-{i}").as_bytes(),
                format!("battle-cose-{i}").as_bytes(),
                "1",
                &format!("battle-k{i}"),
                true,
            )
            .unwrap();
        }
    }
    let n = 6usize;
    let barrier = Arc::new(std::sync::Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for t in 0..n {
        let root = root.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let eng = StorageEngine::open(root.as_path(), engine_cfg()).expect("open");
            let page = (t % 3) + 1;
            let (json, total) = eng
                .key_list_json("pending", page, KEY_PAGE_SIZE)
                .expect("page");
            assert_eq!(total, 12);
            let rows: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
            assert!(rows.len() <= KEY_PAGE_SIZE);
            assert!(!rows.is_empty() || page > 3);
        }));
    }
    for h in handles {
        h.join().expect("join");
    }
}

#[tokio::test]
async fn battle_parallel_image_get() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("battle-img");
    let slug = unique_slug("battle-img-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");

    let upload = post_multipart_with_files(
        &router,
        &format!("/{slug}/images"),
        Some(&cookie),
        &[],
        &[MultipartFile {
            field: "image",
            filename: "dot.png",
            content_type: "image/png",
            bytes: TINY_PNG,
        }],
    )
    .await;
    assert_eq!(status(&upload), StatusCode::CREATED, "upload image");
    let body = upload.into_body().collect().await.expect("body").to_bytes();
    let name = String::from_utf8_lossy(&body).trim().to_owned();
    assert!(name.ends_with(".png"), "{name}");

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    let path = format!("/{slug}/images/{name}");

    for _ in 0..n {
        let barrier = barrier.clone();
        let cookie = cookie.clone();
        let path = path.clone();
        let router = test_router().await;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let resp = get(&router, &path, Some(&cookie)).await;
            assert_eq!(status(&resp), StatusCode::OK);
            let nosniff = resp
                .headers()
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            assert_eq!(nosniff, "nosniff");
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}
