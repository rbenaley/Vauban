//! Contention: concurrent put_commit under tempfile + parallel image GET.

use std::sync::Arc;

use http_body_util::BodyExt;
use tokio::sync::Barrier;
use topcoat::router::StatusCode;
use vcp::config::{StorageConfig, StorageIpcMode};
use vcp::storage::{StorageEngine, StorageScope, sha256_hex, write_abs_file};

use crate::common::{
    MultipartFile, TINY_PNG, cleanup, create_org_with_membership, db_lock, get, login_cookie,
    post_multipart_with_files, status, test_db, test_router, unique_email, unique_slug,
};

fn engine_cfg() -> StorageConfig {
    StorageConfig {
        blob_path: "/tmp/unused".into(),
        ipc: StorageIpcMode::Inline,
        socket_path: String::new(),
        helper_path: String::new(),
        max_artifact_bytes: 1024 * 1024,
        max_image_bytes: 64 * 1024,
        allowed_image_types: vec!["png".into(), "jpeg".into(), "webp".into()],
        max_concurrent_uploads: 8,
        max_images_per_org: 100,
        upload_ttl_secs: 3600,
        expected_peer_uid: None,
    }
}

#[test]
fn battle_concurrent_put_commit_under_tempfile() {
    let dir = tempfile::tempdir().unwrap();
    let root = Arc::new(dir.path().canonicalize().unwrap());
    let n = 8usize;
    let barrier = Arc::new(std::sync::Barrier::new(n));
    let mut handles = Vec::with_capacity(n);

    for i in 0..n {
        let root = root.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            // Per-thread engine (cap-std Dir is not Sync); same blob root.
            let eng = StorageEngine::open(root.as_path(), engine_cfg()).unwrap();
            let release_id = format!("{}", 10_000 + i);
            let data = format!("pkg-body-{i}").into_bytes();
            let digest = sha256_hex(&data);
            barrier.wait();
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
                .put_commit(&begin.upload_id, &digest, None)
                .expect("put_commit");
            assert_eq!(st.sha256, digest);
            let got = eng
                .get_stat(StorageScope::Release, Some(&release_id), None, None, None)
                .expect("stat");
            assert_eq!(got.sha256, digest);
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
