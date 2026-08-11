//! E2E: export → wipe docs → import restores fields and publish exclusivity.

use vcp::docs_bundle::{export_articles_to_dir, import_articles_from_dir};
use vcp::models::{DOC_STATUS_DRAFT, DOC_STATUS_PUBLISHED, DocArticle};

use crate::common::{db_lock, test_db, wipe_seed_surface};

#[tokio::test]
async fn e2e_export_import_round_trip_and_publish_exclusivity() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    wipe_seed_surface(&db).await;

    {
        let mut conn = db.clone();
        let now = vcp::db::now_unix();
        let _ = toasty::create!(DocArticle {
            title: "Stable Guide".to_owned(),
            summary: "sum".to_owned(),
            category: "API".to_owned(),
            slug: "stable-guide".to_owned(),
            version: "v1".to_owned(),
            status: DOC_STATUS_DRAFT.to_owned(),
            body: "Old draft `v1`.".to_owned(),
            updated_at: now,
        })
        .exec(&mut conn)
        .await
        .expect("v1");
        let _ = toasty::create!(DocArticle {
            title: "Stable Guide".to_owned(),
            summary: "sum2".to_owned(),
            category: "API".to_owned(),
            slug: "stable-guide".to_owned(),
            version: "v2".to_owned(),
            status: DOC_STATUS_PUBLISHED.to_owned(),
            body: "Published `v2` body.".to_owned(),
            updated_at: now + 1,
        })
        .exec(&mut conn)
        .await
        .expect("v2");
        let _ = toasty::create!(DocArticle {
            title: "Other".to_owned(),
            summary: "o".to_owned(),
            category: "Security".to_owned(),
            slug: "other-doc".to_owned(),
            version: "v1".to_owned(),
            status: DOC_STATUS_PUBLISHED.to_owned(),
            body: "Other body.".to_owned(),
            updated_at: now,
        })
        .exec(&mut conn)
        .await
        .expect("other");
    }

    let export_dir = tempfile::tempdir().expect("export dir");
    let report = export_articles_to_dir(&db, export_dir.path())
        .await
        .expect("export");
    assert_eq!(report.exported, 3);
    assert!(export_dir.path().join("stable-guide__v1.md").is_file());
    assert!(export_dir.path().join("stable-guide__v2.md").is_file());
    assert!(export_dir.path().join("other-doc__v1.md").is_file());

    // Wipe docs then re-import.
    {
        let mut conn = db.clone();
        for doc in DocArticle::all().exec(&mut conn).await.unwrap_or_default() {
            let _ = DocArticle::delete_by_id(&mut conn, doc.id).await;
        }
    }

    let imported = import_articles_from_dir(&db, export_dir.path())
        .await
        .expect("import");
    assert_eq!(imported.created, 3);
    assert_eq!(imported.updated, 0);

    let mut conn = db.clone();
    let published = DocArticle::all()
        .filter(DocArticle::fields().slug().eq("stable-guide"))
        .filter(DocArticle::fields().status().eq(DOC_STATUS_PUBLISHED))
        .exec(&mut conn)
        .await
        .expect("published");
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].version, "v2");

    let v2 = DocArticle::all()
        .filter(DocArticle::fields().slug().eq("stable-guide"))
        .filter(DocArticle::fields().version().eq("v2"))
        .include(DocArticle::fields().body())
        .exec(&mut conn)
        .await
        .expect("v2 row");
    assert_eq!(v2[0].body.get().as_str(), "Published `v2` body.");

    // Idempotent second import.
    let again = import_articles_from_dir(&db, export_dir.path())
        .await
        .expect("re-import");
    assert_eq!(again.created, 0);
    assert_eq!(again.updated, 3);

    wipe_seed_surface(&db).await;
}

#[tokio::test]
async fn e2e_import_fail_fast_on_bad_category() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    wipe_seed_surface(&db).await;

    let dir = tempfile::tempdir().expect("dir");
    // Bypass validate; write hand-crafted invalid file.
    let md = "---\ntitle: Bad\nslug: bad-cat\nsummary: \"\"\ncategory: NotARealCategory\nstatus: PUBLISHED\nversion: v1\n---\n\nx\n";
    std::fs::write(dir.path().join("bad-cat__v1.md"), md).expect("write");

    let err = import_articles_from_dir(&db, dir.path())
        .await
        .expect_err("must fail-fast");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("unknown category") || msg.contains("parse"),
        "{msg}"
    );

    let mut conn = db.clone();
    let rows = DocArticle::all()
        .filter(DocArticle::fields().slug().eq("bad-cat"))
        .exec(&mut conn)
        .await
        .unwrap_or_default();
    assert!(rows.is_empty(), "fail-fast must not create the bad row");

    wipe_seed_surface(&db).await;
}

#[tokio::test]
async fn e2e_export_refuses_non_empty_dir() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    wipe_seed_surface(&db).await;

    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("stale.txt"), "x").expect("stale");
    let err = export_articles_to_dir(&db, dir.path())
        .await
        .expect_err("non-empty");
    assert!(format!("{err:#}").contains("not empty"), "{err:#}");

    wipe_seed_surface(&db).await;
}
