//! Property: cursor pages visit every id exactly once.

use proptest::prelude::*;
use vcp::db::now_unix;
use vcp::models::DocArticle;
use vcp::toasty_page::advance_scan_page;

use crate::common::{cleanup, db_lock, prop_config, test_db, unique_slug, wipe_seed_surface};

proptest! {
    #![proptest_config(prop_config(16))]

    #[test]
    fn prop_scan_pages_cover_all_ids_no_dups(
        n in 0usize..12,
        batch in 1usize..5,
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async {
            let _guard = db_lock().lock().await;
            let db = test_db().await;
            cleanup(&db).await;
            wipe_seed_surface(&db).await;

            let mut conn = db.clone();
            let mut expected = std::collections::BTreeSet::new();
            for i in 0..n {
                let slug = unique_slug(&format!("pg-{i}"));
                let created = toasty::create!(DocArticle {
                    title: format!("Page {i}"),
                    summary: "s".to_owned(),
                    category: "API".to_owned(),
                    slug: slug.clone(),
                    version: "v1".to_owned(),
                    status: "DRAFT".to_owned(),
                    body: "b".to_owned(),
                    updated_at: now_unix(),
                })
                .exec(&mut conn)
                .await
                .expect("create");
                expected.insert(created.id);
            }

            let mut page = Some(
                DocArticle::all()
                    .order_by(DocArticle::fields().id().asc())
                    .paginate(batch)
                    .exec(&mut conn)
                    .await
                    .expect("first page"),
            );
            let mut seen = std::collections::BTreeSet::new();
            let mut visited = 0usize;
            while let Some(current) = page {
                let (items, next) = advance_scan_page(current, &mut conn)
                    .await
                    .expect("advance");
                for row in items {
                    seen.insert(row.id);
                    visited += 1;
                }
                page = next;
            }
            assert_eq!(visited, n);
            assert_eq!(seen, expected);
        });
    }
}
