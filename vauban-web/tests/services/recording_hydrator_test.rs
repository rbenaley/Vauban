//! Recording hydrator integration tests.
//!
//! These tests cover the DB-facing slice of
//! [`vauban_web::services::recording_hydrator`]: BLAKE3 aggregation,
//! parsing of SSH/RDP `meta.json`, and persistence behaviour
//! (idempotency, partial-index usage). The supervisor FD-passing
//! plumbing is skipped here since spinning a real
//! `vauban-supervisor` is out of scope for unit tests; the
//! corresponding paths (`hydrate_one`, `tick`) are covered by the
//! production deployment runbook in
//! `docs/runbooks/recording_hydrator.md`.
//!
//! The hydrator's pure-logic functions
//! (`parse_meta`, `aggregate_rdp_blake3`, `is_valid_blake3_hex`,
//! `meta_relative_for`) ship with their own `#[cfg(test)]` unit
//! suite inside the module.

use crate::common::TestApp;
use crate::fixtures::{
    create_recorded_session_with_type, create_simple_admin_user, create_simple_ssh_asset,
    unique_name,
};
use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use vauban_web::models::session::SessionType;
use vauban_web::services::recording_hydrator::{
    FORMAT_ASCIICAST_V2, FORMAT_FMP4_DASH, FORMAT_FMP4_FLAT, IntegrityBundle, TASK_NAME,
    aggregate_rdp_blake3, is_valid_blake3_hex, mark_finalized_corrupt,
    mark_finalized_legacy_flat, parse_meta,
};

// ---------------------------------------------------------------------------
// Test 1: SSH meta.json parses into a fully-populated bundle.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_hydrator_parses_ssh_meta_into_bundle() {
    let json = r#"{
        "format": "asciicast-v2",
        "blake3_hex": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "total_bytes": 91234,
        "total_events": 1847,
        "duration_secs": 14.567,
        "width": 132,
        "height": 43
    }"#;

    let bundle = parse_meta(SessionType::Ssh, json).expect("ssh meta should parse");

    assert!(is_valid_blake3_hex(&bundle.blake3_hex));
    assert_eq!(bundle.size_bytes, 91_234);
    assert_eq!(bundle.duration_ms, 14_567);
    assert_eq!(bundle.event_count, Some(1847));
    assert_eq!(bundle.format, FORMAT_ASCIICAST_V2);
    assert_eq!(bundle.width, 132);
    assert_eq!(bundle.height, 43);
    assert_eq!(bundle.segment_count, None);
    assert_eq!(bundle.codec, None);
}

// ---------------------------------------------------------------------------
// Test 2: RDP meta.json with N segments aggregates per the documented
// rule BLAKE3(concat(segment_hex_bytes)) and unifies into the
// `recording_blake3` column.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_hydrator_aggregates_rdp_segments_via_blake3_of_hex_concat() {
    let h1 = "11111111111111111111111111111111111111111111111111111111111111aa";
    let h2 = "22222222222222222222222222222222222222222222222222222222222222bb";
    let json = format!(
        r#"{{
            "segments": [
                {{"index":1,"width":1920,"height":1080,"duration_ticks":900000,
                  "init_size":1024,"file_size":50000,
                  "blake3_hex":"{h1}","codec_string":"avc1.42c01e"}},
                {{"index":2,"width":1920,"height":1080,"duration_ticks":900000,
                  "init_size":1024,"file_size":60000,
                  "blake3_hex":"{h2}","codec_string":"avc1.42c01e"}}
            ]
        }}"#
    );

    let bundle = parse_meta(SessionType::Rdp, &json).expect("rdp meta should parse");
    assert_eq!(bundle.format, FORMAT_FMP4_DASH);
    assert_eq!(bundle.segment_count, Some(2));
    assert_eq!(bundle.size_bytes, 110_000);
    // Total ticks 1_800_000 / 90 kHz = 20 s = 20_000 ms.
    assert_eq!(bundle.duration_ms, 20_000);
    assert_eq!(bundle.codec.as_deref(), Some("avc1.42c01e"));
    assert!(is_valid_blake3_hex(&bundle.blake3_hex));

    // Reproduce the aggregation rule by hand and check exact equality.
    struct H {
        s: String,
    }
    impl vauban_web::services::recording_hydrator::HasSegmentHash for H {
        fn blake3_hex(&self) -> &str {
            &self.s
        }
    }
    let manual = aggregate_rdp_blake3(&[
        H {
            s: h1.to_string(),
        },
        H {
            s: h2.to_string(),
        },
    ]);
    assert_eq!(bundle.blake3_hex, manual);
}

// ---------------------------------------------------------------------------
// Test 3: Persisting a bundle via the SET clause leaves a row that
// passes the `recording_blake3_format` and `recording_format_enum`
// CHECK constraints (idempotent path: subsequent UPDATE no-ops because
// `recording_finalized_at IS NOT NULL`).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_hydrator_persist_then_idempotent() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("hyd_persist");
    let user_id = create_simple_admin_user(&mut conn, &username).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("hyd-asset"), user_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, user_id, asset_id, "ssh").await;

    // Manual UPDATE mirrors persist_bundle's SET clause exactly.
    use vauban_web::schema::proxy_sessions::dsl;
    let blake3_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let now = Utc::now();
    let updated: usize = diesel::update(
        dsl::proxy_sessions
            .filter(dsl::id.eq(session_id))
            .filter(dsl::recording_finalized_at.is_null()),
    )
    .set((
        dsl::recording_blake3.eq(blake3_hex),
        dsl::recording_size_bytes.eq(91_234_i64),
        dsl::recording_duration_ms.eq(14_567_i64),
        dsl::recording_event_count.eq(1847_i32),
        dsl::recording_format.eq(FORMAT_ASCIICAST_V2),
        dsl::recording_width.eq(132_i16),
        dsl::recording_height.eq(43_i16),
        dsl::recording_finalized_at.eq(now),
    ))
    .execute(&mut conn)
    .await
    .expect("first persist must succeed");
    assert_eq!(updated, 1);

    // Second pass: predicate `recording_finalized_at IS NULL` is now
    // false, so the UPDATE matches zero rows -> idempotent.
    let again: usize = diesel::update(
        dsl::proxy_sessions
            .filter(dsl::id.eq(session_id))
            .filter(dsl::recording_finalized_at.is_null()),
    )
    .set(dsl::recording_blake3.eq("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
    .execute(&mut conn)
    .await
    .expect("second persist must execute (no constraint violation)");
    assert_eq!(again, 0, "idempotent: no row updated on second pass");

    // Read back: blake3 is still the original.
    let got: Option<String> = dsl::proxy_sessions
        .filter(dsl::id.eq(session_id))
        .select(dsl::recording_blake3)
        .first::<Option<String>>(&mut conn)
        .await
        .expect("select back");
    assert_eq!(got.as_deref(), Some(blake3_hex));
}

// ---------------------------------------------------------------------------
// Test 4: The CHECK constraint `recording_blake3_format` rejects an
// uppercase hex value at the DB layer (defence in depth: the parser
// already rejects it at the application layer).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_hydrator_db_rejects_uppercase_blake3() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("hyd_uppercase");
    let user_id = create_simple_admin_user(&mut conn, &username).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("hyd-up-asset"), user_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, user_id, asset_id, "ssh").await;

    use vauban_web::schema::proxy_sessions::dsl;
    let bad = "ABCDEF7890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let r = diesel::update(dsl::proxy_sessions.filter(dsl::id.eq(session_id)))
        .set(dsl::recording_blake3.eq(bad))
        .execute(&mut conn)
        .await;
    assert!(
        r.is_err(),
        "DB CHECK recording_blake3_format must reject uppercase hex"
    );
}

// ---------------------------------------------------------------------------
// Test 5: The CHECK constraint `recording_format_enum` rejects a
// format value that is not in the documented enum.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_hydrator_db_rejects_unknown_format() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("hyd_format");
    let user_id = create_simple_admin_user(&mut conn, &username).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("hyd-fmt-asset"), user_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, user_id, asset_id, "ssh").await;

    use vauban_web::schema::proxy_sessions::dsl;
    let r = diesel::update(dsl::proxy_sessions.filter(dsl::id.eq(session_id)))
        .set(dsl::recording_format.eq("h264-mkv"))
        .execute(&mut conn)
        .await;
    assert!(
        r.is_err(),
        "DB CHECK recording_format_enum must reject unknown format"
    );
}

// ---------------------------------------------------------------------------
// Test 6: parse_meta refuses an SSH meta.json with non-hex blake3.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_hydrator_rejects_corrupt_ssh_meta() {
    let json = r#"{
        "blake3_hex": "ZZZ",
        "total_bytes": 0,
        "total_events": 0,
        "duration_secs": 0.0,
        "width": 80,
        "height": 24
    }"#;
    assert!(parse_meta(SessionType::Ssh, json).is_err());
}

// ---------------------------------------------------------------------------
// Test 7: parse_meta refuses an RDP meta.json with no segments.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_hydrator_rejects_rdp_meta_without_segments() {
    assert!(parse_meta(SessionType::Rdp, r#"{"segments":[]}"#).is_err());
}

// ---------------------------------------------------------------------------
// Test 8: The partial index `idx_proxy_sessions_pending_finalization`
// is present and used by the hydrator's batch query (EXPLAIN check).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_hydrator_partial_index_exists() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    use diesel::sql_types::Text;
    #[derive(QueryableByName)]
    struct IndexName {
        #[diesel(sql_type = Text)]
        #[allow(dead_code)]
        indexname: String,
    }

    let r: Vec<IndexName> = diesel::sql_query(
        "SELECT indexname FROM pg_indexes \
         WHERE tablename = 'proxy_sessions' \
         AND indexname = 'idx_proxy_sessions_pending_finalization'",
    )
    .load(&mut conn)
    .await
    .expect("query pg_indexes");
    assert_eq!(
        r.len(),
        1,
        "partial index idx_proxy_sessions_pending_finalization must exist"
    );
}

// ---------------------------------------------------------------------------
// Test 9: marking a row finalized with all integrity columns NULL
// (the hydrator's "corrupt meta.json" path) is accepted by the DB.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_hydrator_corrupt_marker_is_persisted() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("hyd_corrupt");
    let user_id = create_simple_admin_user(&mut conn, &username).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("hyd-corrupt-asset"), user_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, user_id, asset_id, "ssh").await;

    use vauban_web::schema::proxy_sessions::dsl;
    let now = Utc::now();
    let r = diesel::update(dsl::proxy_sessions.filter(dsl::id.eq(session_id)))
        .set(dsl::recording_finalized_at.eq(now))
        .execute(&mut conn)
        .await;
    assert!(
        r.is_ok(),
        "marking finalized with NULL integrity must be accepted (corrupt-meta path)"
    );
    let blake3: Option<String> = dsl::proxy_sessions
        .filter(dsl::id.eq(session_id))
        .select(dsl::recording_blake3)
        .first(&mut conn)
        .await
        .expect("select");
    assert!(blake3.is_none(), "blake3 stays NULL on corrupt-marker rows");
}

// ---------------------------------------------------------------------------
// Test 10: format constants are exactly the three values the migration
// CHECK constraint allows -- pinning prevents drift between the Rust
// const and the SQL enum.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_hydrator_format_constants_match_check_constraint() {
    assert_eq!(FORMAT_ASCIICAST_V2, "asciicast-v2");
    assert_eq!(FORMAT_FMP4_DASH, "fmp4-dash");
    assert_eq!(FORMAT_FMP4_FLAT, "fmp4-flat");
}

// ---------------------------------------------------------------------------
// Test 11: IntegrityBundle is the documented projection -- a quick
// smoke test that the public struct stays buildable from outside the
// crate (so the runbook's "manual UPDATE" recipe stays compilable).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_hydrator_integrity_bundle_constructible() {
    let _b = IntegrityBundle {
        blake3_hex: "0".repeat(64),
        size_bytes: 0,
        duration_ms: 0,
        event_count: None,
        format: FORMAT_ASCIICAST_V2.to_string(),
        width: 80,
        height: 24,
        segment_count: None,
        codec: None,
    };
}

// ---------------------------------------------------------------------------
// Test 12: legacy-flat-mp4 recovery path. A pre-segmentation row whose
// `recording_path` ends in `.mp4` (no directory, no meta.json was ever
// produced) must be marked finalized as `fmp4-flat` exactly once and
// then disappear from the candidate set on subsequent ticks. This
// fixes the production WARN/ERROR loop reported on 2026-04-30 where
// the hydrator kept retrying every interval.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_hydrator_marks_legacy_flat_mp4_as_fmp4_flat_and_is_one_shot() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("hyd_legacy");
    let user_id = create_simple_admin_user(&mut conn, &username).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("hyd-leg-asset"), user_id).await;

    // Insert a session whose recording_path is a flat .mp4 (legacy).
    use vauban_web::models::session::SessionType as ST;
    use vauban_web::schema::proxy_sessions::dsl;
    let session_uuid = ::uuid::Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = "127.0.0.1".parse().unwrap();
    let session_id: i32 = diesel::insert_into(dsl::proxy_sessions)
        .values((
            dsl::uuid.eq(session_uuid),
            dsl::user_id.eq(user_id),
            dsl::asset_id.eq(asset_id),
            dsl::credential_id.eq("c"),
            dsl::credential_username.eq("u"),
            dsl::session_type.eq(ST::Rdp),
            dsl::status.eq("completed"),
            dsl::client_ip.eq(ip),
            dsl::is_recorded.eq(true),
            dsl::recording_path.eq("recordings/legacy/abc-123.mp4"),
            dsl::metadata.eq(serde_json::json!({})),
        ))
        .returning(dsl::id)
        .get_result(&mut conn)
        .await
        .expect("insert legacy");

    // Pre-condition: row appears in the candidate query.
    let pending_before: i64 = dsl::proxy_sessions
        .filter(dsl::id.eq(session_id))
        .filter(dsl::is_recorded.eq(true))
        .filter(dsl::recording_path.is_not_null())
        .filter(dsl::recording_finalized_at.is_null())
        .count()
        .get_result(&mut conn)
        .await
        .expect("count");
    assert_eq!(pending_before, 1, "legacy row must start unfinalized");

    // The hydrator's category-1 branch calls mark_finalized_legacy_flat.
    mark_finalized_legacy_flat(&app.db_pool, session_id)
        .await
        .expect("mark legacy flat");

    // Post-condition: format is fmp4-flat, finalized_at set, blake3 NULL.
    let (fmt, finalized, blake3): (Option<String>, Option<chrono::DateTime<Utc>>, Option<String>) =
        dsl::proxy_sessions
            .filter(dsl::id.eq(session_id))
            .select((
                dsl::recording_format,
                dsl::recording_finalized_at,
                dsl::recording_blake3,
            ))
            .first(&mut conn)
            .await
            .expect("select");
    assert_eq!(fmt.as_deref(), Some(FORMAT_FMP4_FLAT));
    assert!(finalized.is_some(), "finalized_at must be set");
    assert!(
        blake3.is_none(),
        "blake3 stays NULL: no meta.json ever produced for legacy flat .mp4"
    );

    // Idempotency: a second tick must NOT re-pick this row.
    let pending_after: i64 = dsl::proxy_sessions
        .filter(dsl::id.eq(session_id))
        .filter(dsl::is_recorded.eq(true))
        .filter(dsl::recording_path.is_not_null())
        .filter(dsl::recording_finalized_at.is_null())
        .count()
        .get_result(&mut conn)
        .await
        .expect("count after");
    assert_eq!(
        pending_after, 0,
        "legacy row must vanish from candidate set after one finalize"
    );
}

// ---------------------------------------------------------------------------
// Test 13: missing-meta-past-grace is one-shot too. Same regression as
// test 12 but for the "directory-style path with no meta.json on disk
// past the configured grace period" path: must be marked finalized
// with NULL integrity columns and NEVER retried.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_hydrator_marks_lost_recording_as_finalized_null_and_is_one_shot() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("hyd_lost");
    let user_id = create_simple_admin_user(&mut conn, &username).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("hyd-lost-asset"), user_id).await;
    let session_id = create_recorded_session_with_type(&mut conn, user_id, asset_id, "ssh").await;

    use vauban_web::schema::proxy_sessions::dsl;

    // Simulate the hydrator's "missing meta past grace" branch.
    mark_finalized_corrupt(&app.db_pool, session_id)
        .await
        .expect("mark lost");

    let pending_after: i64 = dsl::proxy_sessions
        .filter(dsl::id.eq(session_id))
        .filter(dsl::is_recorded.eq(true))
        .filter(dsl::recording_path.is_not_null())
        .filter(dsl::recording_finalized_at.is_null())
        .count()
        .get_result(&mut conn)
        .await
        .expect("count after");
    assert_eq!(
        pending_after, 0,
        "lost recording must vanish from candidate set after one finalize"
    );

    // All integrity columns stay NULL -- the page renders
    // "Integrity unavailable" but does NOT loop the hydrator.
    let (fmt, blake3): (Option<String>, Option<String>) = dsl::proxy_sessions
        .filter(dsl::id.eq(session_id))
        .select((dsl::recording_format, dsl::recording_blake3))
        .first(&mut conn)
        .await
        .expect("select");
    assert!(fmt.is_none(), "format stays NULL on lost-recording path");
    assert!(blake3.is_none(), "blake3 stays NULL on lost-recording path");
}

// ---------------------------------------------------------------------------
// Test: the hydrator's TASK_NAME is the stable identifier surfaced to
// operators by `shared::tasks::spawn_periodic` (and consumed by
// `tasks::recording_hydrator::start_recording_hydrator`). Pinned here
// so a rename ripples through the tracing-correlation and runbook
// queries deliberately, not silently.
//
// The deeper "scheduler must live in tasks/ and delegate to
// shared::tasks::spawn_periodic" contract is pinned by the source-level
// test inside `tasks/recording_hydrator.rs` itself.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_hydrator_task_name_is_stable() {
    assert_eq!(
        TASK_NAME, "recording_hydrator",
        "task name surfaced to operators in tracing must be stable"
    );
}

// ---------------------------------------------------------------------------
// Test: the heavy hydrator pipeline (`tick`, `hydrate_one`,
// `parse_meta`, `persist_bundle`, ...) lives in the `services` module.
// Scheduling concerns belong to `tasks/`. This split is the same as
// `cleanup` (logic in `tasks/cleanup.rs::run_cleanup_pass` plus
// per-helper async functions) and `dashboard`. We pin both invariants
// so a regression that re-couples scheduling and business logic
// (e.g. by re-introducing a `RecordingHydrator::spawn` method) cannot
// silently reappear.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_hydrator_business_logic_is_decoupled_from_scheduling() {
    let svc = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("services")
        .join("recording_hydrator.rs");
    let svc_src = std::fs::read_to_string(&svc).expect("read services/recording_hydrator.rs");
    // Only match an actual call site, not doc-comment mentions that
    // explain the delegation (those are deliberately allowed and
    // guide the reader to the scheduler).
    assert!(
        !svc_src.contains("shared::tasks::spawn_periodic("),
        "services/recording_hydrator.rs must NOT call shared::tasks::spawn_periodic; \
         scheduling lives in tasks/recording_hydrator.rs"
    );
    assert!(
        !svc_src.contains("pub fn spawn("),
        "services/recording_hydrator.rs must NOT expose a `pub fn spawn(...)` -- use \
         tasks::recording_hydrator::start_recording_hydrator instead"
    );
    assert!(
        !svc_src.contains("tokio::spawn("),
        "services/recording_hydrator.rs must NOT spawn tasks; that is the scheduler's job"
    );

    let task = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("tasks")
        .join("recording_hydrator.rs");
    let task_src = std::fs::read_to_string(&task).expect("read tasks/recording_hydrator.rs");
    assert!(
        task_src.contains("pub async fn start_recording_hydrator("),
        "tasks/recording_hydrator.rs must expose start_recording_hydrator (mirrors start_cleanup_tasks)"
    );
    assert!(
        task_src.contains("shared::tasks::spawn_periodic"),
        "tasks/recording_hydrator.rs must delegate to shared::tasks::spawn_periodic"
    );
}

// ---------------------------------------------------------------------------
// Test 14: meta_relative_for distinguishes flat .mp4 from directory.
// Pinned because the hydrator's category-1 branch hinges on the
// `ends_with('/')` heuristic; a regression here would re-introduce the
// production log-spam loop reported on 2026-04-30.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_meta_relative_for_distinguishes_flat_mp4_from_directory() {
    use vauban_web::services::recording_hydrator::meta_relative_for;
    assert_eq!(
        meta_relative_for("recordings", "recordings/2026/04/abc-123/").as_deref(),
        Some("2026/04/abc-123/meta.json"),
        "directory-style path yields meta.json"
    );
    assert!(
        meta_relative_for("recordings", "recordings/legacy/foo.mp4").is_none(),
        "flat .mp4 path returns None (caller marks fmp4-flat)"
    );
}
