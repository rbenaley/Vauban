//! VAUBAN Web - Live-filter E2E tests for the July 2026 list overhaul.
//!
//! Real HTTP + real Postgres + real in-process vauban-access. Covers
//! the four lists that gained live filters (`/assets/access`,
//! `/vault/secrets`, `/vault/secrets/groups`, `/vault/secrets/access`)
//! plus the two drift regressions fixed by the shared
//! `services::list_filters` seam:
//!
//! - `/sessions/approvals?page=9999` used to skip the page clamp
//!   (missing `.max(1.0)` / `min(total_pages)`),
//! - `/audit/approvals?actor=a%b` used to feed the raw `%` into the
//!   ILIKE pattern, turning user input into a SQL wildcard.
//!
//! Filter semantics under test are conjunctive (every filter ANDed),
//! fail-safe (filtered empty state, never 500) and authorization-
//! neutral (a plain user stays 403 on the vault nest, filters or not).

use axum::http::header;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{
    create_admin_user, create_jit_session, create_simple_ssh_asset, create_test_access_rule,
    create_test_asset_group, create_test_secret_access_rule, create_test_secret_group,
    create_test_session, create_test_ssh_asset, create_test_user, create_test_vauban_group,
    create_test_vault_secret, unique_name,
};

/// Fixture rule names are deterministic from the returned UUID
/// (`create_test_access_rule` -> `test-rule_<uuid8>`).
fn access_rule_name(uuid: &Uuid) -> String {
    format!("test-rule_{}", &uuid.to_string()[..8])
}

/// Same derivation for secret access rules (`test-srule_<uuid8>`).
fn secret_rule_name(uuid: &Uuid) -> String {
    format!("test-srule_{}", &uuid.to_string()[..8])
}

async fn get_html(app: &TestApp, token: &str, path: &str) -> String {
    let response = app
        .server
        .get(path)
        .add_header(header::AUTHORIZATION, app.auth_header(token))
        .await;
    assert_status(&response, 200);
    response.text()
}

async fn vauban_group_name(conn: &mut diesel_async::AsyncPgConnection, uuid: &Uuid) -> String {
    use vauban_web::schema::vauban_groups;
    vauban_groups::table
        .filter(vauban_groups::uuid.eq(uuid))
        .select(vauban_groups::name)
        .first(conn)
        .await
        .expect("vauban group must exist")
}

async fn asset_group_id(conn: &mut diesel_async::AsyncPgConnection, uuid: &Uuid) -> i32 {
    use vauban_web::schema::asset_groups;
    asset_groups::table
        .filter(asset_groups::uuid.eq(uuid))
        .select(asset_groups::id)
        .first(conn)
        .await
        .expect("asset group must exist")
}

// =============================================================================
// /assets/access
// =============================================================================

/// Protocol / status / search filters are conjunctive on the access
/// rule list, and an out-of-range page on a filtered view clamps back
/// to a page that still shows the matching rule.
#[tokio::test]
#[serial]
async fn access_rules_filters_combine_and_out_of_range_page_clamps() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("lf_ar_adm")).await;

    // One (user_group, asset_group) couple per rule: the table carries
    // a UNIQUE(user_group_id, asset_group_id) constraint.
    let mut couples = Vec::new();
    for i in 0..4 {
        let ug = create_test_vauban_group(&mut conn, &unique_name(&format!("lf-ar-ug{i}"))).await;
        let ag = create_test_asset_group(&mut conn, &unique_name(&format!("lf-ar-ag{i}"))).await;
        couples.push((ug, ag));
    }

    let ssh_rule = create_test_access_rule(&mut conn, &couples[0].0, &couples[0].1, &["ssh"]).await;
    let rdp_rule = create_test_access_rule(&mut conn, &couples[1].0, &couples[1].1, &["rdp"]).await;
    let iacs_rule =
        create_test_access_rule(&mut conn, &couples[2].0, &couples[2].1, &["iacs_modbus"]).await;
    let inactive_rule =
        create_test_access_rule(&mut conn, &couples[3].0, &couples[3].1, &["ssh"]).await;
    {
        use vauban_web::schema::access_rules;
        diesel::update(access_rules::table.filter(access_rules::uuid.eq(inactive_rule)))
            .set(access_rules::is_active.eq(false))
            .execute(&mut conn)
            .await
            .expect("deactivate rule");
    }

    let ssh_name = access_rule_name(&ssh_rule);
    let rdp_name = access_rule_name(&rdp_rule);
    let iacs_name = access_rule_name(&iacs_rule);
    let inactive_name = access_rule_name(&inactive_rule);

    // Unfiltered: everything is visible.
    let body = get_html(app, &admin.token, "/assets/access").await;
    for name in [&ssh_name, &rdp_name, &iacs_name, &inactive_name] {
        assert!(body.contains(name.as_str()), "unfiltered must list {name}");
    }

    // protocol=ssh keeps both ssh rules (active + inactive).
    let body = get_html(app, &admin.token, "/assets/access?protocol=ssh").await;
    assert!(body.contains(&ssh_name));
    assert!(body.contains(&inactive_name));
    assert!(!body.contains(&rdp_name), "rdp rule must be filtered out");
    assert!(!body.contains(&iacs_name), "iacs rule must be filtered out");

    // protocol=iacs matches the iacs_* family only.
    let body = get_html(app, &admin.token, "/assets/access?protocol=iacs").await;
    assert!(body.contains(&iacs_name));
    assert!(!body.contains(&ssh_name));
    assert!(!body.contains(&rdp_name));

    // status=inactive isolates the deactivated rule.
    let body = get_html(app, &admin.token, "/assets/access?status=inactive").await;
    assert!(body.contains(&inactive_name));
    assert!(!body.contains(&ssh_name));

    // Conjunction: protocol=ssh AND status=active drops the inactive
    // ssh rule too.
    let body = get_html(
        app,
        &admin.token,
        "/assets/access?protocol=ssh&status=active",
    )
    .await;
    assert!(body.contains(&ssh_name));
    assert!(!body.contains(&inactive_name));
    assert!(!body.contains(&rdp_name));

    // Search on the unique uuid8 fragment of the ssh rule name.
    let needle = &ssh_rule.to_string()[..8];
    let body = get_html(
        app,
        &admin.token,
        &format!("/assets/access?search={needle}"),
    )
    .await;
    assert!(body.contains(&ssh_name));
    assert!(!body.contains(&rdp_name));

    // Drift regression (shared with /sessions/approvals): a filtered
    // view with an absurd page number clamps instead of rendering an
    // out-of-range empty page.
    let body = get_html(
        app,
        &admin.token,
        "/assets/access?protocol=ssh&status=active&page=9999",
    )
    .await;
    assert!(
        body.contains(&ssh_name),
        "out-of-range page must clamp back to the filtered rows"
    );

    test_db::cleanup(&mut conn).await;
}

/// A search that matches nothing renders the FILTERED empty state
/// (with the clear-filters escape hatch), not the "nothing configured"
/// onboarding state.
#[tokio::test]
#[serial]
async fn access_rules_filtered_empty_state_offers_clear_filters() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("lf_ar_es")).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("lf-ar-es-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("lf-ar-es-ag")).await;
    let rule = create_test_access_rule(&mut conn, &ug, &ag, &["ssh"]).await;

    let body = get_html(
        app,
        &admin.token,
        "/assets/access?search=zzz-definitely-no-match",
    )
    .await;
    assert!(
        body.contains("No matching access rules"),
        "must render the filtered empty state"
    );
    assert!(
        !body.contains("No access rules configured"),
        "must NOT render the onboarding empty state while filters are active"
    );
    assert!(!body.contains(&access_rule_name(&rule)));

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// /vault/secrets (SQL-backed search + status + pagination)
// =============================================================================

/// The ILIKE search and the status select filter the SQL query
/// conjunctively; an impossible combination lands on the filtered
/// empty state instead of erroring.
#[tokio::test]
#[serial]
async fn vault_secrets_search_and_status_filter_via_sql() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("lf_vs_adm")).await;

    let uniq = Uuid::new_v4().simple().to_string();
    let needle = format!("findme{}", &uniq[..8]);
    let (_id1, s1) = create_test_vault_secret(&mut conn, &needle, "v1", true).await;
    let (_id2, s2) = create_test_vault_secret(&mut conn, "decoy", "v2", false).await;
    let name1 = format!("test-secret-{}_{}", needle, &s1.to_string()[..8]);
    let name2 = format!("test-secret-decoy_{}", &s2.to_string()[..8]);

    // Unfiltered: both visible.
    let body = get_html(app, &admin.token, "/vault/secrets").await;
    assert!(body.contains(&name1));
    assert!(body.contains(&name2));

    // ILIKE search matches only the seeded needle.
    let body = get_html(
        app,
        &admin.token,
        &format!("/vault/secrets?search={needle}"),
    )
    .await;
    assert!(body.contains(&name1));
    assert!(!body.contains(&name2), "decoy must be filtered out");

    // status=inactive isolates the inactive secret.
    let body = get_html(app, &admin.token, "/vault/secrets?status=inactive").await;
    assert!(body.contains(&name2));
    assert!(!body.contains(&name1));

    // Conjunction that matches nothing: filtered empty state, HTTP 200.
    let body = get_html(
        app,
        &admin.token,
        &format!("/vault/secrets?search={needle}&status=inactive"),
    )
    .await;
    assert!(body.contains("No matching"));
    assert!(!body.contains(&name2));

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// /vault/secrets/groups (in-memory search)
// =============================================================================

/// The group search matches name/slug case-insensitively and falls
/// back to the filtered empty state when nothing matches.
#[tokio::test]
#[serial]
async fn vault_secret_groups_search_filters_by_name() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("lf_sg_adm")).await;

    let uniq = Uuid::new_v4().simple().to_string();
    let fragment = format!("grpfind{}", &uniq[..8]);
    let (_id1, g1) = create_test_secret_group(&mut conn, &fragment).await;
    let (_id2, g2) = create_test_secret_group(&mut conn, "grpdecoy").await;
    let name1 = format!("test-sg-{}_{}", fragment, &g1.to_string()[..8]);
    let name2 = format!("test-sg-grpdecoy_{}", &g2.to_string()[..8]);

    let body = get_html(app, &admin.token, "/vault/secrets/groups").await;
    assert!(body.contains(&name1));
    assert!(body.contains(&name2));

    // Case-insensitive: search with the fragment upper-cased.
    let body = get_html(
        app,
        &admin.token,
        &format!("/vault/secrets/groups?search={}", fragment.to_uppercase()),
    )
    .await;
    assert!(body.contains(&name1));
    assert!(!body.contains(&name2));

    let body = get_html(
        app,
        &admin.token,
        "/vault/secrets/groups?search=zzz-definitely-no-match",
    )
    .await;
    assert!(body.contains("No matching"));
    assert!(!body.contains(&name1));

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// /vault/secrets/access (in-memory selects + status + eclipsed)
// =============================================================================

/// The user-group select, status select and eclipsed select compose
/// conjunctively on the secret access rule list.
#[tokio::test]
#[serial]
async fn vault_secret_access_rules_filters_by_group_status_eclipsed() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("lf_sar_adm")).await;

    let ug1 = create_test_vauban_group(&mut conn, &unique_name("lf-sar-ug1")).await;
    let ug2 = create_test_vauban_group(&mut conn, &unique_name("lf-sar-ug2")).await;
    let (sg_id, _sg_uuid) = create_test_secret_group(&mut conn, "lf-sar-sg").await;
    let ag_uuid = create_test_asset_group(&mut conn, &unique_name("lf-sar-ag")).await;
    let ag_id = asset_group_id(&mut conn, &ag_uuid).await;

    let rule_active =
        create_test_secret_access_rule(&mut conn, &ug1, sg_id, ag_id, true, None, None).await;
    let rule_inactive =
        create_test_secret_access_rule(&mut conn, &ug2, sg_id, ag_id, false, None, None).await;
    let name_active = secret_rule_name(&rule_active);
    let name_inactive = secret_rule_name(&rule_inactive);
    let ug1_name = vauban_group_name(&mut conn, &ug1).await;

    // Unfiltered: both visible.
    let body = get_html(app, &admin.token, "/vault/secrets/access").await;
    assert!(body.contains(&name_active));
    assert!(body.contains(&name_inactive));

    // user_group exact-match select.
    let body = get_html(
        app,
        &admin.token,
        &format!("/vault/secrets/access?user_group={ug1_name}"),
    )
    .await;
    assert!(body.contains(&name_active));
    assert!(!body.contains(&name_inactive));

    // status select.
    let body = get_html(app, &admin.token, "/vault/secrets/access?status=inactive").await;
    assert!(body.contains(&name_inactive));
    assert!(!body.contains(&name_active));

    // Neither rule is eclipsed (distinct user groups): eclipsed=yes
    // must land on the filtered empty state, not a 500.
    let body = get_html(app, &admin.token, "/vault/secrets/access?eclipsed=yes").await;
    assert!(!body.contains(&name_active));
    assert!(!body.contains(&name_inactive));
    assert!(body.contains("No matching"));

    // Impossible conjunction: ug1 has no inactive rule.
    let body = get_html(
        app,
        &admin.token,
        &format!("/vault/secrets/access?user_group={ug1_name}&status=inactive"),
    )
    .await;
    assert!(body.contains("No matching"));
    assert!(!body.contains(&name_active));
    assert!(!body.contains(&name_inactive));

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// /assets/manage/deleted (SQL-backed search on the tombstone audit page)
// =============================================================================

/// The tombstone audit page searches name/hostname via ILIKE and falls
/// back to the filtered empty state -- distinct from the "audit trail
/// is empty" onboarding state -- when nothing matches.
#[tokio::test]
#[serial]
async fn deleted_assets_search_filters_tombstones() {
    use vauban_web::schema::assets as schema_assets;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("lf_del_adm")).await;

    let uniq = Uuid::new_v4().simple().to_string();
    let name_target = format!("test-delfind-{}", &uniq[..8]);
    let name_decoy = format!("test-deldecoy-{}", &uniq[..8]);
    let target = create_test_ssh_asset(&mut conn, &name_target).await;
    let decoy = create_test_ssh_asset(&mut conn, &name_decoy).await;

    // Soft-delete both (tombstones), as `delete_asset_web` would.
    diesel::update(
        schema_assets::table
            .filter(schema_assets::uuid.eq_any([target.asset.uuid, decoy.asset.uuid])),
    )
    .set((
        schema_assets::is_deleted.eq(true),
        schema_assets::deleted_at.eq(chrono::Utc::now()),
    ))
    .execute(&mut conn)
    .await
    .expect("soft-delete assets");

    // Unfiltered: both tombstones visible.
    let body = get_html(app, &admin.token, "/assets/manage/deleted").await;
    assert!(body.contains(&name_target));
    assert!(body.contains(&name_decoy));

    // ILIKE search on the name isolates the target.
    let body = get_html(
        app,
        &admin.token,
        &format!("/assets/manage/deleted?search=delfind-{}", &uniq[..8]),
    )
    .await;
    assert!(body.contains(&name_target));
    assert!(!body.contains(&name_decoy), "decoy must be filtered out");

    // Hostname search also matches (fixture derives hostname from name).
    let body = get_html(
        app,
        &admin.token,
        &format!("/assets/manage/deleted?search=delfind-{}.test", &uniq[..8]),
    )
    .await;
    assert!(body.contains(&name_target));
    assert!(!body.contains(&name_decoy));

    // No match: filtered empty state, not the onboarding one.
    let body = get_html(
        app,
        &admin.token,
        "/assets/manage/deleted?search=zzz-definitely-no-match",
    )
    .await;
    assert!(body.contains("No matching deleted assets"));
    assert!(!body.contains("The audit trail is empty"));

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// /sessions/my-requests (self-service, SQL-backed search + status)
// =============================================================================

/// The Access tab of My Requests filters by asset name/hostname
/// (ILIKE) and by status ("tag"); the two compose conjunctively, an
/// unknown status degrades to "no filter", and an impossible
/// combination lands on the filtered empty state.
#[tokio::test]
#[serial]
async fn my_requests_search_and_status_filter() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("lf_myreq")).await;
    let user_id = user.user.id;

    let uniq = Uuid::new_v4().simple().to_string();
    let name_pending = format!("test-myreq-find-{}", &uniq[..8]);
    let name_approved = format!("test-myreq-other-{}", &uniq[..8]);
    let asset_pending = create_simple_ssh_asset(&mut conn, &name_pending, user_id).await;
    let asset_approved = create_simple_ssh_asset(&mut conn, &name_approved, user_id).await;
    create_jit_session(&mut conn, user_id, asset_pending, "ssh", "pending").await;
    create_jit_session(&mut conn, user_id, asset_approved, "ssh", "approved").await;

    // Unfiltered: both requests visible.
    let body = get_html(app, &user.token, "/sessions/my-requests").await;
    assert!(body.contains(&name_pending));
    assert!(body.contains(&name_approved));

    // ILIKE search on the asset name.
    let body = get_html(
        app,
        &user.token,
        &format!("/sessions/my-requests?search=myreq-find-{}", &uniq[..8]),
    )
    .await;
    assert!(body.contains(&name_pending));
    assert!(!body.contains(&name_approved), "decoy must be filtered out");

    // Status ("tag") select.
    let body = get_html(app, &user.token, "/sessions/my-requests?status=approved").await;
    assert!(body.contains(&name_approved));
    assert!(!body.contains(&name_pending));

    // Unknown status degrades to "no filter" (closed vocabulary).
    let body = get_html(app, &user.token, "/sessions/my-requests?status=bogus").await;
    assert!(body.contains(&name_pending));
    assert!(body.contains(&name_approved));

    // Impossible conjunction: the pending asset has no approved row.
    let body = get_html(
        app,
        &user.token,
        &format!(
            "/sessions/my-requests?search=myreq-find-{}&status=approved",
            &uniq[..8]
        ),
    )
    .await;
    assert!(body.contains("No matching access requests"));
    assert!(!body.contains(&name_pending));
    assert!(!body.contains(&name_approved));

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Authorization is filter-neutral
// =============================================================================

/// A plain user (no `vault_secrets:manage`) stays 403 on the vault
/// lists whatever query string is appended -- filters must never open
/// an authorization side door.
#[tokio::test]
#[serial]
async fn vault_lists_stay_403_for_plain_user_with_filters() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("lf_403")).await;

    for path in [
        "/vault/secrets?search=x&status=inactive&page=2",
        "/vault/secrets/groups?search=x",
        "/vault/secrets/access?user_group=x&status=active&eclipsed=yes",
    ] {
        let response = app
            .server
            .get(path)
            .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
            .await;
        assert_status(&response, 403);
    }

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Drift regressions pinned end-to-end
// =============================================================================

/// `/sessions/approvals` historically skipped the page clamp
/// (`total_pages` could be 0 and `page` unbounded). The shared
/// `paginate` seam must keep any absurd page a plain 200.
#[tokio::test]
#[serial]
async fn approvals_out_of_range_page_clamps_to_200() {
    let app = TestApp::spawn().await;

    let token = app
        .generate_test_token(
            &Uuid::new_v4().to_string(),
            "test_lf_approvals_clamp",
            true,
            true,
        )
        .await;

    for path in [
        "/sessions/approvals?page=9999",
        "/sessions/approvals?page=-5",
        "/sessions/approvals?page=notanumber",
    ] {
        let response = app
            .server
            .get(path)
            .add_header(axum::http::header::COOKIE, format!("access_token={token}"))
            .await;
        assert_status(&response, 200);
    }
}

/// `/audit/approvals?actor=...%...` historically interpolated the raw
/// `%` into the ILIKE pattern (wildcard injection). With
/// `db::like_contains` the `%` must match LITERALLY: an actor whose
/// name really contains `%` is found, a lookalike with another
/// character in that position is not.
#[tokio::test]
#[serial]
async fn audit_actor_filter_treats_percent_literally() {
    use vauban_web::schema::approval_audit_log;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("lf_audit")).await;

    // approval_audit_log is append-only (no cleanup): unique actor
    // names keep this test independent from leftover rows.
    let uniq = Uuid::new_v4().simple().to_string();
    let actor_literal = format!("audit-pct-{}-a%b", &uniq[..8]);
    let actor_decoy = format!("audit-pct-{}-aXb", &uniq[..8]);

    for actor in [&actor_literal, &actor_decoy] {
        diesel::insert_into(approval_audit_log::table)
            .values((
                approval_audit_log::session_uuid.eq(Uuid::new_v4()),
                approval_audit_log::decision.eq("approve"),
                approval_audit_log::actor_username.eq(actor),
                approval_audit_log::requester_username.eq("test_lf_audit_req"),
                approval_audit_log::asset_uuid.eq(Uuid::new_v4()),
                approval_audit_log::asset_name.eq("test-lf-audit-asset"),
            ))
            .execute(&mut conn)
            .await
            .expect("audit row insert");
    }

    // `%` URL-encoded as %25; pre-fix this matched BOTH rows
    // (wildcard), post-fix only the literal one.
    let body = get_html(
        app,
        &admin.token,
        &format!("/audit/approvals?actor=audit-pct-{}-a%25b", &uniq[..8]),
    )
    .await;
    // The filter input echoes the needle, so the decoy's ABSENCE is
    // the discriminating assertion.
    assert!(
        !body.contains(&actor_decoy),
        "wildcard injection: 'a%b' must not match 'aXb'"
    );
    assert!(
        body.contains(&actor_literal),
        "the literal 'a%b' actor must be found"
    );

    test_db::cleanup(&mut conn).await;
}

/// `/sessions?status=X` for EVERY value of the SESSION_HISTORY
/// vocabulary returns exactly the row seeded with that status --
/// including `expired`, which the pre-fix select simply did not
/// offer. An out-of-vocabulary value degrades to the UNFILTERED view
/// (fail-open, anti-oracle), never to a misleading empty list.
#[tokio::test]
#[serial]
async fn sessions_status_filter_covers_full_vocabulary() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("lf_st")).await;
    let uniq = Uuid::new_v4().simple().to_string();

    // Non-IACS vocabulary only: the test app runs with the industrial
    // kill-switch off, so waiting_client / tunnel_active rows are
    // structurally excluded from `/sessions` (layer-2 DB filter).
    let statuses = vauban_web::services::status_vocab::SESSION_HISTORY.values();

    let mut seeded: Vec<(String, String)> = Vec::new();
    for status in &statuses {
        let asset_name = format!("lf-st-{}-{}", &uniq[..8], status.replace('_', "-"));
        let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin.user.id).await;
        create_test_session(&mut conn, admin.user.id, asset_id, "ssh", status).await;
        seeded.push(((*status).to_string(), asset_name));
    }

    // Explicit `expired` case first (the historical gap), then the
    // whole vocabulary: each value returns its row and ONLY its row.
    for (status, asset_name) in &seeded {
        let body = get_html(app, &admin.token, &format!("/sessions?status={status}")).await;
        assert!(
            body.contains(asset_name),
            "?status={status} must return the '{status}' row"
        );
        for (other_status, other_name) in &seeded {
            if other_status != status {
                assert!(
                    !body.contains(other_name),
                    "?status={status} must not return the '{other_status}' row"
                );
            }
        }
    }

    // Fail-open: an unknown status renders the unfiltered view.
    let body = get_html(app, &admin.token, "/sessions?status=bogus").await;
    for (status, asset_name) in &seeded {
        assert!(
            body.contains(asset_name),
            "?status=bogus must degrade to the unfiltered view (missing '{status}' row)"
        );
    }

    test_db::cleanup(&mut conn).await;
}

/// `/audit/approvals?decision=revoke` returns the revocation audit
/// rows -- the pre-fix select only offered approve / reject even
/// though the DB CHECK accepts four verbs. Unknown decisions degrade
/// to the unfiltered view (same fail-open contract as everywhere).
#[tokio::test]
#[serial]
async fn audit_decision_filter_supports_revoke() {
    use vauban_web::schema::approval_audit_log;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("lf_rvk")).await;

    // approval_audit_log is append-only (no cleanup): unique actor
    // names keep this test independent from leftover rows.
    let uniq = Uuid::new_v4().simple().to_string();
    let actor_revoke = format!("audit-rvk-{}-revoker", &uniq[..8]);
    let actor_approve = format!("audit-rvk-{}-approver", &uniq[..8]);

    for (actor, decision) in [(&actor_revoke, "revoke"), (&actor_approve, "approve")] {
        diesel::insert_into(approval_audit_log::table)
            .values((
                approval_audit_log::session_uuid.eq(Uuid::new_v4()),
                approval_audit_log::decision.eq(decision),
                approval_audit_log::actor_username.eq(actor),
                approval_audit_log::requester_username.eq("test_lf_rvk_req"),
                approval_audit_log::asset_uuid.eq(Uuid::new_v4()),
                approval_audit_log::asset_name.eq("test-lf-rvk-asset"),
            ))
            .execute(&mut conn)
            .await
            .expect("audit row insert");
    }

    let body = get_html(app, &admin.token, "/audit/approvals?decision=revoke").await;
    assert!(
        body.contains(&actor_revoke),
        "?decision=revoke must return the revocation row"
    );
    assert!(
        !body.contains(&actor_approve),
        "?decision=revoke must not return the approval row"
    );

    // Fail-open: an unknown decision renders the unfiltered view.
    let body = get_html(app, &admin.token, "/audit/approvals?decision=bogus").await;
    assert!(
        body.contains(&actor_revoke),
        "unfiltered view must show the revoke row"
    );
    assert!(
        body.contains(&actor_approve),
        "unfiltered view must show the approve row"
    );

    test_db::cleanup(&mut conn).await;
}

/// `/accounts/users?sort=last_login` orders by last login with the
/// never-logged-in accounts FIRST (dormant-account spotting: NULLS
/// FIRST, the opposite of the Postgres ASC default), `-last_login`
/// reverses with NULLs last, an unknown sort degrades to the default
/// username ordering (fail-open), and the sort composes with the
/// live search filter.
#[tokio::test]
#[serial]
async fn users_sort_by_last_login_orders_dormant_first() {
    use vauban_web::schema::users;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("lf_us")).await;

    // Username order (aa < mm < zz) is deliberately the OPPOSITE of
    // the dormancy order (zz = never logged in, mm = old login,
    // aa = recent login) so the two orderings are distinguishable.
    let uniq = Uuid::new_v4().simple().to_string();
    let prefix = format!("lfsrt{}", &uniq[..8]);
    let name_recent = format!("{prefix}aa");
    let name_old = format!("{prefix}mm");
    let name_never = format!("{prefix}zz");

    let recent_id = crate::fixtures::create_simple_user(&mut conn, &name_recent).await;
    let old_id = crate::fixtures::create_simple_user(&mut conn, &name_old).await;
    let _never_id = crate::fixtures::create_simple_user(&mut conn, &name_never).await;

    let now = chrono::Utc::now();
    diesel::update(users::table.filter(users::id.eq(recent_id)))
        .set(users::last_login.eq(now))
        .execute(&mut conn)
        .await
        .expect("set recent last_login");
    diesel::update(users::table.filter(users::id.eq(old_id)))
        .set(users::last_login.eq(now - chrono::Duration::days(400)))
        .execute(&mut conn)
        .await
        .expect("set old last_login");
    // name_never keeps last_login = NULL (fixture default).

    // The search filter scopes every assertion to our three rows
    // (the shared DB accumulates users) AND proves sort + search
    // compose.
    let pos = |body: &str, needle: &str| {
        body.find(needle)
            .unwrap_or_else(|| panic!("'{needle}' missing from the page"))
    };

    // Ascending: never (NULL) first, then oldest, then most recent.
    let body = get_html(
        app,
        &admin.token,
        &format!("/accounts/users?search={prefix}&sort=last_login"),
    )
    .await;
    assert!(
        pos(&body, &name_never) < pos(&body, &name_old)
            && pos(&body, &name_old) < pos(&body, &name_recent),
        "sort=last_login must order never -> old -> recent (dormant first)"
    );

    // Descending: most recent first, NULLs last.
    let body = get_html(
        app,
        &admin.token,
        &format!("/accounts/users?search={prefix}&sort=-last_login"),
    )
    .await;
    assert!(
        pos(&body, &name_recent) < pos(&body, &name_old)
            && pos(&body, &name_old) < pos(&body, &name_never),
        "sort=-last_login must order recent -> old -> never"
    );

    // Fail-open: unknown sort falls back to username ASC (aa < mm < zz).
    let body = get_html(
        app,
        &admin.token,
        &format!("/accounts/users?search={prefix}&sort=bogus"),
    )
    .await;
    assert!(
        pos(&body, &name_recent) < pos(&body, &name_old)
            && pos(&body, &name_old) < pos(&body, &name_never),
        "unknown sort must degrade to the default username ordering"
    );

    test_db::cleanup(&mut conn).await;
}
