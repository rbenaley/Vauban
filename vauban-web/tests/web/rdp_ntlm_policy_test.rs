//! `[rdp] ntlm_policy` on the web tier.
//!
//! Under `deny`, `connect_rdp` refuses an asset whose mode is not a
//! Kerberos mode before any session record exists, including for an
//! asset created earlier. The default (`allow`) changes nothing.
//!
//! No RDP proxy runs in this suite: a request that passes the policy
//! reaches the "RDP proxy not available" answer, which is how these
//! tests tell "refused by policy" from "let through".

use crate::common::{TestApp, assertions::assert_status, unwrap_ok};
use crate::fixtures::{
    add_user_to_vauban_group, create_admin_user, create_simple_admin_user, create_simple_user,
    create_test_access_rule_with_constraints, create_test_asset_group,
    create_test_asset_in_group_with_type, create_test_vauban_group, get_asset_uuid, unique_name,
};
use axum::http::header::COOKIE;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;
use vauban_web::models::asset::AssetType;

const PINNED_SPKI_B64: &str = "TUlJQklqQU5CZ2txaGtpRzl3MEJ-VkFVLTAwMS10ZXN0LXNwa2k=";
const PINNED_CERT_FP: &str = "SHA256:vauban-ntlm-policy-pinned-cert-fingerprint";
const POLICY_TOAST_GENERIC: &str = "The target refused the authentication";
const PROXY_UNAVAILABLE: &str = "RDP proxy not available";

struct Scenario {
    user_id: i32,
    user_uuid: Uuid,
    user_name: String,
    asset_id: i32,
    asset_uuid: Uuid,
}

/// A regular user with an access rule on one RDP asset whose certificate
/// is pinned, in the given auth mode (`None` = no stored mode).
async fn scenario(conn: &mut AsyncPgConnection, label: &str, mode: Option<&str>) -> Scenario {
    use vauban_web::schema::{assets::dsl as a, users};

    let admin_id = create_simple_admin_user(conn, &unique_name(&format!("{label}_admin"))).await;
    let user_name = unique_name(&format!("{label}_user"));
    let user_id = create_simple_user(conn, &user_name).await;
    let user_uuid: Uuid = unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(conn)
            .await
    );

    let ug = create_test_vauban_group(conn, &unique_name(&format!("{label}_ug"))).await;
    add_user_to_vauban_group(conn, user_id, &ug).await;
    let ag = create_test_asset_group(conn, &unique_name(&format!("{label}_ag"))).await;
    let asset_id = create_test_asset_in_group_with_type(
        conn,
        &unique_name(&format!("{label}_asset")),
        admin_id,
        &ag,
        AssetType::Rdp,
    )
    .await;
    let asset_uuid = get_asset_uuid(conn, asset_id).await;
    create_test_access_rule_with_constraints(conn, &ug, &ag, &["rdp"], false, false, Some(600))
        .await;

    let mut config = json!({
        "username": "jdoe",
        "domain": "corp.example.com",
        "rdp_server_cert_spki": PINNED_SPKI_B64,
        "rdp_server_cert_fingerprint": PINNED_CERT_FP,
    });
    if let Some(mode) = mode {
        config["rdp_auth_mode"] = json!(mode);
    }
    let _: usize = unwrap_ok!(
        diesel::update(a::assets.filter(a::id.eq(asset_id)))
            .set(a::connection_config.eq(config))
            .execute(conn)
            .await
    );

    Scenario {
        user_id,
        user_uuid,
        user_name,
        asset_id,
        asset_uuid,
    }
}

/// POST connect-rdp as the scenario's user. Returns the toast payload.
async fn connect(app: &TestApp, s: &Scenario) -> String {
    let token = app
        .generate_test_token(&s.user_uuid.to_string(), &s.user_name, false, false)
        .await;
    let csrf = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/assets/{}/connect-rdp", s.asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .add_header(
            axum::http::header::HeaderName::from_static("hx-request"),
            "true",
        )
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert!(response.status_code().as_u16() < 500);
    response
        .headers()
        .get("HX-Trigger")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default()
}

async fn session_rows(conn: &mut AsyncPgConnection, s: &Scenario) -> i64 {
    use vauban_web::schema::proxy_sessions::dsl as ps;
    unwrap_ok!(
        ps::proxy_sessions
            .filter(ps::user_id.eq(s.user_id))
            .filter(ps::asset_id.eq(s.asset_id))
            .count()
            .get_result(conn)
            .await
    )
}

/// Under `deny`, an NTLM asset opens no session: refused before any
/// session record, with the generic sentence for a regular user. An
/// asset with no stored mode is NTLM too.
#[tokio::test]
#[serial]
async fn attack_ntlm_session_under_deny_policy_is_rejected() {
    let app = TestApp::spawn_ntlm_denied().await;
    let mut conn = app.get_conn().await;

    for mode in [Some("ntlm"), None, Some("not-a-mode")] {
        let s = scenario(&mut conn, "ntlm_deny", mode).await;
        let toast = connect(app, &s).await;
        assert!(
            toast.contains(POLICY_TOAST_GENERIC),
            "{mode:?} must be refused by policy, got: {toast}"
        );
        assert!(!toast.contains(PROXY_UNAVAILABLE), "{mode:?}: {toast}");
        // A regular user is not told the cause.
        assert!(!toast.contains("NTLM"), "{mode:?}: {toast}");
        assert_eq!(session_rows(&mut conn, &s).await, 0, "{mode:?}");
    }
}

/// A user with NO access rule on the asset is told so, not that NTLM is
/// forbidden: the policy answer would reveal the asset's auth mode to
/// someone who may not open it.
#[tokio::test]
#[serial]
async fn attack_auth_mode_disclosure_to_user_without_access_is_rejected() {
    let app = TestApp::spawn_ntlm_denied().await;
    let mut conn = app.get_conn().await;

    let s = scenario(&mut conn, "ntlm_noaccess", Some("ntlm")).await;
    // Another user, in no group, with no rule on the asset.
    let outsider_name = unique_name("ntlm_outsider");
    let outsider_id = create_simple_user(&mut conn, &outsider_name).await;
    let outsider_uuid: Uuid = {
        use vauban_web::schema::users;
        unwrap_ok!(
            users::table
                .filter(users::id.eq(outsider_id))
                .select(users::uuid)
                .first(&mut conn)
                .await
        )
    };
    let outsider = Scenario {
        user_id: outsider_id,
        user_uuid: outsider_uuid,
        user_name: outsider_name,
        asset_id: s.asset_id,
        asset_uuid: s.asset_uuid,
    };

    let toast = connect(app, &outsider).await;
    assert!(
        !toast.contains(POLICY_TOAST_GENERIC) && !toast.contains("NTLM"),
        "an outsider must not get the policy answer, got: {toast}"
    );
    assert!(!toast.contains(PROXY_UNAVAILABLE), "got: {toast}");
    assert_eq!(session_rows(&mut conn, &outsider).await, 0);
}

/// Under `deny`, both Kerberos modes pass the policy.
#[tokio::test]
#[serial]
async fn test_kerberos_session_under_deny_policy_passes_the_policy() {
    let app = TestApp::spawn_ntlm_denied().await;
    let mut conn = app.get_conn().await;

    for mode in ["kerberos", "kerberos_restricted_admin"] {
        let s = scenario(&mut conn, "krb_deny", Some(mode)).await;
        let toast = connect(app, &s).await;
        assert!(
            toast.contains(PROXY_UNAVAILABLE),
            "{mode} must pass the policy, got: {toast}"
        );
    }
}

/// The default policy is `allow`: an NTLM asset passes, as before.
#[tokio::test]
#[serial]
async fn test_ntlm_session_under_default_policy_passes_the_policy() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let s = scenario(&mut conn, "ntlm_allow", Some("ntlm")).await;
    let toast = connect(app, &s).await;
    assert!(toast.contains(PROXY_UNAVAILABLE), "got: {toast}");
}

/// Under `deny`, the forms disable the NTLM option, say why, and the
/// create form starts on a Kerberos mode.
#[tokio::test]
#[serial]
async fn test_forms_disable_the_ntlm_option_under_deny_policy() {
    let app = TestApp::spawn_ntlm_denied().await;
    let mut conn = app.get_conn().await;
    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("ntlm_deny_form")).await;

    let page = app
        .server
        .get("/assets/manage/new")
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&page, 200);
    let body = page.text();
    assert!(body.contains(
        r#"<option value="ntlm" disabled>Password / NTLMv2 (forbidden by policy)</option>"#
    ));
    assert!(body.contains("data-ntlm-denied-notice"));
    assert!(body.contains("rdpAuthMode: 'kerberos'"));
}

/// Under the default policy the forms are unchanged.
#[tokio::test]
#[serial]
async fn test_forms_keep_the_ntlm_option_under_default_policy() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("ntlm_allow_form"),
    )
    .await;

    let page = app
        .server
        .get("/assets/manage/new")
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&page, 200);
    let body = page.text();
    assert!(body.contains(r#"<option value="ntlm">Password / NTLMv2</option>"#));
    assert!(!body.contains("data-ntlm-denied-notice"));
    assert!(body.contains("rdpAuthMode: 'ntlm'"));
}

/// Source pins: where the policy sits in `connect_rdp`.
#[test]
fn test_connect_rdp_applies_the_policy_before_any_session_work() {
    let source = include_str!("../../src/handlers/web/rdp.rs");
    let gate = source
        .find("if !state.config.rdp.ntlm_policy.permits(rdp_auth_mode) {")
        .expect("policy gate in connect_rdp");
    assert_eq!(
        source.matches(".ntlm_policy.permits(").count(),
        1,
        "one policy gate"
    );
    // After the access rules, so a caller without access learns nothing.
    let access = source
        .find("No access rule grants you access to this asset")
        .expect("access-rule refusal");
    assert!(access < gate, "the policy gate follows the access rules");
    // Before the proxy, the session record and the token.
    for later in [
        "let proxy_client = match &state.rdp_proxy {",
        "Failed to create session record",
        "proxy_client.open_session(request)",
    ] {
        let at = source
            .find(later)
            .unwrap_or_else(|| panic!("missing `{later}`"));
        assert!(gate < at, "the policy gate precedes `{later}`");
    }
    // The gate asks the shared policy, it does not compare modes itself.
    let block = &source[gate..gate + 500];
    assert!(block.contains("shared::messages::RdpAuthFailure::NtlmForbidden,"));
    assert!(block.contains("return refuse_rdp_auth("));
    assert!(!source.contains("RdpAuthMode::Ntlm =>"));
}

/// The web tier reads the policy through serde's closed set: an unknown
/// value is a configuration error, not `allow`.
#[test]
fn attack_mistyped_ntlm_policy_in_web_config_is_rejected() {
    use vauban_web::config::RdpSettings;
    let parse = |source: serde_json::Value| serde_json::from_value::<RdpSettings>(source);

    assert_eq!(
        unwrap_ok!(parse(json!({}))).ntlm_policy,
        shared::messages::NtlmPolicy::Allow
    );
    assert_eq!(
        unwrap_ok!(parse(json!({"ntlm_policy": "deny"}))).ntlm_policy,
        shared::messages::NtlmPolicy::Deny
    );
    // The supervisor's key in the same table is ignored.
    assert_eq!(
        unwrap_ok!(parse(
            json!({"video_bitrate_bps": 5_000_000, "ntlm_policy": "allow"})
        ))
        .ntlm_policy,
        shared::messages::NtlmPolicy::Allow
    );
    for bad in [
        json!({"ntlm_policy": "Deny"}),
        json!({"ntlm_policy": "denny"}),
        json!({"ntlm_policy": ""}),
        json!({"ntlm_policy": true}),
        json!({"ntlm_policy": 0}),
    ] {
        assert!(parse(bad.clone()).is_err(), "{bad} must be refused");
    }
}
