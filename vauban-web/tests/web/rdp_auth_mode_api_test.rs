//! `rdp_auth_mode` / `rdp_domain` on the asset management JSON API
//! (`/api/v1/assets/manage`) and the mode badge of the admin asset list.
//!
//! The API and the web form share one validator
//! (`services::rdp_auth_mode`), so the rules pinned by
//! `rdp_kerberos_mode_test` for the form hold here too:
//!
//! - an unknown mode is a 400, never stored as `ntlm`;
//! - a Kerberos mode needs an FQDN target and a DNS-form domain;
//! - an update is validated on the effective (mode, hostname, domain);
//! - the fields are refused on an asset that is not RDP.

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{create_admin_user, unique_name};
use axum::http::header::{AUTHORIZATION, COOKIE};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value as Json, json};
use serial_test::serial;
use vauban_web::models::asset::Asset;
use vauban_web::schema::assets;

const REALM: &str = "corp.example.com";

async fn read_asset_by_name(conn: &mut AsyncPgConnection, name: &str) -> Option<Asset> {
    assets::table
        .filter(assets::name.eq(name))
        .filter(assets::is_deleted.eq(false))
        .first::<Asset>(conn)
        .await
        .ok()
}

fn fqdn() -> String {
    format!("{}.{REALM}", unique_name("host"))
}

/// POST the create API for an RDP asset. Returns the name and the response.
async fn api_create(
    app: &TestApp,
    api_key: &str,
    hostname: &str,
    extra: Json,
) -> (String, axum_test::TestResponse) {
    let name = unique_name("rdp-api");
    let mut body = json!({
        "name": name,
        "hostname": hostname,
        "port": 3389,
        "asset_type": "rdp",
    });
    if let (Some(body), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
        body.extend(extra.clone());
    }
    let response = app
        .server
        .post("/api/v1/assets/manage")
        .add_header(AUTHORIZATION, app.api_key_header(api_key))
        .json(&body)
        .await;
    (name, response)
}

async fn api_update(
    app: &TestApp,
    api_key: &str,
    asset: &Asset,
    body: Json,
) -> axum_test::TestResponse {
    app.server
        .put(&format!("/api/v1/assets/manage/{}", asset.uuid))
        .add_header(AUTHORIZATION, app.api_key_header(api_key))
        .json(&body)
        .await
}

// =============================================================================
// Create
// =============================================================================

/// Each mode is stored verbatim and read back in the response and by GET.
#[tokio::test]
#[serial]
async fn test_api_create_rdp_stores_and_returns_each_mode() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("api_mode_ok")).await;

    for mode in ["ntlm", "kerberos", "kerberos_restricted_admin"] {
        let (name, response) = api_create(
            app,
            &admin.api_key,
            &fqdn(),
            json!({"rdp_auth_mode": mode, "rdp_domain": REALM}),
        )
        .await;
        assert_status(&response, 200);
        let created: Json = response.json();
        assert_eq!(created["connection_config"]["rdp_auth_mode"], mode);
        assert_eq!(created["connection_config"]["domain"], REALM);

        let asset = read_asset_by_name(&mut conn, &name).await.expect("row");
        assert_eq!(asset.connection_config["rdp_auth_mode"], mode);

        let read = app
            .server
            .get(&format!("/api/v1/assets/manage/{}", asset.uuid))
            .add_header(AUTHORIZATION, app.api_key_header(&admin.api_key))
            .await;
        assert_status(&read, 200);
        let read: Json = read.json();
        assert_eq!(read["connection_config"]["rdp_auth_mode"], mode);
    }

    test_db::cleanup(&mut conn).await;
}

/// No mode: `ntlm`, with an IP target and no domain, as before.
#[tokio::test]
#[serial]
async fn test_api_create_rdp_without_mode_defaults_to_ntlm() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("api_mode_def")).await;

    let (name, response) = api_create(app, &admin.api_key, "192.0.2.44", json!({})).await;
    assert_status(&response, 200);
    let asset = read_asset_by_name(&mut conn, &name).await.expect("row");
    assert_eq!(asset.connection_config["rdp_auth_mode"], "ntlm");
    assert!(asset.connection_config.get("domain").is_none());

    test_db::cleanup(&mut conn).await;
}

/// An unknown mode is a 400 and NO row: it is not folded into `ntlm`.
#[tokio::test]
#[serial]
async fn attack_api_create_with_unknown_mode_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("api_mode_bad")).await;

    for mode in [
        "Kerberos",
        "kerbeross",
        "kerberos-restricted-admin",
        "negotiate",
        "kerberos'; DROP TABLE assets; --",
    ] {
        let (name, response) = api_create(
            app,
            &admin.api_key,
            &fqdn(),
            json!({"rdp_auth_mode": mode, "rdp_domain": REALM}),
        )
        .await;
        assert_status(&response, 400);
        assert!(
            read_asset_by_name(&mut conn, &name).await.is_none(),
            "mode {mode:?} must not create an asset"
        );
    }

    test_db::cleanup(&mut conn).await;
}

/// A Kerberos mode without an FQDN target or a DNS-form domain: 400, no row.
#[tokio::test]
#[serial]
async fn attack_api_create_kerberos_without_fqdn_or_realm_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("api_krb_bad")).await;

    let good_host = fqdn();
    let cases: [(&str, Json); 6] = [
        ("192.0.2.45", json!({"rdp_domain": REALM})),
        ("srv01", json!({"rdp_domain": REALM})),
        (&good_host, json!({})),
        (&good_host, json!({"rdp_domain": ""})),
        (&good_host, json!({"rdp_domain": "CORP"})),
        (
            &good_host,
            json!({"rdp_domain": "corp.example.com@evil.test"}),
        ),
    ];
    for mode in ["kerberos", "kerberos_restricted_admin"] {
        for (hostname, extra) in &cases {
            let mut extra = extra.clone();
            extra["rdp_auth_mode"] = json!(mode);
            let (name, response) = api_create(app, &admin.api_key, hostname, extra.clone()).await;
            assert_status(&response, 400);
            assert!(
                read_asset_by_name(&mut conn, &name).await.is_none(),
                "{mode} / {hostname} / {extra} must not create an asset"
            );
        }
    }

    test_db::cleanup(&mut conn).await;
}

/// The RDP fields are refused on an SSH asset, on create and on update.
#[tokio::test]
#[serial]
async fn attack_api_rdp_fields_on_non_rdp_asset_are_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("api_nonrdp")).await;

    let name = unique_name("ssh-api");
    let body = |extra: Json| {
        let mut b = json!({"name": name, "hostname": fqdn(), "port": 22, "asset_type": "ssh"});
        if let (Some(b), Some(extra)) = (b.as_object_mut(), extra.as_object()) {
            b.extend(extra.clone());
        }
        b
    };
    for extra in [
        json!({"rdp_auth_mode": "kerberos"}),
        json!({"rdp_domain": REALM}),
    ] {
        let response = app
            .server
            .post("/api/v1/assets/manage")
            .add_header(AUTHORIZATION, app.api_key_header(&admin.api_key))
            .json(&body(extra))
            .await;
        assert_status(&response, 400);
        assert!(read_asset_by_name(&mut conn, &name).await.is_none());
    }

    let response = app
        .server
        .post("/api/v1/assets/manage")
        .add_header(AUTHORIZATION, app.api_key_header(&admin.api_key))
        .json(&body(json!({})))
        .await;
    assert_status(&response, 200);
    let asset = read_asset_by_name(&mut conn, &name).await.expect("ssh row");
    let response = api_update(
        app,
        &admin.api_key,
        &asset,
        json!({"rdp_auth_mode": "ntlm"}),
    )
    .await;
    assert_status(&response, 400);
    let after = read_asset_by_name(&mut conn, &name).await.expect("ssh row");
    assert_eq!(after.connection_config, asset.connection_config);

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Update
// =============================================================================

/// Switching an NTLM asset to Kerberos persists and keeps the other keys.
#[tokio::test]
#[serial]
async fn test_api_update_switches_the_mode() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("api_upd_ok")).await;

    let (name, response) =
        api_create(app, &admin.api_key, &fqdn(), json!({"rdp_domain": "CORP"})).await;
    assert_status(&response, 200);
    let asset = read_asset_by_name(&mut conn, &name).await.expect("row");

    let response = api_update(
        app,
        &admin.api_key,
        &asset,
        json!({"rdp_auth_mode": "kerberos", "rdp_domain": REALM}),
    )
    .await;
    assert_status(&response, 200);
    let updated: Json = response.json();
    assert_eq!(updated["connection_config"]["rdp_auth_mode"], "kerberos");

    let after = read_asset_by_name(&mut conn, &name).await.expect("row");
    assert_eq!(after.connection_config["rdp_auth_mode"], "kerberos");
    assert_eq!(after.connection_config["domain"], REALM);

    // An update that names neither field keeps both.
    let response = api_update(app, &admin.api_key, &after, json!({"description": "x"})).await;
    assert_status(&response, 200);
    let kept = read_asset_by_name(&mut conn, &name).await.expect("row");
    assert_eq!(kept.connection_config, after.connection_config);

    test_db::cleanup(&mut conn).await;
}

/// Updates that would leave a Kerberos asset without an FQDN target or a
/// realm are 400 and change nothing, including a hostname-only update.
#[tokio::test]
#[serial]
async fn attack_api_update_that_breaks_a_kerberos_asset_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("api_upd_bad")).await;

    let (name, response) = api_create(
        app,
        &admin.api_key,
        &fqdn(),
        json!({"rdp_auth_mode": "kerberos", "rdp_domain": REALM}),
    )
    .await;
    assert_status(&response, 200);
    let before = read_asset_by_name(&mut conn, &name).await.expect("row");

    for body in [
        json!({"hostname": "192.0.2.46"}),
        json!({"hostname": "srv01"}),
        json!({"rdp_domain": ""}),
        json!({"rdp_domain": "CORP"}),
        json!({"rdp_auth_mode": "kerbeross"}),
        json!({"rdp_auth_mode": "kerberos_restricted_admin", "rdp_domain": "CORP"}),
    ] {
        let response = api_update(app, &admin.api_key, &before, body.clone()).await;
        assert_status(&response, 400);
        let after = read_asset_by_name(&mut conn, &name).await.expect("row");
        assert_eq!(after.hostname, before.hostname, "{body}");
        assert_eq!(after.connection_config, before.connection_config, "{body}");
    }

    // Leaving Kerberos lifts the constraints in the same request.
    let response = api_update(
        app,
        &admin.api_key,
        &before,
        json!({"rdp_auth_mode": "ntlm", "hostname": "192.0.2.46"}),
    )
    .await;
    assert_status(&response, 200);

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Admin list badge
// =============================================================================

/// The admin list shows the mode of an RDP asset, and no badge for SSH.
#[tokio::test]
#[serial]
async fn test_manage_list_shows_the_mode_badge_for_rdp_only() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("api_badge")).await;

    let list = |search: String| {
        let token = admin.token.clone();
        async move {
            app.server
                .get(&format!("/assets/manage?search={search}"))
                .add_header(COOKIE, format!("access_token={token}"))
                .await
        }
    };

    for (extra, label) in [
        (json!({}), ">\n                                    NTLM\n"),
        (
            json!({"rdp_auth_mode": "kerberos", "rdp_domain": REALM}),
            ">\n                                    Kerberos\n",
        ),
        (
            json!({"rdp_auth_mode": "kerberos_restricted_admin", "rdp_domain": REALM}),
            ">\n                                    Kerberos RA\n",
        ),
    ] {
        let (name, response) = api_create(app, &admin.api_key, &fqdn(), extra).await;
        assert_status(&response, 200);
        let page = list(name.clone()).await;
        assert_status(&page, 200);
        let body = page.text();
        assert_eq!(
            body.matches("data-rdp-auth-mode-badge").count(),
            1,
            "{name}"
        );
        assert!(body.contains(label), "badge {label:?} missing for {name}");
    }

    let ssh_name = unique_name("ssh-badge");
    let response = app
        .server
        .post("/api/v1/assets/manage")
        .add_header(AUTHORIZATION, app.api_key_header(&admin.api_key))
        .json(&json!({"name": ssh_name, "hostname": fqdn(), "port": 22, "asset_type": "ssh"}))
        .await;
    assert_status(&response, 200);
    let page = list(ssh_name.clone()).await;
    assert_status(&page, 200);
    assert!(!page.text().contains("data-rdp-auth-mode-badge"));

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Source pins
// =============================================================================

/// The form and the API validate through the same service, once per
/// write path, and neither compares mode strings itself.
#[test]
fn test_form_and_api_share_one_rdp_auth_validator() {
    let web = include_str!("../../src/handlers/web/manage_assets.rs");
    let api = include_str!("../../src/handlers/api/manage_assets.rs");
    for (name, source) in [("web", web), ("api", api)] {
        assert_eq!(
            source
                .matches("crate::services::rdp_auth_mode::resolve(")
                .count(),
            2,
            "{name}: create and update each resolve once"
        );
        for forbidden in [
            "validate_kerberos_fqdn(",
            "validate_kerberos_domain(",
            "normalize_realm(",
            "\"kerberos_restricted_admin\"",
        ] {
            assert!(
                !source.contains(forbidden),
                "{name} handler uses `{forbidden}`"
            );
        }
    }
    // The API never folds an unknown mode into NTLM.
    assert!(!api.contains("normalize_rdp_auth_mode"));

    let service = include_str!("../../src/services/rdp_auth_mode.rs");
    assert!(service.contains("shared::kerberos::normalize_realm("));
    assert!(service.contains(".ok_or(RdpAuthSettingsError::UnknownMode)"));
}
