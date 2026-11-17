//! Raising a trust-anchor mismatch flag changes one key and nothing else.
//!
//! The flag used to be raised by reading the whole `connection_config`,
//! setting one key in memory and writing the document back, after a
//! network round trip to the target. A pin stored in between was
//! overwritten with the stale copy. `raise_trust_anchor_flag` is one
//! `jsonb_set` statement.

use crate::common::TestApp;
use crate::fixtures::{create_admin_user, create_simple_ssh_asset, get_asset_uuid, unique_name};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serial_test::serial;
use uuid::Uuid;
use vauban_web::models::asset::{TrustAnchorFlag, raise_trust_anchor_flag};

async fn stored_config(conn: &mut AsyncPgConnection, asset: Uuid) -> serde_json::Value {
    use vauban_web::schema::assets;
    assets::table
        .filter(assets::uuid.eq(asset))
        .select(assets::connection_config)
        .first(conn)
        .await
        .expect("asset row")
}

async fn store_config(conn: &mut AsyncPgConnection, asset: Uuid, config: &serde_json::Value) {
    use vauban_web::schema::assets;
    diesel::update(assets::table.filter(assets::uuid.eq(asset)))
        .set(assets::connection_config.eq(config))
        .execute(conn)
        .await
        .expect("update asset");
}

async fn new_asset(app: &TestApp, conn: &mut AsyncPgConnection) -> Uuid {
    let admin = create_admin_user(conn, &app.auth_service, &unique_name("flag_adm")).await;
    let id = create_simple_ssh_asset(conn, "test-trust-flag", admin.user.id).await;
    get_asset_uuid(conn, id).await
}

#[tokio::test]
#[serial]
async fn test_raising_a_flag_keeps_every_other_key() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let asset = new_asset(app, &mut conn).await;
    let before = serde_json::json!({
        "ssh_host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPinned",
        "ssh_host_key_fingerprint": "SHA256:pinned",
        "nested": {"a": [1, 2, 3]},
    });
    store_config(&mut conn, asset, &before).await;

    for flag in TrustAnchorFlag::ALL {
        let rows = raise_trust_anchor_flag(&mut conn, asset, flag)
            .await
            .expect("raise flag");
        assert_eq!(rows, 1);
    }

    let mut expected = before.clone();
    expected["ssh_host_key_mismatch"] = serde_json::Value::Bool(true);
    expected["rdp_server_cert_mismatch"] = serde_json::Value::Bool(true);
    assert_eq!(stored_config(&mut conn, asset).await, expected);

    // Raising it again changes nothing.
    raise_trust_anchor_flag(&mut conn, asset, TrustAnchorFlag::SshHostKeyMismatch)
        .await
        .expect("raise flag again");
    assert_eq!(stored_config(&mut conn, asset).await, expected);
}

/// The lost update: a handler reads the configuration, a pin is stored
/// while it talks to the target, and the handler then raises the flag.
/// The pin must survive.
#[tokio::test]
#[serial]
async fn attack_flag_raised_from_a_stale_copy_does_not_undo_a_new_pin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let asset = new_asset(app, &mut conn).await;
    store_config(
        &mut conn,
        asset,
        &serde_json::json!({"ssh_host_key": "old-key"}),
    )
    .await;

    // The handler's copy, taken before its network round trip.
    let stale = stored_config(&mut conn, asset).await;
    assert_eq!(stale["ssh_host_key"], "old-key");

    // Meanwhile an administrator pins a new key.
    store_config(
        &mut conn,
        asset,
        &serde_json::json!({"ssh_host_key": "new-key", "ssh_host_key_fingerprint": "SHA256:new"}),
    )
    .await;

    raise_trust_anchor_flag(&mut conn, asset, TrustAnchorFlag::SshHostKeyMismatch)
        .await
        .expect("raise flag");

    let stored = stored_config(&mut conn, asset).await;
    assert_eq!(stored["ssh_host_key"], "new-key", "the new pin survives");
    assert_eq!(stored["ssh_host_key_fingerprint"], "SHA256:new");
    assert_eq!(stored["ssh_host_key_mismatch"], true);
}

/// `jsonb_set` fails on a document that is not an object; the flag
/// must still be raised.
#[tokio::test]
#[serial]
async fn test_raising_a_flag_on_a_document_that_is_not_an_object() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let asset = new_asset(app, &mut conn).await;
    for document in [
        serde_json::Value::Null,
        serde_json::json!("text"),
        serde_json::json!([1]),
    ] {
        store_config(&mut conn, asset, &document).await;
        let rows = raise_trust_anchor_flag(&mut conn, asset, TrustAnchorFlag::SshHostKeyMismatch)
            .await
            .expect("raise flag");
        assert_eq!(rows, 1, "{document}");
        assert_eq!(
            stored_config(&mut conn, asset).await,
            serde_json::json!({"ssh_host_key_mismatch": true}),
            "{document}"
        );
    }
}

#[tokio::test]
#[serial]
async fn test_raising_a_flag_on_an_unknown_asset_changes_no_row() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let rows = raise_trust_anchor_flag(
        &mut conn,
        Uuid::new_v4(),
        TrustAnchorFlag::RdpServerCertMismatch,
    )
    .await
    .expect("statement runs");
    assert_eq!(rows, 0);
}

/// No handler writes a mismatch flag by rewriting the whole document.
#[test]
fn test_no_handler_sets_a_mismatch_flag_in_memory() {
    for (file, source) in [
        ("ssh.rs", include_str!("../../src/handlers/web/ssh.rs")),
        ("rdp.rs", include_str!("../../src/handlers/web/rdp.rs")),
    ] {
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        for flag in TrustAnchorFlag::ALL {
            let assignment = format!("[\"{}\"] = ", flag.key());
            assert!(
                !production.contains(&assignment),
                "{file} assigns {} in memory; use raise_trust_anchor_flag",
                flag.key()
            );
        }
        assert!(
            production.contains("raise_trust_anchor_flag"),
            "{file} raises its flag through raise_trust_anchor_flag"
        );
    }
}
