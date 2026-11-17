//! `connection_config` is changed key by key, never from a stale copy.
//!
//! Seven handlers read an asset, talked to the target or to an upstream
//! server, and wrote the whole document back from their copy: the two
//! pin routes of the web zone, the two of the API, the public-key push,
//! and the two MCP catalogue routes. Whatever had been stored in between
//! was lost, a pin included.
//!
//! `patch_connection_config` changes named keys in one statement and can
//! be made conditional on the pin that was read.
//! `update_connection_config_with` recomputes a document that depends on
//! the current one until it is written over the document it was computed
//! from.

use crate::common::TestApp;
use crate::fixtures::{create_admin_user, create_simple_ssh_asset, get_asset_uuid, unique_name};
use chrono::{DateTime, Utc};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};
use serial_test::serial;
use uuid::Uuid;
use vauban_web::models::asset::{
    ConfigPatch, ConfigUpdate, patch_connection_config, update_connection_config_with,
};

struct Row {
    id: i32,
    config: Value,
    updated_at: DateTime<Utc>,
    updated_by_id: Option<i32>,
}

async fn row(conn: &mut AsyncPgConnection, asset: Uuid) -> Row {
    use vauban_web::schema::assets;
    let (id, config, updated_at, updated_by_id) = assets::table
        .filter(assets::uuid.eq(asset))
        .select((
            assets::id,
            assets::connection_config,
            assets::updated_at,
            assets::updated_by_id,
        ))
        .first(conn)
        .await
        .expect("asset row");
    Row {
        id,
        config,
        updated_at,
        updated_by_id,
    }
}

async fn store(conn: &mut AsyncPgConnection, asset: Uuid, config: &Value) {
    use vauban_web::schema::assets;
    diesel::update(assets::table.filter(assets::uuid.eq(asset)))
        .set(assets::connection_config.eq(config))
        .execute(conn)
        .await
        .expect("update asset");
}

/// `(asset uuid, id of the administrator who created it)`.
async fn new_asset(app: &TestApp, conn: &mut AsyncPgConnection) -> (Uuid, i32) {
    let admin = create_admin_user(conn, &app.auth_service, &unique_name("cfg_patch_adm")).await;
    let id = create_simple_ssh_asset(conn, "test-config-patch", admin.user.id).await;
    (get_asset_uuid(conn, id).await, admin.user.id)
}

#[tokio::test]
#[serial]
async fn test_patch_changes_the_named_keys_and_no_other() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let (asset, _) = new_asset(app, &mut conn).await;
    let before = json!({
        "ssh_host_key": "old-key",
        "ssh_host_key_mismatch": true,
        "rdp_auth_mode": "kerberos",
        "nested": {"a": [1, {"b": null}]},
        "password": "v1:ciphertext",
    });
    store(&mut conn, asset, &before).await;

    let patch = ConfigPatch::new()
        .set("ssh_host_key", "new-key")
        .set("ssh_host_key_fingerprint", "SHA256:new")
        .remove("ssh_host_key_mismatch")
        .remove("never_there");
    let rows = patch_connection_config(&mut conn, asset, &patch)
        .await
        .expect("patch");
    assert_eq!(rows, 1);

    assert_eq!(
        row(&mut conn, asset).await.config,
        json!({
            "ssh_host_key": "new-key",
            "ssh_host_key_fingerprint": "SHA256:new",
            "rdp_auth_mode": "kerberos",
            "nested": {"a": [1, {"b": null}]},
            "password": "v1:ciphertext",
        })
    );
}

#[tokio::test]
#[serial]
async fn test_patch_stamps_the_actor_only_when_asked() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let (asset, admin_id) = new_asset(app, &mut conn).await;
    let before = row(&mut conn, asset).await;

    patch_connection_config(&mut conn, asset, &ConfigPatch::new().set("a", 1))
        .await
        .expect("patch");
    let unstamped = row(&mut conn, asset).await;
    assert_eq!(unstamped.updated_at, before.updated_at);
    assert_eq!(unstamped.updated_by_id, before.updated_by_id);

    let patch = ConfigPatch::new().set("b", 2).stamped_by(Some(admin_id));
    patch_connection_config(&mut conn, asset, &patch)
        .await
        .expect("patch");
    let stamped = row(&mut conn, asset).await;
    assert!(stamped.updated_at > before.updated_at);
    assert_eq!(stamped.updated_by_id, Some(admin_id));
    assert_eq!(stamped.config["a"], 1);
    assert_eq!(stamped.config["b"], 2);
}

#[tokio::test]
#[serial]
async fn test_patch_condition_on_the_pin_that_was_read() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let (asset, _) = new_asset(app, &mut conn).await;
    let pin = |key: &str, expected: Option<&'static str>| {
        ConfigPatch::new()
            .set("ssh_host_key", key.to_string())
            .expecting("ssh_host_key", expected)
    };

    // No pin yet, none expected: stored.
    store(&mut conn, asset, &json!({})).await;
    let rows = patch_connection_config(&mut conn, asset, &pin("k1", None)).await;
    assert_eq!(rows.expect("patch"), 1);

    // A pin exists, none expected: refused.
    let rows = patch_connection_config(&mut conn, asset, &pin("k2", None)).await;
    assert_eq!(rows.expect("patch"), 0);
    assert_eq!(row(&mut conn, asset).await.config["ssh_host_key"], "k1");

    // Another pin than the one expected: refused.
    let rows = patch_connection_config(&mut conn, asset, &pin("k2", Some("k0"))).await;
    assert_eq!(rows.expect("patch"), 0);
    assert_eq!(row(&mut conn, asset).await.config["ssh_host_key"], "k1");

    // The expected pin: replaced.
    let rows = patch_connection_config(&mut conn, asset, &pin("k2", Some("k1"))).await;
    assert_eq!(rows.expect("patch"), 1);
    assert_eq!(row(&mut conn, asset).await.config["ssh_host_key"], "k2");

    // A key that holds something else than a string is not "no pin".
    store(&mut conn, asset, &json!({"ssh_host_key": 7})).await;
    let rows = patch_connection_config(&mut conn, asset, &pin("k3", None)).await;
    assert_eq!(rows.expect("patch"), 0, "a number is not 'no pin'");
}

/// The lost pin. A handler reads the asset (no pin), fetches the key of
/// the target; meanwhile an administrator pins another key. The first
/// handler, which decided "first pin, no confirmation needed", must not
/// replace it.
#[tokio::test]
#[serial]
async fn attack_first_pin_decided_on_a_stale_copy_does_not_replace_a_newer_pin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let (asset, _) = new_asset(app, &mut conn).await;
    store(&mut conn, asset, &json!({"rdp_auth_mode": "ntlm"})).await;

    // The handler's copy, taken before its round trip.
    let stale = row(&mut conn, asset).await.config;
    let stale_pin = stale.get("ssh_host_key").and_then(Value::as_str);
    assert_eq!(stale_pin, None);

    // Meanwhile: another pin, and an unrelated edit.
    store(
        &mut conn,
        asset,
        &json!({"ssh_host_key": "pinned-by-someone-else", "rdp_auth_mode": "kerberos"}),
    )
    .await;

    let patch = ConfigPatch::new()
        .set("ssh_host_key", "fetched-by-the-stale-handler")
        .set("ssh_host_key_fingerprint", "SHA256:stale")
        .remove("ssh_host_key_mismatch")
        .expecting("ssh_host_key", stale_pin);
    let rows = patch_connection_config(&mut conn, asset, &patch)
        .await
        .expect("patch");
    assert_eq!(rows, 0, "the decision was made on a pin that is gone");

    assert_eq!(
        row(&mut conn, asset).await.config,
        json!({"ssh_host_key": "pinned-by-someone-else", "rdp_auth_mode": "kerberos"})
    );
}

/// The public-key push sets one flag after a round trip to the target.
/// It used to write back its whole copy.
#[tokio::test]
#[serial]
async fn attack_flag_set_after_a_round_trip_does_not_undo_what_was_stored_meanwhile() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let (asset, _) = new_asset(app, &mut conn).await;
    store(&mut conn, asset, &json!({"ssh_host_key": "old"})).await;

    // Meanwhile: a new pin and a mismatch flag.
    store(
        &mut conn,
        asset,
        &json!({"ssh_host_key": "new", "ssh_host_key_mismatch": true}),
    )
    .await;

    patch_connection_config(
        &mut conn,
        asset,
        &ConfigPatch::new().set("ssh_pubkey_pushed", true),
    )
    .await
    .expect("patch");

    assert_eq!(
        row(&mut conn, asset).await.config,
        json!({"ssh_host_key": "new", "ssh_host_key_mismatch": true, "ssh_pubkey_pushed": true})
    );
}

#[tokio::test]
#[serial]
async fn test_patch_on_a_document_that_is_not_an_object() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let (asset, _) = new_asset(app, &mut conn).await;
    for document in [Value::Null, json!("text"), json!([1])] {
        store(&mut conn, asset, &document).await;
        let patch = ConfigPatch::new().set("k", "v").remove("gone");
        let rows = patch_connection_config(&mut conn, asset, &patch)
            .await
            .expect("patch");
        assert_eq!(rows, 1, "{document}");
        assert_eq!(row(&mut conn, asset).await.config, json!({"k": "v"}));
    }
}

/// A document that depends on the current one is computed from the
/// document as it is when it is written, not from an earlier copy.
#[tokio::test]
#[serial]
async fn attack_merge_computed_from_a_stale_copy_keeps_what_was_stored_meanwhile() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let (asset, _) = new_asset(app, &mut conn).await;
    store(&mut conn, asset, &json!({"tools": ["a"]})).await;
    let asset_id = row(&mut conn, asset).await.id;

    // The handler read `{"tools": ["a"]}` and went to the upstream
    // server. Meanwhile an approval is stored.
    store(
        &mut conn,
        asset,
        &json!({"tools": ["a"], "approved": ["a"]}),
    )
    .await;

    let add_tool = |current: &Value| {
        let mut next = current.clone();
        next["tools"] = json!(["a", "b"]);
        Some(next)
    };
    let outcome = update_connection_config_with(&mut conn, asset_id, add_tool)
        .await
        .expect("update");

    let expected = json!({"tools": ["a", "b"], "approved": ["a"]});
    assert_eq!(outcome, ConfigUpdate::Stored(expected.clone()));
    assert_eq!(row(&mut conn, asset).await.config, expected);
}

#[tokio::test]
#[serial]
async fn test_update_with_nothing_to_change_writes_nothing() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let (asset, _) = new_asset(app, &mut conn).await;
    store(&mut conn, asset, &json!({"k": 1})).await;
    let before = row(&mut conn, asset).await;

    let outcome = update_connection_config_with(&mut conn, before.id, |_| None)
        .await
        .expect("update");
    assert_eq!(outcome, ConfigUpdate::Unchanged);
    assert_eq!(row(&mut conn, asset).await.config, json!({"k": 1}));
}

/// The handlers that write after a round trip no longer write the whole
/// document. `handlers/api/manage_assets.rs` keeps one such write, in
/// the edit handler, which has no round trip.
#[test]
fn test_round_trip_handlers_do_not_write_the_whole_document() {
    let whole_document_writes = |source: &str| {
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        production.matches("connection_config.eq(").count()
            + production.matches("config_col.eq(").count()
    };
    for (file, source, allowed) in [
        (
            "web/ssh.rs",
            include_str!("../../src/handlers/web/ssh.rs"),
            0,
        ),
        (
            "web/rdp.rs",
            include_str!("../../src/handlers/web/rdp.rs"),
            0,
        ),
        (
            "web/mcp_discover.rs",
            include_str!("../../src/handlers/web/mcp_discover.rs"),
            0,
        ),
        (
            "api/manage_assets.rs",
            include_str!("../../src/handlers/api/manage_assets.rs"),
            1,
        ),
    ] {
        assert_eq!(
            whole_document_writes(source),
            allowed,
            "{file}: write named keys with patch_connection_config, or merge with \
             update_connection_config_with"
        );
    }
    // Each pin is conditional on the pin that was read.
    for (file, source, key) in [
        (
            "web/ssh.rs",
            include_str!("../../src/handlers/web/ssh.rs"),
            r#".expecting("ssh_host_key", stored_host_key.as_deref())"#,
        ),
        (
            "web/rdp.rs",
            include_str!("../../src/handlers/web/rdp.rs"),
            r#".expecting("rdp_server_cert_spki", stored_spki.as_deref())"#,
        ),
    ] {
        assert!(source.contains(key), "{file}: the pin must be conditional");
    }
    let api = include_str!("../../src/handlers/api/manage_assets.rs");
    assert!(api.contains(r#".expecting("ssh_host_key", stored_host_key.as_deref())"#));
    assert!(api.contains(r#".expecting("rdp_server_cert_spki", stored_spki.as_deref())"#));
}
