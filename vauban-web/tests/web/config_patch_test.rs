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
    ConfigPatch, ConfigUpdate, TrustAnchorFlag, patch_connection_config,
    raise_trust_anchor_flag_for_pin, update_connection_config_with,
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

/// A check ran against pin A and found a mismatch. Meanwhile an
/// administrator pinned the new identity B. Raising the flag now would
/// block an asset that was just repaired.
#[tokio::test]
#[serial]
async fn attack_mismatch_found_against_a_replaced_pin_does_not_block_the_asset() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let (asset, _) = new_asset(app, &mut conn).await;
    for (flag, pin_key) in [
        (TrustAnchorFlag::SshHostKeyMismatch, "ssh_host_key"),
        (
            TrustAnchorFlag::RdpServerCertMismatch,
            "rdp_server_cert_spki",
        ),
    ] {
        assert_eq!(flag.pin_key(), pin_key);
        store(&mut conn, asset, &json!({pin_key: "pin-a"})).await;
        // The document the check ran against.
        let seen = row(&mut conn, asset).await.config;
        assert_eq!(flag.pin_in(&seen), Some("pin-a"));

        // Meanwhile the administrator pins the new identity.
        store(&mut conn, asset, &json!({pin_key: "pin-b"})).await;

        let rows = raise_trust_anchor_flag_for_pin(&mut conn, asset, flag, flag.pin_in(&seen))
            .await
            .expect("statement runs");
        assert_eq!(
            rows, 0,
            "{flag:?}: the mismatch was about a pin that is gone"
        );
        assert_eq!(
            row(&mut conn, asset).await.config,
            json!({pin_key: "pin-b"})
        );

        // Against the current pin, the flag is raised.
        let current = row(&mut conn, asset).await.config;
        let rows = raise_trust_anchor_flag_for_pin(&mut conn, asset, flag, flag.pin_in(&current))
            .await
            .expect("statement runs");
        assert_eq!(rows, 1, "{flag:?}");
        assert_eq!(row(&mut conn, asset).await.config[flag.key()], true);
    }
}

/// Every handler that raises a flag says which document its check ran
/// against.
#[test]
fn test_flags_are_raised_for_the_pin_the_check_ran_against() {
    for (file, source, helper) in [
        (
            "web/ssh.rs",
            include_str!("../../src/handlers/web/ssh.rs"),
            "flag_ssh_host_key_mismatch(",
        ),
        (
            "web/rdp.rs",
            include_str!("../../src/handlers/web/rdp.rs"),
            "flag_rdp_cert_mismatch(",
        ),
    ] {
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            production.contains("raise_trust_anchor_flag_for_pin("),
            "{file}: the flag helper must be conditional on the pin"
        );
        assert!(
            !production.contains(" raise_trust_anchor_flag(conn"),
            "{file}: no unconditional flag"
        );
        let calls: Vec<&str> = production
            .match_indices(helper)
            .map(|(at, _)| &production[at..(at + 120).min(production.len())])
            .filter(|call| !call.contains("conn: &mut"))
            .collect();
        assert!(calls.len() >= 2, "{file}: {} call(s)", calls.len());
        for call in calls {
            assert!(
                call.contains("&asset.connection_config") || call.contains("&config)"),
                "{file}: a flag is raised without the document the check ran against: {call}"
            );
        }
    }
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

/// The edit form. It reads the asset, encrypts credentials through the
/// vault, and writes. A flag raised in between must survive, and what
/// the form changed must be applied.
#[tokio::test]
#[serial]
async fn attack_edit_computed_from_a_stale_copy_keeps_what_was_stored_meanwhile() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let (asset, _) = new_asset(app, &mut conn).await;
    store(
        &mut conn,
        asset,
        &json!({"username": "root", "rdp_auth_mode": "ntlm", "domain": "old.example"}),
    )
    .await;

    // The form's copy, and the document it computes from it: the mode
    // changes, the domain is cleared, the username is left alone.
    let read = row(&mut conn, asset).await.config;
    let computed = json!({"username": "root", "rdp_auth_mode": "kerberos"});

    // Meanwhile: a failed connection raises the flag, a pin is stored.
    store(
        &mut conn,
        asset,
        &json!({
            "username": "root",
            "rdp_auth_mode": "ntlm",
            "domain": "old.example",
            "rdp_server_cert_mismatch": true,
            "rdp_server_cert_spki": "pinned-meanwhile",
        }),
    )
    .await;

    let change = ConfigPatch::between(&read, &computed);
    let rows = patch_connection_config(&mut conn, asset, &change)
        .await
        .expect("patch");
    assert_eq!(rows, 1);

    assert_eq!(
        row(&mut conn, asset).await.config,
        json!({
            "username": "root",
            "rdp_auth_mode": "kerberos",
            "rdp_server_cert_mismatch": true,
            "rdp_server_cert_spki": "pinned-meanwhile",
        })
    );
}

/// An edit that changes nothing writes nothing over a concurrent change
/// of the same key.
#[tokio::test]
#[serial]
async fn test_edit_that_leaves_a_key_alone_does_not_write_it() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let (asset, _) = new_asset(app, &mut conn).await;
    store(
        &mut conn,
        asset,
        &json!({"ssh_host_key": "k1", "port_hint": 22}),
    )
    .await;
    let read = row(&mut conn, asset).await.config;

    store(
        &mut conn,
        asset,
        &json!({"ssh_host_key": "k2", "port_hint": 22}),
    )
    .await;

    let mut computed = read.clone();
    computed["port_hint"] = json!(2222);
    let change = ConfigPatch::between(&read, &computed);
    patch_connection_config(&mut conn, asset, &change)
        .await
        .expect("patch");

    assert_eq!(
        row(&mut conn, asset).await.config,
        json!({"ssh_host_key": "k2", "port_hint": 2222})
    );
}

/// An edit is written only over the row it read. The filter of the two
/// edit handlers, against a pin stored meanwhile (it stamps
/// `updated_at`) and against a flag raised meanwhile (it does not).
#[tokio::test]
#[serial]
async fn attack_edit_is_not_written_over_a_row_changed_since_it_was_read() {
    use vauban_web::schema::assets;
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let (asset, admin) = new_asset(app, &mut conn).await;
    store(&mut conn, asset, &json!({"rdp_auth_mode": "ntlm"})).await;

    let edit = |read_at: DateTime<Utc>| {
        diesel::update(
            assets::table
                .filter(assets::uuid.eq(asset))
                .filter(assets::updated_at.eq(read_at)),
        )
        .set((assets::port.eq(2222), assets::updated_at.eq(Utc::now())))
    };

    // A failed connection raises the flag between the read and the
    // write: the edit still goes through.
    let read = row(&mut conn, asset).await;
    let raised = raise_trust_anchor_flag_for_pin(
        &mut conn,
        asset,
        TrustAnchorFlag::RdpServerCertMismatch,
        None,
    )
    .await
    .expect("flag");
    assert_eq!(raised, 1);
    let rows = edit(read.updated_at)
        .execute(&mut conn)
        .await
        .expect("edit");
    assert_eq!(rows, 1, "a flag raised meanwhile does not refuse an edit");

    // A pin is stored between the read and the write: the edit was
    // validated against a row that is no longer the stored one.
    let read = row(&mut conn, asset).await;
    let pin = ConfigPatch::new()
        .set("rdp_server_cert_spki", "pinned-meanwhile")
        .stamped_by(Some(admin));
    assert_eq!(
        patch_connection_config(&mut conn, asset, &pin)
            .await
            .expect("pin"),
        1
    );
    let rows = edit(read.updated_at)
        .execute(&mut conn)
        .await
        .expect("edit");
    assert_eq!(rows, 0, "the row changed since it was read");

    // Read again, it is written.
    let read = row(&mut conn, asset).await;
    let rows = edit(read.updated_at)
        .execute(&mut conn)
        .await
        .expect("edit");
    assert_eq!(rows, 1);
}

/// Both edit handlers carry that filter and answer an unwritten edit
/// with the constant sentence.
#[test]
fn test_edit_handlers_write_only_over_the_row_they_read() {
    for (file, source, filter) in [
        (
            "web/manage_assets.rs",
            include_str!("../../src/handlers/web/manage_assets.rs"),
            ".filter(a::updated_at.eq(existing.updated_at))",
        ),
        (
            "api/manage_assets.rs",
            include_str!("../../src/handlers/api/manage_assets.rs"),
            ".filter(updated_at.eq(existing.updated_at))",
        ),
    ] {
        assert_eq!(source.matches(filter).count(), 1, "{file}: {filter}");
        assert!(
            source.contains("crate::models::asset::ASSET_CHANGED_MESSAGE"),
            "{file}: an edit that was not written says so"
        );
    }
}

/// No handler and no IPC command writes the whole document of an
/// existing asset. Same rule as `scripts/check_connection_config_writes.sh`.
#[test]
fn test_handlers_do_not_write_the_whole_document() {
    let whole_document_writes = |source: &str| -> Vec<String> {
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let mut statement = "";
        // The statement compares the column with the document it read:
        // a compare-and-swap, not a write from a stale copy.
        let mut compared = false;
        let mut found = Vec::new();
        for line in production.lines() {
            if line.contains("diesel::insert_into(") {
                statement = "insert";
            }
            if line.contains("diesel::update(") {
                statement = "update";
                compared = false;
            }
            let argument = ["connection_config.eq(", "config_col.eq("]
                .iter()
                .find_map(|needle| line.split_once(needle).map(|(_, rest)| rest));
            let Some(argument) = argument else { continue };
            if line.contains(".filter(") {
                compared = true;
                continue;
            }
            if statement == "insert" || compared {
                continue;
            }
            let through_a_patch = argument.starts_with("crate::models::asset::ConfigPatch")
                || argument.contains(".expression()")
                || argument.starts_with("serde_json::json!({})");
            if !through_a_patch {
                found.push(line.trim().to_string());
            }
        }
        found
    };

    // Every source file of vauban-web except the model that implements
    // the three ways to write, and the supervisor's migration command.
    fn rust_files(dir: &std::path::Path, into: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("source directory").flatten() {
            let path = entry.path();
            if path.is_dir() {
                rust_files(&path, into);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                into.push(path);
            }
        }
    }
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&crate_dir.join("src"), &mut files);
    files.retain(|path| !path.ends_with("models/asset.rs"));
    files.push(crate_dir.join("../vauban-supervisor/src/admin.rs"));
    assert!(
        files.len() > 50,
        "the walk found the sources: {}",
        files.len()
    );

    let mut writers = 0;
    for file in &files {
        let source = std::fs::read_to_string(file).expect("source file");
        if source.contains("connection_config.eq(") || source.contains("config_col.eq(") {
            writers += 1;
        }
        assert_eq!(
            whole_document_writes(&source),
            Vec::<String>::new(),
            "{}: write named keys with patch_connection_config, the change of an edit \
             with ConfigPatch::between, merge with update_connection_config_with, or \
             compare the column with the document that was read",
            file.display()
        );
    }
    assert!(writers >= 4, "the rule looked at the writers: {writers}");

    // The rule sees a whole-document write when there is one.
    assert_eq!(
        whole_document_writes("diesel::update(t)\n    .set(dsl::connection_config.eq(&config))\n")
            .len(),
        1
    );
    // A compare-and-swap is not one; the next statement starts afresh.
    let swap = "diesel::update(\n    t.filter(dsl::connection_config.eq(&read)),\n)\n\
                .set(dsl::connection_config.eq(&next))\n";
    assert_eq!(whole_document_writes(swap).len(), 0);
    let then_whole = format!("{swap}diesel::update(t)\n.set(dsl::connection_config.eq(&config))\n");
    assert_eq!(whole_document_writes(&then_whole).len(), 1);
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
