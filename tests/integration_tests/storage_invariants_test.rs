//! Source-shape invariants for the storage helper (architecture 1.2).

use std::process::Command;

#[test]
fn inv_check_storage_script() {
    let output = Command::new("bash")
        .arg("scripts/check_storage.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_storage.sh");
    assert!(
        output.status.success(),
        "scripts/check_storage.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_release_model_has_no_digest_columns() {
    let models = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/models/mod.rs"));
    let release = models
        .split("pub struct Release")
        .nth(1)
        .and_then(|s| s.split("pub struct ").next())
        .expect("Release struct");
    assert!(
        !release.contains("pub sha256"),
        "Release must not expose sha256 (digests live in helper SQLite + Postgres mirror)"
    );
    assert!(
        !release.contains("pub size_mb"),
        "Release must not expose size_mb (digests live in helper SQLite + Postgres mirror)"
    );
    assert!(models.contains("struct StorageObject"));
    assert!(models.contains("mirror") || models.contains("SoT"));
    assert!(models.contains("STORAGE_SCOPE_RELEASE"));
    assert!(models.contains("STORAGE_SCOPE_IMAGE"));
}

#[test]
fn inv_meta_sqlite_sot_and_verify_on_read() {
    let meta = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/storage/meta_db.rs"
    ));
    assert!(meta.contains("meta.sqlite"));
    assert!(meta.contains("CREATE TABLE IF NOT EXISTS objects"));

    let engine = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/storage/engine.rs"
    ));
    assert!(engine.contains("get_verified"));
    assert!(engine.contains("IntegrityMismatch"));
    assert!(engine.contains("MetaDb"));

    let proto = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/storage/protocol.rs"
    ));
    let get = proto.split("Get {").nth(1).expect("Get variant");
    assert!(
        get.contains("sha256: String"),
        "IPC Get must require expected sha256"
    );

    let dl = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/builds/download.rs"
    ));
    assert!(dl.contains("INTEGRITY_MISMATCH") || dl.contains("integrity mismatch"));
    assert!(dl.contains("obj.sha256"));
}

#[test]
fn inv_download_uses_storage_objects_not_501() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/builds/download.rs"
    ));
    assert!(src.contains("find_release_object"));
    assert!(src.contains("DOWNLOAD_UNAVAILABLE"));
    assert!(src.contains("get_release"));
    assert!(src.contains("X-Content-Type-Options"));
    assert!(!src.contains("NOT_IMPLEMENTED"));
    assert!(!src.contains("download not configured"));
}

#[test]
fn inv_image_routes_gate_before_ipc() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/images.rs"
    ));
    assert!(src.contains("find_image_object"));
    assert!(src.contains("require_org"));
    assert!(
        src.contains("authorize_image_org_id")
            && src.contains("admin_view")
            && src.contains("perms_for_user")
            && !src.contains("require_staff"),
        "GET cross-tenant read must use Casbin admin_view+issues_*, not require_staff"
    );
    assert!(src.contains("X-Content-Type-Options"));
    assert!(src.contains("normalize_image_ext"));
    assert!(src.contains("is_uuid_key"));
    // Lookup must precede get_image in source order.
    let find = src.find("find_image_object").expect("find_image_object");
    let get = src.find("get_image").expect("get_image");
    assert!(find < get, "DB lookup must happen before IPC get_image");
}

#[test]
fn inv_vcp_store_pins_peercred_and_capsicum() {
    let bin = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin/vcp_store.rs"));
    assert!(bin.contains("peer_uid"));
    assert!(bin.contains("peercred failed") || bin.contains("reject peer uid"));
    assert!(bin.contains("enter_capability_mode"));

    // Capsicum: path-based connect/bind must precede cap_enter (os error 94).
    let connect = bin
        .find("connect parent")
        .expect("spawn connect parent error label");
    let bind = bin.find("bind_socket").expect("bind_socket");
    let enter_spawn_branch = bin[connect..]
        .find("enter_capability_mode")
        .expect("enter_capability_mode after spawn connect")
        + connect;
    let enter_bind_branch = bin[bind..]
        .find("enter_capability_mode")
        .expect("enter_capability_mode after bind")
        + bind;
    assert!(
        connect < enter_spawn_branch,
        "UnixStream::connect must happen before enter_capability_mode in spawn mode"
    );
    assert!(
        bind < enter_bind_branch,
        "bind_socket must happen before enter_capability_mode in socket mode"
    );

    let cap = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/storage/capsicum.rs"
    ));
    assert!(
        cap.contains("capsicum::enter"),
        "FreeBSD path must call capsicum::enter (cap_enter(2))"
    );
    assert!(cap.contains("cap_enter"));
    assert!(cap.contains("enter_capability_mode"));
    assert!(
        !cap.contains("allow(unsafe_code)"),
        "Capsicum FFI must live in the capsicum crate, not this module"
    );

    let ipc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/storage/ipc.rs"));
    assert!(ipc.contains("fn peer_uid"));
    assert!(
        ipc.contains("unix_ancillary") || ipc.contains("unix-ancillary"),
        "SCM_RIGHTS must use unix-ancillary OwnedFd API"
    );
    assert!(
        ipc.contains("getpeereid") || ipc.contains("PeerCredentials"),
        "peer_uid must use nix peer-cred APIs"
    );
    assert!(
        !ipc.contains("allow(unsafe_code)"),
        "IPC FFI must live in nix / unix-ancillary, not this module"
    );
}

#[test]
fn inv_production_conf_is_socket_mode() {
    let conf = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/config/vcp.conf"));
    assert!(conf.contains("ipc = \"socket\""));
    assert!(conf.contains("socket_path = \"/var/run/vcp/store.sock\""));
    assert!(
        !conf
            .lines()
            .any(|l| l.trim_start().starts_with("blob_path")),
        "vcp.conf must not set blob_path (helper conf owns it)"
    );

    let store = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/config/vcp-store.conf"
    ));
    assert!(store.contains("blob_path = \"/var/db/vcp/storage\""));
    assert!(store.contains("listen = \"/var/run/vcp/store.sock\""));
}

#[test]
fn inv_webauthn_12_and_adrs_pinned() {
    let store = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/config/vcp-store.conf"
    ));
    assert!(store.contains("webauthn_required = true"));
    assert!(store.contains("webauthn_strict_sign_count = false"));
    assert!(store.contains("webauthn_user_verification = \"required\""));
    assert!(
        store.contains("webauthn_pending_ttl_hours = 24"),
        "helper conf must expire stale PENDING enrolments"
    );

    let def = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/config/default.toml"));
    let development = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/config/development.toml"
    ));
    assert!(
        def.contains("webauthn_pending_ttl_hours = 24"),
        "portal default.toml must carry pending TTL for spawn/dev"
    );
    assert!(
        development.contains("webauthn_pending_ttl_hours = 24"),
        "development.toml must carry pending TTL (vcp-store.conf unused in spawn)"
    );

    let err = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/storage/error.rs"));
    for code in [
        "webauthn_required",
        "webauthn_invalid",
        "webauthn_expired",
        "challenge_unknown",
        "object_modified",
    ] {
        assert!(err.contains(code), "missing {code}");
    }

    let bin = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin/vcp_store.rs"));
    assert!(bin.contains("pending-ops"));
    assert!(bin.contains("list-keys"));
    assert!(bin.contains("approve-key"));
    assert!(bin.contains("Pending credentials"));
    assert!(!bin.contains("PENDING credentials"));
    assert!(!bin.contains("println!(\"binding"));
    assert!(bin.contains("wants_help"));
    assert!(bin.contains("cli_usage"));
    assert!(bin.contains("Usage:"));
    assert!(bin.contains("Commands:"));
    assert!(bin.contains("Options:"));
    assert!(bin.contains("-h, --help"));
    assert!(bin.contains("-V, --version"));
    assert!(bin.contains("wants_version"));
    assert!(bin.contains("HelpStyle"));
    // Old lowercase / footer forms must not remain in usage string literals.
    assert!(!bin.contains("\"usage: vcp-store"));
    assert!(!bin.contains("Help: -h, --help, help"));
    assert!(bin.contains("load_key_cfg_with_env"));
    assert!(bin.contains("VCP_ENVIRONMENT"));
    assert!(
        !bin.contains("Development (spawn)")
            && !bin.contains("VCP_ENVIRONMENT=development")
            && !bin.contains("./target/debug/vcp-store"),
        "ops CLI usage/hints must not advertise development recipes"
    );
    assert!(bin.contains("validate_production_webauthn"));
    assert!(bin.contains("format_ascii_table"));
    assert!(
        bin.contains("STORE_LOG_TARGET"),
        "helper binary logs must use vcp-store target constant"
    );
    assert!(
        !bin.contains("vcp_storage_alert"),
        "forbidden ambiguous tracing target"
    );

    let store_mod = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/storage/mod.rs"));
    assert!(store_mod.contains("STORE_ALERT_TARGET"));
    assert!(store_mod.contains("\"vcp-store::alert\""));
    assert!(store_mod.contains("\"vcp-store\""));

    let webauthn = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/storage/webauthn.rs"
    ));
    assert!(webauthn.contains("canonical_summary"));
    assert!(webauthn.contains("webauthn_host_is_ip"));
    assert!(webauthn.contains("rp_id_from_webauthn_origin"));
    assert!(webauthn.contains("test_attestation_object_b64"));
    assert!(
        !webauthn.contains("sha256={short}") && !webauthn.contains("&s[..12]"),
        "C1 summaries must carry the full digest for operator comparison"
    );

    // The confirm panels must show that digest whole (wrap, never clip).
    for src in [
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/app/admin/releases/confirm.rs"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/app/admin/releases/delete_confirm.rs"
        )),
    ] {
        assert!(
            src.contains("vcp-webauthn-summary"),
            "ceremony page must render the helper summary"
        );
        assert!(
            src.contains("white-space: pre-wrap") && src.contains("overflow-wrap: anywhere"),
            "summary must wrap instead of clipping the 64-hex digest"
        );
    }

    let client = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/storage/client.rs"
    ));
    assert!(
        client.contains("webauthn-origin"),
        "spawn must pass portal webauthn_origin to the helper"
    );

    let dev = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/config/development.toml"
    ));
    assert!(
        dev.contains("webauthn_origin = \"https://localhost:3000\""),
        "dev webauthn_origin must use localhost (RP ID derived; not an IP)"
    );
    assert!(
        !dev.lines()
            .any(|l| l.trim_start().starts_with("webauthn_rp_id")),
        "webauthn_rp_id must not be a config key (derived from origin)"
    );

    let portal_prod = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/config/vcp.conf"));
    let store_prod = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/config/vcp-store.conf"
    ));
    assert!(
        portal_prod.contains("webauthn_origin = \"https://access.vauban.sh\""),
        "packaged vcp.conf [storage] must set webauthn_origin for /admin/key RP ID"
    );
    assert!(
        store_prod.contains("webauthn_origin = \"https://access.vauban.sh\""),
        "packaged vcp-store.conf must set the same webauthn_origin"
    );
    let portal_origin = portal_prod
        .lines()
        .find(|l| l.trim_start().starts_with("webauthn_origin"))
        .expect("portal webauthn_origin");
    let store_origin = store_prod
        .lines()
        .find(|l| l.trim_start().starts_with("webauthn_origin"))
        .expect("store webauthn_origin");
    assert_eq!(
        portal_origin.trim(),
        store_origin.trim(),
        "packaged portal and helper webauthn_origin defaults must match"
    );

    assert!(
        std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/adr/002-storage-webauthn-ceremony-channel-c1.md"
        ))
        .is_file()
    );
    assert!(
        std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/adr/003-ctap2-enrol-revoke-asymmetry.md"
        ))
        .is_file()
    );
    assert!(
        std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/adr/004-webauthn-sign-count-policy.md"
        ))
        .is_file()
    );
    assert!(
        std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/technical/VCP_Storage_Helper_Architecture_EN(1.2).md"
        ))
        .is_file()
    );

    let confirm = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/releases/confirm.rs"
    ));
    assert!(confirm.contains("vcp-webauthn-summary"));
    assert!(confirm.contains("vcp-store pending-ops"));
}

/// §6.5 / ADR 003 dashboard contract: fingerprint at E1, CLI approve
/// instructions, pending cross-check hint, Casbin gate, typed revoke confirm.
#[test]
fn inv_key_dashboard_ui_pinned() {
    let page = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/admin/key.rs"));
    assert!(page.contains("perms.key_manage"), "Casbin gate");
    assert!(page.contains("vcp-key-fingerprint"), "E1 fingerprint block");
    assert!(
        page.contains("activate it from the server with"),
        "compact E1/E2 callout"
    );
    assert!(
        page.contains("vcp-store approve-key"),
        "CLI approve chip in callout"
    );
    assert!(
        page.contains("approve-key --fingerprint"),
        "pending-table copy still exposes full approve CLI"
    );
    assert!(
        !page.contains("VCP_ENVIRONMENT=development"),
        "approve copy must not prefix VCP_ENVIRONMENT / target/debug"
    );
    assert!(
        !page.contains("target/debug/vcp-store"),
        "approve copy must be bare vcp-store approve-key"
    );
    assert!(page.contains("\"Create key\""), "enrol CTA label");
    assert!(
        !page.contains("Create passkey (PENDING)"),
        "enrol CTA must not say Create passkey (PENDING)"
    );
    assert!(
        !page.contains("Per-admin KEY"),
        "page lead must stay removed"
    );
    assert!(
        !page.contains("blob_path/audit/webauthn.log"),
        "audit-log footer must stay removed from dashboard copy"
    );
    assert!(
        page.contains("!= \"revoke\""),
        "typed confirmation gates key_revoke"
    );
    assert!(page.contains("data-mode=\"create\""), "E1 ceremony root");
    assert!(
        page.contains("err=label"),
        "empty admin_label must redirect with err=label"
    );
    assert!(
        page.contains("normalize_admin_label"),
        "portal enrol must share helper label normalization"
    );
    assert!(
        page.contains("KEY_PAGE_SIZE") && page.contains("pending_page"),
        "KEY lists must paginate with KEY_PAGE_SIZE + pending_page"
    );
    assert!(
        page.contains("active_page") && page.contains("list_toolbar"),
        "ACTIVE list must paginate independently with list_toolbar"
    );
    assert!(
        page.contains("key_list_page"),
        "dashboard must use paginated key_list_page (not full dump)"
    );
    assert!(
        page.contains("vb-table-key") && page.contains("vb-key-c-key"),
        "PENDING/ACTIVE must share identical colgroup grid"
    );
    let styles = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/styles.css"));
    assert!(
        styles.contains("col.vb-key-c-key") && styles.contains("table-layout: fixed"),
        "styles.css must pin KEY colgroup widths"
    );
    assert!(
        !page.contains("key_list(\""),
        "dashboard must not call unpaginated key_list"
    );

    let list_page = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/list_page.rs"));
    assert!(
        list_page.contains("KEY_PAGE_SIZE: usize = 4"),
        "KEY_PAGE_SIZE must be 4"
    );

    let meta = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/storage/meta_db.rs"
    ));
    assert!(
        meta.contains("LIMIT ?1 OFFSET ?2")
            && meta.contains("list_pending_credentials_page")
            && meta.contains("count_pending_credentials"),
        "KEY paging must be SQL LIMIT/OFFSET + COUNT"
    );

    let rail = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/_components/rail.rs"
    ));
    assert!(
        rail.contains("ico_key(cx"),
        "rail must use the dedicated key icon for /admin/key"
    );

    let js = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/vcp_webauthn.js"
    ));
    assert!(
        js.contains("cannot run on an IP address"),
        "ceremony JS must reject IP hosts before navigator.credentials"
    );
    assert!(
        js.contains("Key label is required"),
        "create ceremony must refuse empty admin_label before credentials.create"
    );
    assert!(
        js.contains("function isIpHostname"),
        "ceremony JS must keep the IP-host gate"
    );
}

#[test]
fn inv_normalize_image_ext_and_uuid_exported() {
    assert_eq!(vcp::storage::normalize_image_ext("JPG"), Some("jpeg"));
    assert_eq!(vcp::storage::normalize_image_ext("png"), Some("png"));
    assert_eq!(vcp::storage::normalize_image_ext("webp"), Some("webp"));
    assert_eq!(vcp::storage::normalize_image_ext("svg"), None);
    assert!(vcp::storage::is_uuid_key(
        "550e8400-e29b-41d4-a716-446655440000"
    ));
    assert!(!vcp::storage::is_uuid_key("../x"));
}

#[test]
fn inv_storage_ops_logging_not_silent() {
    let log = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/storage/log.rs"));
    assert!(log.contains("STORE_LOG_TARGET"));
    assert!(log.contains("fd_handoff_failed"));
    assert!(log.contains("op_failed"));
    assert!(log.contains("portal_storage_failed"));
    assert!(
        !log.contains("vcp_storage_alert") && !log.contains("target: \"vcp_store\""),
        "forbidden ambiguous tracing targets in storage log helpers"
    );

    let server = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/storage/server.rs"
    ));
    assert!(server.contains("open_partial_for_handoff"));
    assert!(server.contains("open_object_for_handoff"));
    assert!(server.contains("reply_engine_err") || server.contains("op_failed"));
    assert!(
        !server.contains(".map_err(|_| ())?"),
        "server must not swallow FD/open errors as silent ()"
    );
    assert!(
        !server.contains("File::open(") && !server.contains("File::options("),
        "server must not absolute-open for SCM_RIGHTS (dirfd handoff only)"
    );
    assert!(
        !server.contains("open_abs_for_handoff"),
        "open_abs_for_handoff must be gone"
    );

    let engine = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/storage/engine.rs"
    ));
    assert!(engine.contains("open_partial_for_handoff"));
    assert!(engine.contains("open_object_for_handoff"));
    assert!(engine.contains("into_std"));
    // rustfmt may split `entry.metadata()` across lines — pin the dirfd call.
    assert!(
        engine.contains(".metadata()") && engine.contains("DirEntry metadata"),
        "purge must use DirEntry dirfd metadata, not absolute std::fs::metadata"
    );
    assert!(
        !engine.contains("std::fs::metadata("),
        "purge must not call absolute std::fs::metadata"
    );

    let audit = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/storage/audit.rs"));
    assert!(
        audit.contains("Mutex<File>") || audit.contains("file: Mutex"),
        "audit must hold an open FD across Capsicum enter"
    );

    let client = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/storage/client.rs"
    ));
    assert!(client.contains("ipc_denied"));
    assert!(client.contains("portal_storage_failed"));
    assert!(client.contains("open_partial_for_handoff"));
    assert!(client.contains("open_object_for_handoff"));

    let key = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/admin/key.rs"));
    assert!(key.contains("portal_storage_failed"));
    assert!(key.contains("admin_key_enrol"));

    let admin_issue = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/issues/issue_key.rs"
    ));
    let org_issue = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues/issue_key.rs"
    ));
    let org_new = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues.rs"
    ));
    assert!(admin_issue.contains("portal_attach_failed"));
    assert!(org_issue.contains("portal_attach_failed"));
    assert!(org_new.contains("portal_attach_failed"));
}
