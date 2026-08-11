//! Source-shape invariants for FreeBSD `pkg/` packaging.

use std::process::Command;
use std::sync::{Arc, Barrier};
use std::thread;

#[test]
fn inv_check_freebsd_pkg_script() {
    let output = Command::new("bash")
        .arg("scripts/check_freebsd_pkg.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_freebsd_pkg.sh");
    assert!(
        output.status.success(),
        "scripts/check_freebsd_pkg.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn prop_rc_d_and_newsyslog_required_pins() {
    let vcp = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/pkg/rc.d/vcp"));
    let store = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/pkg/rc.d/vcp_store"));
    let ns = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/pkg/newsyslog.conf.d/vcp.conf"
    ));
    for body in [vcp, store, ns] {
        assert!(
            !body.contains("model.conf"),
            "must not ship Casbin model.conf"
        );
    }
    assert!(vcp.contains("VCP_CONFIG_DIR"));
    assert!(store.contains("VCP_CONFIG_DIR"));
    assert!(vcp.contains("REQUIRE:") && vcp.contains("vcp_store"));
    assert!(ns.contains("/var/log/vcp-access.log"));
    assert!(ns.contains("/var/run/vcp/vcp.pid"));
    // rc.subr turns ${name}_user into "su -m", which breaks daemon(8) -u.
    assert!(
        !vcp.contains("vcp_user") && vcp.contains("vcp_runas"),
        "rc.d/vcp must use vcp_runas, never the rc.subr-owned vcp_user"
    );
    assert!(
        !store.contains("vcp_store_user") && store.contains("vcp_store_runas"),
        "rc.d/vcp_store must use vcp_store_runas, never vcp_store_user"
    );
    // Helpers sourced from precmds run inside run_rc_command: assigning
    // rc.subr's dynamically scoped _user would re-enable the su -m wrapper.
    let acl = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/pkg/acl.sh"));
    assert!(
        !acl.contains("\n    _user=") && !acl.contains("\n_user="),
        "acl.sh must not assign the rc.subr-reserved _user variable"
    );
    assert!(
        acl.contains("_vcpacl_"),
        "acl.sh internals must stay namespaced under _vcpacl_"
    );
    // Unreserving low ports before mac_portacl is loaded would let any user
    // bind 443; the load must come first.
    let load = vcp
        .find("kldload mac_portacl")
        .expect("rc.d/vcp must load mac_portacl");
    let unreserve = vcp
        .find("portrange.reserved")
        .expect("rc.d/vcp must unreserve the low port range");
    assert!(
        load < unreserve,
        "mac_portacl must be loaded before portrange is unreserved"
    );
    // daemon -r needs a supervisor pidfile; newsyslog keeps process_guard.
    // Uniform convention across services: /var/run/<service>.pid.
    assert!(
        vcp.contains("pidfile=\"/var/run/vcp.pid\"") && vcp.contains("-P ${pidfile}"),
        "rc.d/vcp must use daemon -P on /var/run/vcp.pid for stop/status"
    );
    assert!(
        store.contains("pidfile=\"/var/run/vcp-store.pid\"") && store.contains("-P ${pidfile}"),
        "rc.d/vcp_store must use daemon -P on /var/run/vcp-store.pid"
    );
    assert!(
        !vcp.contains("-P /var/run/vcp/vcp.pid"),
        "daemon -P must not steal process_guard's /var/run/vcp/vcp.pid"
    );
    let access_line = ns
        .lines()
        .find(|l| l.starts_with("/var/log/vcp-access.log"))
        .expect("newsyslog must rotate the access log");
    assert!(
        access_line.contains("/var/run/vcp/vcp.pid") && !access_line.contains("/var/run/vcp.pid"),
        "access log must SIGHUP process_guard (subdir pidfile), not the supervisor"
    );
    // Stderr captures reopen via daemon -H on SIGHUP to the supervisors.
    for (log, pid) in [
        ("/var/log/vcp.log", "/var/run/vcp.pid"),
        ("/var/log/vcp-store.log", "/var/run/vcp-store.pid"),
    ] {
        let line = ns
            .lines()
            .find(|l| l.starts_with(&format!("{log} ")))
            .unwrap_or_else(|| panic!("newsyslog must rotate {log}"));
        assert!(
            line.contains(pid),
            "{log} rotation must SIGHUP the supervisor at {pid}"
        );
    }
    let post = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/pkg/+POST_INSTALL"));
    let conf = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/config/vcp.conf"));
    let db_placeholder = "postgresql://vcp:CHANGE-ME@localhost/vcp";
    assert!(
        conf.contains(db_placeholder),
        "packaged vcp.conf must ship the DB URL placeholder (injection is pkg-add time)"
    );
    assert!(
        post.contains("_DB_URL_PLACEHOLDER=") && post.contains(db_placeholder),
        "+POST_INSTALL must pin the same DB URL placeholder as config/vcp.conf"
    );
    assert!(
        post.contains("CREATE USER vcp WITH PASSWORD")
            && post.contains("ALTER USER vcp WITH PASSWORD")
            && post.contains("openssl rand"),
        "+POST_INSTALL must CREATE or ALTER the vcp role and inject a generated password"
    );
    assert!(
        !post.contains("grep -q 'CHANGE-ME'") && !post.contains("grep -q \"CHANGE-ME\""),
        "+POST_INSTALL must not gate DB injection on a bare CHANGE-ME grep (SMTP false positive)"
    );

    let build = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/pkg/build-pkg.sh"));
    assert!(
        build.contains("share/vcp/assets"),
        "build-pkg.sh must stage Topcoat assets under share/vcp/assets"
    );
    assert!(
        !build.contains("bin/assets") && !build.contains("/usr/local/bin/assets"),
        "build-pkg.sh must not stage assets under bin/"
    );
    assert!(
        build.contains("manifest.toml"),
        "build-pkg.sh must refuse to package without a release asset bundle"
    );
    assert!(
        vcp.contains("VCP_PACKAGE_ROOT"),
        "rc.d/vcp must export VCP_PACKAGE_ROOT for share/vcp assets"
    );
    let app = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app.rs"));
    assert!(
        app.contains("load_asset_bundle") && app.contains("load_dir"),
        "app.rs must load packaged assets via AssetBundle::load_dir"
    );
    for line in ns
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert!(
            fields[1].contains(':'),
            "newsyslog line needs owner:group so rotation stays writable: {line}"
        );
        // Flags field: path owner mode count size when flags.
        let flags = fields.get(6).copied().unwrap_or("");
        assert!(
            !flags.chars().any(|c| matches!(c, 'Z' | 'J' | 'X' | 'Y')),
            "compression flag in newsyslog line: {line}"
        );
    }
}

#[test]
fn prop_post_install_db_placeholder_matches_packaged_conf() {
    let conf = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/config/vcp.conf"));
    let post = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/pkg/+POST_INSTALL"));
    let urls: Vec<&str> = conf
        .lines()
        .filter_map(|l| {
            let t = l.trim();
            t.strip_prefix("url = \"")
                .and_then(|rest| rest.strip_suffix('"'))
        })
        .collect();
    assert_eq!(
        urls.len(),
        1,
        "config/vcp.conf must have exactly one database url"
    );
    let url = urls[0];
    assert!(
        url.contains("CHANGE-ME"),
        "packaged DB url must remain a placeholder for pkg-add injection"
    );
    assert!(
        post.contains(&format!("_DB_URL_PLACEHOLDER='{url}'")),
        "+POST_INSTALL placeholder must match config/vcp.conf url exactly: {url}"
    );
}

#[test]
fn battle_parallel_check_freebsd_pkg() {
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let output = Command::new("bash")
                .arg("scripts/check_freebsd_pkg.sh")
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .output()
                .expect("run check");
            assert!(
                output.status.success(),
                "stderr={}",
                String::from_utf8_lossy(&output.stderr)
            );
        }));
    }
    for h in handles {
        h.join().expect("join");
    }
}
