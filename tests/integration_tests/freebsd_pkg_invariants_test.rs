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
