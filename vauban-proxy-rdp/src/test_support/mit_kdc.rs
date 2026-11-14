//! A throwaway MIT Kerberos KDC on loopback, for the opt-in tests.
//!
//! `kdb5_util`, `kadmin.local` and `krb5kdc` create and serve a realm in
//! a temporary directory, on an ephemeral TCP port of `127.0.0.1`. The
//! test account is created with `+requires_preauth` and AES keys, which
//! is what the proxy's Kerberos client needs (it sends no RC4 and expects
//! the KDC to demand pre-authentication).
//!
//! Nothing here touches the configuration of the test process: the
//! Kerberos tools get `KRB5_CONFIG` and `KRB5_KDC_PROFILE` through their
//! own environment only.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::{PASSWORD, REALM, USERNAME};

/// Environment variable that opts in to the MIT KDC tests.
pub(crate) const OPT_IN_ENV: &str = "VAUBAN_TEST_MIT_KDC";
/// Where to look for the MIT tools, in order. `VAUBAN_TEST_MIT_KDC_SBIN`
/// overrides the list.
const SBIN_DIRS: [&str; 4] = [
    "/opt/local/sbin",
    "/usr/local/sbin",
    "/usr/sbin",
    "/opt/homebrew/opt/krb5/sbin",
];

pub(crate) struct MitKdc {
    dir: PathBuf,
    child: Child,
    pub addr: SocketAddr,
}

impl MitKdc {
    /// Whether the caller opted in (`VAUBAN_TEST_MIT_KDC=1`).
    pub(crate) fn opted_in() -> bool {
        std::env::var(OPT_IN_ENV).as_deref() == Ok("1")
    }

    fn tool(name: &str) -> PathBuf {
        let dirs: Vec<String> = match std::env::var("VAUBAN_TEST_MIT_KDC_SBIN") {
            Ok(dir) => vec![dir],
            Err(_) => SBIN_DIRS.iter().map(|d| (*d).to_string()).collect(),
        };
        dirs.iter()
            .map(|dir| Path::new(dir).join(name))
            .find(|path| path.exists())
            .unwrap_or_else(|| panic!("MIT Kerberos tool `{name}` not found in {dirs:?}"))
    }

    fn run(tool: &str, args: &[&str], dir: &Path) {
        let output = Command::new(Self::tool(tool))
            .args(args)
            .env("KRB5_CONFIG", dir.join("krb5.conf"))
            .env("KRB5_KDC_PROFILE", dir.join("kdc.conf"))
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|e| panic!("{tool} did not start: {e}"));
        assert!(
            output.status.success(),
            "{tool} {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Create the realm with the test account and start the KDC.
    pub(crate) fn start() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "vauban-mit-kdc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // An ephemeral port: bind, read it, release it for the KDC.
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let d = dir.display();

        std::fs::write(
            dir.join("kdc.conf"),
            format!(
                "[kdcdefaults]\n    kdc_listen = 127.0.0.1:{port}\n    kdc_tcp_listen = 127.0.0.1:{port}\n\n\
                 [realms]\n    {REALM} = {{\n        database_name = {d}/principal\n        \
                 key_stash_file = {d}/stash\n        acl_file = {d}/kadm5.acl\n        \
                 master_key_type = aes256-cts-hmac-sha1-96\n        \
                 supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal\n    }}\n\n\
                 [logging]\n    kdc = FILE:{d}/kdc.log\n"
            ),
        )
        .unwrap();
        std::fs::write(
            dir.join("krb5.conf"),
            format!(
                "[libdefaults]\n    default_realm = {REALM}\n    dns_lookup_kdc = false\n    \
                 dns_lookup_realm = false\n\n[realms]\n    {REALM} = {{\n        kdc = 127.0.0.1:{port}\n    }}\n"
            ),
        )
        .unwrap();
        std::fs::write(dir.join("kadm5.acl"), "").unwrap();

        Self::run(
            "kdb5_util",
            &["-r", REALM, "create", "-s", "-P", "master-key-for-tests"],
            &dir,
        );
        let add_principal = format!("addprinc +requires_preauth -pw {PASSWORD} {USERNAME}");
        Self::run("kadmin.local", &["-r", REALM, "-q", &add_principal], &dir);

        let child = Command::new(Self::tool("krb5kdc"))
            .args(["-n", "-r", REALM, "-P"])
            .arg(dir.join("kdc.pid"))
            .env("KRB5_CONFIG", dir.join("krb5.conf"))
            .env("KRB5_KDC_PROFILE", dir.join("kdc.conf"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("krb5kdc did not start");
        let kdc = Self { dir, child, addr };

        let deadline = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err() {
            assert!(
                Instant::now() < deadline,
                "krb5kdc did not listen on {addr}; log: {}",
                std::fs::read_to_string(kdc.dir.join("kdc.log")).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        kdc
    }
}

impl Drop for MitKdc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
