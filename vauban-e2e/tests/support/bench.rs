//! A real Vauban stack: `vauban-supervisor` and every child service, built
//! from this checkout, on a throw-away database, config, vault key and
//! recording/audit trees. Never touches the lab instance on :8443.

use anyhow::{Context, Result, bail, ensure};
use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use toml_edit::{Array, DocumentMut, value};

use super::sentinel::Sentinel;

/// Every binary the supervisor execs in development.
const SERVICES: &[&str] = &[
    "vauban-audit",
    "vauban-vault",
    "vauban-access",
    "vauban-auth",
    "vauban-proxy-ssh",
    "vauban-proxy-rdp",
    "vauban-proxy-iacs",
    "vauban-proxy-mcp",
    "vauban-web",
    "vauban-mailer",
];

const BOOT_TIMEOUT: Duration = Duration::from_secs(120);
const STOP_TIMEOUT: Duration = Duration::from_secs(45);

/// Seeded by `vauban-supervisor seed-data` for every account.
pub const SEED_PASSWORD: &str = "SecurePassword123!";

pub struct Bench {
    pub web_port: u16,
    pub sentinel: Sentinel,
    _tmp: tempfile::TempDir,
    supervisor: Option<Child>,
}

impl Bench {
    pub fn start() -> Result<Self> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .context("workspace root")?
            .to_path_buf();
        let bin = root.join("target/debug");
        check_binaries(&bin)?;

        let mut tmp = tempfile::Builder::new().prefix("vauban-e2e-").tempdir()?;
        if std::env::var_os("VAUBAN_E2E_KEEP").is_some() {
            tmp.disable_cleanup(true);
            eprintln!("e2e tree kept: {}", tmp.path().display());
        }
        let web_port = free_port()?;
        let iacs_port = free_port()?;
        let smtp_port = free_port()?;
        let database_url = std::env::var("VAUBAN_E2E_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://localhost/vauban_e2e".to_string());

        let config_dir = tmp.path().join("config");
        copy_dir(&root.join("config"), &config_dir)?;
        write_tls(&tmp.path().join("tls"))?;
        write_overlay(
            &config_dir,
            tmp.path(),
            &database_url,
            web_port,
            iacs_port,
            smtp_port,
        )?;

        let master_key = tmp.path().join("vault/master.key");
        fs::create_dir_all(master_key.parent().context("vault dir")?)?;
        let mut key = [0u8; 32];
        fs::File::open("/dev/urandom")?.read_exact(&mut key)?;
        fs::write(&master_key, key)?;

        let log_path = tmp.path().join("vauban-supervisor.log");
        let env = vec![
            ("VAUBAN_ENVIRONMENT", "development".to_string()),
            ("VAUBAN_CONFIG_DIR", config_dir.display().to_string()),
            (
                "VAUBAN_VAULT_MASTER_KEY_PATH",
                master_key.display().to_string(),
            ),
            ("VAUBAN_VAULT_KEY_VERSION", "1".to_string()),
            ("MCP_LAB_AUTO_APPROVE_HITL", "0".to_string()),
        ];

        recreate_database(&database_url)?;
        let supervisor_bin = bin.join("vauban-supervisor");
        run_admin(
            &root,
            &supervisor_bin,
            &env,
            &["migrate", "--database-url", &database_url],
        )?;
        run_admin(&root, &supervisor_bin, &env, &["seed-data"])?;

        let log = fs::File::create(&log_path)?;
        let mut cmd = Command::new(&supervisor_bin);
        cmd.current_dir(&root)
            .env_remove("DATABASE_URL")
            .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
        let supervisor = cmd.spawn().context("spawn vauban-supervisor")?;

        let mut bench = Self {
            web_port,
            sentinel: Sentinel::new(log_path),
            _tmp: tmp,
            supervisor: Some(supervisor),
        };
        bench.wait_ready()?;
        Ok(bench)
    }

    /// Origin the browser and HTTP clients use (matches the dev certificate).
    pub fn origin(&self) -> String {
        format!("https://localhost:{}", self.web_port)
    }

    /// Throw-away tree holding `config/`, `recordings/`, `audit/`.
    pub fn data(&self) -> &Path {
        self._tmp.path()
    }

    /// The supervisor is still alive (a dead stack fails every scenario).
    pub fn ensure_alive(&mut self) -> Result<()> {
        let child = self.supervisor.as_mut().context("supervisor stopped")?;
        if let Some(status) = child.try_wait()? {
            bail!(
                "vauban-supervisor exited ({status})\n{}",
                self.sentinel.tail(40)
            );
        }
        Ok(())
    }

    fn wait_ready(&mut self) -> Result<()> {
        let deadline = Instant::now() + BOOT_TIMEOUT;
        let health = format!("https://127.0.0.1:{}/health", self.web_port);
        loop {
            self.ensure_alive()?;
            let log = self.sentinel.full_text();
            let all_started = log.contains("All services started, entering watchdog loop");
            let web_up = all_started && curl_status(&health) == Some(200);
            if web_up {
                for service in SERVICES {
                    ensure!(
                        log.contains(&format!("Started {service} with pid")),
                        "{service} was never started"
                    );
                }
                return Ok(());
            }
            if Instant::now() > deadline {
                bail!(
                    "stack not ready after {BOOT_TIMEOUT:?}\n{}",
                    self.sentinel.tail(60)
                );
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    pub fn stop(&mut self) -> Result<()> {
        let Some(mut child) = self.supervisor.take() else {
            return Ok(());
        };
        let pgid = child.id().to_string();
        let _ = Command::new("kill")
            .args(["-TERM", &format!("-{pgid}")])
            .status();
        let deadline = Instant::now() + STOP_TIMEOUT;
        while child.try_wait()?.is_none() {
            if Instant::now() > deadline {
                let _ = Command::new("kill")
                    .args(["-KILL", &format!("-{pgid}")])
                    .status();
                let _ = child.wait();
                bail!("supervisor ignored SIGTERM for {STOP_TIMEOUT:?}");
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        // Children share the process group; none may survive the supervisor.
        std::thread::sleep(Duration::from_millis(500));
        let leftovers = Command::new("pgrep").args(["-g", &pgid]).output()?;
        let leftovers = String::from_utf8_lossy(&leftovers.stdout)
            .trim()
            .to_string();
        if !leftovers.is_empty() {
            let _ = Command::new("kill")
                .args(["-KILL", &format!("-{pgid}")])
                .status();
            bail!("children survived the supervisor: {leftovers}");
        }
        Ok(())
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Children are exec'd from `target/debug`; `just test-full-stack` runs
/// `just build` first so none of them speaks an older wire format.
fn check_binaries(bin: &Path) -> Result<()> {
    for name in std::iter::once("vauban-supervisor").chain(SERVICES.iter().copied()) {
        ensure!(
            bin.join(name).exists(),
            "{name} missing: run `just test-full-stack` (it builds first)"
        );
    }
    Ok(())
}

fn free_port() -> Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

fn copy_dir(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

/// The supervisor reads only `default.toml` + `development.toml`
/// (no `local.toml`), so the bench rewrites its private copy of the latter.
fn write_overlay(
    config_dir: &Path,
    tmp: &Path,
    database_url: &str,
    web_port: u16,
    iacs_port: u16,
    smtp_port: u16,
) -> Result<()> {
    let path = config_dir.join("development.toml");
    let mut doc: DocumentMut = fs::read_to_string(&path)?.parse()?;
    let origins: Array = [
        format!("https://localhost:{web_port}"),
        format!("https://127.0.0.1:{web_port}"),
    ]
    .into_iter()
    .collect();

    doc["server"]["host"] = value("127.0.0.1");
    doc["server"]["port"] = value(i64::from(web_port));
    doc["server"]["public_origins"] = value(origins);
    doc["server"]["tls"]["cert_path"] = value(abs(tmp.join("tls/server.crt")));
    doc["server"]["tls"]["key_path"] = value(abs(tmp.join("tls/server.key")));
    doc["database"]["url"] = value(database_url);
    doc["access"]["model_path"] = value(abs(config_dir.join("access/model.conf")));
    doc["access"]["policy_path"] = value(abs(config_dir.join("access/default_policy.csv")));
    doc["recording"]["storage_path"] = value(abs(tmp.join("recordings")));
    doc["audit"]["log_path"] = value(abs(tmp.join("audit")));
    doc["industrial"]["iacs_tunnel"]["bind_addr"] = value(format!("127.0.0.1:{iacs_port}"));
    doc["mailer"]["smtp_host"] = value("127.0.0.1");
    doc["mailer"]["smtp_port"] = value(i64::from(smtp_port));
    doc["mailer"]["base_url"] = value(format!("https://localhost:{web_port}"));
    // Every scenario logs in; the limiter itself gets a dedicated scenario.
    doc["security"]["rate_limit_per_minute"] = value(10_000);
    doc["security"]["session_create_rate_per_minute"] = value(10_000);
    doc["security"]["session_create_rate_global_per_minute"] = value(10_000);

    fs::write(&path, doc.to_string())?;
    Ok(())
}

/// A CA and a `localhost` leaf it signed: clients that verify (the
/// `vauban-mcp` shim) trust the CA file, not a self-signed leaf.
fn write_tls(dir: &Path) -> Result<()> {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
        SanType,
    };
    fs::create_dir_all(dir)?;
    let ca_key = KeyPair::generate()?;
    let mut ca = CertificateParams::new(Vec::<String>::new())?;
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(DnType::CommonName, "Vauban e2e CA");
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca, ca_key);

    let key = KeyPair::generate()?;
    let mut leaf = CertificateParams::new(vec!["localhost".to_string()])?;
    leaf.subject_alt_names
        .push(SanType::IpAddress(std::net::Ipv4Addr::LOCALHOST.into()));
    leaf.distinguished_name
        .push(DnType::CommonName, "localhost");
    let cert = leaf.signed_by(&key, &issuer)?;

    fs::write(dir.join("ca.pem"), ca_cert.pem())?;
    fs::write(dir.join("server.crt"), cert.pem())?;
    let key_path = dir.join("server.key");
    fs::write(&key_path, key.serialize_pem())?;
    fs::set_permissions(
        &key_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )?;
    Ok(())
}

fn abs(p: PathBuf) -> String {
    p.display().to_string()
}

fn recreate_database(url: &str) -> Result<()> {
    let (server, name) = url
        .rsplit_once('/')
        .context("VAUBAN_E2E_DATABASE_URL must end with /<dbname>")?;
    ensure!(
        name.contains("e2e"),
        "refusing to drop a database whose name lacks `e2e`: {name}"
    );
    let admin = format!("{server}/postgres");
    for sql in [
        format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"),
        format!("CREATE DATABASE \"{name}\""),
    ] {
        let out = Command::new("psql")
            .args([admin.as_str(), "-qAtc", sql.as_str()])
            .output()
            .context("psql not found")?;
        ensure!(
            out.status.success(),
            "{sql}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

fn run_admin(root: &Path, bin: &Path, env: &[(&str, String)], args: &[&str]) -> Result<()> {
    let out = Command::new(bin)
        .current_dir(root)
        .env_remove("DATABASE_URL")
        .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    ensure!(
        out.status.success(),
        "vauban-supervisor {}: {}{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

/// Boot probing runs before the async runtime exists.
fn curl_status(url: &str) -> Option<u16> {
    let out = Command::new("curl")
        .args([
            "-sk",
            "-m",
            "3",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            url,
        ])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}
