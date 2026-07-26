//! Apache Common Log Format (CLF) access lines for HTTPS requests.
//!
//! Format: `%h %l %u %t "%r" %>s %b`
//!
//! Lines are appended to the path from `server.access_log_path` (not to the
//! process tracing subscriber).

use std::convert::Infallible;
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use chrono::Local;
use http::{Method, Version};
use hyper::body::Incoming;
use hyper::service::Service;
use topcoat::router::{Request, Response, RouterService};
use tracing::{error, info};

/// Append-only writer for Apache CLF lines (shared across connections).
#[derive(Clone)]
pub struct AccessLog {
    file: Arc<Mutex<File>>,
}

impl AccessLog {
    /// Open (or create) the access log file for append. Parent directories are
    /// created when missing (e.g. crate-local `logs/`).
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        info!(access_log = %path.display(), "Apache CLF access log ready");
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }

    /// Write one CLF line (adds a trailing newline). Failures are logged via
    /// tracing; they do not fail the HTTP response.
    pub fn write_line(&self, line: &str) {
        let mut guard = match self.file.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Err(error) = writeln!(guard, "{line}").and_then(|_| guard.flush()) {
            error!(%error, "failed to write access log line");
        }
    }
}

/// Per-connection service that logs each request in Apache CLF to a file.
#[derive(Clone)]
pub struct AccessLogService {
    inner: RouterService,
    peer: SocketAddr,
    access_log: AccessLog,
}

impl AccessLogService {
    pub fn new(inner: RouterService, peer: SocketAddr, access_log: AccessLog) -> Self {
        Self {
            inner,
            peer,
            access_log,
        }
    }
}

impl Service<Request<Incoming>> for AccessLogService {
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, request: Request<Incoming>) -> Self::Future {
        let inner = self.inner.clone();
        let peer = self.peer;
        let access_log = self.access_log.clone();
        let method = request.method().clone();
        let target = request_target(request.uri());
        let version = request.version();

        Box::pin(async move {
            let response = inner.call(request).await?;
            let status = response.status().as_u16();
            let bytes = response_size_field(&response);
            let line = format_common_log(peer, &method, &target, version, status, &bytes);
            access_log.write_line(&line);
            Ok(response)
        })
    }
}

fn request_target(uri: &http::Uri) -> String {
    uri.path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| uri.path().to_owned())
}

fn response_size_field(response: &Response) -> String {
    response
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty() && *s != "0")
        .map(|s| s.to_owned())
        .unwrap_or_else(|| "-".to_owned())
}

/// `%h %l %u %t "%r" %>s %b`
pub fn format_common_log(
    peer: SocketAddr,
    method: &Method,
    target: &str,
    version: Version,
    status: u16,
    bytes: &str,
) -> String {
    let host = peer.ip().to_string();
    let when = Local::now().format("%d/%b/%Y:%H:%M:%S %z");
    let request_line = format!("{method} {target} {}", version_token(version));
    // CLF has no escape for quotes in %r; neutralize embedded quotes.
    let request_line = request_line.replace('"', "%22");
    format!("{host} - - [{when}] \"{request_line}\" {status} {bytes}")
}

fn version_token(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn formats_clf_line() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 54321);
        let line = format_common_log(peer, &Method::GET, "/login", Version::HTTP_11, 200, "1234");
        assert!(line.starts_with("127.0.0.1 - - ["), "{line}");
        assert!(
            line.contains("] \"GET /login HTTP/1.1\" 200 1234"),
            "{line}"
        );
    }

    #[test]
    fn unknown_size_is_dash() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let line = format_common_log(peer, &Method::GET, "/", Version::HTTP_11, 302, "-");
        assert!(line.ends_with(" 302 -"), "{line}");
    }

    #[test]
    fn includes_query_string_in_request_target() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let line = format_common_log(
            peer,
            &Method::GET,
            "/docs?q=ssh",
            Version::HTTP_11,
            200,
            "-",
        );
        assert!(line.contains("\"GET /docs?q=ssh HTTP/1.1\""), "{line}");
    }

    #[test]
    fn formats_ipv6_host() {
        let peer = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
        let line = format_common_log(peer, &Method::HEAD, "/health", Version::HTTP_2, 204, "-");
        assert!(line.starts_with("::1 - - ["), "{line}");
        assert!(line.contains("\"HEAD /health HTTP/2.0\" 204 -"), "{line}");
    }

    #[test]
    fn escapes_embedded_quotes_in_target() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let line = format_common_log(peer, &Method::GET, r#"/x"y"#, Version::HTTP_11, 404, "-");
        assert!(!line.contains(r#"/x"y"#), "{line}");
        assert!(line.contains("%22"), "{line}");
    }

    #[test]
    fn appends_clf_lines_to_file() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("vcp-access-log-unit-{nanos}.log"));
        let log = AccessLog::open(&path).expect("open");
        log.write_line("127.0.0.1 - - [01/Jan/2026:00:00:00 +0000] \"GET /a HTTP/1.1\" 200 -");
        log.write_line("127.0.0.1 - - [01/Jan/2026:00:00:01 +0000] \"GET /b HTTP/1.1\" 404 -");
        let body = std::fs::read_to_string(&path).expect("read");
        let _ = std::fs::remove_file(&path);
        assert_eq!(body.lines().count(), 2);
        assert!(body.contains("\"GET /a HTTP/1.1\" 200 -"));
        assert!(body.contains("\"GET /b HTTP/1.1\" 404 -"));
        assert!(body.ends_with('\n'));
    }
}
