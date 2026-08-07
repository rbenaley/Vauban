//! FreeBSD package (`.pkg`) inspection for admin release publish.
//!
//! A FreeBSD package is a compressed ustar whose leading members are `+…`
//! metadata files. Validation reads only the metadata prefix (never the
//! full payload) and fails closed on anything that is not a real package.

use std::io::{self, Cursor, Read, Write};

use serde_json::Value;
use thiserror::Error;

/// Hard cap on a single `+MANIFEST` / `+COMPACT_MANIFEST` body.
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
/// Cumulative decompressed budget while scanning the `+` metadata prefix.
pub const MAX_METADATA_PREFIX_BYTES: usize = 8 * 1024 * 1024;

/// Metadata extracted from a packed FreeBSD package manifeste.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreeBsdPkgInfo {
    pub name: String,
    pub version: String,
    pub origin: String,
    /// Prefer packed `abi` (`FreeBSD:15:amd64`), else `arch`.
    pub architecture: String,
    pub prefix: String,
    pub categories: Vec<String>,
    pub licenses: Vec<String>,
    pub maintainer: String,
    pub www: String,
    pub comment: String,
    pub shlibs_required: Vec<String>,
    pub freebsd_version: Option<String>,
    pub flatsize_bytes: Option<u64>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FreeBsdPkgError {
    #[error("empty package")]
    Empty,
    #[error("unsupported or corrupt compression")]
    BadCompression,
    #[error("not a ustar archive")]
    NotTar,
    #[error("unsafe tar member path")]
    BadPath,
    #[error("manifeste missing or unreadable")]
    NoManifest,
    #[error("manifeste exceeds size budget")]
    ManifestTooLarge,
    #[error("metadata prefix exceeds size budget")]
    PrefixTooLarge,
    #[error("manifeste is not a FreeBSD package object")]
    BadManifest,
}

/// Inspect raw upload bytes: must be a FreeBSD `.pkg` (compressed ustar + manifeste).
pub fn inspect(bytes: &[u8]) -> Result<FreeBsdPkgInfo, FreeBsdPkgError> {
    if bytes.is_empty() {
        return Err(FreeBsdPkgError::Empty);
    }
    let (manifest, compact) = extract_manifests(bytes)?;
    let raw = match manifest.or(compact) {
        Some(m) => m,
        None => return Err(FreeBsdPkgError::NoManifest),
    };
    parse_manifest(&raw)
}

/// `pkg info`-style text for the WebAuthn confirm page (`Installed on` omitted:
/// that timestamp is local pkg DB state, not archive metadata).
pub fn format_pkg_info(info: &FreeBsdPkgInfo) -> String {
    let mut out = String::new();
    out.push_str(&format!("{}-{}\n", info.name, info.version));
    push_field(&mut out, "Name", &info.name);
    push_field(&mut out, "Version", &info.version);
    push_field(&mut out, "Origin", &info.origin);
    if !info.architecture.is_empty() {
        push_field(&mut out, "Architecture", &info.architecture);
    }
    push_field(&mut out, "Prefix", &info.prefix);
    if !info.categories.is_empty() {
        push_field(&mut out, "Categories", &info.categories.join(" "));
    }
    if !info.licenses.is_empty() {
        push_field(&mut out, "Licenses", &info.licenses.join(", "));
    }
    if !info.maintainer.is_empty() {
        push_field(&mut out, "Maintainer", &info.maintainer);
    }
    if !info.www.is_empty() {
        push_field(&mut out, "WWW", &info.www);
    }
    push_field(&mut out, "Comment", &info.comment);
    if !info.shlibs_required.is_empty() {
        out.push_str("Shared Libs required:\n");
        for lib in &info.shlibs_required {
            out.push_str(&format!("\t{lib}\n"));
        }
    }
    if let Some(ref fv) = info.freebsd_version {
        out.push_str("Annotations    :\n");
        out.push_str(&format!("\tFreeBSD_version: {fv}\n"));
    }
    if let Some(bytes) = info.flatsize_bytes {
        push_field(&mut out, "Flat size", &format_flat_size(bytes));
    }
    out
}

fn push_field(out: &mut String, label: &str, value: &str) {
    // Match `pkg info` column: label padded to 15, then " : ".
    out.push_str(&format!("{label:<15}: {value}\n"));
}

fn format_flat_size(bytes: u64) -> String {
    const MIB: f64 = 1024.0 * 1024.0;
    if bytes as f64 >= MIB {
        format!("{:.1}MiB", bytes as f64 / MIB)
    } else if bytes >= 1024 {
        format!("{:.1}KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes}B")
    }
}

/// Craft a minimal zstd-compressed FreeBSD `.pkg` for tests / fixtures.
///
/// The archive contains `+COMPACT_MANIFEST` then `+MANIFEST` (JSON) then a
/// tiny payload member so the metadata prefix ends cleanly.
pub fn craft_minimal_pkg(info: &FreeBsdPkgInfo) -> Vec<u8> {
    let manifest = serde_json::json!({
        "name": info.name,
        "version": info.version,
        "origin": info.origin,
        "comment": info.comment,
        "maintainer": info.maintainer,
        "www": info.www,
        "abi": info.architecture,
        "prefix": info.prefix,
        "licenses": info.licenses,
        "categories": info.categories,
        "shlibs_required": info.shlibs_required,
        "flatsize": info.flatsize_bytes,
        "annotations": info.freebsd_version.as_ref().map(|v| {
            serde_json::json!({ "FreeBSD_version": v })
        }).unwrap_or(Value::Null),
    });
    // Drop null annotations for cleaner JSON.
    let mut map = manifest.as_object().cloned().unwrap_or_default();
    if map.get("annotations").is_some_and(|v| v.is_null()) {
        map.remove("annotations");
    }
    if map.get("flatsize").is_some_and(|v| v.is_null()) {
        map.remove("flatsize");
    }
    let body = serde_json::to_vec(&Value::Object(map)).expect("manifest json");
    let tar = write_pkg_tar(&body, &body);
    zstd::encode_all(Cursor::new(tar), 3).expect("zstd encode")
}

/// Convenience fixture with Vauban-like fields (used by integration tests).
pub fn craft_test_vauban_pkg(version: &str) -> Vec<u8> {
    craft_minimal_pkg(&FreeBsdPkgInfo {
        name: "vauban".into(),
        version: version.trim_start_matches('v').into(),
        origin: "security/vauban".into(),
        architecture: "FreeBSD:15:amd64".into(),
        prefix: "/usr/local".into(),
        categories: vec!["security".into()],
        licenses: vec!["BSD2CLAUSE".into()],
        maintainer: "none@freebsd.org".into(),
        www: "https://vauban.sh".into(),
        comment: "Security bastion with SSH and RDP recording, privsep and capsicum(4) sandboxing"
            .into(),
        shlibs_required: vec!["libc.so.7".into(), "libm.so.5".into(), "libthr.so.3".into()],
        freebsd_version: Some("1501000".into()),
        flatsize_bytes: Some(93_450_240),
    })
}

fn write_pkg_tar(compact: &[u8], full: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut ar = tar::Builder::new(&mut buf);
        append_regular(&mut ar, "+COMPACT_MANIFEST", compact);
        append_regular(&mut ar, "+MANIFEST", full);
        append_regular(&mut ar, "usr/local/share/vcp-fixture", b"ok");
        ar.finish().expect("tar finish");
    }
    buf
}

fn append_regular<W: Write>(ar: &mut tar::Builder<W>, name: &str, data: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    ar.append_data(&mut header, name, data)
        .expect("append tar member");
}

enum Compression {
    Zstd,
    Xz,
    Gzip,
    Bzip2,
    Raw,
}

fn sniff_compression(bytes: &[u8]) -> Compression {
    if bytes.len() >= 4 && bytes[..4] == [0x28, 0xB5, 0x2F, 0xFD] {
        return Compression::Zstd;
    }
    if bytes.len() >= 6 && bytes[..6] == [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] {
        return Compression::Xz;
    }
    if bytes.len() >= 2 && bytes[..2] == [0x1F, 0x8B] {
        return Compression::Gzip;
    }
    if bytes.len() >= 3 && &bytes[..3] == b"BZh" {
        return Compression::Bzip2;
    }
    Compression::Raw
}

type ManifestBodies = (Option<Vec<u8>>, Option<Vec<u8>>);

fn extract_manifests(bytes: &[u8]) -> Result<ManifestBodies, FreeBsdPkgError> {
    match sniff_compression(bytes) {
        Compression::Zstd => {
            let dec = zstd::stream::read::Decoder::new(Cursor::new(bytes))
                .map_err(|_| FreeBsdPkgError::BadCompression)?;
            read_manifests_from_tar(BudgetRead::new(dec))
        }
        Compression::Xz => {
            let dec = xz2::read::XzDecoder::new(Cursor::new(bytes));
            read_manifests_from_tar(BudgetRead::new(dec))
        }
        Compression::Gzip => {
            let dec = flate2::read::GzDecoder::new(Cursor::new(bytes));
            read_manifests_from_tar(BudgetRead::new(dec))
        }
        Compression::Bzip2 => {
            let dec = bzip2::read::BzDecoder::new(Cursor::new(bytes));
            read_manifests_from_tar(BudgetRead::new(dec))
        }
        Compression::Raw => read_manifests_from_tar(BudgetRead::new(Cursor::new(bytes))),
    }
}

/// Counts decompressed bytes and fails when the metadata prefix budget is exceeded.
struct BudgetRead<R> {
    inner: R,
    used: usize,
}

impl<R> BudgetRead<R> {
    fn new(inner: R) -> Self {
        Self { inner, used: 0 }
    }
}

impl<R: Read> Read for BudgetRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.used >= MAX_METADATA_PREFIX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "metadata prefix budget exceeded",
            ));
        }
        let room = MAX_METADATA_PREFIX_BYTES - self.used;
        let take = buf.len().min(room);
        let n = self.inner.read(&mut buf[..take])?;
        self.used = self.used.saturating_add(n);
        Ok(n)
    }
}

fn read_manifests_from_tar<R: Read>(
    reader: BudgetRead<R>,
) -> Result<ManifestBodies, FreeBsdPkgError> {
    let mut archive = tar::Archive::new(reader);
    let entries = archive.entries().map_err(|_| FreeBsdPkgError::NotTar)?;

    let mut full: Option<Vec<u8>> = None;
    let mut compact: Option<Vec<u8>> = None;
    let mut saw_plus = false;

    for entry in entries {
        let mut entry = entry.map_err(|e| {
            if e.kind() == io::ErrorKind::InvalidData {
                FreeBsdPkgError::PrefixTooLarge
            } else {
                FreeBsdPkgError::NotTar
            }
        })?;
        let path = entry
            .path()
            .map_err(|_| FreeBsdPkgError::BadPath)?
            .to_string_lossy()
            .into_owned();

        if !is_safe_plus_member(&path) {
            if path.starts_with('+') {
                return Err(FreeBsdPkgError::BadPath);
            }
            // End of metadata prefix (libpkg rule).
            if saw_plus {
                break;
            }
            return Err(FreeBsdPkgError::NoManifest);
        }

        saw_plus = true;
        let header = entry.header();
        if !header.entry_type().is_file() {
            return Err(FreeBsdPkgError::BadPath);
        }
        let size = header.size().map_err(|_| FreeBsdPkgError::NotTar)? as usize;
        if size > MAX_MANIFEST_BYTES {
            return Err(FreeBsdPkgError::ManifestTooLarge);
        }

        match path.as_str() {
            "+MANIFEST" => {
                let mut buf = Vec::with_capacity(size);
                entry
                    .read_to_end(&mut buf)
                    .map_err(|_| FreeBsdPkgError::NoManifest)?;
                if buf.len() > MAX_MANIFEST_BYTES {
                    return Err(FreeBsdPkgError::ManifestTooLarge);
                }
                full = Some(buf);
            }
            "+COMPACT_MANIFEST" => {
                let mut buf = Vec::with_capacity(size);
                entry
                    .read_to_end(&mut buf)
                    .map_err(|_| FreeBsdPkgError::NoManifest)?;
                if buf.len() > MAX_MANIFEST_BYTES {
                    return Err(FreeBsdPkgError::ManifestTooLarge);
                }
                compact = Some(buf);
            }
            _ => {
                // Other `+` members (scripts): skip body within budget.
                let mut sink = vec![0u8; size.min(64 * 1024)];
                let mut remaining = size;
                while remaining > 0 {
                    let chunk = remaining.min(sink.len());
                    entry
                        .read_exact(&mut sink[..chunk])
                        .map_err(|_| FreeBsdPkgError::PrefixTooLarge)?;
                    remaining -= chunk;
                }
            }
        }

        if full.is_some() {
            // Prefer full manifeste; we can stop once we have it (compact may
            // already have been seen earlier).
            break;
        }
    }

    if full.is_none() && compact.is_none() {
        return Err(FreeBsdPkgError::NoManifest);
    }
    Ok((full, compact))
}

fn is_safe_plus_member(path: &str) -> bool {
    if path.is_empty() || !path.starts_with('+') {
        return false;
    }
    if path.contains('/') || path.contains('\\') || path.contains("..") {
        return false;
    }
    // Reject absolute / drive-like names.
    if path.starts_with("+/") {
        return false;
    }
    true
}

fn parse_manifest(raw: &[u8]) -> Result<FreeBsdPkgInfo, FreeBsdPkgError> {
    let text = std::str::from_utf8(raw).map_err(|_| FreeBsdPkgError::BadManifest)?;
    let value = if let Ok(v) = serde_json::from_str::<Value>(text) {
        v
    } else {
        parse_minimal_ucl(text)?
    };
    let obj = value.as_object().ok_or(FreeBsdPkgError::BadManifest)?;

    let name = required_string(obj, "name")?;
    let version = required_string(obj, "version")?;
    let origin = required_string(obj, "origin")?;
    let prefix = required_string(obj, "prefix")?;
    let comment = required_string(obj, "comment")?;

    let abi = optional_string(obj, "abi");
    let arch = optional_string(obj, "arch");
    let architecture = abi.or(arch).unwrap_or_default();

    let freebsd_version = obj
        .get("annotations")
        .and_then(|a| a.as_object())
        .and_then(|a| a.get("FreeBSD_version"))
        .and_then(|v| match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        });

    let flatsize_bytes = obj.get("flatsize").and_then(|v| match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    });

    Ok(FreeBsdPkgInfo {
        name,
        version,
        origin,
        architecture,
        prefix,
        categories: string_list(obj.get("categories")),
        licenses: string_list(obj.get("licenses")),
        maintainer: optional_string(obj, "maintainer").unwrap_or_default(),
        www: optional_string(obj, "www").unwrap_or_default(),
        comment,
        shlibs_required: string_list(obj.get("shlibs_required")),
        freebsd_version,
        flatsize_bytes,
    })
}

fn required_string(
    obj: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<String, FreeBsdPkgError> {
    let s = optional_string(obj, key).ok_or(FreeBsdPkgError::BadManifest)?;
    if s.is_empty() {
        return Err(FreeBsdPkgError::BadManifest);
    }
    Ok(s)
}

fn optional_string(obj: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    obj.get(key).and_then(|v| v.as_str()).map(str::to_owned)
}

fn string_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|i| i.as_str().map(str::to_owned))
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// Minimal UCL object reader for packed-style `key = "value";` / arrays / nested objects.
/// Does not support heredocs (`<<EOD`); packed manifests from `pkg create` do not need them.
fn parse_minimal_ucl(text: &str) -> Result<Value, FreeBsdPkgError> {
    let mut p = UclParser {
        input: text.trim_start(),
    };
    let v = p.parse_object()?;
    Ok(v)
}

struct UclParser<'a> {
    input: &'a str,
}

impl<'a> UclParser<'a> {
    fn parse_object(&mut self) -> Result<Value, FreeBsdPkgError> {
        self.skip_ws();
        let mut map = serde_json::Map::new();
        if self.input.starts_with('{') {
            self.input = &self.input[1..];
        }
        loop {
            self.skip_ws();
            if self.input.is_empty() || self.input.starts_with('}') {
                if self.input.starts_with('}') {
                    self.input = &self.input[1..];
                }
                break;
            }
            let key = self.parse_key()?;
            self.skip_ws();
            if self.input.starts_with('=') || self.input.starts_with(':') {
                self.input = &self.input[1..];
            }
            self.skip_ws();
            let value = self.parse_value()?;
            map.insert(key, value);
            self.skip_ws();
            if self.input.starts_with(';') || self.input.starts_with(',') {
                self.input = &self.input[1..];
            }
        }
        Ok(Value::Object(map))
    }

    fn parse_key(&mut self) -> Result<String, FreeBsdPkgError> {
        self.skip_ws();
        if self.input.starts_with('"') {
            return self.parse_string();
        }
        let end = self
            .input
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            .unwrap_or(self.input.len());
        if end == 0 {
            return Err(FreeBsdPkgError::BadManifest);
        }
        let key = self.input[..end].to_owned();
        self.input = &self.input[end..];
        Ok(key)
    }

    fn parse_value(&mut self) -> Result<Value, FreeBsdPkgError> {
        self.skip_ws();
        if self.input.starts_with('"') {
            return Ok(Value::String(self.parse_string()?));
        }
        if self.input.starts_with('[') {
            return self.parse_array();
        }
        if self.input.starts_with('{') {
            return self.parse_object();
        }
        // Bare number or identifier (true/false/null or unquoted string).
        let end = self
            .input
            .find(|c: char| c.is_whitespace() || matches!(c, ';' | ',' | '}' | ']'))
            .unwrap_or(self.input.len());
        if end == 0 {
            return Err(FreeBsdPkgError::BadManifest);
        }
        let tok = &self.input[..end];
        self.input = &self.input[end..];
        if let Ok(n) = tok.parse::<u64>() {
            return Ok(Value::Number(n.into()));
        }
        if let Ok(n) = tok.parse::<i64>() {
            return Ok(Value::Number(n.into()));
        }
        match tok {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            "null" => Ok(Value::Null),
            other => Ok(Value::String(other.to_owned())),
        }
    }

    fn parse_array(&mut self) -> Result<Value, FreeBsdPkgError> {
        self.input = &self.input[1..];
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            if self.input.starts_with(']') {
                self.input = &self.input[1..];
                break;
            }
            items.push(self.parse_value()?);
            self.skip_ws();
            if self.input.starts_with(',') || self.input.starts_with(';') {
                self.input = &self.input[1..];
            }
        }
        Ok(Value::Array(items))
    }

    fn parse_string(&mut self) -> Result<String, FreeBsdPkgError> {
        if !self.input.starts_with('"') {
            return Err(FreeBsdPkgError::BadManifest);
        }
        self.input = &self.input[1..];
        let mut out = String::new();
        let bytes = self.input.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'"' => {
                    self.input = &self.input[i + 1..];
                    return Ok(out);
                }
                b'\\' if i + 1 < bytes.len() => {
                    out.push(bytes[i + 1] as char);
                    i += 2;
                }
                b => {
                    out.push(b as char);
                    i += 1;
                }
            }
        }
        Err(FreeBsdPkgError::BadManifest)
    }

    fn skip_ws(&mut self) {
        loop {
            self.input = self.input.trim_start();
            if self.input.starts_with("//") {
                if let Some(rest) = self.input.split_once('\n') {
                    self.input = rest.1;
                    continue;
                }
                self.input = "";
                return;
            }
            if self.input.starts_with('#') {
                if let Some(rest) = self.input.split_once('\n') {
                    self.input = rest.1;
                    continue;
                }
                self.input = "";
                return;
            }
            if self.input.starts_with("/*") {
                if let Some(idx) = self.input.find("*/") {
                    self.input = &self.input[idx + 2..];
                    continue;
                }
                self.input = "";
                return;
            }
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_info() -> FreeBsdPkgInfo {
        FreeBsdPkgInfo {
            name: "vauban".into(),
            version: "0.9.35".into(),
            origin: "security/vauban".into(),
            architecture: "FreeBSD:15:amd64".into(),
            prefix: "/usr/local".into(),
            categories: vec!["security".into()],
            licenses: vec!["BSD2CLAUSE".into()],
            maintainer: "none@freebsd.org".into(),
            www: "https://vauban.sh".into(),
            comment: "Security bastion".into(),
            shlibs_required: vec!["libc.so.7".into()],
            freebsd_version: Some("1501000".into()),
            flatsize_bytes: Some(93_450_240),
        }
    }

    #[test]
    fn inspect_accepts_crafted_zstd_pkg() {
        let bytes = craft_minimal_pkg(&sample_info());
        let info = inspect(&bytes).expect("valid pkg");
        assert_eq!(info.name, "vauban");
        assert_eq!(info.version, "0.9.35");
        assert_eq!(info.architecture, "FreeBSD:15:amd64");
        assert_eq!(info.freebsd_version.as_deref(), Some("1501000"));
        assert_eq!(info.flatsize_bytes, Some(93_450_240));
    }

    #[test]
    fn inspect_accepts_gzip_and_xz_and_raw() {
        let info = sample_info();
        let body = serde_json::to_vec(&serde_json::json!({
            "name": info.name,
            "version": info.version,
            "origin": info.origin,
            "comment": info.comment,
            "prefix": info.prefix,
            "maintainer": info.maintainer,
            "www": info.www,
            "abi": info.architecture,
            "licenses": info.licenses,
            "categories": info.categories,
        }))
        .unwrap();
        let tar = write_pkg_tar(&body, &body);

        let gz = {
            use flate2::Compression;
            use flate2::write::GzEncoder;
            let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
            enc.write_all(&tar).unwrap();
            enc.finish().unwrap()
        };
        assert_eq!(inspect(&gz).unwrap().name, "vauban");

        let xz = {
            let mut enc = xz2::write::XzEncoder::new(Vec::new(), 1);
            enc.write_all(&tar).unwrap();
            enc.finish().unwrap()
        };
        assert_eq!(inspect(&xz).unwrap().name, "vauban");

        assert_eq!(inspect(&tar).unwrap().name, "vauban");
    }

    #[test]
    fn inspect_rejects_garbage_and_empty() {
        assert_eq!(inspect(b"").unwrap_err(), FreeBsdPkgError::Empty);
        assert!(inspect(b"not-a-package").is_err());
        assert!(inspect(&[0u8; 64]).is_err());
    }

    #[test]
    fn inspect_rejects_tar_without_manifest() {
        let mut buf = Vec::new();
        {
            let mut ar = tar::Builder::new(&mut buf);
            append_regular(&mut ar, "usr/local/bin/x", b"hi");
            ar.finish().unwrap();
        }
        assert_eq!(inspect(&buf).unwrap_err(), FreeBsdPkgError::NoManifest);
    }

    #[test]
    fn inspect_rejects_path_traversal_plus_member() {
        let mut buf = Vec::new();
        {
            let mut ar = tar::Builder::new(&mut buf);
            append_regular(&mut ar, "+../MANIFEST", b"{}");
            ar.finish().unwrap();
        }
        assert_eq!(inspect(&buf).unwrap_err(), FreeBsdPkgError::BadPath);
    }

    #[test]
    fn inspect_rejects_missing_required_fields() {
        let body = br#"{"name":"x","version":"1"}"#;
        let tar = {
            let mut buf = Vec::new();
            {
                let mut ar = tar::Builder::new(&mut buf);
                append_regular(&mut ar, "+MANIFEST", body);
                ar.finish().unwrap();
            }
            buf
        };
        assert_eq!(inspect(&tar).unwrap_err(), FreeBsdPkgError::BadManifest);
    }

    #[test]
    fn inspect_parses_minimal_ucl() {
        let ucl = r#"
name = "vauban";
version = "1.0.0";
origin = "security/vauban";
prefix = "/usr/local";
comment = "bastion";
abi = "FreeBSD:14:amd64";
licenses = ["BSD2CLAUSE"];
categories = ["security"];
"#;
        let tar = {
            let mut buf = Vec::new();
            {
                let mut ar = tar::Builder::new(&mut buf);
                append_regular(&mut ar, "+MANIFEST", ucl.as_bytes());
                ar.finish().unwrap();
            }
            buf
        };
        let info = inspect(&tar).unwrap();
        assert_eq!(info.name, "vauban");
        assert_eq!(info.licenses, vec!["BSD2CLAUSE".to_owned()]);
    }

    #[test]
    fn format_pkg_info_lists_expected_fields() {
        let text = format_pkg_info(&sample_info());
        assert!(text.starts_with("vauban-0.9.35\n"));
        assert!(text.contains("Name           : vauban"));
        assert!(text.contains("Version        : 0.9.35"));
        assert!(text.contains("Origin         : security/vauban"));
        assert!(text.contains("Architecture   : FreeBSD:15:amd64"));
        assert!(text.contains("Shared Libs required:"));
        assert!(text.contains("\tlibc.so.7\n"));
        assert!(text.contains("FreeBSD_version: 1501000"));
        assert!(text.contains("Flat size      : 89.1MiB"));
        assert!(!text.contains("Installed on"));
    }

    #[test]
    fn craft_test_vauban_pkg_round_trips() {
        let bytes = craft_test_vauban_pkg("v1.2.3");
        let info = inspect(&bytes).unwrap();
        assert_eq!(info.version, "1.2.3");
        assert_eq!(info.origin, "security/vauban");
    }
}
