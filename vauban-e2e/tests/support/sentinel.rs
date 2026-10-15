//! Watches the stack log: any sign of a broken stack fails the scenario
//! that caused it, even when the page itself looked fine.

use anyhow::{Result, bail};
use regex::Regex;
use std::fs;
use std::path::PathBuf;
use std::sync::LazyLock;

/// A line matching one of these means the stack is degraded.
const FORBIDDEN: &[(&str, &str)] = &[
    (
        "IPC pump ended",
        "an IPC pump died (web asks for a respawn)",
    ),
    ("Message too large", "a framed IPC channel lost sync"),
    (
        "Deserialization error",
        "two binaries disagree on the wire format",
    ),
    ("panicked at", "a service panicked"),
    (" exited with code ", "a child service died"),
    ("Respawning ", "the supervisor respawned a child"),
    ("crashed too many times", "a child is in a crash loop"),
    ("status_code: 5", "a request answered 5xx"),
];

static ANSI: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\x1b\[[0-9;]*m").expect("ansi"));

pub struct Sentinel {
    path: PathBuf,
    offset: usize,
}

impl Sentinel {
    pub fn new(path: PathBuf) -> Self {
        Self { path, offset: 0 }
    }

    pub fn full_text(&self) -> String {
        ANSI.replace_all(&fs::read_to_string(&self.path).unwrap_or_default(), "")
            .into_owned()
    }

    pub fn tail(&self, lines: usize) -> String {
        let text = self.full_text();
        let all: Vec<&str> = text.lines().collect();
        all[all.len().saturating_sub(lines)..].join("\n")
    }

    /// Fail on any forbidden line logged since the last call.
    pub fn check(&mut self) -> Result<()> {
        let raw = fs::read(&self.path).unwrap_or_default();
        let start = self.offset.min(raw.len());
        self.offset = raw.len();
        let fresh = ANSI
            .replace_all(&String::from_utf8_lossy(&raw[start..]), "")
            .into_owned();
        let hits: Vec<String> = fresh
            .lines()
            .filter_map(|line| {
                FORBIDDEN
                    .iter()
                    .find(|(needle, _)| line.contains(needle))
                    .map(|(_, why)| format!("{why}:\n    {}", truncate(line, 400)))
            })
            .collect();
        if !hits.is_empty() {
            bail!("stack log:\n  {}", hits.join("\n  "));
        }
        Ok(())
    }
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}
