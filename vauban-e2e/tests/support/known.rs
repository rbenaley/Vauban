//! Product defects the full-stack suite has found and that are not fixed
//! yet. A matching browser error is reported, not failed; an entry that no
//! longer matches anything during a full run fails teardown so it gets
//! removed together with the fix.

use std::collections::BTreeSet;
use std::sync::Mutex;

pub struct KnownDefect {
    pub id: &'static str,
    /// Substring of the probe line (`console: ...`, `js: ...`).
    pub matches: &'static str,
    pub summary: &'static str,
}

pub const KNOWN_DEFECTS: &[KnownDefect] = &[
    KnownDefect {
        id: "E2E-001",
        matches: "console: Event(error) on wss://",
        summary: "htmx-ext-ws opens every ws-connect nested under <body ws-connect> twice: \
                  the first socket is closed while CONNECTING (code 1006, console error) \
                  on every dashboard / sessions / API-key page load",
    },
    KnownDefect {
        id: "E2E-002",
        matches: "js: Uncaught TypeError: Cannot read properties of undefined (reading 'close')",
        summary: "vendored htmx-ext-ws (unchanged from upstream) closes a socket wrapper \
                  that was never created when a ws-connect element leaves the page \
                  before its socket opens (Connect modal on /assets)",
    },
];

static SEEN: Mutex<BTreeSet<&'static str>> = Mutex::new(BTreeSet::new());

/// Splits probe lines into (unknown, known ids).
pub fn triage(lines: Vec<String>) -> (Vec<String>, Vec<&'static KnownDefect>) {
    let mut unknown = Vec::new();
    let mut known: Vec<&'static KnownDefect> = Vec::new();
    for line in lines {
        if line.starts_with("trace: ") {
            unknown.push(line);
            continue;
        }
        match KNOWN_DEFECTS.iter().find(|d| line.contains(d.matches)) {
            Some(d) => {
                SEEN.lock().expect("seen lock").insert(d.id);
                if !known.iter().any(|k| k.id == d.id) {
                    known.push(d);
                }
            }
            None => unknown.push(line),
        }
    }
    if unknown.iter().all(|l| l.starts_with("trace: ")) {
        unknown.clear();
    }
    (unknown, known)
}

/// Entries never observed during this run.
pub fn unseen() -> Vec<&'static str> {
    let seen = SEEN.lock().expect("seen lock");
    KNOWN_DEFECTS
        .iter()
        .map(|d| d.id)
        .filter(|id| !seen.contains(id))
        .collect()
}
