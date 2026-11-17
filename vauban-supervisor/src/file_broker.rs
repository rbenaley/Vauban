//! Who may ask the supervisor for which file operation.
//!
//! The supervisor opens, hands over and unlinks recording and audit-log
//! files as root, on behalf of services that have dropped privileges. The
//! path of each request is validated and confined elsewhere
//! (`shared::recording_paths`, `validate_audit_segment_name`). This module
//! answers the other question: is this service one that has any business
//! asking for this operation at all.
//!
//! Without it, any service able to reach the supervisor could read a
//! session recording, open an audit-log segment or unlink a capture, as
//! long as the path was well formed. With it, a proxy cannot open an
//! audit-log segment or unlink a capture, and the web service cannot
//! obtain a write lease.
//!
//! Default deny: a service or an operation that is not listed is refused.
//!
//! The caller table decides by service. A write lease is narrowed further,
//! by session and by file ([`write_lease`], [`audit_lease`]):
//!
//! - the path must be `YYYY/MM/<session_id>/<file>`, with the session
//!   identifier as a whole directory name, not a substring;
//! - a proxy obtains a lease only on a session it serves, as recorded by
//!   `session_owner` when the session token was accepted;
//! - each service may only name the files of its own format;
//! - the audit service asks on behalf of the proxy whose pipe carried the
//!   message, and is granted only when that proxy serves the session;
//! - a media, capture or seal file is opened with `O_EXCL`: the lease
//!   creates it or fails. No service can obtain a descriptor on a
//!   recording that already holds data;
//! - only the audit service may rewrite a file, and only IACS
//!   `session.json` (written at session start and again at session end).
//!
//! A raw capture is unlinked under the same shape rule
//! ([`is_raw_capture`]).
//!
//! IACS is the one case the token does not cover: `session.json` is
//! written when the operator authenticates, before any channel presents
//! the token. An IACS file is therefore granted while the session has no
//! recorded owner, and refused in a directory that already holds the
//! media of another recorder ([`FOREIGN_TO_IACS`]).

/// A file operation a service can request from the supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileBrokerOp {
    /// `RecordingFileRequest { read_only: false }`: create a
    /// recording file of a session.
    RecordingWrite,
    /// `RecordingFileRequest { read_only: true }`: read a recording back
    /// (playback).
    RecordingRead,
    /// `AuditLogFileRequest`: open a segment of the WORM audit log.
    AuditLogSegment,
    /// `RecordingFileUnlinkRequest`: remove a raw capture once it has been
    /// compressed.
    RecordingUnlink,
    /// `RecordingFileGzipRequest`: retired, compression moved to the audit
    /// service. Kept as a variant because the message still decodes.
    RecordingGzip,
}

impl FileBrokerOp {
    #[cfg(test)]
    pub const ALL: [FileBrokerOp; 5] = [
        FileBrokerOp::RecordingWrite,
        FileBrokerOp::RecordingRead,
        FileBrokerOp::AuditLogSegment,
        FileBrokerOp::RecordingUnlink,
        FileBrokerOp::RecordingGzip,
    ];

    /// The operation a `RecordingFileRequest` asks for.
    pub fn of_recording_request(read_only: bool) -> Self {
        if read_only {
            FileBrokerOp::RecordingRead
        } else {
            FileBrokerOp::RecordingWrite
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            FileBrokerOp::RecordingWrite => "recording_write",
            FileBrokerOp::RecordingRead => "recording_read",
            FileBrokerOp::AuditLogSegment => "audit_log_segment",
            FileBrokerOp::RecordingUnlink => "recording_unlink",
            FileBrokerOp::RecordingGzip => "recording_gzip",
        }
    }
}

/// Text sent back to a refused caller. Fixed: nothing from the request is
/// echoed.
pub const CALLER_NOT_ALLOWED: &str = "caller_not_allowed";

/// Whether `service_key` may request `op`.
///
/// - The session proxies and the audit service write recordings: the
///   proxies own the media file, the audit service the metadata.
/// - Only the web service reads a recording back.
/// - Only the audit service opens audit-log segments and unlinks raw
///   captures.
/// - Nobody may request the retired gzip operation.
pub fn caller_may(service_key: &str, op: FileBrokerOp) -> bool {
    match op {
        FileBrokerOp::RecordingWrite => {
            matches!(
                service_key,
                "proxy_ssh" | "proxy_rdp" | "proxy_mcp" | "audit"
            )
        }
        FileBrokerOp::RecordingRead => service_key == "web",
        FileBrokerOp::AuditLogSegment | FileBrokerOp::RecordingUnlink => service_key == "audit",
        FileBrokerOp::RecordingGzip => false,
    }
}

/// How a write lease opens its file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteLease {
    /// `O_CREAT | O_EXCL`: the file must not exist. Media and captures.
    CreateNew,
    /// `O_CREAT | O_TRUNC`: the file may be replaced. IACS `session.json`
    /// written by the audit service, and nothing else.
    Rewrite,
}

/// Text sent back when the path of a write lease is not one the caller
/// may name. Fixed: nothing from the request is echoed.
pub const PATH_NOT_ALLOWED: &str = "recording_path_not_allowed";

/// Text sent back when a create-only lease names a file that exists.
pub const FILE_EXISTS: &str = "recording_file_exists";

/// Longest session directory name accepted in a write lease.
const MAX_SESSION_DIR_LEN: usize = 128;

/// A session identifier usable as a directory name: ASCII letters,
/// digits, `-` and `_` (a UUID fits; `.`, `/` and the empty string do not).
fn is_session_dir_name(session_id: &str) -> bool {
    !session_id.is_empty()
        && session_id.len() <= MAX_SESSION_DIR_LEN
        && session_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_digits(text: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_digit())
}

/// `NNN<extension>` with three to ten digits (`001.mp4`, `012.pcap.gz`).
fn is_numbered(file: &str, extension: &str) -> bool {
    file.strip_suffix(extension)
        .is_some_and(|stem| is_digits(stem, 3, 10))
}

/// Split `YYYY/MM/<session_id>/<file...>` and return the file part, or
/// `None` when the path has another shape or names another session.
fn session_file<'a>(session_id: &str, relative_path: &'a str) -> Option<Vec<&'a str>> {
    if !is_session_dir_name(session_id) {
        return None;
    }
    let parts: Vec<&str> = relative_path.split('/').collect();
    let [year, month, session_dir, file @ ..] = parts.as_slice() else {
        return None;
    };
    if !is_digits(year, 4, 4) || !is_digits(month, 2, 2) || *session_dir != session_id {
        return None;
    }
    Some(file.to_vec())
}

/// Whether `relative_path` is a raw IACS capture of `session_id`:
/// `YYYY/MM/<session_id>/channels/NNN.pcap`. The only file the unlink
/// broker removes.
pub fn is_raw_capture(session_id: &str, relative_path: &str) -> bool {
    matches!(
        session_file(session_id, relative_path).as_deref(),
        Some(["channels", capture]) if is_numbered(capture, ".pcap")
    )
}

/// Media files whose presence in a session directory shows that the
/// session is not an IACS one. Checked before an IACS file is created.
pub const FOREIGN_TO_IACS: [&str; 3] = ["session.cast", "session.mcp.jsonl", "001.mp4"];

/// Decide whether proxy `service_key` may obtain a write lease on
/// `relative_path` for `session_id`, and how the file is opened.
///
/// `owner` is the service recorded for the session by `session_owner`.
/// `None` is a refusal: the proxy must serve the session, and may only
/// name the files of its own format. The audit service never comes
/// through here; see [`audit_lease`].
///
/// The layout is the one every recorder uses:
/// `YYYY/MM/<session_id>/<file>`.
pub fn write_lease(
    service_key: &str,
    session_id: &str,
    relative_path: &str,
    owner: Option<&str>,
) -> Option<WriteLease> {
    let file = session_file(session_id, relative_path)?;
    if owner != Some(service_key) {
        return None;
    }
    match (service_key, file.as_slice()) {
        ("proxy_ssh", ["session.cast"]) => Some(WriteLease::CreateNew),
        ("proxy_rdp", [segment]) if is_numbered(segment, ".mp4") => Some(WriteLease::CreateNew),
        ("proxy_mcp", ["session.mcp.jsonl" | "session.cast" | "meta.json"]) => {
            Some(WriteLease::CreateNew)
        }
        _ => None,
    }
}

/// Decide whether the audit service may obtain a write lease on
/// `relative_path` for `session_id` on behalf of `source`.
///
/// `source` is the service key of the proxy whose pipe carried the
/// message that made audit ask; `owner` is the service recorded for the
/// session.
///
/// - `proxy_ssh`, `proxy_rdp`: the seal `meta.json`, and only when that
///   proxy serves the session.
/// - `proxy_iacs`: the IACS bundle. The session must have no recorded
///   owner or be an IACS one; the caller must also check
///   [`FOREIGN_TO_IACS`] on disk.
/// - anything else: refused (`proxy_mcp` writes its own files).
pub fn audit_lease(
    source: &str,
    session_id: &str,
    relative_path: &str,
    owner: Option<&str>,
) -> Option<WriteLease> {
    let file = session_file(session_id, relative_path)?;
    match (source, file.as_slice()) {
        ("proxy_ssh" | "proxy_rdp", ["meta.json"]) if owner == Some(source) => {
            Some(WriteLease::CreateNew)
        }
        ("proxy_iacs", file) if owner.is_none() || owner == Some("proxy_iacs") => match file {
            ["session.json"] => Some(WriteLease::Rewrite),
            ["meta.json"] => Some(WriteLease::CreateNew),
            ["channels", capture]
                if is_numbered(capture, ".pcap") || is_numbered(capture, ".pcap.gz") =>
            {
                Some(WriteLease::CreateNew)
            }
            _ => None,
        },
        _ => None,
    }
}

/// The session directory of a well-formed lease path
/// (`YYYY/MM/<session_id>`), for the on-disk IACS check.
pub fn session_dir(session_id: &str, relative_path: &str) -> Option<String> {
    session_file(session_id, relative_path)?;
    let mut parts = relative_path.splitn(4, '/');
    Some(format!(
        "{}/{}/{}",
        parts.next()?,
        parts.next()?,
        parts.next()?
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every service key the supervisor spawns, plus values no service has.
    const SERVICES: [&str; 13] = [
        "web",
        "auth",
        "access",
        "vault",
        "audit",
        "mailer",
        "proxy_ssh",
        "proxy_rdp",
        "proxy_iacs",
        "proxy_mcp",
        "supervisor",
        "",
        "AUDIT",
    ];

    fn allowed(op: FileBrokerOp) -> Vec<&'static str> {
        SERVICES
            .iter()
            .copied()
            .filter(|s| caller_may(s, op))
            .collect()
    }

    #[test]
    fn test_table_is_exactly_the_documented_one() {
        assert_eq!(
            allowed(FileBrokerOp::RecordingWrite),
            ["audit", "proxy_ssh", "proxy_rdp", "proxy_mcp"]
        );
        assert_eq!(allowed(FileBrokerOp::RecordingRead), ["web"]);
        assert_eq!(allowed(FileBrokerOp::AuditLogSegment), ["audit"]);
        assert_eq!(allowed(FileBrokerOp::RecordingUnlink), ["audit"]);
        assert!(allowed(FileBrokerOp::RecordingGzip).is_empty());
    }

    #[test]
    fn test_all_lists_every_operation_once() {
        for op in FileBrokerOp::ALL {
            // Exhaustive: adding a variant without listing it fails to compile.
            match op {
                FileBrokerOp::RecordingWrite
                | FileBrokerOp::RecordingRead
                | FileBrokerOp::AuditLogSegment
                | FileBrokerOp::RecordingUnlink
                | FileBrokerOp::RecordingGzip => {}
            }
            assert_eq!(
                FileBrokerOp::ALL.iter().filter(|o| **o == op).count(),
                1,
                "{op:?} listed more than once"
            );
        }
        let names: std::collections::HashSet<_> =
            FileBrokerOp::ALL.iter().map(|o| o.as_str()).collect();
        assert_eq!(names.len(), FileBrokerOp::ALL.len(), "names must differ");
    }

    #[test]
    fn test_read_only_flag_selects_the_operation() {
        assert_eq!(
            FileBrokerOp::of_recording_request(true),
            FileBrokerOp::RecordingRead
        );
        assert_eq!(
            FileBrokerOp::of_recording_request(false),
            FileBrokerOp::RecordingWrite
        );
    }

    #[test]
    fn attack_web_asking_to_write_a_recording_is_rejected() {
        assert!(!caller_may("web", FileBrokerOp::RecordingWrite));
    }

    #[test]
    fn attack_proxy_asking_to_read_a_recording_is_rejected() {
        for proxy in ["proxy_ssh", "proxy_rdp", "proxy_mcp", "proxy_iacs"] {
            assert!(!caller_may(proxy, FileBrokerOp::RecordingRead), "{proxy}");
        }
    }

    #[test]
    fn attack_non_audit_service_asking_for_an_audit_segment_is_rejected() {
        for service in SERVICES.iter().filter(|s| **s != "audit") {
            assert!(
                !caller_may(service, FileBrokerOp::AuditLogSegment),
                "{service:?} must not open an audit-log segment"
            );
        }
    }

    #[test]
    fn attack_non_audit_service_asking_to_unlink_is_rejected() {
        for service in SERVICES.iter().filter(|s| **s != "audit") {
            assert!(
                !caller_may(service, FileBrokerOp::RecordingUnlink),
                "{service:?} must not unlink a capture"
            );
        }
    }

    #[test]
    fn attack_unknown_or_lookalike_service_is_rejected_for_everything() {
        for service in ["", "AUDIT", "audit ", "web\0", "proxy_", "supervisor"] {
            for op in FileBrokerOp::ALL {
                assert!(!caller_may(service, op), "{service:?} / {op:?}");
            }
        }
    }

    #[test]
    fn attack_retired_gzip_is_rejected_for_every_service() {
        for service in SERVICES {
            assert!(
                !caller_may(service, FileBrokerOp::RecordingGzip),
                "{service}"
            );
        }
    }

    const SID: &str = "8f1c2a34-5b6d-4e7f-8a9b-0c1d2e3f4a5b";

    const FILES: [&str; 8] = [
        "session.cast",
        "001.mp4",
        "999999.mp4",
        "session.mcp.jsonl",
        "meta.json",
        "session.json",
        "channels/001.pcap",
        "channels/001.pcap.gz",
    ];

    /// A proxy asking for a file of a session it serves.
    fn lease(service: &str, file: &str) -> Option<WriteLease> {
        write_lease(
            service,
            SID,
            &format!("2026/11/{SID}/{file}"),
            Some(service),
        )
    }

    /// Audit asking on behalf of `source`, which serves the session.
    fn on_behalf(source: &str, file: &str) -> Option<WriteLease> {
        audit_lease(source, SID, &format!("2026/11/{SID}/{file}"), Some(source))
    }

    fn granted(decide: impl Fn(&str) -> Option<WriteLease>) -> Vec<(&'static str, WriteLease)> {
        FILES
            .iter()
            .filter_map(|f| decide(f).map(|l| (*f, l)))
            .collect()
    }

    #[test]
    fn test_write_lease_table_is_exactly_the_documented_one() {
        use WriteLease::CreateNew;
        assert_eq!(
            granted(|f| lease("proxy_ssh", f)),
            [("session.cast", CreateNew)]
        );
        assert_eq!(
            granted(|f| lease("proxy_rdp", f)),
            [("001.mp4", CreateNew), ("999999.mp4", CreateNew)]
        );
        assert_eq!(
            granted(|f| lease("proxy_mcp", f)),
            [
                ("session.cast", CreateNew),
                ("session.mcp.jsonl", CreateNew),
                ("meta.json", CreateNew)
            ]
        );
        for service in SERVICES
            .iter()
            .filter(|s| !matches!(**s, "proxy_ssh" | "proxy_rdp" | "proxy_mcp"))
        {
            assert!(granted(|f| lease(service, f)).is_empty(), "{service:?}");
        }
    }

    #[test]
    fn test_audit_lease_table_is_exactly_the_documented_one() {
        use WriteLease::{CreateNew, Rewrite};
        assert_eq!(
            granted(|f| on_behalf("proxy_ssh", f)),
            [("meta.json", CreateNew)]
        );
        assert_eq!(
            granted(|f| on_behalf("proxy_rdp", f)),
            [("meta.json", CreateNew)]
        );
        assert_eq!(
            granted(|f| on_behalf("proxy_iacs", f)),
            [
                ("meta.json", CreateNew),
                ("session.json", Rewrite),
                ("channels/001.pcap", CreateNew),
                ("channels/001.pcap.gz", CreateNew)
            ]
        );
        for source in SERVICES
            .iter()
            .filter(|s| !matches!(**s, "proxy_ssh" | "proxy_rdp" | "proxy_iacs"))
        {
            assert!(granted(|f| on_behalf(source, f)).is_empty(), "{source:?}");
        }
    }

    /// The finding: a proxy naming a session another service serves, or
    /// one that no token was ever accepted for.
    #[test]
    fn attack_proxy_lease_on_a_session_it_does_not_serve_is_rejected() {
        for proxy in ["proxy_ssh", "proxy_rdp", "proxy_mcp"] {
            for owner in [
                None,
                Some("proxy_ssh"),
                Some("proxy_rdp"),
                Some("proxy_mcp"),
                Some("proxy_iacs"),
                Some("audit"),
                Some(""),
            ] {
                if owner == Some(proxy) {
                    continue;
                }
                for file in FILES {
                    assert_eq!(
                        write_lease(proxy, SID, &format!("2026/11/{SID}/{file}"), owner),
                        None,
                        "{proxy} owner={owner:?} {file}"
                    );
                }
            }
        }
    }

    /// The deputy: a proxy has audit write the seal of a session that
    /// another proxy serves.
    #[test]
    fn attack_audit_lease_on_behalf_of_a_proxy_that_does_not_serve_the_session_is_rejected() {
        let seal = format!("2026/11/{SID}/meta.json");
        for source in ["proxy_ssh", "proxy_rdp"] {
            for owner in [
                None,
                Some("proxy_ssh"),
                Some("proxy_rdp"),
                Some("proxy_mcp"),
                Some("proxy_iacs"),
            ] {
                if owner == Some(source) {
                    continue;
                }
                assert_eq!(
                    audit_lease(source, SID, &seal, owner),
                    None,
                    "{source} owner={owner:?}"
                );
            }
        }
        // IACS files in a session another proxy serves.
        for owner in ["proxy_ssh", "proxy_rdp", "proxy_mcp"] {
            for file in FILES {
                assert_eq!(
                    audit_lease(
                        "proxy_iacs",
                        SID,
                        &format!("2026/11/{SID}/{file}"),
                        Some(owner)
                    ),
                    None,
                    "owner={owner} {file}"
                );
            }
        }
    }

    /// IACS writes `session.json` before any token is presented.
    #[test]
    fn test_iacs_files_are_granted_before_the_first_token() {
        for file in ["session.json", "meta.json", "channels/001.pcap"] {
            assert!(
                audit_lease("proxy_iacs", SID, &format!("2026/11/{SID}/{file}"), None).is_some(),
                "{file}"
            );
        }
    }

    /// Invariant: `Rewrite` is granted for IACS `session.json` and
    /// nothing else, whatever the caller, source and owner.
    #[test]
    fn attack_nothing_but_iacs_session_json_is_ever_rewritten() {
        let owners = [
            None,
            Some("proxy_ssh"),
            Some("proxy_rdp"),
            Some("proxy_mcp"),
            Some("proxy_iacs"),
            Some("audit"),
        ];
        for service in SERVICES {
            for owner in owners {
                for file in FILES {
                    let path = format!("2026/11/{SID}/{file}");
                    assert_ne!(
                        write_lease(service, SID, &path, owner),
                        Some(WriteLease::Rewrite),
                        "write_lease {service:?} {owner:?} {file}"
                    );
                    if audit_lease(service, SID, &path, owner) == Some(WriteLease::Rewrite) {
                        assert_eq!((service, file), ("proxy_iacs", "session.json"));
                    }
                }
            }
        }
    }

    #[test]
    fn attack_proxy_naming_another_format_is_rejected() {
        assert_eq!(lease("proxy_ssh", "001.mp4"), None);
        assert_eq!(lease("proxy_ssh", "meta.json"), None);
        assert_eq!(lease("proxy_ssh", "session.mcp.jsonl"), None);
        assert_eq!(lease("proxy_rdp", "session.cast"), None);
        assert_eq!(lease("proxy_rdp", "meta.json"), None);
        assert_eq!(lease("proxy_mcp", "001.mp4"), None);
        assert_eq!(lease("proxy_mcp", "session.json"), None);
        assert_eq!(lease("proxy_ssh", "channels/001.pcap"), None);
        assert_eq!(on_behalf("proxy_ssh", "session.cast"), None);
        assert_eq!(on_behalf("proxy_rdp", "001.mp4"), None);
        assert_eq!(on_behalf("proxy_ssh", "session.json"), None);
        assert_eq!(on_behalf("proxy_iacs", "session.cast"), None);
        assert_eq!(on_behalf("proxy_mcp", "meta.json"), None);
    }

    /// The old anchoring was `relative_path.contains(session_id)`: a
    /// one-character identifier matched the path of any session.
    #[test]
    fn attack_session_id_as_a_substring_of_the_path_is_rejected() {
        let victim = format!("2026/11/{SID}/session.cast");
        for forged in [
            "2", "0", "8f1c", "session", "cast", "11", "2026", "", "/", ".", "..", "2026/11",
        ] {
            assert_eq!(
                write_lease("proxy_ssh", forged, &victim, Some("proxy_ssh")),
                None,
                "{forged:?}"
            );
            assert_eq!(
                audit_lease("proxy_iacs", forged, &victim, None),
                None,
                "{forged:?}"
            );
        }
    }

    #[test]
    fn attack_malformed_write_paths_are_rejected() {
        for path in [
            format!("{SID}/session.cast"),
            format!("2026/{SID}/session.cast"),
            format!("2026/11/x/{SID}/session.cast"),
            format!("2026/11/{SID}/../{SID}/session.cast"),
            format!("2026/11/{SID}/x/session.cast"),
            format!("/2026/11/{SID}/session.cast"),
            format!("2026/11/{SID}//session.cast"),
            format!("2026/11/{SID}/session.cast/"),
            format!("20x6/11/{SID}/session.cast"),
            format!("2026/1/{SID}/session.cast"),
            format!("../11/{SID}/session.cast"),
            format!("2026/11/{SID}"),
            format!("2026/11/{SID}/"),
        ] {
            assert_eq!(
                write_lease("proxy_ssh", SID, &path, Some("proxy_ssh")),
                None,
                "{path}"
            );
        }
        for file in [
            "1.mp4",
            "01.mp4",
            "00a.mp4",
            "001.mp4.blake3",
            ".mp4",
            "12345678901.mp4",
            "-01.mp4",
        ] {
            assert_eq!(lease("proxy_rdp", file), None, "{file}");
        }
        for file in [
            "channels/1.pcap",
            "channels/001.pcapx",
            "channels/001.gz",
            "channels/x/001.pcap",
            "001.pcap",
            "channel/001.pcap",
        ] {
            assert_eq!(on_behalf("proxy_iacs", file), None, "{file}");
        }
    }

    #[test]
    fn test_session_dir_is_the_first_three_components() {
        assert_eq!(
            session_dir(SID, &format!("2026/11/{SID}/channels/001.pcap")).as_deref(),
            Some(format!("2026/11/{SID}").as_str())
        );
    }

    #[test]
    fn attack_unlink_of_anything_but_a_raw_capture_of_the_session_is_rejected() {
        let capture = format!("2026/11/{SID}/channels/001.pcap");
        assert!(is_raw_capture(SID, &capture));
        // The old anchor: a short identifier contained in the path.
        for forged in ["p", "1", "pcap", "channels", "", "2026"] {
            assert!(!is_raw_capture(forged, &capture), "{forged:?}");
        }
        for path in [
            format!("2026/11/{SID}/channels/001.pcap.gz"),
            format!("2026/11/{SID}/001.pcap"),
            format!("2026/11/{SID}/session.cast"),
            format!("2026/11/{SID}/meta.json"),
            format!("2026/11/{SID}/channels/x.pcap"),
            format!("2026/11/{SID}/channels/../channels/001.pcap"),
            "2026/11/other/channels/001.pcap".to_string(),
            format!("2026/11/{SID}"),
        ] {
            assert!(!is_raw_capture(SID, &path), "{path}");
        }
    }

    #[test]
    fn test_numbered_files_past_three_digits_are_accepted() {
        assert_eq!(lease("proxy_rdp", "1000.mp4"), Some(WriteLease::CreateNew));
        assert_eq!(
            on_behalf("proxy_iacs", "channels/4294967295.pcap.gz"),
            Some(WriteLease::CreateNew)
        );
    }
}
