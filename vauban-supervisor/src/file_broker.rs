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
//! What this table does NOT do: it decides by service, not by session. A
//! service allowed to write recordings may ask for the file of any
//! session whose path is well formed, and the write lease opens the file
//! read-write and truncates it. A compromised proxy can therefore still
//! truncate, and then read what is appended to, the recording of a
//! session it does not serve. Closing that needs the supervisor to know
//! which service owns which session; it is tracked as an open finding.

/// A file operation a service can request from the supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileBrokerOp {
    /// `RecordingFileRequest { read_only: false }`: create or append to a
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
}
