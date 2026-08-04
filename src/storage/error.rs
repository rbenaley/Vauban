//! Closed error codes for storage IPC / engine (architecture 1.2 §6.8).

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageErrorCode {
    NotFound,
    InvalidId,
    Quota,
    OrgQuota,
    BadImage,
    DigestMismatch,
    /// Postgres mirror / expected hash vs SQLite SoT or disk re-hash mismatch.
    IntegrityMismatch,
    Io,
    Busy,
    WebauthnRequired,
    WebauthnInvalid,
    WebauthnExpired,
    ChallengeUnknown,
    ObjectModified,
}

impl StorageErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::InvalidId => "invalid_id",
            Self::Quota => "quota",
            Self::OrgQuota => "org_quota",
            Self::BadImage => "bad_image",
            Self::DigestMismatch => "digest_mismatch",
            Self::IntegrityMismatch => "integrity_mismatch",
            Self::Io => "io",
            Self::Busy => "busy",
            Self::WebauthnRequired => "webauthn_required",
            Self::WebauthnInvalid => "webauthn_invalid",
            Self::WebauthnExpired => "webauthn_expired",
            Self::ChallengeUnknown => "challenge_unknown",
            Self::ObjectModified => "object_modified",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "not_found" => Some(Self::NotFound),
            "invalid_id" => Some(Self::InvalidId),
            "quota" => Some(Self::Quota),
            "org_quota" => Some(Self::OrgQuota),
            "bad_image" => Some(Self::BadImage),
            "digest_mismatch" => Some(Self::DigestMismatch),
            "integrity_mismatch" => Some(Self::IntegrityMismatch),
            "io" => Some(Self::Io),
            "busy" => Some(Self::Busy),
            "webauthn_required" => Some(Self::WebauthnRequired),
            "webauthn_invalid" => Some(Self::WebauthnInvalid),
            "webauthn_expired" => Some(Self::WebauthnExpired),
            "challenge_unknown" => Some(Self::ChallengeUnknown),
            "object_modified" => Some(Self::ObjectModified),
            _ => None,
        }
    }
}

impl fmt::Display for StorageErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct StorageError {
    pub code: StorageErrorCode,
    pub message: String,
}

impl StorageError {
    pub fn new(code: StorageErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for StorageError {}
