//! JSON control-plane messages (< 4 KiB).

use serde::{Deserialize, Serialize};

pub const MAX_MSG_BYTES: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum StorageRequest {
    Get {
        scope: String,
        /// Expected digest from the Postgres mirror (required).
        sha256: String,
        #[serde(default)]
        release_id: Option<String>,
        #[serde(default)]
        org_id: Option<String>,
        #[serde(default)]
        image_id: Option<String>,
        #[serde(default)]
        ext: Option<String>,
    },
    PutBegin {
        scope: String,
        #[serde(default)]
        release_id: Option<String>,
        #[serde(default)]
        org_id: Option<String>,
        declared_size: u64,
        #[serde(default)]
        ext: Option<String>,
    },
    /// Hash partial + issue WebAuthn challenge (release only). No renameat.
    PutPrepare {
        upload_id: String,
        sha256: String,
        #[serde(default)]
        release_id: Option<String>,
    },
    PutCommit {
        upload_id: String,
        scope: String,
        sha256: String,
        #[serde(default)]
        release_id: Option<String>,
        #[serde(default)]
        org_id: Option<String>,
        #[serde(default)]
        image_id: Option<String>,
        #[serde(default)]
        ext: Option<String>,
        /// WebAuthn assertion JSON (required for release when webauthn_required).
        #[serde(default)]
        assertion: Option<String>,
        #[serde(default)]
        challenge_id: Option<String>,
    },
    PutAbort {
        upload_id: String,
    },
    Stat {
        scope: String,
        /// Expected digest from the Postgres mirror (required).
        sha256: String,
        #[serde(default)]
        release_id: Option<String>,
        #[serde(default)]
        org_id: Option<String>,
        #[serde(default)]
        image_id: Option<String>,
        #[serde(default)]
        ext: Option<String>,
    },
    /// Issue challenge for a gated delete / delete_org.
    ChallengeBegin {
        kind: String,
        #[serde(default)]
        scope: Option<String>,
        #[serde(default)]
        release_id: Option<String>,
        #[serde(default)]
        org_id: Option<String>,
        #[serde(default)]
        image_id: Option<String>,
        #[serde(default)]
        ext: Option<String>,
    },
    Delete {
        scope: String,
        #[serde(default)]
        release_id: Option<String>,
        #[serde(default)]
        org_id: Option<String>,
        #[serde(default)]
        image_id: Option<String>,
        #[serde(default)]
        ext: Option<String>,
        #[serde(default)]
        assertion: Option<String>,
        #[serde(default)]
        challenge_id: Option<String>,
    },
    DeleteOrg {
        org_id: String,
        #[serde(default)]
        assertion: Option<String>,
        #[serde(default)]
        challenge_id: Option<String>,
    },
    KeyEnrolStage {
        credential_id_b64: String,
        public_key_cose_b64: String,
        user_handle: String,
        admin_label: String,
        #[serde(default)]
        is_soft: bool,
    },
    KeyRevoke {
        credential_id_b64: String,
    },
    /// List pending or active KEY credentials (JSON in `summary` field).
    KeyList {
        kind: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_credentials: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

impl StorageResponse {
    pub fn ok_stat(size: u64, sha256: impl Into<String>) -> Self {
        Self {
            ok: true,
            err: None,
            size: Some(size),
            sha256: Some(sha256.into()),
            upload_id: None,
            deleted: None,
            challenge_id: None,
            challenge: None,
            summary: None,
            rp_id: None,
            allow_credentials: None,
            fingerprint: None,
        }
    }

    pub fn ok_upload(upload_id: impl Into<String>) -> Self {
        Self {
            ok: true,
            err: None,
            size: None,
            sha256: None,
            upload_id: Some(upload_id.into()),
            deleted: None,
            challenge_id: None,
            challenge: None,
            summary: None,
            rp_id: None,
            allow_credentials: None,
            fingerprint: None,
        }
    }

    pub fn ok_empty() -> Self {
        Self {
            ok: true,
            err: None,
            size: None,
            sha256: None,
            upload_id: None,
            deleted: None,
            challenge_id: None,
            challenge: None,
            summary: None,
            rp_id: None,
            allow_credentials: None,
            fingerprint: None,
        }
    }

    pub fn ok_deleted(n: u32) -> Self {
        Self {
            ok: true,
            err: None,
            size: None,
            sha256: None,
            upload_id: None,
            deleted: Some(n),
            challenge_id: None,
            challenge: None,
            summary: None,
            rp_id: None,
            allow_credentials: None,
            fingerprint: None,
        }
    }

    pub fn ok_challenge(
        digest: Option<String>,
        challenge_id: impl Into<String>,
        challenge: impl Into<String>,
        summary: impl Into<String>,
        rp_id: impl Into<String>,
        allow_credentials: Vec<String>,
    ) -> Self {
        Self {
            ok: true,
            err: None,
            size: None,
            sha256: digest,
            upload_id: None,
            deleted: None,
            challenge_id: Some(challenge_id.into()),
            challenge: Some(challenge.into()),
            summary: Some(summary.into()),
            rp_id: Some(rp_id.into()),
            allow_credentials: Some(allow_credentials),
            fingerprint: None,
        }
    }

    pub fn ok_fingerprint(fingerprint: impl Into<String>) -> Self {
        Self {
            ok: true,
            err: None,
            size: None,
            sha256: None,
            upload_id: None,
            deleted: None,
            challenge_id: None,
            challenge: None,
            summary: None,
            rp_id: None,
            allow_credentials: None,
            fingerprint: Some(fingerprint.into()),
        }
    }

    pub fn ok_summary(summary: impl Into<String>) -> Self {
        Self {
            ok: true,
            err: None,
            size: None,
            sha256: None,
            upload_id: None,
            deleted: None,
            challenge_id: None,
            challenge: None,
            summary: Some(summary.into()),
            rp_id: None,
            allow_credentials: None,
            fingerprint: None,
        }
    }

    pub fn err(code: impl Into<String>) -> Self {
        Self {
            ok: false,
            err: Some(code.into()),
            size: None,
            sha256: None,
            upload_id: None,
            deleted: None,
            challenge_id: None,
            challenge: None,
            summary: None,
            rp_id: None,
            allow_credentials: None,
            fingerprint: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proptest_util;
    use proptest::prelude::*;

    #[test]
    fn roundtrip_put_begin() {
        let req = StorageRequest::PutBegin {
            scope: "release".into(),
            release_id: Some("1".into()),
            org_id: None,
            declared_size: 100,
            ext: None,
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        assert!(bytes.len() < MAX_MSG_BYTES);
        let back: StorageRequest = serde_json::from_slice(&bytes).unwrap();
        match back {
            StorageRequest::PutBegin { release_id, .. } => {
                assert_eq!(release_id.as_deref(), Some("1"));
            }
            _ => panic!("wrong variant"),
        }
    }

    proptest! {
        #![proptest_config(proptest_util::cases(24))]

        #[test]
        fn prop_err_codes_stable(code in "(not_found|invalid_id|quota|org_quota|bad_image|digest_mismatch|integrity_mismatch|io|busy|webauthn_required|webauthn_invalid|webauthn_expired|challenge_unknown|object_modified)") {
            let resp = StorageResponse::err(code.clone());
            let bytes = serde_json::to_vec(&resp).unwrap();
            prop_assert!(bytes.len() < MAX_MSG_BYTES);
            let back: StorageResponse = serde_json::from_slice(&bytes).unwrap();
            prop_assert!(!back.ok);
            prop_assert_eq!(back.err.as_deref(), Some(code.as_str()));
        }

        #[test]
        fn prop_summary_stable_for_release_put(
            id in "[0-9]{1,6}",
            sha in "[0-9a-f]{64}"
        ) {
            let binding = serde_json::json!({
                "release_id": id,
                "digest": sha,
            });
            let s1 = crate::storage::webauthn::canonical_summary("release_put_commit", &binding);
            let s2 = crate::storage::webauthn::canonical_summary("release_put_commit", &binding);
            prop_assert_eq!(&s1, &s2);
            prop_assert!(s2.contains("release_put_commit"));
            prop_assert!(s2.contains(&id));
        }
    }
}
