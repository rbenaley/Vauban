//! JSON control-plane messages (< 4 KiB).

use serde::{Deserialize, Serialize};

pub const MAX_MSG_BYTES: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum StorageRequest {
    Get {
        scope: String,
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
    },
    PutAbort {
        upload_id: String,
    },
    Stat {
        scope: String,
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
    },
    DeleteOrg {
        org_id: String,
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
        fn prop_err_codes_stable(code in "(not_found|invalid_id|quota|org_quota|bad_image|digest_mismatch|io|busy)") {
            let resp = StorageResponse::err(code.clone());
            let bytes = serde_json::to_vec(&resp).unwrap();
            prop_assert!(bytes.len() < MAX_MSG_BYTES);
            let back: StorageResponse = serde_json::from_slice(&bytes).unwrap();
            prop_assert!(!back.ok);
            prop_assert_eq!(back.err.as_deref(), Some(code.as_str()));
        }
    }
}
