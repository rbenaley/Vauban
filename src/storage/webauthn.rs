//! Helper-side WebAuthn / CTAP2 challenge issue + assertion verify (architecture 1.2).

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{EncodedPoint, PublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::audit::WebauthnAudit;
use super::error::{StorageError, StorageErrorCode};
use super::meta_db::{CredentialStatus, MetaDb, WebauthnChallengeRow, WebauthnCredentialRow};

/// Soft test assertion marker (unit / E2E only; never for production keys).
pub const SOFT_ASSERTION_MARKER: &str = "vcp_soft";

#[derive(Debug, Clone)]
pub struct ChallengeIssued {
    pub challenge_id: String,
    pub challenge_b64: String,
    pub summary: String,
    pub rp_id: String,
    pub allow_credentials: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftAssertion {
    pub vcp_soft: u8,
    pub credential_id: String,
    pub challenge_id: String,
    pub uv: bool,
    pub sign_count: u32,
}

#[derive(Debug, Deserialize)]
struct BrowserAssertion {
    id: String,
    #[serde(default, rename = "rawId")]
    raw_id: Option<String>,
    response: BrowserAssertionResponse,
}

#[derive(Debug, Deserialize)]
struct BrowserAssertionResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    signature: String,
    #[serde(default, rename = "userHandle")]
    user_handle: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
    origin: String,
}

/// SHA-256 fingerprint of credential_id || public_key_cose (architecture §5).
pub fn credential_fingerprint(credential_id: &[u8], public_key_cose: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(credential_id);
    hasher.update(public_key_cose);
    hex::encode(hasher.finalize())
}

/// CTAP2 admin key label: trim; reject empty / whitespace-only.
pub fn normalize_admin_label(raw: &str) -> Option<&str> {
    let label = raw.trim();
    if label.is_empty() { None } else { Some(label) }
}

/// Mirror of `isIpHostname` in `assets/vcp_webauthn.js` (WebAuthn RP ID rule).
pub fn webauthn_host_is_ip(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    if host == "::1" || host.contains(':') {
        return true;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        p.parse::<u16>().is_ok_and(|n| n <= 255)
    })
}

pub fn canonical_summary(op: &str, binding: &Value) -> String {
    match op {
        "release_put_commit" => {
            let id = binding
                .get("release_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let sha = binding
                .get("digest")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let short = if sha.len() >= 12 { &sha[..12] } else { sha };
            format!("release_put_commit id={id} sha256={short}…")
        }
        "delete" => {
            let scope = binding.get("scope").and_then(|v| v.as_str()).unwrap_or("?");
            let sha = binding
                .get("sha256")
                .and_then(|v| v.as_str())
                .map(|s| {
                    if s.len() >= 12 {
                        format!(" sha256={}…", &s[..12])
                    } else {
                        format!(" sha256={s}")
                    }
                })
                .unwrap_or_default();
            if scope == "release" {
                let id = binding
                    .get("release_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                format!("delete release id={id}{sha}")
            } else {
                let org = binding
                    .get("org_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let img = binding
                    .get("image_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                format!("delete image org={org} id={img}{sha}")
            }
        }
        "delete_org" => {
            let org = binding
                .get("org_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            format!("delete_org org_id={org}")
        }
        other => format!("{other} {binding}"),
    }
}

pub fn issue_challenge(
    db: &MetaDb,
    audit: &WebauthnAudit,
    op: &str,
    binding: Value,
    ttl_secs: u64,
    rp_id: &str,
) -> Result<ChallengeIssued, StorageError> {
    let _ = db.purge_expired_challenges()?;
    let challenge_id = Uuid::new_v4().to_string();
    let challenge_bytes: [u8; 32] = {
        let mut buf = [0u8; 32];
        getrandom_compat(&mut buf);
        buf
    };
    let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge_bytes);
    let summary = canonical_summary(op, &binding);
    let expires_at = now_unix().saturating_add(ttl_secs.max(1) as i64);
    let binding_json = serde_json::to_string(&binding)
        .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("binding json: {e}")))?;
    db.insert_challenge(&WebauthnChallengeRow {
        challenge_id: challenge_id.clone(),
        op: op.to_owned(),
        binding_json,
        summary: summary.clone(),
        challenge_b64: challenge_b64.clone(),
        expires_at,
        consumed_at: None,
    })?;
    let allow = db
        .list_active_credentials()?
        .into_iter()
        .map(|c| URL_SAFE_NO_PAD.encode(&c.credential_id))
        .collect();
    let _ = audit.append(
        "challenge_issued",
        json!({
            "challenge_id": challenge_id,
            "op": op,
            "summary": summary,
            "binding": binding,
        }),
    );
    Ok(ChallengeIssued {
        challenge_id,
        challenge_b64,
        summary,
        rp_id: rp_id.to_owned(),
        allow_credentials: allow,
    })
}

pub fn drop_challenge_for_upload(db: &MetaDb, upload_id: &str) -> Result<(), StorageError> {
    db.delete_challenges_matching_upload(upload_id)
}

/// Verify assertion and consume the challenge. Returns credential_id on success.
#[allow(clippy::too_many_arguments)] // closed verify checklist (architecture §6.4)
pub fn verify_and_consume(
    db: &MetaDb,
    audit: &WebauthnAudit,
    assertion_json: &str,
    expected_op: &str,
    expected_binding: &Value,
    rp_id: &str,
    origin: &str,
    strict_sign_count: bool,
    require_uv: bool,
) -> Result<Vec<u8>, StorageError> {
    if let Ok(soft) = serde_json::from_str::<SoftAssertion>(assertion_json)
        && soft.vcp_soft == 1
    {
        return verify_soft(
            db,
            audit,
            &soft,
            expected_op,
            expected_binding,
            strict_sign_count,
            require_uv,
        );
    }
    verify_browser(
        db,
        audit,
        assertion_json,
        expected_op,
        expected_binding,
        rp_id,
        origin,
        strict_sign_count,
        require_uv,
    )
}

fn verify_soft(
    db: &MetaDb,
    audit: &WebauthnAudit,
    soft: &SoftAssertion,
    expected_op: &str,
    expected_binding: &Value,
    strict_sign_count: bool,
    require_uv: bool,
) -> Result<Vec<u8>, StorageError> {
    if require_uv && !soft.uv {
        let _ = audit.append("verify_fail", json!({"reason": "uv_missing", "soft": true}));
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "uv required",
        ));
    }
    let cred_id = hex::decode(soft.credential_id.trim())
        .map_err(|_| StorageError::new(StorageErrorCode::WebauthnInvalid, "credential_id hex"))?;
    let row = db
        .get_credential(&cred_id)?
        .ok_or_else(|| StorageError::new(StorageErrorCode::WebauthnInvalid, "unknown cred"))?;
    if row.status != CredentialStatus::Active || row.revoked_at.is_some() {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "not active",
        ));
    }
    if !row.is_soft {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "soft assertion for non-soft cred",
        ));
    }
    let ch = load_and_check_challenge(db, &soft.challenge_id, expected_op, expected_binding)?;
    apply_sign_count(db, audit, &row, soft.sign_count, strict_sign_count)?;
    db.consume_challenge(&ch.challenge_id)?;
    let _ = audit.append(
        "verify_ok",
        json!({
            "soft": true,
            "challenge_id": soft.challenge_id,
            "summary": ch.summary,
        }),
    );
    Ok(cred_id)
}

#[allow(clippy::too_many_arguments)] // mirrors verify_and_consume surface
fn verify_browser(
    db: &MetaDb,
    audit: &WebauthnAudit,
    assertion_json: &str,
    expected_op: &str,
    expected_binding: &Value,
    rp_id: &str,
    origin: &str,
    strict_sign_count: bool,
    require_uv: bool,
) -> Result<Vec<u8>, StorageError> {
    let assertion: BrowserAssertion = serde_json::from_str(assertion_json)
        .map_err(|_| StorageError::new(StorageErrorCode::WebauthnInvalid, "assertion json"))?;
    let cred_id = b64url_decode(&assertion.id).or_else(|_| {
        assertion
            .raw_id
            .as_deref()
            .map(b64url_decode)
            .transpose()
            .ok()
            .flatten()
            .ok_or_else(|| StorageError::new(StorageErrorCode::WebauthnInvalid, "rawId"))
    })?;
    let row = db
        .get_credential(&cred_id)?
        .ok_or_else(|| StorageError::new(StorageErrorCode::WebauthnInvalid, "unknown cred"))?;
    if row.status != CredentialStatus::Active || row.revoked_at.is_some() {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "not active",
        ));
    }
    let client_data_raw = b64url_decode(&assertion.response.client_data_json)?;
    let client: ClientData = serde_json::from_slice(&client_data_raw)
        .map_err(|_| StorageError::new(StorageErrorCode::WebauthnInvalid, "clientDataJSON"))?;
    if client.typ != "webauthn.get" {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "clientData type",
        ));
    }
    if client.origin != origin {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "origin",
        ));
    }
    let ch = db
        .get_challenge_by_b64(&client.challenge)?
        .ok_or_else(|| StorageError::new(StorageErrorCode::ChallengeUnknown, "challenge"))?;
    check_challenge_row(&ch, expected_op, expected_binding)?;
    let auth_data = b64url_decode(&assertion.response.authenticator_data)?;
    if auth_data.len() < 37 {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "authenticatorData short",
        ));
    }
    let mut rp_hasher = Sha256::new();
    rp_hasher.update(rp_id.as_bytes());
    let rp_hash = rp_hasher.finalize();
    if auth_data[..32] != rp_hash[..] {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "rpIdHash",
        ));
    }
    let flags = auth_data[32];
    let uv = (flags & 0x04) != 0;
    if require_uv && !uv {
        let _ = audit.append("verify_fail", json!({"reason": "uv_missing"}));
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "uv required",
        ));
    }
    let sign_count =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    let sig = b64url_decode(&assertion.response.signature)?;
    let mut client_hash = Sha256::new();
    client_hash.update(&client_data_raw);
    let client_hash = client_hash.finalize();
    let mut msg = Vec::with_capacity(auth_data.len() + 32);
    msg.extend_from_slice(&auth_data);
    msg.extend_from_slice(&client_hash);
    verify_cose_es256(&row.public_key_cose, &msg, &sig)?;
    let _ = assertion.response.user_handle;
    apply_sign_count(db, audit, &row, sign_count, strict_sign_count)?;
    db.consume_challenge(&ch.challenge_id)?;
    let _ = audit.append(
        "verify_ok",
        json!({
            "challenge_id": ch.challenge_id,
            "summary": ch.summary,
        }),
    );
    Ok(cred_id)
}

fn load_and_check_challenge(
    db: &MetaDb,
    challenge_id: &str,
    expected_op: &str,
    expected_binding: &Value,
) -> Result<WebauthnChallengeRow, StorageError> {
    let ch = db
        .get_challenge(challenge_id)?
        .ok_or_else(|| StorageError::new(StorageErrorCode::ChallengeUnknown, "challenge"))?;
    check_challenge_row(&ch, expected_op, expected_binding)?;
    Ok(ch)
}

fn check_challenge_row(
    ch: &WebauthnChallengeRow,
    expected_op: &str,
    expected_binding: &Value,
) -> Result<(), StorageError> {
    if ch.consumed_at.is_some() {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "challenge consumed",
        ));
    }
    if ch.expires_at < now_unix() {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnExpired,
            "challenge expired",
        ));
    }
    if ch.op != expected_op {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "op mismatch",
        ));
    }
    let bound: Value = serde_json::from_str(&ch.binding_json)
        .map_err(|_| StorageError::new(StorageErrorCode::Io, "binding parse"))?;
    if !bindings_match(&bound, expected_binding) {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "binding mismatch",
        ));
    }
    Ok(())
}

fn bindings_match(stored: &Value, expected: &Value) -> bool {
    // Expected may be a subset; require all expected keys equal.
    let Some(exp) = expected.as_object() else {
        return stored == expected;
    };
    let Some(st) = stored.as_object() else {
        return false;
    };
    for (k, v) in exp {
        if st.get(k) != Some(v) {
            return false;
        }
    }
    true
}

fn apply_sign_count(
    db: &MetaDb,
    audit: &WebauthnAudit,
    row: &WebauthnCredentialRow,
    new_count: u32,
    strict: bool,
) -> Result<(), StorageError> {
    if strict && row.sign_count > 0 && new_count < row.sign_count {
        let _ = audit.append(
            "verify_fail",
            json!({
                "reason": "sign_count_regression",
                "stored": row.sign_count,
                "presented": new_count,
            }),
        );
        tracing::error!(
            target: crate::storage::STORE_ALERT_TARGET,
            stored = row.sign_count,
            presented = new_count,
            "ALERT webauthn sign_count regression"
        );
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "sign_count regression",
        ));
    }
    if new_count > 0 {
        db.update_sign_count(&row.credential_id, new_count)?;
    }
    Ok(())
}

/// Verify ES256 COSE_Key over message.
fn verify_cose_es256(cose: &[u8], msg: &[u8], sig_der_or_raw: &[u8]) -> Result<(), StorageError> {
    let (x, y) = parse_cose_p256(cose)?;
    let mut encoded = [0u8; 65];
    encoded[0] = 0x04;
    encoded[1..33].copy_from_slice(&x);
    encoded[33..65].copy_from_slice(&y);
    let point = EncodedPoint::from_bytes(encoded)
        .map_err(|_| StorageError::new(StorageErrorCode::WebauthnInvalid, "pubkey point"))?;
    let pk = PublicKey::from_encoded_point(&point);
    let pk = if bool::from(pk.is_some()) {
        pk.unwrap()
    } else {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "pubkey",
        ));
    };
    let vk = VerifyingKey::from(pk);
    let sig = if sig_der_or_raw.len() == 64 {
        Signature::from_slice(sig_der_or_raw)
            .map_err(|_| StorageError::new(StorageErrorCode::WebauthnInvalid, "sig raw"))?
    } else {
        Signature::from_der(sig_der_or_raw)
            .map_err(|_| StorageError::new(StorageErrorCode::WebauthnInvalid, "sig der"))?
    };
    vk.verify(msg, &sig)
        .map_err(|_| StorageError::new(StorageErrorCode::WebauthnInvalid, "signature"))?;
    Ok(())
}

/// Minimal COSE_Key map parser for EC2 P-256 (-7).
fn parse_cose_p256(cose: &[u8]) -> Result<([u8; 32], [u8; 32]), StorageError> {
    // Expect CBOR map with keys 1,3,-1,-2,-3 (major type 5).
    if cose.is_empty() {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "empty cose",
        ));
    }
    let first = cose[0];
    if (first >> 5) != 5 {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "cose not map",
        ));
    }
    let (len, mut i) = read_cbor_len(cose, 0)?;
    let mut x = None;
    let mut y = None;
    for _ in 0..len {
        let (key, ni) = read_cbor_int(cose, i)?;
        i = ni;
        match key {
            -2 => {
                let (bytes, ni) = read_cbor_bstr(cose, i)?;
                i = ni;
                if bytes.len() != 32 {
                    return Err(StorageError::new(
                        StorageErrorCode::WebauthnInvalid,
                        "cose x",
                    ));
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(bytes);
                x = Some(a);
            }
            -3 => {
                let (bytes, ni) = read_cbor_bstr(cose, i)?;
                i = ni;
                if bytes.len() != 32 {
                    return Err(StorageError::new(
                        StorageErrorCode::WebauthnInvalid,
                        "cose y",
                    ));
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(bytes);
                y = Some(a);
            }
            _ => {
                i = skip_cbor(cose, i)?;
            }
        }
    }
    match (x, y) {
        (Some(x), Some(y)) => Ok((x, y)),
        _ => Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "cose missing xy",
        )),
    }
}

fn read_cbor_len(data: &[u8], i: usize) -> Result<(usize, usize), StorageError> {
    let b = *data
        .get(i)
        .ok_or_else(|| StorageError::new(StorageErrorCode::WebauthnInvalid, "cbor eof"))?;
    let ai = b & 0x1f;
    match ai {
        n @ 0..=23 => Ok((n as usize, i + 1)),
        24 => {
            let v = *data
                .get(i + 1)
                .ok_or_else(|| StorageError::new(StorageErrorCode::WebauthnInvalid, "cbor len"))?;
            Ok((v as usize, i + 2))
        }
        _ => Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "cbor len unsupported",
        )),
    }
}

fn read_cbor_int(data: &[u8], i: usize) -> Result<(i64, usize), StorageError> {
    let b = *data
        .get(i)
        .ok_or_else(|| StorageError::new(StorageErrorCode::WebauthnInvalid, "cbor eof"))?;
    let major = b >> 5;
    let (n, ni) = read_cbor_len(data, i)?;
    match major {
        0 => Ok((n as i64, ni)),
        1 => Ok((-1 - (n as i64), ni)),
        _ => Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "cbor int",
        )),
    }
}

fn read_cbor_bstr(data: &[u8], i: usize) -> Result<(&[u8], usize), StorageError> {
    let b = *data
        .get(i)
        .ok_or_else(|| StorageError::new(StorageErrorCode::WebauthnInvalid, "cbor eof"))?;
    if (b >> 5) != 2 {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "cbor bstr",
        ));
    }
    let (len, ni) = read_cbor_len(data, i)?;
    let end = ni.saturating_add(len);
    if end > data.len() {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "cbor bstr eof",
        ));
    }
    Ok((&data[ni..end], end))
}

fn skip_cbor(data: &[u8], i: usize) -> Result<usize, StorageError> {
    let b = *data
        .get(i)
        .ok_or_else(|| StorageError::new(StorageErrorCode::WebauthnInvalid, "cbor eof"))?;
    let major = b >> 5;
    match major {
        0 | 1 => {
            let (_, ni) = read_cbor_len(data, i)?;
            Ok(ni)
        }
        2 | 3 => {
            let (len, ni) = read_cbor_len(data, i)?;
            Ok(ni + len)
        }
        4 => {
            let (len, mut ni) = read_cbor_len(data, i)?;
            for _ in 0..len {
                ni = skip_cbor(data, ni)?;
            }
            Ok(ni)
        }
        5 => {
            let (len, mut ni) = read_cbor_len(data, i)?;
            for _ in 0..len {
                ni = skip_cbor(data, ni)?;
                ni = skip_cbor(data, ni)?;
            }
            Ok(ni)
        }
        _ => Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "cbor skip",
        )),
    }
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, StorageError> {
    URL_SAFE_NO_PAD
        .decode(s.trim())
        .or_else(|_| STANDARD.decode(s.trim()))
        .map_err(|_| StorageError::new(StorageErrorCode::WebauthnInvalid, "b64"))
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn getrandom_compat(buf: &mut [u8]) {
    // Prefer OS randomness via uuid's rng path; fall back to time mix.
    for (i, b) in buf.iter_mut().enumerate() {
        let u = Uuid::new_v4();
        *b = u.as_bytes()[i % 16];
    }
}

/// Extract credential_id + COSE key from a WebAuthn attestationObject (create).
pub fn extract_attested_credential(
    attestation_object_b64: &str,
) -> Result<(Vec<u8>, Vec<u8>), StorageError> {
    let att = b64url_decode(attestation_object_b64)?;
    // Find authData bstr in CBOR map (key "authData").
    let auth = find_cbor_map_bstr(&att, b"authData")?;
    if auth.len() < 55 {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "authData short",
        ));
    }
    let flags = auth[32];
    if (flags & 0x40) == 0 {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "no attested cred",
        ));
    }
    let mut i = 37; // after rpHash+flags+signCount
    i += 16; // aaguid
    if i + 2 > auth.len() {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "credLen",
        ));
    }
    let cred_len = u16::from_be_bytes([auth[i], auth[i + 1]]) as usize;
    i += 2;
    if i + cred_len > auth.len() {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "credId",
        ));
    }
    let cred_id = auth[i..i + cred_len].to_vec();
    i += cred_len;
    let cose = auth[i..].to_vec();
    if cose.is_empty() {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "cose empty",
        ));
    }
    Ok((cred_id, cose))
}

fn find_cbor_map_bstr<'a>(data: &'a [u8], key: &[u8]) -> Result<&'a [u8], StorageError> {
    if data.is_empty() || (data[0] >> 5) != 5 {
        return Err(StorageError::new(
            StorageErrorCode::WebauthnInvalid,
            "att not map",
        ));
    }
    let (len, mut i) = read_cbor_len(data, 0)?;
    for _ in 0..len {
        let b = *data
            .get(i)
            .ok_or_else(|| StorageError::new(StorageErrorCode::WebauthnInvalid, "cbor eof"))?;
        if (b >> 5) == 3 {
            let (klen, ni) = read_cbor_len(data, i)?;
            let kend = ni + klen;
            let k = &data[ni..kend];
            i = kend;
            if k == key {
                return read_cbor_bstr(data, i).map(|(v, _)| v);
            }
            i = skip_cbor(data, i)?;
        } else {
            i = skip_cbor(data, i)?;
            i = skip_cbor(data, i)?;
        }
    }
    Err(StorageError::new(
        StorageErrorCode::WebauthnInvalid,
        "authData missing",
    ))
}

/// Minimal CBOR attestationObject (authData only) for portal enrol E2E / unit tests.
pub fn test_attestation_object_b64(cred_id: &[u8], cose: &[u8]) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let mut auth = Vec::with_capacity(55 + cred_id.len() + cose.len());
    auth.extend_from_slice(&[0u8; 32]); // rpIdHash
    auth.push(0x40); // AT flag
    auth.extend_from_slice(&[0u8; 4]); // signCount
    auth.extend_from_slice(&[0u8; 16]); // aaguid
    let cred_len = u16::try_from(cred_id.len()).unwrap_or(u16::MAX);
    auth.extend_from_slice(&cred_len.to_be_bytes());
    auth.extend_from_slice(cred_id);
    auth.extend_from_slice(cose);

    let mut cbor = Vec::new();
    cbor.push(0xa1); // map(1)
    cbor.push(0x68); // text(8)
    cbor.extend_from_slice(b"authData");
    encode_cbor_bstr(&mut cbor, &auth);
    URL_SAFE_NO_PAD.encode(cbor)
}

fn encode_cbor_bstr(out: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.len() < 24 {
        out.push(0x40 | (bytes.len() as u8));
    } else if bytes.len() < 256 {
        out.push(0x58);
        out.push(bytes.len() as u8);
    } else {
        out.push(0x59);
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

/// Encode a soft assertion for tests.
pub fn soft_assertion_json(
    credential_id: &[u8],
    challenge_id: &str,
    uv: bool,
    sign_count: u32,
) -> String {
    serde_json::to_string(&SoftAssertion {
        vcp_soft: 1,
        credential_id: hex::encode(credential_id),
        challenge_id: challenge_id.to_owned(),
        uv,
        sign_count,
    })
    .expect("soft assertion json")
}

/// Build a COSE_Key for a P-256 verifying key (tests / soft enrol).
pub fn cose_key_from_p256(vk: &VerifyingKey) -> Vec<u8> {
    let point = vk.to_encoded_point(false);
    let x = point.x().expect("x");
    let y = point.y().expect("y");
    // CBOR map(5): 1:2, 3:-7, -1:1, -2:x, -3:y
    let mut out = Vec::with_capacity(77);
    out.push(0xa5); // map 5
    out.push(0x01);
    out.push(0x02); // kty EC2
    out.push(0x03);
    out.push(0x26); // alg ES256 (-7)
    out.push(0x20);
    out.push(0x01); // crv P-256
    out.push(0x21);
    out.push(0x58);
    out.push(0x20);
    out.extend_from_slice(x);
    out.push(0x22);
    out.push(0x58);
    out.push(0x20);
    out.extend_from_slice(y);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::meta_db::MetaDb;
    use p256::ecdsa::SigningKey;
    use tempfile::tempdir;

    #[test]
    fn fingerprint_stable() {
        let fp = credential_fingerprint(b"cred", b"cose");
        assert_eq!(fp.len(), 64);
        assert_eq!(fp, credential_fingerprint(b"cred", b"cose"));
        assert_ne!(fp, credential_fingerprint(b"cred", b"cose2"));
    }

    #[test]
    fn normalize_admin_label_trims_and_rejects_blank() {
        assert_eq!(normalize_admin_label(""), None);
        assert_eq!(normalize_admin_label("   \t\n"), None);
        assert_eq!(normalize_admin_label("  Yubi-1  "), Some("Yubi-1"));
    }

    #[test]
    fn webauthn_host_is_ip_matches_js_contract() {
        assert!(webauthn_host_is_ip("127.0.0.1"));
        assert!(webauthn_host_is_ip("::1"));
        assert!(webauthn_host_is_ip("2001:db8::1"));
        assert!(!webauthn_host_is_ip("localhost"));
        assert!(!webauthn_host_is_ip("access.vauban.sh"));
        assert!(!webauthn_host_is_ip("127.0.0.256"));
    }

    #[test]
    fn test_attestation_roundtrip_extract() {
        let cred = b"cred-e2e-01";
        let cose = b"cose-bytes";
        let b64 = test_attestation_object_b64(cred, cose);
        let (got_id, got_cose) = extract_attested_credential(&b64).unwrap();
        assert_eq!(got_id, cred);
        assert_eq!(got_cose, cose);
    }

    #[test]
    fn canonical_summary_release_and_delete_shapes() {
        let release = canonical_summary(
            "release_put_commit",
            &json!({"release_id": "42", "digest": "abcdef0123456789"}),
        );
        assert_eq!(release, "release_put_commit id=42 sha256=abcdef012345…");
        let org = canonical_summary("delete_org", &json!({"org_id": "7"}));
        assert_eq!(org, "delete_org org_id=7");
    }

    #[test]
    fn soft_uv_required() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(dir.path()).unwrap();
        let audit = WebauthnAudit::open(dir.path()).unwrap();
        let cred_id = b"softcred01".to_vec();
        let cose = b"soft-cose".to_vec();
        db.insert_credential(&WebauthnCredentialRow {
            credential_id: cred_id.clone(),
            public_key_cose: cose,
            user_handle: "admin".into(),
            admin_label: "t".into(),
            sign_count: 0,
            status: CredentialStatus::Active,
            is_soft: true,
            created_at: now_unix(),
            activated_at: Some(now_unix()),
            revoked_at: None,
        })
        .unwrap();
        let issued = issue_challenge(
            &db,
            &audit,
            "delete_org",
            json!({"org_id": "1"}),
            300,
            "localhost",
        )
        .unwrap();
        let bad = soft_assertion_json(&cred_id, &issued.challenge_id, false, 0);
        let err = verify_and_consume(
            &db,
            &audit,
            &bad,
            "delete_org",
            &json!({"org_id": "1"}),
            "localhost",
            "https://localhost",
            false,
            true,
        )
        .unwrap_err();
        assert_eq!(err.code, StorageErrorCode::WebauthnInvalid);
        let good = soft_assertion_json(&cred_id, &issued.challenge_id, true, 0);
        verify_and_consume(
            &db,
            &audit,
            &good,
            "delete_org",
            &json!({"org_id": "1"}),
            "localhost",
            "https://localhost",
            false,
            true,
        )
        .unwrap();
    }

    #[test]
    fn strict_sign_count_rejects_regression() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(dir.path()).unwrap();
        let audit = WebauthnAudit::open(dir.path()).unwrap();
        let cred_id = b"softcred02".to_vec();
        db.insert_credential(&WebauthnCredentialRow {
            credential_id: cred_id.clone(),
            public_key_cose: b"c".to_vec(),
            user_handle: "a".into(),
            admin_label: "t".into(),
            sign_count: 5,
            status: CredentialStatus::Active,
            is_soft: true,
            created_at: now_unix(),
            activated_at: Some(now_unix()),
            revoked_at: None,
        })
        .unwrap();
        let issued = issue_challenge(
            &db,
            &audit,
            "delete_org",
            json!({"org_id": "2"}),
            300,
            "localhost",
        )
        .unwrap();
        let a = soft_assertion_json(&cred_id, &issued.challenge_id, true, 3);
        let err = verify_and_consume(
            &db,
            &audit,
            &a,
            "delete_org",
            &json!({"org_id": "2"}),
            "localhost",
            "https://localhost",
            true,
            true,
        )
        .unwrap_err();
        assert_eq!(err.code, StorageErrorCode::WebauthnInvalid);
    }

    #[test]
    fn permissive_accepts_zero_sign_count() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(dir.path()).unwrap();
        let audit = WebauthnAudit::open(dir.path()).unwrap();
        let cred_id = b"softcred03".to_vec();
        db.insert_credential(&WebauthnCredentialRow {
            credential_id: cred_id.clone(),
            public_key_cose: b"c".to_vec(),
            user_handle: "a".into(),
            admin_label: "t".into(),
            sign_count: 0,
            status: CredentialStatus::Active,
            is_soft: true,
            created_at: now_unix(),
            activated_at: Some(now_unix()),
            revoked_at: None,
        })
        .unwrap();
        let issued = issue_challenge(
            &db,
            &audit,
            "delete_org",
            json!({"org_id": "3"}),
            300,
            "localhost",
        )
        .unwrap();
        let a = soft_assertion_json(&cred_id, &issued.challenge_id, true, 0);
        verify_and_consume(
            &db,
            &audit,
            &a,
            "delete_org",
            &json!({"org_id": "3"}),
            "localhost",
            "https://localhost",
            false,
            true,
        )
        .unwrap();
    }

    #[test]
    fn cose_roundtrip_parse() {
        let sk = SigningKey::from_slice(&[7u8; 32]).expect("sk");
        let vk = VerifyingKey::from(&sk);
        let cose = cose_key_from_p256(&vk);
        let (x, y) = parse_cose_p256(&cose).unwrap();
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);
    }
}
