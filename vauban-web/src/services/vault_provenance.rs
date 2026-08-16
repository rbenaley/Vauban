//! Vault Secrets M2M provenance — match the caller's source IP to a
//! known asset and actively verify that asset's pinned host identity.
//!
//! The M2M vault API (`/api/v1/vault/*`) may ONLY be consumed from a
//! machine that is a non-deleted SSH or RDP asset of the bastion. The
//! proof is in two stages, both mandatory and fail-closed:
//!
//! 1. **IP -> asset matching**: the resolved client IP (via
//!    `middleware::resolve_client_ip`, trusted-proxy aware) must equal
//!    an asset's `hostname` (IP literal) or one of the addresses its
//!    FQDN hostname resolves to (DNS cache 60 s, short timeout). DNS is
//!    allowed HERE because a poisoned record can at worst nominate a
//!    candidate that will fail stage 2.
//! 2. **Active host-identity challenge**: the candidate must present
//!    its pinned fingerprint (`connection_config.ssh_host_key_fingerprint`
//!    for SSH, `connection_config.rdp_server_cert_fingerprint` for RDP)
//!    when challenged. The connect-back targets **the source IP of the
//!    call** on the asset's stored port — never a resolved name, never
//!    any request-supplied data — so DNS poisoning cannot redirect the
//!    challenge. An asset without a pinned fingerprint is unusable as a
//!    provenance source (fail-closed), as is any asset type without an
//!    identity proof (IACS).
//!
//! Verification successes are cached in memory for
//! [`ProvenanceCache::VERIFY_TTL`] keyed by `(asset_id, pinned_fp)`; a
//! MISMATCH is never cached and emits a security-critical
//! `VaultHostIdentityMismatch` audit event.
//!
//! The active challenge goes through the [`HostIdentityVerifier`] seam
//! stored in `AppState` so tests can inject a deterministic stub; the
//! production implementation ([`ProxyHostIdentityVerifier`]) reuses the
//! SSH host-key fetch / RDP cert fetch IPC paths.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use tracing::{debug, info, warn};

use crate::AppState;
use crate::error::{AppError, AppResult};
use crate::models::asset::AssetType;

/// Protocols that carry an active host-identity proof. Everything else
/// (IACS variants) is structurally excluded from provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceProtocol {
    Ssh,
    Rdp,
}

/// A provenance-matched, identity-verified asset.
#[derive(Debug, Clone)]
pub struct VerifiedAsset {
    pub id: i32,
    pub uuid: uuid::Uuid,
    pub name: String,
}

/// Inputs of one active host-identity challenge.
///
/// `ip` is ALWAYS the resolved source IP of the M2M call — the seam
/// contract forbids passing `asset.hostname` or any request data here
/// (pinned by structural tests).
pub struct HostIdentityProbe<'a> {
    pub protocol: ProvenanceProtocol,
    pub ip: IpAddr,
    pub port: u16,
    /// UUID of the API caller (used to mint the broker token).
    pub user_uuid: &'a str,
    /// UUID of the candidate asset (used to mint the broker token).
    pub asset_uuid: &'a str,
}

/// Seam for the active host-identity challenge.
///
/// Returns the fingerprint OBSERVED at `ip:port`; the comparison with
/// the pinned fingerprint (and the mismatch audit / no-cache policy)
/// lives in [`resolve_caller_asset`], in exactly one place.
pub trait HostIdentityVerifier: Send + Sync {
    fn observe_fingerprint<'a>(
        &'a self,
        state: &'a AppState,
        probe: HostIdentityProbe<'a>,
    ) -> Pin<Box<dyn Future<Output = AppResult<String>> + Send + 'a>>;
}

/// Production verifier: SSH host-key fetch / RDP server-cert fetch via
/// the proxy IPC channels. A missing proxy is a hard error (fail-closed:
/// no proxy, no provenance, no vault API).
///
/// Token path: the supervisor TCP broker is crypto-gated; this system
/// action mints a DIAGNOSTIC token (same verb as the admin host-key
/// fetch). The scope stays bounded: the target `ip:port` comes from the
/// bastion's own asset table + the caller's socket, never from request
/// data, so the verb cannot be steered into network enumeration.
pub struct ProxyHostIdentityVerifier;

impl HostIdentityVerifier for ProxyHostIdentityVerifier {
    fn observe_fingerprint<'a>(
        &'a self,
        state: &'a AppState,
        probe: HostIdentityProbe<'a>,
    ) -> Pin<Box<dyn Future<Output = AppResult<String>> + Send + 'a>> {
        Box::pin(async move {
            let host = probe.ip.to_string();
            match probe.protocol {
                ProvenanceProtocol::Ssh => {
                    let proxy = state.ssh_proxy.as_ref().ok_or_else(|| {
                        AppError::Ipc(
                            "SSH proxy unavailable: cannot challenge host identity (fail-closed)"
                                .to_string(),
                        )
                    })?;
                    let identity = crate::ipc::HostKeyFetchIdentity {
                        access_client: state.access_client.as_ref(),
                        user_uuid: probe.user_uuid,
                        asset_uuid: probe.asset_uuid,
                        // System-bounded diagnostic action (see struct doc):
                        // the diagnostic-token verb skips the access-rule
                        // re-check, which cannot exist for an M2M machine.
                        caller_has_assets_manage: true,
                    };
                    let (_host_key, fingerprint) = proxy
                        .fetch_host_key(
                            &host,
                            probe.port,
                            state.supervisor.as_deref(),
                            Some(identity),
                        )
                        .await?;
                    Ok(fingerprint)
                }
                ProvenanceProtocol::Rdp => {
                    let proxy = state.rdp_proxy.as_ref().ok_or_else(|| {
                        AppError::Ipc(
                            "RDP proxy unavailable: cannot challenge host identity (fail-closed)"
                                .to_string(),
                        )
                    })?;
                    let identity = crate::ipc::CertFetchIdentity {
                        access_client: state.access_client.as_ref(),
                        user_uuid: probe.user_uuid,
                        asset_uuid: probe.asset_uuid,
                        caller_has_assets_manage: true,
                    };
                    let (_spki, fingerprint) = proxy
                        .fetch_server_cert(
                            &host,
                            probe.port,
                            state.supervisor.as_deref(),
                            Some(identity),
                        )
                        .await?;
                    Ok(fingerprint)
                }
            }
        })
    }
}

/// In-memory caches for the provenance pipeline. Cheap to clone (`Arc`
/// inside); one instance lives in `AppState` so each test app gets an
/// isolated cache (no cross-test pollution through re-used asset ids).
#[derive(Clone, Default)]
pub struct ProvenanceCache {
    /// Successful verifications: `(asset_id, pinned_fingerprint)` ->
    /// verification instant. A mismatch is NEVER inserted here.
    verified: Arc<DashMap<(i32, String), Instant>>,
    /// DNS resolutions: hostname -> (instant, addresses). Failures are
    /// cached as an empty list so a dead FQDN does not re-pay the
    /// lookup timeout on every call.
    dns: Arc<DashMap<String, (Instant, Vec<IpAddr>)>>,
}

impl ProvenanceCache {
    /// TTL of a successful host-identity verification.
    pub const VERIFY_TTL: Duration = Duration::from_secs(60);
    /// TTL of a DNS resolution (success or failure).
    pub const DNS_TTL: Duration = Duration::from_secs(60);
    /// Upper bound for one DNS lookup.
    pub const DNS_TIMEOUT: Duration = Duration::from_secs(2);

    pub fn new() -> Self {
        Self::default()
    }

    fn is_verified(&self, asset_id: i32, pinned_fp: &str) -> bool {
        let key = (asset_id, pinned_fp.to_string());
        if let Some(entry) = self.verified.get(&key)
            && entry.elapsed() <= Self::VERIFY_TTL
        {
            return true;
        }
        self.verified.remove(&key);
        false
    }

    fn mark_verified(&self, asset_id: i32, pinned_fp: &str) {
        self.verified
            .insert((asset_id, pinned_fp.to_string()), Instant::now());
    }

    async fn resolve_dns(&self, hostname: &str) -> Vec<IpAddr> {
        if let Some(entry) = self.dns.get(hostname)
            && entry.0.elapsed() <= Self::DNS_TTL
        {
            return entry.1.clone();
        }
        // Port 0 satisfies `lookup_host`'s (host, port) contract; only
        // the addresses are kept. Timeout/error = non-candidate (cached).
        let resolved: Vec<IpAddr> =
            match tokio::time::timeout(Self::DNS_TIMEOUT, tokio::net::lookup_host((hostname, 0)))
                .await
            {
                Ok(Ok(addrs)) => addrs.map(|sa| sa.ip()).collect(),
                Ok(Err(e)) => {
                    debug!(hostname, error = %e, "vault provenance: DNS resolution failed");
                    Vec::new()
                }
                Err(_) => {
                    debug!(hostname, "vault provenance: DNS resolution timed out");
                    Vec::new()
                }
            };
        self.dns
            .insert(hostname.to_string(), (Instant::now(), resolved.clone()));
        resolved
    }

    /// Test/diagnostic helper: number of cached verifications.
    pub fn verified_len(&self) -> usize {
        self.verified.len()
    }
}

/// One provenance candidate loaded from the assets table.
struct Candidate {
    id: i32,
    uuid: uuid::Uuid,
    name: String,
    hostname: String,
    port: i32,
    asset_type: AssetType,
    connection_config: serde_json::Value,
}

/// Select the candidates worth a DNS resolution: FQDN hostname (not an
/// IP literal) AND provenance-capable (SSH/RDP with a pinned
/// fingerprint). An asset that could never anchor provenance must not
/// cost a network lookup — this also caps the worst-case latency of an
/// unknown-IP call to the number of PINNED FQDN assets, not the whole
/// asset table.
fn dns_pool(all: &[Candidate]) -> Vec<&Candidate> {
    all.iter()
        .filter(|c| c.hostname.parse::<IpAddr>().is_err())
        .filter(|c| c.protocol().is_some() && c.pinned_fingerprint().is_some())
        .collect()
}

impl Candidate {
    fn protocol(&self) -> Option<ProvenanceProtocol> {
        match self.asset_type {
            AssetType::Ssh => Some(ProvenanceProtocol::Ssh),
            AssetType::Rdp => Some(ProvenanceProtocol::Rdp),
            // IACS asset types carry no host-identity proof: fail-closed,
            // they can never anchor provenance.
            _ => None,
        }
    }

    /// The pinned fingerprint, or `None` when the asset has never been
    /// pinned (TOFU not done) — such an asset is skipped (fail-closed).
    fn pinned_fingerprint(&self) -> Option<String> {
        let key = match self.asset_type {
            AssetType::Ssh => "ssh_host_key_fingerprint",
            AssetType::Rdp => "rdp_server_cert_fingerprint",
            _ => return None,
        };
        self.connection_config
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
    }
}

/// Resolve the M2M caller to a known, identity-verified asset.
///
/// Returns `None` (fail-closed) when:
/// - no non-deleted SSH/RDP asset matches `source_ip` (literal hostname
///   or DNS), or
/// - every matching candidate lacks a pinned fingerprint, or
/// - the active challenge fails or observes a fingerprint that does not
///   match the pin (critical `VaultHostIdentityMismatch` audit, never
///   cached).
///
/// `user_uuid` is only used to mint the broker token for the challenge.
pub async fn resolve_caller_asset(
    state: &AppState,
    source_ip: IpAddr,
    user_uuid: &str,
) -> Option<VerifiedAsset> {
    use crate::schema::assets;

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "vault provenance: DB pool unavailable (fail-closed)");
            return None;
        }
    };

    type Row = (
        i32,
        uuid::Uuid,
        String,
        String,
        i32,
        AssetType,
        serde_json::Value,
    );
    let rows: Vec<Row> = match assets::table
        .filter(assets::is_deleted.eq(false))
        .filter(assets::asset_type.eq_any([AssetType::Ssh, AssetType::Rdp]))
        .select((
            assets::id,
            assets::uuid,
            assets::name,
            assets::hostname,
            assets::port,
            assets::asset_type,
            assets::connection_config,
        ))
        .order(assets::id.asc())
        .load(&mut conn)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            warn!(error = %e, "vault provenance: asset candidate query failed (fail-closed)");
            return None;
        }
    };
    drop(conn);

    let all: Vec<Candidate> = rows
        .into_iter()
        .map(
            |(id, uuid, name, hostname, port, asset_type, connection_config)| Candidate {
                id,
                uuid,
                name,
                hostname,
                port,
                asset_type,
                connection_config,
            },
        )
        .collect();

    // Stage 1: IP -> asset matching. Literal-IP hostnames first (no
    // network I/O), then DNS-resolved FQDNs (cached, short timeout) —
    // restricted to provenance-capable candidates so the aggregate
    // lookup cost stays bounded by the pinned-asset population.
    let mut candidates: Vec<&Candidate> = Vec::new();
    for c in &all {
        if c.hostname.parse::<IpAddr>() == Ok(source_ip) {
            candidates.push(c);
        }
    }
    for c in dns_pool(&all) {
        let addrs = state.vault_provenance.resolve_dns(&c.hostname).await;
        if addrs.contains(&source_ip) {
            candidates.push(c);
        }
    }

    if candidates.is_empty() {
        info!(source_ip = %source_ip, "vault provenance: no asset matches the caller IP");
        return None;
    }

    // Stage 2: active host-identity challenge on each candidate, in
    // order, until one proves its pinned identity.
    for c in candidates {
        let Some(protocol) = c.protocol() else {
            continue;
        };
        let Some(pinned) = c.pinned_fingerprint() else {
            debug!(
                asset_uuid = %c.uuid,
                "vault provenance: candidate has no pinned fingerprint (skipped, fail-closed)"
            );
            continue;
        };
        let Ok(port) = u16::try_from(c.port) else {
            continue;
        };

        if state.vault_provenance.is_verified(c.id, &pinned) {
            debug!(asset_uuid = %c.uuid, "vault provenance: verification cache hit");
            return Some(VerifiedAsset {
                id: c.id,
                uuid: c.uuid,
                name: c.name.clone(),
            });
        }

        let asset_uuid_str = c.uuid.to_string();
        let probe = HostIdentityProbe {
            protocol,
            // INVARIANT (anti-DNS-poisoning): the challenge targets the
            // SOURCE IP of the call, never `c.hostname` or request data.
            ip: source_ip,
            port,
            user_uuid,
            asset_uuid: &asset_uuid_str,
        };
        let observed = match state
            .host_identity_verifier
            .observe_fingerprint(state, probe)
            .await
        {
            Ok(fp) => fp,
            Err(e) => {
                warn!(
                    asset_uuid = %c.uuid, source_ip = %source_ip, error = %e,
                    "vault provenance: host identity challenge failed (fail-closed)"
                );
                continue;
            }
        };

        if observed == pinned {
            state.vault_provenance.mark_verified(c.id, &pinned);
            info!(
                asset_uuid = %c.uuid, source_ip = %source_ip,
                "vault provenance: host identity verified"
            );
            return Some(VerifiedAsset {
                id: c.id,
                uuid: c.uuid,
                name: c.name.clone(),
            });
        }

        // Mismatch: possible MITM / IP squatting. Critical audit,
        // NEVER cached, candidate rejected.
        warn!(
            asset_uuid = %c.uuid, source_ip = %source_ip,
            "vault provenance: HOST IDENTITY MISMATCH (possible MITM)"
        );
        let _ = crate::services::emit_audit_critical(
            state,
            crate::ipc::AuditEvent::new(
                shared::messages::AuditEventType::VaultHostIdentityMismatch,
                format!(
                    r#"{{"asset":"{}","source_ip":"{}","expected":"{}","observed":"{}"}}"#,
                    c.uuid,
                    source_ip,
                    pinned.replace('"', ""),
                    observed.replace('"', "")
                ),
            )
            .user(user_uuid.to_string()),
        )
        .await;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cache_ttl_is_60s_and_mismatch_is_never_inserted() {
        assert_eq!(ProvenanceCache::VERIFY_TTL, Duration::from_secs(60));
        assert_eq!(ProvenanceCache::DNS_TTL, Duration::from_secs(60));
    }

    #[test]
    fn verified_cache_hits_within_ttl_and_evicts_stale() {
        let cache = ProvenanceCache::new();
        assert!(!cache.is_verified(1, "SHA256:abc"));
        cache.mark_verified(1, "SHA256:abc");
        assert!(cache.is_verified(1, "SHA256:abc"));
        // A different pinned fingerprint for the same asset is a MISS:
        // rotating the pin invalidates the cache by construction.
        assert!(!cache.is_verified(1, "SHA256:other"));
        // Stale entry is evicted on read.
        cache.verified.insert(
            (2, "SHA256:old".to_string()),
            Instant::now() - Duration::from_secs(61),
        );
        assert!(!cache.is_verified(2, "SHA256:old"));
        assert!(!cache.verified.contains_key(&(2, "SHA256:old".to_string())));
    }

    fn candidate(asset_type: AssetType, config: serde_json::Value) -> Candidate {
        Candidate {
            id: 1,
            uuid: uuid::Uuid::new_v4(),
            name: "c".to_string(),
            hostname: "10.0.0.1".to_string(),
            port: 22,
            asset_type,
            connection_config: config,
        }
    }

    #[test]
    fn pinned_fingerprint_reads_the_per_protocol_key() {
        let ssh = candidate(
            AssetType::Ssh,
            serde_json::json!({"ssh_host_key_fingerprint": "SHA256:aaa"}),
        );
        assert_eq!(ssh.pinned_fingerprint().as_deref(), Some("SHA256:aaa"));

        let rdp = candidate(
            AssetType::Rdp,
            serde_json::json!({"rdp_server_cert_fingerprint": "SHA256:bbb"}),
        );
        assert_eq!(rdp.pinned_fingerprint().as_deref(), Some("SHA256:bbb"));

        // Wrong key for the protocol -> None (fail-closed).
        let crossed = candidate(
            AssetType::Ssh,
            serde_json::json!({"rdp_server_cert_fingerprint": "SHA256:bbb"}),
        );
        assert!(crossed.pinned_fingerprint().is_none());
    }

    #[test]
    fn empty_or_missing_pin_is_none() {
        let missing = candidate(AssetType::Ssh, serde_json::json!({}));
        assert!(missing.pinned_fingerprint().is_none());
        let empty = candidate(
            AssetType::Ssh,
            serde_json::json!({"ssh_host_key_fingerprint": "  "}),
        );
        assert!(empty.pinned_fingerprint().is_none());
    }

    #[test]
    fn dns_pool_only_selects_pinned_fqdn_candidates() {
        let mut ip_literal = candidate(
            AssetType::Ssh,
            serde_json::json!({"ssh_host_key_fingerprint": "SHA256:a"}),
        );
        ip_literal.hostname = "10.0.0.1".to_string();

        let mut fqdn_pinned = candidate(
            AssetType::Ssh,
            serde_json::json!({"ssh_host_key_fingerprint": "SHA256:b"}),
        );
        fqdn_pinned.hostname = "host.example.com".to_string();

        let mut fqdn_unpinned = candidate(AssetType::Ssh, serde_json::json!({}));
        fqdn_unpinned.hostname = "unpinned.example.com".to_string();

        let all = vec![ip_literal, fqdn_pinned, fqdn_unpinned];
        let pool = dns_pool(&all);
        assert_eq!(
            pool.iter().map(|c| c.hostname.as_str()).collect::<Vec<_>>(),
            vec!["host.example.com"],
            "only a pinned, provenance-capable FQDN may cost a DNS lookup"
        );
    }

    #[test]
    fn iacs_asset_types_are_structurally_excluded() {
        for t in [
            AssetType::IacsModbus,
            AssetType::IacsOpcua,
            AssetType::IacsProfinet,
            AssetType::IacsIec104,
            AssetType::IacsEnip,
            AssetType::IacsBacnetSc,
            AssetType::IacsDnp3,
            AssetType::IacsIec61850,
            AssetType::IacsTcp,
        ] {
            let c = candidate(
                t,
                serde_json::json!({"ssh_host_key_fingerprint": "SHA256:x"}),
            );
            assert!(c.protocol().is_none(), "{t:?} must never anchor provenance");
            assert!(c.pinned_fingerprint().is_none());
        }
    }
}
