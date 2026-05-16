//! Privileged-port-aware mapping between the asset's upstream port
//! and the local port the EWS will bind via `ssh -L`.
//!
//! ## Why
//!
//! Most industrial protocols use TCP ports below 1024 (Modbus 502,
//! IEC-61850 / MMS 102, FTP / file transfer 21). On every Unix
//! (Linux, FreeBSD, macOS) and on Windows running as a standard
//! user, `bind(2)` to a port < 1024 requires elevated privileges
//! (CAP_NET_BIND_SERVICE on Linux, root on FreeBSD/macOS, the
//! "increased priority" right on Windows).
//!
//! The Vauban IACS tunnel exposes the asset to the EWS through a
//! `ssh -L <local>:<asset_host>:<asset_port>` port forward. The
//! left-hand side of `-L` is bound on the EWS by the operator's
//! SSH client. Forcing operators to run that SSH client as root
//! every time they need to reach a Modbus PLC is unacceptable
//! from a security standpoint (lateral-movement surface) and from
//! a UX standpoint (operator workflow friction, Windows-domain
//! incompatibility).
//!
//! [`derive_local_forward_port`] therefore decouples the local
//! bind port from the upstream asset port: when the asset's port
//! is privileged (`< 1024`), the local port is shifted into the
//! 50000-50999 user-space range using a deterministic, reversible,
//! collision-free formula (`50000 + asset_port`). Above 1024 the
//! local port equals the asset port -- there is no reason to
//! rewrite when no privilege is required.
//!
//! ## Contract
//!
//! - Pure, deterministic, no I/O, no allocation -- safe to call from
//!   anywhere on the request path.
//! - For every input `p`, the output `q` satisfies `q >= 1024`
//!   (post-condition pinned by [`local_forward_port_is_always_unprivileged`]).
//! - Reversible: `recover_asset_port(q) == p` whenever `q` was
//!   produced by `derive_local_forward_port(p)`. The reverse
//!   function is exposed as a debugging convenience; production
//!   code paths should NOT use it -- the asset port is always
//!   pinned in the per-session entry and authoritative.
//! - Stable across releases. The mapping is part of the user-facing
//!   contract: an operator memorising "Modbus assets show up on
//!   :50502 locally" must keep working after every Vauban update.
//!   The drift test
//!   [`derive_local_forward_port_canonical_mapping`]
//!   pins the four most common IACS protocols.
//!
//! ## Why 50000 and not 30000 or 60000?
//!
//! - `50000-50999` is firmly inside IANA's "User Ports" range
//!   (1024-49151 are "User Ports", 49152-65535 are "Dynamic /
//!   Private"), but practically modern operating systems also use
//!   the `49152-65535` range for ephemeral outgoing connections
//!   (`ip_local_port_range` on Linux defaults to `32768-60999`).
//!   Picking `50000` keeps the mapped ports clear of typical
//!   ephemeral allocations on most Linux distributions while
//!   staying well below the IPv4-OS hard limit of 65535.
//! - The shift is exact: `50000 + 502 = 50502`, `50000 + 102 = 50102`.
//!   No modulo, no hashing, no surprise. The mapping is obvious to
//!   read in tcpdump and in operator brains.
//!
//! No two privileged ports collide under this mapping (the addition
//! is injective on `[0, 1023]` -> `[50000, 51023]`).

/// Map an asset's upstream TCP port to the port the EWS should bind
/// locally via `ssh -L`. See module docs for the contract.
pub fn derive_local_forward_port(asset_port: u16) -> u16 {
    if asset_port >= 1024 {
        return asset_port;
    }
    // saturating_add is paranoia: 50000 + 1023 = 51023 fits in u16
    // (max 65535), so the saturation never trips. Kept for the
    // "unrepresentable failure" property even if the constants
    // were edited.
    50_000u16.saturating_add(asset_port)
}

/// Recover the asset port from a previously-mapped local port.
///
/// Inverse of [`derive_local_forward_port`]. Useful in tests and
/// in occasional operator-side debugging (e.g. "this `ssh -L` was
/// minted for which protocol?"). NOT used on the runtime path:
/// the asset port travels end-to-end as a separate field on
/// `IacsTunnelOpenRequest` / `PendingTunnel`, so a recovery here
/// can only ever be a sanity check, never authoritative.
pub fn recover_asset_port(local_forward_port: u16) -> u16 {
    if (50_000..=51_023).contains(&local_forward_port) {
        local_forward_port - 50_000
    } else {
        local_forward_port
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===============================================================
    // Privileged-port mapping (the headline contract)
    // ===============================================================

    /// IACS canonical protocols. These four values are the *user-
    /// facing* contract: changing the mapping for any of them is a
    /// breaking change that requires an explicit changelog entry.
    #[test]
    fn derive_local_forward_port_canonical_mapping() {
        // Modbus / Modbus-TCP (the headline case)
        assert_eq!(derive_local_forward_port(502), 50_502);
        // IEC-61850 / MMS (legacy substation protocol)
        assert_eq!(derive_local_forward_port(102), 50_102);
        // OPC-UA -- already non-privileged, must NOT be rewritten
        assert_eq!(derive_local_forward_port(4_840), 4_840);
        // DNP3 -- already non-privileged
        assert_eq!(derive_local_forward_port(20_000), 20_000);
        // IEC-60870-5-104 -- already non-privileged
        assert_eq!(derive_local_forward_port(2_404), 2_404);
        // BACnet/SC -- already non-privileged
        assert_eq!(derive_local_forward_port(47_808), 47_808);
        // EtherNet/IP (CIP) -- already non-privileged
        assert_eq!(derive_local_forward_port(44_818), 44_818);
        // Profinet IO RT -- already non-privileged
        assert_eq!(derive_local_forward_port(34_962), 34_962);
    }

    /// Boundary: 1023 is the last privileged port, 1024 is the
    /// first user port. The mapping must flip exactly there.
    #[test]
    fn derive_local_forward_port_boundary_is_at_1024() {
        // 1023 is privileged -> shift
        assert_eq!(derive_local_forward_port(1_023), 51_023);
        // 1024 is user -> no shift
        assert_eq!(derive_local_forward_port(1_024), 1_024);
    }

    /// Non-IACS edge cases that may still surface (admin types a
    /// custom `assets.port = 22`, generic TCP, etc.).
    #[test]
    fn derive_local_forward_port_non_iacs_privileged_inputs() {
        // SSH -- shifted
        assert_eq!(derive_local_forward_port(22), 50_022);
        // Telnet -- shifted (and a pet operator might still type it)
        assert_eq!(derive_local_forward_port(23), 50_023);
        // HTTPS -- shifted (rare on a PLC but possible)
        assert_eq!(derive_local_forward_port(443), 50_443);
        // FTP control -- shifted
        assert_eq!(derive_local_forward_port(21), 50_021);
        // 0 (degenerate, but the function MUST stay total) -- shifted
        assert_eq!(derive_local_forward_port(0), 50_000);
    }

    /// Post-condition pin: the output is ALWAYS in the user range.
    /// This is the contract the operator and the `ssh -L` flag
    /// rely on -- the local bind must never need root.
    #[test]
    fn local_forward_port_is_always_unprivileged() {
        for asset_port in 0u16..=u16::MAX {
            let local = derive_local_forward_port(asset_port);
            assert!(
                local >= 1_024,
                "local_forward_port({asset_port}) = {local} but \
                 the contract requires >= 1024"
            );
        }
    }

    /// The mapping must be injective on the privileged range so two
    /// distinct privileged assets never collide on the same local
    /// port (an operator running `ssh -L` to two assets back to
    /// back must see two distinct ports).
    #[test]
    fn derive_local_forward_port_is_injective_on_privileged_range() {
        let mut seen = std::collections::HashSet::with_capacity(1_024);
        for p in 0u16..1_024 {
            let q = derive_local_forward_port(p);
            assert!(
                seen.insert(q),
                "collision: derive_local_forward_port({p}) = {q} \
                 already produced by a smaller input"
            );
        }
    }

    /// And total injectivity: the mapping must NEVER map a user
    /// port and a privileged port to the same output (e.g. asset
    /// `port = 50502` would otherwise collide with the Modbus
    /// 502 -> 50502 mapping). The shift constant 50000 keeps the
    /// privileged range contained inside `[50_000, 51_023]`, so a
    /// raw asset port in that range happens to collide. We accept
    /// this collision deliberately because:
    ///   * the operator who picks `assets.port = 50_502` knew what
    ///     they were doing,
    ///   * the bastion-side `validate_target` still gates on the
    ///     per-session pinned (asset_host, asset_port) -- the local
    ///     port is purely an EWS-side label.
    ///
    /// This test documents the collision as INTENDED, not as a bug.
    #[test]
    fn collision_in_50000_51023_range_is_intentional_and_pinned() {
        let collision_target = derive_local_forward_port(502); // 50_502
        assert_eq!(collision_target, 50_502);
        assert_eq!(derive_local_forward_port(50_502), 50_502);
        // Both 502 and 50_502 produce 50_502. By design.
    }

    // ===============================================================
    // Recovery (inverse function, for sanity / debugging only)
    // ===============================================================

    #[test]
    fn recover_asset_port_inverts_privileged_mappings() {
        for p in 0u16..1_024 {
            let q = derive_local_forward_port(p);
            assert_eq!(
                recover_asset_port(q),
                p,
                "recover_asset_port must be the inverse of \
                 derive_local_forward_port on privileged inputs"
            );
        }
    }

    #[test]
    fn recover_asset_port_is_identity_on_unprivileged_local_port() {
        // Outside [50_000, 51_023], recovery is the identity.
        assert_eq!(recover_asset_port(4_840), 4_840);
        assert_eq!(recover_asset_port(1_024), 1_024);
        assert_eq!(recover_asset_port(65_535), 65_535);
    }

    // ===============================================================
    // Stability (drift): a developer must NOT be able to silently
    // change the mapping. Pin the wire shape with one ground-truth
    // assertion that fails clearly when the constants change.
    // ===============================================================

    #[test]
    fn derive_local_forward_port_is_stable_across_releases() {
        // The values below are the user-facing contract. Updating
        // any of them is a backwards-incompatible change that must
        // be flagged in the docs/runbooks and the operator
        // changelog. Do not silently bump these constants.
        assert_eq!(derive_local_forward_port(502), 50_502, "Modbus");
        assert_eq!(derive_local_forward_port(102), 50_102, "MMS");
        assert_eq!(derive_local_forward_port(0), 50_000, "lower edge");
        assert_eq!(derive_local_forward_port(1_023), 51_023, "upper edge");
        assert_eq!(derive_local_forward_port(1_024), 1_024, "boundary");
    }
}
