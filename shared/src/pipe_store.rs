//! Supervisor-owned IPC pipe mesh.
//!
//! The supervisor must keep both ends of every live topology pipe for its
//! entire lifetime, including after a linked restart. Dropping the
//! `IpcChannel` pair after copying raw fd numbers (the 0.1.0
//! `respawn_linked_group` path) closes the supervisor copies; the kernel
//! then recycles those numbers, and the next spawn hands children stale
//! or colliding descriptors.
//!
//! [`PipeStore`] is the single owner. [`derive_service_pipes`] is the only
//! construction door for the per-service fd tables passed to `spawn_child`.

use crate::ipc::{IpcChannel, IpcError, Result};
use crate::messages::Service;
use std::collections::{BTreeSet, HashMap};
use std::io;
use std::os::unix::io::RawFd;

/// Exit code a leaf uses to request a recoverable respawn (Privsep §6.2).
///
/// Honored even before the first heartbeat Pong, unlike any other
/// non-zero exit. Used by proxies (web IPC EOF) and vauban-web (pump
/// death / sandboxed DB loss).
pub const EXIT_CODE_RESPAWN: i32 = 100;

/// Extra IPC pipes to pass to a child service (raw fd numbers only).
///
/// The numbers are valid only while the matching [`PipeStore`] still
/// owns the underlying [`IpcChannel`]s. Recipients must not close them;
/// they inherit copies at `fork`/`execv`.
#[derive(Default, Clone, Debug)]
pub struct ServicePipes {
    /// Pipes where this service is the "from" side (sender).
    pub outgoing: Vec<(Service, i32, i32)>,
    /// Pipes where this service is the "to" side (receiver).
    pub incoming: Vec<(Service, i32, i32)>,
}

/// Owns every live topology pipe pair for the supervisor process.
pub struct PipeStore {
    pipes: HashMap<(Service, Service), (IpcChannel, IpcChannel)>,
}

impl PipeStore {
    /// Create one pipe pair per directed topology edge and retain both ends.
    pub fn new(topology: &[(Service, Service)]) -> Result<Self> {
        let mut pipes = HashMap::with_capacity(topology.len());
        for &(from, to) in topology {
            if pipes.contains_key(&(from, to)) {
                return Err(IpcError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("duplicate topology edge {from:?} -> {to:?}"),
                )));
            }
            pipes.insert((from, to), IpcChannel::pair()?);
        }
        Ok(Self { pipes })
    }

    /// Replace the pair for an existing edge. The previous pair is dropped
    /// (its fds close) after the processes that inherited them are gone.
    pub fn replace(&mut self, from: Service, to: Service) -> Result<()> {
        if !self.pipes.contains_key(&(from, to)) {
            return Err(IpcError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no pipe {from:?} -> {to:?}"),
            )));
        }
        self.pipes.insert((from, to), IpcChannel::pair()?);
        Ok(())
    }

    /// Unique construction door for the per-service fd tables.
    pub fn derive_service_pipes(&self) -> HashMap<Service, ServicePipes> {
        let mut service_pipes: HashMap<Service, ServicePipes> = HashMap::new();
        for ((from, to), (from_channel, to_channel)) in &self.pipes {
            service_pipes.entry(*from).or_default().outgoing.push((
                *to,
                from_channel.read_fd(),
                from_channel.write_fd(),
            ));
            service_pipes.entry(*to).or_default().incoming.push((
                *from,
                to_channel.read_fd(),
                to_channel.write_fd(),
            ));
        }
        service_pipes
    }

    /// Number of directed edges currently stored.
    pub fn len(&self) -> usize {
        self.pipes.len()
    }

    /// Whether the store holds no edges.
    pub fn is_empty(&self) -> bool {
        self.pipes.is_empty()
    }

    /// Directed edges currently stored.
    pub fn edges(&self) -> impl Iterator<Item = (Service, Service)> + '_ {
        self.pipes.keys().copied()
    }

    /// Borrow the live pair for `from -> to`, if present.
    pub fn get(&self, from: Service, to: Service) -> Option<&(IpcChannel, IpcChannel)> {
        self.pipes.get(&(from, to))
    }

    /// Every raw fd currently owned by the store (four per edge).
    pub fn all_raw_fds(&self) -> Vec<RawFd> {
        let mut fds = Vec::with_capacity(self.pipes.len() * 4);
        for (from_channel, to_channel) in self.pipes.values() {
            fds.push(from_channel.read_fd());
            fds.push(from_channel.write_fd());
            fds.push(to_channel.read_fd());
            fds.push(to_channel.write_fd());
        }
        fds
    }
}

/// Transitive closure of overlapping linked-restart groups.
///
/// Returns the empty set when `key` is not a member of any group
/// (caller should respawn that leaf alone). Otherwise the set always
/// contains `key` and every service reachable by walking overlapping
/// groups (web + proxy_ssh and web + proxy_rdp => all three).
pub fn linked_closure<'a>(groups: &[&'a [&'a str]], key: &str) -> BTreeSet<&'a str> {
    let mut result = BTreeSet::new();
    for group in groups {
        if group.contains(&key) {
            for member in *group {
                result.insert(*member);
            }
        }
    }
    if result.is_empty() {
        return result;
    }
    let mut changed = true;
    while changed {
        changed = false;
        for group in groups {
            if group.iter().any(|member| result.contains(member)) {
                for member in *group {
                    if result.insert(*member) {
                        changed = true;
                    }
                }
            }
        }
    }
    result
}

/// Collect every raw fd referenced by a derived table (for uniqueness checks).
pub fn derived_raw_fds(service_pipes: &HashMap<Service, ServicePipes>) -> Vec<RawFd> {
    let mut fds = Vec::new();
    for pipes in service_pipes.values() {
        for &(_, r, w) in pipes.outgoing.iter().chain(pipes.incoming.iter()) {
            fds.push(r);
            fds.push(w);
        }
    }
    fds
}

/// True when `fd` is open in this process (`fcntl(F_GETFD)` succeeds).
pub fn fd_is_open(fd: RawFd) -> bool {
    use nix::fcntl::{FcntlArg, fcntl};
    use std::os::unix::io::BorrowedFd;
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    fcntl(borrowed, FcntlArg::F_GETFD).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{ControlMessage, Message};
    use nix::unistd::{dup, read};
    use std::collections::HashSet;
    use std::os::unix::io::BorrowedFd;

    const WEB_RDP: (Service, Service) = (Service::Web, Service::ProxyRdp);
    const WEB_SSH: (Service, Service) = (Service::Web, Service::ProxySsh);

    fn mini_topology() -> Vec<(Service, Service)> {
        vec![WEB_RDP, WEB_SSH]
    }

    #[test]
    fn new_creates_one_pair_per_edge() {
        let store = PipeStore::new(&mini_topology()).expect("new");
        assert!(!store.is_empty());
        assert_eq!(store.len(), 2);
        assert!(store.get(Service::Web, Service::ProxyRdp).is_some());
        assert!(store.get(Service::Web, Service::ProxySsh).is_some());
        assert!(store.get(Service::Web, Service::Auth).is_none());
    }

    #[test]
    fn new_rejects_duplicate_edge() {
        let err = match PipeStore::new(&[WEB_RDP, WEB_RDP]) {
            Ok(_) => panic!("duplicate edge must fail"),
            Err(e) => e,
        };
        assert!(format!("{err}").contains("duplicate"));
    }

    fn derive_is_symmetric(service_pipes: &HashMap<Service, ServicePipes>) -> bool {
        for (from, pipes) in service_pipes {
            for &(to, _r, _w) in &pipes.outgoing {
                let Some(peer) = service_pipes.get(&to) else {
                    return false;
                };
                if !peer.incoming.iter().any(|(src, _, _)| src == from) {
                    return false;
                }
            }
            for &(src, _r, _w) in &pipes.incoming {
                let Some(peer) = service_pipes.get(&src) else {
                    return false;
                };
                if !peer.outgoing.iter().any(|(dst, _, _)| dst == from) {
                    return false;
                }
            }
        }
        true
    }

    #[test]
    fn replace_changes_fds_and_old_read_sees_eof() {
        let mut store = PipeStore::new(&[WEB_RDP]).expect("new");
        let (from_ch, to_ch) = store.get(Service::Web, Service::ProxyRdp).expect("pair");
        let old_from_r = from_ch.read_fd();
        let old_from_w = from_ch.write_fd();
        let old_to_r = to_ch.read_fd();
        let old_to_w = to_ch.write_fd();

        let borrowed = unsafe { BorrowedFd::borrow_raw(old_to_r) };
        let duped = dup(borrowed).expect("dup old to-read");

        store
            .replace(Service::Web, Service::ProxyRdp)
            .expect("replace");
        let (new_from, new_to) = store
            .get(Service::Web, Service::ProxyRdp)
            .expect("new pair");
        assert_ne!(
            (
                new_from.read_fd(),
                new_from.write_fd(),
                new_to.read_fd(),
                new_to.write_fd()
            ),
            (old_from_r, old_from_w, old_to_r, old_to_w),
            "replace must install a different pair"
        );

        let mut buf = [0u8; 1];
        let n = read(duped, &mut buf).expect("read dup");
        assert_eq!(n, 0, "old write end dropped => dup'd read sees EOF");
    }

    #[test]
    fn replace_missing_edge_errors() {
        let mut store = PipeStore::new(&[WEB_RDP]).expect("new");
        let err = match store.replace(Service::Web, Service::ProxySsh) {
            Ok(()) => panic!("missing edge must fail"),
            Err(e) => e,
        };
        assert!(format!("{err}").contains("no pipe"));
    }

    #[test]
    fn derive_service_pipes_is_symmetric() {
        let store = PipeStore::new(&mini_topology()).expect("new");
        let derived = store.derive_service_pipes();
        assert!(derive_is_symmetric(&derived));
        let web = derived.get(&Service::Web).expect("web");
        assert_eq!(web.outgoing.len(), 2);
        assert!(web.incoming.is_empty());
        let rdp = derived.get(&Service::ProxyRdp).expect("rdp");
        assert_eq!(rdp.incoming.len(), 1);
        assert_eq!(rdp.incoming[0].0, Service::Web);
        assert!(rdp.outgoing.is_empty());
    }

    #[test]
    fn linked_closure_contains_key_and_unions_overlapping_groups() {
        let groups: &[&[&str]] = &[&["web", "proxy_ssh"], &["web", "proxy_rdp"]];
        let web = linked_closure(groups, "web");
        assert!(web.contains("web"));
        assert_eq!(web, BTreeSet::from(["web", "proxy_ssh", "proxy_rdp"]));
        assert_eq!(linked_closure(groups, "web"), web, "idempotent");
        assert_eq!(linked_closure(groups, "proxy_rdp"), web);
        assert_eq!(linked_closure(groups, "proxy_ssh"), web);
        assert!(linked_closure(groups, "vault").is_empty());
    }

    #[test]
    fn linked_closure_is_symmetric() {
        let groups: &[&[&str]] = &[&["web", "proxy_ssh"], &["web", "proxy_rdp"]];
        for a in ["web", "proxy_ssh", "proxy_rdp"] {
            for b in ["web", "proxy_ssh", "proxy_rdp"] {
                let ca = linked_closure(groups, a);
                let cb = linked_closure(groups, b);
                assert_eq!(ca.contains(b), cb.contains(a), "{a} vs {b}");
            }
        }
    }

    #[test]
    fn derived_fds_are_unique_and_open() {
        let store = PipeStore::new(&mini_topology()).expect("new");
        let fds = store.all_raw_fds();
        let unique: HashSet<RawFd> = fds.iter().copied().collect();
        assert_eq!(unique.len(), fds.len(), "no duplicate fds in the store");
        for fd in fds {
            assert!(fd_is_open(fd), "fd {fd} must be open");
        }
    }

    #[test]
    fn ping_round_trips_on_live_pair() {
        let store = PipeStore::new(&[WEB_RDP]).expect("new");
        let (from_ch, to_ch) = store.get(Service::Web, Service::ProxyRdp).expect("pair");
        let msg = Message::Control(ControlMessage::Ping { seq: 7 });
        from_ch.send(&msg).expect("send");
        match to_ch.recv().expect("recv") {
            Message::Control(ControlMessage::Ping { seq }) => assert_eq!(seq, 7),
            other => panic!("unexpected {other:?}"),
        }
    }
}
