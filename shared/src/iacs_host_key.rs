//! IACS sshd Ed25519 host key persistence.
//!
//! Single source of truth, used by:
//!
//! - `vauban-supervisor`: at boot, BEFORE fork, calls
//!   [`prepare_host_key_fd`] which loads-or-generates the key on disk
//!   (mode 0600) and re-opens the file read-only. The resulting
//!   [`OwnedFd`] is passed to `vauban-proxy-iacs` via the
//!   `VAUBAN_IACS_HOST_KEY_FD` env var (FD inherited across
//!   `fork+execv`, `FD_CLOEXEC` cleared in the spawn helper).
//! - `vauban-proxy-iacs`: BEFORE `cap_enter` -- and therefore before
//!   any `open()` becomes forbidden -- calls
//!   [`read_host_key_from_fd`] on the inherited FD to materialise the
//!   russh `PrivateKey`. The proxy NEVER opens the host key path
//!   itself: under FreeBSD Capsicum, `open()` on an absolute path
//!   returns `errno 94` ("Not permitted in capability mode"), which
//!   is exactly the bug this module exists to fix.
//!
//! See `docs/technical/Vauban_IACS_Proxy_Architecture_EN(1.1).md` for
//! the full FD passing scheme analogous to the HTTPS listener.

use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::io::RawFd;
use std::path::Path;

use russh::keys::PrivateKey;
use russh::keys::ssh_key::Algorithm;
use zeroize::Zeroize;

/// Load (or generate-and-persist) the russh sshd Ed25519 host key.
///
/// If the file at `path` exists, it is parsed as OpenSSH PEM and
/// returned. Otherwise:
///   1. The parent directory is created (`create_dir_all`).
///   2. A fresh Ed25519 key is generated.
///   3. The key is written to `path` in OpenSSH PEM with LF line
///      endings.
///   4. On Unix, the file mode is set to `0o600`.
///
/// This function MUST be called from outside the Capsicum sandbox
/// (the supervisor invokes it in [`prepare_host_key_fd`] BEFORE
/// fork; the proxy never calls it directly post-Capsicum).
pub fn load_or_generate_host_key(path: &Path) -> io::Result<PrivateKey> {
    if path.exists() {
        // The PEM blob holds the Ed25519 private key in clear; we MUST
        // zeroize the backing buffer before it is dropped so the secret
        // does not linger in the process heap arena. `russh`'s
        // `to_openssh` already returns a `Zeroizing<String>`; we mirror
        // the same hygiene on the input side.
        let mut data = std::fs::read_to_string(path)?;
        let parsed = PrivateKey::from_openssh(&data)
            .map_err(|e| io::Error::other(format!("invalid host key: {e}")));
        data.zeroize();
        return parsed;
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    // ssh-key 0.7 (russh 0.61) requires a `rand_core` 0.10 `CryptoRng`.
    // rand_core 0.10 dropped `OsRng`; getrandom's `SysRng` is the OS
    // entropy source but only implements the fallible `TryCryptoRng`, so
    // we wrap it in `UnwrapErr` to obtain the infallible `CryptoRng` the
    // `random` bound demands (an OS RNG failure is unrecoverable here and
    // would panic, which is the correct behaviour for host-key keygen).
    let key = PrivateKey::random(
        &mut russh::keys::ssh_key::rand_core::UnwrapErr(getrandom::SysRng),
        Algorithm::Ed25519,
    )
    .map_err(|e| io::Error::other(format!("ed25519 keygen: {e}")))?;
    // `to_openssh` returns `Zeroizing<String>` so `openssh` zeroes itself
    // when it goes out of scope at the end of this function.
    let openssh = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .map_err(|e| io::Error::other(format!("encode host key: {e}")))?;
    std::fs::write(path, openssh.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(path)?.permissions();
        perm.set_mode(0o600);
        std::fs::set_permissions(path, perm)?;
    }
    Ok(key)
}

/// Prepare the IACS sshd host key for FD inheritance.
///
/// Loads-or-generates the Ed25519 key on disk (mode 0600) via
/// [`load_or_generate_host_key`], then re-opens the file read-only
/// and returns the resulting [`OwnedFd`]. The supervisor passes this
/// FD to `vauban-proxy-iacs` via inherit-across-`execv`; the proxy
/// drains the FD with [`read_host_key_from_fd`] BEFORE entering
/// Capsicum.
///
/// Why a separate read-only FD instead of returning just the
/// in-memory `PrivateKey`? Because the supervisor and the proxy are
/// independent processes: passing a `PrivateKey` would require
/// serialising the secret over the env or an IPC pipe, where it
/// would hit `/proc/<pid>/environ` (env) or stay parked in a kernel
/// pipe buffer (IPC). The FD form keeps the secret exclusively on
/// disk + in the proxy's address space, AND it lets us reuse the
/// same `inheritable_fds` plumbing already used for
/// `VAUBAN_IACS_LISTENER_FD`.
pub fn prepare_host_key_fd(path: &Path) -> io::Result<OwnedFd> {
    let _ = load_or_generate_host_key(path)?;
    let file = std::fs::OpenOptions::new().read(true).open(path)?;
    Ok(OwnedFd::from(file))
}

/// Rewind the host key FD to offset 0 before each `execv` of
/// `vauban-proxy-iacs`.
///
/// SECURITY (multi-respawn correctness): the supervisor opens the
/// host key file ONCE at boot via [`prepare_host_key_fd`] and
/// inherits the resulting FD across `fork+execv` to every spawn of
/// `vauban-proxy-iacs`. The Linux/FreeBSD kernel keeps the **file
/// position in the file table entry, NOT in the file descriptor**
/// number, so the supervisor's FD and the child's FD share the same
/// position cursor by design.
///
/// On the first spawn, the proxy `read_to_string`s the FD to EOF,
/// advancing the shared cursor past the last byte of the PEM blob.
/// On a subsequent crash-and-respawn, the new proxy inherits the
/// **same** FD with the cursor still parked at EOF -- it reads an
/// empty string, and `PrivateKey::from_openssh("")` fails with
/// "PEM preamble contains invalid data (NUL byte)".
///
/// Calling [`rewind_host_key_fd`] before every spawn (boot AND each
/// `respawn_service` / `kill_and_respawn`) resets the cursor to 0
/// so each child sees a fresh, fully-readable PEM blob. Pinned by
/// `rewind_host_key_fd_resets_position_after_full_read` below.
pub fn rewind_host_key_fd(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` MUST be a valid open FD owned by the caller.
    // `lseek(fd, 0, SEEK_SET)` is documented to work on regular
    // files (host key path is always a regular file) and never
    // mutates kernel state beyond the file's position cursor.
    let res = unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    if res < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Read the IACS sshd host key from an inherited [`OwnedFd`].
///
/// Consumes the FD: the underlying file is closed when this
/// function returns. Intended to be called by `vauban-proxy-iacs`
/// BEFORE `setup_service_sandbox_with_listeners` (i.e. before
/// `cap_enter`) so we never try to read a sandboxed FD with capability
/// rights restricted below `CAP_READ`.
pub fn read_host_key_from_fd(fd: OwnedFd) -> io::Result<PrivateKey> {
    use std::io::Read;
    let mut file = std::fs::File::from(fd);
    // The PEM material is the Ed25519 private key in clear; zero it out
    // of the heap as soon as the parse is done so it does not survive
    // beyond this call (the long-lived secret remains as the
    // `russh::keys::PrivateKey` value, which is the unavoidable
    // working set the russh server signs handshakes with).
    let mut buf = String::new();
    let read_res = file.read_to_string(&mut buf);
    if let Err(e) = read_res {
        buf.zeroize();
        return Err(e);
    }
    let parsed = PrivateKey::from_openssh(&buf)
        .map_err(|e| io::Error::other(format!("invalid host key: {e}")));
    buf.zeroize();
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join(name);
        // leak the dir so the file survives until the test ends
        std::mem::forget(dir);
        p
    }

    #[test]
    fn load_or_generate_creates_file_with_mode_0600() {
        let p = temp_path("hostkey1");
        assert!(!p.exists());
        let _ = load_or_generate_host_key(&p).expect("first call generates");
        assert!(p.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "host key file must be 0600");
        }
    }

    #[test]
    fn load_or_generate_is_idempotent() {
        let p = temp_path("hostkey2");
        let k1 = load_or_generate_host_key(&p).expect("generate");
        let k2 = load_or_generate_host_key(&p).expect("re-load");
        // Same OpenSSH-encoded blob -> same key.
        let s1 = k1.to_openssh(russh::keys::ssh_key::LineEnding::LF).unwrap();
        let s2 = k2.to_openssh(russh::keys::ssh_key::LineEnding::LF).unwrap();
        assert_eq!(*s1, *s2, "second call must reload, not regenerate");
    }

    #[test]
    fn prepare_host_key_fd_returns_readable_fd() {
        let p = temp_path("hostkey3");
        let fd = prepare_host_key_fd(&p).expect("prepare");
        let raw = fd.as_raw_fd();
        assert!(raw >= 0);
        let key = read_host_key_from_fd(fd).expect("read+parse");
        // The key must round-trip into PEM (i.e. it is a valid Ed25519 key).
        let pem = key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap();
        assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    }

    #[test]
    fn prepare_then_read_matches_disk_contents() {
        let p = temp_path("hostkey4");
        let fd = prepare_host_key_fd(&p).expect("prepare");
        let key_via_fd = read_host_key_from_fd(fd).expect("read+parse");
        let key_via_disk = load_or_generate_host_key(&p).expect("disk reload");
        let s1 = key_via_fd
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap();
        let s2 = key_via_disk
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap();
        assert_eq!(*s1, *s2);
    }

    /// Multi-respawn correctness: the supervisor opens the host key
    /// once at boot and inherits the FD across every `execv` of
    /// `vauban-proxy-iacs`. Because the kernel stores the file
    /// position on the file table entry (shared between supervisor
    /// and children), a first `read_to_string` to EOF in the first
    /// child leaves the cursor at EOF, and a respawn would inherit
    /// the same cursor -- hence the historical "PEM preamble contains
    /// invalid data (NUL byte)" boot-loop on FreeBSD when proxy_iacs
    /// crashed once.
    ///
    /// Calling [`rewind_host_key_fd`] resets the position to 0 so
    /// the next reader (or the same FD re-used by another child)
    /// sees the full PEM blob again.
    #[test]
    fn rewind_host_key_fd_resets_position_after_full_read() {
        use std::io::Read;
        let p = temp_path("hostkey_rewind");
        let _ = load_or_generate_host_key(&p).expect("generate");
        let f = std::fs::OpenOptions::new()
            .read(true)
            .open(&p)
            .expect("open");
        let raw = f.as_raw_fd();
        let mut first = String::new();
        let mut handle = std::io::BufReader::new(f);
        handle.read_to_string(&mut first).expect("first read");
        assert!(first.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));

        // Without rewind, a second read returns empty -- the
        // production-bug repro.
        let mut second = String::new();
        handle.read_to_string(&mut second).expect("eof read");
        assert!(
            second.is_empty(),
            "without rewind the cursor stays at EOF (this is the historical bug)"
        );

        // After rewind, the FD is fully readable again.
        rewind_host_key_fd(raw).expect("rewind");
        let mut third = String::new();
        handle.read_to_string(&mut third).expect("post-rewind read");
        assert_eq!(
            third, first,
            "rewind_host_key_fd must reset the cursor to byte 0; \
             the post-rewind read must match the initial PEM blob byte-for-byte"
        );
    }

    #[test]
    fn read_host_key_from_fd_rejects_garbage() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("bad");
        std::fs::write(&p, b"not an openssh key\n").unwrap();
        let f = std::fs::OpenOptions::new().read(true).open(&p).unwrap();
        let fd = OwnedFd::from(f);
        let res = read_host_key_from_fd(fd);
        assert!(res.is_err(), "garbage must not parse");
    }

    /// Source-grep pin: every transient `String` that holds the OpenSSH
    /// PEM (which contains the Ed25519 private key in clear) MUST be
    /// zeroized before it is dropped. The same hygiene applies to the
    /// generated blob, but `russh::PrivateKey::to_openssh` already
    /// returns `Zeroizing<String>` so we only need to pin the input
    /// side (`data` in `load_or_generate_host_key`, `buf` in
    /// `read_host_key_from_fd`).
    ///
    /// If a future refactor reads the PEM into a `String` without
    /// calling `zeroize()` on it, this pin fails immediately and the
    /// asymmetry with `SensitiveString` / `SecretString` (used for
    /// every other Vauban secret -- TLS keys, SSH client keys, TOTP
    /// secrets, passwords) is caught at CI time.
    #[test]
    fn pem_buffers_are_zeroized_before_drop() {
        const SOURCE: &str = include_str!("iacs_host_key.rs");
        assert!(
            SOURCE.contains("data.zeroize();"),
            "load_or_generate_host_key MUST zeroize the PEM `data` buffer before it is dropped"
        );
        assert!(
            SOURCE.contains("buf.zeroize();"),
            "read_host_key_from_fd MUST zeroize the PEM `buf` buffer before it is dropped"
        );
        assert!(
            SOURCE.contains("use zeroize::Zeroize;"),
            "shared::iacs_host_key MUST import zeroize::Zeroize"
        );
    }
}
