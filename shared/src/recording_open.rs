//! Open, create and unlink recording files without following a symlink.
//!
//! The supervisor performs these operations as root on a path a
//! sandboxed service supplied. The path is validated lexically
//! elsewhere (`recording_paths`); this module makes the filesystem walk
//! itself safe. It descends from the storage base one component at a
//! time with `openat(O_DIRECTORY | O_NOFOLLOW)`, so a symlink planted in
//! `YYYY`, `MM` or the session directory stops the request instead of
//! taking root outside the storage tree. The file itself is opened with
//! `O_NOFOLLOW` as well.
//!
//! The storage base is trusted (it comes from the supervisor's own
//! configuration) and may itself be a symlink.
//!
//! # Invariants
//!
//! - **INV-1** no component below the base is ever resolved through a
//!   symlink, for a write or for an unlink.
//! - **INV-2** [`WriteOpen::CreateNew`] never returns a descriptor on a
//!   file that holds data. It creates the file, or reopens one that is
//!   still empty (a lease whose reply was lost), or fails with
//!   `AlreadyExists`.
//! - **INV-3** only [`WriteOpen::Rewrite`] truncates.

use nix::errno::Errno;
use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::{Mode, SFlag, fstat, mkdirat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

/// How a recording file is opened for writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOpen {
    /// Create the file. An existing empty file is reopened; an existing
    /// file with data is refused.
    CreateNew,
    /// Create the file or truncate it.
    Rewrite,
}

/// Directory mode before the umask, as `std::fs::create_dir_all` uses.
const DIR_MODE: Mode = Mode::from_bits_truncate(0o777);
/// File mode before the umask, as `std::fs::OpenOptions` uses.
const FILE_MODE: Mode = Mode::from_bits_truncate(0o666);

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

/// Split a relative path into its components. Refuses anything that is
/// not a plain name: empty path, absolute path, `.`, `..`, empty
/// component.
fn plain_components(relative_path: &str) -> io::Result<Vec<&str>> {
    if relative_path.is_empty() {
        return Err(invalid("relative path must not be empty"));
    }
    let parts: Vec<&str> = relative_path.split('/').collect();
    for part in &parts {
        let mut components = Path::new(part).components();
        let plain =
            matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
        if !plain || part.contains('\0') {
            return Err(invalid("relative path must be made of plain names"));
        }
    }
    Ok(parts)
}

fn open_base(storage_base: &Path) -> io::Result<OwnedFd> {
    open(
        storage_base,
        OFlag::O_DIRECTORY | OFlag::O_RDONLY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)
}

/// Descend from `dir` into `name` without following a symlink. With
/// `create`, the directory is created first when it does not exist.
fn descend(dir: &OwnedFd, name: &str, create: bool) -> io::Result<OwnedFd> {
    if create {
        match mkdirat(dir, name, DIR_MODE) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(e) => return Err(e.into()),
        }
    }
    openat(
        dir,
        name,
        OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_RDONLY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)
}

/// The directory that holds the last component, and that component.
fn parent_dir<'a>(
    storage_base: &Path,
    relative_path: &'a str,
    create: bool,
) -> io::Result<(OwnedFd, &'a str)> {
    let parts = plain_components(relative_path)?;
    let (name, dirs) = parts
        .split_last()
        .ok_or_else(|| invalid("relative path must not be empty"))?;
    let mut dir = open_base(storage_base)?;
    for part in dirs {
        dir = descend(&dir, part, create)?;
    }
    Ok((dir, name))
}

/// Reopen an existing file only if it is a regular file with no data.
fn reopen_if_empty(dir: &OwnedFd, name: &str) -> io::Result<File> {
    let exists = || io::Error::from(io::ErrorKind::AlreadyExists);
    let fd = openat(
        dir,
        name,
        OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| exists())?;
    let stat = fstat(&fd).map_err(|_| exists())?;
    let regular = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT == SFlag::S_IFREG;
    if !regular || stat.st_size != 0 {
        return Err(exists());
    }
    Ok(File::from(fd))
}

/// Open `relative_path` under `storage_base` for reading and writing,
/// creating the directories on the way.
///
/// Errors: `AlreadyExists` when a `CreateNew` target holds data;
/// `InvalidInput` for a path that is not made of plain names; the OS
/// error otherwise (a symlink on the way surfaces as `ELOOP` or
/// `ENOTDIR`, depending on the platform).
pub fn open_for_write(
    storage_base: &Path,
    relative_path: &str,
    mode: WriteOpen,
) -> io::Result<File> {
    let (dir, name) = parent_dir(storage_base, relative_path, true)?;
    let common = OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    match mode {
        WriteOpen::CreateNew => {
            match openat(
                &dir,
                name,
                common | OFlag::O_CREAT | OFlag::O_EXCL,
                FILE_MODE,
            ) {
                Ok(fd) => Ok(File::from(fd)),
                Err(Errno::EEXIST) => reopen_if_empty(&dir, name),
                Err(e) => Err(e.into()),
            }
        }
        WriteOpen::Rewrite => openat(
            &dir,
            name,
            common | OFlag::O_CREAT | OFlag::O_TRUNC,
            FILE_MODE,
        )
        .map(File::from)
        .map_err(io::Error::from),
    }
}

/// Unlink `relative_path` under `storage_base`.
///
/// Returns `false` when the file, or a directory on the way, does not
/// exist: an unlink is idempotent. A symlink on the way is an error; a
/// symlink as the last component is removed itself, never its target.
pub fn unlink(storage_base: &Path, relative_path: &str) -> io::Result<bool> {
    let (dir, name) = match parent_dir(storage_base, relative_path, false) {
        Ok(found) => found,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    match unlinkat(&dir, name, UnlinkatFlags::NoRemoveDir) {
        Ok(()) => Ok(true),
        Err(Errno::ENOENT) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::symlink;

    const REL: &str = "2026/11/sess/session.cast";

    fn seed(base: &Path, relative: &str, content: &[u8]) -> std::path::PathBuf {
        let file = base.join(relative);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, content).unwrap();
        file
    }

    #[test]
    fn test_create_new_creates_directories_and_a_read_write_file() {
        let base = tempfile::tempdir().unwrap();
        let mut file = open_for_write(base.path(), REL, WriteOpen::CreateNew).unwrap();
        file.write_all(b"data").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut back = String::new();
        file.read_to_string(&mut back).unwrap();
        assert_eq!(back, "data", "the descriptor is read-write");
        assert_eq!(std::fs::read(base.path().join(REL)).unwrap(), b"data");
    }

    #[test]
    fn attack_create_new_on_a_file_with_data_is_rejected() {
        let base = tempfile::tempdir().unwrap();
        let file = seed(base.path(), REL, b"evidence");
        let err = open_for_write(base.path(), REL, WriteOpen::CreateNew).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(file).unwrap(), b"evidence");
    }

    /// A single byte is data: the reopening is for a lost reply only.
    #[test]
    fn attack_create_new_on_a_one_byte_file_is_rejected() {
        let base = tempfile::tempdir().unwrap();
        let file = seed(base.path(), REL, b"x");
        let err = open_for_write(base.path(), REL, WriteOpen::CreateNew).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(file).unwrap(), b"x");
    }

    /// The lease was granted, the file created, and the reply lost. The
    /// same request must succeed again.
    #[test]
    fn test_create_new_reopens_a_file_that_is_still_empty() {
        let base = tempfile::tempdir().unwrap();
        drop(open_for_write(base.path(), REL, WriteOpen::CreateNew).unwrap());
        let mut again = open_for_write(base.path(), REL, WriteOpen::CreateNew).unwrap();
        again.write_all(b"data").unwrap();
        assert_eq!(std::fs::read(base.path().join(REL)).unwrap(), b"data");
    }

    #[test]
    fn test_rewrite_truncates() {
        let base = tempfile::tempdir().unwrap();
        let file = seed(base.path(), REL, b"a long first version");
        let mut rewritten = open_for_write(base.path(), REL, WriteOpen::Rewrite).unwrap();
        rewritten.write_all(b"v2").unwrap();
        assert_eq!(std::fs::read(file).unwrap(), b"v2");
    }

    /// A symlink at any directory level, pointing outside the base.
    #[test]
    fn attack_symlinked_directory_is_not_followed() {
        for level in ["2026", "2026/11", "2026/11/sess"] {
            for mode in [WriteOpen::CreateNew, WriteOpen::Rewrite] {
                let base = tempfile::tempdir().unwrap();
                let outside = tempfile::tempdir().unwrap();
                let link = base.path().join(level);
                std::fs::create_dir_all(link.parent().unwrap()).unwrap();
                symlink(outside.path(), &link).unwrap();

                assert!(
                    open_for_write(base.path(), REL, mode).is_err(),
                    "{level} {mode:?}"
                );
                assert!(
                    std::fs::read_dir(outside.path()).unwrap().next().is_none(),
                    "{level} {mode:?}: nothing may be created outside the base"
                );
            }
        }
    }

    /// A symlink in place of the file: to a file with data, to an empty
    /// file, and dangling.
    #[test]
    fn attack_symlinked_file_is_not_followed() {
        for mode in [WriteOpen::CreateNew, WriteOpen::Rewrite] {
            let base = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            let secret = outside.path().join("secret");
            let empty = outside.path().join("empty");
            let dangling = outside.path().join("absent");
            std::fs::write(&secret, b"secret").unwrap();
            std::fs::write(&empty, b"").unwrap();
            let link = base.path().join(REL);
            std::fs::create_dir_all(link.parent().unwrap()).unwrap();

            for target in [&secret, &empty, &dangling] {
                symlink(target, &link).unwrap();
                assert!(
                    open_for_write(base.path(), REL, mode).is_err(),
                    "{mode:?} -> {}",
                    target.display()
                );
                std::fs::remove_file(&link).unwrap();
            }
            assert_eq!(std::fs::read(&secret).unwrap(), b"secret", "{mode:?}");
            assert!(!dangling.exists(), "{mode:?}");
        }
    }

    #[test]
    fn attack_create_new_on_a_directory_or_fifo_is_rejected() {
        let base = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(base.path().join(REL)).unwrap();
        assert!(open_for_write(base.path(), REL, WriteOpen::CreateNew).is_err());

        let fifo = "2026/11/sess/001.mp4";
        nix::unistd::mkfifo(&base.path().join(fifo), Mode::from_bits_truncate(0o600)).unwrap();
        let err = open_for_write(base.path(), fifo, WriteOpen::CreateNew).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn attack_paths_that_are_not_plain_names_are_rejected() {
        let base = tempfile::tempdir().unwrap();
        for path in [
            "",
            "/etc/passwd",
            "../x",
            "2026/../x",
            "2026/./x",
            "2026//x",
            "2026/11/",
            ".",
            "..",
        ] {
            for mode in [WriteOpen::CreateNew, WriteOpen::Rewrite] {
                let err = open_for_write(base.path(), path, mode).unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{path:?}");
            }
            let err = unlink(base.path(), path).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{path:?}");
        }
        assert!(std::fs::read_dir(base.path()).unwrap().next().is_none());
    }

    #[test]
    fn test_unlink_removes_the_file_and_is_idempotent() {
        let base = tempfile::tempdir().unwrap();
        let file = seed(base.path(), REL, b"capture");
        assert!(unlink(base.path(), REL).unwrap());
        assert!(!file.exists());
        assert!(!unlink(base.path(), REL).unwrap());
        assert!(!unlink(base.path(), "2027/01/other/x.pcap").unwrap());
        assert!(
            !base.path().join("2027").exists(),
            "an unlink creates no directory"
        );
    }

    #[test]
    fn attack_unlink_through_a_symlinked_directory_is_rejected() {
        let base = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let victim = seed(outside.path(), "sess/session.cast", b"evidence");
        std::fs::create_dir_all(base.path().join("2026")).unwrap();
        symlink(outside.path(), base.path().join("2026/11")).unwrap();

        assert!(unlink(base.path(), REL).is_err());
        assert!(victim.exists());
    }

    #[test]
    fn test_unlink_of_a_symlink_removes_the_link_only() {
        let base = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("target");
        std::fs::write(&target, b"kept").unwrap();
        let link = base.path().join(REL);
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        symlink(&target, &link).unwrap();

        assert!(unlink(base.path(), REL).unwrap());
        assert!(link.symlink_metadata().is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"kept");
    }
}
