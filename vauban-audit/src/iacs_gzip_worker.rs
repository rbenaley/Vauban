//! Off-thread IACS ChannelEnd gzip CPU (post-0.9.24 HOL).
//!
//! The audit main loop keeps exclusive ownership of the supervisor
//! IPC channel and fd-passing socket. This module owns **only** the
//! two SCM_RIGHTS `File`s for the duration of compression: no
//! supervisor IPC types, no `open()`, no unlink.
//!
//! Flow:
//! 1. Main: `end_channel` → broker-open `.pcap.gz` → enqueue [`GzipCpuJob`]
//! 2. Worker: [`run_gzip_cpu`] → wakeup pipe byte
//! 3. Main: unlink raw + [`IacsRecordingManager::finalize_channel_gzip`]

use crate::iacs_recording_manager::gzip_channel_pcap_on_fds;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::mpsc::{Receiver, Sender};
use std::thread::{self, JoinHandle};
use tracing::{debug, error, warn};

/// CPU-only job handed to the gzip worker after the main loop has
/// already brokered the destination FD.
pub struct GzipCpuJob {
    pub session_id: String,
    pub channel_id: u32,
    pub src: File,
    pub dst: File,
    pub src_relative: String,
    pub dst_relative: String,
}

/// Result delivered back to the main loop via mpsc + wakeup pipe.
pub struct GzipCpuOutcome {
    pub session_id: String,
    pub channel_id: u32,
    pub src_relative: String,
    pub dst_relative: String,
    /// `Ok((dst_size, blake3_hex))` after successful gzip + `dst.sync_data`
    /// and `drop(src)`. `Err` means CPU/sync failed; raw may remain on disk.
    pub result: Result<(u64, String), String>,
}

/// Run gzip + BLAKE3 + fdatasync on the job's FDs. Never touches IPC.
#[must_use]
pub fn run_gzip_cpu(job: GzipCpuJob) -> GzipCpuOutcome {
    let GzipCpuJob {
        session_id,
        channel_id,
        mut src,
        mut dst,
        src_relative,
        dst_relative,
    } = job;

    let result = (|| {
        src.sync_data()
            .map_err(|e| format!("sync_data raw pcap: {e}"))?;
        src.seek(SeekFrom::Start(0))
            .map_err(|e| format!("seek raw pcap: {e}"))?;
        let (dst_size, blake3_hex) = gzip_channel_pcap_on_fds(&mut src, &mut dst)?;
        dst.sync_data()
            .map_err(|e| format!("sync_data pcap.gz: {e}"))?;
        // Drop raw FD before main asks supervisor to unlink.
        drop(src);
        drop(dst);
        Ok((dst_size, blake3_hex))
    })();

    if let Err(ref e) = result {
        warn!(
            session_id = %session_id,
            channel_id,
            error = %e,
            "IACS gzip CPU job failed"
        );
    } else {
        debug!(
            session_id = %session_id,
            channel_id,
            "IACS gzip CPU job completed"
        );
    }

    GzipCpuOutcome {
        session_id,
        channel_id,
        src_relative,
        dst_relative,
        result,
    }
}

/// Spawn the dedicated gzip worker. `wake_write` is the write end of a
/// pipe the main loop polls; one byte is written per completed job.
pub fn spawn_gzip_worker(
    job_rx: Receiver<GzipCpuJob>,
    outcome_tx: Sender<GzipCpuOutcome>,
    wake_write: OwnedFd,
) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("iacs-gzip".into())
        .spawn(move || {
            let wake_fd = wake_write.as_raw_fd();
            while let Ok(job) = job_rx.recv() {
                let outcome = run_gzip_cpu(job);
                if outcome_tx.send(outcome).is_err() {
                    error!("IACS gzip outcome channel closed; worker stopping");
                    break;
                }
                if let Err(e) = write_wake_byte(wake_fd) {
                    error!(error = %e, "IACS gzip wake write failed; worker stopping");
                    break;
                }
            }
            debug!("IACS gzip worker stopped");
            drop(wake_write);
        })
}

fn write_wake_byte(fd: RawFd) -> std::io::Result<()> {
    loop {
        // SAFETY: wake_write OwnedFd is live for the worker lifetime.
        let n = unsafe { libc::write(fd, [1u8].as_ptr().cast(), 1) };
        if n == 1 {
            return Ok(());
        }
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "wake pipe write returned 0",
        ));
    }
}

/// Create a wakeup pipe suitable for `poll(2)` (read end non-blocking).
pub fn wakeup_pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    // SAFETY: standard pipe(2); fds initialized on success.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    for fd in fds {
        // SAFETY: freshly created pipe ends.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    // Non-blocking read so drain never stalls the main loop.
    // SAFETY: valid read fd.
    let flags = unsafe { libc::fcntl(fds[0], libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fds[0], libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: unique ownership of each end.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Drain all pending bytes from the wakeup read end (edge coalesce).
pub fn drain_wakeup(read_fd: RawFd) {
    let mut buf = [0u8; 64];
    loop {
        // SAFETY: caller owns the read end for the process lifetime.
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n == 0 {
            break;
        }
        if n < 0 {
            let err = std::io::Error::last_os_error();
            match err.kind() {
                std::io::ErrorKind::WouldBlock => break,
                std::io::ErrorKind::Interrupted => continue,
                _ => {
                    warn!(error = %err, "IACS gzip wakeup drain error");
                    break;
                }
            }
        }
    }
}

/// Session-scoped pending gzip counter for SessionEnd barrier.
#[derive(Debug, Default)]
pub struct PendingGzipTracker {
    by_session: HashMap<String, usize>,
}

impl PendingGzipTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue(&mut self, session_id: &str) {
        *self.by_session.entry(session_id.to_string()).or_insert(0) += 1;
    }

    /// Returns remaining count for the session after decrement (0 if gone).
    pub fn complete(&mut self, session_id: &str) -> usize {
        let Some(entry) = self.by_session.get_mut(session_id) else {
            return 0;
        };
        *entry = entry.saturating_sub(1);
        let left = *entry;
        if left == 0 {
            self.by_session.remove(session_id);
        }
        left
    }

    #[must_use]
    pub fn pending_for(&self, session_id: &str) -> usize {
        self.by_session.get(session_id).copied().unwrap_or(0)
    }

    #[must_use]
    pub fn total_pending(&self) -> usize {
        self.by_session.values().sum()
    }

    /// True when SessionEnd may proceed for `session_id`.
    #[must_use]
    pub fn session_end_unblocked(&self, session_id: &str) -> bool {
        self.pending_for(session_id) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::{Read, Write};
    use tempfile::NamedTempFile;

    fn write_src(bytes: &[u8]) -> File {
        let mut f = NamedTempFile::new().unwrap().into_file();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
        f
    }

    #[test]
    fn run_gzip_cpu_roundtrips_and_hashes() {
        let payload = b"\x00\x01\x02\x03pcap-like-bytes";
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        let outcome = run_gzip_cpu(GzipCpuJob {
            session_id: "s".into(),
            channel_id: 1,
            src: write_src(payload),
            dst: tmp.reopen().unwrap(),
            src_relative: "raw.pcap".into(),
            dst_relative: "raw.pcap.gz".into(),
        });
        let (size, hex) = outcome.result.expect("ok");
        assert_eq!(hex.len(), 64);
        assert!(size > 0);
        let compressed = std::fs::read(&path).unwrap();
        assert_eq!(compressed.len() as u64, size);
        let mut dec = GzDecoder::new(&compressed[..]);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn pending_tracker_barrier() {
        let mut t = PendingGzipTracker::new();
        assert!(t.session_end_unblocked("s"));
        t.enqueue("s");
        t.enqueue("s");
        assert!(!t.session_end_unblocked("s"));
        assert_eq!(t.complete("s"), 1);
        assert!(!t.session_end_unblocked("s"));
        assert_eq!(t.complete("s"), 0);
        assert!(t.session_end_unblocked("s"));
    }

    #[test]
    fn wakeup_pipe_roundtrip() {
        use std::os::fd::AsRawFd;
        let (r, w) = wakeup_pipe().unwrap();
        write_wake_byte(w.as_raw_fd()).unwrap();
        write_wake_byte(w.as_raw_fd()).unwrap();
        drain_wakeup(r.as_raw_fd());
        // Second drain is a no-op (WouldBlock).
        drain_wakeup(r.as_raw_fd());
    }
}
