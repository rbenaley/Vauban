# Runbook -- SSH/RDP proxy-owned FD recording smoke test

> Manual validation after shipping **proxy-owned FD recording**
> (crates **0.9.29+**): SSH/RDP write media on SCM_RIGHTS FDs; audit
> writes `meta.json` from enriched `*RecordingEnd`. CI covers lints and
> wire pins; staging proves flood completeness and I/O fail-closed.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for **0.9.29** (coordinated proxy-ssh,
> proxy-rdp, audit, supervisor, shared). Do not ship without A–D.

Related:

- [Recording Architecture 1.9](../technical/Vauban_Recording_Architecture_EN(1.9).md)
- [ADR 001](../adr/001-recording-durability-per-protocol.md) (amended)
- Lints: `vauban-proxy-ssh/scripts/check_ssh_recording_fd.sh`,
  `vauban-proxy-rdp/scripts/check_rdp_recording_fd.sh`

## Automated prerequisites

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy -p shared -p vauban-proxy-ssh -p vauban-audit -p vauban-supervisor -p vauban-web --all-targets -- -D warnings
rtk cargo clippy --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target --all-targets -- -D warnings
bash vauban-proxy-ssh/scripts/check_ssh_recording_fd.sh
bash vauban-proxy-rdp/scripts/check_rdp_recording_fd.sh
rtk cargo test -p shared -p vauban-proxy-ssh -p vauban-audit -p vauban-web -- recording_fd -- --test-threads=1
rtk cargo test --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target -- recording_fd -- --test-threads=1
# hand-off:
rtk cargo test --workspace -- --test-threads=1
rtk cargo test --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target -- --test-threads=1
```

## Lab prerequisites

- Binaries **0.9.29+** coordinated (shared wire for enriched Ends).
- Recording enabled; SSH and RDP assets available.
- Ability to read proxy-ssh / proxy-rdp / audit logs.
- Disk space under `recordings/` (or `/var/vauban/recordings`).

## A -- SSH calm

1. Open a short SSH session; run a few quiet commands (`ls`, `pwd`).
2. Disconnect; wait for hydrate.
3. Expect Ready, **no** Incomplete capture, Play OK.
4. Confirm `meta.json` blake3 matches `session.cast` on disk.

Pass: clean recording, badge absent.

## B -- SSH flood

1. Open SSH; run `du /` (or equivalent high-volume stdout).
2. Disconnect; wait for hydrate.
3. Expect **no** Incomplete capture (unless real disk/broker failure).
4. Cast size large and coherent; proxy logs must **not** show
   `RecordingLossObserved` for try_send (media is local FD).

Pass: flood captured forensically without IPC drops.

## C -- RDP

1. Open RDP session; optionally resize once mid-session.
2. Disconnect; open Recording Details.
3. Expect segments in meta, Play/DASH OK, `recording_lossy=false`.

Pass: multi-segment FD lease works; no Incomplete badge.

## D -- Fail-closed I/O

1. Lab: force recording path ENOSPC / invalid FD lease (e.g. stop
   supervisor broker briefly mid-open, or fill the filesystem).
2. Open SSH or RDP and generate output.
3. Expect Incomplete capture badge + `recording_lossy` latch; session
   interactive path remains usable.
4. Restore disk/broker; new sessions record cleanly.

Pass: loss is detectable and sticky; UX not ack-blocked.

## Rollback notes

- Mixed versions without enriched `*RecordingEnd` break meta seal.
- Reintroducing `SshRecordingData` / `RdpVideoFrame` firehose fails
  structural lints.
