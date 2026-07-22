// Integration tests legitimately use unwrap/expect/panic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for the IACS PCAP recording pipeline driven
//! through `IacsRecordingManager`'s public API.
//!
//! These tests do NOT spin up a real supervisor IPC socket: they
//! exercise the same call sequence the audit `main_loop` performs
//! when it dispatches `IacsRecordingChannelStart` / `Data` /
//! `ChannelEnd` / `SessionEnd` messages. The supervisor's role
//! (broker write FDs + unlink the raw PCAP) is simulated with
//! `tempfile`-backed FDs; gzip + BLAKE3 run via [`run_gzip_cpu`]
//! (same CPU kernel as the off-thread worker).

use flate2::read::GzDecoder;
use shared::messages::IacsRecordingDirection;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use vauban_audit::iacs_recording_manager::{
    IacsChannelEndpoints, IacsRecordingConfig, IacsRecordingManager,
};
use vauban_audit::{GzipCpuJob, PendingGzipTracker, run_gzip_cpu};

fn endpoints() -> IacsChannelEndpoints {
    IacsChannelEndpoints {
        client_ip: "10.0.0.10".into(),
        client_port: 49_152,
        server_ip: "10.0.0.20".into(),
        server_port: 502,
    }
}

fn ipv6_endpoints() -> IacsChannelEndpoints {
    IacsChannelEndpoints {
        client_ip: "2001:db8::1".into(),
        client_port: 49_152,
        server_ip: "2001:db8::2".into(),
        server_port: 4840,
    }
}

fn read_all(path: &std::path::Path) -> Vec<u8> {
    std::fs::read(path).expect("read file")
}

fn read_handle(mut f: File) -> Vec<u8> {
    f.seek(SeekFrom::Start(0)).expect("seek");
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).expect("read");
    buf
}

#[test]
fn full_session_writes_global_header_handshake_data_close() {
    let mut mgr = IacsRecordingManager::new();
    let f = tempfile::tempfile().unwrap();
    let reader = f.try_clone().unwrap();

    mgr.start_channel(
        "session-1",
        1,
        f,
        "plc.local".into(),
        502,
        1_000,
        1_000,
        endpoints(),
    );
    for (i, payload) in [b"hello".as_ref(), b"world".as_ref(), b"again".as_ref()]
        .iter()
        .enumerate()
    {
        mgr.handle_data(
            "session-1",
            1,
            i as u64,
            IacsRecordingDirection::EwsToAsset,
            2_000 + i as u64,
            payload,
        )
        .unwrap();
    }
    let paths = mgr
        .end_channel("session-1", 1, 5_000)
        .expect("paths returned");
    mgr.finalize_channel_gzip("session-1", 1, "ab".repeat(32), 4242);
    let result = mgr.end_session("session-1").expect("session result");

    let bytes = read_handle(reader);
    // Global header (24) + 3 handshake records + 3 * (data record +
    // ack record) + 4 close records.
    assert!(bytes.len() > 24, "pcap is empty");
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    assert_eq!(magic, 0xa1b2_c3d4, "pcap magic missing");

    assert_eq!(result.channels.len(), 1);
    assert_eq!(result.channels[0].blake3_hex, "ab".repeat(32));
    assert!(paths.dst_relative.ends_with(".pcap.gz"));
}

#[test]
fn crash_mid_session_leaves_partial_but_pcap_magic_intact() {
    let mut mgr = IacsRecordingManager::new();
    let f = tempfile::tempfile().unwrap();
    let reader = f.try_clone().unwrap();

    mgr.start_channel("s", 1, f, "h".into(), 502, 0, 0, endpoints());
    mgr.handle_data(
        "s",
        1,
        0,
        IacsRecordingDirection::EwsToAsset,
        100,
        b"first batch",
    )
    .unwrap();
    mgr.handle_data(
        "s",
        1,
        1,
        IacsRecordingDirection::AssetToEws,
        200,
        b"second batch",
    )
    .unwrap();
    drop(mgr);

    let bytes = read_handle(reader);
    assert!(bytes.len() >= 24);
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    assert_eq!(magic, 0xa1b2_c3d4);
    let linktype = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    assert_eq!(linktype, 12, "LINKTYPE_RAW preserved through crash");
}

#[test]
fn multi_channel_session_produces_independent_pcap_files() {
    let mut mgr = IacsRecordingManager::new();
    let f1 = tempfile::tempfile().unwrap();
    let f2 = tempfile::tempfile().unwrap();
    let r1 = f1.try_clone().unwrap();
    let r2 = f2.try_clone().unwrap();

    mgr.start_channel("s", 1, f1, "h1".into(), 502, 0, 0, endpoints());
    mgr.start_channel("s", 2, f2, "h2".into(), 4840, 0, 0, ipv6_endpoints());

    // Interleave batches across the two channels.
    mgr.handle_data("s", 1, 0, IacsRecordingDirection::EwsToAsset, 100, b"abc")
        .unwrap();
    mgr.handle_data("s", 2, 0, IacsRecordingDirection::EwsToAsset, 110, b"DEF")
        .unwrap();
    mgr.handle_data(
        "s",
        1,
        1,
        IacsRecordingDirection::AssetToEws,
        200,
        b"ghijkl",
    )
    .unwrap();

    mgr.end_channel("s", 1, 1_000);
    mgr.end_channel("s", 2, 2_000);
    mgr.finalize_channel_gzip("s", 1, "11".repeat(32), 11);
    mgr.finalize_channel_gzip("s", 2, "22".repeat(32), 22);
    let result = mgr.end_session("s").unwrap();

    let b1 = read_handle(r1);
    let b2 = read_handle(r2);
    assert_eq!(
        u32::from_le_bytes([b1[0], b1[1], b1[2], b1[3]]),
        0xa1b2_c3d4
    );
    assert_eq!(
        u32::from_le_bytes([b2[0], b2[1], b2[2], b2[3]]),
        0xa1b2_c3d4
    );
    assert_eq!(result.channels.len(), 2);
    assert_eq!(result.total_bytes, 33);
}

#[test]
fn gzip_roundtrip_simulates_audit_local_gzip_and_unlink() {
    // Production ChannelEnd flow (split prepare / CPU / complete):
    //   1. end_channel returns the raw O_RDWR FD
    //   2. main: broker-open dst (simulated File::create)
    //   3. worker: run_gzip_cpu (gzip + blake3 + sync + drop src)
    //   4. main: RecordingFileUnlinkRequest -> supervisor removes raw
    //   5. finalize_channel_gzip(blake3, size)
    let dir = tempfile::tempdir().unwrap();
    let raw_path = dir.path().join("001.pcap");
    let gz_path = dir.path().join("001.pcap.gz");

    let mut mgr = IacsRecordingManager::with_config(IacsRecordingConfig {
        batch_max_bytes: 1024,
        batch_max_ms: 100,
    });
    // O_RDWR so the returned FD can be seeked+read for gzip.
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&raw_path)
        .unwrap();
    mgr.start_channel("s", 1, f, "h".into(), 502, 0, 0, endpoints());
    for i in 0..16 {
        mgr.handle_data(
            "s",
            1,
            i,
            IacsRecordingDirection::EwsToAsset,
            1_000 + i,
            b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a",
        )
        .unwrap();
    }
    let paths = mgr.end_channel("s", 1, 999_999).expect("end_channel");

    // Prepare (main): dst FD
    let dst = File::create(&gz_path).unwrap();
    let outcome = run_gzip_cpu(GzipCpuJob {
        session_id: "s".into(),
        channel_id: 1,
        src: paths.raw_file,
        dst,
        src_relative: paths.src_relative,
        dst_relative: paths.dst_relative,
    });
    let (dst_size, blake3_hex) = outcome.result.expect("cpu ok");

    // Complete (main): unlink then finalize
    std::fs::remove_file(&raw_path).unwrap();
    assert!(!raw_path.exists(), "raw pcap unlinked");

    mgr.finalize_channel_gzip("s", 1, blake3_hex.clone(), dst_size);
    let result = mgr.end_session("s").unwrap();
    assert_eq!(result.channels[0].blake3_hex, blake3_hex);
    assert_eq!(result.channels[0].file_size, dst_size);

    let compressed = read_all(&gz_path);
    assert_eq!(compressed.len() as u64, dst_size);
    assert_eq!(blake3::hash(&compressed).to_hex().as_str(), blake3_hex);

    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();
    assert!(decompressed.len() > 24, "decompressed pcap empty");
    let magic = u32::from_le_bytes([
        decompressed[0],
        decompressed[1],
        decompressed[2],
        decompressed[3],
    ]);
    assert_eq!(magic, 0xa1b2_c3d4);
}

#[test]
fn e2e_session_end_waits_for_inflight_gzip() {
    // Mirrors main_loop SessionEnd barrier: end_session / meta only
    // after pending gzip for the session hits 0.
    let dir = tempfile::tempdir().unwrap();
    let mut mgr = IacsRecordingManager::new();
    let mut pending = PendingGzipTracker::new();
    let mut jobs = Vec::new();

    for channel_id in [1u32, 2] {
        let raw_path = dir.path().join(format!("{channel_id:03}.pcap"));
        let gz_path = dir.path().join(format!("{channel_id:03}.pcap.gz"));
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&raw_path)
            .unwrap();
        mgr.start_channel(
            "s-wait",
            channel_id,
            f,
            "h".into(),
            502,
            0,
            0,
            endpoints(),
        );
        mgr.handle_data(
            "s-wait",
            channel_id,
            0,
            IacsRecordingDirection::EwsToAsset,
            100,
            b"batch",
        )
        .unwrap();
        let paths = mgr
            .end_channel("s-wait", channel_id, 200)
            .expect("end_channel");
        pending.enqueue("s-wait");
        jobs.push((
            channel_id,
            raw_path,
            GzipCpuJob {
                session_id: "s-wait".into(),
                channel_id,
                src: paths.raw_file,
                dst: File::create(&gz_path).unwrap(),
                src_relative: paths.src_relative,
                dst_relative: paths.dst_relative,
            },
        ));
    }

    // SessionEnd arrives while both jobs are still pending.
    assert!(!pending.session_end_unblocked("s-wait"));
    let deferred_reason = Some("client_close");

    let mut session_ended = false;
    for (channel_id, raw_path, job) in jobs {
        let outcome = run_gzip_cpu(job);
        let (dst_size, blake3_hex) = outcome.result.unwrap();
        std::fs::remove_file(&raw_path).unwrap();
        mgr.finalize_channel_gzip("s-wait", channel_id, blake3_hex, dst_size);
        if pending.complete("s-wait") == 0 && deferred_reason.is_some() {
            let result = mgr.end_session("s-wait").expect("deferred SessionEnd");
            assert_eq!(result.channels.len(), 2);
            session_ended = true;
        }
    }
    assert!(session_ended, "SessionEnd must run only after both gzips");
    assert!(pending.session_end_unblocked("s-wait"));
}

#[test]
fn meta_json_relative_path_uses_anchor_month() {
    let mut mgr = IacsRecordingManager::new();
    let f = tempfile::tempfile().unwrap();
    // 2024-04-30 23:59:59 UTC -- one second before the May 1st
    // boundary. The artefacts MUST land in 2024/04 (they would
    // have raced with `now()` previously).
    let connected_at_us: u64 = 1_714_521_599_000_000;
    mgr.start_channel(
        "s-april",
        1,
        f,
        "h".into(),
        502,
        connected_at_us,
        connected_at_us,
        endpoints(),
    );
    mgr.end_channel("s-april", 1, connected_at_us + 1_000_000);
    let result = mgr.end_session("s-april").unwrap();
    assert!(
        result.meta_json_relative_path.starts_with("2024/04/"),
        "got {}",
        result.meta_json_relative_path
    );
}
