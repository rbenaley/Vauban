//! Structural pin + offline E2E tests for the IACS PCAP download
//! endpoint (`/sessions/recordings/{uuid}/download` for an
//! `IacsTunnel` recording).
//!
//! A real TestApp + supervisor harness is intentionally out of
//! scope here because `SupervisorClient` is a concrete type, not a
//! trait, so mocking the FD broker requires test-only infra that
//! does not exist yet. The pins below cover:
//!
//! 1. The handler is wired to `stream_iacs_pcap_zip` for IACS
//!    sessions.
//! 2. The ZIP entries use `Compression::Stored` (the per-channel
//!    `.pcap.gz` files are already gzip'd; re-deflating would
//!    triple the CPU budget for zero compression gain).
//! 3. `meta.json` is read FIRST (the channel list comes from there)
//!    and every `channels[].file` entry is fetched from the
//!    supervisor.
//! 4. The ZIP magic / entry structure is correct given a synthetic
//!    fixture set (offline test).

use async_zip::base::write::ZipFileWriter;
use async_zip::{AttributeCompatibility, Compression, ZipEntryBuilder};
use futures_util::io::AsyncWriteExt as FuturesAsyncWriteExt;

/// Mirror of `iacs_zip_entry_owner_rw` in sessions.rs (offline E2E).
fn iacs_zip_entry_owner_rw(filename: impl Into<async_zip::ZipString>) -> async_zip::ZipEntry {
    ZipEntryBuilder::new(filename.into(), Compression::Stored)
        .attribute_compatibility(AttributeCompatibility::Unix)
        .unix_permissions(0o600)
        .build()
}

const SESSIONS_RS: &str = include_str!("../../src/handlers/web/sessions.rs");
const HYDRATOR_RS: &str = include_str!("../../../vauban-web-evidence/src/hydrator/pipeline.rs");

#[test]
fn iacs_download_handler_is_wired_for_pcap_bundle() {
    assert!(
        SESSIONS_RS.contains("stream_iacs_pcap_zip(&state, &session_uuid_db, base_dir)"),
        "IACS sessions must dispatch to stream_iacs_pcap_zip"
    );
}

#[test]
fn pcap_gz_entries_are_stored_not_deflated() {
    assert!(
        SESSIONS_RS.contains("Compression::Stored"),
        "ZIP entries must use Stored compression -- .pcap.gz is already gzip-compressed; \
         re-deflating wastes CPU and produces a larger output"
    );
    assert!(
        !SESSIONS_RS.contains("Compression::Deflate"),
        "stream_iacs_pcap_zip must not Deflate already-compressed entries"
    );
}

#[test]
fn iacs_zip_entries_pin_unix_mode_0600() {
    assert!(
        SESSIONS_RS.contains("fn iacs_zip_entry_owner_rw"),
        "IACS ZIP helper must exist"
    );
    assert!(
        SESSIONS_RS.contains("unix_permissions(0o600)"),
        "IACS ZIP entries must set Unix mode 0o600"
    );
    assert!(
        SESSIONS_RS.contains("AttributeCompatibility::Unix"),
        "unix_permissions requires AttributeCompatibility::Unix"
    );
    assert!(
        SESSIONS_RS.contains("iacs_zip_entry_owner_rw(\"meta.json\")"),
        "meta.json entry must go through the 0o600 helper"
    );
    assert!(
        SESSIONS_RS.contains("iacs_zip_entry_owner_rw(name)"),
        "channel .pcap.gz entries must go through the 0o600 helper"
    );
}

#[test]
fn meta_json_is_read_before_channel_files() {
    let meta_idx = SESSIONS_RS
        .find("\"meta.json missing\"")
        .expect("meta.json early-out required");
    let channels_idx = SESSIONS_RS
        .find("for ch in &meta.channels")
        .expect("channel iteration required");
    assert!(
        meta_idx < channels_idx,
        "meta.json MUST be fetched and parsed before iterating channels"
    );
}

#[test]
fn iacs_session_path_matches_audit_layout() {
    // Both audit and web derive paths from `connected_at`; the
    // helper in vauban-web mirrors `compute_base_dir` in vauban-audit.
    assert!(
        HYDRATOR_RS.contains("pub fn recording_dir_for_session"),
        "recording_dir_for_session must be public so handlers can call it"
    );
    assert!(
        HYDRATOR_RS.contains("anchor"),
        "recording_dir_for_session must accept a wall-clock anchor (= connected_at)"
    );
}

#[tokio::test]
async fn synthetic_zip_round_trips_meta_plus_two_pcap_gz_entries() {
    // Build the exact ZIP shape stream_iacs_pcap_zip produces, but
    // wholly in-memory, then reparse with the same async_zip reader
    // a client would use. This is an offline E2E that does not
    // depend on the supervisor IPC at all -- it pins the ZIP
    // contract (entries, ordering, compression) so a refactor of
    // the streaming side cannot silently break what tcpdump /
    // Wireshark expect to see when extracting the bundle.

    use async_zip::base::read::seek::ZipFileReader;
    use futures_util::io::Cursor as FuturesCursor;

    // Synthetic fixtures. The .pcap.gz contents do NOT need to be
    // a real PCAP; we only verify the ZIP entries round-trip
    // unchanged.
    let meta_json = br#"{
        "format": "pcap-bundle",
        "channels": [
            {"index": 1, "file": "channels/001.pcap.gz"},
            {"index": 2, "file": "channels/002.pcap.gz"}
        ],
        "blake3_hex": ""
    }"#
    .to_vec();
    let pcap1 = b"\x1f\x8b\x08\x00".to_vec(); // gzip magic
    let pcap2 = b"\x1f\x8b\x08\x00\x00\x00\x00\x00".to_vec();

    let mut buf: Vec<u8> = Vec::new();
    {
        let cursor = FuturesCursor::new(&mut buf);
        let mut zip = ZipFileWriter::new(cursor);

        let entry = iacs_zip_entry_owner_rw("meta.json");
        let mut e = zip.write_entry_stream(entry).await.unwrap();
        e.write_all(&meta_json).await.unwrap();
        e.close().await.unwrap();

        let entry = iacs_zip_entry_owner_rw("channels/001.pcap.gz");
        let mut e = zip.write_entry_stream(entry).await.unwrap();
        e.write_all(&pcap1).await.unwrap();
        e.close().await.unwrap();

        let entry = iacs_zip_entry_owner_rw("channels/002.pcap.gz");
        let mut e = zip.write_entry_stream(entry).await.unwrap();
        e.write_all(&pcap2).await.unwrap();
        e.close().await.unwrap();

        zip.close().await.unwrap();
    }

    // ZIP magic ("PK\x03\x04" local file header).
    assert_eq!(&buf[0..4], b"PK\x03\x04", "missing ZIP local file magic");

    // Reparse and validate entries (futures Cursor supports
    // AsyncSeek + AsyncBufRead unlike std's Cursor).
    let mut reader = ZipFileReader::new(FuturesCursor::new(buf.clone()))
        .await
        .unwrap();
    let entries = reader.file().entries();
    assert_eq!(entries.len(), 3, "expected exactly 3 entries");
    let names: Vec<String> = entries
        .iter()
        .map(|e| e.filename().as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        names,
        vec![
            "meta.json".to_string(),
            "channels/001.pcap.gz".to_string(),
            "channels/002.pcap.gz".to_string()
        ]
    );

    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(
            entry.attribute_compatibility(),
            AttributeCompatibility::Unix,
            "entry {i} must advertise Unix attrs"
        );
        assert_eq!(
            entry.unix_permissions(),
            Some(0o600),
            "entry {i} must extract as owner rw ------- (0o600)"
        );
    }

    // Re-extract the first PCAP entry to make sure Stored
    // compression preserved the bytes (gzip magic must be intact).
    let mut entry_reader = reader.reader_with_entry(1).await.unwrap();
    let mut extracted = Vec::new();
    futures_util::io::AsyncReadExt::read_to_end(&mut entry_reader, &mut extracted)
        .await
        .unwrap();
    assert_eq!(
        &extracted[..4],
        b"\x1f\x8b\x08\x00",
        "gzip magic lost in ZIP round-trip"
    );
}

#[test]
fn meta_json_format_field_is_exactly_pcap_bundle() {
    // Defence in depth: the recording_format DB enum CHECK
    // constraint accepts only `'pcap-bundle'` (with the dash) for
    // IACS recordings. Audit's serialize_meta_json must emit the
    // same literal -- a divergence here would silently break
    // hydration.
    let audit_src = include_str!("../../../vauban-audit/src/iacs_recording_manager.rs");
    assert!(
        audit_src.contains("\"pcap-bundle\""),
        "audit meta.json must contain literal \"pcap-bundle\""
    );
    let hydrator_src = include_str!("../../../vauban-web-evidence/src/hydrator/pipeline.rs");
    assert!(
        hydrator_src.contains("pcap-bundle") || hydrator_src.contains("FORMAT_PCAP_BUNDLE"),
        "hydrator must recognise the pcap-bundle format"
    );
}
