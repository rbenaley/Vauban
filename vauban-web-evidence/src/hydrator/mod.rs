//! Recording integrity hydration (trait-parameterized pipeline).

mod deps;
mod pipeline;

pub use deps::{
    HydratorDb, MetaFd, MetaFdOutcome, MetaOpen, Notify, PendingCandidate, SessionKind,
};
pub use pipeline::{
    FORMAT_ASCIICAST_V2, FORMAT_FMP4_DASH, FORMAT_FMP4_FLAT, FORMAT_PCAP_BUNDLE, HasSegmentHash,
    HydrationError, HydrationReport, IntegrityBundle, RECORDING_HYDRATED_EVENT,
    RECORDING_HYDRATED_RETRY_SECS, RecordingHydrator, TASK_NAME, aggregate_rdp_blake3,
    is_valid_blake3_hex, meta_relative_for, parse_meta, recording_detail_ws_filter_matches,
    recording_dir_for_session, recording_hydrated_json_payload,
};
