//! Recording storage deletion brokered by the supervisor (privsep).

use std::path::Path;

use shared::ipc::IpcChannel;
use shared::messages::Message;
use shared::recording_paths::delete_recording_storage_path;
use tracing::{debug, error, info, warn};

/// Handle a `RecordingDeleteRequest` from vauban-web.
///
/// Only the web service may invoke this; audit never deletes recordings.
pub fn handle_recording_delete_request(
    request_id: u64,
    session_id: &str,
    relative_path: &str,
    storage_base: &str,
    requester_service_key: &str,
    channel: &IpcChannel,
) {
    let respond = |success: bool, bytes_freed: u64, error: Option<String>| {
        let _ = channel.send(&Message::RecordingDeleteResponse {
            request_id,
            session_id: session_id.to_string(),
            success,
            bytes_freed,
            error,
        });
    };

    if requester_service_key != "web" {
        warn!(
            request_id,
            service = requester_service_key,
            "RecordingDeleteRequest rejected: only vauban-web may delete recordings"
        );
        respond(
            false,
            0,
            Some("forbidden: only web may delete recordings".into()),
        );
        return;
    }

    match delete_recording_storage_path(Path::new(storage_base), relative_path, session_id) {
        Ok(bytes_freed) => {
            info!(
                request_id,
                session_id,
                path = relative_path,
                bytes_freed,
                "Recording deleted from storage"
            );
            respond(true, bytes_freed, None);
        }
        Err(e) => {
            error!(
                request_id,
                session_id,
                path = relative_path,
                error = %e,
                "Failed to delete recording from storage"
            );
            respond(false, 0, Some(e));
        }
    }

    debug!(request_id, session_id, "RecordingDeleteResponse sent");
}
