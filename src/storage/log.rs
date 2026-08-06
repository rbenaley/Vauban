//! Storage helper / portal storage-client logging helpers.
//!
//! Process identity: helper lines use [`STORE_LOG_TARGET`] (`vcp-store`);
//! portal call sites use the default `vcp::…` module path.
//!
//! Policy: DEBUG per IPC op; WARN on every denied / failed op with code +
//! message; ERROR reserved for local wire / unexpected I/O that aborts the
//! connection. Never log image bytes, WebAuthn assertions, or secrets.

use std::path::Path;

use super::STORE_LOG_TARGET;
use super::error::StorageError;

/// DEBUG: one line at the start of an IPC dispatch arm.
pub fn op_begin(op: &str) {
    tracing::debug!(target: STORE_LOG_TARGET, op, "storage ipc");
}

/// WARN: engine / business failure returned to the portal as an error code.
pub fn op_failed(op: &str, err: &StorageError) {
    tracing::warn!(
        target: STORE_LOG_TARGET,
        op,
        code = %err.code,
        error = %err.message,
        "storage op failed"
    );
}

/// WARN: absolute-path / FD handoff open failed (typical Capsicum ENOTCAPABLE).
pub fn fd_handoff_failed(op: &str, path: &Path, err: &std::io::Error) {
    tracing::warn!(
        target: STORE_LOG_TARGET,
        op,
        path = %path.display(),
        os_error = %err,
        "failed to open path for SCM_RIGHTS handoff"
    );
}

/// ERROR: length-prefixed IPC encode/send/FD-pass failed (connection dies).
pub fn wire_failed(op: &str, step: &str, err: &StorageError) {
    tracing::error!(
        target: STORE_LOG_TARGET,
        op,
        step,
        code = %err.code,
        error = %err.message,
        "storage ipc wire failed"
    );
}

/// WARN (portal): storage client / attach denial before a soft UI redirect.
pub fn portal_storage_failed(surface: &str, err: &StorageError) {
    tracing::warn!(
        surface,
        code = %err.code,
        error = %err.message,
        "portal storage call failed"
    );
}

/// WARN (portal): non-storage attach error (cap, token, db string, …).
pub fn portal_attach_failed(surface: &str, error: &dyn std::fmt::Display) {
    tracing::warn!(surface, error = %error, "portal attach failed");
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    use proptest::prelude::*;
    use tracing::Subscriber;
    use tracing::field::{Field, Visit};
    use tracing_subscriber::Registry;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::layer::{Context, Layer};

    use super::*;
    use crate::storage::error::{StorageError, StorageErrorCode};

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<Captured>>>);

    #[derive(Clone, Debug)]
    struct Captured {
        level: String,
        target: String,
        message: String,
        fields: String,
    }

    impl Capture {
        fn take(&self) -> Vec<Captured> {
            std::mem::take(&mut *self.0.lock().expect("capture mutex"))
        }
    }

    impl<S> Layer<S> for Capture
    where
        S: Subscriber,
    {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            struct FieldVisit {
                message: String,
                fields: String,
            }
            impl Visit for FieldVisit {
                fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                    if field.name() == "message" {
                        self.message = format!("{value:?}").trim_matches('"').to_owned();
                    } else {
                        self.fields
                            .push_str(&format!(" {}={value:?}", field.name()));
                    }
                }
                fn record_str(&mut self, field: &Field, value: &str) {
                    if field.name() == "message" {
                        self.message = value.to_owned();
                    } else {
                        self.fields.push_str(&format!(" {}={value}", field.name()));
                    }
                }
            }
            let mut v = FieldVisit {
                message: String::new(),
                fields: String::new(),
            };
            event.record(&mut v);
            self.0.lock().expect("capture mutex").push(Captured {
                level: event.metadata().level().to_string(),
                target: event.metadata().target().to_owned(),
                message: v.message,
                fields: v.fields,
            });
        }
    }

    fn with_capture(f: impl FnOnce()) -> Vec<Captured> {
        let cap = Capture::default();
        let subscriber = Registry::default().with(cap.clone());
        tracing::subscriber::with_default(subscriber, f);
        cap.take()
    }

    #[test]
    fn unit_op_failed_is_warn_on_vcp_store_target() {
        let err = StorageError::new(StorageErrorCode::Io, "open tmp: capability mode");
        let lines = with_capture(|| op_failed("put_begin", &err));
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].level, "WARN");
        assert_eq!(lines[0].target, STORE_LOG_TARGET);
        assert!(lines[0].message.contains("storage op failed"));
        assert!(lines[0].fields.contains("op=put_begin"));
        assert!(lines[0].fields.contains("code=io"));
        assert!(lines[0].fields.contains("capability mode"));
    }

    #[test]
    fn unit_fd_handoff_failed_includes_path_and_os_error() {
        let err = io::Error::new(io::ErrorKind::PermissionDenied, "ENOTCAPABLE");
        let lines = with_capture(|| {
            fd_handoff_failed(
                "put_begin",
                Path::new("/var/db/vcp/storage/tmp/x.partial"),
                &err,
            )
        });
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].level, "WARN");
        assert_eq!(lines[0].target, STORE_LOG_TARGET);
        assert!(lines[0].message.contains("SCM_RIGHTS"));
        assert!(lines[0].fields.contains("tmp/x.partial"));
        assert!(lines[0].fields.contains("ENOTCAPABLE"));
    }

    #[test]
    fn unit_wire_failed_is_error() {
        let err = StorageError::new(StorageErrorCode::Io, "send_fd: broken pipe");
        let lines = with_capture(|| wire_failed("get", "send_fd", &err));
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].level, "ERROR");
        assert_eq!(lines[0].target, STORE_LOG_TARGET);
        assert!(lines[0].fields.contains("step=send_fd"));
    }

    #[test]
    fn unit_op_begin_is_debug() {
        let lines = with_capture(|| op_begin("key_enrol_stage"));
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].level, "DEBUG");
        assert_eq!(lines[0].target, STORE_LOG_TARGET);
        assert!(lines[0].fields.contains("op=key_enrol_stage"));
    }

    #[test]
    fn unit_portal_storage_failed_uses_default_target() {
        let err = StorageError::new(StorageErrorCode::Busy, "too many uploads");
        let lines = with_capture(|| portal_storage_failed("issue_reply_screenshots", &err));
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].level, "WARN");
        assert_ne!(lines[0].target, STORE_LOG_TARGET);
        assert!(lines[0].target.contains("storage") || lines[0].target.contains("vcp"));
        assert!(lines[0].fields.contains("surface=issue_reply_screenshots"));
        assert!(lines[0].fields.contains("code=busy"));
    }

    proptest! {
        #[test]
        fn prop_op_failed_always_embeds_code(
            code in prop_oneof![
                Just(StorageErrorCode::NotFound),
                Just(StorageErrorCode::InvalidId),
                Just(StorageErrorCode::Quota),
                Just(StorageErrorCode::OrgQuota),
                Just(StorageErrorCode::BadImage),
                Just(StorageErrorCode::DigestMismatch),
                Just(StorageErrorCode::IntegrityMismatch),
                Just(StorageErrorCode::Io),
                Just(StorageErrorCode::Busy),
                Just(StorageErrorCode::WebauthnRequired),
                Just(StorageErrorCode::WebauthnInvalid),
                Just(StorageErrorCode::WebauthnExpired),
                Just(StorageErrorCode::ChallengeUnknown),
                Just(StorageErrorCode::ObjectModified),
            ],
            msg in "[a-z0-9 _-]{0,40}"
        ) {
            let err = StorageError::new(code, msg);
            let lines = with_capture(|| op_failed("prop_op", &err));
            prop_assert_eq!(lines.len(), 1);
            prop_assert_eq!(lines[0].level.as_str(), "WARN");
            prop_assert!(
                lines[0].fields.contains(&format!("code={}", code.as_str())),
                "missing code in {:?}",
                lines[0].fields
            );
        }
    }

    #[test]
    fn battle_concurrent_op_failed_does_not_panic() {
        use std::sync::Barrier;
        use std::thread;

        let n = 8;
        let barrier = Arc::new(Barrier::new(n));
        let mut handles = Vec::new();
        for i in 0..n {
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                let err = StorageError::new(StorageErrorCode::Io, format!("battle-{i}"));
                op_failed("battle", &err);
                fd_handoff_failed(
                    "battle",
                    Path::new("/tmp/vcp-battle.partial"),
                    &io::Error::other("battle"),
                );
            }));
        }
        for h in handles {
            h.join().expect("battle thread");
        }
    }
}
