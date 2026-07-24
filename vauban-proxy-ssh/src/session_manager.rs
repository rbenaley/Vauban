//! Session manager for handling multiple concurrent SSH sessions.

use crate::error::{SessionError, SessionResult};
use crate::input_redactor::InputRedactor;
use crate::session::{SessionConfig, SshSession};
use crate::ssh_cast_writer::SshCastWriter;
use shared::messages::{Message, SshRecordingEvent};
use std::collections::HashMap;
use std::fs::File;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;
use tokio::sync::{RwLock, mpsc, oneshot};
use tracing::{debug, error, info, warn};

/// Hook invoked once when a session can no longer write its recording.
pub type RecordingWriteErrorHook = Arc<dyn Fn(&str) + Send + Sync>;

/// Main-loop client used by session tasks to lease recording files.
#[derive(Clone)]
pub struct RecordingLeaseClient {
    pub tx: mpsc::Sender<RecordingLeaseReq>,
}

/// Request routed through the main loop so it remains the sole IPC reader.
pub struct RecordingLeaseReq {
    pub session_id: String,
    pub relative_path: String,
    pub reply: oneshot::Sender<Result<File, String>>,
}

/// Recording resources supplied to a newly-created session.
pub enum RecordingSetup {
    /// A file was leased before the session task started.
    #[allow(dead_code)] // Injection seam for callers that already own a supervisor-leased FD.
    PreLeased {
        file: File,
        relative_path: String,
        meta_json_relative_path: String,
    },
    /// Ask the proxy main loop to lease the file from the supervisor.
    Lease(RecordingLeaseClient),
}

/// Commands that can be sent to a session task.
#[derive(Debug)]
pub enum SessionCommand {
    /// Send data to the SSH channel.
    Data(Vec<u8>),
    /// Resize the terminal.
    Resize { cols: u16, rows: u16 },
    /// Close the session.
    Close,
}

/// Handle for communicating with a session task.
pub struct SessionHandle {
    /// Channel to send commands to the session task.
    tx: mpsc::Sender<SessionCommand>,
}

/// Thread-safe manager for multiple SSH sessions.
pub struct SessionManager {
    /// Map of session_id -> SessionHandle.
    /// Wrapped in Arc so it can be shared with cleanup handles.
    sessions: Arc<RwLock<HashMap<String, SessionHandle>>>,
    /// Counter for active sessions (atomic for fast reads).
    /// Wrapped in Arc so it can be shared with cleanup handles.
    active_count: Arc<AtomicU32>,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            active_count: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Create a new SSH session and spawn a task to manage it.
    /// Returns the session_id on success.
    pub async fn create_session(
        &self,
        config: SessionConfig,
        web_tx: mpsc::Sender<Message>,
        audit_tx: Option<mpsc::Sender<Message>>,
        recording: Option<RecordingSetup>,
        recording_write_error: Option<RecordingWriteErrorHook>,
    ) -> SessionResult<String> {
        let session_id = config.session_id.clone();

        // Check if session already exists
        {
            let sessions = self.sessions.read().await;
            if sessions.contains_key(&session_id) {
                return Err(SessionError::SessionAlreadyExists(session_id));
            }
        }

        debug!(session_id = %session_id, "Creating new SSH session");

        // Connect to SSH server (consumes config because of OwnedFd)
        let ssh_session = SshSession::connect(config).await?;

        // Create command channel for this session
        let (cmd_tx, cmd_rx) = mpsc::channel(32);

        // Create session handle
        let handle = SessionHandle { tx: cmd_tx };

        // Add to sessions map
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), handle);
        }
        self.active_count.fetch_add(1, Ordering::SeqCst);

        // Spawn session task
        let session_id_clone = session_id.clone();
        let manager = self.clone_for_cleanup();
        tokio::spawn(async move {
            session_task(
                session_id_clone.clone(),
                ssh_session,
                cmd_rx,
                web_tx,
                audit_tx,
                recording,
                recording_write_error,
            )
            .await;
            // Cleanup when task ends
            manager.remove_session_internal(&session_id_clone).await;
        });

        Ok(session_id)
    }

    /// Send data to a session.
    pub async fn send_data(&self, session_id: &str, data: Vec<u8>) -> SessionResult<()> {
        let sessions = self.sessions.read().await;
        if let Some(handle) = sessions.get(session_id) {
            handle
                .tx
                .send(SessionCommand::Data(data))
                .await
                .map_err(|_| SessionError::SessionClosed)?;
            Ok(())
        } else {
            Err(SessionError::SessionNotFound(session_id.to_string()))
        }
    }

    /// Resize a session's terminal.
    pub async fn resize(&self, session_id: &str, cols: u16, rows: u16) -> SessionResult<()> {
        let sessions = self.sessions.read().await;
        if let Some(handle) = sessions.get(session_id) {
            handle
                .tx
                .send(SessionCommand::Resize { cols, rows })
                .await
                .map_err(|_| SessionError::SessionClosed)?;
            Ok(())
        } else {
            Err(SessionError::SessionNotFound(session_id.to_string()))
        }
    }

    /// Close a session.
    pub async fn close_session(&self, session_id: &str) -> SessionResult<()> {
        let sessions = self.sessions.read().await;
        if let Some(handle) = sessions.get(session_id) {
            // Send close command - the task will cleanup
            let _ = handle.tx.send(SessionCommand::Close).await;
            Ok(())
        } else {
            Err(SessionError::SessionNotFound(session_id.to_string()))
        }
    }

    /// Get the number of active sessions.
    pub fn active_count(&self) -> u32 {
        self.active_count.load(Ordering::SeqCst)
    }

    /// Create a lightweight handle for cleanup operations.
    /// Shares the real sessions map and active_count so that
    /// remove_session_internal actually removes from the real HashMap.
    fn clone_for_cleanup(&self) -> SessionManagerCleanup {
        SessionManagerCleanup {
            sessions: Arc::clone(&self.sessions),
            active_count: Arc::clone(&self.active_count),
        }
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Lightweight handle for cleanup operations (avoids circular Arc).
/// Shares the real sessions map and active_count via Arc,
/// so remove_session_internal actually cleans up ended sessions.
struct SessionManagerCleanup {
    sessions: Arc<RwLock<HashMap<String, SessionHandle>>>,
    active_count: Arc<AtomicU32>,
}

impl SessionManagerCleanup {
    /// Remove a session from the map and decrement the active counter.
    /// Called by the session task when it ends (SSH channel closed, error, etc.).
    async fn remove_session_internal(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        if sessions.remove(session_id).is_some() {
            self.active_count.fetch_sub(1, Ordering::SeqCst);
            info!(session_id = %session_id, "Session removed from manager");
        }
    }
}

fn observe_recording_error(
    session_id: &str,
    error: &dyn std::fmt::Display,
    hook: &Option<RecordingWriteErrorHook>,
    web_tx: &mpsc::Sender<Message>,
    loss_observed: &mut bool,
) {
    if *loss_observed {
        return;
    }
    *loss_observed = true;
    error!(session_id = %session_id, error = %error, "SSH recording write failed");
    if let Some(hook) = hook {
        hook(session_id);
    }
    if web_tx
        .try_send(Message::RecordingLossObserved {
            session_id: session_id.to_string(),
        })
        .is_err()
    {
        warn!(
            session_id = %session_id,
            "Failed to enqueue RecordingLossObserved to web"
        );
    }
}

/// Task that handles a single SSH session.
async fn session_task(
    session_id: String,
    mut ssh_session: SshSession,
    mut commands: mpsc::Receiver<SessionCommand>,
    web_tx: mpsc::Sender<Message>,
    audit_tx: Option<mpsc::Sender<Message>>,
    recording: Option<RecordingSetup>,
    recording_write_error: Option<RecordingWriteErrorHook>,
) {
    debug!(session_id = %session_id, "Session task started");

    let (cols, rows) = ssh_session.terminal_size();
    let meta_json_relative_path = SshCastWriter::compute_meta_json_relative_path(&session_id);
    let base_dir = meta_json_relative_path
        .strip_suffix("/meta.json")
        .unwrap_or(meta_json_relative_path.as_str());
    let relative_path = format!("{base_dir}/session.cast");
    let mut recording_loss_observed = false;
    let recording_file = match recording {
        Some(RecordingSetup::PreLeased {
            file,
            relative_path: preleased_relative_path,
            meta_json_relative_path: preleased_meta_path,
        }) => Some((file, preleased_relative_path, preleased_meta_path)),
        Some(RecordingSetup::Lease(client)) => {
            let (reply, receive) = oneshot::channel();
            let request = RecordingLeaseReq {
                session_id: session_id.clone(),
                relative_path: relative_path.clone(),
                reply,
            };
            match client.tx.send(request).await {
                Ok(()) => match tokio::time::timeout(
                    shared::recording_fd::DEFAULT_BROKER_TIMEOUT,
                    receive,
                )
                .await
                {
                    Ok(Ok(Ok(file))) => Some((file, relative_path, meta_json_relative_path)),
                    Ok(Ok(Err(error))) => {
                        warn!(session_id = %session_id, %error, "Recording lease refused");
                        observe_recording_error(
                            &session_id,
                            &error,
                            &recording_write_error,
                            &web_tx,
                            &mut recording_loss_observed,
                        );
                        None
                    }
                    Ok(Err(_)) => {
                        let error = "recording lease reply channel closed";
                        observe_recording_error(
                            &session_id,
                            &error,
                            &recording_write_error,
                            &web_tx,
                            &mut recording_loss_observed,
                        );
                        None
                    }
                    Err(_) => {
                        let error = "recording lease timed out";
                        observe_recording_error(
                            &session_id,
                            &error,
                            &recording_write_error,
                            &web_tx,
                            &mut recording_loss_observed,
                        );
                        None
                    }
                },
                Err(_) => {
                    let error = "recording lease channel closed";
                    observe_recording_error(
                        &session_id,
                        &error,
                        &recording_write_error,
                        &web_tx,
                        &mut recording_loss_observed,
                    );
                    None
                }
            }
        }
        None => None,
    };

    let mut cast_writer = recording_file.and_then(|(file, relative, meta_path)| {
        match SshCastWriter::start(
            file,
            relative,
            meta_path,
            cols,
            rows,
            ssh_session.asset_name(),
            ssh_session.username(),
        ) {
            Ok(writer) => Some(writer),
            Err(error) => {
                observe_recording_error(
                    &session_id,
                    &error,
                    &recording_write_error,
                    &web_tx,
                    &mut recording_loss_observed,
                );
                None
            }
        }
    });

    if cast_writer.is_some()
        && let Some(ref tx) = audit_tx
    {
        let _ = tx
            .send(Message::SshRecordingStart {
                session_id: session_id.clone(),
                width: cols,
                height: rows,
                asset_name: ssh_session.asset_name().to_string(),
                username: ssh_session.username().to_string(),
            })
            .await;
    }

    let mut redactor = InputRedactor::new();
    let start_time = Instant::now();
    let mut sync_interval = tokio::time::interval(std::time::Duration::from_secs(1));
    sync_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = sync_interval.tick(), if cast_writer.is_some() => {
                let sync_error = cast_writer
                    .as_mut()
                    .and_then(|writer| writer.sync_if_dirty().err());
                if let Some(error) = sync_error {
                    observe_recording_error(
                        &session_id,
                        &error,
                        &recording_write_error,
                        &web_tx,
                        &mut recording_loss_observed,
                    );
                    cast_writer = None;
                }
            }

            // Data from SSH server -> send to web + record output
            data = ssh_session.read() => {
                match data {
                    Some(data) => {
                        redactor.on_server_output(&data);

                        let append_error = cast_writer.as_mut().and_then(|writer| {
                            writer.append(
                                SshRecordingEvent::Output,
                                start_time.elapsed().as_micros() as u64,
                                &data,
                            ).err()
                        });
                        if let Some(error) = append_error {
                            observe_recording_error(
                                &session_id,
                                &error,
                                &recording_write_error,
                                &web_tx,
                                &mut recording_loss_observed,
                            );
                            cast_writer = None;
                        }

                        let msg = Message::SshData {
                            session_id: session_id.clone(),
                            data,
                        };
                        if web_tx.send(msg).await.is_err() {
                            warn!(session_id = %session_id, "Failed to send data to web, closing session");
                            break;
                        }
                    }
                    None => {
                        info!(session_id = %session_id, "SSH channel closed");
                        break;
                    }
                }
            }

            // Commands from web -> send to SSH + record input (redacted)
            cmd = commands.recv() => {
                match cmd {
                    Some(SessionCommand::Data(data)) => {
                        if let Err(e) = ssh_session.write(&data).await {
                            error!(session_id = %session_id, error = %e, "Failed to write to SSH");
                            break;
                        }

                        redactor.on_user_input(&data);
                        if let Some(redacted) = redactor.process_input_for_recording(&data) {
                            let append_error = cast_writer.as_mut().and_then(|writer| {
                                writer.append(
                                SshRecordingEvent::Input,
                                start_time.elapsed().as_micros() as u64,
                                &redacted,
                                ).err()
                            });
                            if let Some(error) = append_error {
                                observe_recording_error(
                                    &session_id,
                                    &error,
                                    &recording_write_error,
                                    &web_tx,
                                    &mut recording_loss_observed,
                                );
                                cast_writer = None;
                            }
                        }
                    }
                    Some(SessionCommand::Resize { cols, rows }) => {
                        if let Err(e) = ssh_session.resize(cols, rows).await {
                            warn!(session_id = %session_id, error = %e, "Failed to resize PTY");
                        }

                        let resize = format!("{cols}x{rows}");
                        let append_error = cast_writer.as_mut().and_then(|writer| {
                            writer.append(
                                SshRecordingEvent::Resize,
                                start_time.elapsed().as_micros() as u64,
                                resize.as_bytes(),
                            ).err()
                        });
                        if let Some(error) = append_error {
                            observe_recording_error(
                                &session_id,
                                &error,
                                &recording_write_error,
                                &web_tx,
                                &mut recording_loss_observed,
                            );
                            cast_writer = None;
                        }
                    }
                    Some(SessionCommand::Close) => {
                        info!(session_id = %session_id, "Close requested");
                        break;
                    }
                    None => {
                        debug!(session_id = %session_id, "Command channel closed");
                        break;
                    }
                }
            }
        }
    }

    if let Some(writer) = cast_writer {
        match writer.finish() {
            Ok(stats) => {
                if let Some(ref tx) = audit_tx {
                    let _ = tx
                        .send(Message::SshRecordingEnd {
                            session_id: session_id.clone(),
                            blake3_hex: stats.blake3_hex,
                            total_bytes: stats.total_bytes,
                            total_events: stats.total_events,
                            duration_secs: stats.duration_secs,
                            width: stats.width,
                            height: stats.height,
                            meta_json_relative_path: stats.meta_json_relative_path,
                        })
                        .await;
                }
            }
            Err(error) => observe_recording_error(
                &session_id,
                &error,
                &recording_write_error,
                &web_tx,
                &mut recording_loss_observed,
            ),
        }
    }

    // Cleanup
    if let Err(e) = ssh_session.close().await {
        warn!(session_id = %session_id, error = %e, "Error closing SSH session");
    }

    info!(session_id = %session_id, "Session task ended");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_manager_new() {
        let manager = SessionManager::new();
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn test_session_command_variants() {
        let _data = SessionCommand::Data(vec![1, 2, 3]);
        let _resize = SessionCommand::Resize { cols: 80, rows: 24 };
        let _close = SessionCommand::Close;
    }

    #[tokio::test]
    async fn test_session_not_found() {
        let manager = SessionManager::new();
        let result = manager.send_data("nonexistent", vec![1, 2, 3]).await;
        assert!(matches!(result, Err(SessionError::SessionNotFound(_))));
    }

    #[tokio::test]
    async fn test_resize_not_found() {
        let manager = SessionManager::new();
        let result = manager.resize("nonexistent", 80, 24).await;
        assert!(matches!(result, Err(SessionError::SessionNotFound(_))));
    }

    #[tokio::test]
    async fn test_close_not_found() {
        let manager = SessionManager::new();
        let result = manager.close_session("nonexistent").await;
        assert!(matches!(result, Err(SessionError::SessionNotFound(_))));
    }

    // ==================== Structural Regression Tests ====================

    /// Helper: Extract production code (before #[cfg(test)]).
    fn prod_source() -> &'static str {
        let full = include_str!("session_manager.rs");
        if let Some(idx) = full.find("#[cfg(test)]") {
            &full[..idx]
        } else {
            full
        }
    }

    #[test]
    fn test_clone_for_cleanup_shares_real_sessions() {
        let source = prod_source();
        let fn_start = source
            .find("fn clone_for_cleanup")
            .expect("clone_for_cleanup must exist");
        let fn_body = &source[fn_start..fn_start + 400];
        // Must use Arc::clone to share the real sessions map
        assert!(
            fn_body.contains("Arc::clone(&self.sessions)"),
            "clone_for_cleanup must share the real sessions map via Arc::clone"
        );
    }

    #[test]
    fn test_clone_for_cleanup_shares_real_active_count() {
        let source = prod_source();
        let fn_start = source
            .find("fn clone_for_cleanup")
            .expect("clone_for_cleanup must exist");
        let fn_body = &source[fn_start..fn_start + 400];
        assert!(
            fn_body.contains("Arc::clone(&self.active_count)"),
            "clone_for_cleanup must share the real active_count via Arc::clone"
        );
    }

    #[test]
    fn test_cleanup_remove_actually_removes() {
        let source = prod_source();
        // Find SessionManagerCleanup::remove_session_internal
        let cleanup_impl = source
            .find("impl SessionManagerCleanup")
            .expect("impl SessionManagerCleanup must exist");
        let cleanup_source = &source[cleanup_impl..];
        assert!(
            cleanup_source.contains("sessions.remove(session_id)"),
            "SessionManagerCleanup::remove_session_internal must actually remove from HashMap"
        );
    }

    #[test]
    fn test_cleanup_decrements_active_count() {
        let source = prod_source();
        let cleanup_impl = source
            .find("impl SessionManagerCleanup")
            .expect("impl SessionManagerCleanup must exist");
        let cleanup_source = &source[cleanup_impl..];
        assert!(
            cleanup_source.contains("fetch_sub(1"),
            "SessionManagerCleanup::remove_session_internal must decrement active_count"
        );
    }

    #[test]
    fn test_no_empty_hashmap_in_clone_for_cleanup() {
        let source = prod_source();
        let fn_start = source
            .find("fn clone_for_cleanup")
            .expect("clone_for_cleanup must exist");
        let fn_body = &source[fn_start..fn_start + 400];
        // Must NOT create a new empty HashMap (the old bug)
        assert!(
            !fn_body.contains("HashMap::new()"),
            "clone_for_cleanup must not create a new empty HashMap"
        );
    }

    #[test]
    fn test_sessions_is_arc_wrapped() {
        let source = prod_source();
        assert!(
            source.contains("sessions: Arc<RwLock<HashMap<String, SessionHandle>>>"),
            "SessionManager.sessions must be Arc-wrapped for sharing with cleanup"
        );
    }

    #[tokio::test]
    async fn test_cleanup_handle_actually_removes_session() {
        // Functional test: verify that SessionManagerCleanup shares the same map
        let manager = SessionManager::new();

        // Manually insert a fake session
        {
            let handle = SessionHandle {
                tx: mpsc::channel(1).0,
            };
            let mut sessions = manager.sessions.write().await;
            sessions.insert("test-session".to_string(), handle);
        }
        manager.active_count.fetch_add(1, Ordering::SeqCst);
        assert_eq!(manager.active_count(), 1);

        // Create cleanup handle and remove the session
        let cleanup = manager.clone_for_cleanup();
        cleanup.remove_session_internal("test-session").await;

        // Verify the session was actually removed from the real map
        assert_eq!(manager.active_count(), 0);
        let sessions = manager.sessions.read().await;
        assert!(
            sessions.is_empty(),
            "Session must be removed from the real HashMap"
        );
    }

    #[tokio::test]
    async fn test_cleanup_handle_nonexistent_session_is_safe() {
        let manager = SessionManager::new();
        let cleanup = manager.clone_for_cleanup();
        // Removing a nonexistent session should be a no-op (no panic)
        cleanup.remove_session_internal("nonexistent").await;
        assert_eq!(manager.active_count(), 0);
    }

    // ==================== SSH Recording Structural Tests ====================

    #[test]
    fn test_session_task_accepts_audit_tx() {
        let source = prod_source();
        let session_task_start = source
            .find("fn session_task")
            .expect("session_task must exist");
        let session_task_source = &source[session_task_start..];
        assert!(
            session_task_source.contains("audit_tx"),
            "session_task must accept audit_tx parameter"
        );
    }

    #[test]
    fn test_session_task_sends_ssh_recording_start() {
        let source = prod_source();
        let session_task_start = source
            .find("fn session_task")
            .expect("session_task must exist");
        let session_task_source = &source[session_task_start..];
        assert!(
            session_task_source.contains("SshRecordingStart"),
            "session_task must send SshRecordingStart"
        );
    }

    #[test]
    fn test_session_task_uses_input_redactor() {
        let source = prod_source();
        let session_task_start = source
            .find("fn session_task")
            .expect("session_task must exist");
        let session_task_source = &source[session_task_start..];
        assert!(
            session_task_source.contains("InputRedactor::new()"),
            "session_task must create InputRedactor"
        );
    }

    #[test]
    fn test_session_task_sends_ssh_recording_end() {
        let source = prod_source();
        let session_task_start = source
            .find("fn session_task")
            .expect("session_task must exist");
        let session_task_source = &source[session_task_start..];
        assert!(
            session_task_source.contains("SshRecordingEnd"),
            "session_task must send SshRecordingEnd at cleanup"
        );
    }

    #[test]
    fn test_session_task_records_output_events() {
        let source = prod_source();
        let session_task_start = source
            .find("fn session_task")
            .expect("session_task must exist");
        let session_task_source = &source[session_task_start..];
        assert!(
            session_task_source.contains("SshRecordingEvent::Output"),
            "session_task must record output events"
        );
    }

    #[test]
    fn test_session_task_records_input_events() {
        let source = prod_source();
        let session_task_start = source
            .find("fn session_task")
            .expect("session_task must exist");
        let session_task_source = &source[session_task_start..];
        assert!(
            session_task_source.contains("SshRecordingEvent::Input"),
            "session_task must record input events"
        );
    }

    #[test]
    fn test_session_task_records_resize_events() {
        let source = prod_source();
        let session_task_start = source
            .find("fn session_task")
            .expect("session_task must exist");
        let session_task_source = &source[session_task_start..];
        assert!(
            session_task_source.contains("SshRecordingEvent::Resize"),
            "session_task must record resize events"
        );
    }

    #[test]
    fn test_create_session_accepts_audit_tx() {
        let source = prod_source();
        let create_session_start = source
            .find("fn create_session")
            .expect("create_session must exist");
        let create_session_source = &source[create_session_start..];
        assert!(
            create_session_source.contains("audit_tx"),
            "create_session must accept audit_tx parameter"
        );
    }
}
