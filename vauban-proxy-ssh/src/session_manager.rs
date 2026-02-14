//! Session manager for handling multiple concurrent SSH sessions.

use crate::error::{SessionError, SessionResult};
use crate::session::{SessionConfig, SshSession};
use shared::messages::Message;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

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
    /// Vauban user ID who owns this session (for access control).
    #[allow(dead_code)]
    pub user_id: String,
    /// Asset ID being accessed (for session info and audit).
    #[allow(dead_code)]
    pub asset_id: String,
    /// When the session was created (for session info and metrics).
    #[allow(dead_code)]
    pub created_at: Instant,
}

/// Thread-safe manager for multiple SSH sessions.
pub struct SessionManager {
    /// Map of session_id -> SessionHandle.
    /// Wrapped in Arc so it can be shared with cleanup handles (M-11).
    sessions: Arc<RwLock<HashMap<String, SessionHandle>>>,
    /// Counter for active sessions (atomic for fast reads).
    /// Wrapped in Arc so it can be shared with cleanup handles (M-11).
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

        // Extract user_id and asset_id before moving config to SshSession::connect
        let user_id = config.user_id.clone();
        let asset_id = config.asset_id.clone();

        // Connect to SSH server (consumes config because of OwnedFd)
        let ssh_session = SshSession::connect(config).await?;

        // Create command channel for this session
        let (cmd_tx, cmd_rx) = mpsc::channel(32);

        // Create session handle
        let handle = SessionHandle {
            tx: cmd_tx,
            user_id,
            asset_id,
            created_at: Instant::now(),
        };

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
            session_task(session_id_clone.clone(), ssh_session, cmd_rx, web_tx).await;
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

    /// Check if a session exists and belongs to a user.
    #[allow(dead_code)] // Will be used for session access control
    pub async fn session_belongs_to_user(&self, session_id: &str, user_id: &str) -> bool {
        let sessions = self.sessions.read().await;
        sessions
            .get(session_id)
            .is_some_and(|h| h.user_id == user_id)
    }

    /// Get session info (user_id, asset_id) if it exists.
    #[allow(dead_code)] // Will be used for session tracking
    pub async fn get_session_info(&self, session_id: &str) -> Option<(String, String)> {
        let sessions = self.sessions.read().await;
        sessions
            .get(session_id)
            .map(|h| (h.user_id.clone(), h.asset_id.clone()))
    }

    /// Remove a session from the map (internal use).
    /// Note: Cleanup from session tasks uses SessionManagerCleanup (M-11).
    #[allow(dead_code)]
    async fn remove_session_internal(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        if sessions.remove(session_id).is_some() {
            self.active_count.fetch_sub(1, Ordering::SeqCst);
            info!(session_id = %session_id, "Session removed from manager");
        }
    }

    /// Create a lightweight handle for cleanup operations.
    /// M-11: Shares the real sessions map and active_count so that
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
/// M-11: Shares the real sessions map and active_count via Arc,
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

/// Task that handles a single SSH session.
async fn session_task(
    session_id: String,
    mut ssh_session: SshSession,
    mut commands: mpsc::Receiver<SessionCommand>,
    web_tx: mpsc::Sender<Message>,
) {
    debug!(session_id = %session_id, "Session task started");

    loop {
        tokio::select! {
            // Data from SSH server -> send to web
            data = ssh_session.read() => {
                match data {
                    Some(data) => {
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

            // Commands from web -> send to SSH
            cmd = commands.recv() => {
                match cmd {
                    Some(SessionCommand::Data(data)) => {
                        if let Err(e) = ssh_session.write(&data).await {
                            error!(session_id = %session_id, error = %e, "Failed to write to SSH");
                            break;
                        }
                    }
                    Some(SessionCommand::Resize { cols, rows }) => {
                        if let Err(e) = ssh_session.resize(cols, rows).await {
                            warn!(session_id = %session_id, error = %e, "Failed to resize PTY");
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

    #[tokio::test]
    async fn test_session_belongs_to_user_not_found() {
        let manager = SessionManager::new();
        let result = manager
            .session_belongs_to_user("nonexistent", "user1")
            .await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_get_session_info_not_found() {
        let manager = SessionManager::new();
        let result = manager.get_session_info("nonexistent").await;
        assert!(result.is_none());
    }

    // ==================== M-11 Structural Regression Tests ====================

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
    fn test_m11_clone_for_cleanup_shares_real_sessions() {
        let source = prod_source();
        let fn_start = source.find("fn clone_for_cleanup")
            .expect("clone_for_cleanup must exist");
        let fn_body = &source[fn_start..fn_start + 400];
        // Must use Arc::clone to share the real sessions map
        assert!(
            fn_body.contains("Arc::clone(&self.sessions)"),
            "M-11: clone_for_cleanup must share the real sessions map via Arc::clone"
        );
    }

    #[test]
    fn test_m11_clone_for_cleanup_shares_real_active_count() {
        let source = prod_source();
        let fn_start = source.find("fn clone_for_cleanup")
            .expect("clone_for_cleanup must exist");
        let fn_body = &source[fn_start..fn_start + 400];
        assert!(
            fn_body.contains("Arc::clone(&self.active_count)"),
            "M-11: clone_for_cleanup must share the real active_count via Arc::clone"
        );
    }

    #[test]
    fn test_m11_cleanup_remove_actually_removes() {
        let source = prod_source();
        // Find SessionManagerCleanup::remove_session_internal
        let cleanup_impl = source.find("impl SessionManagerCleanup")
            .expect("impl SessionManagerCleanup must exist");
        let cleanup_source = &source[cleanup_impl..];
        assert!(
            cleanup_source.contains("sessions.remove(session_id)"),
            "M-11: SessionManagerCleanup::remove_session_internal must actually remove from HashMap"
        );
    }

    #[test]
    fn test_m11_cleanup_decrements_active_count() {
        let source = prod_source();
        let cleanup_impl = source.find("impl SessionManagerCleanup")
            .expect("impl SessionManagerCleanup must exist");
        let cleanup_source = &source[cleanup_impl..];
        assert!(
            cleanup_source.contains("fetch_sub(1"),
            "M-11: SessionManagerCleanup::remove_session_internal must decrement active_count"
        );
    }

    #[test]
    fn test_m11_no_empty_hashmap_in_clone_for_cleanup() {
        let source = prod_source();
        let fn_start = source.find("fn clone_for_cleanup")
            .expect("clone_for_cleanup must exist");
        let fn_body = &source[fn_start..fn_start + 400];
        // Must NOT create a new empty HashMap (the old bug)
        assert!(
            !fn_body.contains("HashMap::new()"),
            "M-11: clone_for_cleanup must not create a new empty HashMap"
        );
    }

    #[test]
    fn test_m11_sessions_is_arc_wrapped() {
        let source = prod_source();
        assert!(
            source.contains("sessions: Arc<RwLock<HashMap<String, SessionHandle>>>"),
            "M-11: SessionManager.sessions must be Arc-wrapped for sharing with cleanup"
        );
    }

    #[tokio::test]
    async fn test_m11_cleanup_handle_actually_removes_session() {
        // Functional test: verify that SessionManagerCleanup shares the same map
        let manager = SessionManager::new();

        // Manually insert a fake session
        {
            let handle = SessionHandle {
                tx: mpsc::channel(1).0,
                user_id: "user1".to_string(),
                asset_id: "asset1".to_string(),
                created_at: Instant::now(),
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
        assert!(sessions.is_empty(), "Session must be removed from the real HashMap");
    }

    #[tokio::test]
    async fn test_m11_cleanup_handle_nonexistent_session_is_safe() {
        let manager = SessionManager::new();
        let cleanup = manager.clone_for_cleanup();
        // Removing a nonexistent session should be a no-op (no panic)
        cleanup.remove_session_internal("nonexistent").await;
        assert_eq!(manager.active_count(), 0);
    }
}
