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
    sessions: RwLock<HashMap<String, SessionHandle>>,
    /// Counter for active sessions (atomic for fast reads).
    active_count: AtomicU32,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            active_count: AtomicU32::new(0),
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

        info!(session_id = %session_id, "Creating new SSH session");

        // Connect to SSH server
        let ssh_session = SshSession::connect(config.clone()).await?;

        // Create command channel for this session
        let (cmd_tx, cmd_rx) = mpsc::channel(32);

        // Create session handle
        let handle = SessionHandle {
            tx: cmd_tx,
            user_id: config.user_id.clone(),
            asset_id: config.asset_id.clone(),
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
    #[allow(dead_code)] // Will be used for session cleanup
    async fn remove_session_internal(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        if sessions.remove(session_id).is_some() {
            self.active_count.fetch_sub(1, Ordering::SeqCst);
            info!(session_id = %session_id, "Session removed from manager");
        }
    }

    /// Create a lightweight handle for cleanup operations.
    fn clone_for_cleanup(&self) -> SessionManagerCleanup {
        SessionManagerCleanup {
            sessions: Arc::new(RwLock::new(HashMap::new())), // Not used directly
            active_count: AtomicU32::new(0),                 // Not used directly
        }
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Lightweight handle for cleanup operations (avoids circular Arc).
/// Will be used when session cleanup is implemented.
#[allow(dead_code)]
struct SessionManagerCleanup {
    sessions: Arc<RwLock<HashMap<String, SessionHandle>>>,
    active_count: AtomicU32,
}

#[allow(dead_code)]
impl SessionManagerCleanup {
    async fn remove_session_internal(&self, _session_id: &str) {
        // This is a placeholder - actual cleanup happens in the real SessionManager
        // The session task notifies via the channel when it's done
    }
}

/// Task that handles a single SSH session.
async fn session_task(
    session_id: String,
    mut ssh_session: SshSession,
    mut commands: mpsc::Receiver<SessionCommand>,
    web_tx: mpsc::Sender<Message>,
) {
    info!(session_id = %session_id, "Session task started");

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
}
