//! Session manager for handling multiple concurrent RDP sessions.

use crate::error::{SessionError, SessionResult};
use crate::session::{RdpSession, SessionCommand, SessionConfig};
use shared::messages::{Message, RdpInputEvent};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info};

/// Handle for communicating with a session task.
pub struct SessionHandle {
    tx: mpsc::Sender<SessionCommand>,
    #[allow(dead_code)]
    pub user_id: String,
    #[allow(dead_code)]
    pub asset_id: String,
    #[allow(dead_code)]
    pub desktop_width: u16,
    #[allow(dead_code)]
    pub desktop_height: u16,
    #[allow(dead_code)]
    pub created_at: Instant,
}

/// Thread-safe manager for multiple RDP sessions.
pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, SessionHandle>>>,
    active_count: Arc<AtomicU32>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            active_count: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Create a new RDP session and spawn a task to manage it.
    pub async fn create_session(
        &self,
        config: SessionConfig,
        web_tx: mpsc::Sender<Message>,
    ) -> SessionResult<(String, u16, u16)> {
        let session_id = config.session_id.clone();

        {
            let sessions = self.sessions.read().await;
            if sessions.contains_key(&session_id) {
                return Err(SessionError::SessionAlreadyExists(session_id));
            }
        }

        debug!(session_id = %session_id, "Creating new RDP session");

        let user_id = config.user_id.clone();
        let asset_id = config.asset_id.clone();

        let (cmd_tx, cmd_rx) = mpsc::channel(64);

        let rdp_session = RdpSession::connect(config, web_tx, cmd_rx).await?;

        let desktop_width = rdp_session.desktop_width;
        let desktop_height = rdp_session.desktop_height;

        let handle = SessionHandle {
            tx: cmd_tx,
            user_id,
            asset_id,
            desktop_width,
            desktop_height,
            created_at: Instant::now(),
        };

        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), handle);
        }
        self.active_count.fetch_add(1, Ordering::SeqCst);

        // Spawn cleanup task: the session loop was already spawned inside RdpSession::connect.
        // When the session's cmd_tx is dropped (session ends), the cmd_rx in the loop will close.
        // We need a separate cleanup mechanism since we don't own the session loop task here.
        let cleanup = self.clone_for_cleanup();
        let sid = session_id.clone();
        tokio::spawn(async move {
            // The session handle's tx will keep the session alive.
            // When all senders are dropped, the session loop exits.
            // We rely on the session being removed via close_session or explicit cleanup.
            // For now, we don't have automatic cleanup on session end.
            // This will be improved when we add session health monitoring.
            let _ = cleanup;
            let _ = sid;
        });

        Ok((session_id, desktop_width, desktop_height))
    }

    /// Send an input event to a session.
    pub async fn send_input(
        &self,
        session_id: &str,
        input: RdpInputEvent,
    ) -> SessionResult<()> {
        let sessions = self.sessions.read().await;
        if let Some(handle) = sessions.get(session_id) {
            handle
                .tx
                .send(SessionCommand::Input(input))
                .await
                .map_err(|_| SessionError::SessionClosed)?;
            Ok(())
        } else {
            Err(SessionError::SessionNotFound(session_id.to_string()))
        }
    }

    /// Resize a session's desktop.
    pub async fn resize(
        &self,
        session_id: &str,
        width: u16,
        height: u16,
    ) -> SessionResult<()> {
        let sessions = self.sessions.read().await;
        if let Some(handle) = sessions.get(session_id) {
            handle
                .tx
                .send(SessionCommand::Resize { width, height })
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
            let _ = handle.tx.send(SessionCommand::Close).await;
            Ok(())
        } else {
            Err(SessionError::SessionNotFound(session_id.to_string()))
        }
    }

    /// Remove a closed session from the map.
    pub async fn remove_session(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        if sessions.remove(session_id).is_some() {
            self.active_count.fetch_sub(1, Ordering::SeqCst);
            info!(session_id = %session_id, "Session removed from manager");
        }
    }

    pub fn active_count(&self) -> u32 {
        self.active_count.load(Ordering::SeqCst)
    }

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

struct SessionManagerCleanup {
    sessions: Arc<RwLock<HashMap<String, SessionHandle>>>,
    active_count: Arc<AtomicU32>,
}

#[allow(dead_code)]
impl SessionManagerCleanup {
    async fn remove_session_internal(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        if sessions.remove(session_id).is_some() {
            self.active_count.fetch_sub(1, Ordering::SeqCst);
            info!(session_id = %session_id, "Session removed from manager (cleanup)");
        }
    }
}
