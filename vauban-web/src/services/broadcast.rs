/// VAUBAN Web - Broadcast service for WebSocket.
///
/// Manages real-time updates to connected clients via channels.
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, warn};

/// Default channel capacity for broadcast channels.
const DEFAULT_CHANNEL_CAPACITY: usize = 100;

/// Available WebSocket channels.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum WsChannel {
    /// Dashboard statistics updates.
    DashboardStats,
    /// Active sessions list updates.
    ActiveSessions,
    /// Recent activity feed updates.
    RecentActivity,
    /// User notifications.
    Notifications,
    /// Live session updates for a specific session.
    SessionLive(String),
    /// User auth sessions list updates (for /accounts/sessions page).
    UserAuthSessions(String),
    /// User API keys list updates (for /accounts/apikeys page).
    UserApiKeys(String),
}

impl WsChannel {
    /// Returns the channel name as a string.
    pub fn as_str(&self) -> String {
        match self {
            WsChannel::DashboardStats => "dashboard:stats".to_string(),
            WsChannel::ActiveSessions => "dashboard:active-sessions".to_string(),
            WsChannel::RecentActivity => "dashboard:recent-activity".to_string(),
            WsChannel::Notifications => "notifications".to_string(),
            WsChannel::SessionLive(id) => format!("session:{}", id),
            WsChannel::UserAuthSessions(user_id) => format!("user:{}:auth-sessions", user_id),
            WsChannel::UserApiKeys(user_id) => format!("user:{}:api-keys", user_id),
        }
    }

    /// Parse a channel from a string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "dashboard:stats" => Some(WsChannel::DashboardStats),
            "dashboard:active-sessions" => Some(WsChannel::ActiveSessions),
            "dashboard:recent-activity" => Some(WsChannel::RecentActivity),
            "notifications" => Some(WsChannel::Notifications),
            s if s.starts_with("session:") => {
                let id = s.strip_prefix("session:")?.to_string();
                Some(WsChannel::SessionLive(id))
            }
            s if s.starts_with("user:") && s.ends_with(":auth-sessions") => {
                let user_id = s.strip_prefix("user:")?.strip_suffix(":auth-sessions")?.to_string();
                Some(WsChannel::UserAuthSessions(user_id))
            }
            s if s.starts_with("user:") && s.ends_with(":api-keys") => {
                let user_id = s.strip_prefix("user:")?.strip_suffix(":api-keys")?.to_string();
                Some(WsChannel::UserApiKeys(user_id))
            }
            _ => None,
        }
    }
}

/// Message sent through WebSocket channels.
#[derive(Debug, Clone)]
pub struct WsMessage {
    /// Target element ID for HTMX swap.
    pub target_id: String,
    /// HTML content to swap.
    pub html: String,
    /// Swap mode (default: innerHTML).
    pub swap_mode: String,
}

impl WsMessage {
    /// Create a new WebSocket message.
    pub fn new(target_id: &str, html: String) -> Self {
        Self {
            target_id: target_id.to_string(),
            html,
            swap_mode: "innerHTML".to_string(),
        }
    }

    /// Set a custom swap mode.
    pub fn with_swap_mode(mut self, mode: &str) -> Self {
        self.swap_mode = mode.to_string();
        self
    }

    /// Format as HTMX-compatible HTML with hx-swap-oob.
    pub fn to_htmx_html(&self) -> String {
        format!(
            r#"<div id="{}" hx-swap-oob="{}">{}</div>"#,
            self.target_id, self.swap_mode, self.html
        )
    }
}

/// Broadcast service for managing WebSocket channels.
#[derive(Clone)]
pub struct BroadcastService {
    channels: Arc<RwLock<HashMap<String, broadcast::Sender<String>>>>,
    capacity: usize,
}

impl BroadcastService {
    /// Create a new broadcast service.
    pub fn new() -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
            capacity: DEFAULT_CHANNEL_CAPACITY,
        }
    }

    /// Create a new broadcast service with custom capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
            capacity,
        }
    }

    /// Get or create a channel sender.
    async fn get_or_create_sender(&self, channel: &str) -> broadcast::Sender<String> {
        // Try read lock first
        {
            let channels = self.channels.read().await;
            if let Some(sender) = channels.get(channel) {
                return sender.clone();
            }
        }

        // Need to create - acquire write lock
        let mut channels = self.channels.write().await;

        // Double-check after acquiring write lock
        if let Some(sender) = channels.get(channel) {
            return sender.clone();
        }

        // Create new channel
        let (sender, _) = broadcast::channel(self.capacity);
        channels.insert(channel.to_string(), sender.clone());
        debug!(channel = %channel, "Created new broadcast channel");
        sender
    }

    /// Subscribe to a channel.
    pub async fn subscribe(&self, channel: &WsChannel) -> broadcast::Receiver<String> {
        let channel_name = channel.as_str();
        let sender = self.get_or_create_sender(&channel_name).await;
        sender.subscribe()
    }

    /// Subscribe to a channel by name.
    pub async fn subscribe_by_name(&self, channel_name: &str) -> broadcast::Receiver<String> {
        let sender = self.get_or_create_sender(channel_name).await;
        sender.subscribe()
    }

    /// Send a message to a channel.
    pub async fn send(&self, channel: &WsChannel, message: WsMessage) -> Result<usize, ()> {
        let channel_name = channel.as_str();
        let html = message.to_htmx_html();
        self.send_raw(&channel_name, html).await
    }

    /// Send raw HTML to a channel.
    pub async fn send_raw(&self, channel_name: &str, html: String) -> Result<usize, ()> {
        let channels = self.channels.read().await;

        if let Some(sender) = channels.get(channel_name) {
            match sender.send(html) {
                Ok(count) => {
                    debug!(channel = %channel_name, receivers = count, "Broadcast message sent");
                    Ok(count)
                }
                Err(_) => {
                    // No receivers - this is not an error, just no one listening
                    debug!(channel = %channel_name, "No receivers for broadcast");
                    Ok(0)
                }
            }
        } else {
            warn!(channel = %channel_name, "Channel does not exist");
            Err(())
        }
    }

    /// Get the number of active subscribers for a channel.
    pub async fn subscriber_count(&self, channel: &WsChannel) -> usize {
        let channel_name = channel.as_str();
        let channels = self.channels.read().await;

        if let Some(sender) = channels.get(&channel_name) {
            sender.receiver_count()
        } else {
            0
        }
    }

    /// Remove a channel (useful for cleanup).
    pub async fn remove_channel(&self, channel: &WsChannel) {
        let channel_name = channel.as_str();
        let mut channels = self.channels.write().await;
        channels.remove(&channel_name);
        debug!(channel = %channel_name, "Removed broadcast channel");
    }
}

impl Default for BroadcastService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== WsChannel Tests ====================

    #[test]
    fn test_ws_channel_as_str() {
        assert_eq!(WsChannel::DashboardStats.as_str(), "dashboard:stats");
        assert_eq!(
            WsChannel::ActiveSessions.as_str(),
            "dashboard:active-sessions"
        );
        assert_eq!(
            WsChannel::RecentActivity.as_str(),
            "dashboard:recent-activity"
        );
        assert_eq!(WsChannel::Notifications.as_str(), "notifications");
        assert_eq!(
            WsChannel::SessionLive("abc123".to_string()).as_str(),
            "session:abc123"
        );
    }

    #[test]
    fn test_ws_channel_from_str() {
        assert_eq!(
            WsChannel::from_str("dashboard:stats"),
            Some(WsChannel::DashboardStats)
        );
        assert_eq!(
            WsChannel::from_str("dashboard:active-sessions"),
            Some(WsChannel::ActiveSessions)
        );
        assert_eq!(
            WsChannel::from_str("notifications"),
            Some(WsChannel::Notifications)
        );
        assert_eq!(
            WsChannel::from_str("session:xyz"),
            Some(WsChannel::SessionLive("xyz".to_string()))
        );
        assert_eq!(WsChannel::from_str("invalid"), None);
    }

    #[test]
    fn test_ws_channel_roundtrip() {
        let channels = vec![
            WsChannel::DashboardStats,
            WsChannel::ActiveSessions,
            WsChannel::RecentActivity,
            WsChannel::Notifications,
            WsChannel::SessionLive("test-id".to_string()),
        ];

        for channel in channels {
            let str_val = channel.as_str();
            let parsed = WsChannel::from_str(&str_val);
            assert_eq!(parsed, Some(channel));
        }
    }

    // ==================== WsMessage Tests ====================

    #[test]
    fn test_ws_message_new() {
        let msg = WsMessage::new("my-target", "<p>Hello</p>".to_string());
        assert_eq!(msg.target_id, "my-target");
        assert_eq!(msg.html, "<p>Hello</p>");
        assert_eq!(msg.swap_mode, "innerHTML");
    }

    #[test]
    fn test_ws_message_with_swap_mode() {
        let msg = WsMessage::new("target", "<p>Test</p>".to_string()).with_swap_mode("outerHTML");
        assert_eq!(msg.swap_mode, "outerHTML");
    }

    #[test]
    fn test_ws_message_to_htmx_html() {
        let msg = WsMessage::new("ws-stats", "<span>Active: 5</span>".to_string());
        let html = msg.to_htmx_html();

        assert!(html.contains(r#"id="ws-stats""#));
        assert!(html.contains(r#"hx-swap-oob="innerHTML""#));
        assert!(html.contains("<span>Active: 5</span>"));
    }

    // ==================== BroadcastService Tests ====================

    #[tokio::test]
    async fn test_broadcast_service_new() {
        let service = BroadcastService::new();
        assert_eq!(service.capacity, DEFAULT_CHANNEL_CAPACITY);
    }

    #[tokio::test]
    async fn test_broadcast_service_with_capacity() {
        let service = BroadcastService::with_capacity(50);
        assert_eq!(service.capacity, 50);
    }

    #[tokio::test]
    async fn test_broadcast_subscribe_creates_channel() {
        let service = BroadcastService::new();
        let _receiver = service.subscribe(&WsChannel::DashboardStats).await;

        // Channel should exist now
        let channels = service.channels.read().await;
        assert!(channels.contains_key("dashboard:stats"));
    }

    #[tokio::test]
    async fn test_broadcast_send_and_receive() {
        let service = BroadcastService::new();

        // Subscribe first
        let mut receiver = service.subscribe(&WsChannel::DashboardStats).await;

        // Send a message
        let msg = WsMessage::new("ws-stats", "<p>Test</p>".to_string());
        let result = service.send(&WsChannel::DashboardStats, msg).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1); // 1 receiver

        // Receive the message
        let received = receiver.recv().await.unwrap();
        assert!(received.contains("ws-stats"));
        assert!(received.contains("<p>Test</p>"));
    }

    #[tokio::test]
    async fn test_broadcast_subscriber_count() {
        let service = BroadcastService::new();

        assert_eq!(
            service.subscriber_count(&WsChannel::DashboardStats).await,
            0
        );

        let _r1 = service.subscribe(&WsChannel::DashboardStats).await;
        assert_eq!(
            service.subscriber_count(&WsChannel::DashboardStats).await,
            1
        );

        let _r2 = service.subscribe(&WsChannel::DashboardStats).await;
        assert_eq!(
            service.subscriber_count(&WsChannel::DashboardStats).await,
            2
        );
    }

    #[tokio::test]
    async fn test_broadcast_remove_channel() {
        let service = BroadcastService::new();

        let _receiver = service.subscribe(&WsChannel::Notifications).await;

        {
            let channels = service.channels.read().await;
            assert!(channels.contains_key("notifications"));
        }

        service.remove_channel(&WsChannel::Notifications).await;

        {
            let channels = service.channels.read().await;
            assert!(!channels.contains_key("notifications"));
        }
    }

    #[tokio::test]
    async fn test_broadcast_default() {
        let service = BroadcastService::default();
        assert_eq!(service.capacity, DEFAULT_CHANNEL_CAPACITY);
    }
}
