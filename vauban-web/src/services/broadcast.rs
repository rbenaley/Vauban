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
    /// Active sessions list updates (dashboard widget).
    ActiveSessions,
    /// Active sessions full list updates (dedicated page).
    ActiveSessionsList,
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
            WsChannel::ActiveSessionsList => "sessions:active-list".to_string(),
            WsChannel::RecentActivity => "dashboard:recent-activity".to_string(),
            WsChannel::Notifications => "notifications".to_string(),
            WsChannel::SessionLive(id) => format!("session:{}", id),
            WsChannel::UserAuthSessions(user_id) => format!("user:{}:auth-sessions", user_id),
            WsChannel::UserApiKeys(user_id) => format!("user:{}:api-keys", user_id),
        }
    }

    /// Parse a channel from a string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "dashboard:stats" => Some(WsChannel::DashboardStats),
            "dashboard:active-sessions" => Some(WsChannel::ActiveSessions),
            "sessions:active-list" => Some(WsChannel::ActiveSessionsList),
            "dashboard:recent-activity" => Some(WsChannel::RecentActivity),
            "notifications" => Some(WsChannel::Notifications),
            s if s.starts_with("session:") => {
                let id = s.strip_prefix("session:")?.to_string();
                Some(WsChannel::SessionLive(id))
            }
            s if s.starts_with("user:") && s.ends_with(":auth-sessions") => {
                let user_id = s
                    .strip_prefix("user:")?
                    .strip_suffix(":auth-sessions")?
                    .to_string();
                Some(WsChannel::UserAuthSessions(user_id))
            }
            s if s.starts_with("user:") && s.ends_with(":api-keys") => {
                let user_id = s
                    .strip_prefix("user:")?
                    .strip_suffix(":api-keys")?
                    .to_string();
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
    use crate::unwrap_ok;

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
    fn test_ws_channel_user_auth_sessions_as_str() {
        let channel = WsChannel::UserAuthSessions("user-uuid-123".to_string());
        assert_eq!(channel.as_str(), "user:user-uuid-123:auth-sessions");
    }

    #[test]
    fn test_ws_channel_user_api_keys_as_str() {
        let channel = WsChannel::UserApiKeys("user-uuid-456".to_string());
        assert_eq!(channel.as_str(), "user:user-uuid-456:api-keys");
    }

    #[test]
    fn test_ws_channel_from_str() {
        assert_eq!(
            WsChannel::parse("dashboard:stats"),
            Some(WsChannel::DashboardStats)
        );
        assert_eq!(
            WsChannel::parse("dashboard:active-sessions"),
            Some(WsChannel::ActiveSessions)
        );
        assert_eq!(
            WsChannel::parse("notifications"),
            Some(WsChannel::Notifications)
        );
        assert_eq!(
            WsChannel::parse("session:xyz"),
            Some(WsChannel::SessionLive("xyz".to_string()))
        );
        assert_eq!(WsChannel::parse("invalid"), None);
    }

    #[test]
    fn test_ws_channel_from_str_user_auth_sessions() {
        assert_eq!(
            WsChannel::parse("user:abc123:auth-sessions"),
            Some(WsChannel::UserAuthSessions("abc123".to_string()))
        );
    }

    #[test]
    fn test_ws_channel_from_str_user_api_keys() {
        assert_eq!(
            WsChannel::parse("user:xyz789:api-keys"),
            Some(WsChannel::UserApiKeys("xyz789".to_string()))
        );
    }

    #[test]
    fn test_ws_channel_from_str_invalid_user_channel() {
        assert_eq!(WsChannel::parse("user:abc:unknown"), None);
        assert_eq!(
            WsChannel::parse("user::auth-sessions"),
            Some(WsChannel::UserAuthSessions("".to_string()))
        );
    }

    #[test]
    fn test_ws_channel_roundtrip() {
        let channels = vec![
            WsChannel::DashboardStats,
            WsChannel::ActiveSessions,
            WsChannel::ActiveSessionsList,
            WsChannel::RecentActivity,
            WsChannel::Notifications,
            WsChannel::SessionLive("test-id".to_string()),
        ];

        for channel in channels {
            let str_val = channel.as_str();
            let parsed = WsChannel::parse(&str_val);
            assert_eq!(parsed, Some(channel));
        }
    }

    #[test]
    fn test_ws_channel_active_sessions_list() {
        let channel = WsChannel::ActiveSessionsList;
        assert_eq!(channel.as_str(), "sessions:active-list");
    }

    #[test]
    fn test_ws_channel_parse_active_sessions_list() {
        assert_eq!(
            WsChannel::parse("sessions:active-list"),
            Some(WsChannel::ActiveSessionsList)
        );
    }

    #[test]
    fn test_ws_channel_roundtrip_user_channels() {
        let channels = vec![
            WsChannel::UserAuthSessions("user-1".to_string()),
            WsChannel::UserApiKeys("user-2".to_string()),
        ];

        for channel in channels {
            let str_val = channel.as_str();
            let parsed = WsChannel::parse(&str_val);
            assert_eq!(parsed, Some(channel));
        }
    }

    #[test]
    fn test_ws_channel_clone() {
        let channel = WsChannel::SessionLive("session-id".to_string());
        let cloned = channel.clone();
        assert_eq!(channel, cloned);
    }

    #[test]
    fn test_ws_channel_debug() {
        let channel = WsChannel::DashboardStats;
        let debug_str = format!("{:?}", channel);
        assert!(debug_str.contains("DashboardStats"));
    }

    #[test]
    fn test_ws_channel_hash_eq() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(WsChannel::DashboardStats);
        set.insert(WsChannel::ActiveSessions);
        set.insert(WsChannel::DashboardStats); // duplicate

        assert_eq!(set.len(), 2);
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
        assert_eq!(unwrap_ok!(result), 1); // 1 receiver

        // Receive the message
        let received = unwrap_ok!(receiver.recv().await);
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

    // ==================== Additional BroadcastService Tests ====================

    #[tokio::test]
    async fn test_broadcast_send_raw() {
        let service = BroadcastService::new();
        let mut receiver = service.subscribe_by_name("custom-channel").await;

        let result = service
            .send_raw("custom-channel", "<div>Raw HTML</div>".to_string())
            .await;
        assert!(result.is_ok());

        let received = unwrap_ok!(receiver.recv().await);
        assert_eq!(received, "<div>Raw HTML</div>");
    }

    #[tokio::test]
    async fn test_broadcast_send_raw_no_channel() {
        let service = BroadcastService::new();

        // Try to send to non-existent channel
        let result = service.send_raw("nonexistent", "test".to_string()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_broadcast_subscribe_by_name() {
        let service = BroadcastService::new();
        let _receiver = service.subscribe_by_name("my-custom-channel").await;

        let channels = service.channels.read().await;
        assert!(channels.contains_key("my-custom-channel"));
    }

    #[tokio::test]
    async fn test_broadcast_multiple_channels() {
        let service = BroadcastService::new();

        let _r1 = service.subscribe(&WsChannel::DashboardStats).await;
        let _r2 = service.subscribe(&WsChannel::ActiveSessions).await;
        let _r3 = service.subscribe(&WsChannel::Notifications).await;

        let channels = service.channels.read().await;
        assert_eq!(channels.len(), 3);
    }

    #[tokio::test]
    async fn test_broadcast_send_no_receivers() {
        let service = BroadcastService::new();

        // Create channel but drop receiver
        {
            let _receiver = service.subscribe(&WsChannel::DashboardStats).await;
        }
        // Receiver dropped, but channel still exists

        let msg = WsMessage::new("test", "content".to_string());
        let result = service.send(&WsChannel::DashboardStats, msg).await;

        // Should succeed with 0 receivers
        assert!(result.is_ok());
        assert_eq!(unwrap_ok!(result), 0);
    }

    #[tokio::test]
    async fn test_broadcast_clone_shares_state() {
        let service = BroadcastService::new();
        let cloned = service.clone();

        let _receiver = service.subscribe(&WsChannel::DashboardStats).await;

        // Cloned service should see the same channels
        assert_eq!(cloned.subscriber_count(&WsChannel::DashboardStats).await, 1);
    }

    #[tokio::test]
    async fn test_broadcast_session_live_channel() {
        let service = BroadcastService::new();
        let session_id = "session-abc-123";
        let channel = WsChannel::SessionLive(session_id.to_string());

        let mut receiver = service.subscribe(&channel).await;

        let msg = WsMessage::new("session-view", "<p>Session data</p>".to_string());
        let _ = service.send(&channel, msg).await;

        let received = unwrap_ok!(receiver.recv().await);
        assert!(received.contains("session-view"));
    }

    #[tokio::test]
    async fn test_broadcast_user_channels() {
        let service = BroadcastService::new();
        let user_id = "user-uuid-123";

        let _r1 = service
            .subscribe(&WsChannel::UserAuthSessions(user_id.to_string()))
            .await;
        let _r2 = service
            .subscribe(&WsChannel::UserApiKeys(user_id.to_string()))
            .await;

        let channels = service.channels.read().await;
        assert!(channels.contains_key(&format!("user:{}:auth-sessions", user_id)));
        assert!(channels.contains_key(&format!("user:{}:api-keys", user_id)));
    }

    // ==================== WsMessage Additional Tests ====================

    #[test]
    fn test_ws_message_clone() {
        let msg = WsMessage::new("target", "content".to_string());
        let cloned = msg.clone();

        assert_eq!(msg.target_id, cloned.target_id);
        assert_eq!(msg.html, cloned.html);
        assert_eq!(msg.swap_mode, cloned.swap_mode);
    }

    #[test]
    fn test_ws_message_debug() {
        let msg = WsMessage::new("my-target", "<p>Test</p>".to_string());
        let debug_str = format!("{:?}", msg);

        assert!(debug_str.contains("WsMessage"));
        assert!(debug_str.contains("my-target"));
    }

    #[test]
    fn test_ws_message_empty_html() {
        let msg = WsMessage::new("target", "".to_string());
        let html = msg.to_htmx_html();

        assert!(html.contains(r#"id="target""#));
        assert!(html.ends_with("></div>") || html.contains("></div>"));
    }

    #[test]
    fn test_ws_message_special_characters() {
        let msg = WsMessage::new("target", "<script>alert('xss')</script>".to_string());
        let html = msg.to_htmx_html();

        // Should preserve the content as-is (escaping is caller's responsibility)
        assert!(html.contains("<script>"));
    }

    #[test]
    fn test_ws_message_swap_modes() {
        let modes = [
            "innerHTML",
            "outerHTML",
            "beforebegin",
            "afterend",
            "delete",
        ];

        for mode in modes {
            let msg = WsMessage::new("target", "content".to_string()).with_swap_mode(mode);
            assert_eq!(msg.swap_mode, mode);
            assert!(
                msg.to_htmx_html()
                    .contains(&format!(r#"hx-swap-oob="{}""#, mode))
            );
        }
    }

    // ==================== Constants Tests ====================

    #[test]
    fn test_default_channel_capacity() {
        assert_eq!(DEFAULT_CHANNEL_CAPACITY, 100);
    }

    #[test]
    fn test_default_channel_capacity_is_reasonable() {
        assert!(DEFAULT_CHANNEL_CAPACITY >= 10);
        assert!(DEFAULT_CHANNEL_CAPACITY <= 10000);
    }

    // ==================== Complete WsChannel from_str Coverage ====================

    #[test]
    fn test_ws_channel_from_str_recent_activity() {
        assert_eq!(
            WsChannel::parse("dashboard:recent-activity"),
            Some(WsChannel::RecentActivity)
        );
    }

    #[test]
    fn test_ws_channel_from_str_empty_session_id() {
        // "session:" with empty ID should still parse
        assert_eq!(
            WsChannel::parse("session:"),
            Some(WsChannel::SessionLive("".to_string()))
        );
    }

    #[test]
    fn test_ws_channel_from_str_session_with_special_chars() {
        let result = WsChannel::parse("session:abc-123_xyz");
        assert_eq!(
            result,
            Some(WsChannel::SessionLive("abc-123_xyz".to_string()))
        );
    }

    #[test]
    fn test_ws_channel_from_str_user_with_colons() {
        // Edge case: user UUID contains colons
        let result = WsChannel::parse("user:a:b:c:auth-sessions");
        assert_eq!(
            result,
            Some(WsChannel::UserAuthSessions("a:b:c".to_string()))
        );
    }

    #[test]
    fn test_ws_channel_from_str_partial_match() {
        // Should not match partial prefixes
        assert_eq!(WsChannel::parse("dashboard:stat"), None);
        assert_eq!(WsChannel::parse("dashboard:"), None);
        assert_eq!(WsChannel::parse("notification"), None);
    }

    #[test]
    fn test_ws_channel_from_str_case_sensitive() {
        assert_eq!(WsChannel::parse("Dashboard:stats"), None);
        assert_eq!(WsChannel::parse("NOTIFICATIONS"), None);
    }

    // ==================== WsChannel Equality Tests ====================

    #[test]
    fn test_ws_channel_eq_same_variant() {
        assert_eq!(WsChannel::DashboardStats, WsChannel::DashboardStats);
        assert_eq!(WsChannel::ActiveSessions, WsChannel::ActiveSessions);
    }

    #[test]
    fn test_ws_channel_eq_different_variant() {
        assert_ne!(WsChannel::DashboardStats, WsChannel::ActiveSessions);
        assert_ne!(WsChannel::Notifications, WsChannel::RecentActivity);
    }

    #[test]
    fn test_ws_channel_eq_session_live_same_id() {
        let a = WsChannel::SessionLive("abc".to_string());
        let b = WsChannel::SessionLive("abc".to_string());
        assert_eq!(a, b);
    }

    #[test]
    fn test_ws_channel_eq_session_live_different_id() {
        let a = WsChannel::SessionLive("abc".to_string());
        let b = WsChannel::SessionLive("xyz".to_string());
        assert_ne!(a, b);
    }

    #[test]
    fn test_ws_channel_eq_user_channels() {
        let a = WsChannel::UserAuthSessions("user-1".to_string());
        let b = WsChannel::UserAuthSessions("user-1".to_string());
        let c = WsChannel::UserAuthSessions("user-2".to_string());

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ==================== WsMessage Edge Cases ====================

    #[test]
    fn test_ws_message_unicode_content() {
        let msg = WsMessage::new("target", "Bonjour le monde! 你好世界 🌍".to_string());
        let html = msg.to_htmx_html();

        assert!(html.contains("Bonjour le monde!"));
        assert!(html.contains("你好世界"));
        assert!(html.contains("🌍"));
    }

    #[test]
    fn test_ws_message_multiline_content() {
        let content = "Line 1\nLine 2\nLine 3";
        let msg = WsMessage::new("target", content.to_string());
        let html = msg.to_htmx_html();

        assert!(html.contains("Line 1\nLine 2\nLine 3"));
    }

    #[test]
    fn test_ws_message_html_entities() {
        let msg = WsMessage::new("target", "&lt;escaped&gt;".to_string());
        let html = msg.to_htmx_html();

        assert!(html.contains("&lt;escaped&gt;"));
    }

    #[test]
    fn test_ws_message_quotes_in_content() {
        let msg = WsMessage::new("target", r#"He said "Hello""#.to_string());
        let html = msg.to_htmx_html();

        assert!(html.contains(r#"He said "Hello""#));
    }

    // ==================== BroadcastService Double-Check Pattern ====================

    #[tokio::test]
    async fn test_broadcast_concurrent_subscribe_same_channel() {
        let service = BroadcastService::new();
        let service_clone = service.clone();

        let handle1 = tokio::spawn(async move {
            for _ in 0..10 {
                let _rx = service_clone.subscribe(&WsChannel::DashboardStats).await;
            }
        });

        let service_clone2 = service.clone();
        let handle2 = tokio::spawn(async move {
            for _ in 0..10 {
                let _rx = service_clone2.subscribe(&WsChannel::DashboardStats).await;
            }
        });

        unwrap_ok!(handle1.await);
        unwrap_ok!(handle2.await);

        // Channel should exist and have been created only once
        let channels = service.channels.read().await;
        assert!(channels.contains_key("dashboard:stats"));
    }

    #[tokio::test]
    async fn test_broadcast_subscribe_reuses_existing_channel() {
        let service = BroadcastService::new();

        // First subscription creates channel
        let _rx1 = service.subscribe(&WsChannel::DashboardStats).await;

        // Get channel count before second subscription
        let before = {
            let channels = service.channels.read().await;
            channels.len()
        };

        // Second subscription should reuse
        let _rx2 = service.subscribe(&WsChannel::DashboardStats).await;

        let after = {
            let channels = service.channels.read().await;
            channels.len()
        };

        assert_eq!(before, after);
    }

    #[tokio::test]
    async fn test_broadcast_capacity_custom() {
        let service = BroadcastService::with_capacity(5);
        let _rx = service.subscribe(&WsChannel::DashboardStats).await;

        assert_eq!(service.capacity, 5);
    }

    #[tokio::test]
    async fn test_broadcast_capacity_one() {
        let service = BroadcastService::with_capacity(1);
        let mut rx = service.subscribe(&WsChannel::DashboardStats).await;

        let msg = WsMessage::new("test", "content".to_string());
        let _ = service.send(&WsChannel::DashboardStats, msg).await;

        let received = unwrap_ok!(rx.recv().await);
        assert!(received.contains("test"));
    }

    // ==================== BroadcastService All Channel Types ====================

    #[tokio::test]
    async fn test_broadcast_all_channel_types() {
        let service = BroadcastService::new();

        let channels = vec![
            WsChannel::DashboardStats,
            WsChannel::ActiveSessions,
            WsChannel::RecentActivity,
            WsChannel::Notifications,
            WsChannel::SessionLive("sess-1".to_string()),
            WsChannel::UserAuthSessions("user-1".to_string()),
            WsChannel::UserApiKeys("user-1".to_string()),
        ];

        for channel in &channels {
            let mut rx = service.subscribe(channel).await;
            let msg = WsMessage::new("target", "test".to_string());
            let _ = service.send(channel, msg).await;
            let _ = rx.recv().await;
        }

        assert_eq!(service.channels.read().await.len(), 7);
    }

    #[tokio::test]
    async fn test_broadcast_remove_all_channels() {
        let service = BroadcastService::new();

        let channels = vec![
            WsChannel::DashboardStats,
            WsChannel::ActiveSessions,
            WsChannel::Notifications,
        ];

        for channel in &channels {
            let _ = service.subscribe(channel).await;
        }

        assert_eq!(service.channels.read().await.len(), 3);

        for channel in &channels {
            service.remove_channel(channel).await;
        }

        assert_eq!(service.channels.read().await.len(), 0);
    }

    #[tokio::test]
    async fn test_broadcast_remove_nonexistent_channel() {
        let service = BroadcastService::new();

        // Should not panic
        service.remove_channel(&WsChannel::Notifications).await;

        assert_eq!(service.channels.read().await.len(), 0);
    }

    // ==================== Arc/RwLock Tests ====================

    #[tokio::test]
    async fn test_broadcast_arc_rwlock_shared() {
        let service = BroadcastService::new();
        let clone1 = service.clone();
        let clone2 = service.clone();

        // All clones share the same channels
        let _rx1 = clone1.subscribe(&WsChannel::DashboardStats).await;

        assert_eq!(clone2.subscriber_count(&WsChannel::DashboardStats).await, 1);
        assert_eq!(
            service.subscriber_count(&WsChannel::DashboardStats).await,
            1
        );
    }
}
