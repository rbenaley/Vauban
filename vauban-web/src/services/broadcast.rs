/// VAUBAN Web - Broadcast service for WebSocket.
///
/// Manages real-time updates to connected clients via channels.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, info, trace};

/// Default channel capacity for broadcast channels.
const DEFAULT_CHANNEL_CAPACITY: usize = 100;

/// Coalesce identical periodic broadcast log lines emitted within
/// this window into a single deferred line tagged with the
/// structured `count = N` field. The dashboard pusher emits 4-12
/// `Broadcast message sent` events per second per connected admin;
/// without coalescing the operator's terminal becomes unreadable
/// even at `debug!`. 1 s matches the fastest pusher cadence so a
/// burst is always aggregated and flushed before the next tick.
const PERIODIC_LOG_COALESCE_WINDOW: Duration = Duration::from_secs(1);

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
    /// User auth sessions list updates (for /accounts/login-sessions page).
    UserAuthSessions(String),
    /// User API keys list updates (for /accounts/apikeys page).
    UserApiKeys(String),
    /// Session history list updates (for /sessions page, admin-only).
    SessionsList,
    /// Admin auth sessions list updates (for /accounts/all-login-sessions page).
    AdminAuthSessions,
    /// Bastion Watch dashboard updates scoped to a specific user.
    /// One channel per non-supervisor user connected to the
    /// `/ws/dashboard/personal` endpoint -- the pusher computes a
    /// user-scoped snapshot (L1 type-system + L2 SQL filter) and
    /// broadcasts the per-tile fragments here. High-cardinality:
    /// scales with the number of dashboards open at any time.
    DashboardStatsUser(String),
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
            WsChannel::SessionsList => "sessions:list".to_string(),
            WsChannel::AdminAuthSessions => "admin:auth-sessions".to_string(),
            WsChannel::DashboardStatsUser(user_uuid) => {
                format!("dashboard:user:{}", user_uuid)
            }
        }
    }

    /// Wire prefix shared by every parametric `DashboardStatsUser`
    /// channel name. Centralised so the pusher's
    /// `active_channels_with_prefix(...)` and the `parse(...)`
    /// matcher cannot drift.
    pub const DASHBOARD_USER_PREFIX: &'static str = "dashboard:user:";

    /// Whether this channel has low cardinality (a single instance
    /// across the whole service) versus high cardinality (one
    /// instance per session / per user / per ...).
    ///
    /// "Low" means a `BroadcastService::send` on this channel can be
    /// safely logged at INFO level: there are at most a few of them
    /// active at any time, and each emission is a meaningful
    /// operational event (e.g. dashboard tick, JIT notification,
    /// `recording_hydrated` push). "High" means the channel is one
    /// of N instances scaling with concurrent sessions / users; INFO
    /// would flood the log under load (e.g. RDP frames at 30-60 fps
    /// per active session).
    ///
    /// See [`.cursor/rules/websocket-logging.mdc`] for the level
    /// matrix and the procedure to follow when adding a new variant.
    /// The exhaustive `match` (no `_ =>` arm) is deliberate: any
    /// future variant MUST be classified explicitly here.
    pub fn is_low_cardinality(&self) -> bool {
        match self {
            // Singleton channels: one instance per service.
            WsChannel::DashboardStats
            | WsChannel::ActiveSessions
            | WsChannel::ActiveSessionsList
            | WsChannel::RecentActivity
            | WsChannel::Notifications
            | WsChannel::SessionsList
            | WsChannel::AdminAuthSessions => true,
            // Parametric channels: one instance per session / user.
            // DashboardStatsUser is parametric because we open one
            // per non-supervisor browser tab subscribed to the
            // user-scoped dashboard; a singleton would force every
            // tile broadcast to land at INFO and flood the log.
            WsChannel::SessionLive(_)
            | WsChannel::UserAuthSessions(_)
            | WsChannel::UserApiKeys(_)
            | WsChannel::DashboardStatsUser(_) => false,
        }
    }

    /// String-keyed variant of [`is_low_cardinality`] used by
    /// [`BroadcastService::send_raw`] callers that bypass the typed
    /// enum. Unknown channel names default to `false` (high-cardinality)
    /// to fail safe against future name drift logging at INFO.
    pub fn is_low_cardinality_str(channel_name: &str) -> bool {
        Self::parse(channel_name)
            .map(|c| c.is_low_cardinality())
            .unwrap_or(false)
    }

    /// Parse a channel from a string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "dashboard:stats" => Some(WsChannel::DashboardStats),
            "dashboard:active-sessions" => Some(WsChannel::ActiveSessions),
            "sessions:active-list" => Some(WsChannel::ActiveSessionsList),
            "sessions:list" => Some(WsChannel::SessionsList),
            "admin:auth-sessions" => Some(WsChannel::AdminAuthSessions),
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
            s if s.starts_with(Self::DASHBOARD_USER_PREFIX) => {
                let user_uuid = s.strip_prefix(Self::DASHBOARD_USER_PREFIX)?.to_string();
                Some(WsChannel::DashboardStatsUser(user_uuid))
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

/// Coalescer for the `send_periodic` / `send_raw_periodic` log
/// stream. Identical `(channel, receivers)` events that arrive
/// within [`PERIODIC_LOG_COALESCE_WINDOW`] are buffered and emitted
/// as a single `debug!` line carrying the aggregated count. The
/// flush is opportunistic: it happens as a side-effect of the next
/// `record(...)` call after the window has elapsed, so an idle
/// stream does not trail a final line -- which is fine given the
/// pusher always ticks. Using `std::sync::Mutex` (not `tokio::sync`)
/// is deliberate: `record` is called from inside a `tokio::sync::
/// RwLock` read guard and we MUST NOT await while holding it; the
/// critical section is purely O(unique-keys) HashMap arithmetic.
#[derive(Debug)]
struct PeriodicLogCoalescer {
    pending: Mutex<HashMap<(String, usize), u32>>,
    last_flush: Mutex<Option<Instant>>,
    window: Duration,
}

impl PeriodicLogCoalescer {
    fn new(window: Duration) -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            last_flush: Mutex::new(None),
            window,
        }
    }

    /// Pure step function suitable for unit tests: returns the
    /// drained batch (possibly empty) and bumps the counter for the
    /// current event. The flush is "due" iff the window has elapsed
    /// since the previous flush -- the very first call always opens
    /// a fresh window with an empty drain.
    fn step(&self, channel: &str, receivers: usize, now: Instant) -> Vec<((String, usize), u32)> {
        // Always lock in the same order (last_flush, pending) so two
        // concurrent recorders never deadlock on each other.
        let mut last = self.last_flush.lock().unwrap_or_else(|p| p.into_inner());
        let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        let due = match *last {
            Some(t) if now.saturating_duration_since(t) < self.window => false,
            _ => {
                *last = Some(now);
                true
            }
        };
        let drained: Vec<((String, usize), u32)> = if due {
            std::mem::take(&mut *pending).into_iter().collect()
        } else {
            Vec::new()
        };
        *pending.entry((channel.to_string(), receivers)).or_insert(0) += 1;
        drained
    }

    /// Record a periodic broadcast and emit any drained batch from
    /// the previous window at `debug!`. The wording is uniform
    /// (`"Broadcast message sent"`) across both branches; the
    /// burst count is carried by the structured `count = N` field
    /// when the same `(channel, receivers)` was emitted more than
    /// once during the window. We deliberately do NOT also append
    /// a `(N times)` suffix to the message body: log aggregators
    /// (Loki, ELK, Datadog) pivot on the structured field, and
    /// duplicating the value in the human-readable message body
    /// would force grep-based readers to dedupe against themselves.
    fn record(&self, channel: &str, receivers: usize) {
        let drained = self.step(channel, receivers, Instant::now());
        for ((ch, recv), cnt) in drained {
            if cnt <= 1 {
                debug!(
                    channel = %ch,
                    receivers = recv,
                    "Broadcast message sent"
                );
            } else {
                debug!(
                    channel = %ch,
                    receivers = recv,
                    count = cnt,
                    "Broadcast message sent"
                );
            }
        }
    }
}

/// Broadcast service for managing WebSocket channels.
#[derive(Clone)]
pub struct BroadcastService {
    channels: Arc<RwLock<HashMap<String, broadcast::Sender<String>>>>,
    capacity: usize,
    /// Per-instance coalescer for `send_raw_periodic` log lines.
    /// Wrapped in `Arc` so all clones of `BroadcastService` share
    /// the same buffer (otherwise each clone would coalesce in
    /// isolation and the operator would see duplicate burst lines).
    periodic_coalescer: Arc<PeriodicLogCoalescer>,
}

impl BroadcastService {
    /// Create a new broadcast service.
    pub fn new() -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
            capacity: DEFAULT_CHANNEL_CAPACITY,
            periodic_coalescer: Arc::new(PeriodicLogCoalescer::new(PERIODIC_LOG_COALESCE_WINDOW)),
        }
    }

    /// Create a new broadcast service with custom capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
            capacity,
            periodic_coalescer: Arc::new(PeriodicLogCoalescer::new(PERIODIC_LOG_COALESCE_WINDOW)),
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
                    // Cardinality-aware level routing -- see
                    // `WsChannel::is_low_cardinality` for the rationale
                    // and the convention pinned by the broadcast tests.
                    if WsChannel::is_low_cardinality_str(channel_name) {
                        info!(channel = %channel_name, receivers = count, "Broadcast message sent");
                    } else {
                        debug!(channel = %channel_name, receivers = count, "Broadcast message sent");
                    }
                    Ok(count)
                }
                Err(_) => {
                    // No receivers - this is not an error, just no one listening
                    trace!(channel = %channel_name, "No receivers for broadcast");
                    Ok(0)
                }
            }
        } else {
            // Channel doesn't exist yet (no subscribers) - this is normal, not a warning
            trace!(channel = %channel_name, "Channel does not exist");
            Err(())
        }
    }

    /// Send a message that is part of a SCHEDULED, HIGH-FREQUENCY
    /// stream (e.g. the Bastion Watch dashboard pusher ticking every
    /// 1 s on `WsChannel::DashboardStats`).
    ///
    /// Unlike [`Self::send`], the success log is FORCED to `debug!`
    /// regardless of the channel's cardinality classification. The
    /// rationale: cardinality is "how many channel instances exist"
    /// (orthogonal to volume), but a low-cardinality channel hammered
    /// by a 1 Hz tick would still flood the operator's terminal --
    /// 4 to 12 lines/s for a single connected admin in our case.
    /// The operationally-meaningful event for a periodic stream is
    /// "the pusher started" / "the pusher stopped" (which the
    /// dispatcher logs at `info!` itself), not every tile push.
    ///
    /// Use [`Self::send`] for event-driven, low-frequency broadcasts
    /// (notifications, `recording_hydrated`, JIT requests, ...) so
    /// every meaningful event still surfaces at `info!` for ops.
    pub async fn send_periodic(
        &self,
        channel: &WsChannel,
        message: WsMessage,
    ) -> Result<usize, ()> {
        let channel_name = channel.as_str();
        let html = message.to_htmx_html();
        self.send_raw_periodic(&channel_name, html).await
    }

    /// String-keyed counterpart of [`Self::send_periodic`]. See that
    /// method for the rationale; this entry point exists for callers
    /// that already work with the wire-form channel name.
    pub async fn send_raw_periodic(&self, channel_name: &str, html: String) -> Result<usize, ()> {
        let channels = self.channels.read().await;

        if let Some(sender) = channels.get(channel_name) {
            match sender.send(html) {
                Ok(count) => {
                    // Coalesced debug log: identical lines emitted
                    // within `PERIODIC_LOG_COALESCE_WINDOW` are folded
                    // into a single deferred entry tagged with the
                    // structured `count = N` field. See
                    // `PeriodicLogCoalescer` for the contract and
                    // `send_periodic` doc for the rationale.
                    self.periodic_coalescer.record(channel_name, count);
                    Ok(count)
                }
                Err(_) => {
                    trace!(channel = %channel_name, "No receivers for broadcast");
                    Ok(0)
                }
            }
        } else {
            trace!(channel = %channel_name, "Channel does not exist");
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

    /// List the names of channels currently registered whose key
    /// starts with `prefix` AND has at least one live subscriber.
    /// Used by the Bastion Watch dashboard pusher to enumerate the
    /// per-user `dashboard:user:<uuid>` channels that need a fresh
    /// per-tick snapshot. Channels with `receiver_count() == 0`
    /// (e.g. a tab that just disconnected and not yet been removed
    /// by `remove_channel`) are skipped so the pusher does not
    /// compute snapshots for nobody.
    ///
    /// SECURITY: this is the discovery seam used to drive the
    /// per-user broadcast loop. It MUST only return channel names;
    /// it does not surface per-user payloads or sensitive state.
    pub async fn active_channels_with_prefix(&self, prefix: &str) -> Vec<String> {
        let channels = self.channels.read().await;
        channels
            .iter()
            .filter(|(name, sender)| name.starts_with(prefix) && sender.receiver_count() > 0)
            .map(|(name, _)| name.clone())
            .collect()
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
    fn test_ws_channel_sessions_list() {
        let channel = WsChannel::SessionsList;
        assert_eq!(channel.as_str(), "sessions:list");
    }

    #[test]
    fn test_ws_channel_parse_sessions_list() {
        assert_eq!(
            WsChannel::parse("sessions:list"),
            Some(WsChannel::SessionsList)
        );
    }

    #[test]
    fn test_ws_channel_roundtrip() {
        let channels = vec![
            WsChannel::DashboardStats,
            WsChannel::ActiveSessions,
            WsChannel::ActiveSessionsList,
            WsChannel::SessionsList,
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
    async fn active_channels_with_prefix_lists_only_subscribed_channels() {
        let service = BroadcastService::new();
        // Three subscribers across different channels, one of them
        // a parametric DashboardStatsUser pseudo-uuid.
        let _r1 = service
            .subscribe(&WsChannel::DashboardStatsUser("alice".into()))
            .await;
        let _r2 = service
            .subscribe(&WsChannel::DashboardStatsUser("bob".into()))
            .await;
        let _r3 = service.subscribe(&WsChannel::DashboardStats).await;

        let mut found = service.active_channels_with_prefix("dashboard:user:").await;
        found.sort();
        assert_eq!(
            found,
            vec![
                "dashboard:user:alice".to_string(),
                "dashboard:user:bob".to_string()
            ],
            "active_channels_with_prefix MUST return ONLY the \
             dashboard:user:* names, never the singleton \
             dashboard:stats"
        );
    }

    #[tokio::test]
    async fn active_channels_with_prefix_skips_zero_receiver_channels() {
        let service = BroadcastService::new();
        // Subscribe then drop -> sender lives in the registry but
        // receiver_count() == 0. The pusher must NOT spend cycles on
        // a snapshot for nobody.
        {
            let _r = service
                .subscribe(&WsChannel::DashboardStatsUser("ghost".into()))
                .await;
        }
        let found = service.active_channels_with_prefix("dashboard:user:").await;
        assert!(
            found.is_empty(),
            "channel with 0 receivers must be skipped (got {:?})",
            found
        );
    }

    #[tokio::test]
    async fn active_channels_with_prefix_returns_empty_for_unknown_prefix() {
        let service = BroadcastService::new();
        let _r = service.subscribe(&WsChannel::DashboardStats).await;
        assert!(
            service
                .active_channels_with_prefix("does-not-exist:")
                .await
                .is_empty()
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
        assert!((10..=10000).contains(&DEFAULT_CHANNEL_CAPACITY));
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

    // ========================================================================
    // is_low_cardinality / level routing -- battle-tested classification
    //
    // Classifies every WsChannel variant explicitly. The match in
    // `WsChannel::is_low_cardinality` is exhaustive (no `_ =>` arm), so
    // a future variant cannot compile without being categorised. These
    // drift-tests pin the *runtime* behaviour matches that
    // categorisation, and lock the contract that BroadcastService::send_raw
    // routes the success log to INFO for low-cardinality channels and
    // DEBUG for high-cardinality ones (rationale: see the audit in
    // `.cursor/rules/websocket-logging.mdc`).
    // ========================================================================

    #[test]
    fn is_low_cardinality_classification_is_exhaustive() {
        // Singleton channels: ONE per service. Logging at INFO is safe.
        for low in &[
            WsChannel::DashboardStats,
            WsChannel::ActiveSessions,
            WsChannel::ActiveSessionsList,
            WsChannel::RecentActivity,
            WsChannel::Notifications,
            WsChannel::SessionsList,
            WsChannel::AdminAuthSessions,
        ] {
            assert!(
                low.is_low_cardinality(),
                "{:?} is a singleton channel and must classify as \
                 low-cardinality (info-loggable)",
                low
            );
        }
        // Parametric channels: scale with concurrent sessions / users.
        // Logging at INFO would flood under load.
        for high in &[
            WsChannel::SessionLive("any".into()),
            WsChannel::UserAuthSessions("any".into()),
            WsChannel::UserApiKeys("any".into()),
            WsChannel::DashboardStatsUser("any-uuid".into()),
        ] {
            assert!(
                !high.is_low_cardinality(),
                "{:?} is a per-instance channel and must classify as \
                 high-cardinality (debug-only)",
                high
            );
        }
    }

    #[test]
    fn is_low_cardinality_str_round_trips_via_parse() {
        // For every CANONICAL wire form, the string-keyed classifier
        // must agree with the typed enum.
        let cases: &[(&str, bool)] = &[
            ("dashboard:stats", true),
            ("dashboard:active-sessions", true),
            ("sessions:active-list", true),
            ("dashboard:recent-activity", true),
            ("notifications", true),
            ("sessions:list", true),
            ("admin:auth-sessions", true),
            ("session:abc-def", false),
            ("user:42:auth-sessions", false),
            ("user:42:api-keys", false),
            ("dashboard:user:00000000-0000-0000-0000-000000000001", false),
        ];
        for (name, expected) in cases {
            assert_eq!(
                WsChannel::is_low_cardinality_str(name),
                *expected,
                "wire form `{}` must classify as low={}",
                name,
                expected
            );
        }
    }

    #[test]
    fn is_low_cardinality_str_unknown_defaults_to_high() {
        // Anti-leak guard: an unknown / future / typoed channel name
        // MUST default to false (high-cardinality, DEBUG). Otherwise
        // a careless `send_raw("custom-foo", ...)` could silently
        // start logging at INFO on a yet-unclassified channel.
        for unknown in &["", "foo", "custom", "session", "user:", "user::api"] {
            assert!(
                !WsChannel::is_low_cardinality_str(unknown),
                "unknown channel name `{}` must default to high-cardinality \
                 (DEBUG) -- never INFO",
                unknown
            );
        }
    }

    /// Source-level pin on `BroadcastService::send_raw`: must route
    /// the level via `WsChannel::is_low_cardinality_str(...)`. A future
    /// edit that drops the routing (back to plain `debug!`) would
    /// re-create the "broadcast invisible at INFO" pathology of the
    /// audit; a future edit that drops the high-cardinality fallback
    /// (forces INFO everywhere) would flood the log under load.
    #[test]
    fn send_raw_routes_log_level_via_cardinality_classifier() {
        let src = include_str!("broadcast.rs");
        // Locate the `send_raw` body via a brace counter so the pin
        // does not break on the formatting / match arms inside.
        let start = src
            .find("pub async fn send_raw(")
            .expect("send_raw signature");
        let tail = &src[start..];
        let open = tail.find('{').expect("open brace after send_raw signature");
        let mut depth: i32 = 0;
        let mut end = tail.len();
        for (i, ch) in tail[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &tail[..end];
        assert!(
            body.contains("WsChannel::is_low_cardinality_str(channel_name)"),
            "send_raw must gate the level on \
             `WsChannel::is_low_cardinality_str(channel_name)` so a single \
             classifier owns the convention. See `.cursor/rules/websocket-logging.mdc`."
        );
        assert!(
            body.contains("info!(channel = %channel_name, receivers = count"),
            "send_raw must emit the success log at INFO for low-cardinality \
             channels (channel + receivers fields, canonical wording)"
        );
        assert!(
            body.contains("debug!(channel = %channel_name, receivers = count"),
            "send_raw must emit the success log at DEBUG for high-cardinality \
             channels (so RDP frame fan-outs do not flood INFO)"
        );
    }

    /// Source-level pin on `BroadcastService::send_raw_periodic`:
    /// must route every success through the `PeriodicLogCoalescer`
    /// and NEVER emit `info!` directly. The coalescer itself logs
    /// at `debug!` (pinned by `coalescer_record_emits_debug_only`).
    /// A future edit that drops the coalescer (back to a per-event
    /// `debug!`) re-creates the production flooding flagged after
    /// the v0.7.0 dashboard refonte: 4-12 identical lines/s per
    /// connected admin. A future edit that uses `info!` here would
    /// regress the v0.7.0 fix that moved the periodic stream to
    /// `debug!`.
    #[test]
    fn send_raw_periodic_routes_through_coalescer() {
        let src = include_str!("broadcast.rs");
        let start = src
            .find("pub async fn send_raw_periodic(")
            .expect("send_raw_periodic signature");
        let tail = &src[start..];
        let open = tail
            .find('{')
            .expect("open brace after send_raw_periodic signature");
        let mut depth: i32 = 0;
        let mut end = tail.len();
        for (i, ch) in tail[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &tail[..end];
        assert!(
            body.contains("self.periodic_coalescer.record(channel_name, count)"),
            "send_raw_periodic must route success through \
             `self.periodic_coalescer.record(channel_name, count)` \
             so identical lines are folded into one entry tagged \
             with the structured `count = N` field per coalesce \
             window. See `PeriodicLogCoalescer`."
        );
        assert!(
            !body.contains("info!(channel = %channel_name"),
            "send_raw_periodic must NOT emit the success log at INFO \
             -- the periodic stream is debug-only by design (see \
             `.cursor/rules/websocket-logging.mdc` section 4.1)"
        );
        assert!(
            !body.contains("debug!(channel = %channel_name, receivers = count"),
            "send_raw_periodic must NOT emit per-event `debug!` \
             directly -- go through `periodic_coalescer.record(...)` \
             so bursts are coalesced. The direct `debug!` belongs to \
             `send_raw` (event-driven path)."
        );
    }

    /// Coalescer behavior: identical events within the window are
    /// buffered; the first event past the window flushes the prior
    /// batch with the aggregated count.
    #[test]
    fn coalescer_buffers_within_window_and_flushes_on_window_close() {
        let c = PeriodicLogCoalescer::new(Duration::from_millis(100));
        let t0 = Instant::now();
        // First event opens a window. Drain is empty (no prior
        // batch).
        let drained = c.step("dashboard:stats", 2, t0);
        assert!(drained.is_empty());
        // Five more events within the window: all buffered, no
        // flush.
        for i in 1..=5 {
            let drained = c.step("dashboard:stats", 2, t0 + Duration::from_millis(10 * i));
            assert!(drained.is_empty(), "iteration {i} unexpectedly flushed");
        }
        // Past the window: the prior batch (6 events on the same
        // (channel, receivers) key) flushes as a single aggregated
        // entry, and a new window opens with the current event.
        let drained = c.step("dashboard:stats", 2, t0 + Duration::from_millis(150));
        assert_eq!(
            drained,
            vec![(("dashboard:stats".to_string(), 2usize), 6u32)],
            "flush MUST fold all 6 within-window events into one \
             entry with count = 6"
        );
    }

    /// Coalescer keys on (channel, receivers): two distinct keys
    /// must NOT be collapsed together.
    #[test]
    fn coalescer_keys_on_channel_and_receivers_pair() {
        let c = PeriodicLogCoalescer::new(Duration::from_millis(100));
        let t0 = Instant::now();
        // Open the window.
        let _ = c.step("dashboard:stats", 2, t0);
        // Burst on three distinct keys.
        for _ in 0..3 {
            let _ = c.step("dashboard:stats", 2, t0 + Duration::from_millis(10));
        }
        for _ in 0..2 {
            let _ = c.step("dashboard:stats", 5, t0 + Duration::from_millis(20));
        }
        for _ in 0..1 {
            let _ = c.step("notifications", 1, t0 + Duration::from_millis(30));
        }
        // Past the window -> drain as a multimap.
        let mut drained = c.step("dashboard:stats", 2, t0 + Duration::from_millis(150));
        drained.sort();
        let mut expected: Vec<((String, usize), u32)> = vec![
            (("dashboard:stats".into(), 2), 4), // 1 from the window-open call + 3 bursts
            (("dashboard:stats".into(), 5), 2),
            (("notifications".into(), 1), 1),
        ];
        expected.sort();
        assert_eq!(drained, expected);
    }

    /// Coalescer is concurrency-safe: two threads recording the same
    /// key in a tight loop must not lose increments and must not
    /// panic on poisoned locks (the impl uses `into_inner()` to
    /// recover from a poisoned `std::sync::Mutex`).
    #[test]
    fn coalescer_concurrent_record_does_not_drop_events() {
        use std::sync::Arc;
        use std::thread;

        // 1-hour window so nothing flushes during the test; we read
        // the buffered count at the end.
        let c = Arc::new(PeriodicLogCoalescer::new(Duration::from_secs(3600)));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let c = Arc::clone(&c);
            handles.push(thread::spawn(move || {
                let t0 = Instant::now();
                for i in 0..250 {
                    let _ = c.step("ch", 1, t0 + Duration::from_micros(i));
                }
            }));
        }
        for h in handles {
            h.join().expect("thread join");
        }
        let pending = c.pending.lock().expect("lock");
        let total: u32 = pending.values().sum();
        assert_eq!(total, 4 * 250, "every increment MUST be recorded");
    }

    /// Pin: the periodic coalescer's `record` method emits at
    /// `debug!` for both branches (count == 1 and count > 1) and
    /// surfaces the burst count via the structured `count = N`
    /// field (NOT via a redundant `(N times)` suffix in the
    /// message body). A drift to `info!` here would re-flood the
    /// INFO stream; a drift in the structured field would silently
    /// drop the burst signal that log aggregators key on.
    #[test]
    fn coalescer_record_emits_debug_only_with_burst_count_field() {
        let src = include_str!("broadcast.rs");
        let start = src
            .find("fn record(&self, channel: &str, receivers: usize)")
            .expect("PeriodicLogCoalescer::record signature");
        let tail = &src[start..];
        let open = tail.find('{').expect("open brace");
        let mut depth: i32 = 0;
        let mut end = tail.len();
        for (i, ch) in tail[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &tail[..end];
        // Two debug! calls: one for cnt == 1, one for cnt > 1.
        let debug_count = body.matches("debug!(").count();
        assert!(
            debug_count >= 2,
            "PeriodicLogCoalescer::record must emit at least two \
             `debug!(...)` calls (one per branch). Found {}",
            debug_count
        );
        assert!(
            !body.contains("info!(") && !body.contains("warn!(") && !body.contains("error!("),
            "PeriodicLogCoalescer::record must stay at `debug!` -- \
             a higher level would defeat the whole point of \
             coalescing the periodic stream."
        );
        assert!(
            body.contains("count = cnt"),
            "the burst branch MUST surface the burst count via the \
             structured `count = N` field so log aggregators can \
             pivot on it. A future drift that drops `count = cnt` \
             would silently lose the burst signal."
        );
        // Anti-redundancy guard: the message body MUST NOT also
        // carry a `(N times)` suffix. The structured `count = N`
        // field already conveys the value; duplicating it in the
        // human-readable body forces grep-based readers to dedupe
        // the same number against itself.
        assert!(
            !body.contains("(N times)") && !body.contains("({} times)"),
            "PeriodicLogCoalescer::record must NOT format `(N times)` \
             in the message body -- the structured `count = N` field \
             is the single source of truth for the burst size."
        );
    }

    /// Cross-file source-grep: the Bastion Watch dashboard pusher MUST
    /// route every per-tile broadcast through `send_periodic`, not
    /// `send`. The pusher ticks at 1 Hz on the singleton
    /// `WsChannel::DashboardStats`; a careless `.send(` here would
    /// regress the log to INFO and flood the operator's console.
    #[test]
    fn dashboard_pusher_uses_send_periodic_not_send() {
        let src = include_str!("../tasks/dashboard_pusher.rs");
        // Tolerate whitespace / newline (rustfmt may wrap long arg
        // lists) and tolerate either inline-channel callers
        // (`.send_periodic(&WsChannel::Foo, ...)`) or routed-channel
        // callers (`.send_periodic(target_channel, ...)`). The
        // post-isolation pusher uses the latter so it can dispatch
        // to `WsChannel::DashboardStats` (Global) or
        // `WsChannel::DashboardStatsUser(uuid)` (per-user) at
        // run-time. Bare `.send(...)` on the broadcast service is
        // forbidden in this file regardless, because the pusher
        // ticks on a 1 Hz scheduled stream and would flood INFO.
        let strip_ws = |s: &str| -> String { s.chars().filter(|c| !c.is_whitespace()).collect() };
        let compact = strip_ws(src);
        let bad = compact.matches(".send(&WsChannel::").count()
            + compact.matches(".send(target_channel,").count();
        let good = compact.matches(".send_periodic(").count();
        assert_eq!(
            bad, 0,
            "dashboard_pusher.rs must not call `.send(...)` on a \
             scheduled tick -- use `.send_periodic(...)` so the \
             success log stays at DEBUG. Found {bad} occurrence(s)."
        );
        assert!(
            good >= 3,
            "dashboard_pusher.rs is expected to broadcast through at \
             least 3 `.send_periodic(...)` call sites (fast, medium, \
             slow tier). Found only {good}."
        );
    }
}
