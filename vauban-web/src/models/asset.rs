/// VAUBAN Web - Asset model.
///
/// Assets represent servers/resources accessible via SSH or RDP.
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use crate::schema::{asset_asset_groups, asset_groups, assets};

// ==================== Flexible Deserialization Helpers ====================

/// Deserialize an optional i32 from either a number or a string.
/// This is needed because HTML forms send all values as strings.
pub(crate) fn deserialize_optional_i32<'de, D>(deserializer: D) -> Result<Option<i32>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrInt {
        String(String),
        Int(i32),
    }

    let opt: Option<StringOrInt> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(StringOrInt::Int(i)) => Ok(Some(i)),
        Some(StringOrInt::String(s)) if s.is_empty() => Ok(None),
        Some(StringOrInt::String(s)) => s
            .parse::<i32>()
            .map(Some)
            .map_err(|_| D::Error::custom(format!("invalid integer: {}", s))),
    }
}

/// Asset type / connection protocol.
///
/// Two families coexist:
///   - Classical IT transports: `Ssh`, `Rdp`. Browser-driven, recorded.
///   - IACS / ISA-62443 transports: `Iacs*` variants. EWS-driven, opened
///     via the in-process IACS sshd (`services::iacs_tunnel`) and routed
///     as a TCP tunnel; never recorded as text/PTY.
///
/// IACS variants encode the industrial protocol family (Modbus, OPC-UA,
/// Profinet, IEC-60870-5-104) plus a generic catch-all (`IacsTcp`) for
/// industrial protocols not yet profiled. The catch-all has NO default
/// port: the asset form requires the operator to enter one explicitly.
///
/// Wire vocabulary is closed: the `assets_asset_type_chk` SQL CHECK
/// constraint enforces the exact 7 strings below at insert time, and
/// the `iacs_drift_test` test extracts that constraint via
/// `pg_get_constraintdef` and asserts it lists every variant declared
/// here. The Rust `parse` function ALSO refuses unknown values
/// (returns `Err` instead of silently falling back to `Ssh` like the
/// pre-IACS implementation did) so the call site is forced to handle
/// the error path -- a misnamed asset_type can no longer get treated
/// as SSH by accident.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    diesel::expression::AsExpression,
    diesel::deserialize::FromSqlRow,
)]
#[serde(rename_all = "snake_case")]
#[diesel(sql_type = diesel::sql_types::Varchar)]
pub enum AssetType {
    Ssh,
    Rdp,
    IacsModbus,
    IacsOpcua,
    IacsProfinet,
    IacsIec104,
    /// Catch-all for industrial protocols not yet profiled by Vauban
    /// (DNP3, BACnet, S7, EtherNet/IP, ...). No default port, the
    /// admin must set one explicitly when creating the asset.
    IacsTcp,
}

/// Asset family: orthogonal to the underlying protocol, used to drive
/// UI grouping (filters, badges) and Casbin gate `assets:connect_iacs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetFamily {
    /// Classical IT transports (SSH, RDP).
    It,
    /// Industrial Automation and Control Systems (ISA/IEC 62443).
    Iacs,
}

/// Sub-classification of an IACS asset's industrial protocol. `None`
/// for IT assets (`Ssh`, `Rdp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IacsProtocol {
    Modbus,
    OpcUa,
    Profinet,
    Iec104,
    /// Generic TCP catch-all (`IacsTcp`); see `AssetType::IacsTcp` doc.
    Tcp,
}

impl IacsProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Modbus => "modbus",
            Self::OpcUa => "opcua",
            Self::Profinet => "profinet",
            Self::Iec104 => "iec104",
            Self::Tcp => "tcp",
        }
    }
}

impl std::fmt::Display for IacsProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when a string cannot be parsed into an `AssetType`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetTypeParseError(pub String);

impl std::fmt::Display for AssetTypeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown asset_type value: {:?}", self.0)
    }
}

impl std::error::Error for AssetTypeParseError {}

impl AssetType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
            Self::IacsModbus => "iacs_modbus",
            Self::IacsOpcua => "iacs_opcua",
            Self::IacsProfinet => "iacs_profinet",
            Self::IacsIec104 => "iacs_iec104",
            Self::IacsTcp => "iacs_tcp",
        }
    }

    /// Strict parse. Returns `Err` for any unknown value -- in
    /// particular, NEVER falls back to `Ssh`. Use this for any code
    /// path that handles persisted data (form submissions, DB reads
    /// via `FromSql`, IPC payloads).
    pub fn parse(s: &str) -> Result<Self, AssetTypeParseError> {
        match s {
            "ssh" => Ok(Self::Ssh),
            "rdp" => Ok(Self::Rdp),
            "iacs_modbus" => Ok(Self::IacsModbus),
            "iacs_opcua" => Ok(Self::IacsOpcua),
            "iacs_profinet" => Ok(Self::IacsProfinet),
            "iacs_iec104" => Ok(Self::IacsIec104),
            "iacs_tcp" => Ok(Self::IacsTcp),
            other => Err(AssetTypeParseError(other.to_string())),
        }
    }

    /// Lossy parse for legacy code paths that need to keep the
    /// pre-IACS infallible signature. New code MUST prefer `parse`.
    /// The fallback is `Ssh` (matches historical behaviour) but the
    /// presence of a CHECK constraint at the DB layer means an
    /// unknown value can only ever appear here for transient form
    /// input that is going to be rejected by the validator anyway.
    pub fn parse_or_ssh(s: &str) -> Self {
        Self::parse(s).unwrap_or(Self::Ssh)
    }

    /// Try to parse a string into an AssetType, returning None for unknown values.
    pub fn try_parse(s: &str) -> Option<Self> {
        Self::parse(s).ok()
    }

    /// Default TCP port suggested by the protocol. `None` for
    /// `IacsTcp` (the operator must enter the port explicitly).
    pub fn default_port(&self) -> Option<i32> {
        match self {
            Self::Ssh => Some(22),
            Self::Rdp => Some(3389),
            // Modbus TCP / IANA 502.
            Self::IacsModbus => Some(502),
            // OPC UA Binary / IANA 4840.
            Self::IacsOpcua => Some(4840),
            // PROFINET cyclic real-time / IANA 34962-34964 (lowest).
            Self::IacsProfinet => Some(34962),
            // IEC 60870-5-104 / IANA 2404.
            Self::IacsIec104 => Some(2404),
            // No default for the generic catch-all.
            Self::IacsTcp => None,
        }
    }

    /// Whether this asset_type belongs to the IACS family.
    pub fn is_iacs(&self) -> bool {
        matches!(
            self,
            Self::IacsModbus
                | Self::IacsOpcua
                | Self::IacsProfinet
                | Self::IacsIec104
                | Self::IacsTcp
        )
    }

    /// Whether this asset_type belongs to the classical IT family
    /// (SSH, RDP).
    pub fn is_it(&self) -> bool {
        matches!(self, Self::Ssh | Self::Rdp)
    }

    pub fn family(&self) -> AssetFamily {
        if self.is_iacs() {
            AssetFamily::Iacs
        } else {
            AssetFamily::It
        }
    }

    /// Industrial protocol sub-classification, `None` for IT assets.
    pub fn iacs_protocol(&self) -> Option<IacsProtocol> {
        match self {
            Self::IacsModbus => Some(IacsProtocol::Modbus),
            Self::IacsOpcua => Some(IacsProtocol::OpcUa),
            Self::IacsProfinet => Some(IacsProtocol::Profinet),
            Self::IacsIec104 => Some(IacsProtocol::Iec104),
            Self::IacsTcp => Some(IacsProtocol::Tcp),
            Self::Ssh | Self::Rdp => None,
        }
    }

    /// Exhaustive enumeration of every variant. Used by drift tests
    /// and form construction.
    pub const ALL: &'static [AssetType] = &[
        AssetType::Ssh,
        AssetType::Rdp,
        AssetType::IacsModbus,
        AssetType::IacsOpcua,
        AssetType::IacsProfinet,
        AssetType::IacsIec104,
        AssetType::IacsTcp,
    ];

    /// Human-readable label suitable for `<select>` options. Kept on
    /// the enum (rather than scattered across templates) so the form
    /// list and the badge captions never drift.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ssh => "SSH",
            Self::Rdp => "RDP",
            Self::IacsModbus => "IACS - Modbus",
            Self::IacsOpcua => "IACS - OPC UA",
            Self::IacsProfinet => "IACS - PROFINET",
            Self::IacsIec104 => "IACS - IEC 60870-5-104",
            Self::IacsTcp => "IACS - Generic TCP",
        }
    }

    /// Compact 3-4 character label suitable for the square asset-type
    /// badge that sits next to the asset name on the detail and list
    /// pages. The square is fixed at `h-10 w-10` (40 px) so the
    /// long-form `IACS_MODBUS` overflowed and crashed into the title
    /// (operator-reported issue 2026-05-08). Each variant gets a
    /// pictogram-style abbreviation that fits the tile and matches
    /// industry conventions:
    ///
    /// - SSH / RDP  -- unchanged.
    /// - IACS Modbus -> `MB`  (Modbus Bus).
    /// - IACS OPC UA -> `OPC` (matches the spec name).
    /// - IACS PROFINET -> `PN` (matches PI/PROFINET conventions).
    /// - IACS IEC 60870-5-104 -> `104` (the protocol's common name).
    /// - IACS generic TCP -> `TCP` (no default port -- matches the
    ///   "raw TCP fallback" semantics).
    pub fn badge_label(&self) -> &'static str {
        match self {
            Self::Ssh => "SSH",
            Self::Rdp => "RDP",
            Self::IacsModbus => "MB",
            Self::IacsOpcua => "OPC",
            Self::IacsProfinet => "PN",
            Self::IacsIec104 => "104",
            Self::IacsTcp => "TCP",
        }
    }

    /// Compact label for the **access rule** "Allowed protocols" row (detail
    /// / list). Shorter than [`Self::label`] which prefixes IACS variants
    /// with "IACS - …" for asset creation forms.
    pub fn access_rule_protocol_display_label(self) -> &'static str {
        match self {
            Self::Ssh => "SSH",
            Self::Rdp => "RDP",
            Self::IacsModbus => "Modbus",
            Self::IacsOpcua => "OPC UA",
            Self::IacsProfinet => "PROFINET",
            Self::IacsIec104 => "IEC-104",
            Self::IacsTcp => "IACS (TCP)",
        }
    }

    /// Map a persisted `allowed_protocols` wire token to the operator-facing
    /// string shown on access-rule pages.
    pub fn format_access_rule_protocol(wire: &str) -> String {
        Self::parse(wire)
            .map(|t| t.access_rule_protocol_display_label().to_string())
            .unwrap_or_else(|_| wire.to_uppercase())
    }

    /// `(value, label)` tuples suitable for the asset_type `<select>`
    /// element in the admin asset form. Single source of truth so the
    /// 7 entries cannot drift between create / edit / list templates.
    ///
    /// `industrial_enabled` mirrors `[industrial].enabled` from the
    /// loaded TOML (see [`crate::config::IndustrialConfig::enabled`]).
    /// When `false`, every `iacs_*` variant is filtered out so the
    /// admin's create / edit form cannot surface industrial protocols
    /// while the master switch is off. Pinned by
    /// [`tests::test_select_options_filters_iacs_when_industrial_disabled`].
    pub fn select_options(industrial_enabled: bool) -> Vec<(String, String)> {
        Self::ALL
            .iter()
            .filter(|t| industrial_enabled || !t.is_iacs())
            .map(|t| (t.as_str().to_string(), t.label().to_string()))
            .collect()
    }

    /// `(value, label)` tuples suitable for the asset_type `<select>`
    /// element in **filter dropdowns** (the user-zone /assets, the
    /// admin /assets/manage list, etc.). Returns the same entries as
    /// [`Self::select_options`] PLUS the synthetic
    /// `("iacs", "IACS - All Industrial Protocols")` row that lets
    /// the operator filter on EVERY `iacs_*` asset_type at once
    /// without ticking five entries.
    ///
    /// `industrial_enabled = false` filters out every `iacs_*` variant
    /// AND the synthetic `iacs` token (see [`IACS_ALL_FILTER_TOKEN`])
    /// so the user/admin filter dropdowns do not leak the existence
    /// of the industrial surface while the master switch is off.
    ///
    /// The synthetic token is intentionally NOT a member of the
    /// `AssetType` enum: filter dropdowns may carry virtual entries
    /// that the create/edit form must NEVER expose (creating an
    /// asset with `asset_type='iacs'` would violate the DB
    /// `assets_asset_type_chk` CHECK constraint). Persistence paths
    /// keep using [`Self::select_options`] / [`Self::try_parse`];
    /// filter paths plug the synthetic row in via [`Self::parse_filter`].
    pub fn filter_options(industrial_enabled: bool) -> Vec<(String, String)> {
        let mut out = Self::select_options(industrial_enabled);
        if industrial_enabled {
            out.push((
                IACS_ALL_FILTER_TOKEN.to_string(),
                "IACS - All Industrial Protocols".to_string(),
            ));
        }
        out
    }

    /// Parse a `?type=` URL parameter into a structured filter
    /// decision. The synthetic `IACS_ALL_FILTER_TOKEN` token expands
    /// to "every variant whose `is_iacs()` is true"; every other
    /// token routes through [`Self::try_parse`].
    pub fn parse_filter(token: &str) -> AssetTypeFilter {
        if token == IACS_ALL_FILTER_TOKEN {
            return AssetTypeFilter::IacsAll;
        }
        match Self::try_parse(token) {
            Some(t) => AssetTypeFilter::One(t),
            None => AssetTypeFilter::Unknown,
        }
    }

    /// Every `iacs_*` variant. Used by callers expanding the synthetic
    /// `IacsAll` filter into a Diesel `eq_any(...)` clause. Centralised
    /// here so a future variant added to [`Self::ALL`] flows through
    /// every filter site automatically.
    pub fn iacs_variants() -> Vec<AssetType> {
        Self::ALL.iter().copied().filter(|t| t.is_iacs()).collect()
    }

    /// `(value, label)` tuples for the industrial-protocol `<select>`
    /// on the IACS asset edit form. Only the five applicative IACS
    /// variants -- never SSH/RDP and never the synthetic `iacs` filter
    /// token.
    pub fn iacs_select_options() -> Vec<(String, String)> {
        Self::iacs_variants()
            .into_iter()
            .map(|t| (t.as_str().to_string(), t.label().to_string()))
            .collect()
    }

    /// Resolve the persisted `asset_type` for an admin edit POST.
    /// IACS rows may switch among IACS variants; IT rows are immutable.
    pub fn resolve_edit_asset_type(
        existing: Self,
        submitted: Option<&str>,
    ) -> Result<Self, AssetTypeEditError> {
        if existing.is_iacs() {
            let raw = submitted
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(existing.as_str());
            let parsed = Self::parse(raw).map_err(AssetTypeEditError::Unknown)?;
            if !parsed.is_iacs() {
                return Err(AssetTypeEditError::IacsToNonIacs);
            }
            Ok(parsed)
        } else if submitted
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_some_and(|s| s != existing.as_str())
        {
            Err(AssetTypeEditError::ProtocolImmutable)
        } else {
            Ok(existing)
        }
    }
}

/// Error returned when an asset edit POST proposes an invalid
/// `asset_type` transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetTypeEditError {
    Unknown(AssetTypeParseError),
    /// An IACS asset was retargeted to SSH/RDP.
    IacsToNonIacs,
    /// An IT asset edit smuggled a different `asset_type`.
    ProtocolImmutable,
}

impl std::fmt::Display for AssetTypeEditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(e) => write!(f, "{e}"),
            Self::IacsToNonIacs => {
                f.write_str("IACS assets can only be switched to another industrial protocol")
            }
            Self::ProtocolImmutable => {
                f.write_str("Asset protocol cannot be changed after creation")
            }
        }
    }
}

impl std::error::Error for AssetTypeEditError {}

/// Synthetic `?type=` token meaning "every IACS protocol at once".
/// Surfaces in [`AssetType::filter_options`] alongside the seven
/// concrete variants but is never persisted on `assets.asset_type`
/// (the column's CHECK constraint would refuse it).
pub const IACS_ALL_FILTER_TOKEN: &str = "iacs";

/// Decision returned by [`AssetType::parse_filter`] for a `?type=`
/// URL parameter. Pattern-matched at every list-handler filter site
/// to either pin the query to a single variant, expand to every
/// IACS variant via `eq_any(...)`, or collapse to "no rows match"
/// when the token is unrecognised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetTypeFilter {
    /// One of the seven concrete `AssetType` variants.
    One(AssetType),
    /// Synthetic "every `iacs_*` variant" virtual filter.
    IacsAll,
    /// Token did not parse; caller MUST collapse to a `id = -1`
    /// empty-result filter (anti-enumeration: a hand-crafted
    /// `?type=garbage` request must not leak the full asset list).
    Unknown,
}

impl std::fmt::Display for AssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl diesel::serialize::ToSql<diesel::sql_types::Varchar, diesel::pg::Pg> for AssetType {
    fn to_sql<'b>(
        &'b self,
        out: &mut diesel::serialize::Output<'b, '_, diesel::pg::Pg>,
    ) -> diesel::serialize::Result {
        <str as diesel::serialize::ToSql<diesel::sql_types::Varchar, diesel::pg::Pg>>::to_sql(
            self.as_str(),
            out,
        )
    }
}

impl diesel::deserialize::FromSql<diesel::sql_types::Varchar, diesel::pg::Pg> for AssetType {
    fn from_sql(
        bytes: <diesel::pg::Pg as diesel::backend::Backend>::RawValue<'_>,
    ) -> diesel::deserialize::Result<Self> {
        let s = <String as diesel::deserialize::FromSql<
            diesel::sql_types::Varchar,
            diesel::pg::Pg,
        >>::from_sql(bytes)?;
        // The DB CHECK constraint guarantees `s` matches one of the 7
        // canonical values; an Err here means schema drift and we
        // bubble it up rather than silently coerce to `Ssh`.
        Self::parse(&s).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }
}

/// Asset status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetStatus {
    Online,
    Offline,
    Maintenance,
    Unknown,
}

impl AssetStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Offline => "offline",
            Self::Maintenance => "maintenance",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "online" => Self::Online,
            "offline" => Self::Offline,
            "maintenance" => Self::Maintenance,
            _ => Self::Unknown,
        }
    }

    /// Strict parse for WRITE paths: `None` for anything outside the
    /// closed vocabulary. The lenient [`Self::parse`] fallback to
    /// `Unknown` is display-only; persisting through it would launder
    /// arbitrary strings into the `assets.status` column (now fenced
    /// by the `assets_status_chk` DB constraint).
    pub fn parse_strict(s: &str) -> Option<Self> {
        match s {
            "online" => Some(Self::Online),
            "offline" => Some(Self::Offline),
            "maintenance" => Some(Self::Maintenance),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }

    /// Display label for the status filter selects.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Online => "Online",
            Self::Offline => "Offline",
            Self::Maintenance => "Maintenance",
            Self::Unknown => "Unknown",
        }
    }

    /// Every status, in select-option order. Exhaustiveness is pinned
    /// by [`tests::test_filter_options_cover_every_status`].
    pub const ALL: &'static [Self] = &[
        Self::Online,
        Self::Offline,
        Self::Maintenance,
        Self::Unknown,
    ];

    /// `(value, label)` couples for the `/assets` and `/assets/manage`
    /// status filter selects. Single source of truth: covers the FULL
    /// closed vocabulary (including `unknown`, which the create/edit
    /// forms can assign) so no asset state is unfilterable.
    #[must_use]
    pub fn filter_options() -> Vec<(String, String)> {
        Self::ALL
            .iter()
            .map(|s| (s.as_str().to_string(), s.label().to_string()))
            .collect()
    }
}

/// Asset database model.
#[derive(Debug, Clone, Queryable, Selectable, Identifiable, Serialize)]
#[diesel(table_name = assets)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Asset {
    pub id: i32,
    pub uuid: Uuid,
    pub name: String,
    pub hostname: String,
    pub port: i32,
    pub asset_type: AssetType,
    pub status: String,
    pub description: Option<String>,
    pub connection_config: serde_json::Value,
    pub created_by_id: Option<i32>,
    pub updated_by_id: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_deleted: bool,
    pub deleted_at: Option<DateTime<Utc>>,
    pub connection_username: String,
}

/// New asset for insertion.
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = assets)]
pub struct NewAsset {
    pub uuid: Uuid,
    pub name: String,
    pub hostname: String,
    pub port: i32,
    pub asset_type: AssetType,
    pub status: String,
    pub description: Option<String>,
    pub connection_config: serde_json::Value,
    pub created_by_id: Option<i32>,
    pub updated_by_id: Option<i32>,
    pub connection_username: String,
}

/// Row in `asset_asset_groups` (many-to-many).
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = asset_asset_groups)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AssetAssetGroup {
    pub asset_id: i32,
    pub asset_group_id: i32,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = asset_asset_groups)]
pub struct NewAssetAssetGroup {
    pub asset_id: i32,
    pub asset_group_id: i32,
}

/// Asset group database model.
#[derive(Debug, Clone, Queryable, Selectable, Identifiable, Serialize)]
#[diesel(table_name = asset_groups)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AssetGroup {
    pub id: i32,
    pub uuid: Uuid,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub color: String,
    pub icon: String,
    pub parent_id: Option<i32>,
    pub created_by_id: Option<i32>,
    pub updated_by_id: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_deleted: bool,
    pub deleted_at: Option<DateTime<Utc>>,
    /// Discriminator for ordinary user-managed groups (`"static"`) vs.
    /// system-managed virtual groups (`"all"` and any future variant).
    /// See [`shared::messages::ALL_ASSETS_GROUP_UUID`] and the
    /// `20260424000000_virtual_asset_group_all` migration.
    pub kind: String,
}

impl Asset {
    /// Get status enum.
    pub fn status_enum(&self) -> AssetStatus {
        AssetStatus::parse(&self.status)
    }

    /// Get connection string.
    pub fn connection_string(&self) -> String {
        format!(
            "{}@{}:{}",
            self.connection_username, self.hostname, self.port
        )
    }
}

/// Asset creation request.
#[derive(Debug, Clone, Deserialize, validator::Validate)]
pub struct CreateAssetRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    #[validate(length(min = 1, max = 255))]
    pub hostname: String,
    #[validate(range(min = 1, max = 65535))]
    pub port: Option<i32>,
    pub asset_type: AssetType,
    /// Legacy single group (use `group_ids` when assigning multiple).
    #[serde(default)]
    pub group_id: Option<i32>,
    /// Asset group IDs to link after creation.
    #[serde(default)]
    pub group_ids: Vec<i32>,
    pub description: Option<String>,
}

/// Asset update request.
///
/// Supports flexible deserialization for HTML form submissions where
/// numbers are sent as strings and checkboxes send "on" or are absent.
#[derive(Debug, Clone, Deserialize, validator::Validate)]
pub struct UpdateAssetRequest {
    #[validate(length(max = 100))]
    pub name: Option<String>,
    #[validate(length(max = 255))]
    pub hostname: Option<String>,
    #[validate(range(min = 1, max = 65535))]
    #[serde(default, deserialize_with = "deserialize_optional_i32")]
    pub port: Option<i32>,
    pub status: Option<String>,
    pub description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test asset
    fn create_test_asset() -> Asset {
        Asset {
            id: 1,
            uuid: Uuid::new_v4(),
            name: "Test Server".to_string(),
            hostname: "test.example.com".to_string(),
            port: 22,
            asset_type: AssetType::Ssh,
            status: "online".to_string(),
            description: Some("A test server".to_string()),
            connection_config: serde_json::json!({}),
            created_by_id: None,
            updated_by_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_deleted: false,
            deleted_at: None,
            connection_username: "root".to_string(),
        }
    }

    // ==================== AssetType Tests ====================

    #[test]
    fn test_asset_type_from_str_ssh() {
        assert_eq!(AssetType::parse("ssh"), Ok(AssetType::Ssh));
    }

    #[test]
    fn test_asset_type_from_str_rdp() {
        assert_eq!(AssetType::parse("rdp"), Ok(AssetType::Rdp));
    }

    #[test]
    fn test_asset_type_parse_strict_rejects_unknown() {
        // Strict parse: NEVER falls back to SSH.
        assert!(AssetType::parse("unknown").is_err());
        assert!(AssetType::parse("").is_err());
        assert!(AssetType::parse("SSH").is_err()); // case-sensitive
        assert!(AssetType::parse("iacs").is_err()); // family name alone
    }

    #[test]
    fn test_asset_type_parse_or_ssh_legacy_fallback() {
        assert_eq!(AssetType::parse_or_ssh("unknown"), AssetType::Ssh);
        assert_eq!(AssetType::parse_or_ssh("rdp"), AssetType::Rdp);
        assert_eq!(
            AssetType::parse_or_ssh("iacs_modbus"),
            AssetType::IacsModbus
        );
    }

    #[test]
    fn test_asset_type_as_str() {
        assert_eq!(AssetType::Ssh.as_str(), "ssh");
        assert_eq!(AssetType::Rdp.as_str(), "rdp");
        assert_eq!(AssetType::IacsModbus.as_str(), "iacs_modbus");
        assert_eq!(AssetType::IacsOpcua.as_str(), "iacs_opcua");
        assert_eq!(AssetType::IacsProfinet.as_str(), "iacs_profinet");
        assert_eq!(AssetType::IacsIec104.as_str(), "iacs_iec104");
        assert_eq!(AssetType::IacsTcp.as_str(), "iacs_tcp");
    }

    #[test]
    fn test_format_access_rule_protocol() {
        assert_eq!(AssetType::format_access_rule_protocol("ssh"), "SSH");
        assert_eq!(AssetType::format_access_rule_protocol("rdp"), "RDP");
        assert_eq!(
            AssetType::format_access_rule_protocol("iacs_modbus"),
            "Modbus"
        );
        assert_eq!(
            AssetType::format_access_rule_protocol("iacs_opcua"),
            "OPC UA"
        );
        assert_eq!(
            AssetType::format_access_rule_protocol("iacs_profinet"),
            "PROFINET"
        );
        assert_eq!(
            AssetType::format_access_rule_protocol("iacs_iec104"),
            "IEC-104"
        );
        assert_eq!(
            AssetType::format_access_rule_protocol("iacs_tcp"),
            "IACS (TCP)"
        );
        assert_eq!(AssetType::format_access_rule_protocol("weird"), "WEIRD");
    }

    #[test]
    fn test_asset_type_default_port_ssh() {
        assert_eq!(AssetType::Ssh.default_port(), Some(22));
    }

    #[test]
    fn test_asset_type_default_port_rdp() {
        assert_eq!(AssetType::Rdp.default_port(), Some(3389));
    }

    #[test]
    fn test_asset_type_default_port_iacs_known_protocols() {
        assert_eq!(AssetType::IacsModbus.default_port(), Some(502));
        assert_eq!(AssetType::IacsOpcua.default_port(), Some(4840));
        assert_eq!(AssetType::IacsProfinet.default_port(), Some(34962));
        assert_eq!(AssetType::IacsIec104.default_port(), Some(2404));
    }

    #[test]
    fn test_asset_type_default_port_iacs_tcp_is_none() {
        assert_eq!(
            AssetType::IacsTcp.default_port(),
            None,
            "the catch-all has no default; the operator must enter a port explicitly"
        );
    }

    #[test]
    fn test_asset_type_roundtrip_all_variants() {
        for asset_type in AssetType::ALL {
            let str_val = asset_type.as_str();
            let parsed = unwrap_ok!(AssetType::parse(str_val));
            assert_eq!(*asset_type, parsed);
        }
    }

    #[test]
    fn test_asset_type_is_iacs() {
        assert!(!AssetType::Ssh.is_iacs());
        assert!(!AssetType::Rdp.is_iacs());
        assert!(AssetType::IacsModbus.is_iacs());
        assert!(AssetType::IacsOpcua.is_iacs());
        assert!(AssetType::IacsProfinet.is_iacs());
        assert!(AssetType::IacsIec104.is_iacs());
        assert!(AssetType::IacsTcp.is_iacs());
    }

    #[test]
    fn test_asset_type_is_it_disjoint_from_iacs() {
        for variant in AssetType::ALL {
            assert_ne!(
                variant.is_iacs(),
                variant.is_it(),
                "is_iacs() and is_it() must partition the enum (variant: {:?})",
                variant
            );
        }
    }

    #[test]
    fn test_asset_type_family() {
        assert_eq!(AssetType::Ssh.family(), AssetFamily::It);
        assert_eq!(AssetType::Rdp.family(), AssetFamily::It);
        assert_eq!(AssetType::IacsTcp.family(), AssetFamily::Iacs);
    }

    #[test]
    fn test_asset_type_iacs_protocol() {
        assert_eq!(AssetType::Ssh.iacs_protocol(), None);
        assert_eq!(AssetType::Rdp.iacs_protocol(), None);
        assert_eq!(
            AssetType::IacsModbus.iacs_protocol(),
            Some(IacsProtocol::Modbus)
        );
        assert_eq!(
            AssetType::IacsOpcua.iacs_protocol(),
            Some(IacsProtocol::OpcUa)
        );
        assert_eq!(
            AssetType::IacsProfinet.iacs_protocol(),
            Some(IacsProtocol::Profinet)
        );
        assert_eq!(
            AssetType::IacsIec104.iacs_protocol(),
            Some(IacsProtocol::Iec104)
        );
        assert_eq!(AssetType::IacsTcp.iacs_protocol(), Some(IacsProtocol::Tcp));
    }

    #[test]
    fn test_iacs_protocol_as_str_and_display() {
        assert_eq!(IacsProtocol::Modbus.as_str(), "modbus");
        assert_eq!(IacsProtocol::OpcUa.as_str(), "opcua");
        assert_eq!(IacsProtocol::Profinet.as_str(), "profinet");
        assert_eq!(IacsProtocol::Iec104.as_str(), "iec104");
        assert_eq!(IacsProtocol::Tcp.as_str(), "tcp");
        assert_eq!(format!("{}", IacsProtocol::Modbus), "modbus");
    }

    #[test]
    fn test_asset_type_label_present_for_every_variant() {
        for variant in AssetType::ALL {
            let label = variant.label();
            assert!(!label.is_empty(), "label must be set for {:?}", variant);
        }
    }

    /// `badge_label` MUST stay short enough to fit the fixed-width
    /// (`h-10 w-10` = 40 px) square asset-type tile on the detail
    /// page. The pre-fix `IACS_MODBUS` (11 chars) overflowed and
    /// crashed into the asset name title (operator-reported
    /// 2026-05-08). 4 chars at `text-xs font-bold` fits comfortably
    /// in the tile; we cap at 3 with `104` as the longest entry to
    /// leave a safety margin for the future.
    #[test]
    fn test_asset_type_badge_label_fits_the_square_tile() {
        for variant in AssetType::ALL {
            let badge = variant.badge_label();
            assert!(
                !badge.is_empty(),
                "badge_label must be set for {:?}",
                variant
            );
            assert!(
                badge.len() <= 3,
                "badge_label '{}' for {:?} is too long for the h-10 w-10 tile (max 3 chars)",
                badge,
                variant
            );
            assert!(
                badge.chars().all(|c| c.is_ascii() && !c.is_whitespace()),
                "badge_label '{}' for {:?} must be ASCII without whitespace",
                badge,
                variant
            );
        }
    }

    /// Pin the exact mapping so a future maintainer cannot silently
    /// rename "MB" -> "MOD" or "104" -> "IEC" without touching this
    /// test. The wire-form labels show up in the rendered HTML and
    /// in operator screenshots; a drift would surprise people.
    #[test]
    fn test_asset_type_badge_label_canonical_mapping() {
        assert_eq!(AssetType::Ssh.badge_label(), "SSH");
        assert_eq!(AssetType::Rdp.badge_label(), "RDP");
        assert_eq!(AssetType::IacsModbus.badge_label(), "MB");
        assert_eq!(AssetType::IacsOpcua.badge_label(), "OPC");
        assert_eq!(AssetType::IacsProfinet.badge_label(), "PN");
        assert_eq!(AssetType::IacsIec104.badge_label(), "104");
        assert_eq!(AssetType::IacsTcp.badge_label(), "TCP");
    }

    /// Operator-reported 2026-05-08: the IACS-TCP variant must
    /// render as "Generic TCP" with a capital G, not "generic TCP".
    /// Pin both the exact label and the case so a future maintainer
    /// cannot silently regress to lowercase.
    #[test]
    fn test_iacs_tcp_label_is_capitalised() {
        assert_eq!(AssetType::IacsTcp.label(), "IACS - Generic TCP");
        assert!(
            !AssetType::IacsTcp.label().contains("generic"),
            "label must use 'Generic' (capital G), not 'generic'"
        );
    }

    /// `filter_options` must surface the synthetic `iacs` filter
    /// row right after the seven concrete variants returned by
    /// `select_options` when `industrial_enabled = true`. Pinned so
    /// the dropdown order stays predictable and the create-form path
    /// NEVER inherits the synthetic row by mistake.
    #[test]
    fn test_filter_options_carries_synthetic_iacs_all() {
        let opts = AssetType::filter_options(true);
        assert_eq!(
            opts.len(),
            AssetType::ALL.len() + 1,
            "filter_options = select_options + 1 synthetic 'iacs' entry"
        );
        let last = opts.last().unwrap();
        assert_eq!(last.0, IACS_ALL_FILTER_TOKEN);
        assert_eq!(last.1, "IACS - All Industrial Protocols");
        // First N rows must match select_options (no reordering).
        for (i, sel) in AssetType::select_options(true).iter().enumerate() {
            assert_eq!(
                &opts[i], sel,
                "filter_options must keep select_options order at index {i}"
            );
        }
    }

    /// `select_options` MUST NOT carry the synthetic IACS filter
    /// token: persistence paths (create/edit forms) would then
    /// submit `asset_type='iacs'` and the DB
    /// `assets_asset_type_chk` CHECK constraint would refuse it.
    #[test]
    fn test_select_options_does_not_carry_synthetic_iacs_filter() {
        let opts = AssetType::select_options(true);
        assert!(
            !opts.iter().any(|(v, _)| v == IACS_ALL_FILTER_TOKEN),
            "select_options must not expose the synthetic 'iacs' filter token; \
             it would land on the create/edit form and violate the DB CHECK"
        );
    }

    /// Industrial kill-switch: `select_options(false)` MUST drop
    /// every `iacs_*` variant so the create / edit `<select>` does
    /// not surface IACS protocols while `industrial.enabled = false`.
    /// Mirrors the four-layer defense documented in the
    /// `industrial gate hide iacs surface` plan.
    #[test]
    fn test_select_options_filters_iacs_when_industrial_disabled() {
        let opts = AssetType::select_options(false);
        assert!(
            !opts.iter().any(|(v, _)| v.starts_with("iacs_")),
            "select_options(false) must NOT expose any iacs_* variant; got {opts:?}"
        );
        let opts_on = AssetType::select_options(true);
        assert!(
            opts_on.iter().any(|(v, _)| v == "iacs_modbus"),
            "select_options(true) must keep the legacy seven entries (regression guard)"
        );
        assert_eq!(
            opts.len() + AssetType::iacs_variants().len(),
            opts_on.len(),
            "select_options(false) drops exactly the iacs_* variants and nothing else"
        );
    }

    /// Industrial kill-switch: `filter_options(false)` MUST drop both
    /// every `iacs_*` variant AND the synthetic `iacs` token, so the
    /// /assets and /assets/manage filter dropdowns reveal nothing of
    /// the industrial surface while the master switch is off.
    #[test]
    fn test_filter_options_filters_iacs_when_industrial_disabled() {
        let opts = AssetType::filter_options(false);
        assert!(
            !opts.iter().any(|(v, _)| v.starts_with("iacs_")),
            "filter_options(false) must NOT expose any iacs_* variant; got {opts:?}"
        );
        assert!(
            !opts.iter().any(|(v, _)| v == IACS_ALL_FILTER_TOKEN),
            "filter_options(false) must NOT expose the synthetic 'iacs' all-industrial token"
        );
    }

    #[test]
    fn test_parse_filter_routes_token_correctly() {
        assert_eq!(
            AssetType::parse_filter("ssh"),
            AssetTypeFilter::One(AssetType::Ssh)
        );
        assert_eq!(
            AssetType::parse_filter("iacs_modbus"),
            AssetTypeFilter::One(AssetType::IacsModbus)
        );
        assert_eq!(
            AssetType::parse_filter(IACS_ALL_FILTER_TOKEN),
            AssetTypeFilter::IacsAll
        );
        assert_eq!(AssetType::parse_filter("garbage"), AssetTypeFilter::Unknown);
        assert_eq!(AssetType::parse_filter(""), AssetTypeFilter::Unknown);
    }

    #[test]
    fn test_iacs_variants_covers_every_iacs_member() {
        let v = AssetType::iacs_variants();
        assert_eq!(v.len(), 5);
        for variant in v {
            assert!(
                variant.is_iacs(),
                "iacs_variants() must only return is_iacs() variants"
            );
        }
        for variant in AssetType::ALL {
            if variant.is_iacs() {
                assert!(
                    AssetType::iacs_variants().contains(variant),
                    "iacs_variants() must include {:?}",
                    variant
                );
            }
        }
    }

    #[test]
    fn iacs_select_options_lists_only_iacs_variants() {
        let opts = AssetType::iacs_select_options();
        assert_eq!(opts.len(), AssetType::iacs_variants().len());
        for (value, _label) in &opts {
            let parsed = AssetType::parse(value).expect("iacs_select_options values must parse");
            assert!(
                parsed.is_iacs(),
                "iacs_select_options must only expose IACS variants"
            );
        }
        assert!(!opts.iter().any(|(v, _)| v == "ssh" || v == "rdp"));
    }

    #[test]
    fn resolve_edit_asset_type_allows_iacs_to_iacs_switch() {
        let updated = AssetType::resolve_edit_asset_type(AssetType::IacsModbus, Some("iacs_opcua"))
            .expect("modbus -> opcua");
        assert_eq!(updated, AssetType::IacsOpcua);
    }

    #[test]
    fn resolve_edit_asset_type_rejects_iacs_to_ssh() {
        assert_eq!(
            AssetType::resolve_edit_asset_type(AssetType::IacsModbus, Some("ssh")),
            Err(AssetTypeEditError::IacsToNonIacs)
        );
    }

    #[test]
    fn resolve_edit_asset_type_rejects_it_protocol_change() {
        assert_eq!(
            AssetType::resolve_edit_asset_type(AssetType::Ssh, Some("rdp")),
            Err(AssetTypeEditError::ProtocolImmutable)
        );
    }

    #[test]
    fn resolve_edit_asset_type_ignores_missing_submission_for_it_assets() {
        assert_eq!(
            AssetType::resolve_edit_asset_type(AssetType::Ssh, None).expect("unchanged"),
            AssetType::Ssh
        );
    }

    #[test]
    fn test_asset_type_all_is_exhaustive() {
        // If a new variant is added without updating ALL, this will
        // fail at compile time on the match below (exhaustiveness
        // check via `_` arm intentionally absent).
        for variant in AssetType::ALL {
            match *variant {
                AssetType::Ssh
                | AssetType::Rdp
                | AssetType::IacsModbus
                | AssetType::IacsOpcua
                | AssetType::IacsProfinet
                | AssetType::IacsIec104
                | AssetType::IacsTcp => {}
            }
        }
        assert_eq!(
            AssetType::ALL.len(),
            7,
            "ALL must list exactly 7 canonical variants"
        );
    }

    // ==================== AssetStatus Tests ====================

    #[test]
    fn test_asset_status_from_str_online() {
        assert_eq!(AssetStatus::parse("online"), AssetStatus::Online);
    }

    #[test]
    fn test_asset_status_from_str_offline() {
        assert_eq!(AssetStatus::parse("offline"), AssetStatus::Offline);
    }

    #[test]
    fn test_asset_status_from_str_maintenance() {
        assert_eq!(AssetStatus::parse("maintenance"), AssetStatus::Maintenance);
    }

    #[test]
    fn test_asset_status_from_str_unknown() {
        assert_eq!(AssetStatus::parse("unknown"), AssetStatus::Unknown);
        assert_eq!(AssetStatus::parse("invalid"), AssetStatus::Unknown);
        assert_eq!(AssetStatus::parse(""), AssetStatus::Unknown);
    }

    #[test]
    fn test_asset_status_as_str() {
        assert_eq!(AssetStatus::Online.as_str(), "online");
        assert_eq!(AssetStatus::Offline.as_str(), "offline");
        assert_eq!(AssetStatus::Maintenance.as_str(), "maintenance");
        assert_eq!(AssetStatus::Unknown.as_str(), "unknown");
    }

    #[test]
    fn test_asset_status_roundtrip() {
        for status in [
            AssetStatus::Online,
            AssetStatus::Offline,
            AssetStatus::Maintenance,
            AssetStatus::Unknown,
        ] {
            let str_val = status.as_str();
            let parsed = AssetStatus::parse(str_val);
            assert_eq!(status, parsed);
        }
    }

    // ==================== Asset Method Tests ====================

    #[test]
    fn test_asset_type_field_is_enum() {
        let asset = create_test_asset();
        assert_eq!(asset.asset_type, AssetType::Ssh);
    }

    #[test]
    fn test_asset_status_enum() {
        let asset = create_test_asset();
        assert_eq!(asset.status_enum(), AssetStatus::Online);
    }

    #[test]
    fn test_asset_connection_string() {
        let asset = create_test_asset();
        assert_eq!(asset.connection_string(), "root@test.example.com:22");
    }

    #[test]
    fn test_asset_connection_string_different_port() {
        let mut asset = create_test_asset();
        asset.port = 2222;
        asset.hostname = "server.local".to_string();
        asset.connection_username = "deploy".to_string();
        assert_eq!(asset.connection_string(), "deploy@server.local:2222");
    }

    // ==================== Validation Tests ====================

    #[test]
    fn test_create_asset_request_validation_valid() {
        use validator::Validate;

        let request = CreateAssetRequest {
            name: "My Server".to_string(),
            hostname: "server.example.com".to_string(),
            port: Some(22),
            asset_type: AssetType::Ssh,
            group_id: None,
            group_ids: vec![],
            description: None,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_asset_request_validation_empty_name() {
        use validator::Validate;

        let request = CreateAssetRequest {
            name: "".to_string(), // Empty name (min 1)
            hostname: "server.example.com".to_string(),
            port: None,
            asset_type: AssetType::Ssh,
            group_id: None,
            group_ids: vec![],
            description: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_create_asset_request_validation_invalid_port() {
        use validator::Validate;

        let request = CreateAssetRequest {
            name: "My Server".to_string(),
            hostname: "server.example.com".to_string(),
            port: Some(70000), // Invalid port (max 65535)
            asset_type: AssetType::Ssh,
            group_id: None,
            group_ids: vec![],
            description: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_create_asset_request_validation_port_zero() {
        use validator::Validate;

        let request = CreateAssetRequest {
            name: "My Server".to_string(),
            hostname: "server.example.com".to_string(),
            port: Some(0), // Invalid port (min 1)
            asset_type: AssetType::Ssh,
            group_id: None,
            group_ids: vec![],
            description: None,
        };

        assert!(request.validate().is_err());
    }

    // ==================== AssetType Additional Tests ====================

    #[test]
    fn test_asset_type_debug() {
        let asset_type = AssetType::Ssh;
        let debug_str = format!("{:?}", asset_type);
        assert!(debug_str.contains("Ssh"));
    }

    #[test]
    fn test_asset_type_clone() {
        let asset_type = AssetType::Rdp;
        let cloned = asset_type;
        assert_eq!(asset_type, cloned);
    }

    #[test]
    fn test_asset_type_copy() {
        let asset_type = AssetType::Rdp;
        let copied = asset_type;
        assert_eq!(asset_type, copied);
    }

    #[test]
    fn test_asset_type_serialize() {
        let asset_type = AssetType::Ssh;
        let json = unwrap_ok!(serde_json::to_string(&asset_type));
        assert!(json.contains("ssh"));
    }

    #[test]
    fn test_asset_type_deserialize() {
        let json = r#""rdp""#;
        let asset_type: AssetType = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(asset_type, AssetType::Rdp);
    }

    #[test]
    fn test_asset_type_display() {
        assert_eq!(AssetType::Ssh.to_string(), "ssh");
        assert_eq!(AssetType::Rdp.to_string(), "rdp");
    }

    // ==================== AssetStatus Additional Tests ====================

    #[test]
    fn test_asset_status_debug() {
        let status = AssetStatus::Online;
        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("Online"));
    }

    #[test]
    fn test_asset_status_clone() {
        let status = AssetStatus::Offline;
        let cloned = status;
        assert_eq!(status, cloned);
    }

    #[test]
    fn test_asset_status_copy() {
        let status = AssetStatus::Maintenance;
        let copied = status;
        assert_eq!(status, copied);
    }

    #[test]
    fn test_asset_status_serialize() {
        let status = AssetStatus::Unknown;
        let json = unwrap_ok!(serde_json::to_string(&status));
        assert!(json.contains("Unknown"));
    }

    // ==================== Asset Additional Tests ====================

    #[test]
    fn test_asset_clone() {
        let asset = create_test_asset();
        let cloned = asset.clone();
        assert_eq!(asset.uuid, cloned.uuid);
        assert_eq!(asset.name, cloned.name);
    }

    #[test]
    fn test_asset_debug() {
        let asset = create_test_asset();
        let debug_str = format!("{:?}", asset);
        assert!(debug_str.contains("Asset"));
        assert!(debug_str.contains("Test Server"));
    }

    #[test]
    fn test_asset_serialize() {
        let asset = create_test_asset();
        let json = unwrap_ok!(serde_json::to_string(&asset));
        assert!(json.contains("Test Server"));
    }

    #[test]
    fn test_asset_type_field_rdp() {
        let mut asset = create_test_asset();
        asset.asset_type = AssetType::Rdp;
        assert_eq!(asset.asset_type, AssetType::Rdp);
    }

    #[test]
    fn test_asset_status_enum_offline() {
        let mut asset = create_test_asset();
        asset.status = "offline".to_string();
        assert_eq!(asset.status_enum(), AssetStatus::Offline);
    }

    #[test]
    fn test_asset_status_enum_maintenance() {
        let mut asset = create_test_asset();
        asset.status = "maintenance".to_string();
        assert_eq!(asset.status_enum(), AssetStatus::Maintenance);
    }

    // ==================== NewAsset Tests ====================

    #[test]
    fn test_new_asset_debug() {
        let new_asset = NewAsset {
            uuid: Uuid::new_v4(),
            name: "New Asset".to_string(),
            hostname: "new.example.com".to_string(),
            port: 22,
            asset_type: AssetType::Ssh,
            status: "unknown".to_string(),
            description: None,
            connection_config: serde_json::json!({}),
            created_by_id: None,
            updated_by_id: None,
            connection_username: "root".to_string(),
        };

        let debug_str = format!("{:?}", new_asset);
        assert!(debug_str.contains("NewAsset"));
    }

    #[test]
    fn test_new_asset_clone() {
        let new_asset = NewAsset {
            uuid: Uuid::new_v4(),
            name: "Clone Asset".to_string(),
            hostname: "clone.example.com".to_string(),
            port: 3389,
            asset_type: AssetType::Rdp,
            status: "online".to_string(),
            description: Some("A cloned asset".to_string()),
            connection_config: serde_json::json!({"key": "value"}),
            created_by_id: Some(1),
            updated_by_id: Some(1),
            connection_username: "Administrator".to_string(),
        };

        let cloned = new_asset.clone();
        assert_eq!(new_asset.name, cloned.name);
    }

    // ==================== AssetGroup Tests ====================

    #[test]
    fn test_asset_group_debug() {
        let group = AssetGroup {
            id: 1,
            uuid: Uuid::new_v4(),
            name: "Test Group".to_string(),
            slug: "test-group".to_string(),
            description: Some("A test group".to_string()),
            color: "#FF0000".to_string(),
            icon: "folder".to_string(),
            parent_id: None,
            created_by_id: None,
            updated_by_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_deleted: false,
            deleted_at: None,
            kind: "static".to_string(),
        };

        let debug_str = format!("{:?}", group);
        assert!(debug_str.contains("AssetGroup"));
    }

    #[test]
    fn test_asset_group_clone() {
        let group = AssetGroup {
            id: 1,
            uuid: Uuid::new_v4(),
            name: "Clone Group".to_string(),
            slug: "clone-group".to_string(),
            description: None,
            color: "#00FF00".to_string(),
            icon: "server".to_string(),
            parent_id: Some(2),
            created_by_id: Some(1),
            updated_by_id: Some(1),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_deleted: false,
            deleted_at: None,
            kind: "static".to_string(),
        };

        let cloned = group.clone();
        assert_eq!(group.name, cloned.name);
    }

    #[test]
    fn test_asset_group_serialize() {
        let group = AssetGroup {
            id: 1,
            uuid: Uuid::new_v4(),
            name: "Serialize Group".to_string(),
            slug: "serialize-group".to_string(),
            description: None,
            color: "#0000FF".to_string(),
            icon: "database".to_string(),
            parent_id: None,
            created_by_id: None,
            updated_by_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_deleted: false,
            deleted_at: None,
            kind: "static".to_string(),
        };

        let json = unwrap_ok!(serde_json::to_string(&group));
        assert!(json.contains("Serialize Group"));
    }

    // ==================== CreateAssetRequest Additional Tests ====================

    #[test]
    fn test_create_asset_request_debug() {
        let request = CreateAssetRequest {
            name: "Debug Server".to_string(),
            hostname: "debug.example.com".to_string(),
            port: None,
            asset_type: AssetType::Ssh,
            group_id: None,
            group_ids: vec![],
            description: None,
        };

        let debug_str = format!("{:?}", request);
        assert!(debug_str.contains("CreateAssetRequest"));
    }

    #[test]
    fn test_create_asset_request_clone() {
        let request = CreateAssetRequest {
            name: "Clone Server".to_string(),
            hostname: "clone.example.com".to_string(),
            port: Some(22),
            asset_type: AssetType::Ssh,
            group_id: Some(1),
            group_ids: vec![],
            description: Some("Cloned".to_string()),
        };

        let cloned = request.clone();
        assert_eq!(request.name, cloned.name);
    }

    #[test]
    fn test_create_asset_request_long_name_invalid() {
        use validator::Validate;

        let request = CreateAssetRequest {
            name: "A".repeat(101), // Too long
            hostname: "server.example.com".to_string(),
            port: None,
            asset_type: AssetType::Ssh,
            group_id: None,
            group_ids: vec![],
            description: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_create_asset_request_long_hostname_invalid() {
        use validator::Validate;

        let request = CreateAssetRequest {
            name: "Server".to_string(),
            hostname: "a".repeat(256), // Too long
            port: None,
            asset_type: AssetType::Ssh,
            group_id: None,
            group_ids: vec![],
            description: None,
        };

        assert!(request.validate().is_err());
    }

    // ==================== UpdateAssetRequest Tests ====================

    #[test]
    fn test_update_asset_request_debug() {
        let request = UpdateAssetRequest {
            name: Some("Updated".to_string()),
            hostname: None,
            port: None,
            status: None,
            description: None,
        };

        let debug_str = format!("{:?}", request);
        assert!(debug_str.contains("UpdateAssetRequest"));
    }

    #[test]
    fn test_update_asset_request_clone() {
        let request = UpdateAssetRequest {
            name: Some("Clone".to_string()),
            hostname: Some("clone.example.com".to_string()),
            port: Some(2222),
            status: Some("maintenance".to_string()),
            description: Some("Updated description".to_string()),
        };

        let cloned = request.clone();
        assert_eq!(request.name, cloned.name);
    }

    // ==================== Flexible Deserialization Tests ====================

    #[test]
    fn test_update_asset_request_port_as_string() {
        let json = r#"{"port": "22"}"#;
        let request: UpdateAssetRequest = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(request.port, Some(22));
    }

    #[test]
    fn test_update_asset_request_port_as_integer() {
        let json = r#"{"port": 22}"#;
        let request: UpdateAssetRequest = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(request.port, Some(22));
    }

    #[test]
    fn test_update_asset_request_port_empty_string() {
        let json = r#"{"port": ""}"#;
        let request: UpdateAssetRequest = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(request.port, None);
    }

    #[test]
    fn test_update_asset_request_port_null() {
        let json = r#"{"port": null}"#;
        let request: UpdateAssetRequest = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(request.port, None);
    }

    #[test]
    fn test_update_asset_request_form_like_json() {
        let json = r#"{
            "name": "test-server",
            "hostname": "test.example.com",
            "port": "22",
            "status": "online",
            "description": "Test server"
        }"#;
        let request: UpdateAssetRequest = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(request.name, Some("test-server".to_string()));
        assert_eq!(request.port, Some(22));
    }

    // ==================== deserialize_optional_i32 Tests ====================

    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct OptI32Wrapper {
        #[serde(default, deserialize_with = "deserialize_optional_i32")]
        value: Option<i32>,
    }

    #[test]
    fn test_deserialize_optional_i32_from_integer() {
        let json = r#"{"value": 42}"#;
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(w.value, Some(42));
    }

    #[test]
    fn test_deserialize_optional_i32_from_string_number() {
        let json = r#"{"value": "99"}"#;
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(w.value, Some(99));
    }

    #[test]
    fn test_deserialize_optional_i32_from_empty_string() {
        let json = r#"{"value": ""}"#;
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(w.value, None);
    }

    #[test]
    fn test_deserialize_optional_i32_from_null() {
        let json = r#"{"value": null}"#;
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(w.value, None);
    }

    #[test]
    fn test_deserialize_optional_i32_missing_field() {
        let json = r#"{}"#;
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(w.value, None);
    }

    #[test]
    fn test_deserialize_optional_i32_negative() {
        let json = r#"{"value": -5}"#;
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(w.value, Some(-5));
    }

    #[test]
    fn test_deserialize_optional_i32_negative_string() {
        let json = r#"{"value": "-10"}"#;
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(w.value, Some(-10));
    }

    #[test]
    fn test_deserialize_optional_i32_zero() {
        let json = r#"{"value": 0}"#;
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(w.value, Some(0));
    }

    #[test]
    fn test_deserialize_optional_i32_zero_string() {
        let json = r#"{"value": "0"}"#;
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(w.value, Some(0));
    }

    #[test]
    fn test_deserialize_optional_i32_invalid_string_fails() {
        let json = r#"{"value": "abc"}"#;
        let result: Result<OptI32Wrapper, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_optional_i32_float_string_fails() {
        let json = r#"{"value": "3.14"}"#;
        let result: Result<OptI32Wrapper, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_optional_i32_whitespace_only_fails() {
        let json = r#"{"value": "  "}"#;
        let result: Result<OptI32Wrapper, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_optional_i32_max_value() {
        let json = format!(r#"{{"value": {}}}"#, i32::MAX);
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(&json));
        assert_eq!(w.value, Some(i32::MAX));
    }

    #[test]
    fn test_deserialize_optional_i32_min_value() {
        let json = format!(r#"{{"value": {}}}"#, i32::MIN);
        let w: OptI32Wrapper = unwrap_ok!(serde_json::from_str(&json));
        assert_eq!(w.value, Some(i32::MIN));
    }
}
