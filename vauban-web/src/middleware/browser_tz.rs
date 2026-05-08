/// VAUBAN Web - Browser timezone extractor.
///
/// Reads the `vbn_tz` cookie that
/// [`vauban-web/static/js/vbn-tz.js`](../../static/js/vbn-tz.js)
/// posts on every page load and resolves it into a typed
/// [`chrono_tz::Tz`]. Handlers receive a [`BrowserTz`] just like
/// any other Axum extractor; templates then render every
/// `DateTime<Utc>` through the
/// [`crate::utils::datetime_format`] helpers (filters
/// `|local` / `|local_seconds`) keyed on the extracted Tz.
///
/// # Contract
///
/// Layer 1 -- the wire (cookie):
/// - Cookie name: `vbn_tz`. URL-encoded IANA identifier
///   (e.g. `Europe%2FParis`).
/// - Whitelist: must round-trip through [`chrono_tz::Tz::from_str`].
///   Any value the IANA tzdb does not recognize is collapsed to UTC.
/// - Anti-injection: the value is rejected before parsing if it
///   exceeds 64 chars or contains characters outside
///   `[A-Za-z0-9_/+-]` (tzdb identifiers never contain `<`, `>`, `'`,
///   `"`, `;`, ...).
///
/// Layer 2 -- the extractor result:
/// - A valid IANA name yields the corresponding `Tz`.
/// - Anything else (cookie absent, invalid value, parse failure)
///   yields [`Tz::UTC`]. The extractor is **infallible**: a
///   handler can always rely on a `Tz` being present.
///
/// # Why an extractor (not a request-scoped middleware)
///
/// The decision is per-render, not per-request. A handler that
/// emits JSON does not care; a handler that renders an Askama
/// template needs the `Tz` to seed the filter. Centralizing the
/// cookie parsing in one type lets us pin the validation rules in
/// one place AND opt in/out per handler.
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chrono_tz::Tz;
use std::str::FromStr;

/// Maximum byte length of the `vbn_tz` cookie value AFTER URL-
/// decoding. The longest IANA identifier
/// (`America/Argentina/ComodRivadavia`) is 32 chars; we allow 64
/// to be future-proof while still cheap to validate.
pub const VBN_TZ_COOKIE_MAX_LEN: usize = 64;

/// Cookie name used to communicate the browser timezone to the
/// server. Centralized so the test suite, the JS bootstrap and
/// the extractor stay in lock-step.
pub const VBN_TZ_COOKIE_NAME: &str = "vbn_tz";

/// Browser timezone resolved from the `vbn_tz` cookie. Always
/// available (`Tz::UTC` if absent / invalid) so handlers never
/// need to handle the `None` branch explicitly.
#[derive(Debug, Clone, Copy)]
pub struct BrowserTz(pub Tz);

impl BrowserTz {
    /// Returns the underlying [`Tz`].
    pub fn tz(&self) -> Tz {
        self.0
    }

    /// Returns the IANA identifier (e.g. `"Europe/Paris"`).
    pub fn name(&self) -> &'static str {
        self.0.name()
    }
}

impl Default for BrowserTz {
    fn default() -> Self {
        Self(Tz::UTC)
    }
}

/// Parse a candidate IANA identifier from the raw cookie value.
///
/// Returns `Some(Tz)` iff:
///
/// 1. The value is at most [`VBN_TZ_COOKIE_MAX_LEN`] bytes long.
/// 2. Every byte matches `[A-Za-z0-9_/+-]`. Real IANA names cover
///    `Etc/GMT+5`, `America/Indiana/Knox`, `Antarctica/DumontDUrville`
///    -- all match.
/// 3. [`chrono_tz::Tz::from_str`] accepts the value.
///
/// All other inputs (including the empty string and any HTML / JS
/// injection probe) yield `None`. The caller treats `None` as
/// "fall back to UTC".
pub fn parse_browser_tz(raw: &str) -> Option<Tz> {
    if raw.is_empty() || raw.len() > VBN_TZ_COOKIE_MAX_LEN {
        return None;
    }
    let safe = raw
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'/' | b'+' | b'-'));
    if !safe {
        return None;
    }
    Tz::from_str(raw).ok()
}

impl<S> FromRequestParts<S> for BrowserTz
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let jar = axum_extra::extract::CookieJar::from_headers(&parts.headers);
        let tz = jar
            .get(VBN_TZ_COOKIE_NAME)
            .and_then(|c| parse_browser_tz(c.value()))
            .unwrap_or(Tz::UTC);
        Ok(BrowserTz(tz))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    /// `parse_browser_tz` accepts every common operator timezone.
    #[test]
    fn parse_accepts_common_iana_names() {
        for tz in [
            "UTC",
            "Europe/Paris",
            "Europe/London",
            "America/New_York",
            "America/Los_Angeles",
            "Asia/Calcutta",
            "Asia/Tokyo",
            "Australia/Sydney",
            "Pacific/Auckland",
        ] {
            assert!(
                parse_browser_tz(tz).is_some(),
                "valid IANA name `{}` must be accepted",
                tz
            );
        }
    }

    /// IANA includes the legacy `Etc/GMT+N` family which has a `+`
    /// in the identifier. The whitelist regex must not reject it.
    #[test]
    fn parse_accepts_etc_gmt_offset_names() {
        assert_eq!(parse_browser_tz("Etc/GMT+5").map(|t| t.name()), Some("Etc/GMT+5"));
        assert_eq!(parse_browser_tz("Etc/GMT-5").map(|t| t.name()), Some("Etc/GMT-5"));
        assert_eq!(parse_browser_tz("Etc/UTC").map(|t| t.name()), Some("Etc/UTC"));
    }

    /// Half-hour and 45-minute offsets must round-trip cleanly.
    /// Calcutta = UTC+5:30, Kathmandu = UTC+5:45, Eucla = UTC+8:45.
    #[test]
    fn parse_accepts_half_and_quarter_hour_offsets() {
        assert!(parse_browser_tz("Asia/Calcutta").is_some());
        assert!(parse_browser_tz("Asia/Kolkata").is_some());
        assert!(parse_browser_tz("Asia/Kathmandu").is_some());
        assert!(parse_browser_tz("Australia/Eucla").is_some());
    }

    /// Empty cookie value falls back to UTC at the call site.
    #[test]
    fn parse_rejects_empty_string() {
        assert_eq!(parse_browser_tz(""), None);
    }

    /// Anything that is not a known IANA name -- including
    /// well-formed but unknown strings -- is collapsed to `None`.
    #[test]
    fn parse_rejects_unknown_iana_name() {
        assert_eq!(parse_browser_tz("Foo/Bar"), None);
        assert_eq!(parse_browser_tz("Mars/Olympus_Mons"), None);
        assert_eq!(parse_browser_tz("UTC+2"), None);
    }

    /// XSS / injection probes are rejected by the whitelist regex
    /// before parse, defence-in-depth in case `chrono_tz::Tz::from_str`
    /// is ever loosened.
    #[test]
    fn parse_rejects_xss_probes() {
        for evil in [
            "<script>",
            "Europe/Paris;<script>",
            "Europe/Paris\"",
            "Europe/Paris'",
            "Europe/Paris \r\nSet-Cookie: foo",
            "Europe/Paris\0",
            "Europe/Paris\nfoo",
        ] {
            assert!(
                parse_browser_tz(evil).is_none(),
                "evil input `{}` must be rejected",
                evil.escape_debug()
            );
        }
    }

    /// Cookie value over 64 bytes is rejected before any parsing
    /// even if it would otherwise be a valid IANA name.
    #[test]
    fn parse_rejects_oversized_input() {
        let s = "A".repeat(VBN_TZ_COOKIE_MAX_LEN + 1);
        assert_eq!(parse_browser_tz(&s), None);
        // Boundary: 64 bytes still attempted, just unlikely to parse.
        let s = "A".repeat(VBN_TZ_COOKIE_MAX_LEN);
        assert_eq!(parse_browser_tz(&s), None);
    }

    /// Names containing whitespace, control chars, or the
    /// percent-encoding sentinel are rejected (the cookie reaches
    /// the extractor already URL-decoded).
    #[test]
    fn parse_rejects_special_chars() {
        assert_eq!(parse_browser_tz("Europe Paris"), None);
        assert_eq!(parse_browser_tz("Europe/%50aris"), None);
        assert_eq!(parse_browser_tz("Europe/Paris\t"), None);
    }

    /// Build a `BrowserTz` from a synthetic header map (mirrors the
    /// real extractor path: `CookieJar::from_headers`).
    fn extract(headers: &HeaderMap) -> BrowserTz {
        let jar = axum_extra::extract::CookieJar::from_headers(headers);
        let tz = jar
            .get(VBN_TZ_COOKIE_NAME)
            .and_then(|c| parse_browser_tz(c.value()))
            .unwrap_or(Tz::UTC);
        BrowserTz(tz)
    }

    #[test]
    fn extractor_falls_back_to_utc_when_cookie_missing() {
        let headers = HeaderMap::new();
        assert_eq!(extract(&headers).tz(), Tz::UTC);
    }

    #[test]
    fn extractor_resolves_valid_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Cookie",
            "vbn_tz=Europe%2FParis".parse().expect("valid header"),
        );
        // The CookieJar extractor takes care of URL-decoding.
        assert_eq!(extract(&headers).tz(), Tz::Europe__Paris);
    }

    #[test]
    fn extractor_falls_back_when_cookie_invalid() {
        let mut headers = HeaderMap::new();
        headers.insert("Cookie", "vbn_tz=Foo%2FBar".parse().expect("valid header"));
        assert_eq!(extract(&headers).tz(), Tz::UTC);
    }

    #[test]
    fn extractor_falls_back_when_cookie_xss_attempt() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Cookie",
            "vbn_tz=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
                .parse()
                .expect("valid header"),
        );
        assert_eq!(
            extract(&headers).tz(),
            Tz::UTC,
            "xss probe in cookie must collapse to UTC"
        );
    }

    #[test]
    fn extractor_falls_back_when_cookie_oversized() {
        let mut headers = HeaderMap::new();
        let big = "A".repeat(VBN_TZ_COOKIE_MAX_LEN + 1);
        let header_value = format!("vbn_tz={}", big);
        headers.insert("Cookie", header_value.parse().expect("valid header"));
        assert_eq!(extract(&headers).tz(), Tz::UTC);
    }

    #[test]
    fn browser_tz_default_is_utc() {
        assert_eq!(BrowserTz::default().tz(), Tz::UTC);
    }

    #[test]
    fn browser_tz_name_round_trips() {
        let bt = BrowserTz(Tz::America__New_York);
        assert_eq!(bt.name(), "America/New_York");
    }
}
