//! Hop 1: `POST /api/v1/mcp/sessions`.

use crate::tofu::origin_key;
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;

#[derive(Debug)]
pub struct Hop1 {
    pub url: String,
    pub bearer: SecretString,
    pub transport: String,
    pub tunnel_spki: Option<String>,
}

/// `expected_origin` is [`origin_key`] of `--url`. A hop-2 `url` on any
/// other origin, or not on `https://`, is refused.
pub fn parse_hop1(body: &str, expected_origin: &str) -> Result<Hop1, String> {
    let v: Value = serde_json::from_str(body).map_err(|e| format!("hop 1 json: {e}"))?;
    let url = v
        .get("url")
        .and_then(Value::as_str)
        .ok_or("hop 1 response has no url")?
        .to_string();
    let origin = origin_key(&url)?;
    if origin != expected_origin {
        return Err(format!(
            "hop 1 url is on {origin}, not on --url origin {expected_origin}; refusing"
        ));
    }
    let bearer = v
        .get("bearer")
        .and_then(Value::as_str)
        .filter(|s| s.starts_with("vbw_"))
        .ok_or("hop 1 response has no vbw_ bearer")?
        .to_string();
    let transport = v
        .get("transport")
        .and_then(Value::as_str)
        .unwrap_or("direct")
        .to_string();
    let tunnel_spki = v
        .get("tunnel_spki")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(Hop1 {
        url,
        bearer: SecretString::from(bearer),
        transport,
        tunnel_spki,
    })
}

pub fn tunnel_ws_url(mcp_url: &str) -> Result<String, String> {
    let trimmed = mcp_url.trim_end_matches('/').trim_end_matches("/mcp");
    let rest = trimmed
        .strip_prefix("https://")
        .ok_or_else(|| format!("hop 2 must be https://, got {mcp_url}"))?;
    Ok(format!("wss://{rest}/mcp/tunnel"))
}

pub async fn open_session(
    client: &reqwest::Client,
    bastion: &str,
    api_key: &SecretString,
    asset: &str,
    justification: &str,
) -> Result<Hop1, String> {
    let expected_origin = origin_key(bastion)?;
    let base = bastion.trim_end_matches('/');
    let response = client
        .post(format!("{base}/api/v1/mcp/sessions"))
        .header(
            "authorization",
            format!("Bearer {}", api_key.expose_secret()),
        )
        .json(&serde_json::json!({
            "asset_id": asset,
            "justification": justification,
        }))
        .send()
        .await
        .map_err(|e| format!("hop 1: {e}"))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| format!("hop 1 body: {e}"))?;
    if !status.is_success() {
        return Err(format!("hop 1 status {status}"));
    }
    parse_hop1(&text, &expected_origin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop1_parses_url_bearer_and_pin() {
        let raw = r#"{"url":"https://b.example/mcp","bearer":"vbw_abc","transport":"tunnel","tunnel_spki":"SHA256:aaaa"}"#;
        let hop = parse_hop1(raw, "b.example:443").unwrap();
        assert_eq!(hop.url, "https://b.example/mcp");
        assert_eq!(hop.bearer.expose_secret(), "vbw_abc");
        assert_eq!(hop.tunnel_spki.as_deref(), Some("SHA256:aaaa"));
        assert_eq!(
            tunnel_ws_url(&hop.url).unwrap(),
            "wss://b.example/mcp/tunnel"
        );
    }

    #[test]
    fn forged_hop1_without_bearer_is_rejected() {
        assert!(parse_hop1(r#"{"url":"https://b.example/mcp"}"#, "b.example:443").is_err());
    }

    #[test]
    fn attack_hop1_url_host_substitution_is_rejected() {
        for url in [
            "https://evil.example/mcp",
            "https://b.example:8443/mcp",
            "https://b.example.evil.example/mcp",
            "https://evil.example/b.example/mcp",
        ] {
            let raw =
                format!(r#"{{"url":"{url}","bearer":"vbw_abc","tunnel_spki":"SHA256:aaaa"}}"#);
            assert!(parse_hop1(&raw, "b.example:443").is_err(), "{url}");
        }
        let raw = r#"{"url":"https://B.Example./mcp","bearer":"vbw_abc"}"#;
        assert!(parse_hop1(raw, "b.example:443").is_ok());
    }

    #[test]
    fn plain_http_hop2_is_refused_everywhere() {
        let raw = r#"{"url":"http://b.example/mcp","bearer":"vbw_abc"}"#;
        assert!(parse_hop1(raw, "b.example:443").is_err());
        assert!(tunnel_ws_url("http://b.example/mcp").is_err());
    }
}
