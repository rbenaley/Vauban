//! Hop 1: `POST /api/v1/mcp/sessions`.

use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;

#[derive(Debug)]
pub struct Hop1 {
    pub url: String,
    pub bearer: SecretString,
    pub transport: String,
    pub tunnel_spki: Option<String>,
}

pub fn parse_hop1(body: &str) -> Result<Hop1, String> {
    let v: Value = serde_json::from_str(body).map_err(|e| format!("hop 1 json: {e}"))?;
    let url = v
        .get("url")
        .and_then(Value::as_str)
        .filter(|s| s.starts_with("https://") || s.starts_with("http://"))
        .ok_or("hop 1 response has no url")?
        .to_string();
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

pub fn tunnel_ws_url(mcp_url: &str) -> String {
    let trimmed = mcp_url.trim_end_matches('/').trim_end_matches("/mcp");
    let ws = if let Some(rest) = trimmed.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        trimmed.to_string()
    };
    format!("{ws}/mcp/tunnel")
}

pub async fn open_session(
    client: &reqwest::Client,
    bastion: &str,
    api_key: &SecretString,
    asset: &str,
    justification: &str,
) -> Result<Hop1, String> {
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
    parse_hop1(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop1_parses_url_bearer_and_pin() {
        let raw = r#"{"url":"https://b.example/mcp","bearer":"vbw_abc","transport":"tunnel","tunnel_spki":"SHA256:aaaa"}"#;
        let hop = parse_hop1(raw).unwrap();
        assert_eq!(hop.url, "https://b.example/mcp");
        assert_eq!(hop.bearer.expose_secret(), "vbw_abc");
        assert_eq!(hop.tunnel_spki.as_deref(), Some("SHA256:aaaa"));
        assert_eq!(tunnel_ws_url(&hop.url), "wss://b.example/mcp/tunnel");
    }

    #[test]
    fn forged_hop1_without_bearer_is_rejected() {
        assert!(parse_hop1(r#"{"url":"https://b.example/mcp"}"#).is_err());
    }
}
