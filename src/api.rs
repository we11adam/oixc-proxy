use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use age::armor::ArmoredReader;
use anyhow::{Context, Result, bail};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use reqwest::{Client as HttpClient, Method, StatusCode};
use serde::Deserialize;
use sha2::Sha256;
use url::Url;

pub const MANAGED_NODES_PATH: &str = "/api/v1/managed/anywhere/direct";
pub const INFORMATION_PATH: &str = "/api/v1/information";
pub const HEADER_TIMESTAMP: &str = "X-Anywhere-Timestamp";
pub const HEADER_SIGNATURE: &str = "X-Anywhere-Signature";
pub const HEADER_AGE_PUBKEY: &str = "X-Anywhere-Age-Pubkey";
pub const HEADER_RESPONSE_SIGNATURE: &str = "X-Anywhere-Response-Signature";
const MAX_RESPONSE_BYTES: usize = 8 << 20;
const USER_AGENT: &str = "oixc-proxy/0.1";
type HmacSha256 = Hmac<Sha256>;

pub struct Client {
    base_url: Url,
    access_token: String,
    app_secret: String,
    http: HttpClient,
    timeout: Duration,
}

impl Client {
    pub fn new(
        base_url: Url,
        access_token: impl Into<String>,
        app_secret: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self> {
        if base_url.scheme() != "https" || base_url.host_str().is_none() {
            bail!("base URL must be an absolute HTTPS URL");
        }
        let access_token = access_token.into().trim().to_owned();
        let app_secret = app_secret.into().trim().to_owned();
        if access_token.is_empty() {
            bail!("access token is required");
        }
        if app_secret.is_empty() {
            bail!("app secret is required");
        }
        if timeout.is_zero() || timeout > Duration::from_secs(120) {
            bail!("timeout must be between 1ns and 2m");
        }
        let http = HttpClient::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .user_agent(USER_AGENT)
            .build()
            .context("create API HTTP client")?;
        Ok(Self {
            base_url,
            access_token,
            app_secret,
            http,
            timeout,
        })
    }

    pub async fn information(&self) -> Result<Vec<u8>> {
        let endpoint = self.endpoint(INFORMATION_PATH)?;
        let response = self
            .http
            .request(Method::POST, endpoint)
            .header("Accept", "application/json")
            .bearer_auth(&self.access_token)
            .timeout(self.timeout)
            .send()
            .await
            .context("perform information request")?;
        let status = response.status();
        let body = read_limited_response(response).await?;
        ensure_success(status, &body)?;
        serde_json::from_slice::<serde_json::Value>(&body)
            .map_err(|_| anyhow::anyhow!("information response is not valid JSON"))?;
        Ok(body)
    }

    pub async fn dump_managed_config(&self) -> Result<Vec<u8>> {
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public().to_string();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_secs()
            .to_string();
        self.get_managed_config(MANAGED_NODES_PATH, &timestamp, &recipient, &identity)
            .await
    }

    async fn get_managed_config(
        &self,
        path: &str,
        timestamp: &str,
        recipient: &str,
        identity: &age::x25519::Identity,
    ) -> Result<Vec<u8>> {
        let endpoint = self.endpoint(path)?;
        let signature = request_signature(&self.app_secret, timestamp, recipient);
        let response = self
            .http
            .request(Method::GET, endpoint)
            .header("Accept", "application/json")
            .bearer_auth(&self.access_token)
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_AGE_PUBKEY, recipient)
            .header(HEADER_SIGNATURE, signature)
            .timeout(self.timeout)
            .send()
            .await
            .context("perform request")?;
        let status = response.status();
        let response_signature = response
            .headers()
            .get(HEADER_RESPONSE_SIGNATURE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .trim()
            .to_owned();
        let body = read_limited_response(response).await?;
        ensure_success(status, &body)?;

        let envelope: ManagedEnvelope =
            serde_json::from_slice(&body).context("decode managed API envelope")?;
        if envelope.ret != StatusCode::OK.as_u16() as i32 {
            bail!(
                "managed API returned ret={}: {}",
                envelope.ret,
                envelope.msg
            );
        }
        if envelope.config.is_empty() {
            bail!(
                "managed API response has no encrypted data: {} (fields: {})",
                envelope.msg,
                describe_json_fields(&body)
            );
        }
        if response_signature.is_empty() {
            bail!("API response is missing its signature");
        }
        if !verify_response_signature(
            &self.app_secret,
            timestamp,
            envelope.config.as_bytes(),
            &response_signature,
        ) {
            bail!("API response signature does not match");
        }
        let armored = base64::engine::general_purpose::STANDARD
            .decode(envelope.config)
            .map_err(|_| anyhow::anyhow!("decode managed config: invalid Base64"))?;
        if armored.len() > MAX_RESPONSE_BYTES {
            bail!("decoded managed config exceeds {MAX_RESPONSE_BYTES} bytes");
        }
        decrypt_age(&armored, identity)
    }

    fn endpoint(&self, path: &str) -> Result<Url> {
        let mut endpoint = self.base_url.clone();
        endpoint.set_path(path);
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        Ok(endpoint)
    }
}

#[derive(Deserialize)]
struct ManagedEnvelope {
    ret: i32,
    #[serde(default)]
    msg: String,
    #[serde(default)]
    config: String,
    #[serde(default, rename = "userinfo")]
    _userinfo: String,
}

pub fn request_signature(app_secret: &str, timestamp: &str, recipient: &str) -> String {
    hmac_hex(app_secret, &format!("{timestamp}.{recipient}"))
}

fn verify_response_signature(
    app_secret: &str,
    timestamp: &str,
    body: &[u8],
    provided_hex: &str,
) -> bool {
    let Ok(provided) = hex::decode(provided_hex) else {
        return false;
    };
    let mut mac =
        HmacSha256::new_from_slice(app_secret.as_bytes()).expect("HMAC accepts every key length");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    mac.verify_slice(&provided).is_ok()
}

fn hmac_hex(key: &str, message: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts every key length");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn decrypt_age(ciphertext: &[u8], identity: &age::x25519::Identity) -> Result<Vec<u8>> {
    let armor = ArmoredReader::new(ciphertext);
    let decryptor = age::Decryptor::new(armor).map_err(|_| {
        anyhow::anyhow!("decrypt API response: invalid age payload or wrong identity")
    })?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|_| {
            anyhow::anyhow!("decrypt API response: invalid age payload or wrong identity")
        })?;
    let mut plaintext = Vec::new();
    reader
        .by_ref()
        .take((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut plaintext)
        .context("read decrypted API response")?;
    if plaintext.len() > MAX_RESPONSE_BYTES {
        bail!("decrypted response exceeds {MAX_RESPONSE_BYTES} bytes");
    }
    Ok(plaintext)
}

async fn read_limited_response(mut response: reqwest::Response) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.context("read response")? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            bail!("response exceeds {MAX_RESPONSE_BYTES} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn ensure_success(status: StatusCode, body: &[u8]) -> Result<()> {
    if !status.is_success() {
        bail!(
            "API returned HTTP {}: {}",
            status.as_u16(),
            safe_error_body(body)
        );
    }
    Ok(())
}

fn safe_error_body(body: &[u8]) -> String {
    let value = String::from_utf8_lossy(body);
    let trimmed = value.trim();
    if trimmed.len() > 512 {
        format!("{}...", &trimmed[..512])
    } else {
        trimmed.to_owned()
    }
}

fn describe_json_fields(body: &[u8]) -> String {
    let Ok(fields) = serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(body)
    else {
        return "unavailable".to_owned();
    };
    let mut descriptions = fields
        .into_iter()
        .map(|(key, value)| {
            let kind = match value {
                serde_json::Value::Null => "null",
                serde_json::Value::Bool(_) => "boolean",
                serde_json::Value::Number(_) => "number",
                serde_json::Value::String(_) => "string",
                serde_json::Value::Array(_) => "array",
                serde_json::Value::Object(_) => "object",
            };
            format!("{key}={kind}")
        })
        .collect::<Vec<_>>();
    descriptions.sort();
    descriptions.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_signature_matches_go_known_vector() {
        assert_eq!(
            request_signature(
                "4a7f27227e2779e5d3e9cd968ba06ceb",
                "1700000000",
                "age1testrecipient"
            ),
            "5a1e17eb5015033d105e3d36a2f46cbdb6e7795a16f358e967f370c145498a11"
        );
    }
}
