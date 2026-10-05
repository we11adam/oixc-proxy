use std::future::Future;
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

use crate::diagnostics::{ApiFailure, ErrorKind, http_error_kind};
use crate::network::NetworkSnapshot;

pub const MANAGED_NODES_PATH: &str = "/api/v1/managed/anywhere/direct";
pub const INFORMATION_PATH: &str = "/api/v1/information";
pub const TOKEN_REBIND_PATH: &str = "/api/v1/token/rebind";
pub const HEADER_CLIENT: &str = "X-oixCloud-Client";
pub const CLIENT_ID: &str = "oixcloud-helper";
pub const HEADER_TIMESTAMP: &str = "X-Anywhere-Timestamp";
pub const HEADER_SIGNATURE: &str = "X-Anywhere-Signature";
pub const HEADER_AGE_PUBKEY: &str = "X-Anywhere-Age-Pubkey";
pub const HEADER_RESPONSE_SIGNATURE: &str = "X-Anywhere-Response-Signature";
const MAX_RESPONSE_BYTES: usize = 8 << 20;
const USER_AGENT: &str = "oixCloud Helper";
type HmacSha256 = Hmac<Sha256>;

pub struct ManagedResponse {
    pub config: Vec<u8>,
    pub userinfo: Option<crate::subscription::UserInfo>,
}

pub struct Client {
    base_url: Url,
    fallback_urls: Vec<Url>,
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
        Self::build(base_url, access_token, app_secret, timeout, None)
    }

    pub fn new_with_network(
        base_url: Url,
        access_token: impl Into<String>,
        app_secret: impl Into<String>,
        timeout: Duration,
        network: &NetworkSnapshot,
    ) -> Result<Self> {
        Self::build(base_url, access_token, app_secret, timeout, Some(network))
    }

    fn build(
        base_url: Url,
        access_token: impl Into<String>,
        app_secret: impl Into<String>,
        timeout: Duration,
        network: Option<&NetworkSnapshot>,
    ) -> Result<Self> {
        crate::config::validate_api_url(&base_url)?;
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
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            HEADER_CLIENT,
            reqwest::header::HeaderValue::from_static(CLIENT_ID),
        );
        let mut builder = HttpClient::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .default_headers(headers)
            .user_agent(USER_AGENT);
        if let Some(network) = network {
            if let Some(source) = network
                .preferred_source()
                .context("select API outbound address")?
            {
                builder = builder.local_address(source);
            }
            #[cfg(target_os = "macos")]
            if let Some(interface) = network.interface_name() {
                builder = builder.interface(interface);
            }
        }
        let http = builder.build().context("create API HTTP client")?;
        Ok(Self {
            base_url,
            fallback_urls: Vec::new(),
            access_token,
            app_secret,
            http,
            timeout,
        })
    }

    pub fn with_fallback_urls(mut self, urls: Vec<Url>) -> Result<Self> {
        if urls.len() > 3 {
            bail!("configure at most three API fallback URLs");
        }
        for (index, url) in urls.iter().enumerate() {
            crate::config::validate_api_url(url)?;
            if url == &self.base_url || urls[..index].contains(url) {
                bail!("API URLs must be distinct");
            }
        }
        self.fallback_urls = urls;
        Ok(self)
    }

    async fn with_fallback<T, F, Fut>(&self, path: &str, mut operation: F) -> Result<T>
    where
        F: FnMut(Url, Duration) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let deadline = tokio::time::Instant::now() + self.timeout;
        let urls = std::iter::once(&self.base_url)
            .chain(self.fallback_urls.iter())
            .collect::<Vec<_>>();
        for (index, base) in urls.iter().enumerate() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(api_failure(ErrorKind::Timeout, None));
            }
            let budget = remaining / u32::try_from(urls.len() - index).unwrap();
            let mut endpoint = (*base).clone();
            endpoint.set_path(path);
            endpoint.set_query(None);
            endpoint.set_fragment(None);
            let result = tokio::time::timeout(budget, operation(endpoint, budget))
                .await
                .unwrap_or_else(|_| Err(api_failure(ErrorKind::Timeout, None)));
            match result {
                Ok(value) => return Ok(value),
                Err(error) if index + 1 < urls.len() && retryable(&error) => {
                    eprintln!(
                        "api.fallback attempt={} reason={:?}",
                        index + 1,
                        crate::diagnostics::classify(&error)
                    );
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("primary API URL always exists")
    }

    pub async fn information(&self) -> Result<Vec<u8>> {
        self.with_fallback(INFORMATION_PATH, |endpoint, budget| {
            self.information_at(endpoint, budget)
        })
        .await
    }

    /// Explicit token import/login: obtain a token owned by oixCloud Helper.
    /// Never retry this mutation: a lost response may already have issued a token.
    pub async fn rebind_token(&self) -> Result<String> {
        let mut endpoint = self.base_url.clone();
        endpoint.set_path(TOKEN_REBIND_PATH);
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        tokio::time::timeout(self.timeout, async {
            let response = self
                .http
                .post(endpoint)
                .header("Accept", "application/json")
                .bearer_auth(&self.access_token)
                .send()
                .await
                .context("perform token rebind request")?;
            ensure_success(response.status(), retry_after_seconds(&response))?;
            let body = read_limited_response(response).await?;
            parse_rebound_token(&body)
        })
        .await
        .unwrap_or_else(|_| Err(api_failure(ErrorKind::Timeout, None)))
    }

    async fn information_at(&self, endpoint: Url, budget: Duration) -> Result<Vec<u8>> {
        let response = self
            .http
            .request(Method::POST, endpoint)
            .header("Accept", "application/json")
            .bearer_auth(&self.access_token)
            .timeout(budget)
            .send()
            .await
            .context("perform information request")?;
        let status = response.status();
        ensure_success(status, retry_after_seconds(&response))?;
        let body = read_limited_response(response).await?;
        serde_json::from_slice::<serde_json::Value>(&body)
            .map_err(|_| api_failure(ErrorKind::InvalidResponse, None))?;
        Ok(body)
    }

    pub async fn dump_managed_config(&self) -> Result<Vec<u8>> {
        Ok(self.fetch_managed().await?.config)
    }

    pub async fn fetch_managed(&self) -> Result<ManagedResponse> {
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public().to_string();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_secs()
            .to_string();
        self.with_fallback(MANAGED_NODES_PATH, |endpoint, budget| {
            self.get_managed_config(endpoint, budget, &timestamp, &recipient, &identity)
        })
        .await
    }

    async fn get_managed_config(
        &self,
        endpoint: Url,
        budget: Duration,
        timestamp: &str,
        recipient: &str,
        identity: &age::x25519::Identity,
    ) -> Result<ManagedResponse> {
        let signature = request_signature(&self.app_secret, timestamp, recipient);
        let response = self
            .http
            .request(Method::GET, endpoint)
            .header("Accept", "application/json")
            .bearer_auth(&self.access_token)
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_AGE_PUBKEY, recipient)
            .header(HEADER_SIGNATURE, signature)
            .timeout(budget)
            .send()
            .await
            .context("perform request")?;
        let status = response.status();
        ensure_success(status, retry_after_seconds(&response))?;
        let response_signature = response
            .headers()
            .get(HEADER_RESPONSE_SIGNATURE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .trim()
            .to_owned();
        let body = read_limited_response(response).await?;

        let envelope: ManagedEnvelope = serde_json::from_slice(&body)
            .map_err(|_| api_failure(ErrorKind::InvalidResponse, None))?;
        if envelope.ret != StatusCode::OK.as_u16() as i32 {
            return Err(api_failure(
                http_error_kind(u16::try_from(envelope.ret).unwrap_or(0)),
                u16::try_from(envelope.ret).ok(),
            ));
        }
        if envelope.config.is_empty() {
            bail!(
                "managed API response has no encrypted data: {} (fields: {})",
                envelope.msg,
                describe_json_fields(&body)
            );
        }
        if response_signature.is_empty() {
            return Err(api_failure(ErrorKind::Signature, None));
        }
        if !verify_response_signature(
            &self.app_secret,
            timestamp,
            envelope.config.as_bytes(),
            &response_signature,
        ) {
            return Err(api_failure(ErrorKind::Signature, None));
        }
        let armored = base64::engine::general_purpose::STANDARD
            .decode(envelope.config)
            .map_err(|_| anyhow::anyhow!("decode managed config: invalid Base64"))?;
        if armored.len() > MAX_RESPONSE_BYTES {
            bail!("decoded managed config exceeds {MAX_RESPONSE_BYTES} bytes");
        }
        let config = decrypt_age(&armored, identity)?;
        let userinfo = envelope
            .userinfo
            .as_str()
            .and_then(crate::subscription::UserInfo::parse);
        Ok(ManagedResponse { config, userinfo })
    }
}

fn parse_rebound_token(body: &[u8]) -> Result<String> {
    #[derive(Deserialize)]
    struct Response {
        ret: i32,
        data: Option<Data>,
    }
    #[derive(Deserialize)]
    struct Data {
        token: String,
    }
    let response: Response =
        serde_json::from_slice(body).map_err(|_| api_failure(ErrorKind::InvalidResponse, None))?;
    if response.ret != 200 {
        return Err(api_failure(
            http_error_kind(u16::try_from(response.ret).unwrap_or(0)),
            u16::try_from(response.ret).ok(),
        ));
    }
    let token = response.data.map(|data| data.token).unwrap_or_default();
    let token = token.trim();
    if token.is_empty()
        || token
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || !byte.is_ascii_graphic())
    {
        return Err(api_failure(ErrorKind::InvalidResponse, None));
    }
    Ok(token.to_owned())
}

fn retryable(error: &anyhow::Error) -> bool {
    matches!(
        crate::diagnostics::classify(error),
        ErrorKind::Timeout | ErrorKind::Network | ErrorKind::Server
    )
}

#[derive(Deserialize)]
struct ManagedEnvelope {
    ret: i32,
    #[serde(default)]
    msg: String,
    #[serde(default)]
    config: String,
    #[serde(default)]
    userinfo: serde_json::Value,
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

fn ensure_success(status: StatusCode, retry_after_seconds: Option<u64>) -> Result<()> {
    if !status.is_success() {
        return Err(ApiFailure {
            kind: http_error_kind(status.as_u16()),
            status: Some(status.as_u16()),
            retry_after_seconds,
        }
        .into());
    }
    Ok(())
}

fn api_failure(kind: ErrorKind, status: Option<u16>) -> anyhow::Error {
    ApiFailure {
        kind,
        status,
        retry_after_seconds: None,
    }
    .into()
}

fn retry_after_seconds(response: &reqwest::Response) -> Option<u64> {
    response
        .headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .parse()
        .ok()
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn mock_response(status: u16, body: &str) -> (Url, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let body = body.to_owned();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut chunk = [0; 1024];
                let count = stream.read(&mut chunk).await.unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&chunk[..count]);
                assert!(bytes.len() < 16384);
                if bytes.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 {status} Mock\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8(bytes).unwrap()
        });
        (url, task)
    }

    #[tokio::test]
    async fn helper_identity_and_token_import_match_official_wire_format() {
        for operation in ["information", "managed", "rebind"] {
            let (url, request) =
                mock_response(200, r#"{"ret":200,"data":{"token":" helper-token "}}"#).await;
            let mut client = fallback_client();
            // Only the test bypasses production HTTPS URL validation.
            client.base_url = url;
            client.fallback_urls.clear();
            match operation {
                "information" => {
                    client.information().await.unwrap();
                }
                "managed" => {
                    assert!(client.fetch_managed().await.is_err());
                }
                _ => {
                    assert_eq!(client.rebind_token().await.unwrap(), "helper-token");
                }
            }
            let request = request.await.unwrap().to_ascii_lowercase();
            assert!(request.contains("user-agent: oixcloud helper\r\n"));
            assert!(request.contains("x-oixcloud-client: oixcloud-helper\r\n"));
            assert!(request.contains("authorization: bearer token\r\n"));
            if operation == "rebind" {
                assert!(request.starts_with("post /api/v1/token/rebind http/1.1\r\n"));
                assert!(request.ends_with("\r\n\r\n"));
                assert!(!request.contains("content-type:"));
            }
        }
    }

    #[tokio::test]
    async fn token_import_never_retries_or_uses_backup() {
        let (url, request) = mock_response(503, "private-server-message").await;
        let backup = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = fallback_client();
        client.base_url = url;
        client.fallback_urls =
            vec![Url::parse(&format!("http://{}", backup.local_addr().unwrap())).unwrap()];
        let error = client.rebind_token().await.unwrap_err();
        assert_eq!(crate::diagnostics::classify(&error), ErrorKind::Server);
        assert!(!format!("{error:#}").contains("private-server-message"));
        request.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), backup.accept())
                .await
                .is_err()
        );
    }

    #[test]
    fn token_import_rejects_invalid_or_missing_tokens_without_disclosure() {
        for body in [
            r#"{"ret":200}"#,
            r#"{"ret":200,"data":{"token":" "}}"#,
            r#"{"ret":200,"data":{"token":123}}"#,
            r#"{"ret":200,"data":{"token":"secret\nlisten=0.0.0.0:80"}}"#,
            r#"{"ret":200,"token":"secret"}"#,
            "secret",
        ] {
            let error = parse_rebound_token(body.as_bytes()).unwrap_err();
            assert_eq!(
                crate::diagnostics::classify(&error),
                ErrorKind::InvalidResponse
            );
            assert!(!format!("{error:#}").contains("secret"));
        }
        let error = parse_rebound_token(br#"{"ret":403,"msg":"private"}"#).unwrap_err();
        assert_eq!(crate::diagnostics::classify(&error), ErrorKind::Forbidden);
    }

    fn fallback_client() -> Client {
        Client::new(
            Url::parse("https://primary.example").unwrap(),
            "token",
            "secret",
            Duration::from_secs(12),
        )
        .unwrap()
        .with_fallback_urls(vec![Url::parse("https://backup.example").unwrap()])
        .unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_primary_leaves_backup_budget_and_body_shares_deadline() {
        let client = fallback_client();
        let started = tokio::time::Instant::now();
        let value = client
            .with_fallback(INFORMATION_PATH, |url, budget| async move {
                assert_eq!(url.path(), INFORMATION_PATH);
                if url.host_str() == Some("primary.example") {
                    assert_eq!(budget, Duration::from_secs(6));
                    std::future::pending::<Result<&str>>().await
                } else {
                    assert_eq!(budget, Duration::from_secs(6));
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    Ok("backup")
                }
            })
            .await
            .unwrap();
        assert_eq!(value, "backup");
        assert_eq!(started.elapsed(), Duration::from_secs(7));
        let started = tokio::time::Instant::now();
        assert!(
            client
                .with_fallback(INFORMATION_PATH, |_, _| std::future::pending::<Result<()>>(
                ))
                .await
                .is_err()
        );
        assert_eq!(started.elapsed(), Duration::from_secs(12));
    }

    #[tokio::test]
    async fn auth_rate_limit_invalid_and_signature_errors_do_not_fallback() {
        let client = fallback_client();
        for kind in [
            ErrorKind::Authentication,
            ErrorKind::Forbidden,
            ErrorKind::ProxyAuthentication,
            ErrorKind::RateLimited,
            ErrorKind::Signature,
            ErrorKind::InvalidResponse,
            ErrorKind::TlsCertificate,
        ] {
            let mut attempts = 0;
            let error = client
                .with_fallback(MANAGED_NODES_PATH, |_, _| {
                    attempts += 1;
                    std::future::ready(Err::<(), _>(api_failure(kind, None)))
                })
                .await
                .unwrap_err();
            assert_eq!(attempts, 1);
            assert_eq!(crate::diagnostics::classify(&error), kind);
        }
        let mut attempts = 0;
        let result = client
            .with_fallback(MANAGED_NODES_PATH, |_, _| {
                attempts += 1;
                std::future::ready(if attempts == 1 {
                    Err(api_failure(ErrorKind::Server, Some(503)))
                } else {
                    Ok(())
                })
            })
            .await;
        assert!(result.is_ok());
        assert_eq!(attempts, 2);
    }

    #[test]
    fn rate_limit_reports_wait_and_auth_is_distinct() {
        let error = ensure_success(StatusCode::TOO_MANY_REQUESTS, Some(60)).unwrap_err();
        let detail = error.downcast_ref::<ApiFailure>().unwrap();
        assert_eq!(detail.kind, ErrorKind::RateLimited);
        assert_eq!(detail.retry_after_seconds, Some(60));
        assert_eq!(
            crate::diagnostics::classify(
                &ensure_success(StatusCode::UNAUTHORIZED, None).unwrap_err()
            ),
            ErrorKind::Authentication
        );
    }

    #[test]
    fn missing_or_unexpected_userinfo_does_not_break_node_envelope() {
        for value in [
            serde_json::Value::Null,
            serde_json::json!({"unexpected": true}),
            serde_json::json!("upload=0; download=0"),
        ] {
            let envelope: ManagedEnvelope = serde_json::from_value(
                serde_json::json!({"ret":200,"config":"signed payload", "userinfo":value}),
            )
            .unwrap();
            assert!(
                envelope
                    .userinfo
                    .as_str()
                    .and_then(crate::subscription::UserInfo::parse)
                    .is_none()
            );
        }
    }

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
