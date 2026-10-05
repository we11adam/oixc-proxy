//! Opt-in verification against real API/nodes using an isolated service process.
//! No existing service, configuration or cache is modified.
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Service(Child);
impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn unused_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
#[ignore = "requires OIXC_LIVE_CONFIG and OIXC_LIVE_BINARY plus real API/nodes"]
async fn isolated_service_publishes_metadata_status_and_filtered_preview() {
    let source = std::env::var("OIXC_LIVE_CONFIG").unwrap();
    let binary = std::env::var("OIXC_LIVE_BINARY").unwrap();
    let config = oixc_proxy::config::load_proxy_config(std::path::Path::new(&source)).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("oixc-proxy.conf");
    let proxy_port = unused_port();
    let mut http_port = unused_port();
    while http_port == proxy_port {
        http_port = unused_port();
    }
    let mut text = format!(
        "token={}\nlisten=127.0.0.1:{proxy_port}\nnodelist-listen=127.0.0.1:{http_port}\napi-base-url={}\nnode-filter-lines=Fusion|CIA\n",
        config.runtime.access_token, config.runtime.api_base_url
    );
    if !config.runtime.api_fallback_urls.is_empty() {
        text.push_str(&format!(
            "api-fallback-urls={}\n",
            config
                .runtime
                .api_fallback_urls
                .iter()
                .map(|url| url.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    std::fs::write(&config_path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut service = Service(
        Command::new(&binary)
            .args(["serve", "--config"])
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let base = format!("http://127.0.0.1:{http_port}");
    let status = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            assert!(
                service.0.try_wait().unwrap().is_none(),
                "isolated service exited before readiness"
            );
            if let Ok(response) = http.get(format!("{base}/status")).send().await {
                if response.status().is_success() {
                    break response.json::<serde_json::Value>().await.unwrap();
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(status["ready"], true);
    assert!(status["published_nodes"].as_u64().unwrap() > 0);
    assert!(status["transport"]["tls_roots"]["count"].as_u64().unwrap() > 0);
    let get = http
        .get(format!("{base}/clash-proxies.yaml"))
        .send()
        .await
        .unwrap();
    let metadata = get
        .headers()
        .get("Subscription-Userinfo")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(oixc_proxy::subscription::UserInfo::parse(&metadata).is_some());
    assert!(!get.bytes().await.unwrap().is_empty());
    let head = http
        .head(format!("{base}/clash-proxies.yaml"))
        .send()
        .await
        .unwrap();
    assert_eq!(head.headers()["Subscription-Userinfo"], metadata);
    assert!(head.bytes().await.unwrap().is_empty());
    let preview = Command::new(&binary)
        .args(["preview-nodes", "--config"])
        .arg(&config_path)
        .output()
        .unwrap();
    assert!(preview.status.success());
    let preview: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(preview["mode"], "custom");
    assert_eq!(preview["kept"], status["published_nodes"]);
    let refreshed = Command::new(&binary)
        .args(["refresh-nodes", "--config"])
        .arg(&config_path)
        .output()
        .unwrap();
    assert!(refreshed.status.success());
    let refreshed: serde_json::Value = serde_json::from_slice(&refreshed.stdout).unwrap();
    assert_eq!(refreshed["ok"], true);
    assert_eq!(refreshed["payload"]["ready"], true);
    let provider = http
        .get(format!("{base}/surge-proxies.conf"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let fields = provider
        .lines()
        .next()
        .unwrap()
        .split(", ")
        .collect::<Vec<_>>();
    let through_proxy = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(25))
        .proxy(
            reqwest::Proxy::all(format!("http://127.0.0.1:{proxy_port}"))
                .unwrap()
                .basic_auth(fields[3], fields[4]),
        )
        .build()
        .unwrap();
    assert!(
        through_proxy
            .get("https://www.gstatic.com/generate_204")
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    let after: serde_json::Value = http
        .get(format!("{base}/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        after["transport"]["ech_dials"]["succeeded"]
            .as_u64()
            .unwrap()
            > 0
    );
}
