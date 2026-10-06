//! Offline CLI/service checks. No installed service or real account is touched.
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use oixc_proxy::catalog_cache::CatalogCache;
use oixc_proxy::nodes::ManagedConfig;

struct Service(Child);
impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn query(path: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_oixc-proxy"))
        .args(["traffic", "--file"])
        .arg(path)
        .args(args)
        .output()
        .unwrap()
}

fn unused_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn service_flushes_on_sigterm_and_keeps_history_across_restarts() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("test.conf");
    let journal = directory.path().join("custom-traffic.jsonl");
    let proxy_port = unused_port();
    let mut http_port = unused_port();
    while proxy_port == http_port {
        http_port = unused_port();
    }
    std::fs::write(&config, format!("token=test\napi-base-url=https://127.0.0.1:9\nrequest-timeout=100ms\nlisten=127.0.0.1:{proxy_port}\nnodelist-listen=127.0.0.1:{http_port}\n")).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let managed = ManagedConfig::parse(br#"
proxies:
  - name: Hong Kong Fusion 01
    type: snell
    server: node.cloud-nodes.com
    port: 443
    psk: local-test-only
    version: 4
    udp: true
    tfo: false
    reuse: true
    identity: true
    obfs-opts:
      mode: ech-tls
      sni: example.com
      path: /
      alpn: snell-ech/1
      ech-config: AEX+DQBBBwAgACABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIAAEAAEAAQAScHVibGljLmV4YW1wbGUuY29tAAA=
      identity-version: 2
      legacy-fallback: false
      skip-cert-verify: false
      preconnect: 0
"#).unwrap();
    CatalogCache::beside_config(&config, "test")
        .store(&managed)
        .unwrap();
    // Seed history from an earlier process, independently of live counters.
    std::fs::write(&journal, b"{\"version\":1,\"timestamp\":60,\"since\":0,\"bytes\":{\"tcp_upload\":600,\"tcp_download\":700,\"udp_upload\":0,\"udp_download\":0}}\n").unwrap();
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let mut previous_samples = 1;
    for _ in 0..2 {
        let mut service = Service(
            Command::new(env!("CARGO_BIN_EXE_oixc-proxy"))
                .args(["serve", "--config"])
                .arg(&config)
                .arg("--traffic-file")
                .arg(&journal)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                assert!(
                    service.0.try_wait().unwrap().is_none(),
                    "service exited before readiness"
                );
                if let Ok(response) = http
                    .get(format!("http://127.0.0.1:{http_port}/status"))
                    .send()
                    .await
                {
                    if response.status().is_success() {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        // Read-only queries work while the writer is running; concurrent writers cannot.
        assert!(query(&journal, &["--all", "--json"]).status.success());
        let duplicate = Command::new(env!("CARGO_BIN_EXE_oixc-proxy"))
            .args(["serve", "--config"])
            .arg(&config)
            .arg("--traffic-file")
            .arg(&journal)
            .output()
            .unwrap();
        assert!(!duplicate.status.success());
        assert!(String::from_utf8_lossy(&duplicate.stderr).contains("another process"));
        assert_eq!(
            unsafe { libc::kill(service.0.id() as i32, libc::SIGTERM) },
            0
        );
        let status = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(status) = service.0.try_wait().unwrap() {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert!(status.success());
        let output = query(&journal, &["--all", "--json"]);
        assert!(output.status.success());
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["total_bytes"], 1300);
        let samples = report["samples"].as_u64().unwrap();
        assert!(
            samples > previous_samples,
            "SIGTERM must persist a final sample"
        );
        previous_samples = samples;
    }
    assert!(!directory.path().join("traffic.jsonl").exists());
    let output = query(&journal, &["--from", "60", "--to", "120", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["samples"], 1);
    assert_eq!(report["total_bytes"], 1300);
    // A query derives its default path without loading secrets or requiring a valid config.
    std::fs::copy(&journal, directory.path().join("traffic.jsonl")).unwrap();
    let default = Command::new(env!("CARGO_BIN_EXE_oixc-proxy"))
        .args(["traffic", "--config"])
        .arg(directory.path().join("missing.conf"))
        .output()
        .unwrap();
    assert!(default.status.success());
    assert!(String::from_utf8_lossy(&default.stdout).contains("1300 bytes"));
    for flags in [
        &["--all", "--from", "60"][..],
        &["--from", "bad"],
        &["--config", "other.conf"],
    ] {
        assert_eq!(query(&journal, flags).status.code(), Some(2));
    }
    assert_eq!(
        std::fs::metadata(&journal).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
