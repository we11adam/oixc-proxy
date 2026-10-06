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

#[test]
fn query_respects_process_timezone_explicit_offsets_and_dst() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("traffic.jsonl");
    // Samples immediately before, at, and at the end of a UTC+08 local day.
    let start = 1791216000u64;
    let mut text = String::new();
    for timestamp in [start - 1, start, start + 86400] {
        text.push_str(&format!("{{\"version\":1,\"timestamp\":{timestamp},\"since\":{},\"bytes\":{{\"tcp_upload\":10,\"tcp_download\":20,\"udp_upload\":0,\"udp_download\":0}}}}\n", timestamp - 60));
    }
    std::fs::write(&path, text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let run = |zone: &str, args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_oixc-proxy"))
            .env("TZ", zone)
            .args(["traffic", "--file"])
            .arg(&path)
            .args(args)
            .output()
            .unwrap()
    };
    let local = run(
        "Asia/Shanghai",
        &[
            "--from",
            "2026-10-06T00:00",
            "--to",
            "2026-10-07T00:00",
            "--json",
        ],
    );
    assert!(
        local.status.success(),
        "{}",
        String::from_utf8_lossy(&local.stderr)
    );
    let expected: serde_json::Value = serde_json::from_slice(&local.stdout).unwrap();
    assert_eq!(expected["from"], start);
    assert_eq!(expected["to"], start + 86400);
    assert_eq!(expected["samples"], 1);
    assert_eq!(expected["total_bytes"], 30);
    for (zone, from, to) in [
        ("UTC0", "2026-10-06 00:00+08:00", "2026-10-07 00:00+08:00"),
        ("Asia/Shanghai", "2026-10-05T16:00Z", "2026-10-06T16:00Z"),
        ("UTC0", "1791216000", "1791302400"),
    ] {
        let output = run(zone, &["--from", from, "--to", to, "--json"]);
        assert!(output.status.success());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            expected
        );
    }
    let human = run(
        "Asia/Shanghai",
        &["--from", "2026-10-06T00:00", "--to", "2026-10-07T00:00"],
    );
    let human = String::from_utf8(human.stdout).unwrap();
    assert!(
        human
            .contains("Range (local time): [2026-10-06T00:00:00+08:00, 2026-10-07T00:00:00+08:00)")
    );
    assert!(human.contains("first=2026-10-06T00:00:00+08:00"));
    // UTC display differs, but numeric JSON remains stable. No parent-process TZ mutation.
    let utc = run("UTC0", &["--all"]);
    assert!(String::from_utf8_lossy(&utc.stdout).contains("first=2026-10-05T15:59:59+00:00"));
    let eastern = "EST5EDT,M3.2.0/2,M11.1.0/2";
    for (from, to, hours) in [
        ("2026-03-08T00:00", "2026-03-09T00:00", 23),
        ("2026-11-01T00:00", "2026-11-02T00:00", 25),
    ] {
        let output = run(eastern, &["--from", from, "--to", to, "--json"]);
        assert!(output.status.success());
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            report["to"].as_u64().unwrap() - report["from"].as_u64().unwrap(),
            hours * 3600
        );
    }
    for (time, error) in [
        ("2026-03-08T02:30", "does not exist"),
        ("2026-11-01T01:30", "ambiguous"),
    ] {
        let output = run(eastern, &["--from", time]);
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(error),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    for (local, explicit) in [
        ("2026-01-01T12:00", "2026-01-01T12:00-05:00"),
        ("2026-07-01T12:00", "2026-07-01T12:00-04:00"),
    ] {
        let local = run(eastern, &["--from", local, "--json"]);
        let explicit = run("UTC0", &["--from", explicit, "--json"]);
        assert!(local.status.success());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&local.stdout).unwrap(),
            serde_json::from_slice::<serde_json::Value>(&explicit.stdout).unwrap()
        );
    }
    let early = run(eastern, &["--from", "2026-11-01T01:30-04:00", "--json"]);
    let late = run(eastern, &["--from", "2026-11-01T01:30-05:00", "--json"]);
    assert!(early.status.success() && late.status.success());
    let early: serde_json::Value = serde_json::from_slice(&early.stdout).unwrap();
    let late: serde_json::Value = serde_json::from_slice(&late.stdout).unwrap();
    assert_eq!(
        late["from"].as_u64().unwrap() - early["from"].as_u64().unwrap(),
        3600
    );
    let repeated = run(
        eastern,
        &[
            "--from",
            "2026-11-01T01:30-04:00",
            "--to",
            "2026-11-01T01:30-05:00",
        ],
    );
    assert!(
        String::from_utf8_lossy(&repeated.stdout)
            .contains("Range (local time): [2026-11-01T01:30:00-04:00, 2026-11-01T01:30:00-05:00)")
    );
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
