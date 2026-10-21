//! Opt-in, Administrator-only SCM test for a disposable Windows CI runner.
#![cfg(windows)]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use oixc_proxy::catalog_cache::CatalogCache;
use oixc_proxy::nodes::ManagedConfig;

fn powershell() -> Command {
    let root = std::env::var_os("SystemRoot").unwrap();
    let mut command =
        Command::new(Path::new(&root).join("System32/WindowsPowerShell/v1.0/powershell.exe"));
    command.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
    ]);
    command
}

fn success(output: Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct Cleanup {
    state: PathBuf,
    binary: PathBuf,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = Command::new(&self.binary)
            .arg("uninstall-windows-service")
            .output();
        // These paths were checked absent and created by this test only.
        let _ = std::fs::remove_dir_all(&self.state);
    }
}

fn private_write(path: &Path, bytes: &[u8]) {
    oixc_proxy::windows::files::open_private(path, true, true)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

#[tokio::test]
#[ignore = "creates the machine-wide oixc-proxy service; disposable Administrator CI only"]
async fn installer_scm_control_restart_and_final_traffic_flush() {
    let absent = powershell()
        .args([
            "-Command",
            "if (Get-Service oixc-proxy -ErrorAction SilentlyContinue) { exit 1 }",
        ])
        .output()
        .unwrap();
    assert!(
        absent.status.success(),
        "refusing to touch an existing service"
    );
    let state = PathBuf::from(std::env::var_os("ProgramData").unwrap()).join("oixc-proxy");
    assert!(!state.exists(), "refusing to touch existing service state");
    let root = tempfile::Builder::new()
        .prefix("oixc-proxy-ci-")
        .tempdir_in(std::env::var_os("ProgramFiles").unwrap())
        .unwrap();
    let installed = root.path().join("oixc-proxy.exe");
    std::fs::create_dir(&state).unwrap();
    let _cleanup = Cleanup {
        state: state.clone(),
        binary: installed.clone(),
    };
    let source = tempfile::tempdir().unwrap();
    let config = source.path().join("配置 with spaces.conf");
    let unused_port = || {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    let proxy = unused_port();
    let mut http = unused_port();
    while http == proxy {
        http = unused_port();
    }
    private_write(&config, format!("token=windows-offline-test\napi-base-url=https://127.0.0.1:9\nrequest-timeout=100ms\nlisten=127.0.0.1:{proxy}\nnodelist-listen=127.0.0.1:{http}\n").as_bytes());
    let managed = ManagedConfig::parse(br#"
proxies:
  - name: Hong Kong Fusion 01
    type: snell
    server: node.cloud-nodes.com
    port: 443
    psk: windows-offline-test
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
      preconnect: 0
"#).unwrap();
    let service_config = state.join("oixc-proxy.conf");
    CatalogCache::beside_config(&service_config, "windows-offline-test")
        .store(&managed)
        .unwrap();
    success(
        powershell()
            .arg("-File")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("install.ps1"))
            .arg("-BinaryPath")
            .arg(env!("CARGO_BIN_EXE_oixc-proxy"))
            .arg("-InstallDir")
            .arg(root.path())
            .arg("-InstallService")
            .arg("-Config")
            .arg(&config)
            .output()
            .unwrap(),
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let healthy = || async {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(response) = client
                .get(format!("http://127.0.0.1:{http}/healthz"))
                .send()
                .await
            {
                if response.status().as_u16() == 204 {
                    break;
                }
            }
            assert!(Instant::now() < deadline, "service did not become healthy");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    healthy().await;
    let response =
        oixc_proxy::control::send(&service_config, oixc_proxy::control::Command::Diagnostics)
            .await
            .unwrap();
    assert!(response.ok);
    assert!(
        oixc_proxy::control::send(&service_config, oixc_proxy::control::Command::ReloadConfig)
            .await
            .unwrap()
            .ok
    );
    success(
        powershell()
            .args(["-Command", "Stop-Service oixc-proxy -ErrorAction Stop"])
            .output()
            .unwrap(),
    );
    let journal = state.join("traffic.jsonl");
    let first = oixc_proxy::traffic::query(&journal, None, None)
        .unwrap()
        .samples;
    assert!(first >= 1, "SCM Stop must flush the partial minute");
    success(
        powershell()
            .args(["-Command", "Start-Service oixc-proxy -ErrorAction Stop"])
            .output()
            .unwrap(),
    );
    healthy().await;
    success(
        powershell()
            .args(["-Command", "Restart-Service oixc-proxy -ErrorAction Stop"])
            .output()
            .unwrap(),
    );
    healthy().await;
    assert!(
        oixc_proxy::traffic::query(&journal, None, None)
            .unwrap()
            .samples
            > first
    );
    success(
        Command::new(&installed)
            .arg("uninstall-windows-service")
            .output()
            .unwrap(),
    );
    assert!(service_config.exists() && journal.exists() && installed.exists());
}

#[test]
fn windows_traffic_query_respects_crt_timezone_and_explicit_offsets() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("traffic.jsonl");
    private_write(&path, b"{\"version\":1,\"timestamp\":1791216000,\"since\":1791215940,\"bytes\":{\"tcp_upload\":10,\"tcp_download\":20,\"udp_upload\":0,\"udp_download\":0}}\n");
    let output = Command::new(env!("CARGO_BIN_EXE_oixc-proxy"))
        .env("TZ", "CST-8")
        .args(["traffic", "--file"])
        .arg(&path)
        .args(["--from", "2026-10-06T00:00", "--to", "2026-10-07T00:00"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&output.stdout).contains("2026-10-06T00:00:00+08:00"));
    success(output);
}
