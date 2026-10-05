use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::config::require_private_file;
use crate::nodes::ManagedConfig;

const CACHE_FILE_NAME: &str = "nodes-cache.yaml";
const CACHE_FORMAT_VERSION: u8 = 2;
const MAX_CACHE_BYTES: usize = (8 << 20) + (64 << 10);
const ACCOUNT_FINGERPRINT_CONTEXT: &[u8] = b"oixc-proxy/catalog-cache-account/v1";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CacheEnvelope {
    version: u8,
    account_fingerprint: String,
    managed: ManagedConfig,
    #[serde(default)]
    fetched_at: Option<u64>,
    #[serde(default)]
    userinfo: serde_json::Value,
}

pub struct CatalogSnapshot {
    pub managed: ManagedConfig,
    pub fetched_at: Option<u64>,
    pub userinfo: Option<crate::subscription::UserInfo>,
}

pub struct CatalogCache {
    path: PathBuf,
    account_fingerprint: String,
}

impl CatalogCache {
    pub fn modified_at(&self) -> Option<u64> {
        std::fs::metadata(&self.path)
            .ok()?
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|time| time.as_secs())
    }

    pub fn beside_config(config_path: &Path, access_token: &str) -> Self {
        let directory = config_path.parent().unwrap_or_else(|| Path::new("."));
        Self {
            path: directory.join(CACHE_FILE_NAME),
            account_fingerprint: account_fingerprint(access_token),
        }
    }

    pub fn load(&self) -> Option<ManagedConfig> {
        self.load_snapshot().map(|snapshot| snapshot.managed)
    }

    pub fn load_snapshot(&self) -> Option<CatalogSnapshot> {
        if !self.path.exists() {
            return None;
        }
        if let Err(error) = require_private_file(&self.path, false) {
            eprintln!("node catalog cache is unusable: {error:#}");
            return None;
        }
        match fs::read(&self.path) {
            Ok(content) if content.len() > MAX_CACHE_BYTES => {
                eprintln!("node catalog cache is unusable: cache is too large");
                None
            }
            Ok(content) => match parse_envelope(&content, &self.account_fingerprint) {
                Ok(managed) => Some(managed),
                Err(error) => {
                    eprintln!("node catalog cache is unusable: {error:#}");
                    None
                }
            },
            Err(error) => {
                eprintln!("node catalog cache is unusable: {error}");
                None
            }
        }
    }

    pub fn store(&self, managed: &ManagedConfig) -> Result<()> {
        self.store_snapshot(managed, None, Some(crate::diagnostics::unix_now()))
    }

    pub fn store_snapshot(
        &self,
        managed: &ManagedConfig,
        userinfo: Option<&crate::subscription::UserInfo>,
        fetched_at: Option<u64>,
    ) -> Result<()> {
        let envelope = CacheEnvelope {
            version: CACHE_FORMAT_VERSION,
            account_fingerprint: self.account_fingerprint.clone(),
            managed: managed.clone(),
            fetched_at,
            userinfo: serde_json::to_value(userinfo)?,
        };
        let content = serde_yaml::to_string(&envelope).context("encode node catalog cache")?;
        write_private_atomic(&self.path, content.as_bytes())
    }

    pub fn store_or_log(&self, managed: &ManagedConfig) {
        if let Err(error) = self.store(managed) {
            eprintln!("node catalog cache write failed: {error:#}");
        }
    }

    pub fn store_snapshot_or_log(&self, snapshot: &CatalogSnapshot) {
        if let Err(error) = self.store_snapshot(
            &snapshot.managed,
            snapshot.userinfo.as_ref(),
            snapshot.fetched_at,
        ) {
            eprintln!("node catalog cache write failed: {error:#}");
        }
    }
}

fn account_fingerprint(access_token: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(access_token.as_bytes())
        .expect("HMAC accepts every key length");
    mac.update(ACCOUNT_FINGERPRINT_CONTEXT);
    hex::encode(mac.finalize().into_bytes())
}

fn parse_envelope(content: &[u8], expected_fingerprint: &str) -> Result<CatalogSnapshot> {
    let mut documents = serde_yaml::Deserializer::from_slice(content);
    let first = documents.next().context("cache is empty")?;
    let envelope = CacheEnvelope::deserialize(first).context("decode cache envelope")?;
    if documents.next().is_some() {
        bail!("cache contains multiple YAML documents");
    }
    if ![1, CACHE_FORMAT_VERSION].contains(&envelope.version) {
        bail!("cache format version is unsupported");
    }
    if !bool::from(
        envelope
            .account_fingerprint
            .as_bytes()
            .ct_eq(expected_fingerprint.as_bytes()),
    ) {
        bail!("cache belongs to a different account");
    }
    envelope.managed.validate()?;
    let userinfo = serde_json::from_value::<crate::subscription::UserInfo>(envelope.userinfo)
        .ok()
        .filter(|info| info.valid());
    Ok(CatalogSnapshot {
        managed: envelope.managed,
        fetched_at: envelope.fetched_at,
        userinfo,
    })
}

fn write_private_atomic(path: &Path, content: &[u8]) -> Result<()> {
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let temporary = directory.join(format!(
        ".{}.tmp-{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let write_result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("create node catalog cache {}", temporary.display()))?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
            .with_context(|| format!("replace node catalog cache {}", path.display()))?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = r#"
proxies:
  - name: Hong Kong Fusion 01
    type: snell
    server: node.cloud-nodes.com
    port: 443
    psk: secret
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
"#;

    #[test]
    fn store_and_load_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let cache =
            CatalogCache::beside_config(&directory.path().join("oixc-proxy.conf"), "token-a");
        let managed = ManagedConfig::parse(YAML.as_bytes()).unwrap();
        cache.store(&managed).unwrap();
        let loaded = cache.load().expect("cache should load");
        assert_eq!(loaded, managed);
    }

    #[test]
    fn metadata_is_account_scoped_and_legacy_or_invalid_metadata_is_omitted() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("oixc-proxy.conf");
        let cache = CatalogCache::beside_config(&path, "token-a");
        let managed = ManagedConfig::parse(YAML.as_bytes()).unwrap();
        let info =
            crate::subscription::UserInfo::parse("upload=1;download=2;total=100;expire=1700000000")
                .unwrap();
        cache
            .store_snapshot(&managed, Some(&info), Some(100))
            .unwrap();
        let loaded = cache.load_snapshot().unwrap();
        assert_eq!(loaded.userinfo, Some(info));
        assert_eq!(loaded.fetched_at, Some(100));
        assert!(
            CatalogCache::beside_config(&path, "token-b")
                .load_snapshot()
                .is_none()
        );
        let mut value: serde_yaml::Value =
            serde_yaml::from_slice(&fs::read(&cache.path).unwrap()).unwrap();
        value["userinfo"] = serde_yaml::Value::String("invalid metadata".to_owned());
        write_private_atomic(
            &cache.path,
            serde_yaml::to_string(&value).unwrap().as_bytes(),
        )
        .unwrap();
        assert_eq!(cache.load_snapshot().unwrap().managed, managed);
        assert!(cache.load_snapshot().unwrap().userinfo.is_none());
        let map = value.as_mapping_mut().unwrap();
        map.insert("version".into(), 1.into());
        map.remove(serde_yaml::Value::String("userinfo".to_owned()));
        map.remove(serde_yaml::Value::String("fetched_at".to_owned()));
        write_private_atomic(
            &cache.path,
            serde_yaml::to_string(&value).unwrap().as_bytes(),
        )
        .unwrap();
        let loaded = cache.load_snapshot().unwrap();
        assert_eq!(loaded.managed, managed);
        assert!(loaded.userinfo.is_none());
        assert!(loaded.fetched_at.is_none());
    }

    #[test]
    fn missing_cache_is_a_miss() {
        let directory = tempfile::tempdir().unwrap();
        let cache =
            CatalogCache::beside_config(&directory.path().join("oixc-proxy.conf"), "token-a");
        assert!(cache.load().is_none());
    }

    #[test]
    fn corrupt_cache_is_a_miss() {
        let directory = tempfile::tempdir().unwrap();
        let cache =
            CatalogCache::beside_config(&directory.path().join("oixc-proxy.conf"), "token-a");
        write_private_atomic(&cache.path, b"not-valid-yaml").unwrap();
        assert!(cache.load().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_cache_is_a_miss() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let cache =
            CatalogCache::beside_config(&directory.path().join("oixc-proxy.conf"), "token-a");
        let managed = ManagedConfig::parse(YAML.as_bytes()).unwrap();
        cache.store(&managed).unwrap();
        fs::set_permissions(&cache.path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(cache.load().is_none());
    }

    #[test]
    fn cache_is_bound_to_the_access_token() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("oixc-proxy.conf");
        let first = CatalogCache::beside_config(&config, "token-a");
        let managed = ManagedConfig::parse(YAML.as_bytes()).unwrap();
        first.store(&managed).unwrap();

        let second = CatalogCache::beside_config(&config, "token-b");
        assert!(second.load().is_none());
    }

    #[test]
    fn legacy_unscoped_cache_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let cache =
            CatalogCache::beside_config(&directory.path().join("oixc-proxy.conf"), "token-a");
        write_private_atomic(&cache.path, YAML.as_bytes()).unwrap();
        assert!(cache.load().is_none());
    }
}
