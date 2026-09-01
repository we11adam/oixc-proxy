use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use base64::Engine as _;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;

pub const PRIVATE_DNS_SUFFIX: &str = "cloud-nodes.com";
pub const PRIVATE_DNS_SERVER: &str = "124.221.68.73:1053";
pub const PRIVATE_DNS_SEED_BASE64: &str = "QiXXv81GasAAq3TfApAmFZ7kOjj+QC/I21N5MP39YNY=";
const CACHE_TTL: Duration = Duration::from_secs(300);
const PARTIAL_CACHE_TTL: Duration = Duration::from_secs(30);
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const QUERY_ATTEMPTS: usize = 2;
const FAMILY_GRACE: Duration = Duration::from_millis(50);

#[derive(Clone)]
pub struct PrivateDnsResolver {
    suffix: String,
    seed: Arc<[u8; 32]>,
    server: SocketAddr,
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
    lookup_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

#[derive(Clone)]
struct CacheEntry {
    addresses: Vec<IpAddr>,
    expires: Instant,
}

impl PrivateDnsResolver {
    pub fn built_in() -> Result<Self> {
        let seed = base64::engine::general_purpose::STANDARD
            .decode(PRIVATE_DNS_SEED_BASE64)
            .map_err(|_| anyhow::anyhow!("decode built-in private DNS signing seed"))?;
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| anyhow::anyhow!("private DNS signing seed has an invalid length"))?;
        Ok(Self {
            suffix: PRIVATE_DNS_SUFFIX.to_owned(),
            seed: Arc::new(seed),
            server: PRIVATE_DNS_SERVER
                .parse()
                .map_err(|_| anyhow::anyhow!("private DNS server is invalid"))?,
            cache: Arc::new(Mutex::new(HashMap::new())),
            lookup_locks: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn lookup(&self, host: &str) -> Result<Option<Vec<IpAddr>>> {
        let host = normalize_dns_name(host);
        if !matches_dns_suffix(&host, &self.suffix) {
            return Ok(None);
        }
        if let Some(addresses) = self.cached(&host).await {
            return Ok(Some(addresses));
        }

        let lookup_lock = {
            let mut locks = self.lookup_locks.lock().await;
            locks
                .entry(host.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let _lookup_guard = lookup_lock.lock().await;
        if let Some(addresses) = self.cached(&host).await {
            return Ok(Some(addresses));
        }

        let unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| anyhow::anyhow!("system clock is before Unix epoch"))?
            .as_secs() as i64;
        let query_name = signed_dns_name(&host, unix_seconds, self.seed.as_ref())?;
        let (mut addresses, complete) = self.query_dual_stack(&query_name).await;
        let mut seen = HashSet::with_capacity(addresses.len());
        addresses.retain(|address| seen.insert(*address));
        if addresses.is_empty() {
            bail!("resolve ECH-TLS node");
        }
        self.cache.lock().await.insert(
            host,
            CacheEntry {
                addresses: addresses.clone(),
                expires: Instant::now()
                    + if complete {
                        CACHE_TTL
                    } else {
                        PARTIAL_CACHE_TTL
                    },
            },
        );
        Ok(Some(addresses))
    }

    async fn query(&self, name: &str, record_type: RecordType) -> Result<Vec<IpAddr>> {
        for _ in 0..QUERY_ATTEMPTS {
            if let Ok(Ok(result)) = timeout(QUERY_TIMEOUT, self.query_once(name, record_type)).await
            {
                return Ok(result);
            }
        }
        bail!("resolve ECH-TLS node")
    }

    async fn query_dual_stack(&self, name: &str) -> (Vec<IpAddr>, bool) {
        let ipv4 = self.query(name, RecordType::A);
        let ipv6 = self.query(name, RecordType::AAAA);
        tokio::pin!(ipv4, ipv6);
        tokio::select! {
            result = &mut ipv4 => {
                let mut addresses = result.unwrap_or_default();
                if addresses.is_empty() {
                    addresses.extend(ipv6.await.unwrap_or_default());
                    (addresses, true)
                } else {
                    match timeout(FAMILY_GRACE, &mut ipv6).await {
                        Ok(Ok(other)) => addresses.extend(other),
                        Ok(Err(_)) => {}
                        Err(_) => return (addresses, false),
                    }
                    (addresses, true)
                }
            }
            result = &mut ipv6 => {
                let mut addresses = result.unwrap_or_default();
                if addresses.is_empty() {
                    addresses.extend(ipv4.await.unwrap_or_default());
                    (addresses, true)
                } else {
                    match timeout(FAMILY_GRACE, &mut ipv4).await {
                        Ok(Ok(other)) => addresses.extend(other),
                        Ok(Err(_)) => {}
                        Err(_) => return (addresses, false),
                    }
                    (addresses, true)
                }
            }
        }
    }

    async fn query_once(&self, name: &str, record_type: RecordType) -> Result<Vec<IpAddr>> {
        let mut id_bytes = [0u8; 2];
        getrandom::fill(&mut id_bytes)
            .map_err(|_| anyhow::anyhow!("generate private DNS query ID"))?;
        let mut message = Message::new();
        message
            .set_id(u16::from_be_bytes(id_bytes))
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true)
            .add_query(Query::query(
                Name::from_ascii(name)
                    .map_err(|_| anyhow::anyhow!("private DNS name is invalid"))?,
                record_type,
            ));
        let request = message
            .to_vec()
            .map_err(|_| anyhow::anyhow!("encode private DNS query"))?;
        let bind_address = if self.server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind_address)
            .await
            .map_err(|_| anyhow::anyhow!("resolve ECH-TLS node"))?;
        socket
            .send_to(&request, self.server)
            .await
            .map_err(|_| anyhow::anyhow!("resolve ECH-TLS node"))?;
        let mut response = [0u8; 4096];
        let (length, _) = socket
            .recv_from(&mut response)
            .await
            .map_err(|_| anyhow::anyhow!("resolve ECH-TLS node"))?;
        let response = Message::from_vec(&response[..length])
            .map_err(|_| anyhow::anyhow!("resolve ECH-TLS node"))?;
        if response.id() != u16::from_be_bytes(id_bytes) {
            bail!("resolve ECH-TLS node");
        }
        Ok(response
            .answers()
            .iter()
            .filter_map(|record| match record.data() {
                RData::A(address) => Some(IpAddr::V4((*address).into())),
                RData::AAAA(address) => Some(IpAddr::V6((*address).into())),
                _ => None,
            })
            .collect())
    }

    async fn cached(&self, host: &str) -> Option<Vec<IpAddr>> {
        let now = Instant::now();
        let mut cache = self.cache.lock().await;
        if let Some(entry) = cache.get(host) {
            if now < entry.expires {
                return Some(entry.addresses.clone());
            }
        }
        cache.remove(host);
        None
    }
}

pub fn signed_dns_name(host: &str, unix_seconds: i64, seed: &[u8]) -> Result<String> {
    let host = normalize_dns_name(host);
    validate_dns_name(&host)?;
    let seed: &[u8; 32] = seed
        .try_into()
        .map_err(|_| anyhow::anyhow!("private DNS signing seed is invalid"))?;
    let signing_key = SigningKey::from_bytes(seed);
    let window = unix_seconds.div_euclid(300);
    let message = format!("{host}|{window}");
    let signature = signing_key.sign(message.as_bytes()).to_bytes();
    let first = BASE32_NOPAD.encode(&signature[..32]).to_lowercase();
    let second = BASE32_NOPAD.encode(&signature[32..]).to_lowercase();
    let result = format!("{first}.{second}.{host}");
    validate_dns_name(&result)?;
    Ok(result)
}

pub fn matches_dns_suffix(host: &str, suffix: &str) -> bool {
    let host = normalize_dns_name(host);
    let suffix = normalize_dns_name(suffix);
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

fn normalize_dns_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_lowercase()
}

fn validate_dns_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 253
        || name
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
    {
        bail!("private DNS name is invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_name_matches_go_reference_vector() {
        let seed = base64::engine::general_purpose::STANDARD
            .decode(PRIVATE_DNS_SEED_BASE64)
            .unwrap();
        assert_eq!(
            signed_dns_name("Node.Cloud-Nodes.Com.", 1_800_000_000, &seed).unwrap(),
            concat!(
                "rf6fz4on43us6trf7jp6mfq4s65u3ezhcfdwkjkefhxdahthgmpq.",
                "hhpdgqn2h4e7yks6tkn7zdhfb4u2io4btsa4on6ngicvhz5bpqgq.",
                "node.cloud-nodes.com"
            )
        );
    }
}
