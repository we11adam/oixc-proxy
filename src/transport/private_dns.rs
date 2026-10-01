use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use base64::Engine as _;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::network::{NetworkSnapshot, bind_udp_socket};

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
    network_generation: u64,
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

    pub async fn lookup(
        &self,
        host: &str,
        network: &NetworkSnapshot,
    ) -> Result<Option<Vec<IpAddr>>> {
        let host = normalize_dns_name(host);
        if !matches_dns_suffix(&host, &self.suffix) {
            return Ok(None);
        }
        if let Some(addresses) = self.cached(&host, network.generation()).await {
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
        if let Some(addresses) = self.cached(&host, network.generation()).await {
            return Ok(Some(addresses));
        }

        let unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| anyhow::anyhow!("system clock is before Unix epoch"))?
            .as_secs() as i64;
        let query_name = signed_dns_name(&host, unix_seconds, self.seed.as_ref())?;
        let (mut addresses, complete) = self.query_dual_stack(&query_name, network).await;
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
                network_generation: network.generation(),
            },
        );
        Ok(Some(addresses))
    }

    async fn query(
        &self,
        name: &str,
        record_type: RecordType,
        network: &NetworkSnapshot,
    ) -> Result<Vec<IpAddr>> {
        for _ in 0..QUERY_ATTEMPTS {
            if let Ok(Ok(result)) =
                timeout(QUERY_TIMEOUT, self.query_once(name, record_type, network)).await
            {
                return Ok(result);
            }
        }
        bail!("resolve ECH-TLS node")
    }

    async fn query_dual_stack(&self, name: &str, network: &NetworkSnapshot) -> (Vec<IpAddr>, bool) {
        merge_families(
            self.query(name, RecordType::A, network),
            self.query(name, RecordType::AAAA, network),
        )
        .await
    }

    async fn query_once(
        &self,
        name: &str,
        record_type: RecordType,
        network: &NetworkSnapshot,
    ) -> Result<Vec<IpAddr>> {
        let mut id_bytes = [0u8; 2];
        getrandom::fill(&mut id_bytes)
            .map_err(|_| anyhow::anyhow!("generate private DNS query ID"))?;
        let id = u16::from_be_bytes(id_bytes);
        let query = Query::query(
            Name::from_ascii(format!("{name}."))
                .map_err(|_| anyhow::anyhow!("private DNS name is invalid"))?,
            record_type,
        );
        let mut message = Message::new();
        message
            .set_id(id)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true)
            .add_query(query.clone());
        let request = message
            .to_vec()
            .map_err(|_| anyhow::anyhow!("encode private DNS query"))?;
        let socket = bind_udp_socket(network, self.server)
            .await
            .map_err(|_| anyhow::anyhow!("resolve ECH-TLS node"))?;
        socket
            .send_to(&request, self.server)
            .await
            .map_err(|_| anyhow::anyhow!("resolve ECH-TLS node"))?;
        let mut response = [0u8; 4096];
        loop {
            let (length, source) = socket
                .recv_from(&mut response)
                .await
                .map_err(|_| anyhow::anyhow!("resolve ECH-TLS node"))?;
            if source != self.server {
                continue;
            }
            if let Some(addresses) = parse_response(&response[..length], id, &query)? {
                return Ok(addresses);
            }
        }
    }

    async fn cached(&self, host: &str, network_generation: u64) -> Option<Vec<IpAddr>> {
        let now = Instant::now();
        let mut cache = self.cache.lock().await;
        if let Some(entry) = cache.get(host) {
            if now < entry.expires && entry.network_generation == network_generation {
                return Some(entry.addresses.clone());
            }
        }
        cache.remove(host);
        None
    }
}

/// Waits for both address families, giving the slower one a short grace
/// period once the other has produced addresses. The result is complete only
/// when both lookups succeeded, so a failed family is retried soon instead of
/// being cached for the full TTL.
async fn merge_families<F>(ipv4: F, ipv6: F) -> (Vec<IpAddr>, bool)
where
    F: Future<Output = Result<Vec<IpAddr>>>,
{
    tokio::pin!(ipv4, ipv6);
    let (first, second) = tokio::select! {
        result = &mut ipv4 => (result, ipv6),
        result = &mut ipv6 => (result, ipv4),
    };
    match first {
        Ok(mut addresses) if !addresses.is_empty() => match timeout(FAMILY_GRACE, second).await {
            Ok(Ok(other)) => {
                addresses.extend(other);
                (addresses, true)
            }
            Ok(Err(_)) | Err(_) => (addresses, false),
        },
        first => match second.await {
            Ok(addresses) => (addresses, first.is_ok()),
            Err(_) => (Vec::new(), false),
        },
    }
}

/// Parses a reply to `query`. `Ok(None)` means the packet does not answer
/// this query and should be ignored; errors are failures worth retrying.
fn parse_response(response: &[u8], id: u16, query: &Query) -> Result<Option<Vec<IpAddr>>> {
    let Ok(response) = Message::from_vec(response) else {
        return Ok(None);
    };
    if response.id() != id
        || response.message_type() != MessageType::Response
        || response.queries() != std::slice::from_ref(query)
    {
        return Ok(None);
    }
    if response.truncated() {
        bail!("resolve ECH-TLS node");
    }
    match response.response_code() {
        ResponseCode::NoError => {}
        ResponseCode::NXDomain => return Ok(Some(Vec::new())),
        _ => bail!("resolve ECH-TLS node"),
    }
    Ok(Some(
        response
            .answers()
            .iter()
            .filter_map(|record| match (query.query_type(), record.data()) {
                (RecordType::A, RData::A(address)) => Some(IpAddr::V4((*address).into())),
                (RecordType::AAAA, RData::AAAA(address)) => Some(IpAddr::V6((*address).into())),
                _ => None,
            })
            .collect(),
    ))
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

    #[tokio::test]
    async fn cached_addresses_are_scoped_to_network_generation() {
        let resolver = PrivateDnsResolver::built_in().unwrap();
        resolver.cache.lock().await.insert(
            "node.cloud-nodes.com".to_owned(),
            CacheEntry {
                addresses: vec!["192.0.2.1".parse().unwrap()],
                expires: Instant::now() + Duration::from_secs(60),
                network_generation: 7,
            },
        );
        assert!(resolver.cached("node.cloud-nodes.com", 7).await.is_some());
        assert!(resolver.cached("node.cloud-nodes.com", 8).await.is_none());
    }

    async fn family(delay_ms: u64, result: Option<&str>) -> Result<Vec<IpAddr>> {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        match result {
            Some(address) => Ok(vec![address.parse().unwrap()]),
            None => bail!("lookup failed"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn failed_family_is_never_reported_complete() {
        let both = merge_families(
            family(10, Some("192.0.2.1")),
            family(20, Some("2001:db8::1")),
        );
        assert!(both.await.1);

        let ipv4_failed = merge_families(family(10, None), family(20, Some("2001:db8::1")));
        let (addresses, complete) = ipv4_failed.await;
        assert_eq!(addresses, ["2001:db8::1".parse::<IpAddr>().unwrap()]);
        assert!(!complete);

        let ipv6_failed = merge_families(family(10, Some("192.0.2.1")), family(20, None));
        let (addresses, complete) = ipv6_failed.await;
        assert_eq!(addresses, ["192.0.2.1".parse::<IpAddr>().unwrap()]);
        assert!(!complete);

        let ipv6_slow = merge_families(family(10, Some("192.0.2.1")), family(5_000, None));
        assert!(!ipv6_slow.await.1);

        let both_failed = merge_families(family(10, None), family(20, None));
        assert_eq!(both_failed.await, (Vec::new(), false));
    }

    fn response_to(query: &Query, id: u16, edit: impl FnOnce(&mut Message)) -> Vec<u8> {
        let mut message = Message::new();
        message
            .set_id(id)
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .add_query(query.clone());
        message.add_answer(hickory_proto::rr::Record::from_rdata(
            query.name().clone(),
            60,
            RData::A("192.0.2.1".parse().unwrap()),
        ));
        message.add_answer(hickory_proto::rr::Record::from_rdata(
            query.name().clone(),
            60,
            RData::AAAA("2001:db8::1".parse().unwrap()),
        ));
        edit(&mut message);
        message.to_vec().unwrap()
    }

    #[test]
    fn responses_must_answer_the_sent_question() {
        let query = Query::query(
            Name::from_ascii("a.node.cloud-nodes.com.").unwrap(),
            RecordType::A,
        );
        let ok = response_to(&query, 7, |_| {});
        assert_eq!(
            parse_response(&ok, 7, &query).unwrap(),
            Some(vec!["192.0.2.1".parse().unwrap()])
        );

        assert_eq!(parse_response(&ok, 8, &query).unwrap(), None);
        assert_eq!(parse_response(b"garbage", 7, &query).unwrap(), None);
        let request = response_to(&query, 7, |message| {
            message.set_message_type(MessageType::Query);
        });
        assert_eq!(parse_response(&request, 7, &query).unwrap(), None);
        let other_name = Query::query(
            Name::from_ascii("b.node.cloud-nodes.com.").unwrap(),
            RecordType::A,
        );
        let other = response_to(&other_name, 7, |_| {});
        assert_eq!(parse_response(&other, 7, &query).unwrap(), None);

        let upper = Query::query(
            Name::from_ascii("A.Node.Cloud-Nodes.Com.").unwrap(),
            RecordType::A,
        );
        let upper = response_to(&upper, 7, |_| {});
        assert!(parse_response(&upper, 7, &query).unwrap().is_some());

        let failed = response_to(&query, 7, |message| {
            message.set_response_code(ResponseCode::ServFail);
        });
        assert!(parse_response(&failed, 7, &query).is_err());
        let missing = response_to(&query, 7, |message| {
            message.set_response_code(ResponseCode::NXDomain);
        });
        assert_eq!(
            parse_response(&missing, 7, &query).unwrap(),
            Some(Vec::new())
        );
        let truncated = response_to(&query, 7, |message| {
            message.set_truncated(true);
        });
        assert!(parse_response(&truncated, 7, &query).is_err());
    }
}
