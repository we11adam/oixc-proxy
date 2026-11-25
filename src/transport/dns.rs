//! Physical-egress DNS recovery for ordinary API and node hostnames.
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Result, bail};
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, lookup_host};
use tokio::sync::{Mutex, watch};
use tokio::time::{Instant, timeout};

use crate::network::{EgressKey, NetworkSnapshot, bind_udp_socket};

const BUDGET: Duration = Duration::from_secs(9);
const TTL: Duration = Duration::from_secs(60);
const MAX_ENTRIES: usize = 1024;
type Answer = std::result::Result<Vec<IpAddr>, ()>;
type Key = (String, EgressKey);

#[derive(Default)]
struct State {
    cache: HashMap<Key, (Instant, Vec<IpAddr>)>,
    pending: HashMap<Key, watch::Sender<Option<Answer>>>,
}

#[derive(Clone)]
pub(crate) struct DirectDns {
    state: Arc<Mutex<State>>,
    servers: Arc<Vec<SocketAddr>>,
}

impl DirectDns {
    pub(crate) fn shared() -> Self {
        static SHARED: OnceLock<DirectDns> = OnceLock::new();
        SHARED
            .get_or_init(|| Self {
                state: Arc::new(Mutex::new(State::default())),
                servers: Arc::new(vec![
                    "223.5.5.5:53".parse().unwrap(),
                    "119.29.29.29:53".parse().unwrap(),
                ]),
            })
            .clone()
    }

    pub(crate) async fn lookup(
        &self,
        host: &str,
        network: &NetworkSnapshot,
    ) -> Result<Vec<IpAddr>> {
        let resolver = self.clone();
        let owned_host = host.to_owned();
        let owned_network = network.clone();
        self.lookup_using(host, network, async move {
            resolver.resolve(&owned_host, &owned_network).await
        })
        .await
    }

    async fn lookup_using<F>(
        &self,
        host: &str,
        network: &NetworkSnapshot,
        operation: F,
    ) -> Result<Vec<IpAddr>>
    where
        F: Future<Output = Result<Vec<IpAddr>>> + Send + 'static,
    {
        if let Ok(ip) = host.parse() {
            return Ok(vec![ip]);
        }
        // Include the complete physical selection as different monitors can
        // have the same numeric generation. Never reuse answers across egresses.
        let key = (
            host.trim_end_matches('.').to_ascii_lowercase(),
            network.egress_key(),
        );
        let now = Instant::now();
        let mut state = self.state.lock().await;
        if let Some((until, ips)) = state.cache.get(&key) {
            if *until > now {
                return Ok(ips.clone());
            }
            state.cache.remove(&key);
        }
        let mut rx = if let Some(tx) = state.pending.get(&key) {
            tx.subscribe()
        } else {
            if state.pending.len() >= MAX_ENTRIES {
                bail!("DNS recovery capacity exceeded");
            }
            let (tx, rx) = watch::channel(None);
            state.pending.insert(key.clone(), tx.clone());
            let resolver = self.clone();
            // The bounded owner survives cancellation of any individual waiter.
            tokio::spawn(async move {
                let answer = timeout(BUDGET, operation)
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .ok_or(());
                let mut state = resolver.state.lock().await;
                if let Ok(ips) = &answer {
                    let now = Instant::now();
                    if state.cache.len() >= MAX_ENTRIES {
                        state.cache.retain(|_, (until, _)| *until > now);
                        if state.cache.len() >= MAX_ENTRIES {
                            state.cache.clear();
                        }
                    }
                    state.cache.insert(key.clone(), (now + TTL, ips.clone()));
                }
                tx.send_replace(Some(answer));
                state.pending.remove(&key);
            });
            rx
        };
        drop(state);
        loop {
            if let Some(answer) = rx.borrow_and_update().clone() {
                return answer.map_err(|_| anyhow::anyhow!("physical DNS resolution failed"));
            }
            rx.changed()
                .await
                .map_err(|_| anyhow::anyhow!("DNS recovery stopped"))?;
        }
    }

    async fn resolve(&self, host: &str, network: &NetworkSnapshot) -> Result<Vec<IpAddr>> {
        if let Ok(Ok(addresses)) = timeout(Duration::from_secs(1), lookup_host((host, 0))).await {
            let ips = usable(addresses.map(|a| a.ip()).collect());
            if !ips.is_empty() {
                return Ok(ips);
            }
        }
        self.recover(host, network).await
    }

    async fn recover(&self, host: &str, network: &NetworkSnapshot) -> Result<Vec<IpAddr>> {
        for &server in self.servers.iter() {
            let lookup = async {
                let (ips, _) = super::private_dns::merge_families(
                    query(server, host, RecordType::A, network),
                    query(server, host, RecordType::AAAA, network),
                )
                .await;
                usable(ips)
            };
            if let Ok(ips) = timeout(Duration::from_secs(3), lookup).await
                && !ips.is_empty()
            {
                return Ok(ips);
            }
        }
        bail!("physical DNS recovery failed")
    }
}

fn usable(ips: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut result = Vec::new();
    for ip in ips {
        let fake =
            matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 198 && v4.octets()[1] & 0xfe == 18);
        if !fake && !ip.is_unspecified() && !ip.is_multicast() && !result.contains(&ip) {
            result.push(ip);
        }
    }
    result
}

/// Retry UDP failures and truncated replies with DNS-over-TCP, on the same
/// physical egress. The caller supplies the overall deadline.
pub(super) async fn query(
    server: SocketAddr,
    host: &str,
    kind: RecordType,
    network: &NetworkSnapshot,
) -> Result<Vec<IpAddr>> {
    let mut bytes = [0; 2];
    getrandom::fill(&mut bytes)?;
    let id = u16::from_be_bytes(bytes);
    let question = Query::query(
        Name::from_ascii(format!("{}.", host.trim_end_matches('.')))?,
        kind,
    );
    let mut request = Message::new();
    request
        .set_id(id)
        .set_recursion_desired(true)
        .add_query(question.clone());
    let packet = request.to_vec()?;
    let udp = async {
        let socket = bind_udp_socket(network, server).await?;
        socket.connect(server).await?;
        socket.send(&packet).await?;
        let mut buffer = [0; 4096];
        loop {
            let n = socket.recv(&mut buffer).await?;
            if let Some(ips) = super::private_dns::parse_response(&buffer[..n], id, &question)? {
                return Ok::<_, anyhow::Error>(ips);
            }
        }
    };
    if let Ok(Ok(ips)) = timeout(Duration::from_secs(1), udp).await {
        return Ok(ips);
    }
    let socket = if server.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    network.bind_tcp(&socket, server)?;
    let mut tcp = socket.connect(server).await?;
    tcp.write_u16(u16::try_from(packet.len())?).await?;
    tcp.write_all(&packet).await?;
    let len = tcp.read_u16().await?;
    let mut buffer = vec![0; usize::from(len)];
    tcp.read_exact(&mut buffer).await?;
    super::private_dns::parse_response(&buffer, id, &question)?
        .ok_or_else(|| anyhow::anyhow!("DNS TCP response does not match query"))
}

pub(crate) struct ApiDns(pub(crate) NetworkSnapshot);

impl reqwest::dns::Resolve for ApiDns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        let network = self.0.clone();
        Box::pin(async move {
            let ips = DirectDns::shared()
                .lookup(&host, &network)
                .await
                .map_err(|_| std::io::Error::other("API DNS resolution failed"))?;
            Ok(Box::new(ips.into_iter().map(|ip| SocketAddr::new(ip, 0))) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::MessageType;

    #[tokio::test]
    async fn canceled_waiter_does_not_cancel_shared_recovery_or_poison_cache() {
        let network = crate::network::NetworkMonitor::test_unbound()
            .snapshot()
            .await;
        let resolver = DirectDns {
            state: Arc::new(Mutex::new(State::default())),
            servers: Arc::new(vec![]),
        };
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let r = resolver.clone();
        let n = network.clone();
        let first = tokio::spawn(async move {
            r.lookup_using("mock.example.test", &n, async {
                started_tx.send(()).unwrap();
                release_rx.await.unwrap();
                Ok(vec!["192.0.2.1".parse().unwrap()])
            })
            .await
        });
        started_rx.await.unwrap();
        first.abort();
        let r = resolver.clone();
        let n = network.clone();
        let follower = tokio::spawn(async move {
            r.lookup_using("mock.example.test", &n, async {
                panic!("duplicate lookup must not execute");
            })
            .await
        });
        tokio::task::yield_now().await;
        release_tx.send(()).unwrap();
        assert_eq!(
            follower.await.unwrap().unwrap(),
            ["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            resolver
                .lookup_using("mock.example.test", &network, async {
                    panic!("cache hit must not query")
                })
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(resolver.state.lock().await.pending.is_empty());
    }

    #[test]
    fn removes_fake_ip_without_discarding_valid_private_or_v6_addresses() {
        let addresses = [
            "198.18.0.1",
            "198.19.255.254",
            "192.168.1.1",
            "2001:db8::1",
            "192.168.1.1",
        ];
        assert_eq!(
            usable(addresses.map(|a| a.parse().unwrap()).to_vec()),
            [
                "192.168.1.1".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse().unwrap()
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn abandoned_recovery_expires_and_a_later_request_can_retry() {
        let network = crate::network::NetworkMonitor::test_unbound()
            .snapshot()
            .await;
        let resolver = DirectDns {
            state: Arc::new(Mutex::new(State::default())),
            servers: Arc::new(vec![]),
        };
        let r = resolver.clone();
        let n = network.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let first = tokio::spawn(async move {
            r.lookup_using("mock.example.test", &n, async {
                tx.send(()).unwrap();
                std::future::pending().await
            })
            .await
        });
        rx.await.unwrap();
        first.abort();
        tokio::time::advance(BUDGET).await;
        tokio::task::yield_now().await;
        assert!(resolver.state.lock().await.pending.is_empty());
        let ips = resolver
            .lookup_using("mock.example.test", &network, async {
                Ok(vec!["192.0.2.2".parse().unwrap()])
            })
            .await
            .unwrap();
        assert_eq!(ips, ["192.0.2.2".parse::<IpAddr>().unwrap()]);
        tokio::time::advance(TTL).await;
        let ips = resolver
            .lookup_using("mock.example.test", &network, async {
                Ok(vec!["192.0.2.3".parse().unwrap()])
            })
            .await
            .unwrap();
        assert_eq!(ips, ["192.0.2.3".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn physical_recovery_checks_question_and_uses_tcp_for_truncation() {
        let network = crate::network::NetworkMonitor::test_unbound()
            .snapshot()
            .await;
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let udp = tokio::net::UdpSocket::bind(addr).await.unwrap();
        let peer = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            let (n, from) = udp.recv_from(&mut buffer).await.unwrap();
            let mut response = Message::from_vec(&buffer[..n]).unwrap();
            let id = response.id();
            response
                .set_id(id.wrapping_add(1))
                .set_message_type(MessageType::Response);
            udp.send_to(&response.to_vec().unwrap(), from)
                .await
                .unwrap();
            response.set_id(id);
            response
                .set_message_type(MessageType::Response)
                .set_truncated(true);
            udp.send_to(&response.to_vec().unwrap(), from)
                .await
                .unwrap();
            let (mut stream, _) = tcp.accept().await.unwrap();
            let n = stream.read_u16().await.unwrap();
            let mut buffer = vec![0; usize::from(n)];
            stream.read_exact(&mut buffer).await.unwrap();
            let mut response = Message::from_vec(&buffer).unwrap();
            let name = response.queries()[0].name().clone();
            response.set_message_type(MessageType::Response).add_answer(
                hickory_proto::rr::Record::from_rdata(
                    name,
                    60,
                    hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(
                        "192.0.2.1".parse().unwrap(),
                    )),
                ),
            );
            let bytes = response.to_vec().unwrap();
            stream.write_u16(bytes.len() as u16).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        let answer = timeout(
            Duration::from_secs(3),
            query(addr, "mock.example.test", RecordType::A, &network),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(answer, ["192.0.2.1".parse::<IpAddr>().unwrap()]);
        peer.await.unwrap();
    }
}
