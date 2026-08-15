use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

#[tokio::test]
#[ignore = "requires a running oixc-proxy and live managed node"]
async fn socks5_udp_associate_resolves_dns() {
    let socks_address =
        std::env::var("OIXC_LIVE_SOCKS").unwrap_or_else(|_| "127.0.0.1:16172".to_owned());
    let provider_url = std::env::var("OIXC_LIVE_PROVIDER")
        .unwrap_or_else(|_| "http://127.0.0.1:16173/surge-proxies.conf".to_owned());
    let provider = reqwest::get(provider_url)
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let first = provider.lines().next().expect("provider contains a node");
    let fields = first.split(", ").collect::<Vec<_>>();
    let username = fields[3].as_bytes();
    let password = fields[4].as_bytes();

    let mut control = TcpStream::connect(socks_address).await.unwrap();
    control.write_all(&[5, 1, 2]).await.unwrap();
    let mut method = [0u8; 2];
    control.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2]);
    let mut authentication = Vec::with_capacity(3 + username.len() + password.len());
    authentication.extend_from_slice(&[1, username.len() as u8]);
    authentication.extend_from_slice(username);
    authentication.push(password.len() as u8);
    authentication.extend_from_slice(password);
    control.write_all(&authentication).await.unwrap();
    let mut auth_response = [0u8; 2];
    control.read_exact(&mut auth_response).await.unwrap();
    assert_eq!(auth_response, [1, 0]);

    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let relay = read_socks_reply(&mut control).await;
    let local = UdpSocket::bind(if relay.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await
    .unwrap();

    let mut query = Message::new();
    query
        .set_id(0x6172)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
    let dns = query.to_vec().unwrap();
    let mut datagram = vec![0, 0, 0, 1, 1, 1, 1, 1, 0, 53];
    datagram.extend_from_slice(&dns);
    local.send_to(&datagram, relay).await.unwrap();

    let mut response = [0u8; 4096];
    let (length, _) = timeout(Duration::from_secs(15), local.recv_from(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(length > 10);
    assert_eq!(&response[..3], &[0, 0, 0]);
    let dns_offset = match response[3] {
        1 => 10,
        4 => 22,
        value => panic!("unexpected SOCKS UDP address type {value}"),
    };
    let decoded = Message::from_vec(&response[dns_offset..length]).unwrap();
    assert_eq!(decoded.id(), 0x6172);
    assert!(!decoded.answers().is_empty());
}

async fn read_socks_reply(stream: &mut TcpStream) -> SocketAddr {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(&header[..3], &[5, 0, 0]);
    let ip = match header[3] {
        1 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await.unwrap();
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        4 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await.unwrap();
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        value => panic!("unexpected SOCKS reply address type {value}"),
    };
    let port = stream.read_u16().await.unwrap();
    SocketAddr::new(ip, port)
}
