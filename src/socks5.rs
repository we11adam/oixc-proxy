use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::{Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::gateway::{GatewayManager, Route};
use crate::snell::{SnellPacketSession, SnellSession, SnellSessionReader, SnellSessionWriter};

const VERSION: u8 = 5;
const METHOD_NO_AUTH: u8 = 0;
const METHOD_USERNAME_PASSWORD: u8 = 2;
const METHOD_UNAVAILABLE: u8 = 0xff;
const COMMAND_CONNECT: u8 = 1;
const COMMAND_UDP_ASSOCIATE: u8 = 3;

#[derive(Clone)]
pub enum Mode {
    Dynamic(Arc<GatewayManager>),
    Fixed {
        route: Route,
        credentials: Option<Credentials>,
    },
}

#[derive(Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Clone)]
pub struct Options {
    pub handshake_timeout: Duration,
    pub udp_idle_timeout: Duration,
    pub udp_bind_address: IpAddr,
    pub mode: Mode,
}

struct Request {
    command: u8,
    host: String,
    port: u16,
}

pub async fn serve_connection(mut client: TcpStream, options: Options) -> Result<()> {
    let session_started = Instant::now();
    if options.handshake_timeout.is_zero() || options.handshake_timeout > Duration::from_secs(120) {
        bail!("SOCKS5 handshake timeout is invalid");
    }
    let handshake_started = Instant::now();
    let route_result = timeout(
        options.handshake_timeout,
        negotiate_and_read_request(&mut client, &options.mode),
    )
    .await;
    let route = match route_result {
        Ok(Ok(value)) => {
            crate::perftrace::stage("socks.handshake", handshake_started, true, &[]);
            value
        }
        Ok(Err(error)) => {
            crate::perftrace::stage("socks.handshake", handshake_started, false, &[]);
            return Err(error);
        }
        Err(_) => {
            crate::perftrace::stage("socks.handshake", handshake_started, false, &[]);
            bail!("SOCKS5 handshake timed out");
        }
    };
    let (route, request) = route;
    let result = match request.command {
        COMMAND_CONNECT => serve_connect(client, route, request).await,
        COMMAND_UDP_ASSOCIATE => {
            if !route.udp {
                write_reply(&mut client, 7, None).await?;
                bail!("SOCKS5 UDP ASSOCIATE is disabled");
            }
            serve_udp_associate(client, route, options).await
        }
        _ => {
            write_reply(&mut client, 7, None).await?;
            bail!("SOCKS5 command is unsupported");
        }
    };
    crate::perftrace::stage("socks.session", session_started, result.is_ok(), &[]);
    result
}

async fn negotiate_and_read_request(
    client: &mut TcpStream,
    mode: &Mode,
) -> Result<(Route, Request)> {
    let mut greeting = [0u8; 2];
    client
        .read_exact(&mut greeting)
        .await
        .map_err(|error| anyhow::anyhow!("read SOCKS5 greeting: {error}"))?;
    if greeting[0] != VERSION || greeting[1] == 0 {
        bail!("SOCKS5 greeting is invalid");
    }
    let mut methods = vec![0u8; greeting[1] as usize];
    client
        .read_exact(&mut methods)
        .await
        .map_err(|error| anyhow::anyhow!("read SOCKS5 methods: {error}"))?;
    let requires_auth = match mode {
        Mode::Dynamic(_) => true,
        Mode::Fixed { credentials, .. } => credentials.is_some(),
    };
    let selected = if requires_auth {
        METHOD_USERNAME_PASSWORD
    } else {
        METHOD_NO_AUTH
    };
    if !methods.contains(&selected) {
        client.write_all(&[VERSION, METHOD_UNAVAILABLE]).await?;
        bail!("SOCKS5 client did not offer the required authentication");
    }
    client.write_all(&[VERSION, selected]).await?;
    let route = if requires_auth {
        let (username, password) = read_credentials(client).await?;
        match mode {
            Mode::Dynamic(manager) => match manager.authenticate(&username, &password).await {
                Ok(route) => route,
                Err(_) => {
                    client.write_all(&[1, 1]).await?;
                    bail!("SOCKS5 authentication failed");
                }
            },
            Mode::Fixed {
                route,
                credentials: Some(expected),
            } => {
                if !constant_time_equal(username.as_bytes(), expected.username.as_bytes())
                    || !constant_time_equal(password.as_bytes(), expected.password.as_bytes())
                {
                    client.write_all(&[1, 1]).await?;
                    bail!("SOCKS5 authentication failed");
                }
                route.clone()
            }
            Mode::Fixed { .. } => unreachable!(),
        }
    } else {
        match mode {
            Mode::Fixed { route, .. } => route.clone(),
            Mode::Dynamic(_) => unreachable!(),
        }
    };
    if requires_auth {
        client.write_all(&[1, 0]).await?;
    }
    let request = read_request(client).await?;
    Ok((route, request))
}

async fn read_credentials(client: &mut TcpStream) -> Result<(String, String)> {
    let mut header = [0u8; 2];
    client
        .read_exact(&mut header)
        .await
        .map_err(|error| anyhow::anyhow!("read SOCKS5 authentication header: {error}"))?;
    if header[0] != 1 || header[1] == 0 {
        client.write_all(&[1, 1]).await?;
        bail!("SOCKS5 authentication request is invalid");
    }
    let mut username = vec![0u8; header[1] as usize];
    client.read_exact(&mut username).await?;
    let password_length = client.read_u8().await?;
    if password_length == 0 {
        client.write_all(&[1, 1]).await?;
        bail!("SOCKS5 password is empty");
    }
    let mut password = vec![0u8; password_length as usize];
    client.read_exact(&mut password).await?;
    Ok((
        String::from_utf8_lossy(&username).into_owned(),
        String::from_utf8_lossy(&password).into_owned(),
    ))
}

async fn read_request(client: &mut TcpStream) -> Result<Request> {
    let mut header = [0u8; 4];
    client
        .read_exact(&mut header)
        .await
        .map_err(|error| anyhow::anyhow!("read SOCKS5 request: {error}"))?;
    if header[0] != VERSION || header[2] != 0 {
        bail!("SOCKS5 request is invalid");
    }
    let host = read_host(client, header[3]).await?;
    let port = client.read_u16().await?;
    if port == 0 && header[1] != COMMAND_UDP_ASSOCIATE {
        bail!("SOCKS5 target port is zero");
    }
    Ok(Request {
        command: header[1],
        host,
        port,
    })
}

async fn read_host(client: &mut TcpStream, address_type: u8) -> Result<String> {
    match address_type {
        1 => {
            let mut octets = [0u8; 4];
            client.read_exact(&mut octets).await?;
            Ok(Ipv4Addr::from(octets).to_string())
        }
        4 => {
            let mut octets = [0u8; 16];
            client.read_exact(&mut octets).await?;
            Ok(std::net::Ipv6Addr::from(octets).to_string())
        }
        3 => {
            let length = client.read_u8().await? as usize;
            if length == 0 {
                bail!("SOCKS5 domain is empty");
            }
            let mut domain = vec![0u8; length];
            client.read_exact(&mut domain).await?;
            Ok(String::from_utf8_lossy(&domain).into_owned())
        }
        _ => bail!("SOCKS5 address type is unsupported"),
    }
}

async fn serve_connect(mut client: TcpStream, route: Route, request: Request) -> Result<()> {
    let started = Instant::now();
    let session = match route.client.dial_tcp(&request.host, request.port).await {
        Ok(session) => session,
        Err(_) => {
            crate::perftrace::stage("socks.upstream", started, false, &[]);
            write_reply(&mut client, 5, None).await?;
            bail!("open upstream tunnel");
        }
    };
    crate::perftrace::stage("socks.upstream", started, true, &[]);
    write_reply(&mut client, 0, Some(session.local_addr())).await?;
    relay(client, session).await
}

async fn relay(client: TcpStream, mut session: SnellSession) -> Result<()> {
    let started = Instant::now();
    crate::perftrace::event("socks.relay_start", &[]);
    let (client_read, client_write) = client.into_split();
    let close_timeout = session.close_timeout();
    let (clean, close_write_sent) = {
        let (remote_read, remote_write) = session.split();
        let mut upload = Box::pin(upload(client_read, remote_write));
        let mut download = Box::pin(download(client_write, remote_read));
        let mut close_write_sent = false;
        let clean = tokio::select! {
            upload_result = &mut upload => {
                close_write_sent = upload_result.is_ok();
                if upload_result.is_ok() {
                    timeout(close_timeout, download)
                        .await
                        .is_ok_and(|result| result.is_ok())
                } else {
                    false
                }
            }
            download_result = &mut download => {
                let _ = download_result;
                false
            }
        };
        (clean, close_write_sent)
    };
    session.finish(clean, close_write_sent).await;
    crate::perftrace::stage("socks.relay", started, clean, &[]);
    if clean {
        Ok(())
    } else {
        bail!("SOCKS5 relay ended with an error");
    }
}

async fn upload(mut client: OwnedReadHalf, mut session: SnellSessionWriter<'_>) -> Result<()> {
    let mut buffer = vec![0u8; 32 << 10];
    let mut first_data = true;
    loop {
        let read = client.read(&mut buffer).await?;
        if read == 0 {
            session.close_write().await?;
            return Ok(());
        }
        if first_data {
            crate::perftrace::event("socks.first_client_data", &[("bytes", read.to_string())]);
            first_data = false;
        }
        session.write(&buffer[..read]).await?;
    }
}

async fn download(mut client: OwnedWriteHalf, mut session: SnellSessionReader<'_>) -> Result<()> {
    let mut buffer = vec![0u8; 32 << 10];
    let mut first_data = true;
    loop {
        let read = session.read(&mut buffer).await?;
        if read == 0 {
            client.shutdown().await?;
            return Ok(());
        }
        if first_data {
            crate::perftrace::event("socks.first_upstream_data", &[("bytes", read.to_string())]);
            first_data = false;
        }
        client.write_all(&buffer[..read]).await?;
    }
}

async fn serve_udp_associate(mut client: TcpStream, route: Route, options: Options) -> Result<()> {
    if options.udp_bind_address.is_unspecified() {
        bail!("SOCKS5 UDP bind address must be a specific IP");
    }
    let local = Arc::new(
        UdpSocket::bind(SocketAddr::new(options.udp_bind_address, 0))
            .await
            .map_err(|_| anyhow::anyhow!("listen for SOCKS5 UDP relay"))?,
    );
    let upstream = Arc::new(
        route
            .client
            .dial_udp()
            .await
            .map_err(|_| anyhow::anyhow!("open upstream UDP association"))?,
    );
    write_reply(&mut client, 0, Some(local.local_addr()?)).await?;
    let control_ip = client.peer_addr().ok().map(|address| address.ip());
    let client_address = Arc::new(Mutex::new(None::<SocketAddr>));

    let local_to_upstream = udp_client_loop(
        local.clone(),
        upstream.clone(),
        client_address.clone(),
        control_ip,
        options.udp_idle_timeout,
    );
    let upstream_to_local =
        udp_upstream_loop(local.clone(), upstream.clone(), client_address.clone());
    let control = async {
        let mut discard = [0u8; 1024];
        while client.read(&mut discard).await? != 0 {}
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        _ = local_to_upstream => {}
        _ = upstream_to_local => {}
        _ = control => {}
    }
    if let Ok(upstream) = Arc::try_unwrap(upstream) {
        upstream.close().await;
    }
    Ok(())
}

async fn udp_client_loop(
    local: Arc<UdpSocket>,
    upstream: Arc<SnellPacketSession>,
    client_address: Arc<Mutex<Option<SocketAddr>>>,
    control_ip: Option<IpAddr>,
    idle_timeout: Duration,
) -> Result<()> {
    let mut buffer = vec![0u8; 64 << 10];
    loop {
        let (length, source) = timeout(idle_timeout, local.recv_from(&mut buffer))
            .await
            .map_err(|_| anyhow::anyhow!("SOCKS5 UDP relay idle timeout"))??;
        if control_ip.is_some_and(|ip| source.ip() != ip) {
            continue;
        }
        let mut allowed = client_address.lock().await;
        let first = allowed.get_or_insert(source);
        if *first != source {
            continue;
        }
        drop(allowed);
        let (host, port, payload) = decode_datagram(&buffer[..length])?;
        upstream.write_to_host(payload, &host, port).await?;
    }
}

async fn udp_upstream_loop(
    local: Arc<UdpSocket>,
    upstream: Arc<SnellPacketSession>,
    client_address: Arc<Mutex<Option<SocketAddr>>>,
) -> Result<()> {
    loop {
        let (source, payload) = upstream.read_from().await?;
        let Some(destination) = *client_address.lock().await else {
            continue;
        };
        let encoded = encode_datagram(source, &payload);
        local.send_to(&encoded, destination).await?;
    }
}

fn decode_datagram(packet: &[u8]) -> Result<(String, u16, &[u8])> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 {
        bail!("SOCKS5 UDP header is invalid");
    }
    if packet[2] != 0 {
        bail!("fragmented SOCKS5 UDP datagrams are unsupported");
    }
    let mut offset = 4;
    let host = match packet[3] {
        1 => {
            if packet.len() < offset + 4 + 2 {
                bail!("SOCKS5 UDP datagram is truncated");
            }
            let ip = Ipv4Addr::new(
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            );
            offset += 4;
            ip.to_string()
        }
        4 => {
            if packet.len() < offset + 16 + 2 {
                bail!("SOCKS5 UDP datagram is truncated");
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[offset..offset + 16]);
            offset += 16;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        3 => {
            if packet.len() <= offset {
                bail!("SOCKS5 UDP datagram is truncated");
            }
            let length = packet[offset] as usize;
            offset += 1;
            if length == 0 || packet.len() < offset + length + 2 {
                bail!("SOCKS5 UDP datagram is truncated");
            }
            let value = String::from_utf8_lossy(&packet[offset..offset + length]).into_owned();
            offset += length;
            value
        }
        _ => bail!("SOCKS5 address type is unsupported"),
    };
    if packet.len() < offset + 2 {
        bail!("SOCKS5 UDP datagram is truncated");
    }
    let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    offset += 2;
    if port == 0 {
        bail!("SOCKS5 target port is zero");
    }
    Ok((host, port, &packet[offset..]))
}

fn encode_datagram(address: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut result = vec![0, 0, 0];
    match address.ip() {
        IpAddr::V4(ip) => {
            result.push(1);
            result.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            result.push(4);
            result.extend_from_slice(&ip.octets());
        }
    }
    result.extend_from_slice(&address.port().to_be_bytes());
    result.extend_from_slice(payload);
    result
}

async fn write_reply(
    client: &mut TcpStream,
    status: u8,
    address: Option<SocketAddr>,
) -> Result<()> {
    let address = address.unwrap_or(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0));
    let mut reply = vec![VERSION, status, 0];
    match address.ip() {
        IpAddr::V4(ip) => {
            reply.push(1);
            reply.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            reply.push(4);
            reply.extend_from_slice(&ip.octets());
        }
    }
    reply.extend_from_slice(&address.port().to_be_bytes());
    client.write_all(&reply).await?;
    Ok(())
}

fn constant_time_equal(first: &[u8], second: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    first.ct_eq(second).into()
}
