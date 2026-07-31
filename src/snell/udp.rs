use std::net::{IpAddr, SocketAddr};

use anyhow::{Result, bail};

const MAX_RECORD_PAYLOAD_SIZE: usize = (1 << 14) - 1;

pub fn encode_udp_request(
    frame: &mut Vec<u8>,
    host: &str,
    port: u16,
    payload: &[u8],
) -> Result<()> {
    if host.is_empty() {
        bail!("Snell UDP target host cannot be empty");
    }
    if port == 0 {
        bail!("Snell UDP target port cannot be zero");
    }
    frame.clear();
    frame.reserve(5 + host.len() + payload.len());
    frame.push(1);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            frame.extend_from_slice(&[0, 4]);
            frame.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            frame.extend_from_slice(&[0, 6]);
            frame.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            if host.len() > 255 {
                bail!("Snell UDP target host is longer than 255 bytes");
            }
            frame.push(host.len() as u8);
            frame.extend_from_slice(host.as_bytes());
        }
    }
    frame.extend_from_slice(&port.to_be_bytes());
    if frame.len() + payload.len() > MAX_RECORD_PAYLOAD_SIZE {
        bail!("Snell UDP datagram is too large");
    }
    frame.extend_from_slice(payload);
    Ok(())
}

pub fn decode_udp_response(frame: &[u8]) -> Result<(SocketAddr, &[u8])> {
    let Some(address_type) = frame.first() else {
        bail!("Snell UDP response is empty");
    };
    match address_type {
        4 => {
            if frame.len() < 7 {
                bail!("Snell UDP response is truncated");
            }
            let port = u16::from_be_bytes([frame[5], frame[6]]);
            if port == 0 {
                bail!("Snell UDP response port is zero");
            }
            let ip = std::net::Ipv4Addr::new(frame[1], frame[2], frame[3], frame[4]);
            Ok((SocketAddr::new(ip.into(), port), &frame[7..]))
        }
        6 => {
            if frame.len() < 19 {
                bail!("Snell UDP response is truncated");
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&frame[1..17]);
            let port = u16::from_be_bytes([frame[17], frame[18]]);
            if port == 0 {
                bail!("Snell UDP response port is zero");
            }
            Ok((
                SocketAddr::new(std::net::Ipv6Addr::from(octets).into(), port),
                &frame[19..],
            ))
        }
        _ => bail!("Snell UDP response address type is invalid"),
    }
}
