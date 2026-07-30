use anyhow::{Result, bail};

pub fn build_connect_request(host: &str, port: u16, reuse: bool) -> Result<Vec<u8>> {
    if host.is_empty() {
        bail!("target host cannot be empty");
    }
    if host.len() > 255 {
        bail!("target host is longer than 255 bytes");
    }
    if port == 0 {
        bail!("target port cannot be zero");
    }
    let command = if reuse { 5 } else { 1 };
    let mut request = Vec::with_capacity(6 + host.len());
    request.extend_from_slice(&[1, command, 0, host.len() as u8]);
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    Ok(request)
}

pub fn build_udp_associate_request() -> [u8; 3] {
    [1, 6, 0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_request_matches_go_vector() {
        let mut expected = vec![1, 1, 0, 11];
        expected.extend_from_slice(b"example.com");
        expected.extend_from_slice(&[1, 0xbb]);
        assert_eq!(
            build_connect_request("example.com", 443, false).unwrap(),
            expected
        );
    }
}
