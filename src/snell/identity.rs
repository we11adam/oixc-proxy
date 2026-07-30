use anyhow::{Result, bail};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

const IDENTITY_V2_MAGIC: &[u8; 8] = b"DLSNID02";
const IDENTITY_V2_ROOT_LABEL: &[u8] = b"oix/snell-ech/2/auth-root";
const IDENTITY_COMPONENT_SIZE: usize = 16;

pub type Exporter = [u8; 32];
pub type IdentityNonce = [u8; 16];
type HmacSha256 = Hmac<Sha256>;

pub fn build_identity_v2(
    psk: &str,
    exporter: &Exporter,
    nonce: &IdentityNonce,
) -> Result<[u8; 56]> {
    if psk.is_empty() {
        bail!("PSK cannot be empty");
    }

    let root_label_hash = Sha256::digest(IDENTITY_V2_ROOT_LABEL);
    let root = hmac_sha256(&root_label_hash, psk.as_bytes());
    let identity_key = derive_key(&root, b"identity");
    let authentication_key = derive_key(&root, b"authentication");
    let identity = &identity_key[..IDENTITY_COMPONENT_SIZE];

    let mut context = Vec::with_capacity(8 + 32 + 16 + 16);
    context.extend_from_slice(IDENTITY_V2_MAGIC);
    context.extend_from_slice(exporter);
    context.extend_from_slice(nonce);
    context.extend_from_slice(identity);
    let authentication = hmac_sha256(&authentication_key, &context);

    let mut result = [0u8; 56];
    result[..16].copy_from_slice(nonce);
    result[16..24].copy_from_slice(IDENTITY_V2_MAGIC);
    result[24..40].copy_from_slice(identity);
    result[40..].copy_from_slice(&authentication[..IDENTITY_COMPONENT_SIZE]);
    Ok(result)
}

fn derive_key(root: &[u8], label: &[u8]) -> [u8; 32] {
    let mut message = Vec::with_capacity(label.len() + 1);
    message.extend_from_slice(label);
    message.push(1);
    hmac_sha256(root, &message)
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts every key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_matches_go_known_vector() {
        let mut exporter = [0u8; 32];
        for (index, value) in exporter.iter_mut().enumerate() {
            *value = index as u8;
        }
        let mut nonce = [0u8; 16];
        for (index, value) in nonce.iter_mut().enumerate() {
            *value = 0xa0 + index as u8;
        }
        let got = build_identity_v2("test-psk-2026", &exporter, &nonce).unwrap();
        assert_eq!(
            hex::encode(got),
            concat!(
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                "444c534e49443032",
                "0494ed911b162dc772388b2de2a92fdd",
                "53c9a6fc01e213a447210cefa2537d51"
            )
        );
    }
}
