use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce, Tag};
use anyhow::{Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::IdentityNonce;

const RECORD_NONCE_SIZE: usize = 12;
const RECORD_HEADER_PLAIN_SIZE: usize = 7;
const RECORD_HEADER_CIPHER_SIZE: usize = RECORD_HEADER_PLAIN_SIZE + 16;
const MAX_RECORD_PAYLOAD_SIZE: usize = (1 << 14) - 1;
const WRITE_BATCH_LIMIT: usize = 64 << 10;

#[derive(Debug, thiserror::Error)]
#[error("Snell zero-length record")]
pub struct ZeroRecord;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecordKind {
    Payload,
    Zero,
}

pub fn derive_record_key(psk: &str, salt: &IdentityNonce) -> Result<[u8; 16]> {
    if psk.is_empty() {
        bail!("PSK cannot be empty");
    }
    let params =
        Params::new(8, 3, 1, Some(32)).map_err(|_| anyhow::anyhow!("create Snell record KDF"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut derived = [0u8; 32];
    argon
        .hash_password_into(psk.as_bytes(), salt, &mut derived)
        .map_err(|_| anyhow::anyhow!("derive Snell record key"))?;
    let mut key = [0u8; 16];
    key.copy_from_slice(&derived[..16]);
    Ok(key)
}

pub struct RecordWriter<W> {
    writer: W,
    aead: Aes128Gcm,
    salt: IdentityNonce,
    salt_sent: bool,
    nonce: [u8; RECORD_NONCE_SIZE],
    scratch: Vec<u8>,
}

impl<W: AsyncWrite + Unpin> RecordWriter<W> {
    pub fn new(writer: W, psk: &str, salt: IdentityNonce) -> Result<Self> {
        let key = derive_record_key(psk, &salt)?;
        Ok(Self {
            writer,
            aead: Aes128Gcm::new_from_slice(&key)
                .map_err(|_| anyhow::anyhow!("create Snell AES-GCM"))?,
            salt,
            salt_sent: false,
            nonce: [0; RECORD_NONCE_SIZE],
            scratch: Vec::new(),
        })
    }

    pub fn mark_salt_sent(&mut self) {
        self.salt_sent = true;
    }

    pub fn encode_frame(&mut self, payload: &[u8], padding_length: usize) -> Result<Vec<u8>> {
        let mut frame = Vec::new();
        self.encode_frame_append(&mut frame, payload, padding_length)?;
        Ok(frame)
    }

    fn encode_frame_append(
        &mut self,
        frame: &mut Vec<u8>,
        payload: &[u8],
        padding_length: usize,
    ) -> Result<()> {
        if payload.len() > MAX_RECORD_PAYLOAD_SIZE || padding_length > MAX_RECORD_PAYLOAD_SIZE {
            bail!("Snell record size is invalid");
        }
        if payload.is_empty() && padding_length != 0 {
            bail!("zero-length Snell record cannot contain padding");
        }

        frame.reserve(
            (!self.salt_sent as usize) * 16
                + RECORD_HEADER_CIPHER_SIZE
                + padding_length
                + if payload.is_empty() {
                    0
                } else {
                    payload.len() + 16
                },
        );
        if !self.salt_sent {
            frame.extend_from_slice(&self.salt);
            self.salt_sent = true;
        }
        let header_start = frame.len();
        frame.resize(header_start + RECORD_HEADER_PLAIN_SIZE, 0);
        let header = &mut frame[header_start..];
        header[0] = 4;
        header[3..5].copy_from_slice(&(padding_length as u16).to_be_bytes());
        header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let tag = self
            .aead
            .encrypt_in_place_detached(Nonce::from_slice(&self.nonce), &[], header)
            .map_err(|_| anyhow::anyhow!("encrypt Snell record header"))?;
        increment_nonce(&mut self.nonce);
        frame.extend_from_slice(&tag);

        let padding_start = frame.len();
        frame.resize(padding_start + padding_length, 0);
        if padding_length != 0 {
            getrandom::fill(&mut frame[padding_start..])
                .map_err(|_| anyhow::anyhow!("generate Snell record padding"))?;
        }
        let payload_start = frame.len();
        if !payload.is_empty() {
            frame.extend_from_slice(payload);
            let tag = self
                .aead
                .encrypt_in_place_detached(
                    Nonce::from_slice(&self.nonce),
                    &[],
                    &mut frame[payload_start..],
                )
                .map_err(|_| anyhow::anyhow!("encrypt Snell record payload"))?;
            increment_nonce(&mut self.nonce);
            frame.extend_from_slice(&tag);
        }
        let (before_payload, payload_ciphertext) = frame.split_at_mut(payload_start);
        swap_padding(&mut before_payload[padding_start..], payload_ciphertext);
        Ok(())
    }

    pub async fn write_frame(&mut self, payload: &[u8], padding_length: usize) -> Result<()> {
        let mut frame = std::mem::take(&mut self.scratch);
        frame.clear();
        let encoded = self.encode_frame_append(&mut frame, payload, padding_length);
        let result = match encoded {
            Ok(()) => self
                .writer
                .write_all(&frame)
                .await
                .map_err(|error| anyhow::anyhow!("write Snell record: {error}")),
            Err(error) => Err(error),
        };
        self.scratch = frame;
        result
    }

    pub async fn write_payload(&mut self, content: &[u8]) -> Result<()> {
        let mut frame = std::mem::take(&mut self.scratch);
        frame.clear();
        let mut result = Ok(());
        for chunk in content.chunks(MAX_RECORD_PAYLOAD_SIZE) {
            if let Err(error) = self.encode_frame_append(&mut frame, chunk, 0) {
                result = Err(error);
                break;
            }
            if frame.len() >= WRITE_BATCH_LIMIT {
                if let Err(error) = self.writer.write_all(&frame).await {
                    result = Err(anyhow::anyhow!("write Snell record: {error}"));
                    break;
                }
                frame.clear();
            }
        }
        if result.is_ok() && !frame.is_empty() {
            result = self
                .writer
                .write_all(&frame)
                .await
                .map_err(|error| anyhow::anyhow!("write Snell record: {error}"));
        }
        self.scratch = frame;
        result
    }

    pub async fn write_raw_all(&mut self, content: &[u8]) -> Result<()> {
        self.writer
            .write_all(content)
            .await
            .map_err(|error| anyhow::anyhow!("write Snell initial flight: {error}"))
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.writer
            .shutdown()
            .await
            .map_err(|error| anyhow::anyhow!("close Snell transport: {error}"))
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

pub struct RecordReader<R> {
    reader: R,
    psk: String,
    aead: Option<Aes128Gcm>,
    nonce: [u8; RECORD_NONCE_SIZE],
}

impl<R: AsyncRead + Unpin> RecordReader<R> {
    pub fn new(reader: R, psk: impl Into<String>) -> Self {
        Self {
            reader,
            psk: psk.into(),
            aead: None,
            nonce: [0; RECORD_NONCE_SIZE],
        }
    }

    pub fn with_salt(reader: R, psk: impl Into<String>, salt: IdentityNonce) -> Result<Self> {
        let psk = psk.into();
        let key = derive_record_key(&psk, &salt)?;
        Ok(Self {
            reader,
            psk,
            aead: Some(
                Aes128Gcm::new_from_slice(&key)
                    .map_err(|_| anyhow::anyhow!("create Snell AES-GCM"))?,
            ),
            nonce: [0; RECORD_NONCE_SIZE],
        })
    }

    pub async fn read_frame(&mut self) -> Result<Vec<u8>> {
        let mut frame = Vec::new();
        match self.read_frame_into(&mut frame).await? {
            RecordKind::Payload => Ok(frame),
            RecordKind::Zero => Err(ZeroRecord.into()),
        }
    }

    pub(crate) async fn read_frame_into(&mut self, frame: &mut Vec<u8>) -> Result<RecordKind> {
        frame.clear();
        if self.aead.is_none() {
            let mut salt = [0u8; 16];
            self.reader
                .read_exact(&mut salt)
                .await
                .map_err(|error| anyhow::anyhow!("read Snell record salt: {error}"))?;
            let key = derive_record_key(&self.psk, &salt)?;
            self.aead = Some(
                Aes128Gcm::new_from_slice(&key)
                    .map_err(|_| anyhow::anyhow!("create Snell AES-GCM"))?,
            );
        }
        let aead = self.aead.as_ref().expect("initialized above");
        let mut encrypted_header = [0u8; RECORD_HEADER_CIPHER_SIZE];
        self.reader
            .read_exact(&mut encrypted_header)
            .await
            .map_err(|error| anyhow::anyhow!("read Snell record header: {error}"))?;
        let (header, header_tag) = encrypted_header.split_at_mut(RECORD_HEADER_PLAIN_SIZE);
        aead.decrypt_in_place_detached(
            Nonce::from_slice(&self.nonce),
            &[],
            header,
            Tag::from_slice(header_tag),
        )
        .map_err(|_| anyhow::anyhow!("authenticate Snell record header"))?;
        increment_nonce(&mut self.nonce);
        if header[0] != 4 {
            bail!("Snell record header is invalid");
        }
        let padding_length = u16::from_be_bytes([header[3], header[4]]) as usize;
        let payload_length = u16::from_be_bytes([header[5], header[6]]) as usize;
        if payload_length > MAX_RECORD_PAYLOAD_SIZE || padding_length > MAX_RECORD_PAYLOAD_SIZE {
            bail!("Snell record size is invalid");
        }
        if payload_length == 0 {
            if padding_length != 0 {
                bail!("zero-length Snell record contains padding");
            }
            return Ok(RecordKind::Zero);
        }

        frame.resize(padding_length + payload_length + 16, 0);
        self.reader
            .read_exact(frame)
            .await
            .map_err(|error| anyhow::anyhow!("read Snell record payload: {error}"))?;
        let (padding, encrypted_payload) = frame.split_at_mut(padding_length);
        swap_padding(padding, encrypted_payload);
        let (payload, payload_tag) = encrypted_payload.split_at_mut(payload_length);
        aead.decrypt_in_place_detached(
            Nonce::from_slice(&self.nonce),
            &[],
            payload,
            Tag::from_slice(payload_tag),
        )
        .map_err(|_| anyhow::anyhow!("authenticate Snell record payload"))?;
        increment_nonce(&mut self.nonce);
        if padding_length != 0 {
            frame.copy_within(padding_length..padding_length + payload_length, 0);
        }
        frame.truncate(payload_length);
        Ok(RecordKind::Payload)
    }
}

fn swap_padding(padding: &mut [u8], payload_ciphertext: &mut [u8]) {
    let limit = padding.len().min(payload_ciphertext.len());
    for index in (0..limit).step_by(2) {
        std::mem::swap(&mut padding[index], &mut payload_ciphertext[index]);
    }
}

fn increment_nonce(nonce: &mut [u8]) {
    for value in nonce {
        *value = value.wrapping_add(1);
        if *value != 0 {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_key_matches_go_known_vector() {
        let mut salt = [0u8; 16];
        for (index, value) in salt.iter_mut().enumerate() {
            *value = 0xa0 + index as u8;
        }
        assert_eq!(
            hex::encode(derive_record_key("test-psk-2026", &salt).unwrap()),
            "f500729fecd347f4378828c643423963"
        );
    }

    #[tokio::test]
    async fn record_round_trip() {
        let salt = [7u8; 16];
        let (left, right) = tokio::io::duplex(4096);
        let mut writer = RecordWriter::new(left, "test-psk-2026", salt).unwrap();
        let mut reader = RecordReader::new(right, "test-psk-2026");
        let payload = b"authenticated test payload";
        writer.write_frame(payload, 17).await.unwrap();
        assert_eq!(reader.read_frame().await.unwrap(), payload);
    }

    #[tokio::test]
    async fn record_reader_reuses_output_capacity() {
        let salt = [9u8; 16];
        let (left, right) = tokio::io::duplex(4096);
        let mut writer = RecordWriter::new(left, "test-psk-2026", salt).unwrap();
        let mut reader = RecordReader::new(right, "test-psk-2026");
        writer.write_frame(b"first payload", 31).await.unwrap();
        writer.write_frame(b"second payload", 7).await.unwrap();

        let mut output = Vec::new();
        assert_eq!(
            reader.read_frame_into(&mut output).await.unwrap(),
            RecordKind::Payload
        );
        assert_eq!(output, b"first payload");
        let capacity = output.capacity();
        assert_eq!(
            reader.read_frame_into(&mut output).await.unwrap(),
            RecordKind::Payload
        );
        assert_eq!(output, b"second payload");
        assert_eq!(output.capacity(), capacity);

        writer.write_frame(&[], 0).await.unwrap();
        assert_eq!(
            reader.read_frame_into(&mut output).await.unwrap(),
            RecordKind::Zero
        );
        assert!(output.is_empty());
        assert_eq!(output.capacity(), capacity);
    }
}
