use anyhow::{Result, bail};
use md5::{Digest, Md5};
use std::collections::BTreeMap;
use tokio::io::{AsyncWrite, AsyncWriteExt};

const DEFAULT: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";

#[derive(Clone)]
pub(super) struct Scheme {
    pub hash: String,
    stop: u32,
    entries: BTreeMap<u32, Vec<Entry>>,
}

#[derive(Clone)]
enum Entry {
    Check,
    Range(usize, usize),
}

impl Default for Scheme {
    fn default() -> Self {
        Self::parse(DEFAULT.as_bytes()).expect("built-in AnyTLS padding")
    }
}

impl Scheme {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() > 8192 {
            bail!("AnyTLS padding scheme too large");
        }
        let rawstr = std::str::from_utf8(raw)
            .map_err(|_| anyhow::anyhow!("invalid AnyTLS padding scheme"))?;
        let mut stop = None;
        let mut entries = BTreeMap::new();
        for line in rawstr.lines() {
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("invalid AnyTLS padding entry"))?;
            if k == "stop" {
                let n: u32 = v.parse()?;
                if n > 1024 {
                    bail!("AnyTLS padding stop exceeds limit");
                }
                stop = Some(n);
                continue;
            }
            let index: u32 = k.parse()?;
            if index > 1024 {
                bail!("AnyTLS padding index exceeds limit");
            }
            let mut list = Vec::new();
            for part in v.split(',') {
                if list.len() >= 32 {
                    bail!("AnyTLS padding has too many fragments");
                }
                if part == "c" {
                    list.push(Entry::Check);
                    continue;
                }
                let (lo, hi) = part
                    .split_once('-')
                    .ok_or_else(|| anyhow::anyhow!("invalid AnyTLS padding range"))?;
                let lo: usize = lo.parse()?;
                let hi: usize = hi.parse()?;
                if lo == 0 || hi == 0 || lo > 65535 || hi > 65535 {
                    bail!("AnyTLS padding range exceeds limit");
                }
                list.push(Entry::Range(lo.min(hi), lo.max(hi)));
            }
            entries.insert(index, list);
        }
        Ok(Self {
            hash: hex::encode(Md5::digest(raw)),
            stop: stop.ok_or_else(|| anyhow::anyhow!("AnyTLS padding stop missing"))?,
            entries,
        })
    }

    pub fn stop(&self) -> u32 {
        self.stop
    }

    pub fn sizes(&self, index: u32) -> Result<Vec<Option<usize>>> {
        if index >= self.stop {
            return Ok(Vec::new());
        }
        self.entries
            .get(&index)
            .into_iter()
            .flatten()
            .map(|e| match e {
                Entry::Check => Ok(None),
                Entry::Range(lo, hi) => Ok(Some(if lo == hi {
                    *lo
                } else {
                    *lo + random(*hi - *lo + 1)?
                })),
            })
            .collect()
    }

    pub fn authentication_padding(&self) -> Result<usize> {
        Ok(self.sizes(0)?.into_iter().flatten().next().unwrap_or(0))
    }
}

fn random(limit: usize) -> Result<usize> {
    let mut bytes = [0; 8];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("generate AnyTLS padding"))?;
    Ok((u64::from_le_bytes(bytes) % limit as u64) as usize)
}

pub(super) async fn write<W: AsyncWrite + Unpin>(
    writer: &mut W,
    scheme: &Scheme,
    index: u32,
    mut data: &[u8],
) -> Result<()> {
    if index >= scheme.stop {
        if !data.is_empty() {
            writer.write_all(data).await?;
        }
        writer.flush().await?;
        return Ok(());
    }
    let sizes = scheme.sizes(index)?;
    let mut scratch = Vec::new();
    for size in sizes {
        let Some(size) = size else {
            if data.is_empty() {
                break;
            } else {
                continue;
            }
        };
        if data.len() > size {
            writer.write_all(&data[..size]).await?;
            writer.flush().await?;
            data = &data[size..];
        } else if !data.is_empty() {
            scratch.clear();
            scratch.extend_from_slice(data);
            if size >= data.len() + 7 {
                append_waste_frame(&mut scratch, size - data.len() - 7)?;
            }
            writer.write_all(&scratch).await?;
            writer.flush().await?;
            data = &[];
        } else {
            scratch.clear();
            append_waste_frame(&mut scratch, size)?;
            writer.write_all(&scratch).await?;
            writer.flush().await?;
        }
    }
    if !data.is_empty() {
        writer.write_all(data).await?;
        writer.flush().await?;
    }
    Ok(())
}

fn append_waste_frame(out: &mut Vec<u8>, payload_len: usize) -> Result<()> {
    let len = u16::try_from(payload_len).map_err(|_| anyhow::anyhow!("AnyTLS frame too large"))?;
    out.reserve(7 + payload_len);
    out.push(0);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.resize(out.len() + payload_len, 0);
    Ok(())
}
