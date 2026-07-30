use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use oixc_proxy::snell::{SnellClient, SnellClientOptions, SnellDialer};
use serde::Serialize;
use tokio::time::timeout;

const DEFAULT_SERVER: &str = "127.0.0.1:19090";
const DEFAULT_PSK: &str = "oixc-local-benchmark-only";

struct Options {
    server: SocketAddr,
    psk: String,
    exporter: [u8; 32],
    requests: usize,
    warmup: usize,
    concurrency: usize,
    payload_bytes: usize,
    application_chunk_bytes: usize,
    reuse: bool,
}

#[derive(Serialize)]
struct Summary {
    implementation: &'static str,
    transport: &'static str,
    reuse: bool,
    requests: usize,
    warmup: usize,
    concurrency: usize,
    payload_bytes: usize,
    application_chunk_bytes: usize,
    elapsed_ms: f64,
    operations_per_second: f64,
    round_trip_mbps: f64,
    latency_mean_us: f64,
    latency_p50_us: f64,
    latency_p95_us: f64,
    latency_p99_us: f64,
    latency_max_us: f64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = parse_options()?;
    let dialer = SnellDialer::direct_for_benchmark(
        options.server,
        options.exporter,
        Duration::from_secs(10),
    )?;
    let client = SnellClient::new(SnellClientOptions {
        node_name: "local-benchmark".to_owned(),
        psk: options.psk.clone(),
        reuse: options.reuse,
        max_idle: options.concurrency.max(1),
        max_uses: 1024,
        idle_timeout: Duration::from_secs(30),
        handshake_timeout: Duration::from_secs(10),
        close_timeout: Duration::from_secs(2),
        dialer,
        dial_limit: None,
        dial_limit_timeout: Duration::from_secs(10),
    })?;

    run_operations(
        client.clone(),
        options.warmup,
        options.concurrency,
        options.payload_bytes,
        options.application_chunk_bytes,
    )
    .await?;
    let started = Instant::now();
    let mut latencies = run_operations(
        client.clone(),
        options.requests,
        options.concurrency,
        options.payload_bytes,
        options.application_chunk_bytes,
    )
    .await?;
    let elapsed = started.elapsed();
    client.close().await;

    latencies.sort_unstable();
    let elapsed_seconds = elapsed.as_secs_f64();
    let operations_per_second = options.requests as f64 / elapsed_seconds;
    let round_trip_bits = options.requests as f64 * options.payload_bytes as f64 * 2.0 * 8.0;
    let mean = latencies
        .iter()
        .copied()
        .map(|value| value as f64)
        .sum::<f64>()
        / latencies.len() as f64;
    let summary = Summary {
        implementation: "rust",
        transport: "plain-tcp-static-exporter",
        reuse: options.reuse,
        requests: options.requests,
        warmup: options.warmup,
        concurrency: options.concurrency,
        payload_bytes: options.payload_bytes,
        application_chunk_bytes: options.application_chunk_bytes,
        elapsed_ms: elapsed.as_secs_f64() * 1_000.0,
        operations_per_second,
        round_trip_mbps: round_trip_bits / elapsed_seconds / 1_000_000.0,
        latency_mean_us: mean,
        latency_p50_us: percentile(&latencies, 50),
        latency_p95_us: percentile(&latencies, 95),
        latency_p99_us: percentile(&latencies, 99),
        latency_max_us: *latencies.last().expect("requests is positive") as f64,
    };
    println!("{}", serde_json::to_string(&summary)?);
    Ok(())
}

async fn run_operations(
    client: SnellClient,
    count: usize,
    concurrency: usize,
    payload_bytes: usize,
    application_chunk_bytes: usize,
) -> Result<Vec<u64>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let next = Arc::new(AtomicUsize::new(0));
    let mut workers = tokio::task::JoinSet::new();
    for worker_id in 0..concurrency.min(count) {
        let client = client.clone();
        let next = next.clone();
        workers.spawn(async move {
            let payload = payload(worker_id, payload_bytes);
            let mut response = vec![0u8; payload_bytes];
            let mut samples = Vec::new();
            loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= count {
                    break;
                }
                let started = Instant::now();
                timeout(
                    Duration::from_secs(15),
                    run_operation(&client, &payload, &mut response, application_chunk_bytes),
                )
                .await
                .map_err(|_| anyhow::anyhow!("benchmark operation timed out"))??;
                samples.push(started.elapsed().as_micros() as u64);
            }
            Result::<Vec<u64>>::Ok(samples)
        });
    }
    let mut samples = Vec::with_capacity(count);
    while let Some(result) = workers.join_next().await {
        samples.extend(result.context("join benchmark worker")??);
    }
    if samples.len() != count {
        bail!("benchmark completed an unexpected number of operations");
    }
    Ok(samples)
}

async fn run_operation(
    client: &SnellClient,
    payload: &[u8],
    response: &mut [u8],
    application_chunk_bytes: usize,
) -> Result<()> {
    let mut session = client.dial_tcp("echo.bench", 443).await?;
    for chunk in payload.chunks(application_chunk_bytes) {
        let written = session.write(chunk).await?;
        if written != chunk.len() {
            bail!("short benchmark write");
        }
    }
    let mut offset = 0;
    while offset < response.len() {
        let read = session.read(&mut response[offset..]).await?;
        if read == 0 {
            bail!("benchmark server closed before echo completed");
        }
        offset += read;
    }
    if response != payload {
        bail!("benchmark echo mismatch");
    }
    session.finish(true, false).await;
    Ok(())
}

fn payload(worker_id: usize, length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index.wrapping_add(worker_id) % 251) as u8)
        .collect()
}

fn percentile(sorted: &[u64], percentile: usize) -> f64 {
    let index = (sorted.len() * percentile).div_ceil(100).saturating_sub(1);
    sorted[index] as f64
}

fn parse_options() -> Result<Options> {
    let mut options = Options {
        server: DEFAULT_SERVER.parse()?,
        psk: DEFAULT_PSK.to_owned(),
        exporter: std::array::from_fn(|index| index as u8),
        requests: 1_000,
        warmup: 100,
        concurrency: 1,
        payload_bytes: 1_024,
        application_chunk_bytes: 0,
        reuse: true,
    };
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let value = match argument.as_str() {
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--reuse" => {
                options.reuse = parse_bool(&required_value(&mut arguments, "--reuse")?)?;
                continue;
            }
            _ => required_value(&mut arguments, &argument)?,
        };
        match argument.as_str() {
            "--server" => options.server = value.parse().context("parse --server")?,
            "--psk" => options.psk = value,
            "--exporter" => {
                options.exporter = hex::decode(value)
                    .context("decode --exporter")?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("--exporter must contain exactly 32 bytes"))?;
            }
            "--requests" => options.requests = value.parse().context("parse --requests")?,
            "--warmup" => options.warmup = value.parse().context("parse --warmup")?,
            "--concurrency" => {
                options.concurrency = value.parse().context("parse --concurrency")?
            }
            "--payload-bytes" => {
                options.payload_bytes = value.parse().context("parse --payload-bytes")?
            }
            "--application-chunk-bytes" => {
                options.application_chunk_bytes =
                    value.parse().context("parse --application-chunk-bytes")?
            }
            _ => bail!("unknown option: {argument}"),
        }
    }
    if options.application_chunk_bytes == 0 {
        options.application_chunk_bytes = options.payload_bytes;
    }
    if options.psk.is_empty()
        || options.requests == 0
        || options.concurrency == 0
        || options.payload_bytes == 0
        || options.application_chunk_bytes == 0
    {
        bail!("PSK, requests, concurrency and payload size must be positive");
    }
    Ok(options)
}

fn required_value(arguments: &mut impl Iterator<Item = String>, option: &str) -> Result<String> {
    arguments
        .next()
        .ok_or_else(|| anyhow::anyhow!("{option} requires a value"))
}

fn parse_bool(value: &str) -> Result<bool> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => bail!("--reuse must be true or false"),
    }
}

fn print_help() {
    println!(
        "Usage: snell-bench-client [--server 127.0.0.1:19090] \
         [--psk VALUE] [--exporter 64_HEX_CHARS] [--requests N] \
         [--warmup N] [--concurrency N] [--payload-bytes N] \
         [--application-chunk-bytes N] [--reuse true|false]"
    );
}
