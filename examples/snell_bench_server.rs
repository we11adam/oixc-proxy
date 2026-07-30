use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use oixc_proxy::snell::{RecordReader, RecordWriter, ZeroRecord, build_identity_v2};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

const DEFAULT_LISTEN: &str = "127.0.0.1:19090";
const DEFAULT_PSK: &str = "oixc-local-benchmark-only";
const DEFAULT_MAX_CONNECTIONS: usize = 1024;
const READ_BUFFER_SIZE: usize = 64 << 10;

#[derive(Clone)]
struct Options {
    listen: SocketAddr,
    psk: String,
    exporter: [u8; 32],
    max_connections: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = parse_options()?;
    if !options.listen.ip().is_loopback() {
        bail!("the unauthenticated benchmark transport may only listen on loopback");
    }

    let listener = TcpListener::bind(options.listen)
        .await
        .context("bind benchmark server")?;
    let address = listener.local_addr().context("read benchmark address")?;
    println!(
        "{}",
        serde_json::json!({
            "status": "ready",
            "listen": address,
            "protocol": "snell-v4-identity-v2",
            "transport": "plain-tcp-static-exporter"
        })
    );

    let slots = Arc::new(Semaphore::new(options.max_connections));
    loop {
        let (stream, _) = listener.accept().await.context("accept benchmark client")?;
        let permit = slots
            .clone()
            .acquire_owned()
            .await
            .context("acquire benchmark connection slot")?;
        let options = options.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = serve_connection(stream, &options).await {
                eprintln!("benchmark connection failed: {error:#}");
            }
        });
    }
}

async fn serve_connection(mut stream: TcpStream, options: &Options) -> Result<()> {
    stream.set_nodelay(true).ok();

    let mut identity = [0u8; 56];
    stream
        .read_exact(&mut identity)
        .await
        .context("read Identity v2")?;
    let nonce: [u8; 16] = identity[..16]
        .try_into()
        .expect("Identity v2 nonce has a fixed length");
    let expected = build_identity_v2(&options.psk, &options.exporter, &nonce)?;
    if !bool::from(identity.ct_eq(&expected)) {
        bail!("reject invalid Identity v2");
    }

    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = RecordReader::with_salt(
        BufReader::with_capacity(READ_BUFFER_SIZE, read_half),
        options.psk.clone(),
        nonce,
    )?;
    let mut server_salt = [0u8; 16];
    getrandom::fill(&mut server_salt)
        .map_err(|_| anyhow::anyhow!("generate server record salt"))?;
    let mut writer = RecordWriter::new(write_half, &options.psk, server_salt)?;

    loop {
        let request = match reader.read_frame().await {
            Ok(request) => request,
            Err(error) if is_connection_end(&error) => return Ok(()),
            Err(error) => return Err(error.context("read CONNECT request")),
        };
        let command = parse_connect_request(&request)?;
        writer.write_frame(&[0], 0).await?;

        loop {
            match reader.read_frame().await {
                Ok(payload) => writer.write_frame(&payload, 0).await?,
                Err(error) if error.downcast_ref::<ZeroRecord>().is_some() => {
                    writer.write_frame(&[], 0).await?;
                    if command == 5 {
                        break;
                    }
                    writer.shutdown().await?;
                    return Ok(());
                }
                Err(error) if is_connection_end(&error) => return Ok(()),
                Err(error) => return Err(error.context("read benchmark payload")),
            }
        }
    }
}

fn parse_connect_request(request: &[u8]) -> Result<u8> {
    if request.len() < 6 || request[0] != 1 || !matches!(request[1], 1 | 5) || request[2] != 0 {
        bail!("invalid Snell CONNECT request");
    }
    let host_length = request[3] as usize;
    if request.len() != host_length + 6 {
        bail!("invalid Snell CONNECT request length");
    }
    let port_offset = 4 + host_length;
    if request[4..port_offset].is_empty()
        || u16::from_be_bytes([request[port_offset], request[port_offset + 1]]) == 0
    {
        bail!("invalid Snell CONNECT target");
    }
    Ok(request[1])
}

fn is_connection_end(error: &anyhow::Error) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("early eof")
        || message.contains("connection reset")
        || message.contains("broken pipe")
        || error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io_error| {
                    matches!(
                        io_error.kind(),
                        std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe
                    )
                })
        })
}

fn parse_options() -> Result<Options> {
    let mut listen = DEFAULT_LISTEN.parse::<SocketAddr>()?;
    let mut psk = DEFAULT_PSK.to_owned();
    let mut exporter = default_exporter();
    let mut max_connections = DEFAULT_MAX_CONNECTIONS;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--listen" => {
                listen = required_value(&mut arguments, "--listen")?
                    .parse()
                    .context("parse --listen")?;
            }
            "--psk" => psk = required_value(&mut arguments, "--psk")?,
            "--exporter" => {
                let value = hex::decode(required_value(&mut arguments, "--exporter")?)
                    .context("decode --exporter")?;
                exporter = value
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("--exporter must contain exactly 32 bytes"))?;
            }
            "--max-connections" => {
                max_connections = required_value(&mut arguments, "--max-connections")?
                    .parse()
                    .context("parse --max-connections")?;
                if max_connections == 0 {
                    bail!("--max-connections must be positive");
                }
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => bail!("unknown option: {argument}"),
        }
    }
    if psk.is_empty() {
        bail!("--psk cannot be empty");
    }
    Ok(Options {
        listen,
        psk,
        exporter,
        max_connections,
    })
}

fn required_value(arguments: &mut impl Iterator<Item = String>, option: &str) -> Result<String> {
    arguments
        .next()
        .ok_or_else(|| anyhow::anyhow!("{option} requires a value"))
}

fn default_exporter() -> [u8; 32] {
    std::array::from_fn(|index| index as u8)
}

fn print_help() {
    println!(
        "Usage: snell-bench-server [--listen 127.0.0.1:19090] \
         [--psk VALUE] [--exporter 64_HEX_CHARS] [--max-connections N]"
    );
}
