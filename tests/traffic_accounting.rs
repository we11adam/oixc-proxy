#![cfg(feature = "benchmark")]
//! Payload accounting through an encrypted loopback Snell peer, including reuse.
use std::time::Duration;

use oixc_proxy::snell::{
    RecordReader, RecordWriter, SnellClient, SnellClientOptions, SnellDialer, ZeroRecord,
    build_identity_v2,
};
use oixc_proxy::traffic::{Bytes, Recorder, query};
use tokio::io::{AsyncReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const PSK: &str = "local-accounting-test";
const EXPORTER: [u8; 32] = [42; 32];

async fn peer(
    stream: &mut TcpStream,
) -> (
    RecordReader<BufReader<tokio::io::ReadHalf<&mut TcpStream>>>,
    RecordWriter<tokio::io::WriteHalf<&mut TcpStream>>,
) {
    let mut identity = [0; 56];
    stream.read_exact(&mut identity).await.unwrap();
    let nonce = identity[..16].try_into().unwrap();
    assert_eq!(identity, build_identity_v2(PSK, &EXPORTER, &nonce).unwrap());
    let (read, write) = tokio::io::split(stream);
    (
        RecordReader::with_salt(BufReader::new(read), PSK, nonce).unwrap(),
        RecordWriter::new(write, PSK, [7; 16]).unwrap(),
    )
}

#[tokio::test]
async fn tcp_and_udp_count_only_application_bytes_without_reuse_duplication() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("traffic.jsonl");
        let recorder = Recorder::start(&path).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (mut reader, mut writer) = peer(&mut stream).await;
            for _ in 0..2 {
                let command = reader.read_frame().await.unwrap();
                assert_eq!(&command[..3], &[1, 5, 0]);
                writer.write_frame(&[0], 200).await.unwrap(); // Handshake and padding must not count.
                loop {
                    match reader.read_frame().await {
                        Ok(payload) => writer.write_frame(&payload, 100).await.unwrap(),
                        Err(error) => {
                            assert!(error.downcast_ref::<ZeroRecord>().is_some());
                            writer.write_frame(&[], 0).await.unwrap();
                            break;
                        }
                    }
                }
            }
            drop(reader);
            drop(writer);
            drop(stream);
            let (mut stream, _) = listener.accept().await.unwrap();
            let (mut reader, mut writer) = peer(&mut stream).await;
            assert_eq!(reader.read_frame().await.unwrap(), [1, 6, 0]);
            writer.write_frame(&[0], 100).await.unwrap();
            let datagram = reader.read_frame().await.unwrap();
            assert_eq!(&datagram[..9], &[1, 0, 4, 127, 0, 0, 1, 0, 53]);
            assert_eq!(&datagram[9..], b"dns");
            let mut response = vec![4, 127, 0, 0, 1, 0, 53];
            response.extend_from_slice(b"reply");
            writer.write_frame(&response, 100).await.unwrap();
            writer.write_frame(&[99], 0).await.unwrap(); // Malformed UDP cannot count.
        });
        let client = SnellClient::new(SnellClientOptions {
            node_name: "local-test".into(),
            psk: PSK.into(),
            reuse: true,
            max_idle: 1,
            max_uses: 32,
            idle_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(2),
            close_timeout: Duration::from_secs(2),
            dialer: SnellDialer::direct_for_benchmark(address, EXPORTER, Duration::from_secs(2))
                .unwrap(),
            dial_limit: None,
            dial_limit_timeout: Duration::from_secs(2),
        })
        .unwrap();
        let mut session = client.dial_tcp("example.com", 443).await.unwrap();
        let local_address = session.local_addr();
        let payload = vec![0x55; 50000];
        assert_eq!(session.write(&payload).await.unwrap(), payload.len());
        let mut downloaded = Vec::new();
        let mut buffer = [0; 511];
        while downloaded.len() < payload.len() {
            let length = session.read(&mut buffer).await.unwrap();
            assert!(length > 0);
            downloaded.extend_from_slice(&buffer[..length]);
        }
        assert_eq!(downloaded, payload);
        session.finish(true, false).await;
        let mut session = client.dial_tcp("example.com", 443).await.unwrap();
        assert_eq!(
            session.local_addr(),
            local_address,
            "must reuse the same transport"
        );
        let (mut read, mut write) = session.split();
        assert_eq!(write.write(b"second").await.unwrap(), 6);
        assert_eq!(read.read_chunk().await.unwrap(), b"second");
        write.close_write().await.unwrap();
        assert!(read.read_chunk().await.unwrap().is_empty());
        session.finish(true, true).await;
        let udp = client.dial_udp().await.unwrap();
        let mut frame = Vec::new();
        assert!(udp.write_to_host(b"invalid", "127.0.0.1", 0).await.is_err());
        assert_eq!(udp.write_to_host(b"dns", "127.0.0.1", 53).await.unwrap(), 3);
        let (_, offset) = udp.read_from(&mut frame).await.unwrap();
        assert_eq!(&frame[offset..], b"reply");
        assert!(udp.read_from(&mut frame).await.is_err());
        udp.close().await;
        server.await.unwrap();
        recorder.stop().unwrap();
        let report = query(&path, None, None).unwrap();
        assert_eq!(
            report.bytes,
            Bytes {
                tcp_upload: 50006,
                tcp_download: 50006,
                udp_upload: 3,
                udp_download: 5
            }
        );
        assert_eq!(report.total_bytes, 100020);
    })
    .await
    .unwrap();
}
