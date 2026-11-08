use super::*;
use crate::network::NetworkMonitor;
use crate::nodes::{AnyTlsOptions, ObfsOptions};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

async fn fixture(
    cdn: bool,
) -> (
    Client,
    TcpListener,
    Arc<rustls::ServerConfig>,
    Arc<rustls::ServerConfig>,
) {
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "origin.test".into()]).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
    )
    .unwrap();
    let mut outer = config.clone();
    outer.alpn_protocols = vec![b"http/1.1".to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let context =
        Arc::new(TransportContext::built_in_with_network(NetworkMonitor::test_unbound()).unwrap());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    context.test_roots(roots).await;
    let proxy = Proxy {
        name: "AnyTLS test".into(),
        proxy_type: "anytls".into(),
        server: "localhost".into(),
        port: listener.local_addr().unwrap().port(),
        psk: "test-password".into(),
        version: 0,
        udp: true,
        tfo: false,
        reuse: true,
        identity: false,
        obfs: ObfsOptions {
            sni: "origin.test".into(),
            ..Default::default()
        },
        anytls: Some(AnyTlsOptions {
            websocket_path: cdn.then(|| "/carrier".into()),
            uses_cdn: cdn,
            udp: true,
        }),
        oixcloud: None,
    };
    let client = Client::new(
        proxy,
        context,
        Duration::from_secs(3),
        Duration::from_secs(2),
        4,
        16,
        Arc::new(Semaphore::new(4)),
        Arc::new(Semaphore::new(4)),
        Arc::new(crate::diagnostics::NodeDiagnostics::default()),
    );
    (client, listener, Arc::new(config), Arc::new(outer))
}
async fn carrier(
    listener: &TcpListener,
    inner: Arc<rustls::ServerConfig>,
    outer: Arc<rustls::ServerConfig>,
    cdn: bool,
) -> BoxStream {
    let (tcp, _) = listener.accept().await.unwrap();
    if cdn {
        let tls = TlsAcceptor::from(outer).accept(tcp).await.unwrap();
        assert_eq!(tls.get_ref().1.server_name(), Some("localhost"));
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );
        let ws = crate::transport::websocket::test_server(tls).await.unwrap();
        let tls = TlsAcceptor::from(inner).accept(ws).await.unwrap();
        assert_eq!(tls.get_ref().1.server_name(), Some("origin.test"));
        assert_eq!(tls.get_ref().1.alpn_protocol(), None);
        Box::new(tls)
    } else {
        let tls = TlsAcceptor::from(inner).accept(tcp).await.unwrap();
        assert_eq!(tls.get_ref().1.server_name(), Some("origin.test"));
        Box::new(tls)
    }
}
async fn authenticate(
    mut io: BoxStream,
) -> (FrameReader<ReadHalf<BoxStream>>, WriteHalf<BoxStream>) {
    let mut hash = [0; 32];
    io.read_exact(&mut hash).await.unwrap();
    assert_eq!(hash.as_slice(), Sha256::digest(b"test-password").as_slice());
    let n = io.read_u16().await.unwrap();
    let mut padding = vec![0; n as usize];
    io.read_exact(&mut padding).await.unwrap();
    assert_eq!(n, 30);
    let (r, w) = tokio::io::split(io);
    (
        FrameReader {
            io: r,
            buffer: Vec::new(),
        },
        w,
    )
}
async fn non_padding<R: AsyncRead + Unpin>(r: &mut FrameReader<R>) -> Frame {
    loop {
        let f = r.next().await.unwrap();
        if f.command != 0 {
            return f;
        }
    }
}

#[tokio::test]
async fn verified_direct_and_cdn_roundtrip_reuse_and_padding_updates() {
    for cdn in [false, true] {
        let (client, listener, inner, outer) = fixture(cdn).await;
        let server = tokio::spawn(async move {
            let io = carrier(&listener, inner, outer, cdn).await;
            let (mut r, mut w) = authenticate(io).await;
            let settings = non_padding(&mut r).await;
            assert_eq!(settings.command, 4);
            assert_eq!(settings.id, 0);
            let settings = String::from_utf8(settings.data).unwrap();
            assert!(settings.starts_with("v=2\nclient=oixc-proxy/"));
            assert!(settings.contains("padding-md5="));
            w.write_all(&frame(10, 0, b"v=2").unwrap()).await.unwrap();
            w.write_all(&frame(6, 0, b"stop=3\n0=5-5\n1=80-80\n2=100-100,c,200-200").unwrap())
                .await
                .unwrap();
            for id in 1..=2 {
                let syn = non_padding(&mut r).await;
                assert_eq!((syn.command, syn.id), (1, id));
                let address = non_padding(&mut r).await;
                assert_eq!((address.command, address.id), (2, id));
                assert_eq!(address.data, socks_address("example.org", 443).unwrap());
                // Split ACK across writes to exercise incremental frame parsing.
                let ack = frame(7, id, &[]).unwrap();
                w.write_all(&ack[..3]).await.unwrap();
                w.flush().await.unwrap();
                tokio::task::yield_now().await;
                w.write_all(&ack[3..]).await.unwrap();
                w.flush().await.unwrap();
                let payload = non_padding(&mut r).await;
                assert_eq!(payload.command, 2);
                assert_eq!(payload.data, b"hello");
                let mut reply = frame(2, id, b"world").unwrap();
                reply.extend(frame(3, id, &[]).unwrap());
                w.write_all(&reply).await.unwrap();
                w.flush().await.unwrap();
            }
        });
        for _ in 0..2 {
            let mut s = client.dial_tcp("example.org", 443).await.unwrap();
            s.write(b"hello").await.unwrap();
            let (r, _) = s.split();
            assert_eq!(r.read_chunk().await.unwrap(), b"world");
            assert!(r.read_chunk().await.unwrap().is_empty());
            s.finish(true, false).await;
        }
        assert_ne!(lock(&client.inner.scheme).hash, Scheme::default().hash);
        client.close().await;
        timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn udp_over_tcp_v2_preserves_datagrams_and_targets() {
    let (client, listener, inner, outer) = fixture(false).await;
    let server = tokio::spawn(async move {
        let (mut r, mut w) = authenticate(carrier(&listener, inner, outer, false).await).await;
        assert_eq!(non_padding(&mut r).await.command, 4);
        w.write_all(&frame(10, 0, b"v=2").unwrap()).await.unwrap();
        let syn = non_padding(&mut r).await;
        let id = syn.id;
        assert_eq!(
            non_padding(&mut r).await.data,
            socks_address("sp.v2.udp-over-tcp.arpa", 0).unwrap()
        );
        w.write_all(&frame(7, id, &[]).unwrap()).await.unwrap();
        w.flush().await.unwrap();
        assert_eq!(non_padding(&mut r).await.data, [0, 1, 0, 0, 0, 0, 0, 0]);
        let request = non_padding(&mut r).await;
        assert_eq!(request.data, [0, 1, 2, 3, 4, 0, 53, 0, 3, b'd', b'n', b's']);
        let mut packet = vec![0, 1, 2, 3, 4, 0, 53, 0, 5];
        packet.extend(b"reply");
        // Two datagrams split across AnyTLS frames with no boundary alignment.
        packet.extend([1]);
        packet.extend([0u8; 15]);
        packet.push(1);
        packet.extend([0, 53, 0, 0]);
        for chunk in packet.chunks(3) {
            w.write_all(&frame(2, id, chunk).unwrap()).await.unwrap();
        }
        w.flush().await.unwrap();
        assert_eq!(non_padding(&mut r).await.command, 3);
    });
    let s = client.dial_udp().await.unwrap();
    s.write_to_host(b"dns", "1.2.3.4", 53).await.unwrap();
    let mut b = Vec::new();
    assert_eq!(
        s.read_from(&mut b).await.unwrap(),
        ("1.2.3.4:53".parse().unwrap(), 0)
    );
    assert_eq!(b, b"reply");
    assert_eq!(
        s.read_from(&mut b).await.unwrap(),
        ("[::1]:53".parse().unwrap(), 0)
    );
    assert!(b.is_empty());
    s.close().await;
    server.await.unwrap();
}

#[tokio::test]
async fn malformed_frames_and_synack_errors_fail_without_leaking_remote_text() {
    let (client, listener, inner, outer) = fixture(false).await;
    let server = tokio::spawn(async move {
        let (mut r, mut w) = authenticate(carrier(&listener, inner, outer, false).await).await;
        non_padding(&mut r).await;
        let syn = non_padding(&mut r).await;
        non_padding(&mut r).await;
        w.write_all(&frame(10, 0, b"v=2").unwrap()).await.unwrap();
        w.write_all(&frame(7, syn.id, b"PRIVATE_REMOTE_ERROR").unwrap())
            .await
            .unwrap();
        w.flush().await.unwrap();
    });
    let error = client.dial_tcp("example.org", 443).await.err().unwrap();
    assert!(!format!("{error:#}").contains("PRIVATE_REMOTE_ERROR"));
    assert!(client.inner.idle.lock().await.is_empty());
    server.await.unwrap();
    let (mut tx, rx) = tokio::io::duplex(32);
    tx.write_all(&[2, 0, 0, 0, 1, 0, 4, 1]).await.unwrap();
    drop(tx);
    assert!(
        FrameReader {
            io: rx,
            buffer: Vec::new()
        }
        .next()
        .await
        .is_err()
    );
}

#[tokio::test]
async fn cancellation_preserves_partial_frame_and_idle_heartbeats_are_serviced() {
    let (mut tx, rx) = tokio::io::duplex(64);
    let wire = frame(2, 9, b"test").unwrap();
    tx.write_all(&wire[..4]).await.unwrap();
    let mut r = FrameReader {
        io: rx,
        buffer: Vec::new(),
    };
    assert!(timeout(Duration::from_millis(10), r.next()).await.is_err());
    tx.write_all(&wire[4..]).await.unwrap();
    assert_eq!(r.next().await.unwrap().data, b"test");
    let (client, listener, inner, outer) = fixture(false).await;
    let (done_tx, done_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut r, mut w) = authenticate(carrier(&listener, inner, outer, false).await).await;
        non_padding(&mut r).await;
        let syn = non_padding(&mut r).await;
        non_padding(&mut r).await;
        w.write_all(&frame(10, 0, b"v=2").unwrap()).await.unwrap();
        w.write_all(&frame(7, syn.id, &[]).unwrap()).await.unwrap();
        w.write_all(&frame(3, syn.id, &[]).unwrap()).await.unwrap();
        w.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        w.write_all(&frame(8, 42, &[]).unwrap()).await.unwrap();
        w.flush().await.unwrap();
        let reply = non_padding(&mut r).await;
        assert_eq!((reply.command, reply.id), (9, 42));
        done_tx.send(()).unwrap();
    });
    let mut s = client.dial_tcp("example.org", 443).await.unwrap();
    let (r, _) = s.split();
    assert!(r.read_chunk().await.unwrap().is_empty());
    s.finish(true, false).await;
    timeout(Duration::from_secs(2), done_rx)
        .await
        .unwrap()
        .unwrap();
    client.close().await;
    server.await.unwrap();
}

#[tokio::test]
async fn padding_shapes_writes_and_rejects_unbounded_schemes() {
    assert!(Scheme::parse(b"stop=900000\n0=1-1").is_err());
    assert!(Scheme::parse(b"stop=2\n1=1-999999").is_err());
    let scheme = Scheme::parse(b"stop=2\n1=30-30,c,99-99").unwrap();
    let (tx, mut rx) = tokio::io::duplex(128);
    let mut tx = tx;
    padding::write(&mut tx, &scheme, 1, &frame(2, 1, b"hello").unwrap())
        .await
        .unwrap();
    drop(tx);
    let mut data = Vec::new();
    rx.read_to_end(&mut data).await.unwrap();
    assert_eq!(data.len(), 30);
    assert_eq!(&data[..12], frame(2, 1, b"hello").unwrap());
    assert_eq!(data[12], 0);
}

#[tokio::test]
async fn mixed_gateway_routes_socks_and_http_through_cdn_anytls() {
    timeout(Duration::from_secs(8), async {
        let (client, listener, inner, outer) = fixture(true).await;
        let peer = tokio::spawn(async move {
            let (mut r, mut w) = authenticate(carrier(&listener, inner, outer, true).await).await;
            assert_eq!(non_padding(&mut r).await.command, 4);
            w.write_all(&frame(10, 0, b"v=2").unwrap()).await.unwrap();
            for id in 1..=2 {
                let syn = non_padding(&mut r).await;
                assert_eq!((syn.command, syn.id), (1, id));
                non_padding(&mut r).await;
                w.write_all(&frame(7, id, &[]).unwrap()).await.unwrap();
                w.flush().await.unwrap();
                let payload = non_padding(&mut r).await;
                assert_eq!(payload.data, b"hello");
                let mut response = frame(2, id, b"world").unwrap();
                response.extend(frame(3, id, &[]).unwrap());
                w.write_all(&response).await.unwrap();
                w.flush().await.unwrap();
            }
        });
        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = inbound.local_addr().unwrap();
        let options = crate::socks5::Options {
            handshake_timeout: Duration::from_secs(3),
            tcp_idle_timeout: Duration::from_secs(3),
            udp_idle_timeout: Duration::from_secs(3),
            udp_relay: crate::socks5::UdpRelay::ephemeral("127.0.0.1".parse().unwrap()),
            mode: crate::socks5::Mode::Fixed {
                route: crate::socks5::FixedRoute::new(crate::gateway::Route {
                    client: crate::upstream::Client::AnyTls(client.clone()),
                    udp: true,
                }),
                credentials: None,
            },
        };
        let gateway = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = inbound.accept().await.unwrap();
                crate::socks5::serve_connection(stream, options.clone())
                    .await
                    .unwrap();
            }
        });
        for http in [false, true] {
            let mut connection = tokio::net::TcpStream::connect(address).await.unwrap();
            if http {
                connection
                    .write_all(b"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n")
                    .await
                    .unwrap();
                let mut response = Vec::new();
                while !response.ends_with(b"\r\n\r\n") {
                    response.push(connection.read_u8().await.unwrap());
                }
                assert!(response.starts_with(b"HTTP/1.1 200"));
            } else {
                connection.write_all(&[5, 1, 0]).await.unwrap();
                let mut response = [0; 2];
                connection.read_exact(&mut response).await.unwrap();
                assert_eq!(response, [5, 0]);
                let mut request = vec![5, 1, 0];
                request.extend(socks_address("example.org", 443).unwrap());
                connection.write_all(&request).await.unwrap();
                let mut response = [0; 10];
                connection.read_exact(&mut response).await.unwrap();
                assert_eq!(&response[..2], &[5, 0]);
            }
            connection.write_all(b"hello").await.unwrap();
            let mut response = [0; 5];
            connection.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"world");
            let mut end = [0; 1];
            assert_eq!(connection.read(&mut end).await.unwrap(), 0);
        }
        peer.await.unwrap();
        gateway.await.unwrap();
        client.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn bad_inner_certificate_and_synack_timeout_do_not_create_idle_sessions() {
    for cdn in [false, true] {
        let (mut client, listener, inner, outer) = fixture(cdn).await;
        Arc::get_mut(&mut client.inner).unwrap().proxy.obfs.sni = "wrong.test".into();
        let peer = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            if cdn {
                let tls = TlsAcceptor::from(outer).accept(tcp).await.unwrap();
                let ws = crate::transport::websocket::test_server(tls).await.unwrap();
                let _ = TlsAcceptor::from(inner).accept(ws).await;
            } else {
                let _ = TlsAcceptor::from(inner).accept(tcp).await;
            }
        });
        assert!(client.dial_tcp("example.org", 443).await.is_err());
        assert!(client.inner.idle.lock().await.is_empty());
        peer.await.unwrap();
    }
    let (mut client, listener, inner, outer) = fixture(false).await;
    Arc::get_mut(&mut client.inner).unwrap().timeout = Duration::from_millis(100);
    let peer = tokio::spawn(async move {
        let (mut r, mut w) = authenticate(carrier(&listener, inner, outer, false).await).await;
        non_padding(&mut r).await;
        non_padding(&mut r).await;
        non_padding(&mut r).await;
        w.write_all(&frame(10, 0, b"v=2").unwrap()).await.unwrap();
        w.flush().await.unwrap();
        while let Ok(f) = r.next().await {
            assert_eq!(
                f.command, 0,
                "no new stream or application data after timeout"
            );
        }
    });
    assert!(client.dial_tcp("example.org", 443).await.is_err());
    assert!(client.inner.idle.lock().await.is_empty());
    peer.await.unwrap();
}
