use std::io;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};

const RESOURCE_BACKOFF: Duration = Duration::from_secs(1);

/// Accepts the next connection, surviving transient failures.
///
/// A connection that failed before it was accepted only affects that client,
/// so the next one is accepted immediately. Resource exhaustion such as
/// `EMFILE` clears once existing connections finish; retrying at once would
/// spin, so wait before trying again. Any other error means the listener
/// itself is unusable and is returned, so the server stops instead of
/// retrying forever.
pub async fn accept(listener: &TcpListener, label: &str) -> io::Result<TcpStream> {
    loop {
        match listener.accept().await {
            Ok((connection, _)) => return Ok(connection),
            Err(error) => match classify(&error) {
                AcceptError::Connection => {}
                AcceptError::Resource => {
                    eprintln!("accept {label} connection failed: {error}");
                    tokio::time::sleep(RESOURCE_BACKOFF).await;
                }
                AcceptError::Fatal => return Err(error),
            },
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum AcceptError {
    Connection,
    Resource,
    Fatal,
}

fn classify(error: &io::Error) -> AcceptError {
    if matches!(
        error.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::Interrupted
    ) {
        return AcceptError::Connection;
    }
    match error.raw_os_error() {
        // Network errors already pending on the new connection are reported
        // by accept on Linux and should be treated like a failed handshake.
        Some(
            libc::ENETDOWN
            | libc::ENETUNREACH
            | libc::EHOSTDOWN
            | libc::EHOSTUNREACH
            | libc::EPROTO
            | libc::ENOPROTOOPT,
        ) => AcceptError::Connection,
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM) => AcceptError::Resource,
        _ => AcceptError::Fatal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_accept_errors() {
        for kind in [
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::Interrupted,
        ] {
            assert_eq!(classify(&io::Error::from(kind)), AcceptError::Connection);
        }
        for (code, expected) in [
            (libc::EPROTO, AcceptError::Connection),
            (libc::EHOSTUNREACH, AcceptError::Connection),
            (libc::EMFILE, AcceptError::Resource),
            (libc::ENFILE, AcceptError::Resource),
            (libc::ENOBUFS, AcceptError::Resource),
            (libc::EBADF, AcceptError::Fatal),
            (libc::EINVAL, AcceptError::Fatal),
        ] {
            assert_eq!(classify(&io::Error::from_raw_os_error(code)), expected);
        }
    }

    #[tokio::test]
    async fn accepts_a_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(TcpStream::connect(address));
        let accepted = accept(&listener, "test").await.unwrap();
        let client = client.await.unwrap().unwrap();
        assert_eq!(accepted.peer_addr().unwrap(), client.local_addr().unwrap());
    }
}
