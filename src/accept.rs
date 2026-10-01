use std::io;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};

const RESOURCE_BACKOFF: Duration = Duration::from_secs(1);

/// Accepts the next connection, surviving transient failures.
///
/// A connection aborted before it was accepted only affects that client, so
/// the next one is accepted immediately. Other errors are usually resource
/// exhaustion such as `EMFILE`; retrying at once would spin, so wait for
/// existing connections to release resources instead of stopping the server.
pub async fn accept(listener: &TcpListener, label: &str) -> TcpStream {
    loop {
        match listener.accept().await {
            Ok((connection, _)) => return connection,
            Err(error) if is_connection_error(&error) => {}
            Err(error) => {
                eprintln!("accept {label} connection failed: {error}");
                tokio::time::sleep(RESOURCE_BACKOFF).await;
            }
        }
    }
}

fn is_connection_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_per_connection_errors() {
        for kind in [
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionRefused,
        ] {
            assert!(is_connection_error(&io::Error::from(kind)));
        }
        assert!(!is_connection_error(&io::Error::from_raw_os_error(
            libc::EMFILE
        )));
        assert!(!is_connection_error(&io::Error::from_raw_os_error(
            libc::ENFILE
        )));
    }

    #[tokio::test]
    async fn accepts_a_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(TcpStream::connect(address));
        let accepted = accept(&listener, "test").await;
        let client = client.await.unwrap().unwrap();
        assert_eq!(accepted.peer_addr().unwrap(), client.local_addr().unwrap());
    }
}
