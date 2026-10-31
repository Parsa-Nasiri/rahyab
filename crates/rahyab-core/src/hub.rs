//! The local SOCKS5 hub: ONE stable endpoint (127.0.0.1:port) that tun2proxy (and
//! anything else on the device) can point at, while the Khorshid supervisor hot-swaps
//! which tunnel serves it underneath — failover without touching the VPN interface.

use crate::transport::socks5::{socks5_read_request, socks5_reply};
use crate::transport::{io_err, BoxStream, SharedConnector};
use arc_swap::ArcSwapOption;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

pub async fn serve_hub(
    listener: TcpListener,
    current: Arc<ArcSwapOption<SharedConnector>>,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            r = listener.accept() => {
                let (sock, _) = r?;
                let cur = current.clone();
                tokio::spawn(async move {
                    let _ = handle_conn(sock, cur).await;
                });
            }
        }
    }
    Ok(())
}

async fn handle_conn(
    sock: TcpStream,
    current: Arc<ArcSwapOption<SharedConnector>>,
) -> std::io::Result<()> {
    let (dst, client) = socks5_read_request(Box::new(sock)).await?;
    let upstream = current.load_full();
    let mut client: BoxStream = client;
    match upstream.as_ref() {
        Some(conn) => match conn.connect(&dst).await {
            Ok(mut up) => {
                socks5_reply(&mut client, true).await?;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
                Ok(())
            }
            Err(e) => {
                let _ = socks5_reply(&mut client, false).await;
                Err(e)
            }
        },
        None => {
            let _ = socks5_reply(&mut client, false).await;
            Err(io_err("hub has no active upstream yet"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{Connector, TargetAddr};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct FakeUp(Arc<AtomicBool>);
    #[async_trait]
    impl Connector for FakeUp {
        fn name(&self) -> String { "fake".into() }
        fn kind(&self) -> &'static str { "test" }
        async fn connect(&self, _dst: &TargetAddr) -> std::io::Result<BoxStream> {
            if !self.0.load(Ordering::SeqCst) {
                return Err(std::io::Error::other("down"));
            }
            let (a, mut b) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                let mut buf = [0u8; 32];
                if let Ok(n) = b.read(&mut buf).await {
                    let _ = b.write_all(&buf[..n]).await;
                }
            });
            Ok(Box::new(a))
        }
        async fn connect_over(&self, _s: BoxStream, _d: &TargetAddr) -> std::io::Result<BoxStream> {
            Err(std::io::Error::other("no"))
        }
    }

    #[tokio::test]
    async fn hub_hot_swap_upstream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop_tx, stop_rx) = watch::channel(false);
        let current: Arc<ArcSwapOption<SharedConnector>> = Arc::new(ArcSwapOption::empty());
        tokio::spawn(serve_hub(listener, current.clone(), stop_rx.clone()));

        let up_flag = Arc::new(AtomicBool::new(true));
        let up: SharedConnector = Arc::new(FakeUp(up_flag.clone()));
        current.store(Some(Arc::new(up.clone())));

        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        // handshake: no-auth
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut buf = [0u8; 2];
        c.read_exact(&mut buf).await.unwrap();
        // connect to example.com:80 (domain atyp 3)
        let host = b"example.com";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&80u16.to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0x00, "upstream up, expect success");

        c.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        c.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");
        drop(c);

        // Flip upstream "down" → next connection must get failure reply.
        up_flag.store(false, Ordering::SeqCst);
        let mut c2 = tokio::net::TcpStream::connect(addr).await.unwrap();
        c2.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut buf2 = [0u8; 2];
        c2.read_exact(&mut buf2).await.unwrap();
        c2.write_all(&req).await.unwrap();
        let mut rep2 = [0u8; 10];
        c2.read_exact(&mut rep2).await.unwrap();
        assert_eq!(rep2[1], 0x01, "upstream down, expect failure reply");

        let _ = stop_tx.send(true);
    }
}
