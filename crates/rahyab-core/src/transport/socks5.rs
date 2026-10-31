//! SOCKS5 client + server handshake (RFC 1928), hand-rolled so it can run over ANY stream
//! (which is what enables chaining: SOCKS5 inside another tunnel).

use super::{io_err, BoxStream, Connector, SharedConnector, TargetAddr};
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Run the SOCKS5 client handshake over `stream` and request `dst`.
pub async fn socks5_connect_over(
    mut stream: BoxStream,
    dst: &TargetAddr,
    auth: Option<&(String, String)>,
) -> std::io::Result<BoxStream> {
    // Greeting: offer no-auth always, user/pass if configured.
    let mut greet = vec![0x05u8, 0x01, 0x00];
    if auth.is_some() {
        greet = vec![0x05u8, 0x02, 0x00, 0x02];
    }
    stream.write_all(&greet).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 {
        return Err(io_err("not a SOCKS5 server"));
    }
    match resp[1] {
        0x00 => {}
        0x02 => {
            let (u, p) = auth.ok_or_else(|| io_err("server requires auth, none configured"))?;
            let mut m = Vec::with_capacity(3 + u.len() + p.len());
            m.push(0x01);
            m.push(u.len() as u8);
            m.extend_from_slice(u.as_bytes());
            m.push(p.len() as u8);
            m.extend_from_slice(p.as_bytes());
            stream.write_all(&m).await?;
            let mut ar = [0u8; 2];
            stream.read_exact(&mut ar).await?;
            if ar[1] != 0x00 {
                return Err(io_err("SOCKS5 authentication failed"));
            }
        }
        other => return Err(io_err(format!("SOCKS5: no acceptable method ({other})"))),
    }

    // CONNECT request
    let mut req = vec![0x05u8, 0x01, 0x00];
    match dst {
        TargetAddr::Domain(h, p) => {
            req.push(0x03);
            req.push(h.len() as u8);
            req.extend_from_slice(h.as_bytes());
            req.extend_from_slice(&p.to_be_bytes());
        }
        TargetAddr::Ip(a) => match a {
            SocketAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.ip().octets());
                req.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.ip().octets());
                req.extend_from_slice(&v6.port().to_be_bytes());
            }
        },
    }
    stream.write_all(&req).await?;

    // Reply: VER REP RSV ATYP [BND...]
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(io_err(format!("SOCKS5 error status {}", head[1])));
    }
    match head[3] {
        0x01 => {
            let mut bnd = [0u8; 6];
            stream.read_exact(&mut bnd).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut bnd = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut bnd).await?;
        }
        0x04 => {
            let mut bnd = [0u8; 18];
            stream.read_exact(&mut bnd).await?;
        }
        other => return Err(io_err(format!("SOCKS5: bad ATYP {other}"))),
    }
    Ok(stream)
}

/// Server side (phase 1): read a local SOCKS5 client's greeting + CONNECT request.
/// Does NOT send the success reply — the caller dials upstream first, then calls
/// [`socks5_reply`] with the real outcome.
pub async fn socks5_read_request(mut stream: BoxStream) -> std::io::Result<(TargetAddr, BoxStream)> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(io_err("client is not SOCKS5"));
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    // Local hub: always accept no-auth.
    stream.write_all(&[0x05, 0x00]).await?;

    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[1] != 0x01 {
        // Only CONNECT is supported (UDP ASSOCIATE: reply not-supported).
        stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err(io_err("only SOCKS5 CONNECT supported"));
    }
    let dst = match req[3] {
        0x01 => {
            let mut b = [0u8; 6];
            stream.read_exact(&mut b).await?;
            let ip = std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            let port = u16::from_be_bytes([b[4], b[5]]);
            TargetAddr::Ip(SocketAddr::new(ip.into(), port))
        }
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            let mut b = vec![0u8; l[0] as usize];
            stream.read_exact(&mut b).await?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            let host = String::from_utf8(b).map_err(|_| io_err("bad domain"))?;
            TargetAddr::Domain(host, u16::from_be_bytes(p))
        }
        0x04 => {
            let mut b = [0u8; 18];
            stream.read_exact(&mut b).await?;
            let arr: [u8; 16] = b[..16].try_into().unwrap();
            let ip = std::net::Ipv6Addr::from(arr);
            let port = u16::from_be_bytes([b[16], b[17]]);
            TargetAddr::Ip(SocketAddr::new(ip.into(), port))
        }
        other => return Err(io_err(format!("bad client ATYP {other}"))),
    };
    Ok((dst, stream))
}

/// Server side (phase 2): tell the client whether the upstream dial succeeded.
pub async fn socks5_reply(stream: &mut BoxStream, ok: bool) -> std::io::Result<()> {
    stream
        .write_all(&[0x05, if ok { 0x00 } else { 0x01 }, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
}

/// Convenience: accept + immediately reply success (used in tests and simple relays).
pub async fn socks5_accept_client(stream: BoxStream) -> std::io::Result<(TargetAddr, BoxStream)> {
    let (dst, mut s) = socks5_read_request(stream).await?;
    socks5_reply(&mut s, true).await?;
    Ok((dst, s))
}

/// A SOCKS5 proxy connector — usable both as a top-level tunnel and as an inner hop
/// (this is how we reach a Psiphon local SOCKS listener, for example).
pub struct Socks5Connector {
    pub server: TargetAddr,
    pub auth: Option<(String, String)>,
    pub inner: Option<SharedConnector>,
}

impl Socks5Connector {
    pub fn new(server: TargetAddr) -> Self {
        Self { server, auth: None, inner: None }
    }
    pub fn with_inner(server: TargetAddr, inner: SharedConnector) -> Self {
        Self { server, auth: None, inner: Some(inner) }
    }
}

#[async_trait]
impl Connector for Socks5Connector {
    fn name(&self) -> String {
        format!("socks5->{}", self.server)
    }
    fn kind(&self) -> &'static str {
        "socks5"
    }
    async fn connect(&self, dst: &TargetAddr) -> std::io::Result<BoxStream> {
        let s = super::dial_underlying(&self.inner, &self.server).await?;
        socks5_connect_over(s, dst, self.auth.as_ref()).await
    }
    async fn connect_over(
        &self,
        stream: BoxStream,
        dst: &TargetAddr,
    ) -> std::io::Result<BoxStream> {
        socks5_connect_over(stream, dst, self.auth.as_ref()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TargetAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Full loop: local SOCKS5 server + echo target; client connector must round-trip.
    #[tokio::test]
    async fn socks5_client_server_roundtrip() {
        // Echo target server.
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = echo.accept().await else { return };
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 { break; }
                        if s.write_all(&buf[..n]).await.is_err() { break; }
                    }
                });
            }
        });

        // Local SOCKS5 server relaying through a direct connector.
        let hub = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hub_addr = hub.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = hub.accept().await else { return };
                tokio::spawn(async move {
                    let (dst, mut client) =
                        socks5_accept_client(Box::new(s)).await.unwrap();
                    let up = tokio::net::TcpStream::connect(match &dst {
                        TargetAddr::Ip(a) => *a,
                        _ => panic!("expected ip"),
                    })
                    .await
                    .unwrap();
                    let mut up: BoxStream = Box::new(up);
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
                });
            }
        });

        let conn = Socks5Connector::new(TargetAddr::Ip(hub_addr));
        let mut s = conn
            .connect(&TargetAddr::Ip(echo_addr))
            .await
            .unwrap();
        s.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }
}
