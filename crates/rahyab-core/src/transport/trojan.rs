//! Trojan client: TLS-wrapped password-authenticated proxy whose handshake is
//! indistinguishable from ordinary HTTPS traffic at the DPI level.

use super::{dial_underlying, io_err, tls, ws, BoxStream, Connector, SharedConnector, TargetAddr};
use async_trait::async_trait;
use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;

pub struct TrojanConnector {
    pub server: TargetAddr,
    pub password: String,
    pub tls: Option<tls::TlsSettings>,
    pub ws: Option<ws::WsSettings>,
    pub inner: Option<SharedConnector>,
}

impl TrojanConnector {
    fn server_host(&self) -> String {
        self.server.host()
    }

    async fn handshake(&self, mut s: BoxStream, dst: &TargetAddr) -> std::io::Result<BoxStream> {
        // Trojan requires TLS in practice; allow explicit override for testing.
        if let Some(t) = &self.tls {
            s = tls::tls_wrap(s, &self.server_host(), t).await?;
        }
        if let Some(w) = &self.ws {
            let mut w2 = w.clone();
            if w2.host_header.is_empty() {
                w2.host_header = self.server_host();
            }
            s = ws::ws_connect_over(s, &w2).await?;
        }
        let hash = hex_lower(&Sha224::digest(self.password.as_bytes()));
        let mut req = Vec::with_capacity(96);
        req.extend_from_slice(hash.as_bytes());
        req.extend_from_slice(b"\r\n");
        req.push(0x01); // CONNECT
        req.extend_from_slice(&dst.port().to_be_bytes());
        match dst {
            TargetAddr::Domain(h, _) => {
                req.push(0x03);
                req.push(h.len() as u8);
                req.extend_from_slice(h.as_bytes());
            }
            TargetAddr::Ip(a) => match a {
                std::net::SocketAddr::V4(v4) => {
                    req.push(0x01);
                    req.extend_from_slice(&v4.ip().octets());
                }
                std::net::SocketAddr::V6(v6) => {
                    req.push(0x04);
                    req.extend_from_slice(&v6.ip().octets());
                }
            },
        }
        req.extend_from_slice(b"\r\n");
        s.write_all(&req).await?;
        Ok(s) // trojan starts relaying immediately after CRLF
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[async_trait]
impl Connector for TrojanConnector {
    fn name(&self) -> String {
        format!("trojan->{}", self.server)
    }
    fn kind(&self) -> &'static str {
        "trojan"
    }
    async fn connect(&self, dst: &TargetAddr) -> std::io::Result<BoxStream> {
        let s = dial_underlying(&self.inner, &self.server).await?;
        self.handshake(s, dst).await
    }
    async fn connect_over(
        &self,
        stream: BoxStream,
        dst: &TargetAddr,
    ) -> std::io::Result<BoxStream> {
        self.handshake(stream, dst).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt};

    #[tokio::test]
    async fn trojan_request_shape() {
        let (client_side, mut server_side) = duplex(64 * 1024);
        let conn = TrojanConnector {
            server: TargetAddr::Domain("t.example".into(), 443),
            password: "pass123".into(),
            tls: None,
            ws: None,
            inner: None,
        };
        let h = tokio::spawn(async move {
            conn.connect_over(Box::new(client_side), &TargetAddr::Domain("x.com".into(), 443))
                .await
        });
        let mut req = vec![0u8; 56 + 2 + 1 + 2 + 1 + 1 + 5 + 2];
        server_side.read_exact(&mut req).await.unwrap();
        // hash is lowercase hex of sha224("pass123"), 56 bytes
        let expect = format!("{:x}", Sha224::digest(b"pass123"));
        assert_eq!(&req[..56], expect.as_bytes());
        assert_eq!(&req[56..58], b"\r\n");
        assert_eq!(req[58], 0x01);
        assert_eq!(&req[59..61], &443u16.to_be_bytes());
        assert_eq!(req[61], 0x03);
        assert_eq!(req[62], 5);
        assert_eq!(&req[63..68], b"x.com");
        assert_eq!(&req[68..70], b"\r\n");
        h.await.unwrap().unwrap();
    }
}
