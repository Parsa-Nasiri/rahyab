//! VLESS client (XTLS protocol family) over any layered transport.
//! Composition supported: TCP → [TLS] → [WebSocket] → VLESS — the exact shape used by
//! Cloudflare-Workers (edgetunnel) deployments that are ubiquitous in the Iranian community.

use super::{dial_underlying, io_err, tls, ws, BoxStream, Connector, SharedConnector, TargetAddr};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct VlessConnector {
    pub server: TargetAddr,
    pub uuid: uuid::Uuid,
    pub tls: Option<tls::TlsSettings>,
    pub ws: Option<ws::WsSettings>,
    pub inner: Option<SharedConnector>,
}

impl VlessConnector {
    fn server_host(&self) -> String {
        self.server.host()
    }

    async fn handshake(&self, mut s: BoxStream, dst: &TargetAddr) -> std::io::Result<BoxStream> {
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
        let mut req = Vec::with_capacity(64);
        req.push(0x00); // version
        req.extend_from_slice(self.uuid.as_bytes());
        req.push(0x00); // addons length
        req.push(0x01); // cmd: TCP
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
        s.write_all(&req).await?;
        let mut hdr = [0u8; 2];
        s.read_exact(&mut hdr).await?;
        if hdr[0] != 0x00 {
            return Err(io_err(format!("vless: bad response version {}", hdr[0])));
        }
        let addon = hdr[1] as usize;
        if addon > 0 {
            let mut junk = vec![0u8; addon];
            s.read_exact(&mut junk).await?;
        }
        Ok(s)
    }
}

#[async_trait]
impl Connector for VlessConnector {
    fn name(&self) -> String {
        format!("vless->{}", self.server)
    }
    fn kind(&self) -> &'static str {
        "vless"
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
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    /// A fake VLESS server: parses the request, replies with the header, then echoes.
    #[tokio::test]
    async fn vless_request_encoding() {
        let (client_side, mut server_side) = duplex(64 * 1024);
        let conn = VlessConnector {
            server: TargetAddr::Domain("vless.example".into(), 443),
            uuid: uuid::Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap(),
            tls: None,
            ws: None,
            inner: None,
        };
        let h = tokio::spawn(async move {
            conn.connect_over(Box::new(client_side), &TargetAddr::Domain("site.com".into(), 80))
                .await
                .unwrap()
        });

        // server reads request
        let mut req = vec![0u8; 1 + 16 + 1 + 1 + 2 + 1 + 1 + 8];
        server_side.read_exact(&mut req).await.unwrap();
        assert_eq!(req[0], 0x00);
        assert_eq!(&req[1..17], uuid::Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap().as_bytes());
        assert_eq!(req[17], 0); // addon len
        assert_eq!(req[18], 0x01); // cmd tcp
        assert_eq!(&req[19..21], &80u16.to_be_bytes());
        assert_eq!(req[21], 0x03); // domain
        let dlen = req[22] as usize;
        assert_eq!(&req[23..23 + dlen], b"site.com");
        // reply
        server_side.write_all(&[0x00, 0x00]).await.unwrap();
        let mut s = h.await.unwrap();
        s.write_all(b"payload").await.unwrap();
        server_side.write_all(b"echo-back").await.unwrap();
        let mut buf = [0u8; 9];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"echo-back");
    }
}
