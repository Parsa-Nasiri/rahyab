//! HTTP CONNECT proxy client (works with plain and Basic-auth HTTP proxies).

use super::{io_err, read_http_head, BoxStream, Connector, SharedConnector, TargetAddr};
use async_trait::async_trait;
use base64::Engine;
use tokio::io::AsyncWriteExt;

pub async fn http_connect_over(
    mut stream: BoxStream,
    dst: &TargetAddr,
    auth: Option<&(String, String)>,
) -> std::io::Result<BoxStream> {
    let hostport = dst.to_string();
    let mut req = format!("CONNECT {hostport} HTTP/1.1\r\nHost: {hostport}\r\n");
    if let Some((u, p)) = auth {
        let cred = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
        req.push_str(&format!("Proxy-Authorization: Basic {cred}\r\n"));
    }
    req.push_str("Proxy-Connection: keep-alive\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;
    let (head, _rest) = read_http_head(&mut stream).await?;
    let status = head.lines().next().unwrap_or("");
    if !status.contains(" 200") {
        return Err(io_err(format!("HTTP proxy refused: {status}")));
    }
    Ok(stream)
}

pub struct HttpConnector {
    pub server: TargetAddr,
    pub auth: Option<(String, String)>,
    pub inner: Option<SharedConnector>,
}

#[async_trait]
impl Connector for HttpConnector {
    fn name(&self) -> String {
        format!("http->{}", self.server)
    }
    fn kind(&self) -> &'static str {
        "http"
    }
    async fn connect(&self, dst: &TargetAddr) -> std::io::Result<BoxStream> {
        let s = super::dial_underlying(&self.inner, &self.server).await?;
        http_connect_over(s, dst, self.auth.as_ref()).await
    }
    async fn connect_over(
        &self,
        stream: BoxStream,
        dst: &TargetAddr,
    ) -> std::io::Result<BoxStream> {
        http_connect_over(stream, dst, self.auth.as_ref()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn connect_roundtrip() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = s.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(req.starts_with("CONNECT "));
            s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
            let mut buf = [0u8; 8];
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(&buf[..n]).await.unwrap();
        });
        let conn = HttpConnector { server: TargetAddr::Ip(addr), auth: None, inner: None };
        let mut s = conn
            .connect(&TargetAddr::Domain("backend.internal".into(), 80))
            .await
            .unwrap();
        s.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }
}
