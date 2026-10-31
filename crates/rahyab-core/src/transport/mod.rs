//! Transport abstraction: every tunnel exposes the same two operations —
//! `connect` (dial the target through this tunnel, opening the underlying channel yourself)
//! and `connect_over` (run this tunnel's protocol over an already-established stream).
//!
//! That second method is what makes arbitrary chaining possible: a VLESS tunnel can run
//! its handshake over a stream that came out of a Psiphon SOCKS hop, and so on.

pub mod frag;
pub mod http_proxy;
pub mod socks5;
pub mod ss;
pub mod tls;
pub mod trojan;
pub mod vless;
pub mod ws;
#[cfg(feature = "wireguard")]
pub mod wireguard;

use async_trait::async_trait;
use std::fmt;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetAddr {
    Domain(String, u16),
    Ip(std::net::SocketAddr),
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetAddr::Domain(h, p) => write!(f, "{h}:{p}"),
            TargetAddr::Ip(a) => write!(f, "{a}"),
        }
    }
}

impl TargetAddr {
    pub fn host(&self) -> String {
        match self {
            TargetAddr::Domain(h, _) => h.clone(),
            TargetAddr::Ip(a) => a.ip().to_string(),
        }
    }
    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Domain(_, p) => *p,
            TargetAddr::Ip(a) => a.port(),
        }
    }
}

pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProxyStream for T {}

pub type BoxStream = Box<dyn ProxyStream>;
pub type SharedConnector = Arc<dyn Connector>;

#[async_trait]
pub trait Connector: Send + Sync {
    fn name(&self) -> String;
    fn kind(&self) -> &'static str;
    /// Dial `dst` through this tunnel. Opens the underlying channel itself
    /// (through `inner` hop if one is configured, otherwise plain TCP).
    async fn connect(&self, dst: &TargetAddr) -> std::io::Result<BoxStream>;
    /// Run this tunnel's protocol over an already-established stream toward the tunnel
    /// server, then request `dst` inside it. Used for chaining.
    async fn connect_over(&self, stream: BoxStream, dst: &TargetAddr) -> std::io::Result<BoxStream>;
}

/// Helper: dial the tunnel server through the inner hop (if any) or plain TCP.
pub async fn dial_underlying(
    inner: &Option<SharedConnector>,
    server: &TargetAddr,
) -> std::io::Result<BoxStream> {
    match inner {
        Some(c) => c.connect(server).await,
        None => tcp_dial(server).await,
    }
}

pub async fn tcp_dial(dst: &TargetAddr) -> std::io::Result<BoxStream> {
    match dst {
        TargetAddr::Domain(h, p) => Ok(Box::new(
            tokio::net::TcpStream::connect((h.as_str(), *p)).await?,
        )),
        TargetAddr::Ip(a) => Ok(Box::new(tokio::net::TcpStream::connect(a).await?)),
    }
}

pub fn io_err(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::other(msg.into())
}

/// Read one HTTP/1.1 response head (up to `\r\n\r\n`) and return `(head, leftover_bytes)`.
pub async fn read_http_head(stream: &mut BoxStream) -> std::io::Result<(String, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).to_string();
            let rest = buf[pos + 4..].to_vec();
            return Ok((head, rest));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io_err("connection closed while reading HTTP head"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 256 * 1024 {
            return Err(io_err("HTTP head too large"));
        }
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Dial a fixed IP:port regardless of the logical server address.
/// Used for "prefer_ips" (CDN IP optimisation): TLS/WS still use the domain for SNI/Host,
/// but the TCP connection goes to the pinned IP.
pub struct TcpDialFix {
    pub addr: std::net::SocketAddr,
}

#[async_trait]
impl Connector for TcpDialFix {
    fn name(&self) -> String {
        format!("tcp({})", self.addr)
    }
    fn kind(&self) -> &'static str {
        "tcp"
    }
    async fn connect(&self, _dst: &TargetAddr) -> std::io::Result<BoxStream> {
        tcp_dial(&TargetAddr::Ip(self.addr)).await
    }
    async fn connect_over(
        &self,
        _stream: BoxStream,
        _dst: &TargetAddr,
    ) -> std::io::Result<BoxStream> {
        Err(io_err("TcpDialFix cannot run over an existing stream"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_subsequence() {
        assert_eq!(find(b"abc\r\n\r\ndef", b"\r\n\r\n"), Some(3));
        assert_eq!(find(b"short", b"\r\n\r\n"), None);
    }

    #[test]
    fn target_display() {
        assert_eq!(
            TargetAddr::Domain("example.com".into(), 443).to_string(),
            "example.com:443"
        );
    }
}
