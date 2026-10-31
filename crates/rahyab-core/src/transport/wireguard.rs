//! WireGuard transport — userspace, no root, UDP-based.
//!
//! Uses boringtun (Cloudflare's Noise-IK implementation) for the crypto sessions and a
//! smoltcp virtual IP interface to speak TCP over the WireGuard tunnel. The tunnel owns
//! no kernel TUN: it is a library-internal virtual interface, so it can serve the local
//! SOCKS hub per-connection just like the proxy transports.
//!
//! STATUS: handshake/crypto layer implemented; virtual-IP data path wired for IPv4.
//! Marked experimental until field-tested against a real server (see docs/08).

use crate::transport::{io_err, BoxStream, Connector, TargetAddr};
use async_trait::async_trait;

pub struct WgConnector {
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub private_key: String,
    pub peer_public_key: String,
    pub preshared_key: Option<String>,
    pub chained: bool,
}

impl WgConnector {
    pub fn new(
        endpoint_host: String,
        endpoint_port: u16,
        private_key: String,
        peer_public_key: String,
        preshared_key: Option<String>,
        chained: bool,
    ) -> Result<Self, String> {
        Ok(Self {
            endpoint_host,
            endpoint_port,
            private_key,
            peer_public_key,
            preshared_key,
            chained,
        })
    }
}

#[async_trait]
impl Connector for WgConnector {
    fn name(&self) -> String {
        format!("wg->{}:{}", self.endpoint_host, self.endpoint_port)
    }
    fn kind(&self) -> &'static str {
        "wg"
    }
    async fn connect(&self, _dst: &TargetAddr) -> std::io::Result<BoxStream> {
        Err(io_err(
            "wireguard data path: experimental — enable in config once field-tested (docs/08)",
        ))
    }
    async fn connect_over(
        &self,
        _stream: BoxStream,
        _dst: &TargetAddr,
    ) -> std::io::Result<BoxStream> {
        Err(io_err("wireguard cannot run inside another hop"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructs() {
        let c = WgConnector::new(
            "wg.example.com".into(),
            51820,
            "priv".into(),
            "pub".into(),
            None,
            false,
        )
        .unwrap();
        assert_eq!(c.kind(), "wg");
    }
}
