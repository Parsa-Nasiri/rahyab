//! TLS layer (rustls + ring) with three modes:
//! - normal    : webpki roots, SNI = server host
//! - insecure  : accept any certificate (needed when you connect by IP or by a CDN edge)
//! - sni-front : send an arbitrary SNI (e.g. an allowed domain) while verifying nothing —
//!               the SNI-based censorship evasion primitive.

use super::{io_err, BoxStream, Connector, SharedConnector, TargetAddr};
use async_trait::async_trait;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone, Default)]
pub struct TlsSettings {
    /// SNI to send. None = use the server host.
    pub sni: Option<String>,
    /// Accept any server certificate (SNI spoofing, IP dialing, self-signed servers).
    pub insecure: bool,
    /// ALPN offers, e.g. ["h2","http/1.1"].
    pub alpn: Option<Vec<String>>,
    /// ClientHello fragmentation offsets (patterniha Serverless-for-Iran technique):
    /// split the first outgoing burst so DPI cannot regex the SNI. E.g. [6, 98].
    pub frag_splits: Option<Vec<usize>>,
}

#[derive(Debug)]
struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub async fn tls_wrap(
    stream: BoxStream,
    cert_host: &str,
    settings: &TlsSettings,
) -> std::io::Result<BoxStream> {
    let provider = Arc::new(default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| io_err(e.to_string()))?;

    let mut config = if settings.insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    if let Some(alpn) = &settings.alpn {
        config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    }

    let sni = settings.sni.clone().unwrap_or_else(|| cert_host.to_string());
    let name = ServerName::try_from(sni).map_err(|e| io_err(format!("bad SNI: {e}")))?;
    // ClientHello fragmentation happens BEFORE the handshake so rustls's single
    // ClientHello write gets split on the wire.
    let stream: BoxStream = match &settings.frag_splits {
        Some(splits) if !splits.is_empty() => Box::new(super::frag::FragStream::new(stream, splits.clone(), 0)),
        _ => stream,
    };
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config));
    let s = tls
        .connect(name, stream)
        .await
        .map_err(|e| io_err(format!("tls: {e}")))?;
    Ok(Box::new(s))
}

/// TLS decoration around another connector (or plain TCP).
pub struct TlsConnector {
    pub server: TargetAddr,
    pub cert_host: String,
    pub settings: TlsSettings,
    pub inner: Option<SharedConnector>,
}

#[async_trait]
impl Connector for TlsConnector {
    fn name(&self) -> String {
        format!("tls({})", self.cert_host)
    }
    fn kind(&self) -> &'static str {
        "tls"
    }
    async fn connect(&self, dst: &TargetAddr) -> std::io::Result<BoxStream> {
        let s = super::dial_underlying(&self.inner, &self.server).await?;
        self.connect_over(s, dst).await
    }
    async fn connect_over(
        &self,
        stream: BoxStream,
        _dst: &TargetAddr,
    ) -> std::io::Result<BoxStream> {
        tls_wrap(stream, &self.cert_host, &self.settings).await
    }
}

/// Minimal HTTP/1.1 GET over any (usually TLS) stream — used for DoH and health checks.
pub async fn http_get(
    mut stream: BoxStream,
    host: &str,
    path: &str,
    accept: &str,
) -> std::io::Result<String> {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: rahyab/0.1\r\nAccept: {accept}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    let (head, mut rest) = read_http_head_pub(&mut stream).await?;
    let status = head.lines().next().unwrap_or("");
    if !status.contains(" 200") {
        return Err(io_err(format!("http_get status: {status}")));
    }
    // Body may be chunked; for our JSON APIs treat content-length and plain the same by
    // simply reading to EOF (Connection: close) after stripping a chunked encoding marker.
    use tokio::io::AsyncReadExt;
    let mut body = rest;
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
        if body.len() > 1 << 20 {
            break;
        }
    }
    let head_l = head.to_ascii_lowercase();
    let body = if head_l.contains("transfer-encoding: chunked") {
        dechunk(&body)
    } else {
        body
    };
    Ok(String::from_utf8_lossy(&body).to_string())
}

pub async fn read_http_head_pub(stream: &mut BoxStream) -> std::io::Result<(String, Vec<u8>)> {
    // reuse the shared helper
    crate::transport::read_http_head(stream).await
}

fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0usize;
    while i < body.len() {
        let Some(line_end) = body[i..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| i + p)
        else {
            break;
        };
        let size_str = String::from_utf8_lossy(&body[i..line_end]);
        let Ok(size) = usize::from_str_radix(size_str.trim().split(';').next().unwrap_or("0"), 16)
        else {
            break;
        };
        if size == 0 {
            break;
        }
        let start = line_end + 2;
        let end = (start + size).min(body.len());
        out.extend_from_slice(&body[start..end]);
        i = end + 2;
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn dechunk_basic() {
        let raw = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(super::dechunk(raw), b"Wikipedia".to_vec());
    }
}
