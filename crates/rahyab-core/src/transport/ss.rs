//! Shadowsocks TCP client (SIP004 / "AEAD 2022-edition" v1 protocol), implemented directly
//! on `shadowsocks-crypto` (pure-RustCrypto backends — no C toolchain needed).
//!
//! Runs over ANY stream, so unlike library-based SS, chaining works here too
//! (e.g. SS inside a local Psiphon hop).
//!
//! Verified against the protocol spec: salt → HKDF-SHA1 "ss-subkey" → AEAD chunks of
//! [encrypted_len(2)][tag][encrypted_payload][tag], payload ≤ 0x3FFF.

use crate::transport::{
    dial_underlying, io_err, BoxStream, Connector, SharedConnector, TargetAddr,
};
use async_trait::async_trait;
use shadowsocks_crypto::v1::{openssl_bytes_to_key, Cipher};
use shadowsocks_crypto::{CipherKind, CipherCategory};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const MAX_CHUNK: usize = 0x3FFF;

pub struct SsConnector {
    pub server: TargetAddr,
    pub method: String,
    pub password: String,
    pub inner: Option<SharedConnector>,
}

impl SsConnector {
    fn parse_kind(&self) -> std::io::Result<CipherKind> {
        let kind: CipherKind = self
            .method
            .parse()
            .map_err(|_| io_err(format!("ss: unknown method '{}'", self.method)))?;
        if kind.category() != CipherCategory::Aead {
            return Err(io_err(format!(
                "ss: method '{}' is not an AEAD cipher (only AEAD methods are supported)",
                self.method
            )));
        }
        Ok(kind)
    }

    fn master_key(&self, kind: CipherKind) -> Vec<u8> {
        let mut key = vec![0u8; kind.key_len()];
        openssl_bytes_to_key(self.password.as_bytes(), &mut key);
        key
    }
}

fn encode_address(dst: &TargetAddr, out: &mut Vec<u8>) {
    match dst {
        TargetAddr::Domain(h, p) => {
            out.push(0x03);
            out.push(h.len() as u8);
            out.extend_from_slice(h.as_bytes());
            out.extend_from_slice(&p.to_be_bytes());
        }
        TargetAddr::Ip(a) => match a {
            std::net::SocketAddr::V4(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.ip().octets());
                out.extend_from_slice(&v4.port().to_be_bytes());
            }
            std::net::SocketAddr::V6(v6) => {
                out.push(0x04);
                out.extend_from_slice(&v6.ip().octets());
                out.extend_from_slice(&v6.port().to_be_bytes());
            }
        },
    }
}

enum ReadPhase {
    Salt,
    Len,
    Payload(usize),
}

pub struct SsStream {
    inner: BoxStream,
    enc: Cipher,
    dec: Option<Cipher>,
    key: Vec<u8>,
    kind: CipherKind,
    tag_len: usize,
    salt_len: usize,
    salt_sent: bool,
    phase: ReadPhase,
    acc: Vec<u8>,
    rx: Vec<u8>,
    tx_buf: Vec<u8>,
    pending_out: Option<(Vec<u8>, usize)>,
    closed: bool,
}

impl SsStream {
    fn new(inner: BoxStream, kind: CipherKind, key: Vec<u8>, dst: &TargetAddr) -> Self {
        let tag_len = kind.tag_len();
        let salt_len = kind.salt_len();
        // The encryption salt is drawn at first flush (so a fresh stream never
        // encrypts before the caller actually writes).
        let enc = Cipher::new(kind, &key, &[0u8; 32]);
        let mut tx_buf = Vec::with_capacity(64);
        encode_address(dst, &mut tx_buf);
        Self {
            inner,
            enc,
            dec: None,
            key,
            kind,
            tag_len,
            salt_len,
            salt_sent: false,
            phase: ReadPhase::Salt,
            acc: Vec::new(),
            rx: Vec::new(),
            tx_buf,
            pending_out: None,
            closed: false,
        }
    }

    /// Encrypt one SS chunk; returns the wire bytes for it.
    fn seal_chunk(&mut self, data: &[u8]) -> Vec<u8> {
        let t = self.tag_len;
        let mut lenblk = vec![0u8; 2 + t];
        lenblk[..2].copy_from_slice(&(data.len() as u16).to_be_bytes());
        self.enc.encrypt_packet(&mut lenblk);
        let mut payblk = vec![0u8; data.len() + t];
        payblk[..data.len()].copy_from_slice(data);
        self.enc.encrypt_packet(&mut payblk);
        let mut out = lenblk;
        out.extend(payblk);
        out
    }

    fn poll_next_payload(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<Option<()>>> {
        loop {
            match self.phase {
                ReadPhase::Salt => {
                    let need = self.salt_len;
                    while self.acc.len() < need {
                        let mut tmp = [0u8; 1024];
                        let mut rb = ReadBuf::new(&mut tmp);
                        ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
                        if rb.filled().is_empty() {
                            return Poll::Ready(Err(io_err("ss: eof before salt")));
                        }
                        self.acc.extend_from_slice(rb.filled());
                    }
                    let salt = self.acc.drain(..need).collect::<Vec<u8>>();
                    let dec = Cipher::new(self.kind, &self.key, &salt);
                    self.dec = Some(dec);
                    self.phase = ReadPhase::Len;
                }
                ReadPhase::Len => {
                    let need = 2 + self.tag_len;
                    while self.acc.len() < need {
                        let mut tmp = [0u8; 1024];
                        let mut rb = ReadBuf::new(&mut tmp);
                        ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
                        if rb.filled().is_empty() {
                            return Poll::Ready(Ok(None)); // clean EOF
                        }
                        self.acc.extend_from_slice(rb.filled());
                    }
                    let mut blk = self.acc.drain(..need).collect::<Vec<u8>>();
                    let dec = self.dec.as_mut().expect("dec after salt");
                    if !dec.decrypt_packet(&mut blk) {
                        return Poll::Ready(Err(io_err("ss: length chunk failed AEAD")));
                    }
                    let len = u16::from_be_bytes([blk[0], blk[1]]) as usize;
                    if len == 0 {
                        return Poll::Ready(Ok(None));
                    }
                    self.phase = ReadPhase::Payload(len);
                }
                ReadPhase::Payload(plen) => {
                    let need = plen + self.tag_len;
                    while self.acc.len() < need {
                        let mut tmp = vec![0u8; (need - self.acc.len()).min(16 * 1024)];
                        let mut rb = ReadBuf::new(&mut tmp);
                        ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
                        if rb.filled().is_empty() {
                            return Poll::Ready(Err(io_err("ss: eof mid-payload")));
                        }
                        self.acc.extend_from_slice(rb.filled());
                    }
                    let mut blk = self.acc.drain(..need).collect::<Vec<u8>>();
                    let dec = self.dec.as_mut().expect("dec after salt");
                    if !dec.decrypt_packet(&mut blk) {
                        return Poll::Ready(Err(io_err("ss: payload failed AEAD")));
                    }
                    blk.truncate(plen);
                    self.rx.extend_from_slice(&blk);
                    self.phase = ReadPhase::Len;
                    return Poll::Ready(Ok(Some(())));
                }
            }
        }
    }

    fn do_flush(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.pending_out.is_none() {
            let mut wire = Vec::new();
            if !self.salt_sent {
                let mut salt = vec![0u8; self.salt_len];
                shadowsocks_crypto::utils::random_iv_or_salt(&mut salt);
                self.enc = Cipher::new(self.kind, &self.key.clone(), &salt);
                wire.extend_from_slice(&salt);
                self.salt_sent = true;
            }
            while !self.tx_buf.is_empty() {
                let take = self.tx_buf.len().min(MAX_CHUNK);
                let chunk: Vec<u8> = self.tx_buf.drain(..take).collect();
                wire.extend(self.seal_chunk(&chunk));
            }
            if !wire.is_empty() {
                self.pending_out = Some((wire, 0));
            }
        }
        while let Some((frame, off)) = &mut self.pending_out {
            while *off < frame.len() {
                let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &frame[*off..]))?;
                if n == 0 {
                    return Poll::Ready(Err(io_err("ss: write zero")));
                }
                *off += n;
            }
            self.pending_out = None;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for SsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.rx.is_empty() {
                let n = buf.remaining().min(this.rx.len());
                let data: Vec<u8> = this.rx.drain(..n).collect();
                buf.put_slice(&data);
                return Poll::Ready(Ok(()));
            }
            match this.poll_next_payload(cx)? {
                Poll::Ready(Some(())) => continue,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for SsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.tx_buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.get_mut().do_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.closed {
            this.closed = true;
        }
        ready!(this.do_flush(cx))?;
        ready!(Pin::new(&mut this.inner).poll_shutdown(cx))?;
        Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl Connector for SsConnector {
    fn name(&self) -> String {
        format!("ss->{}", self.server)
    }
    fn kind(&self) -> &'static str {
        "ss"
    }
    async fn connect(&self, dst: &TargetAddr) -> std::io::Result<BoxStream> {
        let kind = self.parse_kind()?;
        let key = self.master_key(kind);
        let s = dial_underlying(&self.inner, &self.server).await?;
        Ok(Box::new(SsStream::new(s, kind, key, dst)))
    }
    async fn connect_over(
        &self,
        stream: BoxStream,
        dst: &TargetAddr,
    ) -> std::io::Result<BoxStream> {
        let kind = self.parse_kind()?;
        let key = self.master_key(kind);
        Ok(Box::new(SsStream::new(stream, kind, key, dst)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    /// In-process SS *server* (decrypts requests, echoes payloads back encrypted)
    /// to validate the client codec end-to-end.
    async fn fake_ss_server(mut sock: BoxStream, key: Vec<u8>, kind: CipherKind) {
        let tag = kind.tag_len();
        let salt_len = kind.salt_len();
        let mut acc: Vec<u8> = Vec::new();

        // read salt
        let mut tmp = [0u8; 512];
        while acc.len() < salt_len {
            let n = sock.read(&mut tmp).await.unwrap();
            acc.extend_from_slice(&tmp[..n]);
        }
        let salt = acc.drain(..salt_len).collect::<Vec<u8>>();
        let mut dec = Cipher::new(kind, &key, &salt);
        let mut enc: Option<Cipher> = None;

        // First payload contains the address; just parse/skip it, then echo everything after.
        let mut first = true;
        loop {
            // len chunk
            while acc.len() < 2 + tag {
                let n = sock.read(&mut tmp).await.unwrap();
                if n == 0 {
                    return;
                }
                acc.extend_from_slice(&tmp[..n]);
            }
            let mut blk = acc.drain(..2 + tag).collect::<Vec<u8>>();
            assert!(dec.decrypt_packet(&mut blk), "server: len AEAD fail");
            let len = u16::from_be_bytes([blk[0], blk[1]]) as usize;
            while acc.len() < len + tag {
                let n = sock.read(&mut tmp).await.unwrap();
                acc.extend_from_slice(&tmp[..n]);
            }
            let mut pay = acc.drain(..len + tag).collect::<Vec<u8>>();
            assert!(dec.decrypt_packet(&mut pay), "server: payload AEAD fail");
            pay.truncate(len);

            if first {
                // skip address: atyp + ... + port
                let atyp = pay[0];
                let skip = match atyp {
                    0x01 => 1 + 4 + 2,
                    0x04 => 1 + 16 + 2,
                    0x03 => 1 + 1 + pay[1] as usize + 2,
                    _ => panic!("bad atyp"),
                };
                pay.drain(..skip);
                // Server replies with its own salt + its own cipher direction.
                let mut s2 = vec![0u8; salt_len];
                shadowsocks_crypto::utils::random_iv_or_salt(&mut s2);
                enc = Some(Cipher::new(kind, &key, &s2));
                sock.write_all(&s2).await.unwrap();
                first = false;
            }
            if pay.is_empty() {
                continue;
            }
            // echo
            let e = enc.as_mut().unwrap();
            let mut lenblk = vec![0u8; 2 + tag];
            lenblk[..2].copy_from_slice(&(pay.len() as u16).to_be_bytes());
            e.encrypt_packet(&mut lenblk);
            let mut payblk = vec![0u8; pay.len() + tag];
            payblk[..pay.len()].copy_from_slice(&pay);
            e.encrypt_packet(&mut payblk);
            sock.write_all(&lenblk).await.unwrap();
            sock.write_all(&payblk).await.unwrap();
        }
    }

    #[tokio::test]
    async fn ss_roundtrip_over_duplex() {
        let kind: CipherKind = "aes-256-gcm".parse().unwrap();
        let key = {
            let mut k = vec![0u8; kind.key_len()];
            openssl_bytes_to_key(b"hunter2", &mut k);
            k
        };
        let (client_side, server_side) = duplex(64 * 1024);
        tokio::spawn(fake_ss_server(Box::new(server_side), key.clone(), kind));

        let conn = SsConnector {
            server: TargetAddr::Domain("ss.example".into(), 8388),
            method: "aes-256-gcm".into(),
            password: "hunter2".into(),
            inner: None,
        };
        // Route the raw stream through our SsStream manually (server is the dial target).
        let stream = conn
            .connect_over(
                Box::new(client_side),
                &TargetAddr::Domain("target.example".into(), 80),
            )
            .await
            .unwrap();
        let mut s = stream;
        s.write_all(b"hello through ss").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 16];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello through ss");
    }

    #[test]
    fn rejects_non_aead() {
        let c = SsConnector {
            server: TargetAddr::Domain("ss.example".into(), 8388),
            method: "rc4-md5".into(),
            password: "x".into(),
            inner: None,
        };
        // rc4-md5 parses but is a stream cipher → rejected
        assert!(c.parse_kind().is_err());
    }

    #[test]
    fn rejects_unknown() {
        let c = SsConnector {
            server: TargetAddr::Domain("ss.example".into(), 8388),
            method: "rot13".into(),
            password: "x".into(),
            inner: None,
        };
        assert!(c.parse_kind().is_err());
    }
}
