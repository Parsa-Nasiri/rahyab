//! Minimal RFC 6455 WebSocket client that runs over ANY stream (plain TCP or TLS).
//! This is the transport used by the hugely popular Cloudflare Workers / edgetunnel
//! VLESS profiles: VLESS over WebSocket over TLS to a CDN edge.
//!
//! Implemented as a transparent ProxyStream adapter: writers buffer and flush as binary
//! frames, reads demultiplex frames into a byte stream, pings are answered automatically.

use super::{io_err, read_http_head, BoxStream};
use base64::Engine;
use sha1::Digest;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

#[derive(Debug, Clone)]
pub struct WsSettings {
    /// Host header value (often the fronted domain on CDN profiles).
    pub host_header: String,
    /// Path incl. leading '/', e.g. "/vlessws".
    pub path: String,
    /// Extra headers (some deployments require them).
    pub extra_headers: Vec<(String, String)>,
}

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fn encode_frame(opcode: u8, data: &[u8]) -> Vec<u8> {
    let mask: [u8; 4] = rand::random();
    let mut head = vec![0x80u8 | opcode];
    let len = data.len();
    if len < 126 {
        head.push(0x80 | len as u8);
    } else if len <= 0xFFFF {
        head.push(0x80 | 126);
        head.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        head.push(0x80 | 127);
        head.extend_from_slice(&(len as u64).to_be_bytes());
    }
    head.extend_from_slice(&mask);
    let mut out = head;
    out.extend(data.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    out
}

pub async fn ws_connect_over(
    mut stream: BoxStream,
    s: &WsSettings,
) -> std::io::Result<BoxStream> {
    let key_raw: [u8; 16] = rand::random();
    let key = base64::engine::general_purpose::STANDARD.encode(key_raw);
    let mut req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n",
        s.path, s.host_header, key
    );
    for (k, v) in &s.extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;

    let (head, _rest) = read_http_head(&mut stream).await?;
    let first = head.lines().next().unwrap_or("");
    if !first.contains("101") {
        return Err(io_err(format!("ws handshake failed: {first}")));
    }
    let accept = head.lines().find_map(|l| {
        let l = l.trim();
        if l.to_ascii_lowercase().starts_with("sec-websocket-accept:") {
            l.split_once(':').map(|(_, v)| v.trim().to_string())
        } else {
            None
        }
    });
    let expected = base64::engine::general_purpose::STANDARD
        .encode(sha1::Sha1::digest(format!("{key}{GUID}")));
    match accept {
        Some(a) if a == expected => {}
        _ => return Err(io_err("ws: Sec-WebSocket-Accept mismatch")),
    }
    Ok(Box::new(WsStream::new(stream)))
}

#[derive(Clone, Copy)]
struct FrameHead {
    fin: bool,
    opcode: u8,
    need: usize,
    mask: Option<[u8; 4]>,
}

pub struct WsStream {
    inner: BoxStream,
    head: Vec<u8>,
    head_need: usize,
    frame: Option<FrameHead>,
    payload: Vec<u8>,
    rx_msg: Vec<u8>,
    rx: Vec<u8>,
    tx_buf: Vec<u8>,
    control_out: Vec<u8>,
    pending_out: Option<(Vec<u8>, usize)>,
    close_sent: bool,
}

impl WsStream {
    fn new(inner: BoxStream) -> Self {
        Self {
            inner,
            head: Vec::with_capacity(16),
            head_need: 2,
            frame: None,
            payload: Vec::new(),
            rx_msg: Vec::new(),
            rx: Vec::new(),
            tx_buf: Vec::new(),
            control_out: Vec::new(),
            pending_out: None,
            close_sent: false,
        }
    }

    fn poll_next_message(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<Option<Vec<u8>>>> {
        loop {
            if self.frame.is_none() {
                while self.head.len() < self.head_need {
                    let mut tmp = [0u8; 64];
                    let mut rb = ReadBuf::new(&mut tmp);
                    ready!(
                        Pin::new(&mut self.inner).poll_read(cx, &mut rb)
                    )?;
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io_err("ws: eof in header")));
                    }
                    self.head.extend_from_slice(rb.filled());
                    if self.head.len() >= 2 && self.head_need == 2 {
                        let b1 = self.head[1];
                        let l7 = (b1 & 0x7f) as usize;
                        let ext = match l7 {
                            126 => 2,
                            127 => 8,
                            _ => 0,
                        };
                        let maskb = if b1 & 0x80 != 0 { 4 } else { 0 };
                        self.head_need = 2 + ext + maskb;
                    }
                }
                let b0 = self.head[0];
                let b1 = self.head[1];
                let fin = b0 & 0x80 != 0;
                let opcode = b0 & 0x0f;
                let l7 = (b1 & 0x7f) as usize;
                let masked = b1 & 0x80 != 0;
                let mut idx = 2usize;
                let need = match l7 {
                    126 => {
                        let v = u16::from_be_bytes([self.head[2], self.head[3]]) as usize;
                        idx = 4;
                        v
                    }
                    127 => {
                        let v = u64::from_be_bytes(self.head[2..10].try_into().unwrap()) as usize;
                        idx = 10;
                        v
                    }
                    _ => l7,
                };
                let mask = if masked {
                    Some(self.head[idx..idx + 4].try_into().unwrap())
                } else {
                    None
                };
                let hlen = idx + if masked { 4 } else { 0 };
                // Payload bytes that arrived coalesced with the header must NOT be
                // dropped — move them into the payload accumulator (this is what the
                // duplex roundtrip test catches).
                let leftover: Vec<u8> = self.head[hlen..].to_vec();
                self.frame = Some(FrameHead { fin, opcode, need, mask });
                self.payload = leftover;
                self.head.clear();
                self.head_need = 2;
            }

            let (fin, opcode, need, mask) = {
                let f = self.frame.as_ref().unwrap();
                (f.fin, f.opcode, f.need, f.mask)
            };
            while self.payload.len() < need {
                let rem = need - self.payload.len();
                let mut tmp = vec![0u8; rem.min(16 * 1024)];
                let mut rb = ReadBuf::new(&mut tmp);
                ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
                let n = rb.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io_err("ws: eof mid-frame")));
                }
                self.payload.extend_from_slice(rb.filled());
            }
            let mut data = std::mem::take(&mut self.payload);
            if let Some(m) = mask {
                for (i, b) in data.iter_mut().enumerate() {
                    *b ^= m[i % 4];
                }
            }
            self.frame = None;

            match opcode {
                0x9 => {
                    // ping → pong (queued for next flush)
                    self.control_out.extend(encode_frame(0xA, &data));
                }
                0x8 => {
                    self.control_out.extend(encode_frame(0x8, &[]));
                    return Poll::Ready(Ok(None));
                }
                0xA => {} // pong: ignore
                0x0 => {
                    self.rx_msg.extend_from_slice(&data);
                    if fin {
                        return Poll::Ready(Ok(Some(std::mem::take(&mut self.rx_msg))));
                    }
                }
                _ => {
                    // text(1)/binary(2)
                    if fin && self.rx_msg.is_empty() {
                        return Poll::Ready(Ok(Some(data)));
                    }
                    self.rx_msg.extend_from_slice(&data);
                    if fin {
                        return Poll::Ready(Ok(Some(std::mem::take(&mut self.rx_msg))));
                    }
                }
            }
        }
    }

    fn do_flush(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        loop {
            if !self.control_out.is_empty() && self.pending_out.is_none() {
                let c = std::mem::take(&mut self.control_out);
                self.pending_out = Some((c, 0));
            } else if self.pending_out.is_none() && !self.tx_buf.is_empty() {
                let data = std::mem::take(&mut self.tx_buf);
                self.pending_out = Some((encode_frame(0x2, &data), 0));
            }
            match &mut self.pending_out {
                Some((frame, off)) => {
                    while *off < frame.len() {
                        let n =
                            ready!(Pin::new(&mut self.inner).poll_write(cx, &frame[*off..]))?;
                        if n == 0 {
                            return Poll::Ready(Err(io_err("ws: write zero")));
                        }
                        *off += n;
                    }
                    self.pending_out = None;
                }
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncRead for WsStream {
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
            match this.poll_next_message(cx)? {
                Poll::Ready(Some(data)) => this.rx.extend_from_slice(&data),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for WsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.tx_buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.get_mut().do_flush(cx)
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.close_sent {
            this.control_out.extend(encode_frame(0x8, &[]));
            this.close_sent = true;
        }
        ready!(this.do_flush(cx))?;
        ready!(Pin::new(&mut this.inner).poll_shutdown(cx))?;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn frame_roundtrip_in_memory() {
        // Server side simulator (no masking on server->client).
        let (client_side, mut server_side) = duplex(64 * 1024);
        // Handshake response
        let (a, b) = duplex(64 * 1024);
        drop(b);
        let _ = a; // unused

        let ws = WsStream::new(Box::new(client_side));
        let mut ws = ws;

        // Server sends a binary message (unmasked), client reads it.
        let mut raw = vec![0x82u8, 5];
        raw.extend(b"hello");
        server_side.write_all(&raw).await.unwrap();
        server_side.flush().await.unwrap();

        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 5];
        ws.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        // Client writes → buffered until flush → masked binary frame.
        use tokio::io::AsyncWriteExt;
        ws.write_all(b"ping-data").await.unwrap();
        ws.flush().await.unwrap();

        let mut hdr = [0u8; 2];
        server_side.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[0] & 0x0f, 0x2);
        assert!(hdr[1] & 0x80 != 0, "client frames must be masked");
        let l7 = (hdr[1] & 0x7f) as usize;
        let mut rest = vec![0u8; 4 + l7];
        server_side.read_exact(&mut rest).await.unwrap();
        let mask = &rest[..4];
        let payload = &rest[4..];
        let unmasked: Vec<u8> = payload
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect();
        assert_eq!(unmasked, b"ping-data");
    }
}
