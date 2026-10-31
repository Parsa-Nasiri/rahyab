//! TLS ClientHello fragmentation — the patterniha/Serverless-for-Iran technique
//! (see docs/10): the first outgoing burst (which contains the TLS ClientHello and
//! therefore the SNI) is split at fixed byte offsets so DPI regexes can never
//! reassemble the SNI in one segment. Servers reassemble the stream normally.
//!
//! Used by the `frag` profile option: works with any variant (direct / ip / front /
//! via-hop), which is exactly the "combination" doctrine.

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use super::BoxStream;

pub struct FragStream {
    inner: BoxStream,
    /// Absolute byte offsets at which the FIRST outgoing burst is split.
    splits: Vec<usize>,
    /// Small delay between fragments (ms) — defeats burst reassembly heuristics.
    delay_ms: u64,
    prefix: Vec<u8>,
    prefix_done: bool,
    queue: VecDeque<Vec<u8>>,
    next_allowed: Option<std::time::Instant>,
}

impl FragStream {
    pub fn new(inner: BoxStream, splits: Vec<usize>, delay_ms: u64) -> Self {
        Self {
            inner,
            splits,
            delay_ms,
            prefix: Vec::new(),
            prefix_done: false,
            queue: VecDeque::new(),
            next_allowed: None,
        }
    }

    fn split_prefix(&mut self) {
        let mut offsets: Vec<usize> = self
            .splits
            .iter()
            .copied()
            .filter(|&o| o > 0 && o < self.prefix.len())
            .collect();
        offsets.sort_unstable();
        offsets.dedup();
        let mut last = 0usize;
        for o in offsets {
            self.queue.push_back(self.prefix[last..o].to_vec());
            last = o;
        }
        self.queue.push_back(self.prefix[last..].to_vec());
        self.prefix.clear();
        self.prefix_done = true;
    }

    fn do_flush(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        loop {
            if !self.prefix_done && !self.prefix.is_empty() {
                self.split_prefix();
            }
            if let Some(next) = self.next_allowed {
                if std::time::Instant::now() < next {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                self.next_allowed = None;
            }
            let Some(chunk) = self.queue.pop_front() else {
                // Queue drained: pass the flush through so inner TLS streams flush too.
                return Pin::new(&mut self.inner).poll_flush(cx);
            };
            let mut off = 0usize;
            while off < chunk.len() {
                let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &chunk[off..]))?;
                if n == 0 {
                    return Poll::Ready(Err(std::io::Error::other("frag: write zero")));
                }
                off += n;
            }
            if self.delay_ms > 0 {
                self.next_allowed =
                    Some(std::time::Instant::now() + std::time::Duration::from_millis(self.delay_ms));
            }
        }
    }
}

impl AsyncRead for FragStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FragStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.prefix_done {
            // Passthrough after the first burst.
            Pin::new(&mut this.inner).poll_write(cx, buf)
        } else {
            this.prefix.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.get_mut().do_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(this.do_flush(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::AsyncWriteExt;

    /// Records every write chunk separately.
    struct Recorder(Arc<Mutex<Vec<Vec<u8>>>>);
    impl AsyncWrite for Recorder {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.0.lock().unwrap().push(buf.to_vec());
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncRead for Recorder {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn clienthello_is_split_at_offsets() {
        let chunks: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let inner: BoxStream = Box::new(Recorder(chunks.clone()));
        // patterniha Serverless-for-Iran fragA: split ClientHello at 6 / 98 bytes.
        let mut s = FragStream::new(inner, vec![6, 98], 0);

        let hello: Vec<u8> = (0..250u8).collect(); // pretend ClientHello
        s.write_all(&hello).await.unwrap();
        s.flush().await.unwrap();

        let got = chunks.lock().unwrap();
        let sizes: Vec<usize> = got.iter().map(|c| c.len()).collect();
        assert_eq!(sizes, vec![6, 92, 152], "chunks: {sizes:?}");
        let joined: Vec<u8> = got.iter().flat_map(|c| c.iter().copied()).collect();
        assert_eq!(joined, hello, "reassembly must be byte-identical");
    }

    #[tokio::test]
    async fn passthrough_after_first_burst() {
        let chunks: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let inner: BoxStream = Box::new(Recorder(chunks.clone()));
        let mut s = FragStream::new(inner, vec![6], 0);

        s.write_all(&[0u8; 10]).await.unwrap();
        s.flush().await.unwrap();
        s.write_all(&[1u8; 40]).await.unwrap(); // after first burst: single write
        s.flush().await.unwrap();

        let got = chunks.lock().unwrap();
        let sizes: Vec<usize> = got.iter().map(|c| c.len()).collect();
        assert_eq!(sizes, vec![6, 4, 40], "chunks: {sizes:?}");
    }
}
