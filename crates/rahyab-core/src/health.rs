//! Connectivity health checks: real end-to-end verification through a candidate tunnel
//! using captive-portal-style `generate_204` endpoints (multiple providers, any one
//! success counts — during blackouts individual providers themselves may be blocked).

use crate::transport::{read_http_head, BoxStream, SharedConnector, TargetAddr};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;

pub const DEFAULT_HEALTH_TARGETS: &[(&str, u16, &str)] = &[
    ("cp.cloudflare.com", 80, "/generate_204"),
    ("www.gstatic.com", 80, "/generate_204"),
    ("connect.rom.miui.com", 80, "/generate_204"),
    ("captive.v2ex.co", 80, "/generate_204"),
];

pub async fn check_health(
    conn: &SharedConnector,
    timeout: Duration,
) -> Result<Duration, String> {
    check_health_targets(conn, DEFAULT_HEALTH_TARGETS, timeout).await
}

pub async fn check_health_targets(
    conn: &SharedConnector,
    targets: &[(&str, u16, &str)],
    timeout: Duration,
) -> Result<Duration, String> {
    let mut last_err = String::from("no targets");
    for (host, port, path) in targets {
        let started = Instant::now();
        match tokio::time::timeout(timeout, health_once(conn, host, *port, path)).await {
            Ok(Ok(())) => return Ok(started.elapsed()),
            Ok(Err(e)) => last_err = format!("{host}: {e}"),
            Err(_) => last_err = format!("{host}: timeout"),
        }
    }
    Err(last_err)
}

async fn health_once(
    conn: &SharedConnector,
    host: &str,
    port: u16,
    path: &str,
) -> Result<(), String> {
    let mut s: BoxStream = conn
        .connect(&TargetAddr::Domain(host.to_string(), port))
        .await
        .map_err(|e| e.to_string())?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: rahyab/0.1\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    let (head, _) = read_http_head(&mut s).await.map_err(|e| e.to_string())?;
    let status = head.lines().next().unwrap_or("");
    // 204 = perfect; 200/301/302 also prove end-to-end reachability.
    if status.contains(" 204")
        || status.contains(" 200")
        || status.contains(" 301")
        || status.contains(" 302")
    {
        Ok(())
    } else {
        Err(format!("unexpected status: {status}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Connector;
    use async_trait::async_trait;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct EchoHttp;
    #[async_trait]
    impl Connector for EchoHttp {
        fn name(&self) -> String { "echo".into() }
        fn kind(&self) -> &'static str { "test" }
        async fn connect(&self, _dst: &TargetAddr) -> std::io::Result<BoxStream> {
            let (a, mut b) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 512];
                if let Ok(n) = b.read(&mut buf).await {
                    let _ = b
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    let _ = n;
                }
            });
            Ok(Box::new(a))
        }
        async fn connect_over(&self, _s: BoxStream, _d: &TargetAddr) -> std::io::Result<BoxStream> {
            Err(std::io::Error::other("no"))
        }
    }

    #[tokio::test]
    async fn healthy_connector_passes() {
        let conn: SharedConnector = Arc::new(EchoHttp);
        let r = check_health(&conn, Duration::from_secs(2)).await;
        assert!(r.is_ok());
    }
}
