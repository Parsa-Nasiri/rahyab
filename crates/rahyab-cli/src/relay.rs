//! GitHub Actions store-and-forward relay — the channel you already field-verified
//! (Parsa-Nasiri/internet-relay, 25–35s round-trip, works whenever api.github.com and
//! raw.githubusercontent.com are reachable).
//!
//! Flow: PUT `requests/<id>.json` via the Contents API → the repo's relay workflow fires
//! on push → runner fetches the URL → response committed to `responses/<id>.txt` →
//! we poll raw.githubusercontent.com for it.
//!
//! This is deliberately NOT a tunnel transport: it's a fetch channel for configs,
//! news, and control messages during phases where GitHub is the only thing alive.

use rahyab_core::transport::tls::{self, TlsSettings};
use rahyab_core::transport::{tcp_dial, TargetAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Minimal HTTP/1.1 request over our TLS stack (real SNI, verified certs).
pub async fn https_request(
    host: &str,
    path: &str,
    method: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Result<(u16, String), String> {
    let stream = tcp_dial(&TargetAddr::Domain(host.to_string(), 443))
        .await
        .map_err(|e| format!("dial {host}: {e}"))?;
    let mut s = tls::tls_wrap(stream, host, &TlsSettings::default())
        .await
        .map_err(|e| format!("tls {host}: {e}"))?;

    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: rahyab/0.1\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    s.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = s.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() > 8 << 20 {
            break;
        }
    }
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("bad http response")?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let mut body = raw[split + 4..].to_vec();
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        body = dechunk(&body);
    }
    Ok((status, String::from_utf8_lossy(&body).to_string()))
}

fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0usize;
    while i < body.len() {
        let Some(p) = body[i..].windows(2).position(|w| w == b"\r\n") else { break };
        let line_end = i + p;
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

pub fn token() -> Option<String> {
    std::env::var("GITHUB_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
        .or_else(|| {
            std::process::Command::new("gh")
                .args(["auth", "token"])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|t| !t.is_empty())
        })
}

fn b64(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s)
}

/// PUT `requests/<id>.json` (Contents API) — triggers the relay workflow on push.
pub async fn relay_put(repo: &str, id: &str, url: &str, method: &str) -> Result<(), String> {
    let Some(tok) = token() else {
        return Err("no GITHUB_TOKEN env and `gh auth token` failed".into());
    };
    let path = format!("/repos/{repo}/contents/requests/{id}.json");
    let payload = format!(
        r#"{{"message":"rahyab relay request {id}","content":"{}"}}"#,
        b64(&format!(r#"{{"url":"{url}","method":"{method}"}}"#))
    );
    let (status, body) = https_request(
        "api.github.com",
        &path,
        "PUT",
        &[
            ("Authorization", &format!("Bearer {tok}")),
            ("Accept", "application/vnd.github+json"),
            ("Content-Type", "application/json"),
        ],
        Some(&payload),
    )
    .await?;
    if status == 200 || status == 201 {
        Ok(())
    } else {
        Err(format!("PUT {status}: {}", body.chars().take(300).collect::<String>()))
    }
}

/// GET `responses/<id>.txt` via raw.githubusercontent.com. Ok(None) = not there yet.
pub async fn relay_poll(repo: &str, id: &str) -> Result<Option<String>, String> {
    let path = format!("/{repo}/main/responses/{id}.txt");
    let (status, body) = https_request("raw.githubusercontent.com", &path, "GET", &[], None).await?;
    match status {
        200 => Ok(Some(body)),
        404 => Ok(None),
        other => Err(format!("poll {other}: {}", body.chars().take(200).collect::<String>())),
    }
}

/// Full round trip with polling.
pub async fn relay_get(repo: &str, id: &str, url: &str, wait_secs: u64) -> Result<String, String> {
    relay_put(repo, id, url, "GET").await?;
    println!("request {id} committed; polling responses/{id}.txt …");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait_secs);
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(5)).await;
        match relay_poll(repo, id).await {
            Ok(Some(body)) => return Ok(body),
            Ok(None) => print!("."),
            Err(e) => return Err(e),
        }
    }
    Err(format!("no response within {wait_secs}s"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dechunk_works() {
        let raw = b"a\r\n0123456789\r\n0\r\n\r\n";
        assert_eq!(dechunk(raw), b"0123456789".to_vec());
    }
}
