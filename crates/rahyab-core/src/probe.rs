//! Live network probing → `Environment` classification.
//!
//! The classification drives the whole algorithm, so `classify` is pure and unit-tested;
//! the async part only gathers facts. Anchors are configurable because "what is reachable"
//! differs per ISP and per blackout phase.

use crate::config::Anchors;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr, UdpSocket as StdUdpSocket};
use std::time::Duration;
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Environment {
    /// Everything works; rank by latency.
    Open,
    /// International TCP works but DNS is broken/poisoned → need DoH bootstrap + pinned IPs.
    PartialTcp,
    /// Only CDN/whitelisted-ish endpoints answer (classic heavy-filter phase).
    CdnOnly,
    /// UDP (DNS) egress alive but TCP to the world dead → WireGuard-style UDP tunnels first.
    DnsOnly,
    /// Nothing international answers. Only domestic anchors alive.
    FullDark,
}

impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Open => "open",
            Environment::PartialTcp => "partial-tcp",
            Environment::CdnOnly => "cdn-only",
            Environment::DnsOnly => "dns-only",
            Environment::FullDark => "full-dark",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProbeResults {
    pub system_dns: bool,
    pub doh: bool,
    pub udp_intl: bool,
    pub intl_ok: usize,
    pub intl_total: usize,
    pub cdn_ok: usize,
    pub cdn_total: usize,
    pub noncdn_ok: usize,
    pub dom_ok: usize,
    pub dom_total: usize,
}

pub fn classify(r: &ProbeResults) -> Environment {
    let intl = r.intl_ok > 0;
    let udp = r.udp_intl || r.doh;
    if !intl {
        if udp {
            // No international TCP, but UDP/DoH answers: DNS-tunnel class.
            Environment::DnsOnly
        } else {
            Environment::FullDark
        }
    } else if r.noncdn_ok == 0 {
        // Only CDN-ish endpoints answered.
        if udp {
            Environment::CdnOnly
        } else {
            Environment::CdnOnly
        }
    } else if r.system_dns && r.doh && r.udp_intl {
        Environment::Open
    } else {
        Environment::PartialTcp
    }
}

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

fn is_cdn_anchor(hostport: &str) -> bool {
    let h = hostport.split(':').next().unwrap_or("").to_ascii_lowercase();
    h.parse::<IpAddr>().is_ok()
        || ["cloudflare", "google", "gstatic", "fastly", "cloudfront", "akamai", "arvan"]
            .iter()
            .any(|k| h.contains(k))
}

pub struct ProbeEngine {
    pub anchors: Anchors,
}

impl Default for ProbeEngine {
    fn default() -> Self {
        Self { anchors: Anchors::default() }
    }
}

impl ProbeEngine {
    pub fn new(anchors: Anchors) -> Self {
        Self { anchors }
    }

    pub async fn run(&self) -> ProbeResults {
        let mut r = ProbeResults::default();

        // 1. System DNS
        r.system_dns = tokio::time::timeout(PROBE_TIMEOUT, async {
            tokio::net::lookup_host(("github.com", 443)).await.is_ok()
                && tokio::net::lookup_host(("cloudflare.com", 443)).await.is_ok()
        })
        .await
        .unwrap_or(false);

        // 2. DoH
        if let Some(url) = self.anchors.doh.first() {
            r.doh = doh_resolve(url, "github.com").await.is_ok();
        }

        // 3. UDP DNS to international resolvers
        for srv in &self.anchors.udp_dns {
            if udp_dns_probe(srv, "google.com").await {
                r.udp_intl = true;
                break;
            }
        }

        // 4. TCP anchors
        for a in &self.anchors.tcp_intl {
            r.intl_total += 1;
            if tcp_probe(a).await {
                r.intl_ok += 1;
                if is_cdn_anchor(a) {
                    r.cdn_ok += 1;
                } else {
                    r.noncdn_ok += 1;
                }
            } else if is_cdn_anchor(a) {
                // counted as cdn_total below
            }
            if is_cdn_anchor(a) {
                r.cdn_total += 1;
            }
        }
        // Re-count noncdn_total via intl_total - cdn_total (derive, not stored).

        // 5. Domestic anchors (must be provided by the user for their carrier/ISP)
        for a in &self.anchors.tcp_domestic {
            r.dom_total += 1;
            if tcp_probe(a).await {
                r.dom_ok += 1;
            }
        }

        r
    }
}

pub async fn tcp_probe(hostport: &str) -> bool {
    tokio::time::timeout(PROBE_TIMEOUT, async {
        TcpStream::connect(hostport).await.is_ok()
    })
    .await
    .unwrap_or(false)
}

fn build_dns_query(name: &str) -> Vec<u8> {
    let mut q = vec![0u8; 12];
    // id=0, flags: recursion desired
    q[2] = 0x01;
    q[5] = 0x01; // QDCOUNT=1
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]); // A, IN
    q
}

pub async fn udp_dns_probe(server: &str, name: &str) -> bool {
    let Ok(addr) = server.parse::<SocketAddr>() else { return false };
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let Ok(std_sock) = StdUdpSocket::bind(bind) else { return false };
    std_sock.set_read_timeout(Some(PROBE_TIMEOUT)).ok();
    let q = build_dns_query(name);
    tokio::task::spawn_blocking(move || {
        let mut s = std_sock;
        if s.send_to(&q, addr).is_err() {
            return false;
        }
        let mut buf = [0u8; 512];
        match s.recv_from(&mut buf) {
            Ok((n, _)) => n >= 12, // any DNS-shaped response counts
            Err(_) => false,
        }
    })
    .await
    .unwrap_or(false)
}

/// Minimal DoH (JSON API) using our own TLS + HTTP code — works even when system DNS
/// is dead because we dial the resolver by IP with SNI.
pub async fn doh_resolve(template: &str, name: &str) -> Result<Vec<IpAddr>, String> {
    // template like "https://cloudflare-dns.com/dns-query?name=%s&type=A"
    let (base, path) = template
        .split_once("://")
        .map(|(_, r)| r.split_once('/').map(|(h, p)| (h.to_string(), format!("/{p}")))
            .unwrap_or((r.to_string(), "/".into())))
        .ok_or("bad doh url")?;
    let host = base.split(':').next().unwrap_or(&base).to_string();
    let path = path.replace("%s", name);
    let url = format!("https://{base}{path}");
    let mut ips = Vec::new();

    // Dial the resolver (by IP if given, otherwise via system DNS).
    let stream = tokio::time::timeout(
        PROBE_TIMEOUT,
        crate::transport::tcp_dial(&crate::transport::TargetAddr::Domain(host.clone(), 443)),
    )
    .await
    .map_err(|e| format!("doh dial: {e}"))?
    .map_err(|e| format!("doh dial: {e}"))?;

    let tls = crate::transport::tls::tls_wrap(
        stream,
        &host,
        &crate::transport::tls::TlsSettings::default(),
    )
    .await
    .map_err(|e| format!("doh tls: {e}"))?;
    let body = crate::transport::tls::http_get(tls, &host, &path, "application/dns-json")
        .await
        .map_err(|e| format!("doh http: {e}"))?;
    let _ = url; // kept for clarity/logging
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
        if let Some(ans) = v["Answer"].as_array() {
            for a in ans {
                if a["type"].as_i64() == Some(1) {
                    if let Some(d) = a["data"].as_str() {
                        if let Ok(ip) = d.parse::<IpAddr>() {
                            ips.push(ip);
                        }
                    }
                }
            }
        }
    }
    if ips.is_empty() {
        Err("doh: no answers".into())
    } else {
        Ok(ips)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(
        system_dns: bool,
        doh: bool,
        udp: bool,
        intl_ok: usize,
        cdn_ok: usize,
        dom_ok: usize,
    ) -> ProbeResults {
        ProbeResults {
            system_dns,
            doh,
            udp_intl: udp,
            intl_ok,
            intl_total: 4,
            cdn_ok,
            cdn_total: 2,
            noncdn_ok: intl_ok.saturating_sub(cdn_ok),
            dom_ok,
            dom_total: 1,
        }
    }

    #[test]
    fn classification_matrix() {
        assert_eq!(classify(&r(true, true, true, 4, 2, 1)), Environment::Open);
        assert_eq!(classify(&r(false, true, false, 4, 2, 1)), Environment::PartialTcp);
        assert_eq!(classify(&r(true, false, false, 2, 2, 1)), Environment::CdnOnly);
        assert_eq!(classify(&r(false, true, true, 0, 0, 1)), Environment::DnsOnly);
        assert_eq!(classify(&r(false, false, false, 0, 0, 1)), Environment::FullDark);
        assert_eq!(classify(&r(false, false, false, 0, 0, 0)), Environment::FullDark);
    }

    #[test]
    fn dns_query_shape() {
        let q = build_dns_query("google.com");
        // 12 header + (1+6)"google" + (1+3)"com" + 1 root + 4 qtype/qclass = 28
        assert_eq!(q.len(), 28);
        assert_eq!(&q[12..13], b"\x06");
        assert_eq!(&q[13..19], b"google");
    }
}
