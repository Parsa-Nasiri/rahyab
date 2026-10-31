//! Configuration: parses the *standard* share-link ecosystem so Rahyab is instantly
//! compatible with config channels the Iranian community already publishes
//! (vless:// trojan:// ss:// vmess:// socks:// + base64 subscription lists).
//!
//! Also defines `AppConfig` — the JSON the app and CLI consume.

use crate::transport::{
    http_proxy::HttpConnector, socks5::Socks5Connector, ss::SsConnector, tls::TlsSettings,
    trojan::TrojanConnector, vless::VlessConnector, ws::WsSettings, SharedConnector,
    TargetAddr,
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Share-link parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct WsOpts {
    pub host_header: String,
    pub path: String,
}

#[derive(Debug, Clone)]
pub enum ParsedProfile {
    Vless {
        name: String,
        host: String,
        port: u16,
        uuid: String,
        tls: bool,
        sni: Option<String>,
        insecure: bool,
        ws: Option<WsOpts>,
    },
    Trojan {
        name: String,
        host: String,
        port: u16,
        password: String,
        tls: bool,
        sni: Option<String>,
        insecure: bool,
        ws: Option<WsOpts>,
    },
    Ss {
        name: String,
        host: String,
        port: u16,
        method: String,
        password: String,
    },
    Socks {
        name: String,
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    },
    Http {
        name: String,
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    },
    /// WireGuard (rahyab:// JSON profiles; also how WARP/wgcf profiles are expressed).
    Wg {
        name: String,
        host: String,
        port: u16,
        private_key: String,
        peer_public_key: String,
        preshared_key: Option<String>,
    },
    /// Recognized but not implementable in the Rust core (surfaced to the user honestly).
    Unsupported { name: String, reason: String },
}

pub fn b64_decode_flexible(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let s = s.trim().replace(['\n', '\r', ' '], "");
    let e = base64::engine::general_purpose::STANDARD;
    for candidate in [s.as_str(), &format!("{}{}", s, "=".repeat((4 - s.len() % 4) % 4))] {
        if let Ok(v) = e.decode(candidate) {
            return Some(v);
        }
        let url_safe = base64::engine::general_purpose::URL_SAFE;
        if let Ok(v) = url_safe.decode(candidate) {
            return Some(v);
        }
    }
    None
}

fn urldecode(s: &str) -> String {
    percent_encoding::percent_decode_str(s).decode_utf8_lossy().to_string()
}

fn query_get(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then(|| urldecode(v))
    })
}

pub fn parse_share_link(link: &str) -> ParsedProfile {
    let link = link.trim();
    let (scheme, rest) = match link.split_once("://") {
        Some(x) => x,
        None => {
            return ParsedProfile::Unsupported {
                name: link.chars().take(24).collect(),
                reason: "not a share link".into(),
            }
        }
    };
    let frag_name = |link: &str| -> String {
        link.split_once('#')
            .map(|(_, f)| urldecode(f))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "profile".into())
    };

    match scheme {
        "vless" | "trojan" => {
            let name = frag_name(link);
            let Ok(u) = url::Url::parse(link) else {
                return ParsedProfile::Unsupported { name, reason: "unparseable url".into() };
            };
            let host = u.host_str().unwrap_or("").to_string();
            if host.is_empty() {
                return ParsedProfile::Unsupported { name, reason: "no host".into() };
            }
            let port = u.port().unwrap_or(443);
            let query = u.query().unwrap_or("");
            let security = query_get(query, "security").unwrap_or_default();
            let net = query_get(query, "type").unwrap_or_else(|| "tcp".into());
            let sni = query_get(query, "sni").or_else(|| query_get(query, "peer"));
            let allow_insecure = matches!(
                query_get(query, "allowInsecure").as_deref(),
                Some("1") | Some("true")
            );
            let ws = if net == "ws" {
                Some(WsOpts {
                    host_header: query_get(query, "host").unwrap_or_default(),
                    path: query_get(query, "path").unwrap_or_else(|| "/".into()),
                })
            } else {
                None
            };
            if security == "reality" || query_get(query, "pbk").is_some() {
                return ParsedProfile::Unsupported {
                    name,
                    reason: "XTLS-REALITY: roadmap (needs raw ClientHello forgery)".into(),
                };
            }
            if net == "grpc" || net == "httpupgrade" {
                return ParsedProfile::Unsupported {
                    name,
                    reason: format!("{net} transport: roadmap"),
                };
            }
            if let Some(flow) = query_get(query, "flow") {
                if !flow.is_empty() {
                    return ParsedProfile::Unsupported {
                        name,
                        reason: "xtls flow (vision): roadmap".into(),
                    };
                }
            }
            if scheme == "vless" {
                let uuid = urldecode(u.username());
                ParsedProfile::Vless {
                    name,
                    host,
                    port,
                    uuid,
                    tls: security == "tls" || security.is_empty() && ws.is_some(),
                    sni,
                    insecure: allow_insecure,
                    ws,
                }
            } else {
                ParsedProfile::Trojan {
                    name,
                    host,
                    port,
                    password: urldecode(u.username()),
                    tls: security != "none",
                    sni,
                    insecure: allow_insecure,
                    ws,
                }
            }
        }
        "ss" => {
            let name = frag_name(link);
            let mut main = rest.to_string();
            if let Some(pos) = main.find('#') {
                main.truncate(pos);
            }
            if let Some(pos) = main.find('?') {
                main.truncate(pos); // plugin params unsupported
            }
            let main = urldecode(&main);
            let (method_pass, hostport) = match main.split_once('@') {
                Some((ui, hp)) => {
                    let decoded = b64_decode_flexible(ui)
                        .and_then(|v| String::from_utf8(v).ok())
                        .unwrap_or_else(|| ui.to_string());
                    (decoded, hp.to_string())
                }
                None => {
                    let decoded = b64_decode_flexible(&main)
                        .and_then(|v| String::from_utf8(v).ok())
                        .unwrap_or_default();
                    match decoded.rsplit_once('@') {
                        Some(x) => x.to_pair(),
                        None => {
                            return ParsedProfile::Unsupported { name, reason: "bad ss link".into() }
                        }
                    }
                }
            };
            let Some((method, password)) = method_pass.split_once(':') else {
                return ParsedProfile::Unsupported { name, reason: "ss: method:password missing".into() };
            };
            let Some((host, port)) = split_host_port(&hostport) else {
                return ParsedProfile::Unsupported { name, reason: "ss: bad hostport".into() };
            };
            ParsedProfile::Ss {
                name,
                host,
                port,
                method: method.to_string(),
                password: password.to_string(),
            }
        }
        "vmess" => {
            let name = frag_name(link);
            let decoded = b64_decode_flexible(rest).and_then(|v| String::from_utf8(v).ok());
            match decoded.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()) {
                Some(v) => {
                    let net = v["net"].as_str().unwrap_or("tcp").to_string();
                    let tls = v["tls"].as_str().unwrap_or("") == "tls";
                    ParsedProfile::Unsupported {
                        name,
                        reason: format!(
                            "vmess: legacy protocol not in Rust core (net={net}, tls={tls}); prefer the vless equivalent"
                        ),
                    }
                }
                None => ParsedProfile::Unsupported { name, reason: "bad vmess link".into() },
            }
        }
        "socks" | "socks5" => {
            let name = frag_name(link);
            match parse_userinfo_hostport(rest) {
                Some((user, pass, host, port)) => ParsedProfile::Socks { name, host, port, username: user, password: pass },
                None => ParsedProfile::Unsupported { name, reason: "bad socks link".into() },
            }
        }
        "http" | "https" => {
            let name = frag_name(link);
            match parse_userinfo_hostport(rest) {
                Some((user, pass, host, port)) => ParsedProfile::Http { name, host, port, username: user, password: pass },
                None => ParsedProfile::Unsupported { name, reason: "bad http link".into() },
            }
        }
        "rahyab" => {
            let name = frag_name(link);
            match b64_decode_flexible(rest)
                .and_then(|v| serde_json::from_slice::<serde_json::Value>(&v).ok())
            {
                Some(v) if v["kind"] == "wg" => ParsedProfile::Wg {
                    name,
                    host: v["endpoint_host"].as_str().unwrap_or_default().into(),
                    port: v["endpoint_port"].as_u64().unwrap_or(51820) as u16,
                    private_key: v["private_key"].as_str().unwrap_or_default().into(),
                    peer_public_key: v["peer_public_key"].as_str().unwrap_or_default().into(),
                    preshared_key: v["preshared_key"].as_str().map(|s| s.to_string()),
                },
                _ => ParsedProfile::Unsupported { name, reason: "bad rahyab:// profile".into() },
            }
        }
        "hysteria2" | "hy2" | "tuic" => ParsedProfile::Unsupported {
            name: frag_name(link),
            reason: "QUIC-family transport: roadmap (see docs/02)".into(),
        },
        other => ParsedProfile::Unsupported {
            name: frag_name(link),
            reason: format!("unknown scheme '{other}'"),
        },
    }
}

trait ToPair<T> {
    fn to_pair(self) -> (T, T);
}
impl ToPair<String> for (&str, &str) {
    fn to_pair(self) -> (String, String) {
        (self.0.to_string(), self.1.to_string())
    }
}

fn split_host_port(s: &str) -> Option<(String, u16)> {
    let s = s.trim();
    if let Some(stripped) = s.strip_prefix('[') {
        // [v6]:port
        let (h, p) = stripped.split_once("]:")?;
        return Some((h.to_string(), p.parse().ok()?));
    }
    let (h, p) = s.rsplit_once(':')?;
    Some((h.to_string(), p.parse().ok()?))
}

fn parse_userinfo_hostport(
    rest: &str,
) -> Option<(Option<String>, Option<String>, String, u16)> {
    let mut main = rest.to_string();
    if let Some(pos) = main.find('#') {
        main.truncate(pos);
    }
    let (userinfo, password, hostport) = match main.rsplit_once('@') {
        Some((ui, hp)) => {
            let creds = b64_decode_flexible(ui)
                .and_then(|v| String::from_utf8(v).ok())
                .unwrap_or_else(|| urldecode(ui));
            match creds.split_once(':') {
                Some((u, p)) => (Some(u.to_string()), Some(p.to_string()), hp.to_string()),
                None => (Some(creds), None, hp.to_string()),
            }
        }
        None => (None, None, main.clone()),
    };
    let (host, port) = split_host_port(&hostport)?;
    Some((userinfo, password, host, port))
}

/// A base64 or plaintext subscription body → list of share links.
pub fn parse_subscription(text: &str) -> Vec<String> {
    let text = text.trim();
    let candidate = if text.contains("://") {
        text.to_string()
    } else {
        match b64_decode_flexible(text).and_then(|v| String::from_utf8(v).ok()) {
            Some(s) => s,
            None => text.to_string(),
        }
    };
    candidate
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| l.contains("://"))
        .collect()
}

// ---------------------------------------------------------------------------
// Connector building
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct BuildOpts {
    /// Pin the TCP dial to a known-good IP (CDN IP optimisation / DNS-dead environments).
    /// TLS SNI + WS Host keep using the domain.
    pub server_ip: Option<IpAddr>,
    /// Run the tunnel INSIDE this hop (e.g. the local Psiphon SOCKS listener).
    pub dial_through: Option<SharedConnector>,
    pub sni_override: Option<String>,
    pub force_insecure: bool,
    /// Fragment the TLS ClientHello (patterniha Serverless-for-Iran technique).
    pub frag: bool,
    /// Distinguishes planner variants in the candidate id (memory keys on it).
    pub variant: Option<String>,
}

#[derive(Clone)]
pub struct BuiltProfile {
    pub id: String,
    pub label: String,
    pub connector: SharedConnector,
    pub server_host: String,
    pub port: u16,
    pub kind: String,
    /// Heuristic: looks like a CDN-fronted profile (good in CDN-only environments).
    pub cdn_likely: bool,
    pub udp_based: bool,
}

impl BuiltProfile {
    pub fn server_addr(&self) -> TargetAddr {
        TargetAddr::Domain(self.server_host.clone(), self.port)
    }
}

fn tls_settings(
    sni: Option<&str>,
    insecure: bool,
    sni_override: &Option<String>,
    force_insecure: bool,
    frag: bool,
) -> TlsSettings {
    TlsSettings {
        sni: sni_override.clone().or_else(|| sni.map(|s| s.to_string())),
        insecure: insecure || force_insecure,
        alpn: None,
        // patterniha Serverless-for-Iran fragA offsets: split the ClientHello at
        // bytes 6 and 98 so the SNI never appears whole on the wire.
        frag_splits: frag.then(|| vec![6, 98]),
    }
}

pub fn build_connector(p: &ParsedProfile, opts: &BuildOpts) -> Result<BuiltProfile, String> {
    use crate::transport::TcpDialFix;
    let base = p_label(p).replace(' ', "_");
    let variant = opts.variant.clone().unwrap_or_else(|| "direct".into());

    let mk = |label: String, connector: SharedConnector, host: String, port: u16, kind: &str, cdn: bool, udp: bool| {
        Ok(BuiltProfile {
            id: format!("{base}|{host}:{port}|{variant}"),
            label,
            connector,
            server_host: host,
            port,
            kind: kind.to_string(),
            cdn_likely: cdn,
            udp_based: udp,
        })
    };

    // IP-pinning: dial a fixed IP:port while TLS/WS keep using the domain (SNI/Host).
    let chained = opts.dial_through.is_some();
    let inner_for = |port: u16| -> Option<SharedConnector> {
        match opts.server_ip {
            Some(ip) if !chained => {
                Some(Arc::new(TcpDialFix { addr: SocketAddr::new(ip, port) }))
            }
            _ => opts.dial_through.clone(),
        }
    };

    match p {
        ParsedProfile::Vless { name, host, port, uuid, tls, sni, insecure, ws } => {
            let uuid = uuid::Uuid::parse_str(uuid).map_err(|e| format!("vless uuid: {e}"))?;
            let conn = VlessConnector {
                server: TargetAddr::Domain(host.clone(), *port),
                uuid,
                tls: if *tls {
                    Some(tls_settings(sni.as_deref(), *insecure, &opts.sni_override, opts.force_insecure, opts.frag))
                } else {
                    None
                },
                ws: ws.as_ref().map(|w| WsSettings {
                    host_header: if w.host_header.is_empty() { host.clone() } else { w.host_header.clone() },
                    path: w.path.clone(),
                    extra_headers: Vec::new(),
                }),
                inner: inner_for(*port),
            };
            let cdn = is_cdn_likely(host, sni.as_deref(), opts.server_ip.is_some());
            mk(name.clone(), Arc::new(conn), host.clone(), *port, "vless", cdn, false)
        }
        ParsedProfile::Trojan { name, host, port, password, tls, sni, insecure, ws } => {
            let conn = TrojanConnector {
                server: TargetAddr::Domain(host.clone(), *port),
                password: password.clone(),
                tls: if *tls {
                    Some(tls_settings(sni.as_deref(), *insecure, &opts.sni_override, opts.force_insecure, opts.frag))
                } else {
                    None
                },
                ws: ws.as_ref().map(|w| WsSettings {
                    host_header: if w.host_header.is_empty() { host.clone() } else { w.host_header.clone() },
                    path: w.path.clone(),
                    extra_headers: Vec::new(),
                }),
                inner: inner_for(*port),
            };
            let cdn = is_cdn_likely(host, sni.as_deref(), opts.server_ip.is_some());
            mk(name.clone(), Arc::new(conn), host.clone(), *port, "trojan", cdn, false)
        }
        ParsedProfile::Ss { name, host, port, method, password } => {
            if chained {
                return Err("ss cannot be chained under a hop".into());
            }
            let conn = SsConnector {
                server: TargetAddr::Domain(host.clone(), *port),
                method: method.clone(),
                password: password.clone(),
                inner: None,
            };
            mk(name.clone(), Arc::new(conn), host.clone(), *port, "ss", is_cdn_likely(host, None, opts.server_ip.is_some()), false)
        }
        ParsedProfile::Socks { name, host, port, username, password } => {
            let conn = Socks5Connector {
                server: TargetAddr::Domain(host.clone(), *port),
                auth: username.clone().zip(password.clone()),
                inner: inner_for(*port),
            };
            mk(name.clone(), Arc::new(conn), host.clone(), *port, "socks5", false, false)
        }
        ParsedProfile::Http { name, host, port, username, password } => {
            let conn = HttpConnector {
                server: TargetAddr::Domain(host.clone(), *port),
                auth: username.clone().zip(password.clone()),
                inner: inner_for(*port),
            };
            mk(name.clone(), Arc::new(conn), host.clone(), *port, "http", false, false)
        }
        #[allow(unused_variables)]
        ParsedProfile::Wg { name, host, port, private_key, peer_public_key, preshared_key } => {
            #[cfg(feature = "wireguard")]
            {
                let conn = crate::transport::wireguard::WgConnector::new(
                    host.clone(),
                    *port,
                    private_key.clone(),
                    peer_public_key.clone(),
                    preshared_key.clone(),
                    opts.dial_through.is_some(),
                )?;
                mk(name.clone(), Arc::new(conn), host.clone(), *port, "wg", false, true)
            }
            #[cfg(not(feature = "wireguard"))]
            {
                Err("wireguard feature disabled".into())
            }
        }
        ParsedProfile::Unsupported { name, reason } => Err(format!("'{name}': {reason}")),
    }
}

fn p_label(p: &ParsedProfile) -> String {
    match p {
        ParsedProfile::Vless { name, .. }
        | ParsedProfile::Trojan { name, .. }
        | ParsedProfile::Ss { name, .. }
        | ParsedProfile::Socks { name, .. }
        | ParsedProfile::Http { name, .. }
        | ParsedProfile::Wg { name, .. }
        | ParsedProfile::Unsupported { name, .. } => name.clone(),
    }
}

fn is_cdn_likely(host: &str, sni: Option<&str>, ip_pinned: bool) -> bool {
    ip_pinned
        || sni.is_some()
        || host.ends_with(".workers.dev")
        || host.ends_with(".pages.dev")
        || host.ends_with("vercel.app")
}

// ---------------------------------------------------------------------------
// AppConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProfileSource {
    pub link: String,
    #[serde(default)]
    pub dial_through: Option<String>,
    #[serde(default)]
    pub prefer_ips: Vec<String>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub insecure: Option<bool>,
    #[serde(default)]
    pub name: Option<String>,
    /// Fragment the TLS ClientHello at bytes 6/98 (SNI regex defeat — patterniha
    /// Serverless-for-Iran). Applies to every variant generated from this profile.
    #[serde(default)]
    pub frag: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalHop {
    pub name: String,
    /// SOCKS5 endpoint of a local helper, e.g. the embedded Psiphon library: 127.0.0.1:1080
    pub socks: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyConfig {
    #[serde(default = "def_concurrency")]
    pub concurrency: usize,
    #[serde(default = "def_attempt_timeout_ms")]
    pub attempt_timeout_ms: u64,
    #[serde(default = "def_health_timeout_ms")]
    pub health_timeout_ms: u64,
    #[serde(default = "def_true")]
    pub persist: bool,
    #[serde(default = "def_reprobe_secs")]
    pub reprobe_secs: u64,
    #[serde(default = "def_healthcheck_secs")]
    pub healthcheck_secs: u64,
    /// Allowed-domain SNIs used by the "front:" planner variants (SNI-whitelisting
    /// escape). Field-verified: fonts.googleapis.com answered while other traffic died.
    #[serde(default = "def_sni_escape_domains")]
    pub sni_escape_domains: Vec<String>,
}
fn def_concurrency() -> usize { 4 }
fn def_attempt_timeout_ms() -> u64 { 8000 }
fn def_health_timeout_ms() -> u64 { 6000 }
fn def_true() -> bool { true }
fn def_reprobe_secs() -> u64 { 300 }
fn def_healthcheck_secs() -> u64 { 15 }
fn def_sni_escape_domains() -> Vec<String> {
    vec!["fonts.googleapis.com".into(), "www.gstatic.com".into()]
}
impl Default for StrategyConfig {
    fn default() -> Self {
        Self {
            concurrency: def_concurrency(),
            attempt_timeout_ms: def_attempt_timeout_ms(),
            health_timeout_ms: def_health_timeout_ms(),
            persist: def_true(),
            reprobe_secs: def_reprobe_secs(),
            healthcheck_secs: def_healthcheck_secs(),
            sni_escape_domains: def_sni_escape_domains(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anchors {
    /// International TCP anchors: "host:port"
    #[serde(default = "def_tcp_intl")]
    pub tcp_intl: Vec<String>,
    /// Domestic (Iran) anchors — user-provided, e.g. a banking or gov portal.
    #[serde(default)]
    pub tcp_domestic: Vec<String>,
    /// Known-good CDN edge IPs (the "IP finder" output the community shares).
    #[serde(default)]
    pub cdn_ips: Vec<String>,
    #[serde(default = "def_doh")]
    pub doh: Vec<String>,
    #[serde(default = "def_udp_dns")]
    pub udp_dns: Vec<String>,
}
fn def_tcp_intl() -> Vec<String> {
    vec![
        "1.1.1.1:443".into(),
        "8.8.8.8:443".into(),
        "www.google.com:443".into(),
        "github.com:443".into(),
    ]
}
fn def_doh() -> Vec<String> {
    vec!["https://cloudflare-dns.com/dns-query?name=%s&type=A".into()]
}
fn def_udp_dns() -> Vec<String> {
    vec!["8.8.8.8:53".into(), "1.1.1.1:53".into()]
}
impl Default for Anchors {
    fn default() -> Self {
        Self {
            tcp_intl: def_tcp_intl(),
            tcp_domestic: Vec::new(),
            cdn_ips: Vec::new(),
            doh: def_doh(),
            udp_dns: def_udp_dns(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub profiles: Vec<ProfileSource>,
    #[serde(default)]
    pub local_hops: Vec<LocalHop>,
    #[serde(default)]
    pub strategy: StrategyConfig,
    #[serde(default)]
    pub anchors: Anchors,
    #[serde(default)]
    pub memory_path: Option<String>,
}

impl AppConfig {
    pub fn from_json(s: &str) -> Result<Self, String> {
        serde_json::from_str(s).map_err(|e| format!("config json: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vless_ws_tls() {
        let link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@cf.example.com:443?encryption=none&security=tls&sni=cf.example.com&fp=chrome&type=ws&host=cf.example.com&path=%2Fws#CF-WS";
        match parse_share_link(link) {
            ParsedProfile::Vless { name, host, port, tls, ws, .. } => {
                assert_eq!(name, "CF-WS");
                assert_eq!(host, "cf.example.com");
                assert_eq!(port, 443);
                assert!(tls);
                let ws = ws.unwrap();
                assert_eq!(ws.path, "/ws");
                assert_eq!(ws.host_header, "cf.example.com");
            }
            other => panic!("wrong parse: {other:?}"),
        }
    }

    #[test]
    fn parses_trojan() {
        let link = "trojan://secretpw@tj.example.com:443?sni=tj.example.com#Trojan1";
        match parse_share_link(link) {
            ParsedProfile::Trojan { password, port, tls, .. } => {
                assert_eq!(password, "secretpw");
                assert_eq!(port, 443);
                assert!(tls);
            }
            other => panic!("wrong parse: {other:?}"),
        }
    }

    #[test]
    fn parses_ss_userinfo() {
        // aes-256-gcm:test → YWVzLTI1Ni1nY206dGVzdA==
        let link = "ss://YWVzLTI1Ni1nY206dGVzdA==@1.2.3.4:8388#SS1";
        match parse_share_link(link) {
            ParsedProfile::Ss { method, password, host, port, .. } => {
                assert_eq!(method, "aes-256-gcm");
                assert_eq!(password, "test");
                assert_eq!(host, "1.2.3.4");
                assert_eq!(port, 8388);
            }
            other => panic!("wrong parse: {other:?}"),
        }
    }

    #[test]
    fn flags_reality_as_unsupported() {
        let link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@r.example.com:443?security=reality&pbk=SOMEKEY&sni=www.microsoft.com&type=tcp#REALITY1";
        match parse_share_link(link) {
            ParsedProfile::Unsupported { reason, .. } => assert!(reason.contains("REALITY")),
            other => panic!("expected unsupported, got {other:?}"),
        }
    }

    #[test]
    fn parses_vmess_as_unsupported_with_info() {
        let body = serde_json::json!({
            "v": "2", "ps": "VM1", "add": "vm.example.com", "port": "443",
            "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "net": "ws", "tls": "tls"
        })
        .to_string();
        let link = format!("vmess://{}", {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(body)
        });
        match parse_share_link(&link) {
            ParsedProfile::Unsupported { reason, .. } => assert!(reason.contains("vmess")),
            other => panic!("expected unsupported, got {other:?}"),
        }
    }

    #[test]
    fn subscription_parsing() {
        use base64::Engine;
        let links = "vless://a@b:1#x\ntrojan://c@d:2#y\n";
        let b64 = base64::engine::general_purpose::STANDARD.encode(links);
        let parsed = parse_subscription(&b64);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parse_subscription(links).len(), 2);
    }

    #[test]
    fn builds_vless_connector() {
        let p = parse_share_link(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@cf.example.com:443?security=tls&sni=cf.example.com&type=ws&path=/ws#T",
        );
        let built = build_connector(&p, &BuildOpts::default()).unwrap();
        assert_eq!(built.kind, "vless");
        assert!(built.cdn_likely); // sni present
        assert_eq!(built.port, 443);
    }
}
