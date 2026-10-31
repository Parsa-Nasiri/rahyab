//! rahyab CLI — the combo-tester the whole project leans on:
//!
//!   rahyab probe                          → what kind of network am I on right now?
//!   rahyab test --config app.json         → race EVERY candidate, print the live matrix
//!   rahyab serve --config app.json        → run the full Khorshid engine + local SOCKS hub
//!   rahyab scan --targets ips.txt --port 443 → find alive CDN edge IPs (the "IP finder")
//!
//! Run `rahyab test` inside Iran during different blackout phases and the results ARE the
//! knowledge base (docs/03) filled with ground truth.

use clap::{Parser, Subcommand};
use rahyab_core::algo::{plan, race, EngineShared};
use rahyab_core::config::AppConfig;
use rahyab_core::health::check_health;
use rahyab_core::hub::serve_hub;
use rahyab_core::probe::{classify, ProbeEngine};
use rahyab_core::transport::socks5::Socks5Connector;
use rahyab_core::transport::{SharedConnector, TargetAddr};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

mod relay;

#[derive(Parser)]
#[command(name = "rahyab", version, about = "Blackout-resilient connectivity toolkit (Rahyab)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Probe the network and classify the environment.
    Probe {
        #[arg(long)] config: Option<PathBuf>,
    },
    /// Build every candidate and try each one — the live combo matrix.
    Test {
        #[arg(long)] config: PathBuf,
        #[arg(long, default_value_t = 8)] timeout: u64,
        /// Also race them concurrently like the app does
        #[arg(long, default_value_t = true)] race_too: bool,
    },
    /// Run the full Khorshid engine with a local SOCKS5 hub (usable system-wide).
    Serve {
        #[arg(long)] config: PathBuf,
        #[arg(long, default_value = "127.0.0.1:1080")] listen: String,
        #[arg(long)] memory: Option<PathBuf>,
    },
    /// TCP reachability scan (find alive IPs, e.g. working CDN edges).
    Scan {
        #[arg(long)] targets: String,
        #[arg(long, default_value_t = 443)] port: u16,
        #[arg(long, default_value_t = 1200)] timeout: u64,
        #[arg(long, default_value_t = 128)] concurrency: usize,
    },
    /// GitHub Actions store-and-forward relay (field-verified channel):
    /// PUT requests/<id>.json → your relay workflow fetches → poll responses/<id>.txt
    RelayGet {
        /// owner/repo of your internet-relay repository
        #[arg(long, default_value = "Parsa-Nasiri/internet-relay")]
        repo: String,
        #[arg(long)] url: String,
        #[arg(long, default_value = "rahyab-req")] id: String,
        #[arg(long, default_value_t = 90)] wait: u64,
    },
    /// Write a starter config to ./rahyab.json
    Init,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    match Cli::parse().cmd {
        Cmd::Probe { config } => probe(config).await,
        Cmd::Test { config, timeout, race_too } => test(config, timeout, race_too).await,
        Cmd::Serve { config, listen, memory } => serve(config, listen, memory).await,
        Cmd::Scan { targets, port, timeout, concurrency } => scan(targets, port, timeout, concurrency).await,
        Cmd::RelayGet { repo, url, id, wait } => {
            match relay::relay_get(&repo, &id, &url, wait).await {
                Ok(body) => {
                    println!("\n=== response ({}) ===", body.len());
                    println!("{body}");
                    let _ = std::fs::write("rahyab-relay-response.txt", &body);
                    println!("saved to rahyab-relay-response.txt");
                }
                Err(e) => {
                    eprintln!("relay failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::Init => init(),
    }
}

fn load_config(p: &PathBuf) -> AppConfig {
    let s = std::fs::read_to_string(p).unwrap_or_else(|e| panic!("read {p:?}: {e}"));
    AppConfig::from_json(&s).unwrap_or_else(|e| panic!("config: {e}"))
}

async fn probe(config: Option<PathBuf>) {
    let engine = match config {
        Some(p) => ProbeEngine::new(load_config(&p).anchors),
        None => ProbeEngine::default(),
    };
    println!("probing…");
    let r = engine.run().await;
    let env = classify(&r);
    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
        "results": r,
        "environment": env.as_str(),
        "meaning": match env {
            rahyab_core::probe::Environment::Open => "open network — everything should work",
            rahyab_core::probe::Environment::PartialTcp => "TCP works, DNS broken/poisoned — use DoH + pinned IPs",
            rahyab_core::probe::Environment::CdnOnly => "only CDN-ish endpoints alive — CDN-fronted profiles first",
            rahyab_core::probe::Environment::DnsOnly => "UDP/DNS alive but TCP dead — UDP tunnels (WireGuard) first",
            rahyab_core::probe::Environment::FullDark => "full blackout — nothing international answers; exotic channels only",
        },
    })).unwrap());
}

async fn test(config: PathBuf, timeout: u64, race_too: bool) {
    let cfg = load_config(&config);
    let engine = ProbeEngine::new(cfg.anchors.clone());
    let r = engine.run().await;
    let env = classify(&r);
    println!("== environment: {} ==", env.as_str());

    let hop: Option<SharedConnector> = cfg.local_hops.first().map(|h| {
        let (h2, p2) = h.socks.rsplit_once(':').expect("hop socks host:port");
        Arc::new(Socks5Connector::new(TargetAddr::Domain(h2.to_string(), p2.parse().expect("port")))) as SharedConnector
    });

    let mem = rahyab_core::memory::Memory::load(&memory_path(&cfg, &None));
    let cands = plan(&cfg, &mem, &env, hop);
    println!("== {} candidates built ==", cands.len());
    println!("| # | label | kind | port | fit | score | result | ms |");
    println!("|---|-------|------|------|-----|-------|--------|----|");
    let mut matrix = Vec::new();
    for (i, c) in cands.iter().enumerate() {
        let started = std::time::Instant::now();
        let res = tokio::time::timeout(
            Duration::from_secs(timeout),
            check_health(&c.connector, Duration::from_secs(timeout)),
        )
        .await;
        let (status, ms) = match res {
            Ok(Ok(_)) => ("OK".to_string(), started.elapsed().as_millis()),
            Ok(Err(e)) => (format!("FAIL ({e})"), started.elapsed().as_millis()),
            Err(_) => ("TIMEOUT".to_string(), started.elapsed().as_millis()),
        };
        println!("| {i} | {} | {} | {} | {} | {:.0} | {status} | {ms} |", c.label, c.kind, c.port, c.env_fit, c.score);
        matrix.push(serde_json::json!({
            "rank": i, "label": c.label, "kind": c.kind, "port": c.port,
            "env_fit": c.env_fit, "score": c.score, "status": status, "ms": ms,
        }));
    }
    if race_too {
        let strat = cfg.strategy.clone();
        println!("== racing top {} concurrently ==", strat.concurrency);
        match race(&cands, &strat).await {
            Some((w, lat)) => println!("RACE WINNER: {} ({lat:?})", w.label),
            None => println!("RACE: no winner"),
        }
    }
    let _ = std::fs::write("rahyab-matrix.json", serde_json::to_string_pretty(&matrix).unwrap());
    println!("matrix saved to rahyab-matrix.json");
}

fn memory_path(cfg: &AppConfig, custom: &Option<PathBuf>) -> PathBuf {
    custom.clone().unwrap_or_else(|| {
        cfg.memory_path.clone().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("rahyab_memory.json"))
    })
}

async fn serve(config: PathBuf, listen: String, memory: Option<PathBuf>) {
    let cfg = load_config(&config);
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|e| panic!("bind {listen}: {e}"));
    let hub_port = listener.local_addr().unwrap().port();
    let shared = Arc::new(EngineShared::new());
    shared.update(|s| s.hub_addr = Some(listener.local_addr().unwrap()));
    let (stop_tx, stop_rx) = watch::channel(false);

    let hop: Option<SharedConnector> = cfg.local_hops.first().map(|h| {
        let (h2, p2) = h.socks.rsplit_once(':').expect("hop socks host:port");
        Arc::new(Socks5Connector::new(TargetAddr::Domain(h2.to_string(), p2.parse().expect("port")))) as SharedConnector
    });

    let mem_path = memory_path(&cfg, &memory);
    tokio::spawn(serve_hub(listener, shared.hub_current.clone(), stop_rx.clone()));
    tokio::spawn(rahyab_core::algo::supervise(
        cfg.clone(),
        mem_path.clone(),
        shared.clone(),
        stop_rx.clone(),
        hop,
    ));

    println!("rahyab hub on socks5://127.0.0.1:{hub_port}  (Ctrl-C to stop)");
    let (stop2, mut tick_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        println!("shutting down…");
        let _ = stop_tx.send(true);
        let _ = stop2.send(true);
    });
    loop {
        tokio::select! {
            _ = tick_rx.changed() => break,
            _ = tokio::time::sleep(Duration::from_secs(10)) => {
                let s = shared.status_json();
                println!("status: {s}");
            }
        }
    }
}

async fn scan(targets: String, port: u16, timeout: u64, concurrency: usize) {
    let raw = std::fs::read_to_string(&targets).unwrap_or_else(|e| panic!("read {targets}: {e}"));
    let mut ips: Vec<IpAddr> = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((base, bits)) = line.split_once('/') {
            // IPv4 CIDR (capped: no larger than /20 to stay polite)
            if let (Ok(b), Ok(n)) = (base.parse::<std::net::Ipv4Addr>(), bits.parse::<u8>()) {
                if n < 20 {
                    println!("skipping {line}: subnet larger than /20 (be polite)");
                    continue;
                }
                let net = u32::from(b);
                let mask = if n == 0 { 0 } else { u32::MAX << (32 - n as u32) };
                let start = net & mask;
                let count = 1u32 << (32 - n as u32);
                for i in 0..count {
                    ips.push(IpAddr::V4(std::net::Ipv4Addr::from(start + i)));
                }
            }
        } else if let Ok(ip) = line.parse::<IpAddr>() {
            ips.push(ip);
        } else {
            // hostname: resolve once
            if let Ok(mut addrs) = tokio::net::lookup_host((line, port)).await {
                if let Some(a) = addrs.next() {
                    ips.push(a.ip());
                }
            }
        }
    }
    println!("scanning {} targets on port {port}…", ips.len());
    use tokio::sync::Semaphore;
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::new();
    for ip in ips {
        let sem = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await;
            let dst = std::net::SocketAddr::new(ip, port);
            let ok = tokio::time::timeout(Duration::from_millis(timeout), tokio::net::TcpStream::connect(dst))
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);
            (ip, ok)
        }));
    }
    let mut alive = Vec::new();
    for h in handles {
        if let Ok((ip, true)) = h.await {
            println!("ALIVE {ip}:{port}");
            alive.push(ip.to_string());
        }
    }
    println!("{} alive", alive.len());
    let _ = std::fs::write("rahyab-alive-ips.txt", alive.join("\n"));
    println!("saved to rahyab-alive-ips.txt");
}

fn init() {
    let sample = serde_json::json!({
        "profiles": [
            { "link": "vless://YOUR-UUID@your-cf-worker.yourdomain.workers.dev:443?security=tls&type=ws&host=your-cf-worker.yourdomain.workers.dev&path=%2Fws#worker-direct" },
            { "link": "vless://YOUR-UUID@your-cf-worker.yourdomain.workers.dev:443?security=tls&type=ws&host=your-cf-worker.yourdomain.workers.dev&path=%2Fws#worker-betterip",
              "prefer_ips": ["104.16.0.1", "172.67.0.1"] },
            { "link": "trojan://YOUR-PASSWORD@your-vps.example.com:443?sni=your-vps.example.com#vps-trojan" },
            { "link": "ss://BASE64(method:password)@your-vps.example.com:8388#vps-ss" }
        ],
        "local_hops": [
            { "name": "psiphon", "socks": "127.0.0.1:1080" }
        ],
        "anchors": {
            "tcp_intl": ["1.1.1.1:443", "8.8.8.8:443", "www.google.com:443", "github.com:443"],
            "tcp_domestic": [],
            "cdn_ips": [],
            "doh": ["https://cloudflare-dns.com/dns-query?name=%s&type=A"],
            "udp_dns": ["8.8.8.8:53", "1.1.1.1:53"]
        }
    });
    let _ = std::fs::write("rahyab.json", serde_json::to_string_pretty(&sample).unwrap());
    println!("wrote rahyab.json — edit profiles, then: rahyab test --config rahyab.json");
}
