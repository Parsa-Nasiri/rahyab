//! Rahyab core — blackout-resilient connection engine.
//!
//! Layers:
//! - `transport`  : pluggable tunnels (SOCKS5, HTTP-CONNECT, Shadowsocks, VLESS, Trojan, WireGuard)
//!                  with arbitrary chaining (e.g. VLESS inside a local Psiphon SOCKS hop).
//! - `config`     : parses the standard share-link ecosystem (vless:// trojan:// ss:// …) so the app
//!                  is instantly compatible with the Iranian config-distribution channels.
//! - `probe`      : classifies the network into an `Environment` (Open → FullDark) from live probes.
//! - `algo`       : "Khorshid" — the adaptive planner/racer/supervisor that keeps you connected.
//! - `hub`        : a local SOCKS5 hub that hot-swaps its upstream without dropping the VPN.

pub mod algo;
pub mod config;
pub mod health;
pub mod hub;
pub mod memory;
pub mod probe;
pub mod transport;

pub use transport::{Connector, SharedConnector, TargetAddr};
