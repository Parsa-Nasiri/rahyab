# 09 — Research Sources

## Blackout measurement & research

- OONI-based multi-stakeholder analysis — *"Iran's Stealth Blackout"* (June 2025) — near-zero
  OONI measurements June 19–20 2025; stealth model (BGP preserved, domestic isolation).
- *"Iran's Stealth Internet Blackout: A New Model of Censorship"* (July 2025).
- *"Report on Iran's Blackout of the Global Internet"* (Oct 2025).
- NetBlocks live measurements, June 2025 (near-total national blackout, ~40% connectivity).
- Access Now / IODA — shutdown tracking, 2019 & 2022 blackouts.

## The shirokhorshid ecosystem (community)

- https://github.com/shirokhorshid — شیر و خورشید org:
  - `shirokhorshid-android` (1.6k★, GPL-3.0): independent community fork of the Psiphon
    Android client with extra connection controls; active through Oct 2026.
  - forks of `psiphon-tunnel-core`, `quic-go`, `pion/dtls`, `XTLS/Xray-core`.
  - Telegram: t.me/ShirokhorshidOfficial.
- Psiphon-Labs: `psiphon-tunnel-core` (MobileLibrary/Android gomobile AAR, EmbeddedClient),
  `psiphon-tunnel-core-binaries` (prebuilt AARs).

## Config ecosystem (compatible link formats)

- cmliu/edgetunnel (48.7k★) + zizifn/edgetunnel — Cloudflare Workers VLESS/Trojan/SS over WS+TLS.
- barry-far/V2ray-Configs, Epodonios/v2ray-configs, mahdibland/V2RayAggregator — the
  subscription aggregators whose link formats Rahyab parses.

## Rust / Android stack (verified against vendored sources)

- tun2proxy 0.8.6 (blechschmidt) — `Args`, `general_run_async(args, mtu, pi, CancellationToken)`,
  `tun_fd` for Android VpnService, virtual DNS (198.18.0.0/15), SOCKS5/HTTP upstreams.
- shadowsocks-crypto 0.8 — v1 AEAD ciphers, HKDF "ss-subkey", `openssl_bytes_to_key`
  (pure RustCrypto backend; avoids the aws-lc/CMake path of the full shadowsocks crate).
- rustls 0.23 + ring, tokio-rustls 0.26 — TLS with SNI-front/insecure modes.
- boringtun 0.6 (Cloudflare) — WireGuard Noise-IK in Rust (low-maintenance upstream:
  considered GotaTun/tokio-wireguard as alternatives; kept boringtun for now).
- smoltcp 0.12 — userspace TCP/IP stack (WireGuard virtual interface).
- arc-swap 1.9 — hot-swappable hub upstream.

## Serverless / free egress

- cmliu/edgetunnel deploy docs (Workers/Pages, KV, PROXYIP, BEST_SUB).
- XIU2/CloudflareSpeedTest + Persian CF-IP-scanner tools → `prefer_ips` feeds.
- ViRb3/wgcf — WARP WireGuard profile generator.
- GitHub: raw/Pages/gists as config CDN; GitHub Actions 6h egress (documented, not recommended).
- Google Apps Script web-app relays (quotas, GET-only, no streaming).

## patterniha (researched via sub-agent, full report in docs/10)

- https://github.com/patterniha — MITM-DomainFronting (2.9k★, merged into Xray-core
  XTLS/Xray-core#4348), SNI-Spoofing (wrong-sequence decoy ClientHello, 2.8k★),
  Serverless-for-Iran (TLS fragmentation 6/98, UDP noise, IPv6 Happy Eyeballs),
  Free-Configs (daily-tested, upload-limit-aware), PattNG (v2rayNG fork embedding the
  Aether Rust core + Psiphon sidecar with bundled signed server list), QS/QQ-Tunnel
  (DNS-based tunnels).

## Your own field data (primary evidence)

- Obsidian vault `Blackout Internet Access/` — Transport Matrix, Test Results, Playbook
  (Oct 30, 2026): GitHub relay verified end-to-end, Fonts-IP SNI whitelisting verified,
  Apps Script relay verified, full connectivity map from the restricted position.
- `github.com/Parsa-Nasiri/internet-relay` — the working relay repo + workflows.

## Status of unverified items

- "Ruflo plugin": no VPN/proxy product by this name exists (the only notable GitHub project
  `ruvnet/ruflo` is an AI agent platform). If you meant a different tool, tell me and it
  goes in the matrix.
