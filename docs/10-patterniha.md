# 10 — patterniha: Research & What We Adopted

Research on [github.com/patterniha](https://github.com/patterniha) (3.5k+ followers,
Telegram: t.me/patterniha, t.me/projectXhttp) — one of the most consequential individual
contributors to Iran-specific circumvention right now: inventor of the MITM+DomainFronting
method that was **merged into upstream Xray-core** (XTLS/Xray-core#4348), author of the
blackout-oriented serverless configs, maintainer of PattN/PattNG clients (v2rayN/v2rayNG
forks combining Xray + Rust Aether/WARP-MASQUE + Psiphon sidecar), and operator of a
daily-tested free-config pipeline.

## Their repos that matter to Rahyab

| Repo | ★ | Technique | Status for us |
|------|---|-----------|---------------|
| [MITM-DomainFronting](https://github.com/patterniha/MITM-DomainFronting) | 2,944 | Local MITM with user CA → re-emit TLS with fake SNI of frontable domain; serverless access to Google/Meta/Fastly sites; Android no-root (Chromium) | **Roadmap** (needs user-CA trust flow; browser-level, not core-level) |
| [SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing) | 2,846 | **Wrong-sequence decoy ClientHello**: DPI reads fake SNI and whitelists; server drops the out-of-window packet; real handshake follows | **Roadmap** (needs raw-packet injection; WinDivert there, etherparse/raw-sockets for us) |
| [Serverless-for-Iran](https://github.com/patterniha/Serverless-for-Iran) | 1,312 | Serverless direct access: **TLS ClientHello fragmentation (6/98/1 splits)**, UDP noise flood (24×1200B), Happy Eyeballs IPv6-first, FakeDNS | **TLS frag: IMPLEMENTED** (`frag: true` on profiles); UDP noise + IPv6-first: roadmap |
| [Free-Configs](https://github.com/patterniha/Free-Configs) | 430 | Daily-tested free configs; **keeps only Cloudflare-working ones to bypass Iranian upload-limiting** on foreign IPs | Feed directly into Rahyab: `configs.txt` parses natively |
| [PattNG](https://github.com/patterniha/PattNG) | 1,426 | v2rayNG fork: Xray + **Aether Rust core** + **Psiphon sidecar** + **bundled signed `psiphon_servers.dat`** for fresh installs on dead networks | Architecture validation for Rahyab; Psiphon server-list bundling: adopt (docs/06) |
| [Aether](https://github.com/patterniha/Aether) (CluvexStudio upstream) | 34 | **Rust WARP-over-MASQUE core (quiche/HTTP-3)** with data-plane-validated gateway scanning, nested tunnels (WG-over-MASQUE `--gool`, MASQUE-in-MASQUE `--mim`), Tor-inside-tunnel | **Roadmap integration**: another pure-Rust transport crate we can bind the same way |
| QS-Tunnel / QQ-Tunnel | 186/119 | UDP-over-DNS with IP-spoofed replies; DNS-only tunnels with rotating resolvers + source-port rotation | Confirms the DNS-tunnel roadmap priority (docs/05) |
| Xray-core fork | 67 | ECH `+one` DoH variants, `finalmask` TCP masks, oob dial mode | Watch for more merges |

## Decisions made for Rahyab from this research

1. **IMPLEMENTED — TLS ClientHello fragmentation** (`frag: true` per profile, offsets 6/98):
   a `FragStream` decorator wraps the stream *before* the rustls handshake; unit-tested
   to split `[6,92,rest]` with byte-identical reassembly. Works with EVERY variant
   (direct/ip/front/via-hop) because it's applied at the TLS layer — combinations again.
2. **ADOPT — bundled Psiphon server list**: fresh installs on dead networks can't fetch
   server entries; PattNG ships a signature-verified `psiphon_servers.dat`. When you build
   the Psiphon AAR, also drop the server list into assets (docs/06).
3. **ADOPT — upload-limit-aware profile selection**: Iranian ISPs throttle upload to
   foreign IPs; patterniha's pipeline filters for CF-working configs — our `prefer_ips` +
   cdn-only ranking already prefers exactly those.
4. **VALIDATED — our architecture**: PattNG ⇄ Aether is the same shape we built
   (Rust core via JNI under a Kotlin GUI, scanner + delay-tester + identity manager).
5. **ROADMAP (ordered by value/effort)**: wrong-seq SNI decoy (needs raw sockets) →
   UDP noise around QUIC transports → MITM+DomainFronting mode (user CA + browser rules)
   → Aether/MASQUE transport integration → IPv6-first Happy Eyeballs in the probe.

Their explicit warning worth keeping: **client-side latency tests do not predict whether
serverless fragmented configs work** — only real connections do. Our racer already only
trusts real end-to-end 204s.
