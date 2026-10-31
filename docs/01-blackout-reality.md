# 01 — Blackout Reality: what actually dies, what survives

## The June 2025 "stealth blackout" was a new thing

Research from OONI-based analysts ("Iran's Stealth Blackout", June 2025) and
the October 2025 "Report on Iran's Blackout of the Global Internet":

- Iran did **not** withdraw from the global BGP table. The country *looked* online from
  the outside while domestic users were cut off. This defeats the usual "is Iran offline?"
  dashboards — reachability must be measured **from inside**.
- Connectivity dropped to ~40% and below for days; NetBlocks logged the shutdown as the
  **longest nation-scale internet shutdown on record** (weeks, not hours).
- Domestic services (banking, government "National Information Network" content) kept working.
- Cloudflare addresses and even satellite gear were actively targeted/blocked.

Practical consequence for tooling: **probes must run from the phone itself** — which is
exactly what Rahyab's probe engine does every time the tunnel is (re)established.

## Severity ladder (what the app detects)

| Class | State | What still works | App strategy |
|-------|-------|------------------|--------------|
| `open` | Normal heavy filtering | everything, VPNs may need obfuscation | rank by latency |
| `partial-tcp` | TCP out, DNS broken/poisoned | TCP 443 to most of the world | DoH bootstrap + IP-pinned profiles |
| `cdn-only` | Only big-CDN/whitelisted edges answer | Cloudflare/Akamai/Fastly edges, allowed domains | CDN-fronted profiles (Workers/edgetunnel) first, SNI-fronting |
| `dns-only` | UDP egress alive, international TCP dead | plain UDP (DNS!) | UDP-based tunnels (WireGuard class) first |
| `full-dark` | Nothing international answers | domestic intranet only | honest fail state; keep low-rate retries; document out-of-band options |

## What has historically worked *during* severe phases

- **Psiphon** (shirokhorshid is a community fork with ~1.6k stars) — survives many phases
  thanks to rotating obfuscation protocols and in-country proxies.
- **Tor Snowflake** — cited as working in June 2025.
- **VLESS over WebSocket behind Cloudflare** (edgetunnel deployments) — the dominant
  Iranian community method in 2024–2026; dies only in the CDN-only phase if the CF edge IPs
  themselves are cut (community then shares "better IPs", which Rahyab ingests as `prefer_ips`).
- **In-country relays**: a VPS *inside* Iran (or on domestic CDN like ArvanCloud) that
  forwards to the remaining international links. Requires someone/something inside that
  keeps running — the server side is outside this repo's scope but documented.
- **Satellite** (smuggled Starlink terminals — hardware, illegal in Iran, mentioned for completeness).
- **Offline mesh** (Briar over Wi-Fi/BT, Bridgefy, Meshtastic) and **SMS** — not internet,
  but the last-resort communication layer during full-dark.

## What reliably dies

- Plain OpenVPN, plain WireGuard on UDP 51820, SSH tunnels, HTTPS proxies — DPI+port
  blocks take these within minutes of a crackdown starting.
- VMess (legacy) — detectable; superseded by VLESS+REALITY ecosystem.
- Anything that needs the system resolver during DNS-killing phases — this is why the
  app never trusts system DNS and uses DoH/IP-pinning.

## The "Google Fonts" idea (you asked about it)

The concept — high-trust Google domains stay reachable during filtering, so use them as a
bootstrap channel — has real value but with limits (details in 05):

- `fonts.googleapis.com` / `fonts.gstatic.com` are extremely unlikely to be blocked while
  any international path exists, and Google serves them from CDN edges. You can:
  - distribute **config lists** through Google-hosted endpoints ( Apps Script web app, Google Drive raw links),
  - use `dns.google` (8.8.8.8) and `https://cloudflare-dns.com` as DoH anchors,
  - use Google/Cloudflare edges as the SNI-front for tunnel endpoints.
- What you **cannot** do: turn the fonts CDN itself into a tunnel — it serves static files,
  and Google dropped the old "domain fronting" capability in 2018.
- During a true full-dark phase even Google edges die. There is no software-only trick that
  crosses a hard national shutdown; the ladder above is the realistic fight.
