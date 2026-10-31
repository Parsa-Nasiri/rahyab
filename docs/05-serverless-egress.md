# 05 — Free / Serverless Egress & Bootstrap Channels

Verified late-2026 status of the "free infrastructure" layer.

## Cloudflare Workers — VLESS over WebSocket (edgetunnel) ✅ primary recommendation

- [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) (48.7k★, active): VLESS +
  Trojan + SS over WS+TLS on Workers/Pages, admin panel, auto-generated subscriptions
  (v2rayNG/Clash/sing-box compatible).
- Deploy: Workers → paste `_worker.js` → set `ADMIN` → bind KV namespace → (optionally)
  custom domain → `/admin` panel. Sub links can be pasted straight into Rahyab.
- Limits: free plan CPU/requests quotas; Error 1101 known issue; needs a Cloudflare account.
- Iranian-community practice: front it on your own domain, then hunt "better IPs"
  (alive CF edge IPs) with `rahyab scan` and feed them as `prefer_ips`.
- Related: zizifn/edgetunnel (original), 3Kmfi6HP/EDtunnel, SHIJS1999/cloudflare-worker-vless-ip.

## GitHub as egress/CDN

- `raw.githubusercontent.com` + GitHub Pages + gists: excellent for **config
  distribution** (subscriptions), and typically reachable whenever any international
  path exists.
- **GitHub Actions store-and-forward relay — VERIFIED WORKING by you** (Oct 2026,
  `Parsa-Nasiri/internet-relay`): write `requests/<id>.json` via Contents API → workflow
  fetches with full internet → response committed to `responses/<id>.txt` → read via raw.
  ~25–35s round trip, GET/POST/headers/redirects all verified. Rahyab CLI reproduces it:
  `rahyab relay-get --url https://example.com/...` (uses `GITHUB_TOKEN` / `gh auth token`).
  Not a real-time tunnel — use it for configs, news, and control messages when GitHub is
  the only thing alive.
- GitHub Codespaces: real outbound egress, 60h/month free — a human-only stopgap.

## Google-hosted bootstrap (the "Google Fonts" idea, refined)

- What's genuinely useful:
  - **DoH anchors**: `dns.google` (8.8.8.8), Cloudflare 1.1.1.1 — hardcoded anchors in Rahyab.
  - **Google Apps Script web app** as a CORS/GET relay: deploy a tiny `doGet` that fetches
    a URL and returns it — good for pulling config lists when only Google domains respond.
    Limits: quotas (~20k/day consumer), no streaming, GET-oriented. Roadmap client: fetch
    subscription via Apps-Script-relay when direct fetch fails.
  - **Google Fonts/gstatic**: always-allowed static delivery — fine for shipping small
    bootstrap payloads (e.g. an updated anchor list) to your own users; not a tunnel.
- What's dead: classic domain fronting (killed by Google/Cloudflare in 2018); ECH is not
  a bypass channel against Iranian DPI today.

## Cloudflare WARP

- `wgcf` (ViRb3/wgcf) generates WARP WireGuard profiles → Rahyab can ingest them as
  `rahyab://` WG profiles. Community reports on WARP in Iran vary by phase/ISP — treat
  as one more candidate the racer can try, not a plan.

## Emergency low-bandwidth channels (full-dark adjacency)

| Channel | Tool | Bandwidth | Notes |
|---------|------|-----------|-------|
| DNS tunnel | iodine / dns2tcp (needs your own authoritative NS) | ~10–50 kbps | works in `dns-only` phase; roadmap client |
| ICMP tunnel | icmptx / hans (root) | ~20–100 kbps | rare but real window |
| SMS bridges | Tasker/automation + relay bot | human-scale | config refresh, not browsing |
| Offline mesh | Briar (Wi-Fi/BT), Bridgefy, Meshtastic | local | coordination during total blackout |
| Shortwave/data HF | experimental | very low | last resort, hardware |

## IP finding / scanning (the "IP finder" you asked for)

`rahyab scan --targets ips.txt --port 443` — polite TCP reachability scanner
(≤ /20 subnets, configurable concurrency) for finding alive CDN edges / your own
server IPs. Community alternatives: XIU2/CloudflareSpeedTest and the Persian
"CF IP scanner" tools — their output pastes directly into `prefer_ips` or
`anchors.cdn_ips`.
