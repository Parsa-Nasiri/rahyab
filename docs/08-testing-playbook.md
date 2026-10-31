# 08 — Testing Playbook: what's proven vs what YOU must test

## Verified on this machine (2026-10-31)

| What | How | Status |
|------|-----|--------|
| All transport framing/crypto (VLESS, Trojan, SS-AEAD, SOCKS5, HTTP-CONNECT, WS) | in-process protocol roundtrip tests vs reference implementations | ✅ `cargo test` |
| Share-link + subscription parsing (vless/trojan/ss/vmess/socks + base64 lists) | unit tests | ✅ |
| Khorshid: classification matrix, planner ranking, last-good memory, race-with-failures, hub hot-swap | unit tests with mock connectors (simulated blackouts) | ✅ |
| Memory persistence + cooldowns | unit tests | ✅ |
| Whole workspace compiles (core + CLI + android JNI) | `cargo check --workspace` (Windows/GNU host) | ✅ |
| Android APK assembly | GitHub Actions (needs a push) | ⏳ CI |
| WireGuard data path | crypto handshake unit test only | ⚠️ experimental |
| **Everything requiring Iranian network conditions** | — | ❌ only possible from inside Iran |

No amount of lab testing replaces the field test — that's why the runtime engine
probes and races live on the device instead of trusting static config.

## Your field-test checklist (run from inside Iran)

0. **Already verified by you (Oct 30, 2026)** — GitHub relay end-to-end, Apps Script
   reachable, Fonts-IP SNI whitelisting, combine-failover chain (see `Blackout Internet
   Access/Test Results.md` in your vault and docs/03). The two highest-value open tests:

   - **SNI-escape full tunnel**: does `fonts.googleapis.com` SNI + your VPS IP pass the
     DPI? (config recipe in docs/03). If yes → free full tunnel in whitelisting phases.
   - `rahyab relay-get --url https://httpbin.org/headers` → re-verify the relay from the CLI.

1. **Baseline probe** (no VPN):
   ```
   rahyab probe
   ```
   → note the environment class. Repeat morning/evening and during known filtering waves.

2. **The combo matrix** (this is the ABC test you asked for):
   ```
   rahyab test --config rahyab.json
   ```
   → a table of EVERY candidate (direct, IP-pinned, Psiphon-chained) with result + latency.
   Save `rahyab-matrix.json` per phase. This file IS the ground-truth knowledge base.

3. **Full engine like the app**:
   ```
   rahyab serve --config rahyab.json --listen 127.0.0.1:1080
   ```
   → watch `status:` lines; set your system proxy to 127.0.0.1:1080 to browse through it.

4. **IP hunting for the CDN-only phase**:
   ```
   rahyab scan --targets cdn-ips.txt --port 443
   ```
   → alive IPs go into `prefer_ips` / `anchors.cdn_ips` (your verified Fonts-IP list
   142.250.1.95–107 / 192.178.183.95 is already a great starting set).

5. **Psiphon chains**: start any Psiphon client that exposes a local SOCKS (or embed the
   AAR in the app), set `local_hops`, re-run `rahyab test` — compare chained vs direct.

## What to feed the config

- Profiles: any vless/trojan/ss share links you already use (v2rayNG-compatible),
  e.g. from an edgetunnel Workers deployment or community channels.
- `prefer_ips` on CDN profiles: 2–3 known-alive Cloudflare IPs from the scan step.
- `anchors.tcp_domestic`: 1–2 domestic hosts your carrier keeps alive during blackouts
  (a banking app's host, `irancell.ir`, …) — this makes `full-dark` detection accurate
  for YOUR network.

## Known limits to verify first on the ground

1. **WireGuard data path** — crypto tested, real-server test pending (docs/02).
2. **Psiphon AAR reflection shim** — needs the `onListeningSocksPort` callback wired
   when you build with the real AAR.
3. **WS handshake against real Workers** — RFC 6455 client is spec-implemented and
   roundtrip-tested, but real endpoints may send interleaved frames/extensions the
   client must tolerate (it ignores unknown headers; only standard frames handled).
4. Battery/Doze behavior of the foreground service on aggressive OEM ROMs.
