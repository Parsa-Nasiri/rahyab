# Rahyab — راه‌یاب

**A blackout-resilient internet pathfinder for Iran.** One Android button that probes the
network, races every connection method it knows (VLESS·WS·TLS / Trojan / Shadowsocks /
SOCKS5 / HTTP / WireGuard / embedded Psiphon / Cloudflare-Workers nodes), remembers what
worked, and hot-swaps tunnels without dropping the VPN when the network degrades.

> Named for the [shirokhorshid](https://github.com/shirokhorshid) community — شیر و خورشید.
> This project stands on their shoulders and on the June-2025 stealth-blackout research
> (OONI/NetBlocks/Access Now) — full knowledge base in [`docs/`](docs/00-INDEX.md).

## Why "best algorithm" means this

During a real blackout there is no single magic protocol — there is a *sequence of dying
networks*, and **combinations are what survive them**. That's field-proven: VLESS inside
Psiphon connected during a full-dark period when both were closed alone; CDN-fronted
profiles with clean pinned IPs reached the open internet; allowed-domain SNI escape
(`fonts.googleapis.com`) passed whitelisting DPI. Khorshid (the algorithm in
`crates/rahyab-core/src/algo.rs`) therefore treats connectivity as a control problem:

1. **PROBE** — classify the environment: `open / partial-tcp / cdn-only / dns-only / full-dark`.
2. **PLAN** — every profile × every combination class: `direct` / `ip<clean-IP>` /
   `front:<allowed-SNI>` (whitelisting escape) / combinations of those / `via-hop`
   (inside Psiphon) / `via-hop+front` — the full-dark champion — plus optional
   **TLS ClientHello fragmentation** (`frag: true`, patterniha's serverless technique),
   all scored for the detected environment + learned memory.
3. **RACE** — top-N candidates proven with real end-to-end `generate_204` checks; first
   genuine success wins.
4. **WATCH** — 15s health beacons, 2-strike failover, exponential backoff; the local SOCKS
   hub hot-swaps upstreams atomically so the VPN interface never flaps.

State persists: the app gets better on *your* network every day it runs.

## The app

- Rust core (`rahyab-core`) + JNI (`rahyab-android`): tun2proxy binds the VpnService tun
  fd (virtual DNS, UDP-gateway) and feeds the local hub.
- Compose UI: **one CONNECT button**, live status (phase • environment • active method),
  profile editor accepting any `vless:// trojan:// ss://` links + base64 subscriptions
  (v2rayNG-ecosystem compatible — Workers/edgetunnel configs paste straight in).
- Optional embedded Psiphon (reflective AAR drop-in, docs/06) → automatic VLESS-in-Psiphon,
  SS-in-Psiphon chains ("V2Ray + Psiphon" combos).

## The CLI (the combo-tester)

```bash
rahyab probe                       # what kind of network am I on?
rahyab test  --config rahyab.json  # race EVERY candidate → the live combo matrix
rahyab serve --config rahyab.json  # full Khorshid engine as a local SOCKS hub
rahyab scan  --targets ips.txt --port 443   # alive-IP finder (CDN edges)
rahyab relay-get --url https://…   # GitHub Actions store-and-forward fetch (field-verified)
```

`rahyab init` writes a starter config. Run `test` in every blackout phase you see and keep
the `rahyab-matrix.json` outputs — that's how the knowledge base gets ground truth.

## Build & CI

- **GitHub Actions** (`.github/workflows/`): unit tests on every push + an APK build job
  (cargo-ndk for arm64/armv7/x86_64 → assembleDebug → artifact). Push and download.
- Local build: [`docs/07-android-build.md`](docs/07-android-build.md).

## Honest status

See [`docs/08-testing-playbook.md`](docs/08-testing-playbook.md): everything testable
without Iranian network conditions is tested here (31+ unit tests: protocol roundtrips,
classification matrix, planner, racer, hub hot-swap, memory). The WireGuard data path is
experimental; REALITY/Hysteria2/DNS-tunnel are roadmap items parsed with clear messages.
The field test is yours — the playbook lists exactly what to run and what to send back.

## License

MIT (check dependencies' licenses for distribution specifics).
