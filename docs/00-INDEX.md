# Rahyab Knowledge Base — Index

راه‌یاب = "pathfinder". This is the complete knowledge base for **connecting to the
internet during an Iranian full blackout**, gathered from research (OONI, NetBlocks,
Access Now, IRCF, the shirokhorshid community), verified Rust source code, and a
runnable test harness.

| File | What's in it |
|------|--------------|
| [01-blackout-reality.md](01-blackout-reality.md) | What a blackout actually kills, the June 2025 "stealth blackout", what survived |
| [02-methods-catalog.md](02-methods-catalog.md) | Every transport method: how it works, when it dies, requirements |
| [03-combo-matrix.md](03-combo-matrix.md) | The ABC matrix: method × environment + YOUR verified full-dark field data |
| [04-khorshid-algorithm.md](04-khorshid-algorithm.md) | The adaptive connection algorithm implemented in the app |
| [05-serverless-egress.md](05-serverless-egress.md) | Cloudflare Workers (edgetunnel), GitHub relay (field-verified), Apps Script, Google-Fonts bootstrap, WARP |
| [06-psiphon.md](06-psiphon.md) | Psiphon embedding + the field-proven VLESS+Psiphon combos (both directions) |
| [07-android-build.md](07-android-build.md) | How the app is built (CI + locally), Psiphon AAR drop-in |
| [08-testing-playbook.md](08-testing-playbook.md) | What was verified here vs what YOU must test inside Iran — exact commands |
| [09-sources.md](09-sources.md) | All research sources |
| [10-patterniha.md](10-patterniha.md) | patterniha research: MITM+DomainFronting, wrong-seq SNI, TLS frag (implemented), Aether/Rust-MASQUE |

## The repo

```
rahyab/
├── crates/
│   ├── rahyab-core/      # transports + probe + Khorshid algorithm (pure Rust, tested)
│   ├── rahyab-cli/       # rahyab probe / test / serve / scan — the combo tester
│   └── rahyab-android/   # JNI: tun2proxy + engine for the Android app
├── android/              # Compose app: one big CONNECT button (VpnService)
├── .github/workflows/    # CI: unit tests + automatic APK builds
└── docs/                 # this knowledge base
```

## Honest summary of what works where (details in 03)

- **Normal filtering**: VLESS+WS+TLS (Cloudflare Workers), Trojan, Shadowsocks, Psiphon — all implemented and code-tested.
- **Partial blackout (TCP alive, DNS broken)**: the algorithm switches to DoH + IP-pinned profiles automatically.
- **CDN-only phase**: CDN-fronted profiles (Workers/edgetunnel + "better IP" lists) rank first automatically.
- **Full dark**: nothing international answers — the app keeps trying (UDP/WG, CDN edges), holds last-good memory, and tells you honestly that out-of-band channels (satellite, SMS mesh) are the remaining options. No app can conjure a path through a hard shutdown; **planning for full-dark is about surviving the phases before and after it**.
