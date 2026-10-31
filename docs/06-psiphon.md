# 06 — Psiphon Integration (the shirokhorshid path)

[shirokhorshid](https://github.com/shirokhorshid) — "شیر و خورشید" — is an independent,
community-maintained fork of the Psiphon Android client (~1.6k★, active through 2026),
plus forks of psiphon-tunnel-core, quic-go and dtls. Their approach validates the core
assumption of Rahyab: **Psiphon is the single most resilient general-purpose tool during
Iranian blackouts**, and the right way to use it is as a *component*, not the whole app.

## How Psiphon embedding works (verified from Psiphon-Labs sources)

- Engine: `Psiphon-Labs/psiphon-tunnel-core` (Go) — gomobile-compiled Android library.
- Library: `MobileLibrary/Android` in that repo → builds `ca.psiphon.aar`
  (`PsiphonTunnel.Host` interface, `startTunnel(context, embeddedConfigJson)`).
- Prebuilt: `Psiphon-Labs/psiphon-tunnel-core-binaries` releases ship the AAR.
- Runtime: the tunnel exposes **local HTTP/SOCKS proxies** on 127.0.0.1.

## Rahyab's integration (reflective, optional)

`PsiphonManager.kt` loads `ca.psiphon.PsiphonTunnel` **by reflection**:
- AAR present → Psiphon starts as a local hop (`127.0.0.1:<port>` SOCKS),
- AAR absent → the rest of the app is unaffected (pure VLESS/Trojan/SS engine).

The hop is registered in the Khorshid config as `local_hops[0]`, which automatically
gives you every combo:

1. **Psiphon only** — if all profiles are dead, the hub can serve the Psiphon hop directly.
2. **VLESS-in-Psiphon** — the Worker/VLESS profile dialing *through* Psiphon: your VLESS
   handshake hides inside Psiphon's rotating obfuscation. The classic "V2Ray + Psiphon"
   combo, implemented as a one-flag variant (`via-hop`).
   **This is the combination that field-verified CONNECTED during a real full-dark
   period when both alone were closed.** The planner therefore ranks `via-hop`
   candidates first in the FullDark environment (+6).
3. **SS/Trojan-in-Psiphon** — same for other servers.
4. **Psiphon-through-VLESS (reverse chain)** — psiphon-tunnel-core supports an
   `upstreamProxyUrl` in its embedded config. Point it at the Rahyab hub running a
   VLESS profile: `"upstreamProxyUrl": "socks://127.0.0.1:<hubPort>"`. If your VLESS
   server is reachable but Psiphon's own bootstrap is blocked, this lets Psiphon ride
   your tunnel — the second direction of the same proven combination.
5. **via-hop + front** — chained through Psiphon *and* claiming an allowed-domain SNI;
   the planner's top FullDark candidate when the hop is alive.

## Setup

1. Get the AAR — and for the full-dark behavior you described, prefer the
   **shirokhorshid fork**:
   - **shirokhorshid's aggressive server search** (the one that found Psiphon servers
     when nothing else could) lives in `github.com/shirokhorshid/psiphon-tunnel-core`
     (their fork, actively maintained through 2026). Build the AAR from it with gomobile:
     ```bash
     git clone https://github.com/shirokhorshid/psiphon-tunnel-core
     cd psiphon-tunnel-core/MobileLibrary/Android
     ./gradlew build   # → app/build/outputs/aar/*.aar (rename ca.psiphon.aar)
     ```
   - Or the official prebuilt: `Psiphon-Labs/psiphon-tunnel-core-binaries` releases →
     `psiphon-tunnel-library-android-*.aar` → rename to `android/app/libs/ca.psiphon.aar`.
2. Provide an embedded config: sponsor ID, propagation channel ID, and (for a private
   deployment) server entries — in `android/app/src/main/assets/psiphon_embedded.json`.
   Without your own sponsor IDs you're using Psiphon's public network, same as the
   official app.
3. CI fetches the official AAR automatically when available (android.yml, optional step);
   replace it with the shirokhorshid-built one for the aggressive search.

## Honest notes

- The reflection shim polls/assumes the local SOCKS port; wire the real
  `onListeningSocksPort` host callback when you build with the AAR (marked in code).
- Embedded config values are **yours to obtain** — this repo can't ship credentials.
- Test Psiphon-in-Rahyab with `rahyab test` too: run the Psiphon app or `psiphon-tunnel-core`
  locally with its SOCKS listener on 1080, set `local_hops` in rahyab.json, and the CLI
  exercises every chained variant from the terminal.
