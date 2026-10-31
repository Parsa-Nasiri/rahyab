# 04 — The Khorshid Algorithm (خورشید)

"Khorshid" = the sun. Named for the shirokhorshid community. It is a four-stage loop
whose entire purpose is: **never stay down one second longer than physics allows, and
never lie about what it found.**

```
        ┌──────────────────────────────────────────────────┐
        │                    SUPERVISOR                    │
        │                                                  │
   ┌────▼────┐   ┌────────┐   ┌───────┐   ┌──────────────┐  │
   │  PROBE  │──▶│  PLAN  │──▶│ RACE  │──▶│    WATCH     │  │
   │ 2.5s to │   │ scored │   │ top-N │   │ beacon 15s   │  │
   │ timeout │   │ ranked │   │ races │   │ 2 strikes →  │  │
   └─────────┘   └────────┘   └───────┘   │ re-plan      │  │
        ▲              ▲          │       └──────────────┘  │
        │              │          ▼ winner                  │
        │              │     ┌──────────────┐               │
        └──────────────┴─────│  LOCAL HUB   │ hot-swaps     │
                             │ 127.0.0.1:…  │ upstream      │
                             └──────────────┘ without VPN   │
                                                            │
        backoff on total failure: 2s → 5min (+ jitter)      │
        re-probe at least every 5 min                       │
        └──────────────────────────────────────────────────┘
```

## 1. PROBE — classify before you act

Parallel probes with 3s timeouts each (probe.rs):
- system DNS (resolve two well-known domains),
- DoH (own TLS+HTTP stack, dial by IP so dead system DNS can't hurt),
- UDP DNS query to 8.8.8.8/1.1.1.1,
- TCP connects to international anchors + CDN-tagged anchors + user-supplied domestic anchors.

Pure function `classify()` maps results → `open | partial-tcp | cdn-only | dns-only | full-dark`.
Unit-tested classification matrix.

## 2. PLAN — combinatorics with memory

For **every profile** the planner generates the combination classes (bounded to 8):

| Variant | What it does |
|---------|--------------|
| `direct` | the profile as configured |
| `ip<addr>` ×3 | TCP pinned to a clean/known-good IP (community "better IPs"), SNI keeps the domain |
| `front:<allowed-SNI>` ×2 | dial the server while claiming `fonts.googleapis.com` / `www.gstatic.com` SNI (field-verified whitelisting escape) |
| `ip0+front:` | clean IP + allowed SNI |
| `via-hop` | chained through the local Psiphon SOCKS |
| `via-hop+front:` | Psiphon hop + allowed SNI — **the field-proven full-dark champion** (VLESS-in-Psiphon connected when both were closed alone → +6 in FullDark) |

Each candidate is scored: `env_fit(kind, port, cdn_likelihood, udp, chained, sni_front,
environment) × 10 + last-good(+50) + latency-EMA bonus + wins − failures×2 − cooldown(−1000)`.
All state persists (`rahyab_memory.json`) — the app gets better the longer it lives
on a given network. This is the "implement the best algorithm" answer: not one magic
trick, but measured selection + racing + memory.

## 3. RACE — first *proven* path wins

Top `concurrency` (default 4) candidates are health-checked concurrently. The health
check is real: a full TCP+HTTP GET `/generate_204` through the tunnel to multiple
independent endpoints (Cloudflare, Google, MIUI, V2EX) — first candidate that returns
a genuine 204/200 wins. Others are marked failed (cooldown after 3 consecutive losses).
No candidate is trusted because a config file *says* it works.

## 4. WATCH — hot failover

The winner serves the **local SOCKS hub**; tun2proxy (the VPN's TUN device) points at
the hub. When health decays (2 failed beacons), the supervisor re-plans and the hub's
upstream is swapped atomically (arc-swap) — **the VPN interface never goes down during
failover**. Backoff doubles on total failure (2s → 300s cap).

## Android flow (one button)

```
[CONNECT] → Engine.start()        → RustCore.startEngine(config) → hub on 127.0.0.1:P
          → VpnService permission → TunnelVpnService → establish() fd
          → RustCore.startTunnel(fd, 1500, P) → tun2proxy(tun fd → hub)
          → Khorshid picks winner → hub upstream set → internet flows
```

## Design guarantees

- Every probe/planning decision is logged + exposed via `statusJson()` (the UI shows
  phase, environment, active method, attempts, last error).
- All transports equal citizens (one trait) → new methods are additive.
- Mockable everything → the full loop is unit-tested with simulated blackouts
  (`race_picks_the_healthy_candidate`, `planner_prefers_last_good`, hub hot-swap test).
