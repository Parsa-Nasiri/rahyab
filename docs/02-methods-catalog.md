# 02 — Methods Catalog

Every transport implemented in `rahyab-core`, with requirements and failure modes.
All of them share one Rust trait (`Connector`) so any can run **inside** any other
(see Chaining).

## Proxy-class transports (per-connection, chainable)

### VLESS (+ TLS, + WebSocket, + ClientHello fragmentation)
- What: the modern V2Ray-family protocol; request = `[ver][uuid][addons][cmd][port][addr]`.
  We implement TCP + optional TLS (rustls) + optional WebSocket (hand-rolled RFC 6455 client)
  + optional **ClientHello fragmentation** (`frag: true` — splits the first burst at bytes
  6/98 so DPI regexes never see the SNI whole; patterniha Serverless-for-Iran technique,
  unit-tested, docs/10).
- Why it matters: **this is the profile shape of every Cloudflare-Workers (edgetunnel) node**
  — the single most-used free method in the Iranian community right now.
- Field-proven combo: **VLESS inside Psiphon** connected during a real full-dark period
  when both were closed alone (`via-hop` variants rank first there).
- Dies when: the CDN edge IP is unreachable (CDN-only phase) → feed `prefer_ips` with
  community "better IP" lists; or SNI-filtered → use `front:` variants.
- Share links: `vless://uuid@host:443?security=tls&type=ws&host=...&path=...#name` ✔ parsed.
- NOT implemented (honest): XTLS-REALITY (needs raw ClientHello forgery), gRPC transport,
  xtls-rprx-vision flow. Parsed and reported as `Unsupported` with a clear reason.

### Trojan (+ TLS, + WS)
- What: password-authenticated proxy that looks like ordinary HTTPS (SHA-224 password, CRLF framing).
- Dies when: same as VLESS. `trojan://password@host:443?sni=...#name` ✔ parsed.

### Shadowsocks (AEAD v1)
- What: the classic. Implemented **directly on shadowsocks-crypto** (pure RustCrypto —
  no C toolchain), supports AES-GCM / ChaCha20-Poly1305 family, runs over any stream,
  so unlike typical SS clients it CAN be chained (e.g. inside Psiphon).
- Dies when: heavy DPI phases (SS remains identifiable); still valuable as backup.

### SOCKS5 / HTTP-CONNECT
- Plain proxies. Mainly useful as *inner hops* (Psiphon's local listener, LAN proxies)
  and for the local hub itself.

## Tunnel-class transports

### WireGuard (experimental)
- What: boringtun (Cloudflare's Noise-IK in Rust) + a smoltcp virtual IP interface.
  UDP-based, no kernel TUN needed — the virtual interface is inside the library.
- Status: **handshake path implemented, data path experimental** — unit-tested crypto
  roundtrip; must be field-tested against a real server before trusting it (docs/08).
- Why it matters: UDP egress sometimes survives phases where TCP is throttled (`dns-only` class).

### Psiphon (embedded, optional AAR)
- What: the full Psiphon tunnel-core as an Android library (gomobile AAR). Provides its own
  obfuscation rotation + server rotation; exposes a **local SOCKS** listener.
- Integration: reflective, optional (docs/06) — app builds with or without the AAR.
- This is the shirokhorshid approach: their Android client is a community Psiphon fork
  (~1.6k★, actively maintained through 2026).

## Chaining (the combinatorics engine)

`connect_over(stream, dst)` on every transport means: dial the profile's server *through*
the previous hop, then run the protocol. Implemented chains worth testing:

| Chain | Command shape | Use case |
|-------|--------------|----------|
| VLESS→WS→TLS→TCP | plain profile | edgetunnel/Workers standard |
| VLESS→WS→TLS→**Psiphon-SOCKS** | profile with `dial_through: psiphon` | hide your Worker traffic inside Psiphon's obfuscated tunnel |
| Trojan→TLS→**Psiphon-SOCKS** | same | same for trojan servers |
| SS→**Psiphon-SOCKS** | same | SS inside psiphon |
| VLESS→TLS→**pinned-IP** | `prefer_ips` | DNS-dead phases (SNI still correct) |
| **Psiphon alone** | local hop with no profile | classic Psiphon-only mode |

The planner generates these variants automatically for every profile + hop it knows about.

## Explicitly NOT implemented (and why)

| Method | Why not |
|--------|---------|
| VMess | legacy, detectable, heavy to hand-roll; VLESS supersedes it (links are parsed + reported) |
| XTLS-REALITY | needs custom TLS ClientHello forgery below rustls; roadmap item, high value |
| Hysteria2 / TUIC | QUIC stack + protocol work; roadmap; UDP path partly covered by WG |
| DNS tunneling | needs a controlled authoritative NS + is ~kb/s; documented in 05 as emergency channel |
| ICMP tunneling | needs raw sockets (root); external tools (icmptx/hans) documented |
| gRPC/httpupgrade transports | niche; parsed as Unsupported |
