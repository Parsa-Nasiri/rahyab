# 07 — Building the Android App

## The one-paragraph version

Push this repo to GitHub → the `Android APK` workflow builds `librahyab.so` for
arm64-v8a / armeabi-v7a / x86_64 with cargo-ndk, assembles the debug APK and uploads it
as an artifact. Download → install → paste your profiles (vless://… links from any
subscription) → tap CONNECT.

## What's inside

```
android/
├── app/src/main/AndroidManifest.xml     VPN permissions + foreground service
├── app/build.gradle.kts                 Compose UI, optional ca.psiphon.aar
└── app/src/main/java/app/rahyab/vpn/
    ├── MainActivity.kt                  one big CONNECT button + status + profile editor
    ├── TunnelVpnService.kt              VpnService: tun fd → RustCore.startTunnel()
    ├── RustCore.kt                      JNI bridge to librahyab.so
    ├── Engine.kt                        config assembly (profiles + psiphon hop + anchors)
    └── PsiphonManager.kt                reflective, optional Psiphon hop
```

Rust side: `crates/rahyab-android` (cdylib `librahyab.so`) — JNI functions
`startEngine/stopEngine/statusJson/startTunnel/stopTunnel`; tun2proxy binds the tun fd
and routes into the local hub; the Khorshid supervisor runs on its own tokio threads.

## Manual build (if you want to build locally)

Requirements: JDK 17, Android SDK + NDK r27, Rust with android targets, cargo-ndk.

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install cargo-ndk --locked
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
  -o android/app/src/main/jniLibs build --release -p rahyab-android
gradle -p android assembleDebug
# APK: android/app/build/outputs/apk/debug/app-debug.apk
```

## Psiphon AAR (optional)

Drop `ca.psiphon.aar` into `android/app/libs/` (sources: docs/06) and add
`android/app/src/main/assets/psiphon_embedded.json` with your embedded config.
The build and the app both work without it.

## Why a debug-signed APK?

Release signing needs your keystore — add it as a GitHub secret and extend
`android.yml` with `assembleRelease` when you're ready. The debug APK is fully
functional and installable ("install from unknown sources").

## Device notes

- minSdk 26 (Android 8.0+), targetSdk 34, foreground service type `specialUse`
  (VPN tunnel) — required on Android 14+.
- The VPN requests `0.0.0.0/1 + 128.0.0.0/1` routes so it takes all traffic without
  killing the physical network's own routes; DNS inside the tunnel is handled by
  tun2proxy's virtual-DNS (198.18.0.0/15 pool → hostname handed to the hub).
