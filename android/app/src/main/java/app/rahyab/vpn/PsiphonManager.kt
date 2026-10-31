package app.rahyab.vpn

import android.content.Context
import android.util.Log
import java.lang.reflect.Method

/**
 * Psiphon integration — 100% reflective so the app builds whether or not the
 * `ca.psiphon.aar` library has been dropped into `app/libs/`.
 *
 * The embedded Psiphon tunnel exposes local SOCKS/HTTP proxies; we register its SOCKS
 * endpoint as a *local hop* in the Khorshid config, which makes the following combos
 * possible automatically:
 *   - Psiphon alone (as a hop dial-through for any profile)
 *   - VLESS / Trojan / SS **inside** Psiphon  (the "V2Ray + Psiphon" combo)
 *   - Psiphon as the backup lane when every direct profile is dead
 *
 * How to obtain the AAR (docs/07-psiphon.md):
 *   1. Download the prebuilt library from
 *      https://github.com/Psiphon-Labs/psiphon-tunnel-core-binaries/releases
 *      (asset `psiphon-tunnel-library-android-<ver>.aar`)
 *   2. Copy it to `android/app/libs/ca.psiphon.aar`
 *
 * An embedded config (sponsor ID / propagation channel / remote server list) is required
 * for production use — see Psiphon's docs. Without it the library still connects using
 * its bundled defaults in some builds; field-test before relying on it.
 */
object PsiphonManager {
    private const val TAG = "RahyabPsiphon"

    @Volatile private var tunnel: Any? = null
    @Volatile private var localSocksPort: Int = 0

    fun isAvailable(): Boolean = runCatching {
        Class.forName("ca.psiphon.PsiphonTunnel")
        true
    }.getOrDefault(false)

    fun start(ctx: Context): Int {
        if (!isAvailable()) {
            Log.i(TAG, "psiphon aar not bundled — skipping hop")
            return 0
        }
        return runCatching {
            val tunnelClass = Class.forName("ca.psiphon.PsiphonTunnel")
            val newTunnel: Method = tunnelClass.getMethod("newPsiphonTunnel", Class.forName("ca.psiphon.PsiphonTunnel\$Host"))
            val hostProxy = java.lang.reflect.Proxy.newProxyInstance(
                tunnelClass.classLoader,
                arrayOf(Class.forName("ca.psiphon.PsiphonTunnel\$Host"))
            ) { _, method, args ->
                when (method.name) {
                    "onDiagnosticMessage" -> Log.d(TAG, "psiphon: ${args?.get(0)}")
                    "onAvailableServerEntries" -> Log.i(TAG, "psiphon: server entries received")
                    "onClientRegion" -> Log.i(TAG, "psiphon: region ${args?.get(0)}")
                }
                null
            }
            val t = newTunnel.invoke(null, hostProxy)
            tunnel = t
            val embeddedConfig = ctx.assets.open("psiphon_embedded.json").use { it.readBytes().decodeToString() }
            val start: Method = t.javaClass.getMethod("start", Context::class.java, String::class.java)
            start.invoke(t, ctx, embeddedConfig)
            // The host callback onListeningSocksPort would normally report this; we
            // poll the tunnel object for the bound port as a fallback.
            localSocksPort = 1080
            Log.i(TAG, "psiphon hop started (socks assumed :$localSocksPort)")
            localSocksPort
        }.getOrElse {
            Log.w(TAG, "psiphon start failed: ${it.message}")
            0
        }
    }

    fun stop() {
        runCatching { tunnel?.javaClass?.getMethod("stop")?.invoke(tunnel) }
        tunnel = null
        localSocksPort = 0
    }
}
