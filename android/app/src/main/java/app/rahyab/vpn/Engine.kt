package app.rahyab.vpn

import android.content.Context
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Owns the Rust Khorshid engine. The config JSON is assembled from:
 *  - user profiles (share links pasted or imported from a subscription)
 *  - optional Psiphon local hop (127.0.0.1:<port>) when the embedded lib is present
 *  - anchors (probe targets), strategy, memory path
 */
object Engine {
    private const val TAG = "RahyabEngine"

    @Volatile var hubPort: Int = 0
        private set

    @Volatile var psiphonPort: Int = 0
        private set

    fun configFile(ctx: Context): File = File(ctx.filesDir, "rahyab.json")

    fun buildConfig(ctx: Context, profileLinks: List<String>): String {
        val cfg = JSONObject()
        val profiles = JSONArray()
        for (link in profileLinks.filter { it.contains("://") }) {
            profiles.put(JSONObject().put("link", link.trim()))
        }
        cfg.put("profiles", profiles)

        val hops = JSONArray()
        if (psiphonPort > 0) {
            hops.put(
                JSONObject()
                    .put("name", "psiphon")
                    .put("socks", "127.0.0.1:$psiphonPort")
            )
        }
        cfg.put("local_hops", hops)
        cfg.put("strategy", JSONObject()) // all defaults
        cfg.put(
            "anchors",
            JSONObject()
                .put(
                    "tcp_intl",
                    JSONArray(arrayOf("1.1.1.1:443", "8.8.8.8:443", "www.google.com:443", "github.com:443"))
                )
                .put("tcp_domestic", JSONArray())
                .put("cdn_ips", JSONArray())
                .put("doh", JSONArray(arrayOf("https://cloudflare-dns.com/dns-query?name=%s&type=A")))
                .put("udp_dns", JSONArray(arrayOf("8.8.8.8:53", "1.1.1.1:53")))
        )
        cfg.put("memory_path", File(ctx.filesDir, "rahyab_memory.json").absolutePath)
        return cfg.toString()
    }

    /** Start the engine. Returns hub port or negative. */
    fun start(ctx: Context, profileLinks: List<String>): Int {
        if (hubPort > 0) return hubPort
        // Best effort: start embedded Psiphon if the AAR was bundled (optional).
        try {
            psiphonPort = PsiphonManager.start(ctx)
        } catch (t: Throwable) {
            Log.w(TAG, "psiphon unavailable: ${t.message}")
            psiphonPort = 0
        }
        val json = buildConfig(ctx, profileLinks)
        configFile(ctx).writeText(json)
        val port = RustCore.startEngine(json)
        Log.i(TAG, "engine hub port: $port")
        if (port > 0) hubPort = port
        return port
    }

    fun stop() {
        PsiphonManager.stop()
        RustCore.stopEngine()
        hubPort = 0
    }

    fun status(): String = runCatching { RustCore.statusJson() }.getOrDefault("{}")

    /** Profiles persisted locally (share links, one per line). */
    fun loadProfiles(ctx: Context): List<String> {
        val f = File(ctx.filesDir, "profiles.txt")
        return if (f.exists()) f.readLines().filter { it.contains("://") } else emptyList()
    }

    fun saveProfiles(ctx: Context, links: List<String>) {
        File(ctx.filesDir, "profiles.txt").writeText(links.joinToString("\n"))
    }
}
