package app.rahyab.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat

/**
 * VpnService: creates the TUN interface and hands its fd to the Rust core.
 * The Khorshid supervisor keeps running independently of this service —
 * failover swaps the hub upstream without tearing the VPN down.
 */
class TunnelVpnService : android.net.VpnService() {

    companion object {
        const val TAG = "RahyabVpn"
        const val CHANNEL_ID = "rahyab-vpn"
        const val NOTIFICATION_ID = 42
        const val MTU = 1500
        private const val TUN_ADDR = "10.111.0.2"
        private const val TUN_DNS = "10.111.0.1"

        @Volatile var instance: TunnelVpnService? = null
            private set
        val running: Boolean get() = instance != null
    }

    private var tunFd: Int = -1

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    override fun onDestroy() {
        RustCore.stopTunnel()
        tunFd = -1
        instance = null
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForegroundCompat()
        if (intent?.action == "app.rahyab.vpn.STOP") {
            stopVpn()
            return START_NOT_STICKY
        }
        val hubPort = Engine.hubPort
        if (hubPort <= 0) {
            Log.e(TAG, "startTunnel requested before engine is up")
            stopVpn()
            return START_NOT_STICKY
        }
        if (tunFd == -1) {
            val builder = Builder()
                .setSession("Rahyab")
                .setMtu(MTU)
                .addAddress(TUN_ADDR, 32)
                .addDnsServer(TUN_DNS)
                // 0.0.0.0/0 via the two-route trick; LAN/loopback stay excluded.
                .addRoute("0.0.0.0", 1)
                .addRoute("128.0.0.0", 1)
            val fd = builder.establish()?.detachFd()
            if (fd == null) {
                Log.e(TAG, "establish() failed — VPN permission missing?")
                stopVpn()
                return START_NOT_STICKY
            }
            tunFd = fd
        }
        val rc = RustCore.startTunnel(tunFd, MTU, hubPort)
        Log.i(TAG, "startTunnel(fd=$tunFd, hub=$hubPort) → $rc")
        return START_STICKY
    }

    fun stopVpn() {
        RustCore.stopTunnel()
        tunFd = -1
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun startForegroundCompat() {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Rahyab VPN", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val n: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Rahyab")
            .setContentText("Khorshid engine active")
            .setOngoing(true)
            .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
            .build()
        startForeground(NOTIFICATION_ID, n)
    }
}
