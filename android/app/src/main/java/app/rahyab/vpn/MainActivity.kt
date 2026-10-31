package app.rahyab.vpn

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.text.font.FontWeight
import kotlinx.coroutines.*

class MainActivity : ComponentActivity() {
    private val vpnPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
            if (res.resultCode == RESULT_OK) connectNow()
            else Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { RahyabApp() }
    }

    @Composable
    fun RahyabApp() {
        val scope = rememberCoroutineScope()
        var status by remember { mutableStateOf("idle") }
        var connected by remember { mutableStateOf(Engine.hubPort > 0) }
        var profileText by remember { mutableStateOf(Engine.loadProfiles(this@MainActivity).joinToString("\n")) }
        var showEditor by remember { mutableStateOf(false) }

        // Status poller
        LaunchedEffect(connected) {
            while (true) {
                if (connected) {
                    val s = Engine.status()
                    status = runCatching {
                        val o = org.json.JSONObject(s)
                        "${o.optString("phase")} • ${o.optString("environment")} • ${o.optString("active", "—")}"
                    }.getOrDefault(s)
                }
                delay(1500)
            }
        }

        MaterialTheme(colorScheme = if (connected) darkColorScheme() else lightColorScheme()) {
            Surface(Modifier.fillMaxSize()) {
                Column(
                    Modifier.fillMaxSize().padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Text("RAHYAB", fontSize = 28.sp, fontWeight = FontWeight.Bold)
                    Text("راه‌یاب — blackout pathfinder", fontSize = 13.sp, color = Color.Gray)
                    Spacer(Modifier.height(28.dp))

                    Button(
                        onClick = { connected = !connected; if (connected) connectFlow() else disconnect() },
                        shape = CircleShape,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (connected) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
                        ),
                        modifier = Modifier.size(190.dp)
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(
                                if (connected) "DISCONNECT" else "CONNECT",
                                fontSize = 20.sp, fontWeight = FontWeight.Bold
                            )
                            if (connected && status.isNotEmpty()) {
                                Spacer(Modifier.height(6.dp))
                                Text(status.take(120), fontSize = 10.sp, color = Color.White.copy(alpha = 0.85f))
                            }
                        }
                    }
                    Spacer(Modifier.height(24.dp))
                    TextButton(onClick = { showEditor = true }) { Text("Profiles / subscription") }
                    Text(
                        "Khorshid probes the network, races every method it knows, remembers what works.",
                        fontSize = 11.sp, color = Color.Gray,
                        modifier = Modifier.padding(top = 12.dp)
                    )
                }

                if (showEditor) {
                    AlertDialog(
                        onDismissRequest = { showEditor = false },
                        confirmButton = {
                            TextButton(onClick = {
                                val links = profileText.lines().filter { it.contains("://") }
                                Engine.saveProfiles(this@MainActivity, links)
                                showEditor = false
                            }) { Text("Save") }
                        },
                        dismissButton = { TextButton(onClick = { showEditor = false }) { Text("Cancel") } },
                        title = { Text("Profiles — one share link per line") },
                        text = {
                            Column {
                                OutlinedTextField(
                                    value = profileText,
                                    onValueChange = { profileText = it },
                                    placeholder = { Text("vless://…\ntrojan://…\nss://…") },
                                    modifier = Modifier.fillMaxWidth().height(220.dp)
                                )
                                Text(
                                    "Supports vless/trojan/ss/socks links and base64 subscriptions. For a Psiphon hop, drop ca.psiphon.aar into app/libs (docs/07).",
                                    fontSize = 10.sp, color = Color.Gray, modifier = Modifier.padding(top = 8.dp)
                                )
                            }
                        }
                    )
                }
            }
        }
    }

    private fun connectFlow() {
        val intent = VpnService.prepare(this)
        if (intent != null) vpnPermission.launch(intent) else connectNow()
    }

    private fun connectNow() {
        val links = Engine.loadProfiles(this)
        val port = Engine.start(this, links)
        if (port <= 0) {
            Toast.makeText(this, "Engine failed to start (config error?)", Toast.LENGTH_LONG).show()
            return
        }
        startForegroundService(Intent(this, TunnelVpnService::class.java))
    }

    private fun disconnect() {
        startService(
            Intent(this, TunnelVpnService::class.java).setAction("app.rahyab.vpn.STOP")
        )
        Engine.stop()
    }
}
