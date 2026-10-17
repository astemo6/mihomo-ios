package io.github.astemo6.mihomo.a3

import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.api.ControllerClient
import io.github.astemo6.mihomo.data.AppSettings
import io.github.astemo6.mihomo.data.ProfileStore
import io.github.astemo6.mihomo.ui.MainActivity
import io.github.astemo6.mihomo.vpn.MihomoVpnService
import io.github.astemo6.mihomo.vpn.VpnState
import io.github.astemo6.mihomo.vpn.VpnStatus
import io.github.astemo6.mihomo.widget.NodeWidget
import io.github.astemo6.mihomo.widget.TrafficWidget
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/** Live traffic numbers for the traffic widget (session totals summed from the 1 s samples). */
data class TrafficNow(val up: Long = 0, val down: Long = 0, val upTotal: Long = 0, val downTotal: Long = 0)

/**
 * A3 runtime glue, started from MihomoApp: follows [VpnState] (its own collector; the single
 * VpnState.listener stays with the tile / status widget) to run the per-network switcher and feed the
 * node / traffic widgets, keeps the dynamic shortcuts in sync with the profile list and reports a VPN
 * start that failed without any UI (boot / always-on).
 */
object A3Runtime {
    private const val FAIL_NOTIFICATION_ID = 3
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private lateinit var app: Context
    private var trafficJob: Job? = null
    @Volatile var traffic = TrafficNow()
        private set
    /** Set when the VPN was started by boot / always-on: a failure then gets a notification. */
    @Volatile private var backgroundStart = false

    fun init(context: Context) {
        app = context.applicationContext
        A3Prefs.init(app)
        scope.launch {
            VpnState.info.map { it.status }.distinctUntilChanged().collect { s -> onStatus(s) }
        }
        scope.launch {
            VpnState.info.map { it.nodeText to it.mode }.distinctUntilChanged().collect {
                runCatching { NodeWidget.updateAll(app) }
            }
        }
        scope.launch {
            ProfileStore.profiles.combine(ProfileStore.activeId) { l, a -> l to a }
                .collect { runCatching { A3Shortcuts.publishDynamic(app) } }
        }
    }

    private fun onStatus(s: VpnStatus) {
        when (s) {
            VpnStatus.RUNNING -> {
                backgroundStart = false
                NetworkModeSwitcher.start(app, scope)
                startTraffic()
            }
            VpnStatus.STOPPED -> {
                NetworkModeSwitcher.stop()
                trafficJob?.cancel(); trafficJob = null
                traffic = TrafficNow()
                val err = VpnState.info.value.error
                if (backgroundStart && err != null) notifyBackgroundFailure(app, err)
                backgroundStart = false
            }
            else -> Unit
        }
        runCatching { NodeWidget.updateAll(app) }
        runCatching { TrafficWidget.updateAll(app) }
    }

    /** Traffic widget feed: only while a traffic widget exists and the screen is on. */
    private fun startTraffic() {
        trafficJob?.cancel()
        traffic = TrafficNow()
        trafficJob = scope.launch {
            delay(1000)
            val pm = app.getSystemService(PowerManager::class.java)
            var n = 0
            while (isActive && VpnState.info.value.isRunning) {
                ControllerClient.traffic().catch { }.collect { s ->
                    traffic = TrafficNow(s.up, s.down, traffic.upTotal + s.up, traffic.downTotal + s.down)
                    if (++n % 3 == 0 && pm?.isInteractive != false && TrafficWidget.hasWidgets(app)) {
                        runCatching { TrafficWidget.updateAll(app) }
                    }
                }
                delay(3000)
            }
        }
    }

    // ---- service hooks (one line each in MihomoVpnService) -------------------------------------

    /** onStartCommand: remember an always-on start and the always-on / lockdown state (API 29+). */
    fun onServiceStart(service: VpnService, intent: Intent?) {
        val action = intent?.action
        if (action == null || action == VpnService.SERVICE_INTERFACE) backgroundStart = true
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            runCatching {
                A3Prefs.lastAlwaysOn = service.isAlwaysOn
                A3Prefs.lastLockdown = service.isLockdownEnabled
            }
        }
    }

    /** onRevoke: another VPN took over / permission revoked: do not auto-reconnect on boot. */
    fun onRevoked() {
        AppSettings.wantRunning = false
    }

    fun markBackgroundStart() {
        backgroundStart = true
    }

    /** A start without UI failed (or cannot happen without UI): tell the user, tap opens the app. */
    fun notifyBackgroundFailure(context: Context, error: String?) {
        val ctx = context.applicationContext
        val open = PendingIntent.getActivity(ctx, 30,
            Intent(ctx, MainActivity::class.java).setAction(MainActivity.ACTION_CONNECT).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val n = NotificationCompat.Builder(ctx, MihomoVpnService.CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_mihomo)
            .setContentTitle(ctx.getString(R.string.a3_bg_start_failed))
            .setContentText(error ?: ctx.getString(R.string.a3_bg_start_needs_ui))
            .setStyle(NotificationCompat.BigTextStyle().bigText(error ?: ctx.getString(R.string.a3_bg_start_needs_ui)))
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        runCatching { ctx.getSystemService(NotificationManager::class.java).notify(FAIL_NOTIFICATION_ID, n) }
    }
}
