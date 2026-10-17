package io.github.astemo6.mihomo.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.api.ControllerClient
import io.github.astemo6.mihomo.core.Core
import io.github.astemo6.mihomo.data.AppSettings
import io.github.astemo6.mihomo.data.Overrides
import io.github.astemo6.mihomo.data.ProfileStore
import io.github.astemo6.mihomo.ui.Fmt
import io.github.astemo6.mihomo.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.sample
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.net.Inet6Address
import java.net.InetAddress

/**
 * The VPN: builds the tun interface (198.18.0.1/30, DNS 198.18.0.2, 0.0.0.0/0, optional
 * fdfe:dcba:9876::1/126 + ::/0, MTU 9000), hands its fd to the Go core and protects every socket the
 * core opens (SetSocketProtector → VpnService.protect). Runs in the UI process.
 */
class MihomoVpnService : VpnService() {
    companion object {
        const val ACTION_START = "io.github.astemo6.mihomo.START"
        const val ACTION_STOP = "io.github.astemo6.mihomo.STOP"
        const val ACTION_RELOAD = "io.github.astemo6.mihomo.RELOAD"
        const val ACTION_TOGGLE = "io.github.astemo6.mihomo.TOGGLE"
        /**
         * Boolean extra on ACTION_START / ACTION_TOGGLE: the overrides.safeMode value to connect with.
         * Absent = a normal user connect (switch, tile, widget, shortcut), which clears safe mode like iOS.
         * Only the diagnostics "safe-mode connect" passes true.
         */
        const val EXTRA_SAFE_MODE = "io.github.astemo6.mihomo.SAFE_MODE"
        const val CHANNEL = "vpn"
        private const val NOTIFICATION_ID = 1
        private const val TAG = "MihomoVpn"

        const val TUN_ADDRESS4 = "198.18.0.1"
        const val TUN_PREFIX4 = 30
        const val TUN_DNS4 = "198.18.0.2"
        const val TUN_ADDRESS6 = "fdfe:dcba:9876::1"
        const val TUN_PREFIX6 = 126
        const val TUN_MTU = 9000

        fun createChannel(context: Context) {
            val nm = context.getSystemService(NotificationManager::class.java)
            val ch = NotificationChannel(CHANNEL, context.getString(R.string.notif_channel), NotificationManager.IMPORTANCE_LOW)
            ch.setShowBadge(false)
            nm.createNotificationChannel(ch)
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lock = Mutex()
    private var trafficJob: Job? = null
    private var netCallback: ConnectivityManager.NetworkCallback? = null
    private val physical = linkedMapOf<Network, NetworkCapabilities>()
    @Volatile private var coreUp = false
    @Volatile private var notifText: String = ""

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Always enter the foreground first: the system requires it for startForegroundService().
        goForeground()
        io.github.astemo6.mihomo.a3.A3Runtime.onServiceStart(this, intent) // A3: always-on start / state
        when (intent?.action) {
            ACTION_STOP -> scope.launch { stopVpn(null) }
            ACTION_RELOAD -> scope.launch { reload() }
            ACTION_TOGGLE -> {
                val safe = intent.getBooleanExtra(EXTRA_SAFE_MODE, false)
                scope.launch { if (coreUp) stopVpn(null) else startVpn(safe) }
            }
            ACTION_START -> {
                val safe = intent.getBooleanExtra(EXTRA_SAFE_MODE, false)
                scope.launch { startVpn(safe) }
            }
            // null (sticky restart) and "android.net.VpnService" (always-on) start with the stored safeMode.
            else -> scope.launch { startVpn(null) }
        }
        return START_NOT_STICKY
    }

    // ---- start / stop -------------------------------------------------------------------------

    /** [safeMode]: value written to overrides.safeMode before starting; null keeps the stored value (system restarts). */
    private suspend fun startVpn(safeMode: Boolean?) = lock.withLock {
        if (coreUp) return@withLock
        VpnState.update { it.copy(status = VpnStatus.CONNECTING, error = null) }
        try {
            if (VpnService.prepare(this) != null) throw IllegalStateException(getString(R.string.err_vpn_permission))
            val profile = ProfileStore.active ?: throw IllegalStateException(getString(R.string.err_no_profile))
            if (!profile.file.exists()) throw IllegalStateException(getString(R.string.err_profile_missing))
            var o = Overrides.load()
            if (safeMode != null && o.safeMode != safeMode) o = Overrides.update { it.copy(safeMode = safeMode) }

            refreshPhysicalNetworks()
            val v6 = when (o.ipv6Mode) {
                "always" -> true
                "auto" -> physicalHasGlobalIPv6()
                else -> false
            }
            Core.setTunStack(AppSettings.tunStack)
            Core.setNetworkIPv6(v6)
            Core.setProtector { fd -> protect(fd) }

            val pfd = buildTun(o, v6, profile.name) ?: throw IllegalStateException(getString(R.string.err_vpn_permission))
            // The core owns the descriptor from here on (sing-tun closes it on shutdown), like CMFA.
            val fd = pfd.detachFd()
            try {
                Core.start(profile.file.absolutePath, fd)
            } catch (e: Exception) {
                if (!Core.isRunning) runCatching { ParcelFileDescriptor.adoptFd(fd).close() }
                throw IllegalStateException(Core.friendlyError(e.message ?: Core.lastError))
            }
            coreUp = true
            AppSettings.wantRunning = true
            VpnState.update { it.copy(status = VpnStatus.RUNNING, since = System.currentTimeMillis(), error = null, mode = o.mode) }
            registerNetworkCallback()
            reportNetwork()
            startTrafficNotification()
            scope.launch { refreshNodeText() }
        } catch (e: Exception) {
            Log.w(TAG, "start failed", e)
            Core.setProtector(null)
            AppSettings.wantRunning = false
            VpnState.update { VpnInfo(status = VpnStatus.STOPPED, error = e.message ?: e.toString()) }
            finish()
        }
    }

    private fun buildTun(o: Overrides, v6: Boolean, session: String): ParcelFileDescriptor? {
        val b = Builder()
            .setSession(session)
            .setMtu(TUN_MTU)
            .addAddress(TUN_ADDRESS4, TUN_PREFIX4)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(TUN_DNS4)
            .setBlocking(false)
        if (v6) {
            b.addAddress(TUN_ADDRESS6, TUN_PREFIX6)
            b.addRoute("::", 0)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) b.setMetered(false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            // 排除的路由 (same list as iOS; IPv6 entries only with IPv6 on). The core still routes
            // private ranges DIRECT by its rules, so a failure here is harmless.
            for (cidr in o.excludedRoutes) {
                val parts = cidr.trim().split('/')
                val addr = runCatching { InetAddress.getByName(parts[0]) }.getOrNull() ?: continue
                if (addr is Inet6Address && !v6) continue
                val len = parts.getOrNull(1)?.toIntOrNull() ?: if (addr is Inet6Address) 128 else 32
                runCatching { b.excludeRoute(IpPrefix(addr, len)) }
            }
        }
        // 分应用代理 (Android only). The app itself always stays inside the VPN (decision: protect()
        // instead of excluding the app, so always-on + lockdown keeps working).
        val own = packageName
        when (AppSettings.perAppMode) {
            AppSettings.PerAppMode.ALLOW -> {
                val pkgs = AppSettings.perAppPackages + own
                for (p in pkgs) runCatching { b.addAllowedApplication(p) }.onFailure { logMissing(p) }
            }
            AppSettings.PerAppMode.DENY -> {
                for (p in AppSettings.perAppPackages - own) runCatching { b.addDisallowedApplication(p) }.onFailure { logMissing(p) }
            }
            AppSettings.PerAppMode.OFF -> Unit
        }
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        b.setConfigureIntent(open)
        currentUnderlying()?.let { b.setUnderlyingNetworks(arrayOf(it)) }
        return b.establish()
    }

    private fun logMissing(pkg: String) = Log.i(TAG, "per-app: package not installed: $pkg")

    private suspend fun reload() = lock.withLock {
        if (!coreUp) return@withLock
        val profile = ProfileStore.active ?: return@withLock
        try {
            Core.setTunStack(AppSettings.tunStack)
            Core.reload(profile.file.absolutePath)
            VpnState.update { it.copy(error = null, mode = Overrides.load().mode) }
            refreshNodeText()
        } catch (e: Exception) {
            VpnState.update { it.copy(error = Core.friendlyError(e.message ?: Core.lastError)) }
        }
        updateNotification()
    }

    /** reason != null: unexpected stop (revoked, failure) shown to the user. */
    private suspend fun stopVpn(reason: String?) = lock.withLock {
        VpnState.update { it.copy(status = VpnStatus.STOPPING) }
        trafficJob?.cancel()
        trafficJob = null
        unregisterNetworkCallback()
        if (coreUp || Core.isRunning) runCatching { Core.stop() }
        Core.setProtector(null)
        coreUp = false
        if (reason == null) AppSettings.wantRunning = false
        VpnState.update { VpnInfo(status = VpnStatus.STOPPED, error = reason) }
        finish()
    }

    private fun finish() {
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        // Another VPN app took over, or the user revoked the permission in system settings.
        io.github.astemo6.mihomo.a3.A3Runtime.onRevoked() // A3: no auto-reconnect on boot after a takeover
        scope.launch { stopVpn(getString(R.string.stop_revoked)) }
    }

    override fun onDestroy() {
        if (coreUp) {
            runCatching { Core.stop() }
            Core.setProtector(null)
            coreUp = false
            VpnState.update { VpnInfo(status = VpnStatus.STOPPED) }
        }
        unregisterNetworkCallback()
        scope.cancel()
        super.onDestroy()
    }

    // ---- notification -------------------------------------------------------------------------

    private fun buildNotification(): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val stop = PendingIntent.getService(this, 1, Intent(this, MihomoVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val info = VpnState.info.value
        val title = when (info.status) {
            VpnStatus.RUNNING -> ProfileStore.active?.name ?: getString(R.string.app_name)
            VpnStatus.CONNECTING -> getString(R.string.status_connecting)
            VpnStatus.STOPPING -> getString(R.string.status_stopping)
            VpnStatus.STOPPED -> getString(R.string.status_off)
        }
        val text = listOfNotNull(info.nodeText, notifText.ifEmpty { null }).joinToString("  ·  ")
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_mihomo)
            .setContentTitle(title)
            .setContentText(text.ifEmpty { getString(R.string.notif_running) })
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .addAction(0, getString(R.string.action_disconnect), stop)
            .build()
    }

    private fun goForeground() {
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
        ServiceCompat.startForeground(this, NOTIFICATION_ID, buildNotification(), type)
    }

    private fun updateNotification() {
        if (!coreUp) return
        val nm = getSystemService(NotificationManager::class.java)
        runCatching { nm.notify(NOTIFICATION_ID, buildNotification()) }
    }

    @OptIn(kotlinx.coroutines.FlowPreview::class)
    private fun startTrafficNotification() {
        trafficJob?.cancel()
        trafficJob = scope.launch {
            delay(800)
            while (isActive && coreUp) {
                ControllerClient.traffic()
                    .sample(2000)
                    .catch { }
                    .collect { s ->
                        notifText = "↑ ${Fmt.speed(s.up)}  ↓ ${Fmt.speed(s.down)}"
                        updateNotification()
                    }
                delay(3000) // socket closed (reload / core restart): reconnect
            }
        }
    }

    private suspend fun refreshNodeText() {
        val text = runCatching {
            delay(500)
            val proxies = ControllerClient.proxies()
            val order = proxies["GLOBAL"]?.all.orEmpty()
            val first = order.firstOrNull { proxies[it]?.isGroup == true && proxies[it]?.hidden != true }
                ?: proxies.values.firstOrNull { it.isGroup && it.name != "GLOBAL" && it.hidden != true }?.name
            first?.let { g ->
                val chain = mutableListOf(g)
                var cur = proxies[g]?.now
                while (cur != null && chain.size < 6 && cur !in chain) {
                    chain += cur
                    cur = proxies[cur]?.now
                }
                chain.joinToString(" ➤ ")
            }
        }.getOrNull()
        if (text != null) {
            VpnState.update { it.copy(nodeText = text) }
            updateNotification()
        }
    }

    // ---- networks -----------------------------------------------------------------------------

    private val cm: ConnectivityManager get() = getSystemService(ConnectivityManager::class.java)

    @Suppress("DEPRECATION")
    private fun refreshPhysicalNetworks() {
        synchronized(physical) {
            physical.clear()
            for (n in cm.allNetworks) {
                val caps = cm.getNetworkCapabilities(n) ?: continue
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) physical[n] = caps
            }
        }
    }

    /** Prefer Wi-Fi / Ethernet over cellular among the non-VPN networks. */
    private fun currentUnderlying(): Network? = synchronized(physical) {
        physical.entries.sortedBy { (_, c) ->
            when {
                c.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 0
                c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 1
                c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 2
                else -> 3
            }
        }.firstOrNull()?.key
    }

    private fun physicalHasGlobalIPv6(): Boolean {
        val n = currentUnderlying() ?: return false
        val lp: LinkProperties = cm.getLinkProperties(n) ?: return false
        return lp.linkAddresses.any { la ->
            val a = la.address
            a is Inet6Address && !a.isLinkLocalAddress && !a.isLoopbackAddress && !a.isSiteLocalAddress &&
                (a.address[0].toInt() and 0xfe) != 0xfc // not ULA fc00::/7
        }
    }

    private fun registerNetworkCallback() {
        if (netCallback != null) return
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                val changed = synchronized(physical) { physical.put(network, caps) == null }
                if (changed) onPhysicalChanged()
            }

            override fun onLost(network: Network) {
                synchronized(physical) { physical.remove(network) }
                onPhysicalChanged()
            }
        }
        runCatching { cm.registerNetworkCallback(req, cb) }.onSuccess { netCallback = cb }
    }

    private fun unregisterNetworkCallback() {
        netCallback?.let { runCatching { cm.unregisterNetworkCallback(it) } }
        netCallback = null
    }

    private fun onPhysicalChanged() {
        if (!coreUp) return
        val n = currentUnderlying()
        runCatching { setUnderlyingNetworks(n?.let { arrayOf(it) }) }
        reportNetwork()
    }

    /** 按网络切换 + $network for event scripts (type only; SSID would need location permission). */
    private fun reportNetwork() {
        val n = currentUnderlying()
        val caps = n?.let { synchronized(physical) { physical[it] } }
        val type = when {
            caps == null -> "other"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "wired"
            else -> "other"
        }
        scope.launch {
            runCatching { Core.setNetworkState(type, if (type == "wifi") io.github.astemo6.mihomo.a3.NetworkModeSwitcher.ssid.orEmpty() else "") }
            runCatching { Core.notifyNetworkChanged("{\"type\":\"$type\"}") }
        }
    }

    @Suppress("unused")
    private fun isInstalled(pkg: String): Boolean =
        runCatching { packageManager.getPackageInfo(pkg, 0); true }.getOrElse { e -> e !is PackageManager.NameNotFoundException }
}
