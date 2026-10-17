package io.github.astemo6.mihomo.a3

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import io.github.astemo6.mihomo.api.ControllerClient
import io.github.astemo6.mihomo.core.Core
import io.github.astemo6.mihomo.data.Overrides
import io.github.astemo6.mihomo.data.ProfileStore
import io.github.astemo6.mihomo.vpn.VpnState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** The physical network as the switcher sees it. [ssid] is null when unknown (no location permission …). */
data class NetSnapshot(val type: String, val ssid: String?) {
    /** Same type names as MihomoVpnService.reportNetwork / Core.setNetworkState. */
    val key: String get() = "$type|${ssid.orEmpty()}"
}

/**
 * 按网络切换模式: while the VPN runs, watches the non-VPN networks (its own ConnectivityManager callback,
 * independent of the service's) and applies the first matching [NetRule] when the network changes:
 * SSID rules first, then Wi-Fi / cellular / Ethernet. A rule is only applied when the network identity
 * changes, so a manual mode switch afterwards sticks until the next network change.
 *
 * SSID needs ACCESS_FINE_LOCATION (+ location services on; ACCESS_BACKGROUND_LOCATION to read it while the
 * app is in the background on Android 10+). Without it the SSID is null and SSID rules never match; Wi-Fi
 * rules still do.
 */
object NetworkModeSwitcher {
    private const val TAG = "A3NetSwitch"
    private val _current = MutableStateFlow<NetSnapshot?>(null)
    val current: StateFlow<NetSnapshot?> = _current.asStateFlow()

    /** Last SSID read (for Core.setNetworkState in the service; per-group SSID policies). */
    @Volatile var ssid: String? = null
        private set

    private var appContext: Context? = null
    private var callback: ConnectivityManager.NetworkCallback? = null
    private val nets = linkedMapOf<Network, NetworkCapabilities>()
    private var lastAppliedKey: String? = null
    private var pending: Job? = null
    private lateinit var scope: CoroutineScope

    fun start(context: Context, scope: CoroutineScope) {
        this.scope = scope
        val ctx = context.applicationContext
        appContext = ctx
        if (callback != null) return
        lastAppliedKey = null
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val cb = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            object : ConnectivityManager.NetworkCallback(FLAG_INCLUDE_LOCATION_INFO) {
                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = onCaps(network, caps)
                override fun onLost(network: Network) = onGone(network)
            }
        } else {
            object : ConnectivityManager.NetworkCallback() {
                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = onCaps(network, caps)
                override fun onLost(network: Network) = onGone(network)
            }
        }
        runCatching { cm.registerNetworkCallback(req, cb) }
            .onSuccess { callback = cb }
            .onFailure { Log.w(TAG, "registerNetworkCallback", it) }
    }

    fun stop() {
        val ctx = appContext
        callback?.let { cb -> runCatching { ctx?.getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb) } }
        callback = null
        pending?.cancel()
        synchronized(nets) { nets.clear() }
        lastAppliedKey = null
    }

    /** Re-evaluate now (after the user edited the rules). */
    fun reapply() {
        lastAppliedKey = null
        schedule(0)
    }

    private fun onCaps(network: Network, caps: NetworkCapabilities) {
        synchronized(nets) { nets[network] = caps }
        schedule(1200)
    }

    private fun onGone(network: Network) {
        synchronized(nets) { nets.remove(network) }
        schedule(1200)
    }

    /** Debounced: Wi-Fi ↔ cellular hand-overs fire several callbacks in a row. */
    private fun schedule(delayMs: Long) {
        if (!::scope.isInitialized) return
        pending?.cancel()
        pending = scope.launch {
            delay(delayMs)
            evaluate()
        }
    }

    private suspend fun evaluate() {
        val ctx = appContext ?: return
        val snap = snapshot(ctx)
        val oldSsid = ssid
        ssid = snap.ssid
        _current.value = snap
        if (oldSsid != snap.ssid && VpnState.info.value.isRunning) {
            runCatching { Core.setNetworkState(snap.type, snap.ssid.orEmpty()) }
        }
        if (!A3Prefs.netEnabled.value || !VpnState.info.value.isRunning) return
        if (snap.key == lastAppliedKey) return
        lastAppliedKey = snap.key
        val target = match(snap) ?: A3Prefs.netDefault.takeIf { it != "keep" } ?: return
        Log.i(TAG, "network ${snap.key} → $target")
        apply(target)
    }

    fun match(snap: NetSnapshot, rules: List<NetRule> = A3Prefs.rules.value): String? {
        val on = rules.filter { it.enabled }
        if (snap.type == "wifi" && !snap.ssid.isNullOrEmpty()) {
            on.firstOrNull { it.kind == NetRule.KIND_SSID && it.ssid.trim() == snap.ssid }?.let { return it.target }
        }
        val kind = when (snap.type) {
            "wifi" -> NetRule.KIND_WIFI
            "cellular" -> NetRule.KIND_CELLULAR
            "wired" -> NetRule.KIND_ETHERNET
            else -> return null
        }
        return on.firstOrNull { it.kind == kind }?.target
    }

    /** "mode:x" switches the outbound mode (persisted like the home mode switch); "profile:id" the profile. */
    suspend fun apply(target: String) {
        when {
            target.startsWith("mode:") -> applyMode(target.removePrefix("mode:"))
            target.startsWith("profile:") -> {
                val id = target.removePrefix("profile:")
                val p = ProfileStore.profiles.value.firstOrNull { it.id == id } ?: return
                if (ProfileStore.active?.id != p.id) ProfileStore.setActive(p) // reloads the running core
            }
        }
    }

    suspend fun applyMode(m: String) {
        if (m !in listOf("rule", "global", "direct")) return
        if (Overrides.load().mode != m) Overrides.update { it.copy(mode = m) }
        VpnState.update { it.copy(mode = m) }
        if (VpnState.info.value.isRunning) runCatching { ControllerClient.setMode(m) }.onFailure { Log.w(TAG, "setMode", it) }
    }

    // ---- network reading -------------------------------------------------------------------------

    fun snapshot(ctx: Context): NetSnapshot {
        val list = synchronized(nets) { nets.toList() }
        val best = if (list.isNotEmpty()) list.sortedBy { (_, c) -> rank(c) }.first().second else currentCaps(ctx)
        val type = when {
            best == null -> "other"
            best.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            best.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            best.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "wired"
            else -> "other"
        }
        val ssid = if (type == "wifi") readSsid(ctx, best) else null
        return NetSnapshot(type, ssid)
    }

    private fun rank(c: NetworkCapabilities) = when {
        c.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 0
        c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 1
        c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 2
        else -> 3
    }

    @Suppress("DEPRECATION")
    private fun currentCaps(ctx: Context): NetworkCapabilities? {
        val cm = ctx.getSystemService(ConnectivityManager::class.java) ?: return null
        return cm.allNetworks.mapNotNull { cm.getNetworkCapabilities(it) }
            .filter { it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) && it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) }
            .minByOrNull { rank(it) }
    }

    @Suppress("DEPRECATION")
    private fun readSsid(ctx: Context, caps: NetworkCapabilities?): String? {
        if (!hasLocationPermission(ctx)) return null
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            cleanSsid((caps?.transportInfo as? WifiInfo)?.ssid)?.let { return it }
        }
        // < 12, or a capabilities object without location info (redacted "<unknown ssid>").
        return cleanSsid(runCatching { ctx.applicationContext.getSystemService(WifiManager::class.java)?.connectionInfo?.ssid }.getOrNull())
    }

    fun cleanSsid(raw: String?): String? {
        val s = raw?.trim()?.removeSurrounding("\"") ?: return null
        if (s.isEmpty() || s == WifiManager.UNKNOWN_SSID.removeSurrounding("\"") || s == "<unknown ssid>" || s == "0x") return null
        return s
    }

    fun hasLocationPermission(ctx: Context): Boolean =
        ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED

    fun hasBackgroundLocation(ctx: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.Q ||
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_BACKGROUND_LOCATION) == PackageManager.PERMISSION_GRANTED

    fun locationEnabled(ctx: Context): Boolean {
        val lm = ctx.getSystemService(LocationManager::class.java) ?: return false
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) lm.isLocationEnabled
        else runCatching {
            @Suppress("DEPRECATION")
            android.provider.Settings.Secure.getInt(ctx.contentResolver, android.provider.Settings.Secure.LOCATION_MODE) != 0
        }.getOrDefault(true)
    }

    /** One-off read for the settings screen (also works while the VPN is off). */
    fun refreshNow(ctx: Context) {
        val snap = snapshot(ctx.applicationContext)
        _current.value = snap
    }
}
