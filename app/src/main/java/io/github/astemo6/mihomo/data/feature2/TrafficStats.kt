package io.github.astemo6.mihomo.data.feature2

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ProcessLifecycleOwner
import io.github.astemo6.mihomo.api.ConnectionItem
import io.github.astemo6.mihomo.api.ControllerClient
import io.github.astemo6.mihomo.core.Paths
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import java.io.File
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale

@Serializable
data class Bytes(val up: Long = 0, val down: Long = 0) {
    val total: Long get() = up + down
    operator fun plus(o: Bytes) = Bytes(up + o.up, down + o.down)
}

/** Daily core totals (iOS TrafficHistory): up / down plus the Wi-Fi / cellular split at sample time. */
@Serializable
data class TrafficDay(val day: String, val up: Long = 0, val down: Long = 0, val wifi: Long? = null, val cell: Long? = null) {
    val total: Long get() = up + down
}

/** Per-day direct / proxy / per-policy / per-host bytes (iOS AnalyticsHistory), from /connections deltas. */
@Serializable
data class AnalyticsDay(
    val day: String,
    val direct: Bytes = Bytes(),
    val proxy: Bytes = Bytes(),
    val policies: Map<String, Bytes> = emptyMap(),
    val hosts: Map<String, Bytes> = emptyMap(),
) {
    val total: Long get() = direct.total + proxy.total
}

data class RuleHit(val rule: String, val policy: String, val hits: Int)

/** This session's numbers (since the core came up or the user reset them). */
data class SessionStats(
    val since: Long = System.currentTimeMillis(),
    val policies: Map<String, Bytes> = emptyMap(),
    val hosts: Map<String, Bytes> = emptyMap(),
    val rules: Map<String, RuleHit> = emptyMap(),
    val totalConnections: Int = 0,
    val activeConnections: Int = 0,
)

data class RateSample(val time: Long, val up: Long, val down: Long)

/**
 * Feeds the 流量统计 screen. Same process as the VPN service, so it runs for the process lifetime once
 * started ([ensureStarted] — called by Feature2Router; calling it from MihomoApp would also count traffic
 * while no feature2 screen was opened yet):
 *  - every 30 s while the core runs: TrafficTotals deltas → traffic-history.json (Wi-Fi / cellular split);
 *  - every 2 s while the app is in the foreground: /connections deltas → session per-policy / host / rule
 *    stats and analytics-history.json (like iOS, this only counts what is seen while the app is open);
 *  - /traffic samples for the rate graph while the app is in the foreground.
 */
object TrafficStats {
    private const val KEEP_DAYS = 120
    private const val KEEP_ANALYTICS_DAYS = 90
    private const val POLICY_CAP = 60
    private const val HOST_CAP = 120
    private const val SESSION_HOST_CAP = 600
    private const val RATE_POINTS = 180

    private val historyFile: File get() = File(Paths.root, "traffic-history.json")
    private val analyticsFile: File get() = File(Paths.root, "analytics-history.json")

    private val dayFmt get() = SimpleDateFormat("yyyy-MM-dd", Locale.US)
    fun dayKey(t: Long = System.currentTimeMillis()): String = dayFmt.format(Date(t))

    private val _session = MutableStateFlow(SessionStats())
    val session: StateFlow<SessionStats> = _session.asStateFlow()
    private val _days = MutableStateFlow<List<TrafficDay>>(emptyList())
    val days: StateFlow<List<TrafficDay>> = _days.asStateFlow()
    private val _analytics = MutableStateFlow<List<AnalyticsDay>>(emptyList())
    val analytics: StateFlow<List<AnalyticsDay>> = _analytics.asStateFlow()
    private val _rate = MutableStateFlow<List<RateSample>>(emptyList())
    val rate: StateFlow<List<RateSample>> = _rate.asStateFlow()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var started = false
    private var appContext: Context? = null
    private var lastTotals: Pair<Long, Long>? = null
    private var lastConn = HashMap<String, Pair<Long, Long>>()
    private var analyticsDirty = false
    private var lastAnalyticsSave = 0L
    private var rateJob: Job? = null

    @Synchronized
    fun ensureStarted(context: Context) {
        if (started) return
        started = true
        appContext = context.applicationContext
        _days.value = JsonFiles.read(historyFile, ListSerializer(TrafficDay.serializer())) ?: emptyList()
        _analytics.value = JsonFiles.read(analyticsFile, ListSerializer(AnalyticsDay.serializer())) ?: emptyList()
        scope.launch { totalsLoop() }
        scope.launch { connectionsLoop() }
    }

    private val foreground: Boolean
        get() = runCatching { ProcessLifecycleOwner.get().lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) }.getOrDefault(false)

    private suspend fun totalsLoop() {
        while (scope.isActive) {
            val t = F2Core.trafficTotals()
            if (t == null) {
                lastTotals = null
            } else {
                val prev = lastTotals
                // A smaller value means the core restarted: count from zero again.
                val du = if (prev == null || t.first < prev.first) t.first else t.first - prev.first
                val dd = if (prev == null || t.second < prev.second) t.second else t.second - prev.second
                lastTotals = t
                if (du > 0 || dd > 0) addDay(du, dd, iface())
            }
            delay(30_000)
        }
    }

    private suspend fun connectionsLoop() {
        var wasRunning = false
        while (scope.isActive) {
            val running = F2Core.isConnected
            if (running && !wasRunning) resetSession()
            wasRunning = running
            if (running && foreground) {
                runCatching { ControllerClient.connections().connections.orEmpty() }.onSuccess { ingest(it) }
                ensureRate()
            } else {
                rateJob?.cancel(); rateJob = null
                if (analyticsDirty) saveAnalytics(force = true)
            }
            delay(2_000)
        }
    }

    private fun ensureRate() {
        if (rateJob?.isActive == true) return
        rateJob = scope.launch {
            ControllerClient.traffic().catch { }.collect { s ->
                val l = _rate.value
                _rate.value = (if (l.size >= RATE_POINTS) l.drop(l.size - RATE_POINTS + 1) else l) +
                    RateSample(System.currentTimeMillis(), s.up, s.down)
            }
        }
    }

    private fun iface(): String? {
        val cm = appContext?.getSystemService(ConnectivityManager::class.java) ?: return null
        return runCatching {
            for (n in cm.allNetworks) {
                val c = cm.getNetworkCapabilities(n) ?: continue
                if (c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
                if (!c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
                if (c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return@runCatching "wifi"
                if (c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) return@runCatching "cellular"
            }
            null
        }.getOrNull()
    }

    @Synchronized
    private fun addDay(up: Long, down: Long, iface: String?) {
        val key = dayKey()
        val l = _days.value.toMutableList()
        val i = l.indexOfFirst { it.day == key }
        val d = if (i >= 0) l[i] else TrafficDay(key)
        val both = up + down
        val nd = d.copy(
            up = d.up + up, down = d.down + down,
            wifi = if (iface == "wifi") (d.wifi ?: 0) + both else d.wifi,
            cell = if (iface == "cellular") (d.cell ?: 0) + both else d.cell,
        )
        if (i >= 0) l[i] = nd else l += nd
        val cutoff = Calendar.getInstance().apply { add(Calendar.DAY_OF_YEAR, -KEEP_DAYS) }.timeInMillis
        val c = dayKey(cutoff)
        val out = l.filter { it.day >= c }.sortedBy { it.day }
        _days.value = out
        runCatching { JsonFiles.write(historyFile, ListSerializer(TrafficDay.serializer()), out) }
    }

    fun resetSession() {
        lastConn = HashMap()
        _session.value = SessionStats()
    }

    private val skipNames = setOf("__MITM__", "REJECT", "REJECT-DROP", F2Core.PROBE_GROUP)

    private fun hostName(c: ConnectionItem): String {
        val m = c.metadata
        return m.host?.takeIf { it.isNotEmpty() } ?: m.sniffHost?.takeIf { it.isNotEmpty() } ?: m.destinationIP ?: "?"
    }

    @Synchronized
    private fun ingest(conns: List<ConnectionItem>) {
        val s = _session.value
        val pol = s.policies.toMutableMap()
        var hs = s.hosts.toMutableMap()
        val rs = s.rules.toMutableMap()
        val stepPol = HashMap<String, Bytes>()
        val stepHost = HashMap<String, Bytes>()
        val seen = HashMap<String, Pair<Long, Long>>(conns.size)
        var newCount = 0
        for (c in conns) {
            val policy = c.chains?.lastOrNull() ?: "DIRECT" // mihomo chains are [node, …, rule target]: count per rule target, as iOS
            val prev = lastConn[c.id]
            if (prev == null) {
                newCount++
                val rule = c.ruleText.ifEmpty { "—" }
                val key = rule + "\u0001" + policy
                rs[key] = RuleHit(rule, policy, (rs[key]?.hits ?: 0) + 1)
            }
            val du = (c.upload - (prev?.first ?: 0)).coerceAtLeast(0)
            val dd = (c.download - (prev?.second ?: 0)).coerceAtLeast(0)
            if (du > 0 || dd > 0) {
                val b = Bytes(du, dd)
                val h = hostName(c)
                pol[policy] = (pol[policy] ?: Bytes()) + b
                hs[h] = (hs[h] ?: Bytes()) + b
                stepPol[policy] = (stepPol[policy] ?: Bytes()) + b
                stepHost[h] = (stepHost[h] ?: Bytes()) + b
            }
            seen[c.id] = c.upload to c.download
        }
        if (hs.size > SESSION_HOST_CAP * 2) {
            hs = hs.entries.sortedByDescending { it.value.total }.take(SESSION_HOST_CAP).associate { it.key to it.value }.toMutableMap()
        }
        lastConn = seen
        _session.value = s.copy(policies = pol, hosts = hs, rules = rs, totalConnections = s.totalConnections + newCount,
            activeConnections = conns.size)
        addAnalytics(stepPol, stepHost)
    }

    private fun addAnalytics(policies: Map<String, Bytes>, hosts: Map<String, Bytes>) {
        if (policies.isEmpty()) return
        val key = dayKey()
        val l = _analytics.value.toMutableList()
        val last = l.lastOrNull()?.takeIf { it.day == key }
        var direct = last?.direct ?: Bytes()
        var proxy = last?.proxy ?: Bytes()
        val pol = (last?.policies ?: emptyMap()).toMutableMap()
        var hs = (last?.hosts ?: emptyMap()).toMutableMap()
        for ((name, b) in policies) {
            if (name in skipNames) continue
            if (name == "DIRECT") direct += b else proxy += b
            pol[name] = (pol[name] ?: Bytes()) + b
        }
        for ((h, b) in hosts) hs[h] = (hs[h] ?: Bytes()) + b
        if (hs.size > HOST_CAP * 2) hs = hs.entries.sortedByDescending { it.value.total }.take(HOST_CAP).associate { it.key to it.value }.toMutableMap()
        val d = AnalyticsDay(key, direct, proxy, pol, hs)
        if (last != null) l[l.size - 1] = d else {
            l += d
            while (l.size > KEEP_ANALYTICS_DAYS) l.removeAt(0)
        }
        _analytics.value = l
        analyticsDirty = true
        saveAnalytics(force = false)
    }

    private fun saveAnalytics(force: Boolean) {
        val now = System.currentTimeMillis()
        if (!analyticsDirty || (!force && now - lastAnalyticsSave < 60_000)) return
        analyticsDirty = false
        lastAnalyticsSave = now
        val trimmed = _analytics.value.map { d ->
            d.copy(
                policies = d.policies.entries.sortedByDescending { it.value.total }.take(POLICY_CAP).associate { it.key to it.value },
                hosts = d.hosts.entries.sortedByDescending { it.value.total }.take(HOST_CAP).associate { it.key to it.value },
            )
        }
        runCatching { JsonFiles.write(analyticsFile, ListSerializer(AnalyticsDay.serializer()), trimmed) }
    }

    /** Last [count] days ending today, empty days filled in (oldest first). */
    fun recentDays(count: Int): List<TrafficDay> {
        val by = _days.value.associateBy { it.day }
        return (count - 1 downTo 0).map { back ->
            val k = dayKey(Calendar.getInstance().apply { add(Calendar.DAY_OF_YEAR, -back) }.timeInMillis)
            by[k] ?: TrafficDay(k)
        }
    }

    /** Analytics merged over the last [count] days (1 = today). */
    fun analyticsSummary(count: Int): AnalyticsDay {
        val keys = recentDays(count).map { it.day }.toSet()
        var direct = Bytes(); var proxy = Bytes()
        val pol = HashMap<String, Bytes>(); val hs = HashMap<String, Bytes>()
        for (d in _analytics.value) {
            if (d.day !in keys) continue
            direct += d.direct; proxy += d.proxy
            d.policies.forEach { (k, v) -> pol[k] = (pol[k] ?: Bytes()) + v }
            d.hosts.forEach { (k, v) -> hs[k] = (hs[k] ?: Bytes()) + v }
        }
        return AnalyticsDay("", direct, proxy, pol, hs)
    }

    fun clearHistory() {
        _days.value = emptyList(); _analytics.value = emptyList()
        historyFile.delete(); analyticsFile.delete()
    }
}
