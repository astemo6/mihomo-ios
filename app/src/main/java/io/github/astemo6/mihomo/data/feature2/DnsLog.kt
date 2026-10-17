package io.github.astemo6.mihomo.data.feature2

import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ProcessLifecycleOwner
import io.github.astemo6.mihomo.api.ControllerClient
import io.github.astemo6.mihomo.data.AppJson
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
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

data class DnsQuery(
    val id: Long,
    val time: Long,
    val domain: String,
    val qtype: String,
    val answers: List<String>,
    val server: String?,
    val cached: Boolean,
    val error: String? = null,
)

data class BlockedDomain(val domain: String, val count: Int, val rule: String, val policy: String, val last: Long)

data class DnsAnswer(val type: String, val data: String, val ttl: Int?)

/**
 * DNS 查询日志 + 被拦截的域名. Read from the core's /logs stream at debug level while the app is in the
 * foreground and connected (same process as the VPN service): the resolver logs every upstream query
 * ("[DNS] a.com --> [1.2.3.4] A from https://…", cache hits, errors) and the tunnel logs each connection
 * a REJECT / REJECT-DROP rule stopped. In fake-ip mode most answers are fake addresses served locally
 * without an upstream query; those domains show up as hosts in 网络活动 instead.
 */
object DnsLog {
    private const val CAP = 600

    private val _queries = MutableStateFlow<List<DnsQuery>>(emptyList())
    val queries: StateFlow<List<DnsQuery>> = _queries.asStateFlow()
    private val _blocked = MutableStateFlow<Map<String, BlockedDomain>>(emptyMap())
    val blocked: StateFlow<Map<String, BlockedDomain>> = _blocked.asStateFlow()
    private val _paused = MutableStateFlow(false)
    val paused: StateFlow<Boolean> = _paused.asStateFlow()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var started = false
    private var job: Job? = null
    private var seq = 0L

    private val answerRe = Regex("""^\[DNS] (cache hit )?(\S+) --> (\[[^\]]*]|\S+)(?: (\w+))?(?: from (\S+))?(?:, expire at .*)?$""")
    private val errorRe = Regex("""^\[DNS] resolve (\S+) error: (.*)$""")
    private val blockRe = Regex("""^\[(TCP|UDP)] .+? --> (\S+) (?:match (.+?) )?using (.*)$""")

    fun setPaused(p: Boolean) { _paused.value = p }
    fun clear() { _queries.value = emptyList(); _blocked.value = emptyMap() }

    @Synchronized
    fun ensureStarted() {
        if (started) return
        started = true
        scope.launch {
            while (isActive) {
                val fg = runCatching { ProcessLifecycleOwner.get().lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) }.getOrDefault(false)
                val want = fg && F2Core.isConnected
                if (want && job?.isActive != true) {
                    job = scope.launch { ControllerClient.logs("debug").catch { }.collect { if (!_paused.value) handle(it.payload) } }
                } else if (!want && job != null) {
                    job?.cancel(); job = null
                }
                delay(2_000)
            }
        }
    }

    private fun hostOnly(addr: String): String {
        if (addr.startsWith("[")) return addr.substringAfter('[').substringBefore(']')
        val i = addr.lastIndexOf(':')
        return if (i > 0 && addr.indexOf(':') == i) addr.substring(0, i) else addr
    }

    internal fun handle(line: String) {
        val now = System.currentTimeMillis()
        if (line.startsWith("[DNS]")) {
            answerRe.find(line)?.let { m ->
                val raw = m.groupValues[3]
                val answers = raw.trim('[', ']').split(' ').filter { it.isNotBlank() }
                add(DnsQuery(++seq, now, m.groupValues[2].trimEnd('.'), m.groupValues[4].ifEmpty { "A" }, answers,
                    m.groupValues[5].ifEmpty { null }, m.groupValues[1].isNotEmpty()))
                return
            }
            errorRe.find(line)?.let { m ->
                add(DnsQuery(++seq, now, m.groupValues[1].trimEnd('.'), "", emptyList(), null, false, m.groupValues[2]))
            }
            return
        }
        if (!line.contains("using REJECT")) return
        val m = blockRe.find(line) ?: return
        val policy = m.groupValues[4].trim()
        if (!policy.startsWith("REJECT")) return
        val host = hostOnly(m.groupValues[2])
        val b = _blocked.value.toMutableMap()
        val prev = b[host]
        b[host] = BlockedDomain(host, (prev?.count ?: 0) + 1, m.groupValues[3].ifEmpty { prev?.rule ?: "" }, policy, now)
        _blocked.value = b
    }

    private fun add(q: DnsQuery) {
        val l = _queries.value
        _queries.value = (if (l.size >= CAP) l.drop(l.size - CAP + 1) else l) + q
    }

    /** GET /dns/query through the core (follows its DNS settings). */
    suspend fun lookup(name: String, type: String): List<DnsAnswer> {
        val json = F2Api.get(listOf("dns", "query"), mapOf("name" to name, "type" to type))
        val o = AppJson.parseToJsonElement(json).jsonObject
        val ans = (o["Answer"] as? JsonArray) ?: return emptyList()
        return ans.jsonArray.map { e ->
            val a = e.jsonObject
            DnsAnswer(rrType(a["type"]?.jsonPrimitive?.intOrNull), a["data"]?.jsonPrimitive?.contentOrNull ?: "",
                a["TTL"]?.jsonPrimitive?.intOrNull)
        }
    }

    private fun rrType(t: Int?): String = when (t) {
        1 -> "A"; 5 -> "CNAME"; 28 -> "AAAA"; 16 -> "TXT"; 15 -> "MX"; 2 -> "NS"; 65 -> "HTTPS"; null -> "?"; else -> t.toString()
    }
}
